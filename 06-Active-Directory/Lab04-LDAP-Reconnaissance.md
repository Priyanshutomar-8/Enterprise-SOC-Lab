# Lab 04 - LDAP / BloodHound Reconnaissance (detection gap)

## Objective
Detect Active Directory reconnaissance - the bulk LDAP enumeration a tool like
BloodHound performs to map users, groups, ACLs, GPOs and trusts. Unlike the
credential-theft labs (Kerberoasting, AS-REP roasting), recon has **no single-event
signature**: it is *reading the directory*, which every domain-joined host does all
day. Detection has to key on **volume and shape**, not a distinctive event.

This lab is written up honestly as a **detection-gap investigation**. It reaches a
firm, evidence-backed conclusion rather than a firing rule: with default auditing
the always-on telemetry is **blind** to LDAP reads; the telemetry that *does* see
them (event **1644**) requires non-default diagnostics, self-floods the SIEM when
tuned to catch modern collectors, and - once delivered to Wazuh - **is not routed
into the rule engine** on this channel. The detection logic was proven correct with
`wazuh-logtest`; the blocker is the platform's live event pipeline, not the rule.
Rule id **100602** is reserved and documented but **does not fire** - per this
repo's hard rule, it is not presented as working.

## MITRE ATT&CK
| Field | Value |
|---|---|
| Tactic | Discovery (TA0007) |
| Techniques | **T1087** (Account Discovery), **T1069** (Permission Groups Discovery), **T1482** (Domain Trust Discovery) |
| Log sources | Windows **Security** 4662 (Directory Service Access); **Directory Service** 1644 (expensive/inefficient LDAP search) |
| Reference | https://attack.mitre.org/techniques/T1087/ |

## Environment
| Component | Details |
|---|---|
| Domain controller / target | `DC01` (Windows Server 2022), `lab.local`, 192.168.56.10, Wazuh agent **004** |
| Attacker | Kali - `bloodhound-python`, then `ldapsearch` (ldap-utils), 192.168.56.80 |
| Manager | Wazuh 4.14.6 all-in-one, Ubuntu, 192.168.56.79 |
| Recon identity | `jdoe` (any authenticated domain user can enumerate the whole directory) |
| Reserved rule | **100602** (documented, not firing - see conclusion) |

## The detection problem

Reconnaissance is the hardest AD attack to detect because the malicious action -
an LDAP search - is indistinguishable at the single-event level from legitimate
directory use. There is no equivalent of "an RC4 ticket for a user SPN." The only
discriminators are **who** is asking, **how much** they pull, and **how fast**. That
forces a volume/aggregation approach and, first, a telemetry source that actually
records the reads. Two candidates exist, and the lab evaluated both by measurement.

## Finding 1 - event 4662 is structurally blind to LDAP read recon

4662 ("An operation was performed on an object") is on the always-on **Security**
channel and was already enabled in Lab 01. It seems the obvious source. It is not.

A full `bloodhound-python -c DCOnly` collection (7 users, 52 groups, all ACLs, GPOs,
OUs, containers) was run, then measured on the DC:

```
4662 total: 0     4662 by jdoe: 0     4624 by jdoe: 0
```

**Zero 4662.** 4662 fires only where an object carries an **audit SACL** for the
access performed, and default AD objects have no read-audit SACLs on the attributes
BloodHound reads; BloodHound uses plain, efficient LDAP *searches*, not the
"Control Access" operations that raise 4662. Catching recon on 4662 would require
blanket read-auditing on every object - operationally impossible (catastrophic
volume). (The NTLM LDAP bind also logs as 4776 credential-validation, not a clean
per-bind 4624, so even the auth trail is thin.) **4662 cannot see this attack.**

## Finding 2 - event 1644 sees it, but only after non-default work

Event **1644** (LDAP "expensive/inefficient search") records the actual **filter
string**, **client address**, and **visited/returned counts** of a search. It is
the right telemetry - but it is off by default and lives on a channel Wazuh does
not watch. Enabling it took three steps:

1. **Field Engineering diagnostic** - `HKLM\...\NTDS\Diagnostics` `15 Field
   Engineering` from `0` to `5`.
2. **Lower the search thresholds** - `NTDS\Parameters` `Expensive/Inefficient Search
   Results Threshold` and `Search Time Threshold`, whose defaults (10000/1000/30000)
   keep normal traffic silent.
3. **Subscribe Wazuh to the Directory Service channel** - the default agent config
   does not forward it:
   ```xml
   <localfile><location>Directory Service</location><log_format>eventchannel</log_format></localfile>
   ```

With thresholds at `1`, a BloodHound sweep produced ~150+ 1644 carrying exactly the
recon signature (client `192.168.56.80`, filter `(objectClass=*)`, user `jdoe`).

## Finding 3 - the tuning that catches modern BloodHound self-DoSes the SIEM

Modern collectors are **efficient**: BloodHound's per-object lookups return a single
indexed entry in ~0 ms, so they only appear as 1644 at a *very* low threshold. But a
threshold of `1` logs **every internal LDAP search a DC performs** - a constant
firehose. Forwarded to a small all-in-one manager, it starved it: the agent log
showed a reconnect storm (`Server unavailable` / `actively refused`, repeating), and
the 1644 events were lost in the churn (196 on the DC, 0 delivered).

The fix is the real tuning lesson: raise the **Expensive** threshold so only **bulk**
searches (returning > 20 entries - the whole-object-class pulls BloodHound and
`ldapsearch '(objectClass=*)'` do) log, while the DC's single-object chatter goes
silent. Ambient 1644 dropped to ~0 and the manager recovered. **The SIEM's own
capacity is part of the detection design** - the telemetry setting that catches the
attack is the same one that can drown the analyst.

## The intended detection (reserved rule 100602)

The eventchannel decoder flattens a 1644's payload into a single comma-joined field,
`win.eventdata.data`, e.g.:

```
DC=lab,DC=local,  (objectClass=*), 3693, 244, 192.168.56.80:60294, subtree, [], ... , jdoe@lab.local
```

An **internal** DC search instead shows `Internal` / `[::1]` with no IPv4. So the
discriminator needs no custom decoder: an expensive 1644 (threshold-gated) whose
client is an **external IPv4** is recon. The reserved rule:

```xml
<rule id="100602" level="10">
  <decoded_as>windows_eventchannel</decoded_as>
  <field name="win.system.eventID">^1644$</field>
  <field name="win.eventdata.data" type="pcre2">(?:\d{1,3}\.){3}\d{1,3}:\d+</field>
  <field name="win.eventdata.data" type="pcre2" negate="yes">192\.168\.56\.10:\d+</field>
  <description>LDAP reconnaissance: expensive directory search from external client</description>
  <mitre><id>T1087</id><id>T1069</id><id>T1482</id></mitre>
</rule>
```

## Finding 4 - the wall: 1644 reaches Wazuh but never enters the rule tree

Rule 100602 did not fire. Neither did any of a series of deliberately-broad probes,
each testing one assumption, all against events that `logall_json` **confirmed were
arriving and decoding** (decoder `windows_eventchannel`, `win.system.eventID`
`"1644"`, `win.system.channel` `"Directory Service"`, the client IP in
`win.eventdata.data`):

| Probe | Condition | Result |
|---|---|---|
| `if_sid 60000` + eventID 1644 | the standard eventchannel base rule | **no match** |
| `decoded_as windows_eventchannel` + eventID 1644 | what `logall` says the decoder is | **no match** |
| `decoded_as windows_eventchannel` + channel "Directory Service" | channel only | **no match** |
| `decoded_as json` + eventID 1644 | fallback-decoder hypothesis | **no match** |
| `<match>` on the raw message text | no decoded fields at all | **no match** |

Every route failed **live**, while the identical mechanism matches Security-channel
events (Labs 02-03 fired fine). The ground truth came from `wazuh-logtest`, fed a
real captured 1644:

```
**Phase 2: Completed decoding.   name: 'json'
        win.system.eventID: '1644'   win.system.channel: 'Directory Service'
        win.eventdata.data: '... 192.168.56.80:57400 ... jdoe@lab.local'
**Phase 3: Completed filtering (rules).   id: '100616'  ... **Alert to be generated.
```

`logtest` **proves the detection logic is correct** - the same event content, run
through the normal decoder path, decodes cleanly and fires the raw-match rule. The
discrepancy is the whole finding: **`logtest` uses the `json` decoder (stdin path);
the live agent path decodes the Directory Service channel with the built-in
`windows_eventchannel` C-decoder, which archives the event but does not route it
into the rule tree.** A custom XML decoder cannot fix this - the built-in C-decoder
claims the event first in the live path, so no user decoder ever sees it.

## Result

Detection **telemetry** was validated end to end: attack -> 1644 on the DC ->
forwarded -> received and decoded on the manager, carrying every field a rule needs.
Detection **alerting** is blocked by the platform: Wazuh 4.14.6 does not route
Directory Service eventchannel events into rule evaluation, so no rule - however
written - fires on them. Rule 100602 is reserved and documented; it **does not
fire** and is not claimed to.

The honest one-line conclusion: **AD LDAP-recon is hard to detect here for three
independent reasons - the always-on channel is blind to it, the channel that sees it
must be coaxed on and then floods, and once delivered it is not rule-routed.** That
is a more useful result than a rule that only appears to work.

## Notes, limitations, lessons learned

- **Measure-first paid for itself.** Running the real collector and counting 4662
  *before* building anything killed a detection that structurally cannot see the
  attack. Building the rule first would have shipped a coverage chart that lies.
- **The SIEM's capacity is a detection parameter.** A threshold low enough to catch
  efficient BloodHound is low enough to firehose a DC's internal LDAP into a small
  manager and starve it. Tuning is a trade between blindness and self-DoS; aggregate
  by client on bulk searches, do not log every search.
- **`wazuh-logtest` is the authority for the decoder/field/rule verdict** - but only
  for the stdin path. It decodes pasted eventchannel JSON with the `json` decoder,
  which is *not* the live agent path. A rule that fires in `logtest` can still never
  fire live for a channel the live pipeline handles differently. Proving a detection
  requires a live fire, never `logtest` alone.
- **Non-standard eventchannel channels are second-class in Wazuh.** Security,
  System, Application and Sysmon route to rules; Directory Service (NTDS) decodes and
  archives but does not. Any detection built on a non-default Windows channel must be
  live-fire validated before it is trusted.
- **Attack tooling:** `bloodhound-python`'s DNS was unreliable over the host-only
  link (3-second SRV lifetime timeouts; a DC that publishes both a reachable
  host-only A record and an unreachable NAT A record). `ldapsearch` addressing the DC
  by IP (`-H ldap://192.168.56.10`) is a reliable, DNS-free generator of the same
  bulk-search telemetry and a legitimate manual-recon technique in its own right.
- **Possible future workaround (untested):** ingest the Directory Service log via the
  classic `<log_format>eventlog</log_format>` rather than `eventchannel`, which may
  route events through the standard decoder path that `logtest` showed does match.
  Deferred - it is uncertain and the DC was performance-degraded by session's end.

## Status
**Complete as an investigation; detection unresolved.** Telemetry validated; alerting
blocked by a platform limitation in Wazuh's Directory Service eventchannel routing.
Rule **100602** reserved, documented, not firing. Next: **Lab 05 - DCSync**
(event 4662 with the DS-Replication-Get-Changes GUID, rule 100603) - which returns
to the Security channel and should not hit this wall.
