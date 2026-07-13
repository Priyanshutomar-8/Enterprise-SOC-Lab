# Lab 06 - Reconnaissance / Discovery Detection

## Objective
Detect an attacker running host reconnaissance commands (`whoami`,
`id`, `uname`, `hostname`, `ss`, `ifconfig`, etc.) on the Kali
endpoint, and correlate a burst of them into a single high-severity
alert instead of drowning the analyst in one alert per command.

## MITRE ATT&CK
| Field | Value |
|---|---|
| Tactic | Discovery |
| Technique | T1057 - Process Discovery |
| Secondary | T1082 - System Information Discovery |
| Reference | https://attack.mitre.org/techniques/T1057/ |

## Why this matters
Reconnaissance is the first thing an attacker does after landing on
a host. Before moving laterally or escalating, they orient: who am I
(`whoami`, `id`), what is this box (`uname`, `hostname`), what is it
talking to (`ss`, `netstat`, `ifconfig`, `arp`). These are all
legitimate admin commands, so no single one is worth alerting on. The
signal is not the command, it is the **pattern**: several discovery
commands from the same user in a short window. That behavioural
signature is what this lab detects.

Wazuh does not flag these out of the box, which makes this lab a real
detection-engineering exercise rather than a rule already shipped by
the vendor.

## Environment
| Component | Details |
|---|---|
| Agent | Kali GNU/Linux 2025.4 (192.168.1.161) |
| Manager | Ubuntu Server (192.168.1.79) |
| Log source | Linux Audit (auditd) -> /var/log/audit/audit.log |
| Wazuh version | 4.14.5 |

## The gotcha that made this lab hard

Wazuh only decodes an audited command into the `audit.exe` /
`audit.auid` fields **if the auditd rule uses a key that Wazuh
recognises as a command key.** Recognised keys live in a CDB list at
`/var/ossec/etc/lists/audit-keys`, and the built-in command key is
`audit-wazuh-c`.

The first attempt used invented keys (`recon`, `recon_tool`,
`download`) and a broad unfiltered `-S execve` catch-all. It failed
silently: the events reached the manager but were never categorised
as commands, so no command fields existed to write rules against.
Inventing your own audit key does nothing unless you also register it
in the CDB list.

**Lesson: use `audit-wazuh-c` (or register your own key in
`audit-keys`) - do not assume a custom key works.**

## auditd configuration applied (on the Kali agent)

Two rules using the recognised key - one for root-run commands, one
for real logged-in users. `auid>=1000` scopes the second rule to
human accounts and keeps low-level system UIDs out.

```bash
# /etc/audit/rules.d/wazuh.rules
-a always,exit -F arch=b64 -S execve -F euid=0 -k audit-wazuh-c
-a always,exit -F arch=b64 -S execve -F auid>=1000 -F auid!=-1 -k audit-wazuh-c
```

```bash
sudo augenrules --load
sudo auditctl -l          # confirm both rules loaded
```

Agent `ossec.conf` points the log collector at the audit log:

```xml
<localfile>
  <log_format>audit</log_format>
  <location>/var/log/audit/audit.log</location>
</localfile>
```

With this in place, Wazuh's built-in **Rule 80792** ("Audit:
Command: ...") fires for every audited command and populates
`audit.exe` and `audit.auid`.

## Detection rules (on the manager)

Added to `/var/ossec/etc/rules/local_rules.xml`. Rules only ever live
on the **manager** - agents do not evaluate rules, so there is no
`/var/ossec/etc/rules/` on Kali.

```xml
<group name="local,audit,discovery,">

  <!-- Tag an individual recon command (informational) -->
  <rule id="100300" level="3">
    <if_sid>80792</if_sid>
    <field name="audit.exe">whoami|/usr/bin/id|uname|hostname|/usr/bin/w$|/usr/bin/who|/usr/bin/last|netstat|/usr/bin/ss|ifconfig|/usr/bin/arp|/usr/bin/nmap|/usr/bin/nc</field>
    <field name="audit.auid" negate="yes">4294967295</field>
    <description>Recon command executed: $(audit.exe) by auid $(audit.auid)</description>
    <mitre><id>T1057</id><id>T1082</id></mitre>
  </rule>

  <!-- Escalate a BURST of recon from the same user (actionable) -->
  <rule id="100301" level="12" frequency="4" timeframe="60">
    <if_matched_sid>100300</if_matched_sid>
    <same_field>audit.auid</same_field>
    <description>Discovery activity: 4+ recon commands by same user (auid $(audit.auid)) in 60s</description>
    <mitre><id>T1057</id></mitre>
  </rule>

</group>
```

Design notes:
- **100300** (level 3) tags each recon command but is deliberately
  low severity - one `id` is not an incident.
- **100301** (level 12) is the real alert: `frequency="4"` +
  `timeframe="60"` fires when 4 or more `100300` events occur within
  60 seconds, and `<same_field>audit.auid</same_field>` requires them
  to come from the **same user** - so unrelated background activity
  across different UIDs does not accidentally build a burst.
- Short command names (`id`, `w`, `ss`, `nc`) are anchored to full
  paths in the regex (`/usr/bin/id`, `/usr/bin/w$`) to prevent
  substring false-matches against unrelated binaries.
- `<field name="audit.auid" negate="yes">4294967295</field>` excludes
  non-login daemons (auid unset = 4294967295) from being tagged as
  recon - see the noise analysis below.

```bash
sudo systemctl restart wazuh-manager
```

## Attack simulation (on Kali, as the logged-in user)

Six discovery commands in one line - deliberately above the
threshold of 4 to guarantee the burst fires:

```bash
whoami; id; uname -a; hostname; ss -tulpn >/dev/null; ifconfig
```

`ss` / `ifconfig` are used instead of `netstat`, which is not
installed by default on current Kali.

## Detection results

| Rule ID | Description | Severity | Trigger |
|---|---|---|---|
| 80792 | Audit: Command executed | Level 3 | Every audited command (built-in) |
| 100300 | Recon command executed | Level 3 | Any single recon command (custom) |
| 100301 | Discovery activity: 4+ recon commands by same user in 60s | Level 12 | The burst (custom correlation) |

### Confirmed 100301 fires (auid 1000 = the simulation)
```
2026-07-13T18:13:42  Discovery activity: 4+ recon commands by same user (auid 1000) in 60s
2026-07-13T18:23:29  Discovery activity: 4+ recon commands by same user (auid 1000) in 60s
2026-07-13T18:38:34  Discovery activity: 4+ recon commands by same user (auid 1000) in 60s
```
Every escalation fired on the real user session (auid 1000). None
fired on root or daemon activity - which is exactly what the
correlation logic is meant to guarantee.

## Signal vs noise analysis (the part that matters)

`100300` is intentionally chatty, so the individual-command tag fires
across every UID that runs a recon command. Measured distribution of
`100300` events:

| auid | Meaning | 100300 count | Triggered 100301? |
|---|---|---|---|
| 1000 | Logged-in user (the attacker sim) | 15 | Yes |
| 0 | Interactive root | 27 | No |
| 4294967295 | Non-login daemon (auid unset) | 3 | No |

Key observations:
- The 27 root (`auid 0`) `100300` events are a background job running
  `id` roughly once per minute. They never cluster 4-in-60s, so they
  **never escalate to 100301.** The correlation window does the
  filtering for us.
- The `auid 4294967295` events are non-login daemons - never an
  interactive attacker. These are excluded from `100300` entirely via
  the `negate="yes"` field so they do not even generate informational
  noise.
- Interactive root (`auid 0`) is **kept** on purpose: an attacker in a
  root shell running recon is a legitimate thing to alert on. If a
  root-owned automation job ever bursts recon 4x/60s and causes a
  false 100301, the tuning knob is to add an `auid=0` exclusion or
  raise the threshold - a documented tradeoff, not an oversight.

This is the honest story of the rule: the low-severity tag is noisy
by design, and the escalation stays quiet because the correlation
requires a same-user burst that only real reconnaissance produces.

## Dashboard queries used
- `rule.id:100301` - the escalation (analyst starts here)
- `rule.id:100300` - the individual recon commands feeding it
- `rule.id:80792` - raw audited command stream
- `rule.groups:discovery`

## Investigation steps
1. Open the `100301` alert - identify the `audit.auid` and time window.
2. Pivot to `100300` for that same auid in the 60s before the alert -
   this is the exact sequence of recon commands the attacker ran.
3. Pull the raw `80792` events for full command lines and cwd.
4. Determine whether that user/session is expected to be running
   discovery commands, or whether the account is compromised.
5. If unauthorised, isolate the host and pivot to the login source
   (SSH? local session?) using the auth logs from Labs 02-04.

```bash
# Investigation commands (on the manager)
sudo grep -a '"id":"100301"' /var/ossec/logs/alerts/alerts.json | tail -5
sudo grep -a '"id":"100300"' /var/ossec/logs/alerts/alerts.json | tail -20
```

## Lessons learned
- Custom auditd keys are invisible to Wazuh's command decoder unless
  registered in the `audit-keys` CDB list - use `audit-wazuh-c`.
- Rules live only on the manager; agents never evaluate them.
- Detection value for discovery is in the **pattern**, not the single
  command - correlation (`frequency` + `timeframe` + `same_field`)
  turns noise into one actionable alert.
- Anchor short command names to full paths to avoid substring
  false-matches.
- A good rule separates signal from noise by design: the low-severity
  tag can be chatty as long as the escalation stays quiet on
  legitimate activity - and you can prove it with the auid breakdown.

## MITRE ATT&CK mapping
```
Discovery
  |
  T1057 - Process Discovery (whoami, id, ps)
  T1082 - System Information Discovery (uname, hostname, ifconfig)
  |
  Rule 80792  (audited command)          Level 3
  Rule 100300 (recon command tagged)     Level 3
  Rule 100301 (recon burst correlated)   Level 12
```

## Status
Complete - Rule 100301 confirmed firing on the attack simulation
(auid 1000) across three separate runs, verified clean against root
and daemon noise. Rules 80792 / 100300 / 100301 verified.
