# Lab 01 - Sysmon Deployment, Config Audit, and Ingestion

## Objective
Deploy Sysmon on the Windows 11 endpoint, ship its channel to Wazuh, and prove
the telemetry arrives - then use it to test a detection that Module 04 proved
was unreachable without it.

Module 04 built eight detections entirely from **native Windows event logs**
(Security, System, PowerShell/Operational, Defender/Operational). Three of its
documented defects exist *because* of that constraint:

| Module 04 lab | Gap | Cause |
|---|---|---|
| Lab 07 | Rules 92007/92008 (`Set-MpPreference` tampering) never fire | Both require Sysmon |
| Lab 08 | Event 4688 carries no command line by default | Native auditing; needs a registry key |
| all | No visibility into process access, image loads, or per-process network | No native equivalent exists |

Sysmon is the sensor that closes those. This lab is the foundation the rest of
Module 05 stands on, so it ends with a **falsifiable test**: re-run the Lab 07
Defender-tampering attack and confirm the previously-unreachable rules now fire.

They do - but only under conditions narrow enough that the finding became the
headline of the lab.

## MITRE ATT&CK
The deployment itself maps to nothing; the closing test does.

| Field | Value |
|---|---|
| Tactic | Defense Evasion |
| Technique | T1562.001 - Impair Defenses: Disable or Modify Tools |
| Reference | https://attack.mitre.org/techniques/T1562/001/ |

## Environment
| Component | Details |
|---|---|
| Endpoint | Windows 11 Home - agent ID 002 `windows`, 192.168.56.103 |
| Manager | Ubuntu Server, Wazuh 4.14.6 all-in-one, 192.168.56.79 |
| Sensor | Sysmon **v15.21** (x64), schema version 4.91 |
| Config | SwiftOnSecurity `sysmonconfig-export.xml`, schema version **4.50** |
| New log source | `Microsoft-Windows-Sysmon/Operational` |
| Manager RAM | 2968 MB total, ~1100 MB available, 630 MB swap already in use |

Rule namespace **100500+** is reserved for Module 05. This lab writes no custom
rule - its findings are all about the shipped ruleset and the sensor config.

## Deployment

### Verifying the binary before running it
Sysmon was downloaded from Sysinternals and its Authenticode signature checked
*before* execution, rather than after.

```powershell
Get-AuthenticodeSignature "C:\Tools\Sysmon\Sysmon64.exe" |
  Format-List Status, StatusMessage, SignerCertificate
```

```
Status        : Valid
StatusMessage : Signature verified.
Subject       : CN=Microsoft Windows Publisher, O=Microsoft Corporation
Issuer        : CN=Microsoft Windows Production PCA 2011
Not Before    : 9/18/2025      Not After : 9/8/2026
Thumbprint    : B84270C6D037916FE012F4727BB0A00C353ACA08
```

The signing certificate **expires 8 Sep 2026** - 29 days after this lab was run.
The binary does not stop validating on that date, because the signature is
**countersigned by a timestamping authority**:

```powershell
(Get-AuthenticodeSignature "C:\Tools\Sysmon\Sysmon64.exe").TimeStamperCertificate |
  Format-List Subject, NotAfter
```

```
Subject  : CN=Microsoft Time-Stamp Service, OU=Microsoft Ireland Operations Limited
NotAfter : 11/13/2026
```

Validation asks whether the certificate was valid **at signing time**, not
whether it is valid today. Without a countersignature, every signed binary would
become untrusted the moment its signing cert expired.

Two caveats recorded deliberately, because they matter for Lab 04 of this module:

- `Status: Valid` proves **integrity and publisher identity**. It does not prove
  the software is safe. Sysmon is trustworthy because it is Microsoft's, not
  because it carries a signature.
- The **config file is not signed**. `sysmonconfig-export.xml` is community XML
  pulled from GitHub over HTTPS. Trust in it is trust in a maintainer, not in a
  cryptographic chain. It was therefore audited before deployment (below).

### Install
```powershell
C:\Tools\Sysmon\Sysmon64.exe -accepteula -i C:\Tools\Sysmon\sysmonconfig.xml
```

```
Loading configuration file with schema version 4.50
Sysmon schema version: 4.91
Configuration file validated.
Sysmon64 installed.  SysmonDrv installed.  Sysmon64 started.
```

**The config is four schema revisions behind the binary.** It works, but newer
event types (`FileDelete`, `FileBlockExecutable`, `FileExecutableDetected`) are
not configured at all. No coverage is claimed for them anywhere in this module.

## Config audit - what the baseline actually enables
The community config was read before being trusted, not after something failed
to fire.

```powershell
Select-String -Path "C:\Tools\Sysmon\sysmonconfig.xml" -Pattern '<([A-Za-z]+) onmatch="([a-z]+)"' -AllMatches |
  ForEach-Object { $_.Matches } |
  ForEach-Object { "{0,-26} {1}" -f $_.Groups[1].Value, $_.Groups[2].Value } |
  Sort-Object -Unique
```

`include` is an **allow-list** (log nothing except explicit matches). `exclude`
is a **deny-list** (log everything except filtered noise). The distinction
decides whether a technique is visible at all.

| Event | EID | Mode | Consequence for Module 05 |
|---|---|---|---|
| ProcessCreate | 1 | exclude | Broad coverage. Fine. |
| NetworkConnect | 3 | both | Filtered but present. |
| DriverLoad | 6 | exclude | Present. |
| **ImageLoad** | **7** | **include, EMPTY** | **Effectively disabled - an empty include logs nothing (corrected during Lab 04; source v74 ships no entries here). A sideloaded DLL is invisible until Lab 04's config amendment.** |
| CreateRemoteThread | 8 | exclude | Present. |
| **ProcessAccess** | **10** | **include, EMPTY** | **Effectively disabled - Lab 02 needs a config amendment.** |
| RegistryEvent | 12/13/14 | both | Present. |
| FileCreateStreamHash | 15 | both | Present - Lab 06 usable. |
| DnsQuery | 22 | exclude | Highest-volume source in the config. |
| ProcessTampering | 25 | exclude | Present. |

The `ProcessAccess` block is empty, and the config says so in its own comment:

```xml
<ProcessAccess onmatch="include">
  <!--NOTE: Using "include" with no rules means nothing in this section will be logged-->
</ProcessAccess>
```

**EID 10 - the event that detects LSASS credential dumping - is off by default
in the most widely deployed community Sysmon config.** SwiftOnSecurity excludes
it for volume reasons, which is a defensible engineering choice, but an operator
who deploys this config and assumes "I have Sysmon, I can see credential access"
is wrong. Same for EID 7 and signature-based DLL analysis.

## Volume baseline - measured before enabling ingestion
The manager is a 3 GB all-in-one that has previously been starved into
unresponsiveness. Ingestion volume was measured on the endpoint *before* the
channel was shipped.

```powershell
$start = (Get-WinEvent -ListLog "Microsoft-Windows-Sysmon/Operational").RecordCount
Start-Sleep -Seconds 180
$end = (Get-WinEvent -ListLog "Microsoft-Windows-Sysmon/Operational").RecordCount
"Baseline: {0} events in 180s = {1:N1} events/min" -f ($end - $start), (($end - $start) / 3)
```

```
Baseline: 2 events in 180s = 0.7 events/min
```

Idle distribution on the endpoint: 65x EID 1, 6x EID 13, 5x EID 22, 2x EID 3,
and single instances of 16, 4 and 8.

0.7 events/min at idle is negligible. **Idle is not load** - attack simulations
spike it, and `DnsQuery` on a deny-list is the first candidate for a `<query>`
filter if it ever matters. Recorded so the decision is revisitable rather than
assumed.

## Shipping the channel to Wazuh
Pushed via the centralized **`windows` agent group**, the same mechanism used for
Lab 05's PowerShell channel and Lab 07's Defender channel. The Windows VM has no
SSH, so every local `ossec.conf` edit is a manual console step; group config
avoids that, and keeps a Windows-only `localfile` off the Linux agent.

```xml
<localfile>
  <location>Microsoft-Windows-Sysmon/Operational</location>
  <log_format>eventchannel</log_format>
</localfile>
```

Appended to `/var/ossec/etc/shared/windows/agent.conf` with a **pattern-matched**
`sed` on the closing tag, not a line-numbered one - line numbers are not stable
across edits and broke this manager in a previous session.

Two operational details worth keeping:

1. **`sed -i` changes file ownership.** It writes a temporary file and renames
   it, so a root-run edit leaves the file `root:root`. Wazuh then cannot read its
   own config. Ownership must be restored to `wazuh:wazuh 0660` afterwards.
2. **No manager restart is needed for `agent.conf`.** `wazuh-remoted` detected the
   change and rebuilt `merged.mg` on its own within the same minute. A manager
   restart is only required for manager-side `ossec.conf` or new rule/decoder
   files. On a swap-pressured box, the safest restart is the one you avoid.

Validated before deploying:

```
# /var/ossec/bin/verify-agent-conf
verify-agent-conf: Verifying [etc/shared/windows/agent.conf]
verify-agent-conf: OK
```

The agent pulled the config and subscribed on its next keepalive:

```
2026/08/10 13:45:05 wazuh-agent: INFO: (1951): Analyzing event log:
  'Microsoft-Windows-Sysmon/Operational'.
```

That log line - not the presence of `merged.mg` on disk - is the proof the
config took effect.

## Ingestion verification
Most shipped Sysmon rules sit at **level 0**: decoded, deliberately not alerted.
`alerts.json` can therefore be empty while ingestion works perfectly. **Absence
of alerts is not absence of data.** Seeing level-0 events requires archives:

```xml
<logall_json>yes</logall_json>
```

Enabled for the duration of Module 05 and to be disabled at its end.

Events arriving at the manager, by event ID:

| EID | Endpoint (idle) | Manager (post-enable) |
|---|---|---|
| 1 - ProcessCreate | 65 | 40 |
| 22 - DnsQuery | 5 | 19 |
| 3 - NetworkConnect | 2 | 6 |
| 13 - RegistryValueSet | 6 | 5 |
| 5 - ProcessTerminate | - | 3 |

Different windows, and the endpoint was suspended for nine minutes across a
manager restart, so the counts are not expected to match. The **shape** matches,
and no event type is missing.

### Two self-referential traps
Both cost time and are worth naming:

- Grepping `archives.json` for `Microsoft-Windows-Sysmon/Operational` returned a
  match with **zero Sysmon events present** - the manager's own `sudo` audit
  record of the `grep` command contained the search string.
- The same grep later counted EID `4104` and `4688` as if they were Sysmon
  events. They were PowerShell script-block and process-creation records of the
  **investigator's own `Get-WinEvent` commands**, which contained the channel
  name as an argument.

**Hunting activity contaminates the dataset being hunted.** Filter to the channel
first, then extract, rather than matching a raw string across whole records.

### Field paths
Confirmed by replaying an event, since guessing field names cost time in Lab 08
(`new Value` carries a literal space):

```
win.eventdata.image          : 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe'
win.eventdata.commandLine    : '"C:\\WINDOWS\\...\\powershell.exe" -Command "Set-MpPreference ..."'
win.eventdata.parentImage    : 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe'
win.eventdata.originalFileName : 'PowerShell.EXE'
win.eventdata.hashes         : 'MD5=...,SHA256=...,IMPHASH=...'
win.eventdata.integrityLevel : 'High'
win.system.eventID           : '1'
```

**Backslashes are doubled in `eventdata`.** Every path regex in this module must
account for it - which is why shipped rule 92003 matches
`\\\\Users\\\\Public\\\\` while 92007 uses the looser `\\powershell\.exe`.

## Closing test - does Sysmon reopen the Lab 07 gap?
Lab 07 recorded that Wazuh's `Set-MpPreference` detection "requires Sysmon, so it
cannot fire on a native-logs-only endpoint." Sysmon is now present, so the claim
is testable.

The shipped chain, read before running anything:

```xml
<rule id="92007" level="3">
  <if_group>sysmon_event1</if_group>
  <field name="win.eventdata.image" type="pcre2">(?i)\\powershell\.exe</field>
  <field name="win.eventdata.commandLine" type="pcre2">(?i)Set-MpPreference</field>
  <description>Possible tampering on Windows Defender configuration by Powershell command</description>
</rule>

<rule id="92008" level="12">
  <if_sid>92007</if_sid>
  <field name="win.eventdata.commandLine" type="pcre2">(?i)(DisableRealtimeMonitoring|drtm)\s+(\$true|1)</field>
  <description>Windows Defender real time monitoring was disabled by Powershell command</description>
</rule>
```

Two weaknesses are visible on inspection, before any test:

- `92007` keys off **`sysmon_event1`** - process creation. A command typed into an
  *already running* shell creates no process and emits no EID 1.
- `92008` requires `\s+` - **whitespace** between parameter and value. PowerShell
  also accepts colon binding (`-DisableRealtimeMonitoring:1`), which is
  functionally identical and contains no whitespace.

### Test matrix
Value `1` used throughout rather than `$true`; the rule regex accepts both, and
`1` survives shell quoting intact.

| Test | Parent | Form | Expected | Result |
|---|---|---|---|---|
| A | powershell.exe | `-DisableRealtimeMonitoring $true` | 92008 L12 | **92027 L4** |
| B | powershell.exe | `-DisableRealtimeMonitoring:1` | 92007 L3 | **92027 L4** |
| C | *(interactive, no new process)* | `-DisableRealtimeMonitoring $false` | nothing | **nothing** |
| D | cmd.exe | `-DisableRealtimeMonitoring 1` | 92008 L12 | **92008 L12 - passed** |
| E | cmd.exe | `-DisableRealtimeMonitoring:1` | 92007 L3 | **92007 L3 - passed** |

```
92008 12 | powershell.exe  -Command Set-MpPreference -DisableRealtimeMonitoring 1
92007  3 | powershell.exe  -Command Set-MpPreference -DisableRealtimeMonitoring:1
```

Rule **92027 fired 5 times** - every powershell-parented attempt.

`RealTimeProtectionEnabled` remained `True` and `IsTamperProtected` remained
`True` for the entire test. **Tamper Protection blocked the change; the
detections fired anyway**, because they match the command line rather than the
outcome. Detecting a blocked attack is correct behaviour and worth stating
explicitly - the alert is evidence of intent, not of success.

## Findings

### 1. Rule 92007 is shadowed by rule 92027 (high)
Both are direct siblings under `if_group sysmon_event1`:

| Rule | Line | Level | Conditions |
|---|---|---|---|
| 92007 | 84 | 3 | image=powershell, commandLine=`Set-MpPreference` |
| 92027 | 297 | 4 | image=powershell, parentImage=powershell |

A PowerShell process launching PowerShell to run `Set-MpPreference` satisfies
**both**. 92007 sits 213 lines earlier and has the lower rule ID, yet **92027
won every time**. Isolating the cause by swapping the parent to `cmd.exe` - which
breaks 92027's `parentImage` condition and nothing else - made 92007 fire
immediately. The overlap is the whole cause.

The consequence: an attacker disabling Defender real-time protection from a
PowerShell-hosted tool - the ordinary shape of PowerShell-based offensive
tooling - generates **"Powershell process spawned powershell instance", level 4,
T1059.001** instead of **"Windows Defender real time monitoring was disabled",
level 12, T1562.001**. Wrong severity, wrong technique, wrong description. It
would not page anyone.

This is qualitatively worse than Module 04's defects. Lab 05's `Invoke-Expresion`
was a typo; Lab 08's T1490 was an honest blank. This is a **low-value
informational rule suppressing a high-severity one**, silently, on the common
path.

*Not established:* whether Wazuh orders siblings by level, or by some other
property. One data point (level 4 beating level 3 despite later file position and
higher ID) is enough to prove the shadowing, not enough to explain the mechanism.
Worth confirming against Wazuh's rule-tree construction before the claim is made
more broadly.

### 2. Rule 92008's regex is evaded by colon parameter binding (medium)
`(DisableRealtimeMonitoring|drtm)\s+(\$true|1)` requires whitespace.
`-DisableRealtimeMonitoring:1` is functionally identical PowerShell and does not
match, downgrading a level-12 alert to level 3. Confirmed in Test E. Prefix
abbreviation (`-DisableRealtimeMon 1`) is a second untested variant of the same
weakness.

### 3. Rule 92007 cannot see interactive execution (medium)
It requires Sysmon EID 1. Running `Set-MpPreference` at an existing PowerShell
prompt creates no process and produces no EID 1, so the rule cannot fire (Test
C). Only the scripted, spawn-a-process form is covered - while an interactive
shell is the normal condition after initial access.

### 4. `wazuh-logtest -l EventChannel` does not replay eventchannel events (tooling)
Feeding a captured Sysmon event back through logtest decoded it with the generic
`json` decoder rather than `windows_eventchannel`, and produced **no Phase 3 at
all** - zero rules evaluated. Field extraction was correct; rule matching never
happened. Rule-precedence questions had to be answered from `archives.json`,
which records the rule that matched each event. Adds to the Lab 08 note that
`wazuh-logtest -t` does not exist.

## Notes and limitations
- **No custom rule was written.** This is a deployment lab; 100500+ is reserved
  for the detection labs that follow. The findings are properties of the shipped
  ruleset and the community config.
- **Labs 02 and 04 are blocked on config amendments.** EID 10 (`ProcessAccess`) is
  empty and EID 7 (`ImageLoad`) is a narrow allow-list. Both need targeted
  additions - which is itself the more instructive exercise, since the tuning is
  the detection engineering.
- **Test attribution is partly inferred.** Five EID 1 records carrying
  `Set-MpPreference` reached the manager and the alert counts match the matrix,
  but individual events at the same second were not correlated one-by-one to
  invocations.
- **Sibling-precedence conclusion is scoped to this pair.** 92007 vs 92027 is
  demonstrated. Whether the same shadowing affects other rule pairs in
  `0800-sysmon_id_1.xml` (82 rules) is untested.
- **The volume baseline is idle-state only.** No load test was performed; the
  3 GB manager's behaviour under sustained Sysmon ingestion during an attack
  simulation is unknown.
- **`logall_json` is temporarily enabled** and must be turned off at the end of
  Module 05. The archive was already 39 MB before this lab.

## Lessons learned
- **Audit a sensor config before trusting it, not after a detection fails.**
  Reading the SwiftOnSecurity config took two minutes and revealed that the two
  highest-value event types for this module were disabled. Discovering that
  through a silent Lab 02 would have cost hours and looked like a broken rule.
- **`include` versus `exclude` is the whole ballgame.** An allow-list with no
  entries is a disabled sensor that looks configured. "We have Sysmon" says
  nothing about what Sysmon is watching.
- **Diff every config edit against a `cp -p` backup before restarting the
  service.** A `sed` one-liner containing an unescaped `...` - regex for *any
  three characters* - replaced the first three characters of **every line** in
  `ossec.conf`, corrupting all ~240 of them. The manager refused to start. It was
  caught and reverted in under two minutes because a `-p` backup existed and
  `diff` was run before the restart. The control is the diff, not "be careful
  with sed".
- **Absence of alerts is not absence of data.** Level-0 rules mean a working
  pipeline can look identical to a broken one in `alerts.json`. Verify ingestion
  against archives before debugging rules.
- **Your own investigation is telemetry.** Two separate greps matched the
  investigator's own commands rather than the attack. On a monitored host, the
  analyst is part of the dataset.
- **Signed does not mean safe, and expired does not mean invalid.** Every
  malicious PowerShell command in this lab ran from a Microsoft-signed binary
  with a valid signature. Meanwhile the signature on Sysmon itself outlives its
  certificate because of countersigned timestamping. Both facts matter when
  reasoning about EID 7 in Lab 04.
- **The test harness shapes the result.** Running the attack from PowerShell
  instead of `cmd.exe` changed which rule fired, from a level-12 detection to a
  level-4 informational. The same lesson as Lab 08's `{default}` mangling, in a
  more consequential form: **validate detections against the process ancestry a
  real attack produces.**

## MITRE ATT&CK mapping
```
Impair Defenses: Disable or Modify Tools (T1562.001)
  |
  +-- Sysmon Event 1 (process creation)  [requires Sysmon - absent in Module 04]
        |
        +--> sysmon_event1
               |
               +--> 92027  Level 4  "Powershell spawned powershell"  [T1059.001]
               |      ^
               |      +-- WINS whenever parent is powershell.exe  <-- SHADOWING
               |
               +--> 92007  Level 3  "Possible tampering on Defender config"  [T1562]
                      |
                      +--> 92008  Level 12  "Real time monitoring disabled"  [T1562.001]
                             ^
                             +-- requires whitespace before the value  <-- EVADED by ':1'
```

## Status
Complete - Sysmon v15.21 deployed on a live Windows 11 endpoint with its
Authenticode signature and timestamp countersignature verified before execution,
the community config audited before trust, an idle volume baseline measured
before ingestion, and the `Microsoft-Windows-Sysmon/Operational` channel shipped
through the centralized `windows` agent group. End-to-end ingestion confirmed
with no event types lost.

The closing test confirmed Lab 07's claim - the shipped `Set-MpPreference`
detection chain **is** reachable once Sysmon is present - and then found that it
is reachable only when the attack is *not* launched from PowerShell. Rule 92007
is shadowed by rule 92027 for every PowerShell-parented invocation, converting a
level-12 Defender-tampering alert into a level-4 informational one; rule 92008 is
independently evaded by colon parameter binding; and neither rule can see
interactive execution at all. Tamper Protection blocked every change attempt, and
the detections fired on the attempt regardless.

Four findings recorded, three of them defects in the shipped ruleset. No custom
rule was written; Labs 02 and 04 are blocked pending Sysmon config amendments for
`ProcessAccess` (EID 10) and `ImageLoad` (EID 7), both of which the community
baseline leaves effectively disabled.
