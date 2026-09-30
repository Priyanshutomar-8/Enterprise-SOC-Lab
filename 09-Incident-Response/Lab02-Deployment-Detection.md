# Lab 02 - Deployment Detection (service install)

## Objective
Detect the moment INC Ransom deploys its payload as a Windows service, and work the
alert as the first triage decision of an incident: *is this one host or the start of
a spread?* The cited INC artifact is a service named `winupd` pointing at
`%SystemRoot%\winupd.exe`, installed to run as `LocalSystem`. This lab reproduces
that service install with a harmless stand-in, tests what the shipped ruleset does
with it, and closes the gap that testing exposed.

**Attack is a benign stand-in.** The "payload" is `cmd.exe` copied to
`C:\Windows\winupd.exe` and registered as a service with native `sc.exe` - no
PsExec, no code execution, the service is never started. The detection keys on the
*service-install event* (7045), never on the binary, which is exactly what makes it
reusable against the real thing.

## Framing
| Field | Value |
|---|---|
| Discipline | Detection engineering + IR triage |
| INC link (Lab 05 rank) | PsExec cluster, #1: T1570 / T1569.002 / T1036.005 |
| ATT&CK | T1543.003 (Create/Modify System Process: Windows Service), T1569.002 (Service Execution) |
| Data source | Windows **System** channel, Service Control Manager event **7045** |
| Endpoint | Windows Sysmon endpoint, agent 002 (`C:\Windows\winupd.exe`) |
| Rule produced | **100900** (level 12) |
| Namespace | 100900+ |

## The attack (what was run on agent 002)
At an elevated PowerShell on the endpoint console:
```powershell
Copy-Item C:\Windows\System32\cmd.exe C:\Windows\winupd.exe -Force
sc.exe create winupd binPath= "C:\Windows\winupd.exe" type= own start= demand
```
`sc.exe create` alone reproduces INC's cited artifact - `winupd`,
`%SystemRoot%\winupd.exe`, demand start, `LocalSystem` - and emits System event
**7045 "A service was installed in the system."** **No PsExec is required to produce
the deployment signature**, which is itself a finding: the deployment event is the
service install, not the tool that performs it.

## Detection engineering

### The starting claim was wrong - there *is* a shipped rule
Module 08 Lab 05 ranked this PsExec/service-deployment cluster the #1 INC gap and
treated it as *uncovered*. That is wrong at the ID level. Wazuh 4.14.6 ships
**rule 92650 (level 12)** in `0840-win_event_channel.xml`, tagged
T1021.002/T1569.002, whose whole purpose is this:

```xml
<rule id="92650" level="12">
  <if_sid>61138</if_sid>   <!-- 7045: New Windows Service Created -->
  <field name="win.eventdata.imagePath">^%systemroot%\\\\\w+\.exe$</field>
  <description>New Windows Service Created to start from windows root path...</description>
</rule>
```
So the real Lab 02 question flipped from "build a missing rule" to **"does the
shipped rule actually fire, or is it another shipped-but-blind rule?"** (the pattern
seen repeatedly in Modules 05/06).

### Live fire: 92650 is blind - a brittle-regex evasion, not a coverage gap
Two service installs of `winupd` were live-fired. Both delivered the 7045, both
matched only **61138 (level 5, "New Windows Service Created")**. **92650 never
fired.** The event carried:
```
imagePath = C:\Windows\winupd.exe
```
92650's field expects the **literal token** `%systemroot%` at the start of the path.
The service registered the **expanded** drive path `C:\Windows\winupd.exe` - the same
file, the same directory - so the regex does not match. This is the important
distinction from Modules 05/06: the event reached the rule and decoded correctly
(61138 proves the pipeline end to end); 92650 is not blind to the *channel*, it is
**evadable by path representation.**

An attacker (or, here, `sc.exe`, and INC's own cited `C:\Windows\winupd.exe`
artifact) that writes the expanded path sails past the loud level-12 detection and
leaves only a level-5 event that most alerting never surfaces.

### Rule 100900 - catch the binary in the Windows root by *either* representation
```xml
<rule id="100900" level="12">
  <if_sid>61138</if_sid>
  <field name="win.eventdata.imagePath" type="pcre2">(?i)^"?(%systemroot%\\\\|[c-z]:\\\\windows\\\\)[^\\\\]+\.exe"?$</field>
  <description>Service installed with binary directly in Windows root ... - evades shipped 92650 via expanded path [INC Ransom winupd pattern, T1543.003/T1569.002]</description>
  <mitre><id>T1543.003</id><id>T1569.002</id></mitre>
</rule>
```
Design notes:
- Chains off **61138** (the 7045 base), so it is a sibling of 92650 under the same
  parent - same first-match tree, higher specificity.
- Alternation matches **both** `%systemroot%\<name>.exe` (what 92650 wanted) **and**
  `C:\Windows\<name>.exe` (what evades it). `(?i)` and `[c-z]:` cover case and drive
  letter.
- `[^\\]+` allows only **one path segment** after the root, so legitimate deep paths
  (`C:\Windows\System32\drivers\...`, `...\WinSxS\...`) do **not** trip it - it fires
  only on the unusual case of a service binary dropped directly in the Windows root,
  which is INC's exact shape.

## Test matrix (live fire on agent 002)
| # | Service imagePath | 61138 (L5) | 92650 (L12) | 100900 (L12) | Verdict |
|---|---|---|---|---|---|
| 1 | `C:\Windows\winupd.exe` (pre-100900) | fired | **silent** | n/a | 92650 evaded by expanded path |
| 2 | `C:\Windows\winupd.exe` (100900 v1, 2 backslashes) | fired | silent | **silent** | rule bug - see gotcha |
| 3 | `C:\Windows\winupd.exe` (100900 v2, 4 backslashes) | (superseded) | silent | **FIRED L12** | gap closed |

Confirmed 100900 alert (evidence record):
```
Alert:        100900  level 12  "Service installed with binary directly in Windows root..."
Fired at:     2026-09-30T20:44:00 UTC (collector; agent System-log wall time 4:32 PM local - ~4h skew, NTP off)
Host / agent: windows / 002
eventID:      7045   channel: System   serviceName: winupd   imagePath: C:\Windows\winupd.exe
MITRE:        T1543.003, T1569.002
```

## IR triage angle - one host or many?
The point of a level-12 service-install alert in an INC scenario is the **spread
question.** A single `winupd` install is a foothold; the same service name appearing
on multiple agents in a short window is lateral deployment in progress - the moment
to isolate before the encryptor runs. Triage steps for this alert:
1. Confirm true positive: 7045, `imagePath` in the Windows root, service not a known
   product (Brother `BrHostDrv`, Bitdefender `BdDci4`, etc. are legitimate 7045s and
   were observed as baseline noise on the endpoint - tune, do not alert on them).
2. Pivot on `serviceName` across **all** agents for the same name in the window.
3. Correlate with the surrounding process/account context (4688, logon events).
4. Containment (simulated, per Lab 01): isolate the host NIC; the account-disable and
   fleet-wide service-kill are documented as the production actions.

## Gotchas banked this session (real cost)
- **pcre2 backslash escaping in Wazuh XML = FOUR backslashes per literal `\`.** The
  shipped convention is `[c-z]:\\\\Windows\\\\.+\.exe`; Wazuh's XML reader collapses
  `\\\\`->`\\` before handing the pattern to PCRE2. 100900 v1 used two backslashes,
  which reached PCRE2 as a single `\` that escaped the next letter and **silently
  never matched** - the rule loaded, passed `wazuh-analysisd -t`, and did nothing.
  Copy the escaping from a shipped pcre2 path rule; do not hand-count.
- **`agent_control -R` on top of two manager restarts starved the manager.** SSH
  began timing out at banner exchange (the load-spike / D-state pattern). The fix was
  a **host-side reboot** (`VBoxManage controlvm Ubuntu acpipowerbutton` -> forced
  `poweroff` -> `startvm --type headless`), which also **flushed the stuck 7045**: an
  event generated locally but not yet forwarded shipped on the agent's reconnect.
  Lesson: do not stack a manager restart and a remote agent restart; batch the rule,
  restart once.
- **The endpoint is console-only.** Win 11 Home, auto-login `vboxuser`, no RDP; the
  privileged attack step must be run by a human at the VirtualBox console with UAC.
  Verify machine identity (`hostname` = `Windows`, manufacturer `innotek GmbH`,
  `WazuhSvc` running) before firing - the app terminal is always the host laptop.
- **Clocks are unmanaged** (NTP off): the collector timestamp and the endpoint's
  System-log wall time differ by ~4h. Reason about event **count and order**, not
  absolute time.

## Result
- Shipped **92650 does not cover** INC's cited service-deployment artifact - it is
  evaded by the expanded-path representation that `sc.exe` and INC both use. This
  refines Module 08 Lab 05: the gap is real, but it is a brittle-rule gap, not an
  absent-rule gap.
- **100900 (level 12)** closes it, live-verified firing on the exact event where
  92650 stayed silent, without tripping on legitimate deep-path service installs.
- Endpoint left clean (`sc delete winupd`, binary removed).

## Files
- Rule: `local_rules.xml` on the manager (100900).
- Namespace 100900+ ; next: Lab 03 (exfiltration), Lab 04 (RDP-with-context,
  deploys 100412 from Module 08).
