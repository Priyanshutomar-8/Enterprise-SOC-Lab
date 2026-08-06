# Module 04 - Windows Detection Lab

Attack simulations on the Windows 11 endpoint with detection verified in
Wazuh SIEM and mapped to MITRE ATT&CK. This module uses **native Windows
event logs** (Security / System / PowerShell channels); Sysmon-based
process/host telemetry is built separately in Module 05.

## Environment note
The endpoint runs **Windows 11 Home**, which has no Local Group Policy or
Security Policy editor (`gpedit.msc` / `secpol.msc`). Audit policy is
configured with `auditpol.exe` and PowerShell logging via the registry - a
CLI-driven workflow documented per lab.

## Labs

| # | Lab | Windows Event | MITRE | Custom Rule | Status |
|---|---|---|---|---|---|
| 01 | [Brute force](Lab01-Brute-Force.md) | 4625 | T1110.001 | 100400 | **Complete** |
| 02 | [Suspicious logon (RDP / admin)](Lab02-Suspicious-Logon.md) | 4624, 4672 | T1078 / T1021.001 | 100401 | **Complete** |
| 03 | [Rogue admin account](Lab03-Rogue-Admin-Account.md) | 4720, 4732 | T1136.001 / T1098 | 100402 | **Complete** |
| 04 | [Persistence: service / scheduled task](Lab04-Persistence.md) | 7045, 4698 | T1543.003 / T1053.005 | 100403, 100404 | **Complete** |
| 05 | [PowerShell abuse](Lab05-PowerShell-Abuse.md) | 4104 | T1059.001 / T1105 | 100405, 100406 | **Complete** |
| 06 | [Defense evasion: event log cleared](Lab06-Event-Log-Cleared.md) | 1102, 104 | T1070.001 | 100407 | **Complete** |
| 07 | [Defender tampering / exclusions](Lab07-Defender-Tampering.md) | 5007, 5013, 4104 | T1562.001 | 100408, 100409, 100410 | **Complete** |
| 08 | Ransomware: shadow-copy deletion | 4688 / 4104 (`vssadmin`/`wmic`) | T1490 | 100411 | Planned |
| 09 | Automation + AI-assisted triage (capstone) | Active Response + Claude API | - | - | Planned |

Custom detection rules are namespaced at **100400+**. The rule IDs have drifted
from the original plan because Labs 04 and 05 each needed two rules rather than
one, and Lab 07 needed three - two on the *result* of the tampering (Defender
channel) and one on the *method* (PowerShell script block).

## Log sources
Labs 01-04 read the Windows **Security** channel. Lab 05 is the first to
require a second channel - `Microsoft-Windows-PowerShell/Operational` - pushed
to the agent via a dedicated `windows` agent group rather than by editing
`ossec.conf` on the endpoint. Lab 06 uses Security + System. Lab 07 adds a third
channel, `Microsoft-Windows-Windows Defender/Operational`, through the same
agent group.

## Each lab includes
- Objective and MITRE ATT&CK mapping
- Windows audit-policy / logging prerequisites (`auditpol` / registry)
- Attack simulation commands
- Custom Wazuh detection rule
- Detection results and investigation steps
- Notes, limitations, and lessons learned

## Capstone (Lab 09) - Automation + AI-assisted triage
High-severity Windows alerts drive a defensive response pipeline:
- **Wazuh Active Response** auto-contains the threat (disable the account /
  block the source).
- An **AI enrichment step** sends the alert to the Claude API for a triage
  summary and MITRE context, written back to the case notes.

Defensive automation only. No credentials or API keys are committed to this
repository.

## Status
In progress - Labs 01 (brute force, 100400), 02 (suspicious/admin logon,
100401), 03 (rogue admin account, 100402), 04 (persistence via service /
scheduled task, 100403/100404), 05 (PowerShell download cradle,
100405/100406), 06 (event log cleared, 100407) and 07 (Defender tampering,
100408/100409/100410) complete and verified firing on a live Windows 11
endpoint. Labs 08-09 planned.

Defects in the **shipped** Wazuh ruleset documented along the way:

- **Lab 05** - rule 91837 matches `Invoke-Expresion` (misspelled), so a
  fully-spelled `Invoke-Expression` download-and-execute cradle raises no alert
  at all on a default install.
- **Lab 06** - log clearing alerts at level 5. The better rule (60117, level 9)
  is very likely unreachable because it loses a first-match race to a sibling,
  and it maps to `T1070.004` (File Deletion) rather than `T1070.001` (Clear
  Windows Event Logs). Wazuh's own sample event embedded above rule 63103 is
  also stale, showing fields under `eventdata` that the live event places under
  `logFileCleared`.
- **Lab 07** - Defender event 5013 (Tamper Protection blocked a change) has no
  shipped rule at all and is discarded at level 0; the ruleset's only `5013` is
  rule 60691, an unrelated Application-channel event sharing the number. Adding
  an exclusion and tuning scan CPU both alert as 62154 at level 5 with identical
  text. The shipped `Set-MpPreference` detection (92007/92008) requires Sysmon,
  so it cannot fire on a native-logs-only endpoint. The agent additionally
  reports `ERROR_EVT_CHANNEL_NOT_FOUND` (15007) as "The eventlog service is
  down", which points at the wrong fault.
