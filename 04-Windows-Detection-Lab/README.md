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
| 07 | Defender tampering / exclusions | 5007 + Defender Operational | T1562.001 | 100408 | Planned |
| 08 | Ransomware: shadow-copy deletion | 4688 / 4104 (`vssadmin`/`wmic`) | T1490 | 100409 | Planned |
| 09 | Automation + AI-assisted triage (capstone) | Active Response + Claude API | - | - | Planned |

Custom detection rules are namespaced at **100400+**. The rule IDs for Labs
06-08 shifted by one from the original plan because Labs 04 and 05 each needed
two rules rather than one.

## Log sources
Labs 01-04 read the Windows **Security** channel. Lab 05 is the first to
require a second channel - `Microsoft-Windows-PowerShell/Operational` - pushed
to the agent via a dedicated `windows` agent group rather than by editing
`ossec.conf` on the endpoint. Labs 06-08 will need the same treatment for the
Defender Operational channel.

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
100405/100406), and 06 (event log cleared, 100407) complete and verified
firing on a live Windows 11 endpoint. Labs 07-09 planned.

Two defects in the **shipped** Wazuh ruleset were documented along the way:

- **Lab 05** - rule 91837 matches `Invoke-Expresion` (misspelled), so a
  fully-spelled `Invoke-Expression` download-and-execute cradle raises no alert
  at all on a default install.
- **Lab 06** - log clearing alerts at level 5. The better rule (60117, level 9)
  is very likely unreachable because it loses a first-match race to a sibling,
  and it maps to `T1070.004` (File Deletion) rather than `T1070.001` (Clear
  Windows Event Logs). Wazuh's own sample event embedded above rule 63103 is
  also stale, showing fields under `eventdata` that the live event places under
  `logFileCleared`.
