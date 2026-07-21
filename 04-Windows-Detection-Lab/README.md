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
| 01 | Brute force | 4625 | T1110.001 | 100400 | Planned |
| 02 | Suspicious logon (RDP / admin) | 4624, 4672 | T1078 / T1021.001 | 100401 | Planned |
| 03 | Account creation + admin group add | 4720, 4732 | T1136.001 / T1098 | 100402 | Planned |
| 04 | Persistence: service / scheduled task | 7045, 4698 | T1543.003 / T1053.005 | 100403 | Planned |
| 05 | PowerShell abuse | 4104 | T1059.001 | 100404 | Planned |
| 06 | Defense evasion: event log cleared | 1102 | T1070.001 | 100405 | Planned |
| 07 | Defender tampering / exclusions | 5007 + Defender Operational | T1562.001 | 100406 | Planned |
| 08 | Ransomware: shadow-copy deletion | 4688 / 4104 (`vssadmin`/`wmic`) | T1490 | 100407 | Planned |
| 09 | Automation + AI-assisted triage (capstone) | Active Response + Claude API | - | - | Planned |

Custom detection rules are namespaced at **100400+**.

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
In progress - planning complete; Lab 01 (brute force) build underway.
