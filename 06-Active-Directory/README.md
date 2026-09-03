# Module 06 - Active Directory

Detection engineering against a real Active Directory domain. Modules 04 and 05
built every detection on a single Windows endpoint; the flagship AD attacks -
Kerberoasting, AS-REP roasting, DCSync, LDAP reconnaissance - leave their traces
in events that **only a domain controller produces** (4768, 4769, 4662). This
module stands up a domain controller as both sensor and target, then builds
detections on that Kerberos and directory telemetry.

## Environment note
The domain controller runs **Windows Server 2022 Standard (Desktop Experience)**,
not the Windows 11 Home endpoint from Modules 04-05 - Home cannot host a domain or
even join one. The DC is the first (and only) controller of a new forest,
`lab.local`, and ships its **Security** event channel to the manager through the
same centralized mechanism the earlier modules used. Attacks in the later labs are
launched from **Kali + impacket** over the host-only network - the realistic
position of a remote attacker holding stolen low-privilege credentials.

## Labs

| # | Lab | Key events | MITRE | Custom Rule | Status |
|---|---|---|---|---|---|
| 01 | [Domain controller deployment, AD auditing, ingestion](Lab01-Domain-Controller-Deployment.md) | 4768, 4769, 4662 (enabled) | - (foundation) | - | **Complete** |
| 02 | [Kerberoasting](Lab02-Kerberoasting.md) | 4769 | T1558.003 | 100600 | **Complete** |
| 03 | [AS-REP roasting](Lab03-AS-REP-Roasting.md) | 4768 | T1558.004 | 100601 | **Complete** |
| 04 | [LDAP / BloodHound reconnaissance](Lab04-LDAP-Reconnaissance.md) | 4662, 1644 | T1087, T1069, T1482 | 100602* | **Investigation (detection gap)** |
| 05 | DCSync | 4662 | T1003.006 | 100603 | Planned |
| 06 | Golden Ticket / anomaly correlation (capstone) | 4769 | T1558.001 | 100604 | Planned |

Custom detection rules are namespaced at **100600+**, continuing from Module 05's
100500 block. Lab 01 writes no rule - it is a deployment and verification lab.
`100602*` (Lab 04) is **reserved but not firing**: the lab is an honest
detection-gap investigation - the telemetry (1644) was validated end to end, but
Wazuh does not route Directory Service eventchannel events into rule evaluation, so
no rule fires on them. See the lab writeup for the full evidence.

## Log source
One new channel for the module (already shipped by the default Windows agent
config, so no `ossec.conf` amendment is required):

```xml
<localfile>
  <location>Security</location>
  <log_format>eventchannel</log_format>
</localfile>
```

The events this module keys on (4768/4769/4662) are **not** logged by a default
domain controller - Lab 01 enables the audit subcategories that write them.

## Each lab includes
- Objective and MITRE ATT&CK mapping
- The attack, run from Kali/impacket against the DC
- The Windows events it generates on the domain controller
- Custom Wazuh detection rule
- Detection results with a full test matrix, including negative controls
- Notes, limitations, and lessons learned
