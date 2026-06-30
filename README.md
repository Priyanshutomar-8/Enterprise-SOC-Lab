# Enterprise SOC Lab

A self-built Security Operations Center (SOC) lab implementing enterprise-grade
detection engineering, threat hunting, and incident response workflows using
Wazuh SIEM on a three-endpoint virtual network.

## Lab environment
| Component | Details |
|---|---|
| SIEM platform | Wazuh 4.14.5 (Manager + Indexer + Dashboard) |
| Manager node | Ubuntu Server — 192.168.1.79 |
| Linux endpoint | Kali GNU/Linux 2025.4 — 192.168.1.161 |
| Windows endpoint | Windows 11 Home — 192.168.1.13 |
| Hypervisor | Oracle VirtualBox (bridged networking) |

## Modules
| # | Module | Status |
|---|---|---|
| 01 | Wazuh Installation | Complete |
| 02 | Agent Enrollment | Complete |
| 03 | Linux Detection Lab | In progress |
| 04 | Windows Detection Lab | Planned |
| 05 | Sysmon | Planned |
| 06 | Active Directory | Planned |
| 07 | Threat Hunting | Planned |
| 08 | MITRE ATT&CK Mapping | Planned |
| 09 | Incident Response | Planned |

*Built and documented by Priyanshu — ongoing project*
