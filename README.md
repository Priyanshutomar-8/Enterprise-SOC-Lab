# Enterprise SOC Lab

A self-built Security Operations Center (SOC) lab implementing enterprise-grade
detection engineering, threat hunting, and incident response workflows using
Wazuh SIEM on a three-endpoint virtual network.

---

## Lab environment

| Component | Details |
|---|---|
| SIEM platform | Wazuh 4.14.5 (Manager + Indexer + Dashboard) |
| Manager node | Ubuntu Server — 192.168.1.79 |
| Linux endpoint | Kali GNU/Linux 2025.4 — 192.168.1.161 |
| Windows endpoint | Windows 11 Home — 192.168.1.13 |
| Hypervisor | Oracle VirtualBox (bridged networking) |
| Status | Active — all agents reporting |

---

## Modules

| # | Module | Status |
|---|---|---|
| 01 | [Wazuh Installation](./01-Wazuh-Installation/) | Complete |
| 02 | [Agent Enrollment](./02-Agent-Enrollment/) | Complete |
| 03 | [Linux Detection Lab](./03-Linux-Detection-Lab/) | Complete |
| 04 | [Windows Detection Lab](./04-Windows-Detection-Lab/) | Planned |
| 05 | [Sysmon](./05-Sysmon/) | Planned |
| 06 | [Active Directory](./06-Active-Directory/) | Planned |
| 07 | [Threat Hunting](./07-Threat-Hunting/) | Planned |
| 08 | [MITRE ATT&CK Mapping](./08-MITRE-Mapping/) | Planned |
| 09 | [Incident Response](./09-Incident-Response/) | Planned |

---

## Skills demonstrated

- SIEM deployment and multi-endpoint agent management
- Linux and Windows attack simulation and detection
- Detection rule writing and tuning
- MITRE ATT&CK framework mapping
- Incident response documentation
- Threat hunting methodology

---

## Each lab includes

- Objective and architecture
- Attack simulation commands
- Wazuh alert analysis
- MITRE ATT&CK mapping
- Detection screenshots
- Investigation steps
- Lessons learned

---

*Built and documented by Priyanshu — ongoing project*
