# Module 02 — Agent Enrollment

## Objective
Connect Kali Linux and Windows 11 endpoints to the Wazuh Manager
as monitored agents reporting security telemetry in real time.

## Agents enrolled
| ID | Hostname | OS | IP | Method |
|---|---|---|---|---|
| 002 | kali | Kali GNU/Linux 2025.4 | 192.168.1.161 | Manual key import |
| 003 | Priyanshu | Windows 11 Home | 192.168.1.13 | MSI silent install |

## Key challenges resolved
- NAT isolation: resolved by adding Bridged Adapter 2 to all VMs
- Version mismatch: agent 4.14.5 > manager 4.13.1, fixed by upgrading manager
- Duplicate agent name rejection: resolved by full registry wipe + manual key enrollment
- authd SSL certificate: regenerated with correct permissions

## Verification commands
```bash
sudo /var/ossec/bin/manage_agents -l
sudo /var/ossec/bin/wazuh-control status
sudo ss -tlnp | grep -E "1514|1515"
```

## Status
Complete — both agents active and reporting
