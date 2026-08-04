# Module 02 — Agent Enrollment

## Objective
Connect Kali Linux and Windows 11 endpoints to the Wazuh Manager
as monitored agents reporting security telemetry in real time.

## Agents enrolled
Current state, verified on the manager with `/var/ossec/bin/agent_control -l`:

| ID | Hostname | OS | IP | Method |
|---|---|---|---|---|
| 001 | kali | Kali GNU/Linux 2025.4 | 192.168.56.80 (host-only, static) | authd enrollment |
| 002 | windows | Windows 11 Home | 192.168.56.103 (host-only, DHCP) | MSI install |

> **Superseded:** an earlier revision of this table listed Kali as 002 and
> Windows as 003 on the `192.168.1.0/24` bridged network. Both the IDs and the
> addressing predate the lab rebuild, which moved every VM to a host-only
> network (`192.168.56.0/24`) for stability across WiFi changes and re-enrolled
> the agents. Always confirm with `agent_control -l` before quoting an agent ID.

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
