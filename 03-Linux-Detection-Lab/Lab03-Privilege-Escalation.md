# Lab 03 — Privilege Escalation Detection

## Objective
Simulate multiple privilege escalation techniques on a Linux endpoint
and verify Wazuh detects both failed attempts and successful root access.

## MITRE ATT&CK
| Field | Value |
|---|---|
| Tactic | Privilege Escalation |
| Technique | T1548 - Abuse Elevation Control Mechanism |
| Sub-technique | T1548.003 - Sudo and Sudo Caching |
| Secondary | T1078.003 - Valid Accounts: Local Accounts |
| Reference | https://attack.mitre.org/techniques/T1548/ |

## Why this matters
Privilege escalation is the most critical phase of an attack
it is the moment an attacker transitions from limited user access
to full system control. Once root is achieved, the attacker can:
- Read all files including /etc/shadow (password hashes)
- Install persistent backdoors
- Disable security tools including Wazuh itself
- Move laterally to other systems

Real world example: In the 2021 SolarWinds attack, privilege
escalation was used to gain SYSTEM-level access before deploying
the SUNBURST backdoor. Detecting this phase is critical to
stopping attacks before they cause irreversible damage.

## Environment
| Component | Details |
|---|---|
| Agent | Kali GNU/Linux 2025.4 (192.168.1.161) |
| Manager | Ubuntu Server (192.168.1.79) |
| Wazuh version | 4.14.5 |

## Attack simulation

```bash
# Step 1 - Attempt direct su to root (wrong password)
su root

# Step 2 - SUID binary reconnaissance (attacker maps escalation paths)
find / -perm -4000 -type f 2>/dev/null

# Step 3 - Attempt to write to sensitive file
sudo bash -c 'echo "test" >> /etc/crontab'

# Step 4 - Attempt shadow file access
cat /etc/shadow

# Step 5 - Check sudo permissions (attacker reconnaissance)
sudo -l

# Step 6 - Successful escalation to root
sudo su
whoami
exit
```

## Detection results - multiple rules fired

| Rule ID | Description | Severity | Trigger |
|---|---|---|---|
| 5402 | Successful sudo to ROOT executed | Level 3 | sudo su succeeded |
| 5301 | User missed password to change UID | Level 5 | Wrong password on su |
| 5503 | PAM: User login failed | Level 5 | Authentication failure |
| 5501 | PAM: Login session opened | Level 3 | New session created |
| 5502 | PAM: Login session closed | Level 3 | Session terminated |

## Key alert - Rule 5402
Rule 5402 is the most critical detection here.
"Successful sudo to ROOT executed" means the escalation
succeeded an attacker has root. In a real SOC environment
this would trigger an immediate P1 incident response.

## Dashboard queries used
- rule.id:5501
- rule.id:5402
- rule.id:5301
- rule.group:syscheck
- rule.description:su
## Alert correlation - the full attack story
Reading the alerts in sequence tells the complete attack narrative:
- 21:13:34 - PAM session opened    (attacker gains initial foothold)
- 21:14:08 - Successful sudo ROOT  (first escalation attempt succeeds)
- 21:14:30 - Successful sudo ROOT  (confirms root access)
- 21:14:31 - PAM session opened    (new root session started)
- 21:14:45 - Successful sudo ROOT  (repeated root access)
- 21:14:59 - User missed password  (tried su with wrong password)
- 21:15:05 - PAM session closed    (attacker cleans up session)
- This timeline shows an attacker methodically escalating and
establishing root access, a textbook privilege escalation chain.

## Investigation steps
1. Identify which user account performed the sudo to root
2. Determine if this was an authorized administrative action
3. Check what commands were run as root after escalation
4. Review all file changes made during the root session
5. Check for new files, cron jobs, or user accounts created

```bash
# Investigation commands on Ubuntu manager
sudo grep "sudo.*ROOT\|su root" /var/ossec/logs/alerts/alerts.log | tail -20
sudo grep "priyanshu\|root" /var/log/auth.log | tail -30
sudo last root
sudo find / -newer /tmp -type f 2>/dev/null | head -20
```

## Why multiple rules fire for one attack
Each rule captures a different layer of the same event:
- 5301 captures the PAM-level password failure
- 5402 captures the successful sudo elevation
- 5501/5502 captures session lifecycle
Together they give a complete picture failed attempt
followed by successful escalation is the clearest possible
indicator of privilege escalation.

## MITRE ATT&CK mapping
Reconnaissance → Initial Access → Execution → Privilege Escalation
↓
T1548.003 sudo abuse
↓
find SUID binaries (T1082)
↓
sudo su → root achieved
↓
Rules 5301, 5402, 5501, 5502, 5503
## Lessons learned
- Wazuh captures the complete escalation chain, not just one event
- Rule 5402 (successful root) is more critical than 5503 (failed attempt)
- Timeline correlation reveals attacker intent and sequence
- SUID reconnaissance itself should trigger investigation
- Root sessions opened outside business hours = immediate P1

## Status
Complete - 5 distinct rule IDs confirmed in Wazuh dashboard
