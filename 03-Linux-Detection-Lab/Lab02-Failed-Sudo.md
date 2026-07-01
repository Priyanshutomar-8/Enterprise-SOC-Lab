# Lab 02 — Failed Sudo Attempts Detection

## Objective
Simulate an attacker attempting privilege escalation via repeated
failed sudo attempts and verify Wazuh detects the authentication failures.

## MITRE ATT&CK
| Field | Value |
|---|---|
| Tactic | Privilege Escalation |
| Technique | T1548.003 — Sudo and Sudo Caching |
| Secondary | T1078 — Valid Accounts |
| Reference | https://attack.mitre.org/techniques/T1548/003/ |

## Why this matters
After compromising a low-privilege account, attackers immediately
attempt privilege escalation. Repeated sudo failures from the same
user in a short timeframe is a strong indicator of an active
privilege escalation attempt. A legitimate user rarely fails sudo
more than once or twice.

Real world example: In post-exploitation phases, tools like LinPEAS
and sudo_killer automatically probe sudo misconfigurations. Each
probe generates authentication events that Wazuh captures.

## Environment
| Component | Details |
|---|---|
| Agent | Kali GNU/Linux 2025.4 (192.168.1.161) |
| Manager | Ubuntu Server (192.168.1.79) |
| Wazuh version | 4.14.5 |

## Attack simulation

```bash
# Step 1 - Create low privilege user (simulates compromised account)
sudo useradd -m -s /bin/bash lowpriv_user
sudo passwd lowpriv_user

# Step 2 - Switch to low privilege user
su - lowpriv_user

# Step 3 - Simulate attacker probing sudo (enter wrong password each time)
sudo whoami
sudo cat /etc/shadow
sudo su root
sudo id
sudo bash

# Step 4 - Return to main user
exit

# Step 5 - Cleanup
sudo userdel -r lowpriv_user
```

## Detection result

| Field | Value |
|---|---|
| Rule ID | 5503 |
| Description | PAM: User login failed |
| Severity | Level 5 (Medium) |
| Agent | kali |
| Timestamp | Jun 30, 2026 @ 20:51:19 |
| Log source | /var/log/auth.log |
| PAM module | PAM (Pluggable Authentication Module) |

## Dashboard queries used
rule.id:5503;
rule.id:5503 OR rule.id:5504;
rule.group:authentication_failed
## What Wazuh detected
- PAM authentication failure captured from auth.log
- Failed sudo attempt logged with username and source
- Alert generated within seconds of the failed command
- Rule 5503 fires on PAM-level authentication failure
- Rule 5504 fires specifically when user is not in sudoers file

## What PAM is
PAM (Pluggable Authentication Module) is the authentication
framework Linux uses for all login and privilege operations.
When sudo fails, PAM generates an event in auth.log which
Wazuh's log collector picks up and analyzes against its ruleset.

## Investigation steps
1. Identify the username that generated the failures
2. Count how many failures occurred and in what timeframe
3. Check if failures were followed by a successful login
4. Look for lateral movement from the same source IP
5. Correlate with other alerts from the same agent

```bash
# Investigation commands on Ubuntu manager
sudo grep "sudo\|authentication failure" /var/ossec/logs/alerts/alerts.log | tail -30
sudo grep "lowpriv_user" /var/log/auth.log
sudo last lowpriv_user
```

## Alert correlation - what to look for next
If you see rule 5503 in production, immediately check for:
- Rule 5902 (new user created) around the same time
- Rule 5501 (su root attempt)
- Rule 5712 (SSH brute force)

Multiple of these together = active attack in progress.

## MITRE ATT&CK mapping
Initial Access → Persistence → Privilege Escalation (T1548.003)
↓
Repeated failed sudo attempts
↓
PAM authentication failures
↓
Wazuh rule 5503 triggered
## Lessons learned
- Every sudo failure is logged and visible to Wazuh immediately
- PAM is the authentication layer Linux uses understanding it is key
- Real attackers use automated tools that generate dozens of attempts
- Threshold-based alerting (5+ failures = critical) improves signal quality
- Failed sudo is more suspicious than failed SSH, it means attacker is already inside

## Status
Complete — alert confirmed in Wazuh dashboard
