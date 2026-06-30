# Lab 01 — Linux User Creation Detection

## Objective
Simulate a backdoor user account creation by an attacker
and verify Wazuh detects it in real time.

## MITRE ATT&CK
| Field | Value |
|---|---|
| Tactic | Persistence |
| Technique | T1136.001 — Create Account: Local Account |
| Reference | https://attack.mitre.org/techniques/T1136/001/ |

## Why this matters
After gaining initial access, attackers frequently create local
accounts as persistence backdoors. Even if the initial compromise
vector is patched, the backdoor account remains active and gives
the attacker a way back in.

Real world example: In many ransomware attacks, the first thing
threat actors do after breaching a network is create a hidden admin
account before deploying the ransomware payload.

## Environment
| Component | Details |
|---|---|
| Agent | Kali GNU/Linux 2025.4 (192.168.1.161) |
| Manager | Ubuntu Server (192.168.1.79) |
| Wazuh version | 4.14.5 |

## Attack simulation

```bash
# Step 1 - Create backdoor user with bash shell
sudo useradd -m -s /bin/bash backdoor_user

# Step 2 - Set password (makes account usable)
sudo passwd backdoor_user

# Step 3 - Add to sudo group (privilege escalation)
sudo usermod -aG sudo backdoor_user

# Step 4 - Cleanup after lab
sudo userdel -r backdoor_user
```

## Detection result

| Field | Value |
|---|---|
| Rule ID | 5902 |
| Description | New user added to the system |
| Severity | Level 8 (Medium) |
| Agent | kali |
| Timestamp | Jun 30, 2026 @ 19:53:06 |
| Log source | /var/log/auth.log |

## Dashboard query used
rule.id:5902
## What Wazuh detected
- useradd command execution captured from auth.log
- New username, UID, home directory, and shell all logged
- Alert generated within seconds of command execution
- usermod to sudo group triggered additional privilege alert

## Investigation steps
1. Identify which account was created and at what time
2. Check if account was added to privileged groups (sudo, wheel)
3. Review auth.log for any login attempts under the new account
4. Determine if creation was authorized via change management
5. If unauthorized: disable account, preserve logs, escalate

```bash
# Investigate commands
sudo cat /etc/passwd | grep backdoor
sudo last backdoor_user
sudo grep backdoor /var/log/auth.log
```

## MITRE ATT&CK mapping
Initial Access → Execution → Persistence (T1136.001) → Privilege Escalation
↓
Create local backdoor account
↓
Add to sudo/admin group
## Lessons learned
- Linux user creation is instantly visible in Wazuh via auth.log monitoring
- Both useradd and usermod events generate separate alerts
- Real attackers use less obvious usernames (service accounts, system-looking names)
- This technique is commonly paired with T1098 (Account Manipulation)
- Detection works even without endpoint agent restart

## Status
Complete — alert confirmed in Wazuh dashboard
