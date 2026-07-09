# Lab 04 - SSH Brute Force Detection

## Objective
Simulate an SSH brute force attack using Hydra and verify
Wazuh detects it with high-severity threshold-based alerting.

## MITRE ATT&CK
| Field | Value |
|---|---|
| Tactic | Credential Access |
| Technique | T1110.001 - Brute Force: Password Guessing |
| Reference | https://attack.mitre.org/techniques/T1110/001/ |

## Why this matters
SSH brute force is one of the most common attack vectors on the
internet. Automated bots scan the entire IPv4 space continuously,
attempting thousands of username/password combinations against
any exposed port 22. In a real enterprise environment, internet-
facing SSH servers receive brute force attempts within minutes
of going online.

Real world example: The 2016 Mirai botnet infected 600,000+
devices primarily through SSH brute force using default credentials.
Detecting brute force early is critical once a password is found
the attacker has immediate persistent access.

## Environment
| Component | Details |
|---|---|
| Agent | Kali GNU/Linux 2025.4 (192.168.1.161) |
| Manager | Ubuntu Server (192.168.1.79) |
| Attack tool | Hydra v9.6 |
| Target | SSH on 127.0.0.1:22 |
| Wazuh version | 4.14.5 |

## Setup required
Kali 2025.4 uses systemd journald instead of traditional log files.
Wazuh agent config was updated to monitor journald:

```xml
<localfile>
  <log_format>journald</log_format>
  <location>journald</location>
  <filter>_SYSTEMD_UNIT=ssh.service</filter>
</localfile>
```

rsyslog was also installed to provide traditional auth.log support:
```bash
sudo apt-get install rsyslog -y
sudo systemctl restart rsyslog
```

## Attack simulation

```bash
# Create password wordlist
cat > /tmp/passwords.txt << 'PASSEOF'
password
123456
admin
root
toor
letmein
qwerty
abc123
password123
test123
welcome
monkey
dragon
master
sunshine
PASSEOF

# Run brute force against multiple usernames
hydra -l priyanshu -P /tmp/passwords.txt ssh://127.0.0.1 -t 4 -V
hydra -l root -P /tmp/passwords.txt ssh://127.0.0.1 -t 4 -V
hydra -l admin -P /tmp/passwords.txt ssh://127.0.0.1 -t 4 -V
```

## Detection results

### Total alerts generated: 744 hits

| Rule ID | Description | Severity | Count |
|---|---|---|---|
| 2502 | Syslog: User missed password more than once | Level 10 | High volume |
| 5760 | sshd: authentication failed | Level 5 | High volume |
| 5557 | unix_chkpwd: Password check failed | Level 5 | High volume |

### Key alert - Rule 2502 Level 10
Rule 2502 is the brute force threshold detection. When Wazuh sees repeated password failures from the same source within a short window, it escalates to Level 10 the highest tier before critical. In a production SOC this source within a short window, it escalates to Level 10, the highest tier before critical. In a production SOC this would trigger a P1 incident and automatic IP blocking.

### Alert timeline
All 744 alerts fired within a 10-second window (19:57:33 - 19:57:43)
confirming automated tooling rather than manual attempts.
Speed of attempts is itself an indicator humans cannot
type passwords faster than a few per minute.

## Dashboard queries used
- rule.id:5760
- rule.id:2502
- rule.id:5557
- rule.id:5712 OR rule.id:5720 OR rule.id:5760
- rule.group:authentication_failures
rule.id:5760;
rule.id:2502;
rule.id:5557;
rule.id:5712 OR rule.id:5720 OR rule.id:5760;
rule.group:authentication_failures
## What made this lab technically interesting
Kali Linux 2025.4 no longer uses traditional /var/log/auth.log
by default it uses systemd journald. This required:
1. Adding journald as a log source in Wazuh agent config
2. Installing rsyslog to restore traditional log file support
3. Restarting both rsyslog and wazuh-agent for changes to take effect

This is a real-world skill modern Linux distributions increasingly
use journald, and SOC teams must ensure their SIEM agents are
configured to collect from the correct log sources.

## Investigation steps
1. Identify source IP of brute force attempts
2. Check if any attempt was successful (rule 5715)
3. Block source IP at firewall level immediately
4. Check for successful logins around the same timeframe
5. Review all commands run if any session was established

```bash
# Investigation commands
sudo grep "Failed password\|Accepted password" /var/log/auth.log
sudo journalctl _COMM=sshd --since "1 hour ago" | grep -i "failed\|accepted"
sudo last | head -20
sudo netstat -tnp | grep :22
```

## MITRE ATT&CK mapping
Reconnaissance (T1595) → Credential Access (T1110.001)
↓
Hydra brute force — 15 passwords × 3 users
↓
744 authentication failures in 10 seconds
↓
Rules 5557, 5760 (individual) → 2502 (threshold breach)
↓
Level 10 alert - P1 incident
## Lessons learned
- 744 alerts from one tool run shows why alert fatigue is real
- Threshold-based rules (2502) are more actionable than individual failures
- Speed of attempts distinguishes automated tools from human error
- Modern Kali uses journald SIEM log source config matters
- Real brute force comes from external IPs add GeoIP context in production
- Fail2ban or similar should auto-block IPs after N failures

## Status
Complete - 744 alerts confirmed, Level 10 brute force rule triggered
## Critical finding - complete account takeover chain detected

### Rule 5715 - SSH authentication success (5 hits)
After the brute force, Wazuh detected SUCCESSFUL logins:

| Rule ID | Description | Severity | Significance |
|---|---|---|---|
| 5715 | sshd: authentication success | Level 3 | Login succeeded after brute force |
| 5555 | PAM: User changed password | Level 3 | Attacker changed root password |
| 5402 | Successful sudo to ROOT | Level 3 | Root access confirmed |

### Complete attack timeline (from Wazuh alerts)
- 18:04 — Brute force begins (rule 5763 level 10)
- 18:30 — SSH authentication success (rule 5715) ← password cracked
- 18:39 — Further successful logins
- 20:24 — Additional successful SSH sessions
- 20:25 — Successful sudo to ROOT (rule 5402)
- 20:25 — User password changed (rule 5555) ← attacker persistence
- 20:25 — Session closed (rule 5502)
### Why rule 5715 after brute force is a P0 incident
In a real SOC environment, seeing rule 5715 fire immediately
after rule 5763 is the worst possible outcome it means:
1. The brute force SUCCEEDED
2. The attacker now has valid credentials
3. They can return any time without triggering brute force alerts
4. If they changed the password, the legitimate owner is locked out

### Credentials found
- Target: root account
- Password found: toor (default Kali root password)
- Lesson: Default and weak passwords are found within seconds

### Remediation taken
- Root password changed to strong password
- SSH penalty activated automatically by srclimit
- Wazuh captured the full attack chain for forensic analysis
