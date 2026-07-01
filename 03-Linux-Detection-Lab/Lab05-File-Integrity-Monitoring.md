# Lab 05 — File Integrity Monitoring (FIM)

## Objective
Simulate an attacker modifying critical system files and verify
Wazuh FIM detects every change in real time with cryptographic precision.

## MITRE ATT&CK
| Field | Value |
|---|---|
| Tactic | Impact / Persistence |
| Technique | T1565.001 — Stored Data Manipulation |
| Secondary | T1136.001 — Create Account (via /etc/passwd) |
| Third | T1053.003 — Cron Persistence |
| Reference | https://attack.mitre.org/techniques/T1565/001/ |

## Why this matters
File integrity monitoring is one of the most reliable detection
techniques in security. Every serious attack eventually touches
the filesystem — adding backdoor users, planting malware, modifying
configurations. FIM catches these changes regardless of how the
attacker got in or what tools they used.

Real world example: In the 2020 SolarWinds supply chain attack,
attackers modified the SolarWinds Orion build system files to
inject malicious code. FIM on the build server would have detected
the checksum change immediately.

## Environment
| Component | Details |
|---|---|
| Agent | Kali GNU/Linux 2025.4 (192.168.1.161) |
| Manager | Ubuntu Server (192.168.1.79) |
| FIM mode | Real-time (inotify) |
| Wazuh version | 4.14.5 |

## FIM Configuration applied
Default Wazuh config had no directories defined.
Updated /var/ossec/etc/ossec.conf with:

```xml
<syscheck>
  <disabled>no</disabled>
  <frequency>300</frequency>
  <scan_on_start>yes</scan_on_start>

  <directories realtime="yes" check_all="yes">
    /etc/passwd,/etc/shadow,/etc/group,/etc/sudoers
  </directories>
  <directories realtime="yes" check_all="yes">
    /etc/hosts,/etc/hostname,/etc/resolv.conf
  </directories>
  <directories realtime="yes" check_all="yes">
    /etc/cron.d,/etc/crontab,/var/spool/cron
  </directories>
  <directories realtime="yes" check_all="yes">
    /bin,/sbin,/usr/bin,/usr/sbin
  </directories>
  <directories realtime="yes" check_all="yes">
    /tmp,/var/tmp
  </directories>

  <ignore>/etc/mtab</ignore>
  <ignore>/etc/hosts.deny</ignore>
  <ignore>/etc/adjtime</ignore>
</syscheck>
```

Key settings:
- realtime="yes" uses Linux inotify for instant detection
- check_all="yes" monitors permissions, ownership, size, and hash
- frequency=300 means full scan every 5 minutes

## Attack simulation

```bash
# Attack 1 - Modify passwd (backdoor user preparation)
sudo bash -c 'echo "# attacker was here" >> /etc/passwd'

# Attack 2 - Modify hosts (DNS poisoning)
sudo bash -c 'echo "1.2.3.4 malicious.bank.com" >> /etc/hosts'

# Attack 3 - Plant suspicious binary
sudo touch /bin/suspicious_binary
sudo chmod +x /bin/suspicious_binary

# Attack 4 - Modify sudoers (privilege persistence)
sudo bash -c 'echo "# test" >> /etc/sudoers'

# Attack 5 - Create malicious cron job (persistence)
sudo bash -c 'echo "* * * * * root /bin/bash -c id" > /etc/cron.d/malicious_job'
```

## Detection results — 64 hits

| Rule ID | Description | Severity | Trigger |
|---|---|---|---|
| 550 | Integrity checksum changed | Level 7 | /etc/passwd, /etc/hosts modified |
| 554 | File added to the system | Level 5 | /bin/suspicious_binary created |

### Alert timeline
21:47:48 — Rule 554: File added (/bin/suspicious_binary)
21:47:48 — Rule 550: Integrity checksum changed (/etc/passwd)
21:47:48 — Rule 550: Integrity checksum changed (/etc/hosts)
21:47:48 — Rule 550: Integrity checksum changed (/etc/sudoers)
21:47:48 — Rule 554: File added (/etc/cron.d/malicious_job)All alerts fired within milliseconds — real-time inotify detection.

## What FIM actually checks
For each monitored file Wazuh stores and compares:
- MD5 hash (detects content changes)
- SHA1 hash (stronger integrity verification)
- SHA256 hash (strongest — used for forensics)
- File size
- File permissions (chmod changes)
- File owner (chown changes)
- Last modification timestamp
- Inode number

Any change to ANY of these fields triggers an alert.

## Dashboard queries used
rule.groups:syscheck
rule.id:550
rule.id:554
rule.id:553
## FIM dedicated view
Navigate to:
Endpoint Security → File Integrity Monitoring → kali agent
Shows visual list of all changed files with before/after comparison.

## Investigation steps
1. Identify exactly which file changed and what changed
2. Compare old hash vs new hash for content verification
3. Check who made the change (process and user context)
4. Determine if change was authorized
5. If unauthorized — restore from backup, preserve evidence

```bash
# Investigation commands
sudo cat /var/ossec/logs/alerts/alerts.log | grep "550\|554" | tail -20
sudo md5sum /etc/passwd
sudo sha256sum /etc/passwd
sudo stat /etc/passwd
sudo ls -la /bin/suspicious_binary
sudo cat /etc/cron.d/malicious_job
```

## Cleanup performed
```bash
sudo sed -i '/attacker was here/d' /etc/passwd
sudo sed -i '/malicious.bank.com/d' /etc/hosts
sudo rm -f /bin/suspicious_binary
sudo sed -i '/# test/d' /etc/sudoers
sudo rm -f /etc/cron.d/malicious_job
```

## Why realtime="yes" matters
Without realtime, FIM only detects changes at the next
scheduled scan (every 300 seconds or 12 hours default).
With realtime, Linux inotify notifies Wazuh the instant
a file is opened for writing. This reduces detection time
from hours to milliseconds — critical for stopping
attackers before they establish full persistence.

## MITRE ATT&CK mapping
Initial Access → Execution → Persistence / Impact
↓
T1565.001 — Modify /etc/passwd
T1053.003 — Create /etc/cron.d/malicious_job
T1136.001 — Backdoor via /etc/passwd
↓
Rule 550 (checksum changed) Level 7
Rule 554 (file added) Level 5
64 total FIM alerts
## Lessons learned
- Default Wazuh config monitors no directories — must configure
- realtime="yes" is essential for fast detection
- FIM catches attackers regardless of entry method
- Hash comparison catches even single-byte file modifications
- /etc/passwd, /etc/shadow, /etc/sudoers are highest priority
- Cleanup of malicious files also generates FIM alerts (good!)

## Status
Complete — 64 FIM alerts confirmed, rules 550 and 554 verified
