# Lab 08 - Cron Persistence Detection (T1053.003)

## Objective
Detect an attacker establishing persistence through cron - dropping or
editing scheduled jobs so their code re-runs on a schedule and survives
reboots - and identify **who** made the change, not just that a file
changed.

## MITRE ATT&CK
| Field | Value |
|---|---|
| Tactic | Persistence (also Execution, Privilege Escalation) |
| Technique | T1053.003 - Scheduled Task/Job: Cron |
| Reference | https://attack.mitre.org/techniques/T1053/003/ |

## The design decision: this is a FIM lab, not a command lab

Each technique dictates its own sensor. Cron persistence is fundamentally
a **file-modification** technique, so the primary detector is **File
Integrity Monitoring** (built in Lab 05), not command auditing. That is a
deliberate contrast across the module:

- Lab 06 (recon) -> behavioural **correlation** (a burst of benign commands)
- Lab 07 (reverse shell) -> single high-fidelity **command** event
- Lab 08 (cron persistence) -> **file change** on a persistence path,
  enriched with **whodata** attribution

## The attacker's cron real-estate

A junior watches only `/etc/crontab`. Real coverage means every drop point:

| Path | Purpose |
|---|---|
| `/etc/crontab` | system-wide crontab |
| `/etc/cron.d/` | drop-in job files |
| `/etc/cron.{hourly,daily,weekly,monthly}/` | script directories |
| `/var/spool/cron/crontabs/` | per-user crontabs (Debian/Kali) |
| `/etc/cron.allow`, `/etc/cron.deny` | access control (tampering = evasion) |

Adjacent but out of scope here: **systemd timers** (`/etc/systemd/system/*.timer`)
are T1053.006, a separate sub-technique - a good follow-on lab.

## FIM configuration (on the Kali agent)

`<syscheck>` runs on the **agent**; the manager only evaluates rules. Lab 05
already monitored `/etc/cron.d`, `/etc/crontab`, and `/var/spool/cron` in
`realtime`. Two upgrades for this lab:

1. Add the missing cron paths (script dirs + allow/deny).
2. Switch from `realtime` to **`whodata`** and add **`report_changes`**.

```xml
<directories whodata="yes" check_all="yes" report_changes="yes">/etc/cron.d,/etc/crontab,/etc/cron.hourly,/etc/cron.daily,/etc/cron.weekly,/etc/cron.monthly,/etc/cron.allow,/etc/cron.deny,/var/spool/cron</directories>
```

- **`realtime` vs `whodata`:** `realtime` uses inotify - instant, but records
  *no* actor. `whodata` rides the Linux audit subsystem (already configured
  in Lab 06) to capture the **user and process** responsible for the change.
  For a persistence alert, "who did it" is the analyst's first question, so
  whodata answers it automatically.
- **`report_changes`:** records a content diff of changed text files. Realized
  on **modifications** of existing files (shows the exact line added);
  newly-*added* files have no prior version to diff, so those carry metadata +
  hashes + whodata instead.

```bash
sudo systemctl restart wazuh-agent
```

## Detection rule (on the manager)

Elevate generic FIM events (rules 550/553/554) to a cron-persistence alert
when the changed path is a cron location. Added to `local_rules.xml`:

```xml
<group name="local,syscheck,persistence,">
  <rule id="100305" level="10">
    <if_group>syscheck</if_group>
    <field name="file">^/etc/cron|^/var/spool/cron</field>
    <description>Cron persistence: FIM change on $(file) [T1053.003]</description>
    <mitre><id>T1053.003</id></mitre>
  </rule>
</group>
```

`<if_group>syscheck</if_group>` inherits every FIM event (added/modified/deleted);
`<field name="file">` matches the changed path. `^/etc/cron` covers `/etc/crontab`
and all `cron.*` directories; `^/var/spool/cron` covers per-user crontabs.

## Attack simulation (on Kali)

Three drop points, three different techniques:

```bash
# 1 - system drop-in (the classic)
echo '* * * * * root /tmp/backdoor.sh' | sudo tee /etc/cron.d/backdoor

# 2 - script directory (+ make it executable)
echo -e '#!/bin/bash\n/tmp/evil.sh' | sudo tee /etc/cron.daily/system-update
sudo chmod +x /etc/cron.daily/system-update

# 3 - per-user crontab (writes /var/spool/cron/crontabs/priyanshu)
(crontab -l 2>/dev/null; echo '* * * * * /tmp/evil.sh') | crontab -
```

## Detection results

All three vectors fired **rule 100305 (level 10)** with full whodata
attribution:

| Cron vector | Event | Actor (whodata) |
|---|---|---|
| `/etc/cron.d/backdoor` | added | `login_user: priyanshu` -> `process: /usr/bin/tee` -> `effective_user: root` |
| `/etc/cron.daily/system-update` | added | same (sudo tee) |
| `/etc/cron.daily/system-update` | **modified** | `process: /usr/bin/chmod`, perms `rw-r--r--` -> `rwxr-xr-x` |
| `/var/spool/cron/crontabs/priyanshu` | added | `process: /usr/bin/crontab`, **parent: /usr/bin/zsh**, `user: priyanshu` |

### Why whodata is the story
Without it, the alert is "a cron file changed." With it, the alert is
"**priyanshu** used **crontab** from a **zsh** session to add a job in the
per-user spool." The `chmod` firing as a **separate `modified` event** is a
second observable in the persistence chain - the attacker making their payload
executable. Process, parent process, login user, and effective user all land
in the alert, so triage starts already answered.

Sample alert (crontab vector, trimmed):
```json
"rule":{"level":"10","id":"100305","description":"Cron persistence: FIM change on /var/spool/cron/crontabs/priyanshu [T1053.003]"},
"syscheck":{"path":"/var/spool/cron/crontabs/priyanshu","mode":"whodata","event":"added",
  "audit":{"process":{"name":"/usr/bin/crontab","parent_name":"/usr/bin/zsh"},
           "login_user":{"name":"priyanshu"},"effective_user":{"name":"priyanshu"}}}
```

## Dashboard queries
- `rule.id:100305` - all cron-persistence alerts
- `syscheck.path:/etc/cron*` - cron file changes
- `rule.groups:persistence`

## Investigation steps
1. Open the `100305` alert - note `syscheck.path` (which cron file) and
   `syscheck.event` (added / modified / deleted).
2. Read the whodata block: `login_user` + `process` + `parent_name` =
   who did it, with what, from where.
3. If `report_changes` provided a diff (modification), read the exact cron
   line added; for an add, pull the file contents from the host.
4. Determine whether that user/change is authorised. A new job in
   `/etc/cron.d` or a user's spool that maps to no change ticket is
   persistence until proven otherwise.
5. Contain, then hunt the referenced payload path (`/tmp/backdoor.sh`,
   `/tmp/evil.sh`) and the process lineage from Lab 06/07 telemetry.

## Notes and limitations
- **`report_changes` on adds:** no prior version exists to diff, so new-file
  drops carry metadata + hashes + whodata, not a content diff. The line-level
  diff shows on *modifications* of existing cron files.
- **whodata depends on auditd:** it reuses the Linux audit subsystem from
  Lab 06. If auditd rules were immutable (`-e 2`), whodata would fall back to
  realtime (detection intact, attribution lost).
- **systemd timers (T1053.006)** are a separate persistence surface, not
  covered here - a natural next lab.

## Lessons learned
- Match the sensor to the technique: file-based persistence -> FIM, not
  command auditing.
- `whodata` over `realtime` for security-relevant paths - attribution is the
  difference between an alert and an investigation.
- `report_changes` turns "a file changed" into "here is the line they added."
- One rule (`if_group syscheck` + path match) cleanly promotes generic FIM
  noise into a MITRE-tagged persistence alert.
- Ops: never restart the manager on an unvalidated ruleset - keep a `.working`
  backup, write the full file via `tee`, and validate with `wazuh-logtest`
  first. (When pasting a `sudo` heredoc, run `sudo -v` beforehand so the
  password prompt does not consume the pasted content.)

## MITRE ATT&CK mapping
```
Persistence
  |
  T1053.003 - Scheduled Task/Job: Cron
  |
  Rule 554/550 (FIM add/modify)   built-in
  Rule 100305  (cron persistence) Level 10  + whodata attribution
```

## Status
Complete - Rule 100305 confirmed firing on all three cron persistence
vectors (system drop-in, script directory, per-user crontab), each with
whodata attribution (user + process + parent). The `chmod` modification was
independently detected as part of the persistence chain.
