# Lab 09 - Root Login Detection (T1078.003)

## Objective
Detect an actor obtaining an interactive **root session** - either by
escalating with `su` or by logging straight in as root over SSH - and do it
without drowning in the noise of everyday `sudo` commands. Separate a genuine
root shell from a one-off privileged command.

## MITRE ATT&CK
| Field | Value |
|---|---|
| Tactic | Defense Evasion, Persistence, Privilege Escalation, Initial Access |
| Technique | T1078.003 - Valid Accounts: Local Accounts |
| Reference | https://attack.mitre.org/techniques/T1078/003/ |

## The design decision: which signal means "root session"?

Every root session on Linux passes through PAM, which emits a
`session opened for user root` line (Wazuh base rule **5501**). The naive
detector is "alert on 5501 for user root." That is wrong - and the reason is
the whole point of this lab:

> **Every single `sudo` command opens a root PAM session.** `sudo systemctl`,
> `sudo tee`, `sudo apt` - each one produces
> `pam_unix(sudo:session): session opened for user root`. Matching that = a
> level-10 alert on every administrative command an operator ever runs.

So the rule must key on the **PAM service** that opened the session, not just
the fact that root's session opened:

| PAM service token | What actually happened | Detect? |
|---|---|---|
| `pam_unix(su:session)` / `pam_unix(su-l:session)` | `su` / `su -` to root - interactive shell | **yes** (100306) |
| `pam_unix(sshd:session)` | direct root login over SSH | **yes** (100307) |
| `pam_unix(login:session)` | direct root login at a console/tty | **yes** (100307) |
| `pam_unix(sudo:session)` | a `sudo` command ran - not a shell | **no** (excluded as noise) |

## Why not match on `dstuser` or `program_name`?

Two approaches that look obvious and both fail on this Wazuh build (4.14.5):

**`dstuser` has no rule-layer selector.** The PAM decoder cleanly extracts
`dstuser: root`, but you cannot match it in a rule:
- `<field name="dstuser">root</field>` -> `Failure to read rule ... Field
  'dstuser' is static` (static fields are not addressable via `<field>`).
- `<dstuser>root</dstuser>` -> `Invalid option 'dstuser' for rule` (no dedicated
  tag exists for it).

An unloadable ruleset takes the manager offline, so this dead-end has to be
designed around, not fought.

**`program_name` is not what you think.** The intuitive rule is
`<program_name>^sshd$</program_name>`. On this endpoint it silently matches
nothing, because modern OpenSSH (9.8+) splits the session into a privilege-
separated helper - the decoded `program_name` is **`sshd-session`**, not
`sshd`. Likewise `su -` decodes as `su`, and the login uses the `su-l` PAM
service. Anchoring on `program_name` would have produced a rule that loads
clean, passes review, and **never fires on a real login.**

The robust anchor is the **PAM service token in `full_log`** via `<match>` -
it survives the `sshd-session` split and needs no fragile field addressing.

## Detection rules (on the manager)

Added to `local_rules.xml`. Both are children of PAM rule **5501** and match
the service token in the raw log:

```xml
<group name="local,pam,authentication,">
  <rule id="100306" level="10">
    <if_sid>5501</if_sid>
    <match>pam_unix(su:session): session opened for user root|pam_unix(su-l:session): session opened for user root</match>
    <description>Interactive root shell via su [T1078.003]</description>
    <mitre><id>T1078.003</id></mitre>
  </rule>
  <rule id="100307" level="12">
    <if_sid>5501</if_sid>
    <match>pam_unix(sshd:session): session opened for user root|pam_unix(login:session): session opened for user root</match>
    <description>Direct root login (sshd/login) [T1078.003]</description>
    <mitre><id>T1078.003</id></mitre>
  </rule>
</group>
```

- `<match>` supports `|` for OR and treats `(`, `)`, `:` as literals - no regex
  escaping needed. It deliberately does **not** include `pam_unix(sudo:session)`.
- `su` -> **level 10** (escalation from an existing account); direct root login
  -> **level 12** (rarer, higher-signal, often a hardening violation).

## A prerequisite finding: `PermitRootLogin yes`

Direct root SSH login is only possible because the endpoint's sshd allows it:

```bash
sudo sshd -T | grep -i permitrootlogin
# permitrootlogin yes   <-- hardening gap
```

This is itself the finding 100307 exists to catch. The secure default
(`prohibit-password`) blocks root password login entirely; `yes` re-opens it.
The detection and the misconfiguration are two sides of the same control.

## Attack simulation

```bash
# 1 - interactive escalation to a root shell (fires 100306)
sudo su -
exit

# 2 - direct root login over SSH (fires 100307)
#     requires PermitRootLogin yes + a root password
ssh root@localhost
exit
```

`sudo su -` is the realistic path: `sudo` elevates, then `su -` opens a genuine
login shell as root - a `su-l` PAM session, no root password required.

## Detection results

Both rules confirmed firing on live events.

**100306** - interactive root shell (level 10):
```json
"rule":{"level":"10","id":"100306","description":"Interactive root shell via su [T1078.003]"},
"full_log":"su[10219]: pam_unix(su-l:session): session opened for user root(uid=0) by vboxuser(uid=0)",
"data":{"srcuser":"vboxuser","dstuser":"root","uid":"0"}
```

**100307** - direct root login (level 12):
```json
"rule":{"level":"12","id":"100307","description":"Direct root login (sshd/login) [T1078.003]"},
"full_log":"sshd-session[36902]: pam_unix(sshd:session): session opened for user root(uid=0) by root(uid=0)",
"predecoder":{"program_name":"sshd-session"},
"data":{"srcuser":"root","dstuser":"root","uid":"0"}
```

Note the `program_name: sshd-session` in the 100307 evidence - the exact reason
a `program_name`-anchored rule would have missed this login.

**Negative control (the point of the design):** running any `sudo <command>`
produces a bare `5501` at level 3 and **no** 100306/100307. The sudo-session
noise is excluded by construction.

## Dashboard queries
- `rule.id:100306 OR rule.id:100307` - all root-session alerts
- `rule.id:100307` - direct root logins only (highest priority)
- `rule.groups:authentication AND data.dstuser:root`

## Investigation steps
1. Open the alert - `100307` (direct login) outranks `100306` (escalation).
2. Read `full_log`: the PAM service token says how root was reached (`sshd`,
   `login`, `su`), and `srcuser` says which account initiated it.
3. For 100307, cross-check the source: was there a preceding SSH auth success
   from an expected IP, or is this off-hours / unknown-source?
4. For 100306, pivot on `srcuser` - which account escalated, and does that
   operator have a change ticket or an authorised reason for a root shell?
5. If unauthorised: contain the session, then hunt what root did next using
   the command-auditing telemetry from Labs 06/07.

## Notes and limitations
- **`sudo -i` / `sudo -s` are not caught.** An interactive sudo shell opens a
  `pam_unix(sudo:session)` - indistinguishable at the PAM-session layer from a
  one-off `sudo` command. Catching it requires a separate rule on `5402`
  matching the `COMMAND=` field for a shell binary. Documented gap, not an
  oversight - the alternative (matching all sudo sessions) is unacceptable noise.
- **Duplicate source.** When the endpoint ships both `/var/log/auth.log` and
  `journald`, a single root login can fire 100307 twice (once per source).
  Dedup by monitoring one source, or accept and group on the alert.
- **Failed logins are a different detector.** Wrong-password root attempts
  surface via `5301`/`5760`/`2502` (brute-force), not these rules. 100306/100307
  are scoped to **successful** root access, which is the correct scope for
  T1078.003.

## Lessons learned
- Match the sensor to the technique - and verify what actually decodes.
  `program_name` looked right and was wrong; the `full_log` PAM token was right.
- Modern OpenSSH (9.8+) runs `sshd-session`, not `sshd` - a rule assumption from
  older docs would silently fail. Always confirm with `wazuh-logtest` on a real
  event before trusting a field.
- Noise exclusion is a design requirement, not an afterthought. A root-session
  rule that fires on every `sudo` is worse than no rule.
- Static decoded fields (`dstuser`) are not always addressable in rules - know
  the difference between "decoded" and "matchable" before building around a field.

## MITRE ATT&CK mapping
```
Defense Evasion / Persistence / Privilege Escalation / Initial Access
  |
  T1078.003 - Valid Accounts: Local Accounts
  |
  Rule 5501 (PAM session opened)           built-in
  Rule 100306 (interactive root via su)    Level 10
  Rule 100307 (direct root login)          Level 12  <- also flags PermitRootLogin yes
```

## Status
Complete - Rules 100306 (level 10) and 100307 (level 12) confirmed firing on
live events: `sudo su -` produced a `su-l` root session (100306), and a direct
`ssh root@localhost` produced an `sshd-session` root login (100307). Everyday
`sudo` commands are excluded by design. Surfaced a real hardening finding on the
endpoint: `PermitRootLogin yes`.
