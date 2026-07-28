# Lab 01 - Windows Brute Force Detection (T1110.001)

## Objective
Detect a password brute-force / guessing attack against a single Windows
account - a burst of failed logons (Event **4625**) aimed at one username -
and elevate that pattern from low-severity log noise into one actionable,
account-attributed alert. As with Lab 06 (Linux recon), the individual events
are benign; the signal is the *burst against one target*.

## MITRE ATT&CK
| Field | Value |
|---|---|
| Tactic | Credential Access |
| Technique | T1110 - Brute Force |
| Sub-technique | T1110.001 - Password Guessing |
| Reference | https://attack.mitre.org/techniques/T1110/001/ |

## Detection philosophy - correlation, not single-event
A single 4625 is everyday noise: a fat-fingered password, a stale cached
credential, a service with an old secret. Alerting on one is useless. So Lab 01
is a **frequency-correlation** detection (contrast Lab 07's single high-fidelity
reverse-shell event): the rule fires only when *N* failures hit the *same
account* inside a short window.

## The design decision: correlate on the target account, not the source IP
Wazuh already ships a brute-force rule for Windows - **60204, "Multiple Windows
Logon Failures"** (frequency 8 / 240s, MITRE T1110). Rebuilding it would add
nothing. 60204 correlates on `win.eventdata.ipAddress` - the **source**.

That has a real blind spot: several Windows logon paths record
`ipAddress` as `-` (empty). Console logons, and a number of local/service logon
types, carry no source IP. When the source is blank, 60204's
`same_field win.eventdata.ipAddress` cannot group the events, and a
single-account hammering goes uncorrelated.

Custom rule **100400** closes that gap by correlating on
`win.eventdata.targetUserName` - the **account under attack** - instead. This
catches:
- single-account brute force where the source IP is absent, and
- password spray focused on one privileged account,

regardless of whether a source address was logged. It is the Windows analogue
of the "match the signal that is actually present" lesson from Lab 09 (where
`program_name` was the wrong anchor and the PAM token was the right one).

## Environment
| Component | Details |
|---|---|
| Endpoint | Windows 11 Home (agent, Wazuh v4.14.6, ID 002 `windows`) |
| Manager | Ubuntu Server, Wazuh 4.14.6 all-in-one |
| Log source | Windows Security channel (eventchannel) -> Wazuh agent |
| Audit prereq | `auditpol` (Win 11 Home has no `gpedit`/`secpol`) |

**Windows 11 Home caveat:** there is no Local Group Policy or Local Security
Policy editor. Audit policy is set from the CLI with `auditpol.exe`, not
`gpedit.msc`.

## Prerequisite - enable failed-logon auditing (on the endpoint)
By default the "Logon" subcategory may not audit failures, so no 4625 is
generated. Enable it:

```powershell
auditpol /set /subcategory:"Logon" /failure:enable
auditpol /get /subcategory:"Logon"     # must show: Failure (or Success and Failure)
```

The Wazuh agent must also forward the Security channel (default install does):
`<localfile><location>Security</location><log_format>eventchannel</log_format></localfile>`.

## Detection rule (on the manager)
Added to `/var/ossec/etc/rules/local_rules.xml`.

```xml
<group name="local,windows,windows_security,authentication,">
  <rule id="100400" level="12" frequency="8" timeframe="120">
    <if_matched_sid>60122</if_matched_sid>
    <same_field>win.eventdata.targetUserName</same_field>
    <description>Windows brute force: repeated failed logons for account $(win.eventdata.targetUserName) [T1110.001]</description>
    <options>no_full_log</options>
    <mitre><id>T1110.001</id></mitre>
  </rule>
</group>
```

Design notes:
- **Parent 60122** ("Logon Failure - Unknown user or bad password") is the
  brute-force-relevant 4625 subtype - it excludes other failure reasons
  (time-restriction, disabled account, etc.), keeping the rule tight.
- **`same_field win.eventdata.targetUserName`** is the account correlation -
  the whole point of the rule (see design decision above).
- **frequency 8 / timeframe 120** - 8 failures in 2 minutes. Tighter window than
  60204's 240s so a real guessing burst surfaces fast.
- **level 12** (higher than 60204's 10) - a sustained attack on a *named*
  account, tagged to the T1110.001 sub-technique.
- Structurally identical to Wazuh's own composite rules 60203/60204
  (`if_matched_sid` + `same_field` + `frequency`), so the pattern is idiomatic.

## Attack simulation (on the endpoint)
Generate >=8 independent failed logons for one account inside the window:

```powershell
$sig = @'
[DllImport("advapi32.dll", SetLastError=true)]
public static extern bool LogonUser(string u, string d, string p, int t, int pr, out IntPtr h);
'@
$L = Add-Type -MemberDefinition $sig -Name W -Namespace Win -PassThru
$h = [IntPtr]::Zero
1..10 | ForEach-Object { [void]$L::LogonUser("bruteforce_test", $env:COMPUTERNAME, "BadPass$_", 3, 0, [ref]$h) }
```

`LogonType 3` = network logon. Each `LogonUser` call is an independent
authentication attempt for the same account (`bruteforce_test`) with a wrong
password, so each one logs its own 4625.

### Why not `net use` (a real finding)
The first attempt used a `net use \\127.0.0.1\IPC$ /user:... <badpass>` loop. It
under-generated: only 4 of 10 attempts produced a 4625. Cause: **Windows error
1219** - "multiple connections to a server or shared resource by the same user
are not allowed." After the first connection, Windows *rejects* subsequent
attempts to the same server **without authenticating**, so no logon occurs and
no 4625 is written. `net use` is therefore a poor brute-force generator; the
`LogonUser` API avoids the connection-caching entirely.

## Detection results
Confirmed firing on live endpoint telemetry and verified in the dashboard.

```
level:      12
id:         100400
description: Windows brute force: repeated failed logons for account bruteforce_test [T1110.001]
mitre:      T1110.001
agent:      windows (002)
firedtimes: 1
```

- 13x rule **60122** (level 5) for `targetUserName: bruteforce_test` fed the
  correlation; the 8th within-window match triggered **100400** (level 12).
- In **Threat Hunting** (`rule.id:100400`), the single level-12 alert sits atop
  the cluster of level-5 60122 events, all inside ~1 second - the visual
  signature of "noise collapsed into one actionable alert."

| Rule ID | Description | Severity | Result |
|---|---|---|---|
| 60122 | Logon Failure - unknown user/bad password (per 4625) | Level 5 | Fired x13 |
| 100400 | Windows brute force (same-account correlation) | Level 12 | **Confirmed firing** |

## Investigation steps
1. Open the **100400** alert - read `targetUserName` (which account was
   attacked) and the agent (which host).
2. **Check for success:** search the same account for a subsequent **4624**
   (successful logon). A 4624 shortly after the burst = the guess likely
   worked - escalate to credential compromise.
3. **Source:** for network logons pull `ipAddress` / `workstationName`; correlate
   with firewall/VPN logs to locate the origin.
4. **Scope:** was only one account targeted (guessing) or many (spray)? Pivot on
   the burst timestamps.
5. Contain (disable/reset the account, block the source) and hunt for follow-on
   activity.

## Notes and limitations
- **Auditing must be on.** With Logon-failure auditing disabled, no 4625 exists
  and the rule is silent by construction - the `auditpol` prereq is the
  foundation, not an afterthought.
- **`net use` caching (error 1219)** makes it unreliable for simulation; use the
  `LogonUser` API for independent attempts. Documented above.
- **Offline rule validation is limited.** Feeding a synthetic 4625 JSON to
  `wazuh-logtest` did not exercise the eventchannel base chain (rule 60001's
  precondition ties to the agent submission path, not just field content), so
  the event matched generic rule 1002 in logtest. The rule was validated to
  *load* (`wazuh-analysisd -t`) and then confirmed *firing* on a genuine live
  4625 from the agent - which is the authoritative test for a Windows rule.
- **Lockout policy interaction.** If an account-lockout policy is active, the
  account may lock before 8 failures accrue; tune `frequency` to the environment
  (lower it below the lockout threshold, or pair with 4740 lockout events).
- **`sysmon`-based process context** (who launched the auth attempts) is out of
  scope here and belongs to Module 05.

## Lessons learned
- Don't rebuild a built-in - **earn the custom rule.** 60204 already covers
  same-source brute force; 100400 adds same-*account* correlation to cover the
  blank-source-IP gap. Know what ships before you write.
- Match the field that is actually populated - `targetUserName` over
  `ipAddress` when the source can be empty (same lesson as Lab 09's PAM token).
- Verify the simulator, not just the rule - `net use` silently under-generated;
  reading the actual 4625 count exposed it.
- A Windows detection is only proven by a **live** event from the agent;
  `wazuh-logtest` on synthetic eventchannel JSON is not sufficient.

## MITRE ATT&CK mapping
```
Credential Access
  |
  T1110.001 - Password Guessing
  |
  Rule 60122  (per-4625 logon failure)     built-in  Level 5
  Rule 100400 (>=8 failures / same account) Level 12  [DETECTED]
```

## Status
Complete - Rule 100400 (level 12) confirmed firing on a live Windows 11
endpoint: 13 failed logons for `bruteforce_test` produced the correlated
brute-force alert, verified in the Threat Hunting dashboard. Detection
correlates on the target account to cover the blank-source-IP gap left by
built-in rule 60204.
