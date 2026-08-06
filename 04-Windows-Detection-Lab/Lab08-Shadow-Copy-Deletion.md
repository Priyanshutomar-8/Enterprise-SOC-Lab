# Lab 08 - Impact: Ransomware Recovery Inhibition (T1490)

## Objective
Catch ransomware in the narrow window between *break-in* and *encryption* -
the moment it destroys the victim's ability to recover, which almost every
family does **before** it starts encrypting.

Windows silently keeps **Volume Shadow Copies** - point-in-time snapshots that
power "Restore previous versions" and System Restore. They are the single
biggest obstacle to a ransom demand: if the victim can roll back, they do not
pay. So the standard ransomware playbook runs one command first:

```
vssadmin delete shadows /all /quiet
```

This is **T1490 - Inhibit System Recovery**, and it is high-value to detect for
one reason: it happens *before* the files are encrypted. Detecting the
encryption is too late; detecting the shadow-copy wipe is the last chance to
contain the host while the data is still recoverable.

| Tool | Destructive command | What it kills |
|---|---|---|
| `vssadmin` | `delete shadows /all /quiet` | All volume shadow copies |
| `wmic` | `shadowcopy delete` | All volume shadow copies (alt. path) |
| `bcdedit` | `/set {default} recoveryenabled no` | Windows recovery environment |
| `bcdedit` | `/set {default} bootstatuspolicy ignoreallfailures` | Boot-failure recovery prompts |
| `wbadmin` | `delete catalog -quiet` | The backup catalog |

## MITRE ATT&CK
| Field | Value |
|---|---|
| Tactic | Impact |
| Technique | T1490 - Inhibit System Recovery |
| Reference | https://attack.mitre.org/techniques/T1490/ |

## Environment
| Component | Details |
|---|---|
| Endpoint | Windows 11 Home (agent, Wazuh v4.14.6, ID 002 `windows`) |
| Manager | Ubuntu Server, Wazuh 4.14.6 all-in-one |
| Log source | Windows **Security** channel - Event **4688** (process creation) |
| Audit prereq | Process Creation auditing **+ command-line inclusion** (see below) |

### The prerequisite that makes or breaks this lab
Event 4688 by default records only the **process name**, not its arguments. For
this technique that is worthless:

```
vssadmin list shadows              <- a backup admin checking. Harmless.
vssadmin delete shadows /all /quiet <- ransomware. Catastrophic.
```

Same binary. The entire difference - benign versus catastrophic - lives in the
arguments, which Windows hides unless explicitly told to log them. This is the
same shape of problem as Lab 07's Event 5007 ("configuration changed" without
saying *what* changed).

```powershell
# 1. Log successful process creation (Event 4688)
auditpol /set /subcategory:"Process Creation" /success:enable

# 2. Include the command line in 4688 - the setting this lab depends on
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" `
  /v ProcessCreationIncludeCmdLine_Enabled /t REG_DWORD /d 1 /f
```

**On this endpoint, Process Creation auditing was already enabled** (likely from
a prior lab). 4688 events were already flowing - but *without* command lines, so
they were undetectable for this technique. The meaningful change was the
registry key, not the audit policy.

**The setting is read at process start.** A PowerShell session opened before the
key was set produces command-line-less 4688s - proven live: events captured
from the pre-change session showed `(no cmdline)`, while a fresh session
captured the full argument string. Same lesson as Lab 05's cached script-block
policy: **open a new session after changing the policy.**

## What the shipped ruleset covers: nothing
Traced by hand before writing anything (Lab 03 discipline). The result is
different from every prior Windows lab.

| Search | Result |
|---|---|
| Rules mapped to **T1490** | **Zero.** The only `T1490` strings in the product are inside `sca/cis_ubuntu18-04.yml.disabled` - policy metadata in a **disabled** Linux compliance file, not a detection. |
| Rules matching `vssadmin` / `wbadmin` / `bcdedit` as attacks | **Zero.** All 16 `shadow copy` hits are in `0585-win-application_rules.xml` and describe VSS **service errors** ("Unable to create a shadow copy", "writers do not have enough privileges") - operational noise, not deletion. |
| Rules reading `commandLine` | Two files, both effectively Sysmon-scoped (`0800-sysmon_id_1.xml`) or product-specific. |

Labs 05, 06 and 07 each found coverage that was *wrong* - a typo, a bad
severity, a Sysmon gate. **Here there is nothing to be wrong.** T1490 is an
unmarked blank on the ATT&CK map for a native-logs endpoint.

There is exactly one shipped rule for Event 4688:

```xml
<rule id="67027" level="3">
  <if_sid>60103</if_sid>
  <field name="win.system.providerName">Microsoft-Windows-Security-Auditing</field>
  <field name="win.system.eventID">4688</field>
  <description>A process was created.</description>
</rule>
```

**Level 3, no command line in the description, no MITRE tag, and it fires for
every process on the machine.** That is the baseline.

## Baseline - measured before deploying (Lab 06/07 discipline)
`logall_json` was already enabled from Lab 07. The attack was run against the
**stock** ruleset first. Every process on the endpoint produced rule 67027 at
level 3 - and so did the attack, indistinguishable from the noise:

```
21:26:44  67027 L3  vssadmin.exe list shadows
21:27:08  67027 L3  vssadmin.exe delete shadows /all /quiet   <-- the attack
21:26:44  67027 L3  vssvc.exe
21:27:35  67027 L3  SearchIndexer.exe /Embedding
21:27:51  67027 L3  RuntimeBroker.exe -Embedding
21:27:51  67027 L3  backgroundTaskHost.exe -ServerName:...
```

`vssadmin delete shadows /all /quiet` - the command that makes a ransomware
attack unrecoverable - was rated **identically to the search indexer waking up**.
Not under-rated like Lab 07's level-5 exclusion; simply undifferentiated, one
line in a stream of routine level-3 OS churn.

### Three tooling findings from the baseline run
1. **`wmic` is gone.** `wmic shadowcopy delete` returned `'wmic' is not
   recognized` - `wmic.exe` has been removed from this Windows 11 build. No
   process spawned, no 4688. Detections assuming `wmic` is present will find
   nothing to match because the attacker's classic tool no longer exists; modern
   ransomware has moved to PowerShell/CIM (`Get-CimInstance Win32_ShadowCopy |
   Remove-CimInstance`) partly for this reason.
2. **`{default}` is a PowerShell trap.** `bcdedit /set {default} recoveryenabled
   no` **failed** ("The parameter is incorrect") - PowerShell parsed `{default}`
   as a script block. The 4688 captured what `bcdedit` actually received:
   ```
   bcdedit.exe /set -encodedCommand ZABlAGYAYQB1AGwAdAA= recoveryenabled no -inputFormat xml -outputFormat text
   ```
   That base64 decodes to `default`. The authentic command run verbatim in
   PowerShell does not work; the braces must be quoted (`'{default}'`). **An
   analyst testing T1490 detections through PowerShell captures a command line
   the real attack - run from cmd.exe or a dropper - never produces.**
3. **The command-line audit setting is load-bearing.** 4688 events from the
   pre-change session recorded `(no cmdline)`; only after enabling
   `ProcessCreationIncludeCmdLine_Enabled` and opening a fresh session did the
   arguments appear. Without it, this entire technique is invisible even with
   4688 auditing "on".

## Detection rule (on the manager)
Added to `/var/ossec/etc/rules/local_rules.xml`.

```xml
<group name="local,windows,ransomware_prep,">

  <rule id="100411" level="13">
    <if_sid>67027</if_sid>
    <field name="win.eventdata.commandLine" type="pcre2">(?i)(vssadmin.*\bdelete\b.*shadow|\bwmic\b.*\bshadowcopy\b.*\bdelete\b|wbadmin.*\bdelete\b.*(catalog|systemstate|backup)|bcdedit.*/set\b.*(recoveryenabled\s+no|bootstatuspolicy.*ignoreall)|\bDelete-ComputerRestorePoint\b|Win32_Shadowcopy\b.*\b(delete|remove)\b)</field>
    <description>Ransomware recovery inhibition on $(win.system.computer) by $(win.eventdata.subjectUserName) - destroying backups/recovery before encryption [T1490]: $(win.eventdata.commandLine)</description>
    <options>no_full_log</options>
    <mitre><id>T1490</id></mitre>
  </rule>

</group>
```

Design notes:

- **`if_sid 67027` - the first-match-wins lesson, applied deliberately this
  time.** 67027 already claims every 4688. The naive chain `if_sid 60103` +
  `eventID 4688` would make this rule a **sibling** of 67027 under the base rule
  60103; 67027 wins the first-match race on every 4688 and this rule would be
  **orphaned** - exactly how Lab 05's 100405/100406 were silently lost. To
  *escalate* an event a leaf rule already catches, become that leaf rule's
  **child**. 67027 was confirmed live as the sole rule matching 4688.
- **Match per tool requires BOTH the tool AND its destructive verb**, so the
  negative controls stay silent: `vssadmin list shadows` has no `delete`;
  `bcdedit /enum` has no `/set`. Verified live.
- **Match on `commandLine`, not `newProcessName`.** This catches the tool even
  if renamed or copied elsewhere, and is parent-agnostic (fires whether launched
  from PowerShell, cmd, or a dropper).
- **`type="pcre2"` is mandatory** for `(?i)` and alternation - `<field>` defaults
  to OSRegex, under which `(?i)` silently never matches (Lab 04's bug).
- **Custom group `ransomware_prep`** shares no substring with a parent group, so
  `if_sid`/`if_group` cannot self-match (Lab 05/06/07 precaution).
- **Level 13.** This is pre-encryption impact preparation - the last containment
  opportunity before data loss. It should outrank almost everything.

## Attack simulation (on the endpoint)
Run in a **fresh** elevated PowerShell (post-registry-change), each command ~20s
apart, read-only controls first.

```powershell
# NEGATIVE CONTROLS - legitimate admin inspection, must stay silent
vssadmin list shadows
bcdedit /enum

# POSITIVE 1 - the signature ransomware command
vssadmin delete shadows /all /quiet

# POSITIVE 2 - disable Windows recovery (note the QUOTED brace)
bcdedit /set '{default}' recoveryenabled no

# RESTORE
bcdedit /set '{default}' recoveryenabled yes
```

Method notes:
- **The negative controls use the same tools as the attack**, differing only in
  the verb (`list` vs `delete`, `/enum` vs `/set`). A control that used an
  unrelated command would not test the thing that matters: that the rule keys on
  *destruction*, not on the tool's mere presence.
- **`vssadmin delete` spawns `vssadmin.exe` even with no shadow copies to
  delete** ("No items found"). The 4688 - and the detection - fire on the
  *attempt*, which is correct: you want the alert whether or not the attacker
  found anything to destroy.
- **`'{default}'` is quoted** to survive PowerShell's script-block parsing (see
  baseline finding 2). Unquoted, it is mangled into a base64 blob before
  `bcdedit` sees it.
- **Positive 2 actually disables recovery** and is reversed in the RESTORE step.

## Detection results
Confirmed firing on live endpoint telemetry.

```
Rule: 100411 (level 13) -> 'Ransomware recovery inhibition on Windows by vboxuser
   - destroying backups/recovery before encryption [T1490]:
     "C:\WINDOWS\system32\vssadmin.exe" delete shadows /all /quiet'
Rule: 100411 (level 13) -> 'Ransomware recovery inhibition on Windows by vboxuser
   - destroying backups/recovery before encryption [T1490]:
     "C:\WINDOWS\system32\bcdedit.exe" /set {default} recoveryenabled no'
```

Full test matrix:

| Test | Action | Expected | Result |
|---|---|---|---|
| NC 1 | `vssadmin list shadows` | silent | **silent - passed** |
| NC 2 | `bcdedit /enum` | silent | **silent - passed** |
| Pos 1 | `vssadmin delete shadows /all /quiet` | 100411 L13 | **fired, command line named** |
| Pos 2 | `bcdedit /set '{default}' recoveryenabled no` | 100411 L13 | **fired, clean command line** |

Exactly **two** 100411 alerts were produced by the four commands - confirming
the negative controls did not escalate. The Pos 2 alert shows a clean
`/set {default} recoveryenabled no` (the quoting fix), versus the base64-mangled
form from the baseline run.

### Before and after, same command
| | Stock ruleset | With rule 100411 |
|---|---|---|
| `vssadmin delete shadows /all /quiet` | 67027 L3, identical to SearchIndexer.exe | **100411 L13, names user + command** |
| `bcdedit /set ... recoveryenabled no` | 67027 L3 | **100411 L13** |
| ATT&CK T1490 coverage | none | **detected** |

## Investigation steps
1. **Treat 100411 as an active ransomware incident until proven otherwise.**
   Almost nothing legitimate deletes all shadow copies with `/quiet`. This alert
   typically means encryption is imminent or already beginning.
2. **The command line and `subjectUserName` are in the alert.** They name what
   ran and which account ran it.
3. **Correlate backwards - fast.** T1490 is late in the kill chain. Look
   immediately before it for the account's earlier activity across this module:
   brute force (100400), rogue admin (100402), persistence (100403/100404),
   download cradle (100405/100406), Defender tampering (100408-100410). The
   intrusion did not start here.
4. **Isolate the host now, not after triage.** Unlike most techniques, the
   window between this alert and irreversible data loss is minutes. Containment
   precedes investigation.
5. **Check `bcdedit /enum` and `vssadmin list shadows` on the host** to assess
   what recovery capability survives.

## Notes and limitations
- **This detects the exe-based path (Event 4688).** A PowerShell-native wipe
  (`Get-CimInstance Win32_ShadowCopy | Remove-CimInstance`) that never spawns
  `vssadmin.exe` would be caught by the `Win32_Shadowcopy` / `Delete-Computer
  RestorePoint` branches **only via the PowerShell Script Block channel (Event
  4104)** from Lab 05 - which this single 4688 rule does not read. A companion
  4104 rule is worthwhile future work; it was scoped out here to keep the lab to
  one verifiable rule.
- **`wmic` coverage is untested on this endpoint** because `wmic.exe` is not
  installed. The branch is retained for portability to older Windows.
- **Command-line matching can be evaded** by an attacker who avoids the known
  tool names entirely (e.g. calling the VSS COM API directly). This rule raises
  the cost of the common path; it is not a proof against a determined operator.
- **Depends on the command-line audit setting.** An endpoint with 4688 auditing
  but without `ProcessCreationIncludeCmdLine_Enabled` produces no matchable
  field, and the rule cannot fire. This prerequisite should be part of the fleet
  baseline, not a per-host step.
- **Level 13 is intentionally loud.** If deployed fleet-wide, backup software or
  admin scripts that legitimately run `wbadmin delete` on a schedule will need an
  explicit exclusion - tune to the environment before enabling paging.

## Lessons learned
- **An empty gap is different from a wrong rule, and arguably worse.** Labs 05-07
  found defective coverage; a defect is at least a hook to improve. T1490 had no
  hook at all - the technique simply did not exist as far as the SIEM was
  concerned, and only a manual trace of the ruleset revealed it rather than a
  failed alert.
- **The discriminator is the argument, not the process.** Auditing 4688 without
  its command line is the security equivalent of a CCTV camera that records that
  *someone* entered but not *who* - technically "monitored", operationally
  blind. The registry key is the whole lab.
- **The test harness is not the attacker.** PowerShell mangled the authentic
  `bcdedit {default}` command into something the real technique never emits.
  Validate detections against the command line a real attack produces (cmd /
  dropper), not the one your test shell happens to generate.
- **Escalate by becoming a child, not a sibling.** The correct fix for "a leaf
  rule already catches this event at too low a severity" is `if_sid <that leaf>`.
  Chaining to the base rule instead re-creates the Lab 05 orphaning bug.
- **Attacker tooling ages.** `wmic` is gone from current Windows; a detection
  library that still leans on it is decaying. Detections need the same
  maintenance discipline as the threats they track.

## MITRE ATT&CK mapping
```
Inhibit System Recovery (T1490)
  |
  +-- Event 4688 (process creation, WITH command line)
        |
        +--> 60103 > 67027  Level 3  "A process was created"  [fires for EVERY process]
                      |
                      +--> if_sid 67027 --> Rule 100411  Level 13  [DETECTED - T1490]
```

## Status
Complete - Rule **100411** (level 13) confirmed firing on a live Windows 11
endpoint for `vssadmin delete shadows /all /quiet` and `bcdedit /set {default}
recoveryenabled no`, each naming the responsible account and the exact command.
The two negative controls (`vssadmin list shadows`, `bcdedit /enum`) stayed
silent, confirming the rule keys on destruction rather than tool presence.

The lab documented that **T1490 has no coverage whatsoever in the shipped
ruleset** - the sole 4688 rule (67027) rates destroying all system backups
identically to the search indexer starting, at level 3 - and that the technique
is only detectable at all once Event 4688 is configured to include command
lines. Three tooling findings were recorded: `wmic` has been removed from this
Windows 11 build, PowerShell mangles the unquoted `bcdedit {default}` argument
into a base64 blob, and the command-line audit registry key is a hard
prerequisite. The endpoint's recovery configuration was restored afterwards.
