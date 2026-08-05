# Lab 06 - Defense Evasion: Windows Event Log Cleared (T1070.001)

## Objective
Detect an attacker destroying the record of their own intrusion by clearing
Windows event logs - the digital equivalent of wiping the CCTV footage on the
way out.

Windows makes this unusually detectable. When a log is cleared, Windows
immediately writes a new entry **into the now-empty log** recording that the
clear happened and who did it. The attacker cannot suppress it without
disabling the Event Log service entirely, which is itself loud.

| Event | Meaning | Channel |
|---|---|---|
| **1102** | The Security (audit) log was cleared | Security |
| **104** | Some other log was cleared - System, Application, PowerShell/Operational | System |

Event 104 matters more than it first appears. Lab 05 enabled PowerShell Script
Block Logging on the `Microsoft-Windows-PowerShell/Operational` channel; an
attacker erasing evidence of a download cradle would clear *that* log, which
produces **104**, not 1102.

## MITRE ATT&CK
| Field | Value |
|---|---|
| Tactic | Defense Evasion |
| Technique | T1070.001 - Indicator Removal: Clear Windows Event Logs |
| Reference | https://attack.mitre.org/techniques/T1070/001/ |

## Environment
| Component | Details |
|---|---|
| Endpoint | Windows 11 Home (agent, Wazuh v4.14.6, ID 002 `windows`) |
| Manager | Ubuntu Server, Wazuh 4.14.6 all-in-one |
| Log sources | Windows **Security** channel (1102) and **System** channel (104) |
| Audit prereq | **None** - 1102 and 104 are always recorded and cannot be disabled |

No `auditpol` configuration was required, unlike Labs 01-04. That is precisely
what makes these two events valuable: they are not subject to an audit policy
an attacker could quietly turn off first.

## What the shipped ruleset already covers
Following the Lab 03 discipline - check before building - the shipped ruleset
was traced by hand before any rule was written. Wazuh covers **both** events.
The initial hypothesis that Event 104 was uncovered was **wrong**.

| Rule | Event | Level | Chain | File |
|---|---|---|---|---|
| 63103 | 1102 | **5** | 60000 > 60001 > 60017 > 63108 | `0610-win-ms_logs_rules.xml` |
| 63104 | 104 | **5** | 60000 > 60002 > 60007 > 63100 | `0610-win-ms_logs_rules.xml` |
| 60117 | 1102 | **9** | 60000 > 60001 > 60100 | `0580-win-security_rules.xml` |

The gating rules, confirmed by reading them directly:

```
60001  win.system.channel      = ^Security$
60002  win.system.channel      = ^System$
60017  win.system.providerName = ^Microsoft-Windows-Eventlog$      (child of 60001)
60007  win.system.providerName = ^Eventlog$|^Microsoft-Windows-Eventlog$  (child of 60002)
60100  win.system.severityValue = ^INFORMATION$                    (child of 60001)
```

**The gap is severity, not coverage.** Both log-clearing events alert at
**level 5** - the same band as a service starting or a printer driver
installing. Almost nothing legitimate clears a Windows event log, which makes
this one of the highest-confidence signals available on the platform, and it
was landing in the noise floor.

### The reachability problem with 60117
Rule 60117 is the better shipped rule - level 9, carries a MITRE mapping - and
it appears to be **unreachable**.

60117 hangs off **60100**. 63103 hangs off **60017**. Both 60100 and 60017 are
children of **60001**, making them siblings. Wazuh evaluates sibling rules
**first-match-wins** and then descends only into the winner's subtree (the same
mechanism documented in Lab 05, which orphaned rules 100405/100406). Rule files
load in numeric order, so `0575-win-base_rules.xml` (containing 60017) loads
before `0580-win-security_rules.xml` (containing 60100).

A real 1102 event carries `providerName: Microsoft-Windows-Eventlog`, so it
matches 60017. 60017 therefore claims the event, analysis descends into 63108
-> 63103 (level 5), and 60100 -> 60117 (level 9) is never evaluated.

**This is stated as a strong prediction, not a confirmed result.** It follows
from mechanics verified in Lab 05, but it was not proven here, for a
methodological reason worth recording: rule 100407 was deployed *before* a
baseline was captured, and because Wazuh reports only the single winning rule
per event, the custom rule now masks whichever shipped rule fired beneath it.
**Measure the baseline before changing the system.** Confirming this would
require replaying a captured event through `wazuh-logtest` or temporarily
disabling 100407.

### The MITRE mapping on 60117 is wrong
```xml
<mitre><id>T1070.004</id></mitre>
```
`T1070.004` is **File Deletion**. Clearing Windows event logs is
**T1070.001**, a sibling sub-technique literally named "Clear Windows Event
Logs". Combined with the reachability problem above, an ATT&CK coverage
dashboard built on the stock ruleset would show **nothing at all** for
T1070.001 - not even a miscategorised hit, because the rule carrying the
(wrong) tag never fires. Rules 63103/63104 map only to the parent `T1070`.

## Detection rule (on the manager)
Added to `/var/ossec/etc/rules/local_rules.xml`.

```xml
<group name="local,windows,log_wipe,">

  <rule id="100407" level="13">
    <if_group>log_clearing|logs_cleared</if_group>
    <description>Windows event log CLEARED on $(win.system.computer) by $(win.logFileCleared.subjectUserName) - anti-forensics, log: $(win.logFileCleared.channel) [T1070.001]</description>
    <options>no_full_log</options>
    <mitre><id>T1070.001</id></mitre>
  </rule>

</group>
```

Design notes:

- **`if_group`, not `if_sid`** - directly applying Lab 05's hardest lesson.
  Chaining to a group means the rule fires regardless of *which* shipped rule
  won the event, so it cannot be orphaned by sibling ordering the way
  100405/100406 were. It also makes the rule immune to the unresolved 60117
  question: whether 63103 or 60117 wins, both are matched.
- **`log_clearing|logs_cleared`** covers all three shipped rules.
  `log_clearing` is a substring of 63103's `log_clearing_auditlog`, so that one
  alternative catches both 63103 and 63104; `logs_cleared` catches 60117 if it
  turns out to be reachable after all.
- **Custom group named `log_wipe`** - deliberately *not* containing the
  substring `log_clearing`, so `if_group` cannot match this rule against
  itself. Same precaution as Lab 05's `ps_cradle`.
- **Level 13** - one rule covering both events. Level 5 says "noted"; level 13
  says "wake someone up". Log clearing usually means the damage is already
  done and this is the last chance to notice.
- **Correct MITRE mapping** - T1070.001.

## Bug 1 - the vendor's own sample event is stale
The first version of this rule used `$(win.eventdata.subjectUserName)` for the
account name. It alerted correctly but rendered with a blank:

```
'Windows event log CLEARED on Windows by  - possible anti-forensics [T1070.001]'
```

The field name came from Wazuh's **own documentation**: the sample event pasted
as a comment directly above rule 63103 in `0610-win-ms_logs_rules.xml`, which
shows `"eventdata":{"subjectUserName":"HFFG$", ...}`.

The live event does not look like that. Captured from the endpoint:

```
win.logFileCleared.subjectUserName: vboxuser
win.logFileCleared.subjectDomainName: WINDOWS
win.logFileCleared.channel: Application
win.logFileCleared.clientProcessId: 1688
```

The fields live under **`logFileCleared`**, not `eventdata`. The shipped sample
is dated 2018 and even its `providerGuid` differs from the live event
(`{555908d1-...}` in the comment vs `{fc65ddd8-d6ef-4962-83d5-6e5cfe9ce148}`
observed). Referencing a non-existent field is **not an error** in Wazuh - it
silently renders as empty - so this only surfaced by reading the alert text.

Fix: `$(win.logFileCleared.subjectUserName)`.

Same lesson as Lab 05's `Invoke-Expresion` typo, from the opposite direction:
there the shipped *rule* was wrong, here the shipped *documentation* was.
**The live event is the only source of truth.**

## Bug 2 - 1102 and 104 do not carry the same fields
After fixing Bug 1 the description read
`$(win.logFileCleared.channel) log wiped by ...`, which worked for Event 104
but produced a hole mid-sentence on Event 1102:

```
'Windows event log CLEARED on Windows:  log wiped by vboxuser'
```

Event **104** carries `channel` (naming the log that was cleared). Event
**1102** does **not** - it only ever means the Security log, so Windows does
not name it. Verified against both captured events.

Wazuh rule descriptions have no conditional logic, so the fix is ordering:
move the optional field to the **end** of the sentence, where a missing value
degrades quietly instead of leaving a gap in the middle.

## Attack simulation (on the endpoint)
```powershell
# NEGATIVE CONTROLS - touch the logs without destroying them
Get-WinEvent -LogName Application -MaxEvents 5 | Out-Null
wevtutil epl Application C:\Windows\Temp\app-backup.evtx /ow:true

# POSITIVE 1 - clear a harmless log (Event 104)
wevtutil cl Application

# POSITIVE 2 - clear the audit log (Event 1102)
wevtutil cl Security
```

`wevtutil` is a built-in Windows utility, so it raises no suspicion by its
presence alone - `epl` exports, `cl` clears.

Two points on method:

- **The negative controls read and back up logs rather than doing something
  unrelated.** The failure mode most worth testing is a rule that keys on *any*
  log activity rather than on destruction - a rule that fires when an admin
  exports a log for troubleshooting gets muted within a week. Both controls
  stayed silent.
- **The harmless log was attacked first.** Clearing Application before Security
  means a broken or over-broad rule is caught while the only casualty is a log
  nobody needs (and which had just been exported). Testing the destructive case
  first risks destroying the evidence that proves your own detection does not
  work.

## Detection results
Confirmed firing on live endpoint telemetry.

```
Rule: 100407 (level 13) -> 'Windows event log CLEARED on Windows by vboxuser
                            - anti-forensics, log: Application [T1070.001]'
```
```
Rule: 100407 (level 13) -> 'Windows event log CLEARED on Windows by vboxuser
                            - anti-forensics, log:  [T1070.001]'
```

Full test matrix:

| Test | Action | Event | Expected | Result |
|---|---|---|---|---|
| NC 1 | `Get-WinEvent` (read a log) | none | silent | **silent - passed** |
| NC 2 | `wevtutil epl` (export a log) | none | silent | **silent - passed** |
| Pos 1 | `wevtutil cl Application` | 104 | 100407 L13 | **fired, log named** |
| Pos 2 | `wevtutil cl Security` | 1102 | 100407 L13 | **fired, log field empty by design** |

Both positives correctly identified `vboxuser` as the account responsible.

### The property this lab actually proves
`wevtutil cl Security` erased the endpoint's entire security history - every
4625, 4720, 7045 and 4104 from Labs 01-05 on that machine. **Every
corresponding alert remained intact on the Wazuh manager**, including the alert
describing the erasure itself and naming the account that performed it.

That is the whole argument for centralised logging, demonstrated rather than
asserted: an attacker with full control of an endpoint can destroy what is on
that endpoint, and cannot reach what has already left it.

## Investigation steps
1. Open the **100407** alert - it names the host, the account, and (for Event
   104) which log was cleared. `win.logFileCleared.clientProcessId` identifies
   the process that issued the clear.
2. **Which log was cleared is the first triage question.** Security suggests
   covering authentication or account-manipulation tracks; **PowerShell/
   Operational** suggests covering script execution and points straight back at
   Lab 05's detections.
3. **Correlate backwards, and expect a gap.** Look at what the same account was
   doing before the clear - brute force (100400), admin logon (100401), rogue
   account (100402), persistence (100403/100404), download cradle
   (100405/100406). The clear is usually the *last* action in a chain, so the
   interesting activity sits immediately before it.
4. **Treat the endpoint's local logs as untrustworthy from that timestamp
   onward.** Work from the manager's copy, not the host's.
5. **Contain** - the account that cleared the log is compromised or malicious;
   disable it and isolate the host.

## Notes and limitations
- **No audit policy prerequisite**, unlike Labs 01-04 - these events cannot be
  turned off short of stopping the Event Log service.
- **This detects the aftermath, not the method.** 1102/104 say a log was
  cleared, not which tool did it. Because Lab 05 enabled Script Block Logging,
  a clear performed *via PowerShell* (`Clear-EventLog`, `wevtutil` called from
  a script) also produces a 4104 naming the command - a worthwhile future
  correlation, deliberately out of scope here.
- **An attacker who stops the Event Log service first** suppresses both events.
  That produces a different signal (Event 6005/6006 service stop, shipped rule
  63105) and is a separate detection.
- **`clientProcessId` is not resolved to a process name** by these events.
  Naming the binary requires Event 4688 or Sysmon Event 1 - Module 05.
- **60117's reachability remains unconfirmed** - see the methodology note
  above. The custom rule is deliberately written so the answer does not matter
  operationally.

## Lessons learned
- **The gap is not always missing coverage - sometimes it is severity.** Two
  shipped rules existed and worked; they were simply rated at the level of
  routine informational noise. "Is there a rule?" is the wrong question. "Would
  anyone ever see it?" is the right one.
- **Measure the baseline before you change the system.** Deploying 100407
  before capturing which shipped rule fired destroyed the evidence needed to
  confirm the 60117 prediction. Wazuh reports one rule per event; adding a
  winning rule hides the previous winner.
- **Vendor documentation ages badly, and silently.** The stale sample event in
  Wazuh's own rule comments produced a blank field in a level 13 alert. A
  missing field name raises no error - it just prints nothing.
- **Two events for the same behaviour rarely carry the same fields.** 104
  names the cleared log, 1102 does not. Write descriptions so absent fields
  degrade gracefully rather than leaving holes.
- **Attack the harmless target first.** Ordering the positive tests so the
  destructive one runs last is cheap insurance against destroying your own
  evidence.

## MITRE ATT&CK mapping
```
Indicator Removal: Clear Windows Event Logs (T1070.001)
  |
  +-- Event 1102 (Security channel) --> 60001 > 60017 > 63108 > 63103  Level 5
  |        |                            60001 > 60100 > 60117  Level 9  [UNREACHABLE - sibling loses]
  |        |                                                            [and mis-mapped T1070.004]
  |        +--> if_group --> Rule 100407  Level 13  [DETECTED]
  |
  +-- Event 104 (System channel) ----> 60002 > 60007 > 63100 > 63104  Level 5
           |
           +--> if_group --> Rule 100407  Level 13  [DETECTED]
```

## Status
Complete - Rule **100407** (level 13) confirmed firing on a live Windows 11
endpoint for both log-clearing events: `wevtutil cl Application` (Event 104)
and `wevtutil cl Security` (Event 1102), each naming the responsible account.
Reading and exporting logs stayed silent, confirming the rule keys on
destruction rather than on log access.

The lab documented that shipped coverage existed but alerted at level 5; that
the better shipped rule (60117, level 9) is very likely unreachable due to
sibling ordering and additionally carries the wrong ATT&CK sub-technique; and
that Wazuh's own embedded sample event for these rules is stale, which is what
produced a blank account name in the first draft of the custom rule.
