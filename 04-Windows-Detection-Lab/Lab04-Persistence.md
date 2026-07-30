# Lab 04 - Persistence via Service / Scheduled Task (T1543.003 / T1053.005)

## Objective
Detect the classic "leave a back window open" persistence move: an attacker who
already has access installs a **Windows service** or a **scheduled task** that
runs a hidden payload automatically - at boot, or on a timer - so access
survives even after the original compromised credential is rotated.

Lab 03 caught an attacker creating and elevating their own account. Lab 04
catches the next step: making sure they can come back.

## MITRE ATT&CK
| Field | Value |
|---|---|
| Tactic | Persistence |
| Technique | T1543.003 - Create or Modify System Process: Windows Service |
| Related | T1053.005 - Scheduled Task/Job: Scheduled Task |
| Reference | https://attack.mitre.org/techniques/T1543/003/, https://attack.mitre.org/techniques/T1053/005/ |

## What the shipped ruleset already covers
Both raw events already have built-in Wazuh coverage, deliberately quiet:

| Event | Built-in rule | Level |
|---|---|---|
| 7045 (service created) | 61138 | 4 |
| 4698 (scheduled task created) | 60228 | 4 |

That low volume is correct, not a gap by itself - Windows creates services and
scheduled tasks constantly for entirely benign reasons (Windows Update, printer
drivers, browser updaters). Alerting at high severity on every one would be an
alert-fatigue generator, not a detection.

**The real gap: neither built-in rule inspects *what* is being run.** A
legitimate service points at a real installed program
(`C:\Program Files\...\app.exe`). An attacker's service or task points at a
command interpreter (`cmd.exe`, `powershell.exe`) or a path in a
world-writable location (`\Temp\`, `\AppData\`, `\Users\Public\`) - the same
folders any non-admin process can always write to. That inspection is the
entire custom contribution of this lab.

## The design decision: two rules, one for each object type
Services (7045) decode to field `win.eventdata.imagePath`; scheduled tasks
(4698) decode the entire task definition as XML into
`win.eventdata.taskContent`, containing a `<Command>` element. Different
fields, different parent rules (61138 vs 60228) - so this is two rule IDs for
one lab, the same pattern as Lab 06 (100300/100301).

Both rules are single-event checks - no `timeframe`, no correlation window.
That was a deliberate choice: it sidesteps the open question from Lab 03 about
whether Wazuh's composite `timeframe` is evaluated against manager processing
time rather than the event's own `systemTime`.

## Environment
| Component | Details |
|---|---|
| Endpoint | Windows 11 Home (agent, Wazuh v4.14.6, ID 002 `windows`) |
| Manager | Ubuntu Server, Wazuh 4.14.6 all-in-one |
| Log source | Windows Security channel (eventchannel) |
| Audit prereq | `auditpol` - "Other Object Access Events", **success** (governs both 7045 and 4698) |

## Prerequisites - enable success auditing (on the endpoint)
```powershell
auditpol /set /subcategory:"Other Object Access Events" /success:enable
```
One subcategory covers both service and scheduled-task creation events.
Verified with `auditpol /get /subcategory:"Other Object Access Events"` -
must show **Success** - and confirmed to survive a full VM reboot during this
lab (see Notes).

## Detection rules (on the manager)
Added to `/var/ossec/etc/rules/local_rules.xml`.

```xml
<group name="local,windows,windows_persistence,">

  <rule id="100403" level="12">
    <if_sid>61138</if_sid>
    <field name="win.eventdata.imagePath" type="pcre2">(?i)cmd\.exe|powershell\.exe|\\Temp\\|\\AppData\\|\\Users\\Public\\</field>
    <description>Suspicious service persistence: $(win.eventdata.serviceName) runs $(win.eventdata.imagePath) [T1543.003]</description>
    <options>no_full_log</options>
    <mitre><id>T1543.003</id></mitre>
  </rule>

  <rule id="100404" level="12">
    <if_sid>60228</if_sid>
    <field name="win.eventdata.taskContent" type="pcre2">(?i)cmd\.exe|powershell\.exe|\\Temp\\|\\AppData\\|\\Users\\Public\\</field>
    <description>Suspicious scheduled task persistence: $(win.eventdata.taskName) [T1053.005]</description>
    <options>no_full_log</options>
    <mitre><id>T1053.005</id></mitre>
  </rule>

</group>
```

Design notes:
- **`if_sid 61138` / `60228`** - the event must already be a service or task
  creation.
- **`type="pcre2"` on the field** - **required**, not cosmetic. See Bug 1
  below: without it, `(?i)` is not a recognized inline flag and the rule
  silently never matches, with no validation error.
- **`(?i)`** - case-insensitive, because `CMD.EXE` / `PowerShell.exe` are
  trivial evasions of a case-sensitive match.
- **Level 12** - above the built-in parent's level 4-5, so the flagged case
  clearly outranks routine service/task churn.

## Attack simulation (on the endpoint)
```powershell
sc.exe create LabSvcBad2 binPath= "C:\Windows\System32\cmd.exe /c calc.exe" start= demand
schtasks /create /tn LabTaskBad3 /tr "powershell.exe -Command Get-Process" /sc once /st 23:59
```
`binPath= "..."` requires that exact spacing - a space after `=`, none
before - or `sc.exe` silently creates a broken service definition.

## Detection results
Confirmed firing on live endpoint telemetry, verified against negative
controls run the same session.

```
level:       12
id:          100403
description: Suspicious service persistence: LabSvcBad2 runs C:\Windows\System32\cmd.exe /c calc.exe [T1543.003]
agent:       windows (002)
```
```
level:       12
id:          100404
description: Suspicious scheduled task persistence: \LabTaskBad3 [T1053.005]
agent:       windows (002)
```

Full test matrix, across two sessions (see Bug 1 for why two sessions were
needed):

| Test | Object | Content | Rule expected | Result |
|---|---|---|---|---|
| Negative control | `LabSvcTest` | `notepad.exe` | should stay quiet | **60228/61138 only - passed** |
| Negative control | `LabTaskTest` | `notepad.exe` | should stay quiet | **60228/61138 only - passed** |
| Positive (pre-fix) | `LabSvcBad` | `cmd.exe /c calc.exe` | 100403 | **Did not fire - exposed Bug 1** |
| Positive (pre-fix) | `LabTaskBad` | `powershell.exe ...` | 100404 | Fired - but see Bug 1, not a clean pass |
| Positive (post-fix) | `LabSvcBad2` | `cmd.exe /c calc.exe` | 100403 | **Fired - confirmed under corrected regex engine** |
| Positive (post-fix) | `LabTaskBad3` | `powershell.exe ...` | 100404 | **Fired - confirmed under corrected regex engine** |

## Bug 1 - `(?i)` requires `type="pcre2"`, and the failure was silent
The first deployment used `<field name="win.eventdata.imagePath">(?i)cmd\.exe|...</field>`
with no `type` attribute. It **validated cleanly** (`wazuh-analysisd -t` passed)
and then **never matched anything** in testing.

Root cause: Wazuh's `<field>` tag defaults to its own OSRegex engine, which
does not implement PCRE inline modifiers like `(?i)`. Every shipped rule in
the ruleset that uses `(?i)` also carries `type="pcre2"` on the same tag
(confirmed by grepping `/var/ossec/ruleset/rules/` - e.g.
`0830-sysmon_id_11.xml`); none use it bare. Without the attribute, `analysisd`
still compiles *something* from the pattern - just not PCRE - so there is no
syntax error, only silence.

**The asymmetry that made this dangerous rather than merely broken:** the
service rule (100403, matching `imagePath`) visibly failed to fire on
`LabSvcBad`. The task rule (100404, matching `taskContent`, a much larger XML
blob) *did* fire on `LabTaskBad` - but through the same malformed, unsupported
syntax. It was not correctly interpreting `(?i)` as case-insensitive; it was
coincidentally matching under OSRegex's undocumented handling of the
leftover `(`, `?`, `i`, `)` tokens against a large field. **A rule that passes
by accident on broken logic is worse than one that visibly fails** - nothing
would have caught it until an evasion (a case variation, or a red-flag term
in a different structural position) slipped through silently. Both rules got
the `type="pcre2"` fix for this reason, not just the one that visibly broke.

Fix: add `type="pcre2"` to both `<field>` tags. Re-verified against fresh
objects (`LabSvcBad2`, `LabTaskBad3`) under the corrected engine - both fired
correctly.

## Investigation steps
1. Open the **100403**/**100404** alert - `serviceName`/`taskName` and the
   flagged `imagePath`/command identify what was installed and how.
2. **Correlate backwards** - was this preceded by a brute-force burst (100400),
   an unexpected admin logon (100401), or account creation/elevation (100402)?
   A full chain (access -> escalate -> persist) is a high-confidence
   compromise.
3. **Contain** - stop and delete the service (`sc.exe delete`) or task
   (`schtasks /delete /tn <name> /f`); the payload path itself (a `cmd.exe`
   command line, or a dropped file in `\Temp\`) is the next investigation
   target.

## Notes and limitations
- **One audit subcategory covers both events** ("Other Object Access Events"),
  simpler than Labs 01-03, which each needed a distinct subcategory.
- **`schtasks /create` on an existing task name does not generate a fresh
  4698.** Replacing an existing task appears to log as a different event
  (task *updated*, not *created*) at the Windows Security-auditing layer, even
  though `schtasks` presents "replace" as the user-facing action. Discovered
  when a retest against an already-existing `LabTaskBad2` produced zero
  events; resolved by deleting first and using a genuinely new task name
  (`LabTaskBad3`). Worth knowing before assuming a "no event" result means a
  rule failure - it may mean the wrong event ID was ever emitted.
- **Audit policy survives a full reboot.** Confirmed directly: the endpoint
  VM was rebooted mid-lab (see below) and `auditpol /get` still showed
  Success afterward with no reconfiguration needed - it is stored in the
  persistent security policy database, not session state.
- **Infrastructure note, not a detection finding:** this lab's testing window
  coincided with a severe host memory-pressure episode (see
  [[wazuh-lab-access-2026-machine]] for full detail) that took both the
  manager and the endpoint VM down to a full power-off. Recovery required a
  cold boot of both VMs rather than a service restart. Both were confirmed
  fully healthy - rules intact, audit policy intact - before the final,
  clean test run reported above.
- **Endpoint disk is critically low** - `C:` was observed at **30.5 MB free**
  during this lab (previously ~400MB), a real and worsening constraint on
  this Windows 11 Home endpoint, tracked as an open infrastructure item.

## Lessons learned
- **A clean `wazuh-analysisd -t` validation does not mean a rule works.**
  Syntax validity and semantic correctness are different guarantees; the
  `type="pcre2"` bug passed validation cleanly on both rules.
- **A rule that fires "by accident" is a bigger risk than one that visibly
  fails.** The task rule's coincidental pass on broken logic could easily have
  been mistaken for a working detection and shipped as-is.
- **"No event fired" has more than one explanation.** Before concluding a
  detection rule is broken, confirm which underlying Windows event ID was
  actually generated - `schtasks`'s create-vs-replace event split is a
  concrete example of an assumption (same command == same event) that does
  not hold.
- **Negative controls plus a genuinely fresh object name are both required**
  for a trustworthy retest - reusing a test object name can silently
  invalidate the very test meant to prove the fix.

## MITRE ATT&CK mapping
```
Create or Modify System Process: Windows Service (T1543.003)
  |
  Event 7045 --> built-in rule 61138  Level 4
                    |
                    +--> imagePath flags cmd/powershell/writable path --> Rule 100403  Level 12  [DETECTED]

Scheduled Task/Job: Scheduled Task (T1053.005)
  |
  Event 4698 --> built-in rule 60228  Level 4
                    |
                    +--> taskContent flags cmd/powershell/writable path --> Rule 100404  Level 12  [DETECTED]
```

## Status
Complete - Rules 100403 and 100404 (both level 12) confirmed firing on a live
Windows 11 endpoint: a service pointing at `cmd.exe` and a scheduled task
running `powershell.exe` both triggered their respective rules, while
identical-shaped negative controls pointing at Notepad stayed silent. A
regex-engine bug (missing `type="pcre2"`) that caused one rule to silently
never match - while its sibling rule happened to pass by accident on the same
broken syntax - was found, fixed, and re-verified under the corrected engine.
