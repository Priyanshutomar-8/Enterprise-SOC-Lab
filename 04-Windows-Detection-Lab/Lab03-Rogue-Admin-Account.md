# Lab 03 - Rogue Admin Account Creation (T1136.001 / T1098)

## Objective
Detect the classic post-compromise persistence move: an attacker who already has
administrative access **creates a new local account and immediately grants it
administrator rights**, leaving behind a credential that survives a password
reset on the originally compromised account.

Lab 01 caught the failed-logon burst, Lab 02 the successful privileged logon.
Lab 03 catches what the intruder *does* with that access.

## MITRE ATT&CK
| Field | Value |
|---|---|
| Tactic | Persistence, Privilege Escalation |
| Technique | T1136.001 - Create Account: Local Account |
| Related | T1098 - Account Manipulation |
| Reference | https://attack.mitre.org/techniques/T1136/001/ |

## What the shipped ruleset already covers - and why that shaped this lab
The first step was reading Wazuh's own ruleset instead of assuming a gap. Unlike
Lab 02 - where **no** built-in 4672 rule existed - both raw events here are
already covered, and covered well:

| Event | Built-in rule | Level | Notes |
|---|---|---|---|
| 4720 created / 4722 enabled | 60109 | 8 | both event IDs map to the same rule |
| 4738 account changed | 60110 | 8 | fired by `net user` setting the password |
| 4732 -> **Users** | 60170 | 5 | matches `targetSid ^S-1-5-\S+-545$` |
| 4732 -> **Administrators** | **60154** | **12** | matches `targetSid ^S-1-5-32-544$` |

**60154 already does privileged-group scoping**, and anchors on the well-known
SID `S-1-5-32-544` rather than the string "Administrators" - locale-independent,
and better than a name match. An earlier draft of this lab included a custom
"alert on adds to Administrators" rule; it would have been a line-for-line
rebuild of 60154. It was dropped.

So this lab deliberately does **not** re-detect the individual events. The one
thing the ruleset does not do is **correlate the sequence**.

## The design decision: detect the sequence, not the events
A lone 4720 is helpdesk noise. A lone 60154 may be a legitimate group edit. The
**same actor creating an account and then elevating an account to local
Administrators within seconds** is the attacker storyline - and nothing in the
default ruleset joins those two facts.

The custom rule is therefore a **composite**: it triggers on the Administrators
group-add (60154) only when that actor also triggered an account creation
(60109) inside a 120-second window.

## Environment
| Component | Details |
|---|---|
| Endpoint | Windows 11 Home (agent, Wazuh v4.14.6, ID 002 `windows`) |
| Manager | Ubuntu Server, Wazuh 4.14.6 all-in-one |
| Log source | Windows Security channel (eventchannel) |
| Audit prereqs | `auditpol` - User Account Management + Security Group Management, **success** |

## Prerequisites - enable success auditing (on the endpoint)
```powershell
auditpol /set /subcategory:"User Account Management" /success:enable
auditpol /set /subcategory:"Security Group Management" /success:enable
```

Both require an **elevated** PowerShell. A non-elevated shell fails with
`Error 0x00000522: A required privilege is not held by the client`, and
`net user /add` fails with `System error 5`, **even when the account is an
administrator** - UAC hands the shell a filtered token. The `C:\WINDOWS\system32`
prompt is not proof of elevation. Verify explicitly:

```powershell
([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
# must print True
```

## Detection rule (on the manager)
Added to `/var/ossec/etc/rules/local_rules.xml`.

```xml
<group name="local,windows,windows_security,">

  <rule id="100402" level="13" timeframe="120">
    <if_sid>60154</if_sid>
    <if_matched_sid>60109</if_matched_sid>
    <field name="win.system.eventID">^4732$</field>
    <same_field>win.eventdata.subjectUserName</same_field>
    <description>Rogue admin account: $(win.eventdata.subjectUserName) created an account and added SID $(win.eventdata.memberSid) to Administrators within 120s [T1136.001/T1098]</description>
    <options>no_full_log</options>
    <mitre><id>T1136.001</id><id>T1098</id></mitre>
  </rule>

</group>
```

Design notes:
- **`if_sid 60154`** - the current event must be an Administrators group change.
- **`if_matched_sid 60109`** - an account-creation alert must have preceded it
  within `timeframe`.
- **`field eventID ^4732$`** - **essential**, see Bug 1 below. 60154 is built on
  `if_sid 60144,60145` - member *added* **and** member *removed*. Without this
  guard a 4733 removal also matches and is reported as an addition.
- **`same_field subjectUserName`** - ties both events to the same actor. Its
  limits are documented in Bug 2.
- **Level 13** - one above 60154's own level 12, so the correlated sequence
  outranks the individual group change it is built from.

## Attack simulation (on the endpoint)
```powershell
net user svc_ops * /add
net localgroup administrators svc_ops /add
```

`*` prompts for the password interactively (masked) rather than putting a
credential on the command line or in this repository.

## Detection results
Confirmed firing on live endpoint telemetry, with two negative controls.

```
level:       13
id:          100402
description: Rogue admin account: vboxuser created an account and added SID
             S-1-5-21-1921619791-3159049687-311327346-1003 to Administrators within 120s
agent:       windows (002)
```

Full verified timeline (manager clock, UTC):

| Time | Event | Gap since 4720 | Rule fired | Verdict |
|---|---|---|---|---|
| 22:01:57 | 4720 + 4722 + 4738 + 4732(Users) | - | 60109 x2, 60110, 60170 | `svc_ops` created |
| 22:02:06 | 4732 -> Administrators | 9s | **100402** (L13) | **True positive** |
| 22:02:15 | 4733 <- Administrators | 18s | 60154 only | **Removal control passed** |
| 22:03:14 | 4732 -> Administrators | 77s (in window) | 100402 | Correct by design - see Bug 2 |
| 22:05:35 | 4733 <- Administrators | 218s | 60154 only | - |
| 22:05:42 | 4732 -> Administrators | 225s (expired) | 60154 only | **Timeframe control passed** |

| Rule ID | Description | Severity | Result |
|---|---|---|---|
| 100402 | Rogue admin account (4720 -> 4732 Administrators, same actor, 120s) | Level 13 | **Confirmed firing** |

The **22:02:15 removal control** is the strongest evidence in this table: that
4733 landed 9 seconds after the true positive, deep inside the 120s window with
live 60109 matches available. Before the `eventID` guard, that exact event fired
a false alert. It now produces 60154 alone.

The **22:05:42 timeframe control** is a genuine addition to Administrators with
no account creation in the preceding 120s - 100402 correctly stayed silent.

## Two bugs the negative controls caught
The first deployment of this rule fired **three times** on a four-command
simulation. Only one firing was correct.

### Bug 1 - the rule fired on group *removals* (fixed)
`net localgroup administrators svc_backup /delete` produced Event **4733**, which
matched and was reported as *"created an account and added SID ... to
Administrators"*. Wrong on the facts.

Root cause: parent rule **60154 covers both 60144 (added) and 60145 (removed)** -
its description, "Administrators Group Changed", is honestly vague about which.
Inheriting from it without pinning the event ID inherits that ambiguity.

Fix: the explicit `<field name="win.system.eventID">^4732$</field>` guard,
verified by the 22:02:15 control above.

### Bug 2 - the correlation ties the actor, not the account (documented, not fixable)
The rule also fired on re-adding an account created hours earlier, because the
same actor had created a *different* account within the window. The 22:03:14 row
in the results table is this behaviour reproduced deliberately.

The correct correlation key would be **4720's `targetSid` == 4732's
`memberSid`**. Wazuh's `same_field` compares a field against *itself* across
events; it cannot cross-match two differently-named fields, and the rule language
has no expression for it.

This is a real limitation, not an oversight, and it is documented rather than
hidden. **100402 detects "the same actor created an account *and* elevated an
account within 120s"** - a strong sequence heuristic, not proof that they are the
same account. The analyst closes the gap by hand (Investigation step 2).

## Investigation steps
1. Open the **100402** alert - `subjectUserName` is the actor, and the agent
   identifies the host.
2. **Resolve the member SID.** 4732 carries only `memberSid`; on a workgroup host
   `memberName` is absent entirely, so the alert names a SID, not a user. Match
   that SID against the `targetSid` of the preceding **4720** - this both
   identifies the created account and confirms the two events really concern the
   same account (Bug 2).
3. **Was the creation authorised?** A new local admin outside a change ticket is
   the incident. Check whether the actor legitimately administers this host.
4. **Correlate backwards** - was the actor's session preceded by a brute-force
   burst (100400) or an unexpected admin logon (100401)? That chain is a full
   compromise storyline: access -> escalate -> persist.
5. **Contain** - disable the created account, remove it from Administrators, and
   audit for other accounts created by the same actor.

## Notes and limitations
- **`net user /add` is not one event.** It emits a cluster: **4720** (created),
  **4722** (enabled), **4738** (changed, from the password being set), and
  **4732** into **Users**. Both 4720 and 4722 map to 60109, so a single account
  creation yields *two* level-8 alerts that look duplicated.
- **`memberName` is absent on a workgroup host** - only `memberSid` is
  populated, so no rule built on 4732 alone can name the elevated account.
- **Correlation is actor-scoped, not account-scoped** (Bug 2).
- **Domain environments differ** - 4728 (global group) and rule 60141 are the
  domain equivalents; this rule covers local groups (4732) only.
- **Buffered agents and `timeframe` - untested hypothesis.** During this lab the
  endpoint agent buffered while the manager was restarting, then replayed the
  backlog: events generated at 21:13 were processed at 21:40, 27 minutes late.
  If `analysisd` evaluates composite windows against processing time rather than
  the event's own `systemTime`, a long outage could collapse real-world gaps and
  correlate events that were minutes apart. The replay in this lab could not
  isolate that, because the underlying events were also within 120s of each
  other. **Flagged as a hypothesis to test, not a verified finding** - worth
  settling before trusting a tight `timeframe` in production.

## Lessons learned
- **Read the shipped ruleset before writing a rule.** The first draft of this lab
  included a rule that turned out to duplicate built-in 60154 - which was already
  anchored on the well-known SID, the more robust approach. A custom rule earns
  its place only where the ruleset genuinely stops: here, correlation.
- **Inheriting a parent inherits its ambiguity.** 60154 means "changed", not
  "added". Building on it without pinning the event ID produced an alert that
  actively misreported what happened.
- **Negative controls are the test, not a formality.** The positive case passed
  on the first run and looked like success. Both bugs were visible only because
  the simulation deliberately included a removal and a no-creation re-add.
- **A control that can't fail proves nothing.** Three attempts at the timeframe
  control were void - run inside the window, or rejected by Windows with
  `System error 1378` before generating any event at all. A negative control has
  to be constructed so that the fix under test is the *only* thing that can keep
  it silent.
- **State the limitation in the rule, not just the writeup.** Bug 2 cannot be
  fixed in Wazuh's rule language, so the constraint lives as a comment beside the
  rule, where the next person to edit it will see it.

## MITRE ATT&CK mapping
```
Create Account: Local Account (T1136.001)
  |
  Event 4720/4722 --> built-in rule 60109  Level 8
                          |
                          +--> correlated (same actor, 120s) --> Rule 100402  Level 13  [DETECTED]
                          |
  Event 4732 (targetSid S-1-5-32-544) --> built-in rule 60154  Level 12
  |
Account Manipulation (T1098)
```

## Status
Complete - Rule 100402 (level 13) confirmed firing on a live Windows 11 endpoint:
`vboxuser` created `svc_ops` and added it to Administrators 9 seconds later,
producing one correlated alert. Both negative controls pass - a group **removal**
(4733) and an addition **outside** the 120s window each produce built-in 60154
only, with no 100402. The actor-vs-account correlation limit (Bug 2) is
documented as an accepted constraint of Wazuh's rule language.
