# Lab 07 - Defense Evasion: Microsoft Defender Tampering (T1562.001)

## Objective
Detect an attacker disarming the endpoint's antivirus before doing anything
else - the step that makes every later step quieter.

There are two ways to do it, and they are not equally loud:

| Approach | What it looks like | Reality |
|---|---|---|
| **Switch protection off** | Obvious, total | Blocked by Tamper Protection on a modern default install |
| **Add an exclusion** | Defender stays "on", green checkmark intact | Succeeds, and is the technique real intrusions actually use |

An exclusion is the interesting case. Defender keeps running, the UI keeps
reporting a healthy state, and one registry value quietly instructs it to stop
looking at a directory. Ransomware operators do this before staging payloads
precisely because nothing appears to break.

| Event | Meaning | Channel |
|---|---|---|
| **5007** | Defender configuration changed (includes exclusions) | Microsoft-Windows-Windows Defender/Operational |
| **5013** | Tamper Protection **blocked** a change | Microsoft-Windows-Windows Defender/Operational |
| 5001 / 5010 / 5012 | Real-time protection or scanning disabled | Microsoft-Windows-Windows Defender/Operational |

## MITRE ATT&CK
| Field | Value |
|---|---|
| Tactic | Defense Evasion |
| Technique | T1562.001 - Impair Defenses: Disable or Modify Tools |
| Reference | https://attack.mitre.org/techniques/T1562/001/ |

## Environment
| Component | Details |
|---|---|
| Endpoint | Windows 11 Home (agent, Wazuh v4.14.6, ID 002 `windows`) |
| Manager | Ubuntu Server, Wazuh 4.14.6 all-in-one |
| Log sources | **Microsoft-Windows-Windows Defender/Operational** (new in this lab) and `Microsoft-Windows-PowerShell/Operational` (from Lab 05) |
| Defender state | `AMRunningMode: Normal`, real-time protection **enabled**, **`IsTamperProtected: True`** |
| Audit prereq | **None** - Defender writes these events unconditionally |

### Collecting the channel
Defender events are **not** on the Security channel, so the agent must subscribe
to a third log source. Pushed through the centralized `windows` agent group
rather than by editing `ossec.conf` on the endpoint - the same mechanism Lab 05
introduced, and for the same reason: the Windows VM has no SSH, so every local
edit is a manual console step.

```xml
<localfile>
  <location>Microsoft-Windows-Windows Defender/Operational</location>
  <log_format>eventchannel</log_format>
</localfile>
```

The channel string must match exactly - Wazuh's gating rule 60005 anchors on
`^Microsoft-Windows-Windows Defender/Operational$`, and the space inside
"Windows Defender" is part of it.

### Tamper Protection decides which half of the lab is reachable
`IsTamperProtected: True` is not an obstacle here, it is the subject. It blocks
the loud attack and permits the quiet one - which is the lab's entire thesis,
handed over by the operating system itself:

| Attack | Tamper Protection | Event |
|---|---|---|
| Disable real-time protection | **Blocks** | 5013 |
| Add an exclusion path | **Allows** | 5007 |

Microsoft protects the switch and not the blind spot. That asymmetry is why
exclusion abuse is worth a dedicated detection.

## What the shipped ruleset already covers
Traced by hand before writing anything, per the Lab 03 discipline. Everything on
this channel gates through **60005**, then splits by severity into 62100
(INFORMATION, **level 0**), 62101 (WARNING, level 0) and 62102 (ERROR, level 5).

| Event | Shipped rule | Level | Assessment |
|---|---|---|---|
| 5007 - configuration changed | 62154 | **5** | Fires, but never says *what* changed. No MITRE tag. |
| 5001 - real-time protection disabled | 62152 | **5** | Same band as a printer driver install. No MITRE tag. |
| 5004 - RTP feature config changed | 62153 | 3 | - |
| 5010 / 5012 - scanning disabled | 62157 / 62159 | 10 | Reasonable as shipped. |
| **5013 - tamper attempt blocked** | **none** | **0** | **No rule exists.** |

Two gaps, of different kinds.

### Gap 1 - 5007 cannot distinguish tuning from sabotage
Rule 62154 fires on *any* configuration change and describes all of them
identically: `Windows Defender: Antimalware platform feature configuration
changed`. Setting the scan CPU ceiling and blinding the scanner to a directory
are the same event ID, and on a stock install they produce the same alert text
at the same severity. **The discriminator is not the event - it is which value
changed, and in which direction.**

### Gap 2 - 5013 has no coverage at all
Searching the entire shipped ruleset for `5013` returns exactly one hit, and it
is a false friend: **rule 60691**, on the *Application* channel, describing
`Routine BackupEventLogW called by EventLogs failed`. An unrelated event that
happens to share a number.

Defender's 5013 carries `severityValue: INFORMATION`, so it matches 62100 at
**level 0** and is discarded. On a default install, an attacker attempting to
disable antivirus - and being stopped by the OS - generates **no alert of any
kind**. This is the highest-fidelity signal on the platform: nothing legitimate
trips Tamper Protection.

### Gap 3 - the command-line detection is Sysmon-gated
Wazuh does ship a `Set-MpPreference` detection:

```xml
<rule id="92007" level="3">
  <if_group>sysmon_event1</if_group>
  <field name="win.eventdata.image" type="pcre2">(?i)\\powershell\.exe</field>
  <field name="win.eventdata.commandLine" type="pcre2">(?i)Set-MpPreference</field>
  ...
<rule id="92008" level="12">
  <if_sid>92007</if_sid>
  <field name="win.eventdata.commandLine" type="pcre2">(?i)(DisableRealtimeMonitoring|drtm)\s+(\$true|1)</field>
```

Both hang off `sysmon_event1` and read `win.eventdata.commandLine` - a field that
only exists with Sysmon installed. **No Sysmon, no detection**, and Sysmon is
Module 05. There is no equivalent rule on the PowerShell Script Block channel,
even though Lab 05 already enabled it.

## Baseline - measured *before* deploying anything
Lab 06 recorded a methodology failure: a custom rule was deployed before a
baseline was captured, which destroyed the evidence needed to confirm a
prediction about the shipped ruleset. That mistake is not repeated here.

`logall_json` was enabled first so that **level-0 events reach disk** - without
it, 5013 never appears in `alerts.json` at all and the most important event in
the lab would have been invisible to its own investigation.

Attacks were then run against the **stock** ruleset:

| Time (UTC) | Action | Event | Alert | Level |
|---|---|---|---|---|
| 18:57:48 | `Set-MpPreference -ScanAvgCPULoadFactor 30` (benign) | 5007 | 62154 | 5 |
| 18:58:51 | `Add-MpPreference -ExclusionPath C:\LabTemp` (**attack**) | 5007 | 62154 | **5** |
| 18:59:11 | `Set-MpPreference -DisableRealtimeMonitoring $true` (**attack**) | 5013 | **none** | - |

The benign change and the attack produced **byte-identical alerts**. Not
similar - identical.

### The noise floor, measured rather than asserted
In the same ten-minute window, rule **61102** (`Windows System error event`,
level 5) fired **17 times** from a repeatedly failing Windows Search service
(events 7023 / 7034 / 10010).

So the exclusion alert was not missing. It was published at level 5, into a
stream carrying seventeen other level-5 events in the same ten minutes. **"Is
there a rule?" is the wrong question; "would anyone ever see it?" is the right
one** - and here that question has a number attached.

## The live events - field names taken from the wire
Captured from `archives.json`. Vendor documentation was not trusted for field
names, following Lab 06's stale-sample bug.

**5007 - benign tuning** (both values present):
```json
"eventdata": {
  "product Name": "Microsoft Defender Antivirus",
  "old Value": "Default\\Scan\\AvgCPULoadFactor = 0x32",
  "new Value": "HKLM\\SOFTWARE\\Microsoft\\Windows Defender\\Scan\\AvgCPULoadFactor = 0x1E"
}
```

**5007 - exclusion added** (note: **no `old Value` field at all**):
```json
"eventdata": {
  "product Name": "Microsoft Defender Antivirus",
  "new Value": "HKLM\\SOFTWARE\\Microsoft\\Windows Defender\\Exclusions\\Paths\\C:\\LabTemp = 0x0"
}
```

**5013 - tamper blocked**:
```json
"eventdata": {
  "changed Type": "Blocked",
  "value": "HKLM\\SOFTWARE\\Microsoft\\Windows Defender\\Real-Time Protection\\DisableRealtimeMonitoring = (Current)"
}
```

Three properties of this data drove the rule design:

1. **Field names contain spaces.** Wazuh lowercases only the *first character* of
   the Windows `Data Name`, so `Old Value` becomes `old Value` - space intact.
2. **`Default\...` means reverted, `HKLM\...` means explicitly set.** This is the
   direction indicator, and it is what separates adding an exclusion from
   removing one.
3. **`message` and `eventdata` escape backslashes differently.** The same path is
   `HKLM\SOFTWARE` in `win.system.message` and `HKLM\\SOFTWARE` in
   `win.eventdata`. Any regex counting backslashes must know which it is reading.

## Detection rules (on the manager)
Added to `/var/ossec/etc/rules/local_rules.xml`. Three rules: two on the result,
one on the method.

```xml
<group name="local,windows,defender_tamper,">

  <rule id="100408" level="12">
    <if_group>windows_defender</if_group>
    <field name="win.system.eventID">^5007$</field>
    <field name="win.system.message" type="pcre2">(?i)New value:[^\r\n]*HKLM[^\r\n]*Exclusions</field>
    <description>Microsoft Defender EXCLUSION added on $(win.system.computer) - scanner is now blind to this location [T1562.001]: $(win.eventdata.new Value)</description>
    <options>no_full_log</options>
    <mitre><id>T1562.001</id></mitre>
  </rule>

  <rule id="100409" level="10">
    <if_group>windows_defender</if_group>
    <field name="win.system.eventID">^5013$</field>
    <description>Tamper Protection BLOCKED a change to Microsoft Defender on $(win.system.computer) - attempted protection tampering [T1562.001]: $(win.eventdata.value)</description>
    <options>no_full_log</options>
    <mitre><id>T1562.001</id></mitre>
  </rule>

  <rule id="100410" level="12">
    <if_group>powershell</if_group>
    <field name="win.system.eventID">^4104$</field>
    <field name="win.eventdata.scriptBlockText" type="pcre2">(?i)\b(Set|Add)-MpPreference\b</field>
    <field name="win.eventdata.scriptBlockText" type="pcre2">(?i)-(ExclusionPath|ExclusionExtension|ExclusionProcess|ExclusionIpAddress|DisableRealtimeMonitoring|DisableIOAVProtection|DisableBehaviorMonitoring|DisableScriptScanning|DisableBlockAtFirstSeen|MAPSReporting)\b</field>
    <description>PowerShell command attempted to weaken Microsoft Defender on $(win.system.computer) - AV tampering via Set/Add-MpPreference [T1562.001]</description>
    <options>no_full_log</options>
    <mitre><id>T1562.001</id></mitre>
  </rule>

</group>
```

Design notes:

- **`if_group`, not `if_sid`** - carried over from Labs 05 and 06. Chaining to a
  group survives whichever shipped rule wins the event, so these cannot be
  orphaned by sibling ordering.
- **Custom group `defender_tamper`** contains neither `windows_defender` nor
  `powershell` as a substring, so `if_group` cannot match these rules against
  themselves. Same precaution as `ps_cradle` (Lab 05) and `log_wipe` (Lab 06).
- **100408 matches on `win.system.message`, not the eventdata field.** The
  decoded field is literally named `new Value`, with a space. Rather than stake
  the detection on whether the rule engine can address such a name, the *match*
  runs against the message text - which additionally has single backslashes and
  no escaping ambiguity. The space-named field is still referenced in the
  *description*, where a failure would degrade to a blank rather than kill the
  rule. (It rendered. See Finding 1 below.)
- **`New value:[^\r\n]*HKLM[^\r\n]*Exclusions`** is doing two jobs. Anchoring to
  the *New value* line means removing an exclusion does not fire; requiring
  `HKLM` means the value was explicitly **set** rather than reverted to
  `Default\`. Both were verified by negative control.
- **100409 needs no field beyond the event ID.** 5013 has exactly one meaning.
- **Level 10 for 5013, level 12 for the others.** The tamper attempt **failed** -
  that is "someone is here and trying", not "you are already blind". Ranking a
  blocked attack above a successful one would be dishonest.
- **100410 requires two conditions, and the second is what makes it usable.**
  See Bug 2.

## Bug 1 - Wazuh misdiagnoses its own subscription failure
On first subscribing to the channel, the agent logged:

```
WARNING: The eventlog service is down. Unable to collect logs from
         'Microsoft-Windows-Windows Defender/Operational' channel.
ERROR: Could not EvtSubscribe() for (Microsoft-Windows-Windows Defender/Operational)
       which returned (15007)
```

**15007 is `ERROR_EVT_CHANNEL_NOT_FOUND`** - Windows saying "no such channel".
Wazuh translates that into a claim about the Event Log *service* being down,
which is a different fault with a different fix. Checked directly against
Windows at the time:

```
LogName                                        IsEnabled RecordCount
Microsoft-Windows-Windows Defender/Operational      True         952
```

The channel existed, was enabled, and held 952 records while the agent was
reporting the service as down. The subscription succeeded on retry
(`channel has been reconnected succesfully`) and has been stable since.

Third instance in this module of vendor text sending an analyst to the wrong
place - after Lab 05's `Invoke-Expresion` typo and Lab 06's stale sample event.
**Verify the platform's claim against the platform.**

## Bug 2 - a naive PowerShell rule is a false-positive machine
The obvious version of rule 100410 matches `MpPreference` in the script block
text. That rule is unusable, and the negative control proves it in one command.

Running the **read-only** `Get-MpPreference` emitted roughly **18 script-block
events** of auto-generated cmdlet-definition boilerplate, containing text like:

```
${DisableScriptScanning}
Name = 'DisableEmailScanning'
Name = 'DisableCoreServiceTelemetry'
${AttackSurfaceReductionRules_RuleSpecificExclusions_Id}
```

Every dangerous-looking keyword an analyst would think to match on appears in
the module's own parameter declarations - emitted when somebody merely *looks at*
the settings. A keyword rule would fire eighteen times on a read.

The fix is requiring **both** a mutating verb (`Set-`/`Add-`) **and** a
protection-weakening parameter. `Remove-MpPreference` fails the first test,
`-ScanAvgCPULoadFactor` fails the second, and the boilerplate flood fails both.

## Attack simulation (on the endpoint)
```powershell
# PRE-STATE - record what you are about to change
Get-MpComputerStatus | Select-Object AMRunningMode,RealTimeProtectionEnabled,IsTamperProtected
Get-MpPreference | Select-Object ScanAvgCPULoadFactor
Get-MpPreference | Select-Object -ExpandProperty ExclusionPath

# NEGATIVE CONTROLS
Remove-MpPreference -ExclusionPath "C:\LabTemp"     # NC1 - undoing an attack
Set-MpPreference -ScanAvgCPULoadFactor 50           # NC2 - benign config change (5007)
Get-MpPreference | Select-Object -ExpandProperty ExclusionPath   # NC3 - read only

# POSITIVE 1 - the quiet attack: blind the scanner
New-Item -ItemType Directory -Path "C:\LabTemp" -Force
Add-MpPreference -ExclusionPath "C:\LabTemp"

# POSITIVE 2 - the loud attack: switch protection off
Set-MpPreference -DisableRealtimeMonitoring $true

# RESTORE
Remove-MpPreference -ExclusionPath "C:\LabTemp"
Set-MpPreference -DisableRealtimeMonitoring $false
Remove-Item "C:\LabTemp" -Recurse -Force
```

Three points on method:

- **Each negative control targets a specific way the rule could be wrong**, not
  merely "something unrelated". NC1 tests whether *fixing* the problem looks like
  causing it; NC2 tests whether the rule keys on *what* changed rather than
  *that* something changed; NC3 tests the boilerplate flood from Bug 2. A control
  that cannot fail is not a control.
- **The benign change is the same event ID as the attack.** That is the point of
  including it - it is the exact case the shipped rule cannot separate.
- **The pre-state is recorded before anything is touched**, so the machine can be
  restored exactly. `ScanAvgCPULoadFactor` was `50`; the exclusion list was empty.

### Positive 2 behaves differently than expected
`Set-MpPreference -DisableRealtimeMonitoring $true` **returned no error**. It
looked like it succeeded. It did not:

```
RealTimeProtectionEnabled : True
```

Tamper Protection accepted the request and overruled the enforcement, recording
`changed Type: Blocked`. An attacker running this command gets no feedback that
they failed - which is an argument for detecting the *attempt* rather than
waiting to observe the *outcome*.

## Detection results
Confirmed firing on live endpoint telemetry.

```
Rule: 100410 (level 12) -> 'PowerShell command attempted to weaken Microsoft Defender
                            on Windows - AV tampering via Set/Add-MpPreference [T1562.001]'
Rule: 100408 (level 12) -> 'Microsoft Defender EXCLUSION added on Windows - scanner is now
                            blind to this location [T1562.001]:
                            HKLM\\SOFTWARE\\Microsoft\\Windows Defender\\Exclusions\\Paths\\C:\\LabTemp = 0x0'
Rule: 100410 (level 12) -> 'PowerShell command attempted to weaken Microsoft Defender
                            on Windows - AV tampering via Set/Add-MpPreference [T1562.001]'
Rule: 100409 (level 10) -> 'Tamper Protection BLOCKED a change to Microsoft Defender on Windows
                            - attempted protection tampering [T1562.001]:
                            HKLM\\SOFTWARE\\Microsoft\\Windows Defender\\Real-Time Protection\\DisableRealtimeMonitoring = (Current)'
```

Full test matrix:

| Test | Action | Event | Expected | Result |
|---|---|---|---|---|
| NC 1 | `Remove-MpPreference -ExclusionPath` | 5007 | silent | **silent - passed** |
| NC 2 | `Set-MpPreference -ScanAvgCPULoadFactor 50` | 5007 | silent | **silent - passed** |
| NC 3 | `Get-MpPreference` (read) | 4104 x ~18 | silent | **silent - passed** |
| Pos 1 | `Add-MpPreference -ExclusionPath` | 5007 + 4104 | 100408 + 100410 | **both fired, path named** |
| Pos 2 | `Set-MpPreference -DisableRealtimeMonitoring $true` | 5013 + 4104 | 100409 + 100410 | **both fired** |

### Before and after, same action
| Action | Stock ruleset | With Lab 07 rules |
|---|---|---|
| Exclusion added | 62154, level 5, indistinguishable from CPU tuning | **100408, level 12, names the excluded path** |
| Tamper attempt blocked | **no alert at all** | **100409, level 10, names the targeted setting** |
| Either, via PowerShell | no alert (Sysmon-gated) | **100410, level 12, on the command itself** |

### Why two detection paths for one attack
100410 watches the **method**, 100408/100409 watch the **result**, and they fail
independently:

- Exclusion added through the Windows Security GUI, or by a non-PowerShell
  process -> no 4104, but 100408 still fires.
- Defender's own channel unavailable, or the attacker clears it (Lab 06) ->
  100408/100409 lost, but 100410 still fires from the PowerShell channel.

Neither is redundant with the other, which is the test for whether a second rule
earns its place.

## Investigation steps
1. **Open the 100408 alert - the excluded path is the lead.** It tells you where
   the attacker intends to work. Anything written there afterwards was never
   scanned.
2. **Check whether the exclusion is still present.** `Get-MpPreference` on the
   host. A *removed* exclusion means the attacker cleaned up - and 100408 does
   not fire on removal by design, so the alert is your only record that it ever
   existed.
3. **Treat 100409 as an intrusion in progress, not a blocked nuisance.** Tamper
   Protection stopped this attempt. It does not stop an attacker who has other
   options, and nothing legitimate produces this event.
4. **Correlate backwards through the module.** These almost never appear first:
   brute force (100400), admin logon (100401), rogue account (100402),
   persistence (100403/100404), download cradle (100405/100406). Disarming the AV
   is preparation - look for what it was preparing *for*.
5. **Correlate forwards to log clearing (100407).** Tampering with Defender and
   wiping event logs are the same instinct at different stages.
6. **Contain.** Re-enable protection, remove the exclusion, and scan the excluded
   path explicitly - it is the one place on disk with no scan history.

## Notes and limitations
- **No audit-policy prerequisite**, unlike Labs 01-04. Defender writes these
  events unconditionally.
- **Tamper Protection is doing real work here, and cannot be assumed.** On a
  machine where it is off, `DisableRealtimeMonitoring` succeeds and produces
  **5001** (shipped rule 62152, level 5) instead of 5013 - which is *also*
  under-rated and is **not** covered by these rules. That branch was not
  reachable on this endpoint and is therefore not claimed. A production ruleset
  should elevate 5001 as well.
- **100408 detects addition, not the exclusion's existence.** An exclusion added
  before the rule was deployed is invisible to it. Periodic configuration
  auditing, not event detection, is the answer to that.
- **100410 covers PowerShell only.** Exclusions set through the GUI, Group
  Policy, `MpCmdRun.exe`, or direct registry writes produce no 4104 - which is
  exactly why 100408/100409 exist alongside it.
- **Registry-level detection was not built.** These settings live under
  `HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions`, so FIM on that key would
  catch writes that bypass both channels. Deferred rather than dismissed.
- **The `1102`/`104` interaction is untested.** An attacker who clears the
  Defender Operational channel after tampering would trigger Lab 06's 100407, but
  that specific sequence was not simulated.
- **Timestamps required care.** The agent writes its log in the endpoint's
  **local** time while the manager records **UTC** - a four-hour apparent offset
  that is not a fault. Separately, resuming a saved VM produced a backwards clock
  jump and a scan reporting a duration of **-424 seconds**; NTP was found
  inactive on the manager. Evidence timestamps in a paused-VM lab deserve
  scepticism, and this bears on the open question from Lab 03 about whether
  correlation windows are judged on event time or processing time.

## Lessons learned
- **The vendor's own defaults tell you where the attacker will go.** Tamper
  Protection guards the switch and not the blind spot. That asymmetry is not an
  oversight to complain about - it is a map of which technique to detect.
- **Measuring the baseline first changed the lab.** Following Lab 06's correction,
  `logall_json` was enabled *before* any rule was deployed. Without it, event
  5013 - the event with no shipped coverage, and the most valuable finding here -
  would never have reached disk, because level-0 events do not produce alerts.
  **You cannot discover an invisible event by looking at the alert stream.**
- **"Would anyone see it?" deserves a number.** Seventeen level-5 events in the
  same ten minutes is a measurement; "level 5 is too low" is an opinion. The
  first survives review.
- **A negative control must be able to fail.** Three controls, three distinct
  failure modes - undo, benign change, read-only. The read-only one uncovered an
  18-event boilerplate flood that would have made the naive rule unusable, and no
  amount of reading the rule would have revealed it.
- **The same value is spelled differently in different parts of the same event.**
  Single backslashes in `message`, doubled in `eventdata`. Match against the
  representation you have actually read, not the one you assume.
- **A blocked attack is still an attack, and it is a better signal than a
  successful one.** 5013 only exists because something tried and failed. It has
  a near-zero legitimate rate, which is exactly the property a detection wants -
  and it was rated level 0.

## Findings for the record
**Finding 1 - Wazuh can address a field name containing a space.** The decoded
field is `new Value`; `$(win.eventdata.new Value)` rendered the full registry
path in the live alert. The opposite outcome to Lab 06, where a *wrongly named*
field silently rendered blank - reinforcing that a blank field means the name is
wrong, not that the syntax is unsupported.

**Finding 2 - shipped rule 60691 collides with Defender's 5013.** Different
channel, different provider, same event number, and the ruleset's only match for
`5013`. A text search for coverage returns a false positive; only tracing the
channel gate distinguishes them.

**Finding 3 - `Set-MpPreference` coverage is unreachable without Sysmon.** Rules
92007/92008 are the only shipped detection for AV tampering by command, and both
require `sysmon_event1`. On a native-logs-only endpoint an ATT&CK coverage chart
would show T1562.001 as covered while nothing can fire.

## MITRE ATT&CK mapping
```
Impair Defenses: Disable or Modify Tools (T1562.001)
  |
  +-- Event 5007 (exclusion added) ---> 60000 > 60005 > 62100 > 62154   Level 5
  |        |                            [indistinguishable from benign config change]
  |        +--> if_group --> Rule 100408  Level 12  [DETECTED - names the path]
  |
  +-- Event 5013 (tamper blocked) ----> 60000 > 60005 > 62100          Level 0
  |        |                            [NO SHIPPED RULE - no alert produced]
  |        +--> if_group --> Rule 100409  Level 10  [DETECTED]
  |
  +-- Event 4104 (script block) ------> [92007/92008 require Sysmon - unreachable]
           |
           +--> if_group --> Rule 100410  Level 12  [DETECTED - the method]
```

## Status
Complete - Rules **100408** (level 12), **100409** (level 10) and **100410**
(level 12) confirmed firing on a live Windows 11 endpoint. Adding a Defender
exclusion raised a level 12 alert naming the excluded path; a Tamper
Protection-blocked attempt to disable real-time protection raised a level 10
alert naming the targeted setting, where the stock ruleset raised nothing at all;
and both attacks were independently caught from PowerShell script-block
telemetry. Undoing an exclusion, changing a benign setting, and reading the
configuration all stayed silent.

The lab documented that the stock ruleset rates an exclusion identically to a CPU
tuning change at level 5, against a measured background of 17 other level-5
events in the same ten minutes; that Defender's event 5013 has no shipped rule
and is discarded at level 0; that the vendor's `Set-MpPreference` coverage is
reachable only with Sysmon; and that the agent misreports
`ERROR_EVT_CHANNEL_NOT_FOUND` as "the eventlog service is down".

The endpoint was restored: exclusion removed, real-time protection re-enabled and
verified, scan CPU factor returned to its recorded pre-lab value, and the test
directory deleted.
