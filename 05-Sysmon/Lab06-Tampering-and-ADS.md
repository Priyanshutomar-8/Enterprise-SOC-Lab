# Lab 06 - Defense Evasion: Sysmon Tampering and NTFS Alternate Data Streams (T1562.001 / T1564.004)

## Objective
Two evasion techniques that share a theme - **hiding from the sensor** - but fail in
opposite ways, and are detected from opposite ends of the pipeline:

| Technique | Where it hides | Detection shape |
|---|---|---|
| **ADS hiding** (T1564.004) | payload written into an NTFS alternate data stream of an innocent file | single-event - a stream with a risky name is created (Sysmon EID 15) |
| **Sysmon tampering** (T1562.001) | by disabling the sensor itself | the sensor cannot be trusted to report its own death - detection must lean on sources it does not control |

The tampering half is the more instructive: a sensor asked to witness its own removal
is a conflict of interest. This lab measures exactly how much of that removal actually
reaches the SIEM on a modern Windows 11 host, and the answer overturns the common
folklore.

## MITRE ATT&CK
| Field | Value |
|---|---|
| Tactic | Defense Evasion |
| Technique | T1564.004 - Hide Artifacts: NTFS File Attributes (Alternate Data Streams) |
| Technique | T1562.001 - Impair Defenses: Disable or Modify Tools |
| Reference | https://attack.mitre.org/techniques/T1564/004/ |
| Reference | https://attack.mitre.org/techniques/T1562/001/ |

## Environment
| Component | Details |
|---|---|
| Endpoint | Windows 11 - agent ID 002 `windows`, host-only 192.168.56.103 |
| Manager | Ubuntu Server, Wazuh 4.14.6 all-in-one, 192.168.56.79 |
| Sensor | Sysmon v15.21, SwiftOnSecurity config - **unmodified for this lab** |
| Events used | Sysmon **EID 15** (FileCreateStreamHash), **EID 4** (service state); native **SCM 7045** (System channel) |
| Custom rules | **100506** (ADS), **100507**, **100508** (tampering) in `local_rules.xml` |

## Prerequisite - none
Both event types are already enabled. `FileCreateStreamHash` (EID 15) ships **on** in
the SwiftOnSecurity config (Lab 01 recorded it as usable); EID 4 is emitted by Sysmon
itself and is not a config toggle. No amendment was required - the second lab in a row
after Lab 05.

## What the sensor collects - and what it does not (EID 15)
The `FileCreateStreamHash` section is an **`onmatch="include"` list**, and it is
narrow and script-focused. A stream's `TargetFilename` is logged only if it:

- **contains** `Downloads`, `Temp\7z`, or `Startup`, **or**
- **ends with** one of: `.bat .cmd .doc .hta .jse .lnk .ppt .ps1 .ps2 .reg .sct .vb .vbe .vbs .wsc .wsf`

Two consequences drive the whole ADS design:

1. **A hidden PE by extension is invisible.** `secret.txt:payload.exe` created outside a
   watched path fires **nothing** - `.exe`/`.dll` are not in the list. The authors bet a
   hidden executable gets caught at execution instead; the *stream* they watch for is a
   *script*.
2. **`Zone.Identifier` in `Downloads` is the false positive.** Every browser download drops
   `file.ext:Zone.Identifier` into `Downloads`, which matches `contains Downloads` and logs
   EID 15. The rule must exclude the mark-of-the-web, or it fires on every download.

Idle EID 15 volume over 30 minutes was **0** - no starvation risk, and `logall_json`
stayed off for the whole lab.

## What the shipped ruleset covers - and what it does not
Both events are **decoded at level 0** - a tag, never an alert. This is a *severity* gap,
not a coverage gap (the shape of Module 04's log-clearing lab):

| Event | Shipped rule | Level | Meaning |
|---|---|---|---|
| EID 15 FileCreateStreamHash | 61617 | **0** | a payload hidden in a stream alerts at nothing |
| EID 4 Sysmon service state | 61606 | **0** | the sensor being stopped alerts at nothing |
| EID 16 Sysmon config change | 61644 | **0** | a config swap alerts at nothing |

Custom rules **escalate** these level-0 leaves via `if_sid`, the pattern established in
Labs 02-05. One trap noted in passing: the shipped Sysmon groups are inconsistently
named - `sysmon_event4` (no underscore) versus `sysmon_event_15` (with one) - so
chaining by `if_sid <leaf>` is safer than `if_group`.

## Attack simulation

### ADS hiding (T1564.004)
```powershell
Set-Content C:\Tools\lab06\notes.txt "Meeting notes - nothing to see here."
# hide a PowerShell payload in an alternate data stream whose name ends .ps1
Set-Content -Path C:\Tools\lab06\notes.txt -Stream 'update.ps1' -Value 'Write-Host "hidden ADS payload ran"'
# the carrier looks innocent; the stream is invisible to a normal listing
Get-ChildItem C:\Tools\lab06\                       # shows only notes.txt (38 bytes)
Get-Item C:\Tools\lab06\notes.txt -Stream *          # reveals :$DATA and :update.ps1
```
Sysmon v15 records the stream **and its contents** for small text - a second stage payload
`IEX (New-Object Net.WebClient).DownloadString(...)` was surfaced verbatim in the alert.

### Sysmon tampering (T1562.001)
```powershell
Stop-Service Sysmon64 -Force     # DENIED
sc.exe stop Sysmon64             # [SC] ControlService FAILED 5: Access is denied.
Sysmon64 -u force                # graceful uninstall - the realistic fallback
Sysmon64 -accepteula -i C:\Tools\Sysmon\sysmonconfig.xml   # reinstall / restore
```

## Detection rules (on the manager)

```xml
<!-- 100506 - ADS: a script/executable payload written to an NTFS alternate data
     stream, escalating the level-0 EID 15 leaf 61617. The regex anchors on the SECOND
     colon (the ADS separator; the C: drive colon is followed by a backslash, which the
     class rejects) plus a risky stream extension. That anchor alone excludes
     Zone.Identifier; the explicit negate is belt-and-suspenders. -->
<rule id="100506" level="12">
  <if_sid>61617</if_sid>
  <field name="win.eventdata.targetFilename" type="pcre2">(?i):[^\\/:\r\n]+\.(ps1|ps2|bat|cmd|hta|vbs|vbe|jse|wsf|wsc|vb|sct|exe|dll)$</field>
  <field name="win.eventdata.targetFilename" type="pcre2" negate="yes">(?i)Zone\.Identifier$</field>
  <options>no_full_log</options>
  <description>ADS hiding [T1564.004]: payload written to alternate data stream $(win.eventdata.targetFilename) by $(win.eventdata.image)</description>
  <mitre><id>T1564.004</id></mitre>
</rule>

<!-- 100507 - Sysmon's own EID 4 'Stopped': the in-band dying breath. -->
<rule id="100507" level="12">
  <if_sid>61606</if_sid>
  <field name="win.eventdata.state" type="pcre2">(?i)^stopped$</field>
  <options>no_full_log</options>
  <description>Sysmon tampering [T1562.001]: Sysmon service reported state change to Stopped (sensor going blind)</description>
  <mitre><id>T1562.001</id></mitre>
</rule>

<!-- 100508 - out-of-band SCM 7045 naming the Sysmon service/driver, escalating the
     shipped 61138. Catches the (re)install half of an uninstall->reinstall or a
     neutered redeploy. -->
<rule id="100508" level="12">
  <if_sid>61138</if_sid>
  <field name="win.eventdata.serviceName" type="pcre2">(?i)^Sysmon(64|Drv)?$</field>
  <options>no_full_log</options>
  <description>Sysmon tampering [T1562.001]: Sysmon service/driver (re)installed - $(win.eventdata.serviceName) from $(win.eventdata.imagePath) (out-of-band SCM 7045 witness)</description>
  <mitre><id>T1562.001</id></mitre>
</rule>
```

## The tampering half, as it actually behaved
The plan was textbook: catch the tamper with Sysmon's EID 4, and corroborate it with the
"industry-standard" out-of-band witness - SCM **7036** ("service entered the stopped
state"). Measurement demolished the plan and produced a better lab.

1. **Naive stop is denied.** `Stop-Service` and `sc.exe stop` both fail with **Access
   Denied (error 5)** from an elevated shell. Sysmon's service DACL denies the stop right
   even to Administrators - built-in anti-tamper. `net stop sysmon` is not a viable
   technique; the attacker must uninstall or escalate to SYSTEM.
2. **SCM 7036 does not exist on this host.** Zero 7036 events in the System log, ever -
   modern Windows 11 does not emit the "service state changed" informational event that a
   decade of blog posts tells you to alert on. The folklore detection has no data to match.
3. **EID 4 is a *race*, not a guarantee.** On `Sysmon64 -u`, Sysmon writes a final EID 4
   "Stopped" and then tears down its own Operational log. Whether the Wazuh agent reads
   that last event before the channel disappears is timing-dependent: across runs, 100507
   fired **and** stayed silent for the identical action.
4. **"Forwarded" is not "delivered".** Two events that *would* be better removal-witnesses
   are written to the local log but **never reach Wazuh**, despite their channels being
   fully forwarded with no query filter:
   - **FilterManager EID 1** ("SysmonDrv ... unloaded successfully", System channel) - the
     truest removal signal, logged locally on every uninstall, undetectable by a rule that
     matched *any* System EID 1.
   - **Sysmon EID 16** (config change, Sysmon channel) - logged locally three times, never
     alerted, even when chained straight to the Sysmon channel base rule 60004.
5. **What does survive is the reinstall.** SCM **7045** ("A service was installed") fires
   for `Sysmon64` and `SysmonDrv` and *does* reach Wazuh (shipped rule 61138). Rule 100508
   escalates it - catching the (re)install half of the common uninstall->reinstall-neutered
   pattern. It is a weaker witness than a removal event, but it is the one that is real.

## Detection results - full test matrix
| # | Action | Sysmon/native event | Reached Wazuh? | Alert | Expected |
|---|---|---|---|---|---|
| 1 | ADS `.ps1` stream on `notes.txt` | EID 15 | yes | **100506 L12** | pass |
| 2 | payload contents in the stream | EID 15 `contents` | yes | surfaced in alert | pass |
| 3 | **NC** hidden `.exe` stream outside `Downloads` | none (include-list) | n/a | **silent** | pass - blind spot |
| 4 | **NC** `Zone.Identifier` in `Downloads` | EID 15 (x2) | yes | **silent** (rule excludes it) | pass - FP tuned |
| 5 | `Stop-Service` / `sc stop` | none | n/a | **silent** | Access Denied - anti-tamper |
| 6 | `Sysmon64 -u force` (uninstall) | EID 4 Stopped | **sometimes** (race) | **100507 L12** when it wins | best-effort |
| 7 | `Sysmon64 -i` (reinstall) | SCM 7045 SysmonDrv | yes | **100508 L12** | pass |
| 8 | **NC/finding** uninstall driver unload | FilterManager EID 1 | **no** | silent | delivery gap |
| 9 | **NC/finding** `Sysmon64 -c` config swap | Sysmon EID 16 | **no** | silent | delivery gap |
| 10 | **NC/finding** service stop event | SCM 7036 | not emitted | silent | Win11 does not log it |

Rows 3-5 and 8-10 - the negative controls - carry this writeup. Rows 1, 2, 7 only prove a
rule that fires; the value is in the six rows that map the edges of what is actually
detectable.

## Notes and limitations
1. **The ADS extension threshold is the community config's, not ours.** Widening
   `NetworkConnect`-style, a real deployment would add `.exe`/`.dll` to the stream
   include-list to close the row-3 blind spot - at a volume cost the SwiftOnSecurity
   authors declined to pay.
2. **EID 15 double-fires.** Each stream creation produced two EID 15 events (an NTFS
   minifilter artefact the config comments call out) - so 100506 alerts twice per action.
   Harmless, but worth an `ignore`/`timeframe` in production.
3. **The tamper baseline is unrealistically quiet.** A production host cycles services
   constantly; the 7045 witness would need noise tuning, and the "no 7036" finding should
   be re-checked per Windows build.
4. **100507 cannot be relied on alone.** Because it races the log teardown, an uninstall
   can be entirely silent on the Sysmon side. This is the argument *for* an out-of-band
   witness - and the argument is undercut by the delivery gap in rows 8-9.
5. **The correct robust control is not a rule at all.** The only tamper-proof detection of
   "the sensor went dark" is manager-side: alert when an agent's event throughput for a
   given source drops to zero for N minutes (a dead-man's switch). Wazuh does not do this
   per-source out of the box; it is recorded here as the right future control, not faked
   as a rule.

## Lessons learned
- **A sensor cannot be trusted to report its own death.** EID 4 is in-band and races its
  own teardown; the events that *would* be independent (FilterManager unload, EID 16) do
  not survive the trip to the SIEM here. Detection of tampering belongs to a source the
  attacker is not tampering with.
- **"Forwarded" is not "delivered".** The System and Sysmon channels are both fully
  forwarded with no query, yet FilterManager EID 1 and Sysmon EID 16 never arrive.
  Verifying a channel is subscribed is not verifying that a specific event reaches the
  manager - only an event that fires a rule proves the path end-to-end.
- **Folklore expires.** "Alert on SCM 7036 for Sysmon tampering" is widely repeated and
  produces zero coverage on Windows 11, which does not emit the event. Detections copied
  from blog posts must be validated against the platform, not the post.
- **Read the include-list as a threat model.** The stream extensions the config watches -
  scripts, not executables - reveal the attacker its authors imagined, and the gap they
  accepted.
- **Negative controls define the ceiling.** The hidden `.exe` that produced no telemetry
  and the mark-of-the-web that produced a benign one say more about the rule's real value
  than the positive that fired.

## MITRE ATT&CK mapping
| Rule | Level | Technique | Coverage |
|---|---|---|---|
| 100506 | 12 | T1564.004 | Script/executable payload in an NTFS alternate data stream - escalates the level-0 EID 15 tag, excludes Zone.Identifier |
| 100507 | 12 | T1562.001 | Sysmon service reported Stopped (EID 4) - in-band, best-effort |
| 100508 | 12 | T1562.001 | Sysmon service/driver (re)installed (SCM 7045) - out-of-band, reliable |

Shipped coverage escalated: **61617** (EID 15, level 0), **61606** (EID 4, level 0),
**61138** (SCM 7045, level 5 -> 12 for Sysmon). Documented but not shippable on this host:
FilterManager EID 1 unload and Sysmon EID 16 (not delivered), SCM 7036 (not emitted).

## Status
**Complete.** Three custom rules deployed and confirmed firing on the live endpoint, with
a ten-row test matrix whose six negative-control/finding rows define the technique's real
detectability. No Sysmon config amendment was required. `logall_json` remained disabled.

Headline: **the standard advice for detecting Sysmon tampering fails on modern Windows.**
SCM 7036 is never emitted; Sysmon's own EID 4 races its log teardown; and the two events
that would make good out-of-band witnesses - the FilterManager driver-unload and Sysmon's
EID 16 config-change - are written locally but never reach the SIEM even with their
channels fully forwarded. What remains is a best-effort in-band signal (EID 4) and a
reliable *reinstall* witness (SCM 7045); the genuinely tamper-proof control is a
manager-side source-silence detection, named here as future work rather than faked as a
rule. On the ADS side, the SwiftOnSecurity stream include-list watches scripts and not
executables, so a hidden `.ps1` is caught (rule 100506) while a hidden `.exe` outside a
watched path is invisible - and the Zone.Identifier mark-of-the-web, the one benign
stream that does fire EID 15, is tuned out.
