# Lab 02 - Credential Access: LSASS Memory Read (T1003.001)

## Objective
Detect an attacker reading LSASS memory to steal credentials - and discover, in
the process, that the shipped detection is simultaneously **noisy** (it alerts on
Windows Defender doing its job) and **blind** (it misses the most powerful access
an attacker can request), while a hardened endpoint blocks the attack before the
SIEM ever sees it.

**LSASS** (Local Security Authority Subsystem Service) is the Windows process
that handles authentication. It holds credential material in memory so users are
not re-prompted constantly. An attacker who reads that memory obtains credentials
for accounts across the environment without guessing a single password. This is
the pivot from "one compromised host" to "compromised domain."

Native Windows logs cannot see a process reading another process's memory. Only
**Sysmon Event ID 10 (ProcessAccess)** records it - which is why this lab depends
on Module 05 Lab 01, and why it is the clearest demonstration of what Sysmon adds
over native telemetry.

## MITRE ATT&CK
| Field | Value |
|---|---|
| Tactic | Credential Access |
| Technique | T1003.001 - OS Credential Dumping: LSASS Memory |
| Reference | https://attack.mitre.org/techniques/T1003/001/ |

## Environment
| Component | Details |
|---|---|
| Endpoint | Windows 11 Home - agent ID 002 `windows` |
| Manager | Ubuntu Server, Wazuh 4.14.6 all-in-one |
| Sensor | Sysmon v15.21, SwiftOnSecurity config (amended, see below) |
| New event | Sysmon **Event ID 10** - ProcessAccess |
| Custom rule | **100500** (level 13), `local_rules.xml` |

## Prerequisite - Event ID 10 is shipped disabled
Lab 01 established that the SwiftOnSecurity config ships `ProcessAccess` as an
**empty allow-list** - EID 10 logs nothing by default, because it is the noisiest
event Sysmon produces (antivirus, EDR, and Windows internals open handles to
LSASS constantly). The config was amended with a single targeted entry:

```xml
<ProcessAccess onmatch="include">
        <TargetImage condition="image">lsass.exe</TargetImage>
</ProcessAccess>
```

Reloaded without reinstalling:

```powershell
C:\Tools\Sysmon\Sysmon64.exe -c C:\Tools\Sysmon\sysmonconfig.xml
```

`TargetImage` is the process being accessed (the victim); `SourceImage` will be
whoever reached for it. `condition="image"` matches the executable name
regardless of path. Idle rate after enabling: **2 EID 10 events in 60 seconds** -
modest, but non-zero even at rest, which is the whole reason it ships off.

## What the shipped ruleset covers
Unlike Lab 08's T1490 blank, T1003.001 **has** shipped coverage. Rule **92900**
in `0945-sysmon_id_10.xml`, level 12:

```xml
<rule id="92900" level="12">
  <if_group>sysmon_event_10</if_group>
  <field name="win.eventdata.targetImage" type="pcre2">(?i)lsass\.exe</field>
  <field name="win.eventdata.grantedAccess" type="pcre2">(?i)(0x1010|0x40)</field>
  <field name="win.eventdata.sourceImage" type="pcre2" negate="yes">(?i)(C:\\\\Program Files|wmiprvse\.exe)</field>
  <description>Lsass process was accessed ... possible credential dump</description>
  <mitre><id>T1003.001</id></mitre>
</rule>
```

Note the parent group is **`sysmon_event_10`** (underscore before the number),
where EID 1's group is `sysmon_event1` (none). The shipped naming is
inconsistent, and a custom rule that chains to the wrong form silently never
fires. The parent is rule **61612, level 0** in `0595-win-sysmon_rules.xml`.

The `grantedAccess` field is the Windows **access mask** - the set of permissions
the accessing process requested. Reading LSASS memory requires
`PROCESS_VM_READ (0x10)`; benign status polling does not. This field is the whole
game, and rule 92900 gets it wrong in three ways proven below.

## Baseline - who touches LSASS legitimately
Measured before any attack, decoding each EID 10's `SourceImage` and
`GrantedAccess`:

| Count | Source | Mask | Reads memory? |
|---|---|---|---|
| 302 | `svchost.exe` | `0x1000` | No - QUERY_LIMITED_INFORMATION |
| 150 | `svchost.exe` | `0x1400` | No - +QUERY_INFORMATION |
| 13 | `svchost.exe` | `0x2000` | No |
| 3 | `MsMpEng.exe` (Defender) | `0x101000` | **No** - SYNCHRONIZE + QUERY_LIMITED |
| 1 | `MRT.exe` | `0x1418` | Yes - includes VM_READ |

The critical baseline fact: **legitimate accessors overwhelmingly request query
masks without the VM_READ bit.** Defender's `0x101000` is `SYNCHRONIZE (0x100000)
| QUERY_LIMITED_INFORMATION (0x1000)` - it does **not** contain `0x10`. Defender
is not reading LSASS memory; it is checking status. Hold that fact; it breaks the
shipped rule.

## Attack simulation - two methods, two blocks
Run as the hands-on operator, read-only, on the live endpoint.

### Method 1 - comsvcs.dll MiniDump (LOLBin), blocked by Defender
```powershell
$lsass = (Get-Process lsass).Id
rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump $lsass C:\Tools\Sysmon\lsass_test.dmp full
```

`comsvcs.dll` is a legitimate, Microsoft-signed Windows DLL whose `MiniDump`
export writes a process's memory to disk - the archetypal "living off the land"
LSASS dump, requiring no external tooling. Result:

```
Program 'rundll32.exe' failed to run: Access is denied
```

Defender's behavioural engine blocked it at launch - `Get-MpThreatDetection`
confirmed a detection (`ThreatID 2147786203`) naming the exact command line.
Because the process never ran, it **never opened a handle to LSASS, so Sysmon
produced no EID 10.** The attack was stopped so early the SIEM had nothing to
detect. First layered-defense finding.

### Method 2 - direct handle open, blocked by PPL
To generate the telemetry without a real dump, open a handle to LSASS with a
chosen access mask and close it immediately - no memory read, no file written,
but Sysmon records the access exactly as for a real tool:

```powershell
$h = [P]::OpenProcess(0x1010, $false, (Get-Process lsass).Id)   # 0x1010 = VM_READ | QUERY_LIMITED
```

Result, from an **elevated** shell: `Handle: 0  LastError: 5` (ACCESS_DENIED).
Admin was not enough. Cause:

```powershell
Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name RunAsPPL
# RunAsPPL : 2
```

**LSASS is running as a Protected Process Light (PPL).** When PPL is on, the
kernel refuses memory-read handles to any userland caller regardless of privilege
- even SYSTEM with SeDebugPrivilege. Only equal-or-higher protected processes
(like Defender's `MsMpEng.exe`) may access it. Credential Guard was off
(`SecurityServicesRunning = 0`), so this was PPL specifically.

**Second layered-defense finding, and the headline:** on a hardened Windows 11
endpoint, classic LSASS dumping is blocked at the OS layer before it generates
the Sysmon telemetry the SIEM rule depends on. Rule 92900 is a **backstop** for
when PPL is absent, disabled, or bypassed (a vulnerable-driver / BYOVD attack),
not a frontline control. Also recorded: a **denied** access generates no EID 10
at all, so the rule can only ever fire on *granted* access.

### Validating the detection
To exercise the rule, PPL was temporarily disabled (`RunAsPPL = 0`) and the
endpoint rebooted - the legitimate way an analyst validates that a detection
would catch the attack *if* an adversary bypassed PPL. PPL was restored to `2`
immediately after the lab. With PPL down, the handle opens succeeded:

```
mask 0x1010    handle 2920      # Mimikatz-style read
mask 0x1fffff  handle 1068      # PROCESS_ALL_ACCESS - what ProcDump/comsvcs request
```

Both reached the manager (confirmed in archives), giving the two test masks the
rule analysis needs.

## Three defects in the shipped rule - all demonstrated
The `0x1010` and `0x1fffff` accesses, plus ongoing Defender activity, produced
four rule-92900 alerts:

| Level | Mask | Source | Verdict |
|---|---|---|---|
| 12 | `0x101000` | MsMpEng.exe (Defender) | **False positive** |
| 12 | `0x1010` | powershell.exe (test) | True positive |
| 12 | `0x101000` | MsMpEng.exe | **False positive** |
| 12 | `0x101000` | MsMpEng.exe | **False positive** |

**Defect 1 - unanchored regex false-positives on Defender (high).** The mask
condition `(?i)(0x1010|0x40)` is **unanchored**, so it matches the substring
`0x1010` inside `0x101000`. Defender's `MsMpEng.exe`, which requests `0x101000`
(no VM_READ bit - it does not read LSASS memory), trips a level-12 "possible
credential dump" alert every scan. Observed **5 times** across the lab window.

**Defect 2 - the AV exclusion misses the AV (high, compounding).** The rule tries
to suppress this with `negate` on `C:\Program Files`. But Defender's engine runs
from `C:\ProgramData\Microsoft\Windows Defender\Platform\...`. `ProgramData` is
not `Program Files`, so the exclusion never covers the process it was written for.

**Defect 3 - the exact-mask allow-list is evaded (high).** `0x1fffff`
(PROCESS_ALL_ACCESS - what ProcDump, Task Manager, and comsvcs request) contains
neither `0x1010` nor `0x40`, so it does **not** match. The `0x1fffff` access
reached the manager but produced **no 92900 alert**. The rule misses the most
powerful LSASS handle an attacker can request.

The shipped rule is therefore both **noisy** (alerts on benign Defender) and
**blind** (misses full-access dumps) - the worst of both.

## Detection rule (on the manager)
Added to `/var/ossec/etc/rules/local_rules.xml`.

```xml
<group name="local,windows,credential_access,">
  <rule id="100500" level="13">
    <if_group>sysmon_event_10</if_group>
    <field name="win.eventdata.targetImage" type="pcre2">(?i)\\lsass\.exe$</field>
    <field name="win.eventdata.grantedAccess" type="pcre2">(?i)^0x(10|30|1010|1410|1418|1438|143a|1478|1fffff)$</field>
    <field name="win.eventdata.sourceImage" type="pcre2" negate="yes">(?i)\\(wininit|services|svchost|csrss|lsass|MsMpEng|MRT)\.exe$</field>
    <options>no_full_log</options>
    <description>Possible LSASS credential access [T1003.001]: $(win.eventdata.sourceImage) opened lsass with mask $(win.eventdata.grantedAccess)</description>
    <mitre><id>T1003.001</id></mitre>
  </rule>
</group>
```

Design, each choice mapped to a defect:

- **Anchored mask regex `^0x...$`** fixes Defect 1: `0x101000` no longer matches,
  because the anchors forbid substring matching.
- **Enumerated read/dump masks** including `0x1fffff` fixes Defect 3: full access
  now fires. The set covers masks carrying `PROCESS_VM_READ (0x10)` plus full
  access - pcre2 cannot test a bit, so the known credential-access masks are
  listed explicitly (the approach Sigma's LSASS rules also take).
- **Exclusion by executable name, anchored** (`\\MsMpEng\.exe$`) fixes Defect 2:
  Defender is excluded by its exe name regardless of whether it lives in
  `Program Files` or `ProgramData`.
- **Custom group `credential_access`** shares no substring with any parent group,
  so `if_group` cannot self-match (Lab 05/06/07 precaution).
- **Level 13**, above the shipped 92900's 12 - deliberately, see the precedence
  finding below.

## Detection results
```
100500 L13 | 0x1010   | powershell.exe   <- Mimikatz-style read, caught
100500 L13 | 0x1fffff | powershell.exe   <- FULL ACCESS, which 92900 EVADES, caught
100500 L13 | 0x1418   | MRT.exe          <- see tuning below
```

Head-to-head with the shipped rule:

| Mask | Meaning | 92900 (shipped) | 100500 (this lab) |
|---|---|---|---|
| `0x1010` | Mimikatz minimal read | fires L12 | **fires L13** |
| `0x1fffff` | full access (ProcDump/comsvcs) | **evades** | **fires L13** |
| `0x101000` | Defender sync+query (benign) | **FP x5** | **silent** |

**Two independent wins:** 100500 catches the full-access dump 92900 misses, and
stays silent on the Defender activity 92900 false-positives on.

### Tuning - the rule found its own false positive
100500 also fired on `MRT.exe` (`0x1418`) - the Microsoft Malicious Software
Removal Tool, which legitimately scans process memory and so genuinely requests
VM_READ. This was a real false positive of the *new* rule: a benign accessor the
allow-list did not know about. Tuned by adding `MRT` to the exclusion, the one-
line fix that is the detection-tuning loop in miniature (observe benign accessor
-> allow-list -> redeploy).

The deeper lesson is that this tuning never ends by mask alone: **AV, MRT, and
Mimikatz all read LSASS.** They cannot be separated by access mask - only by
*who* is doing the reading (a signed, reputable image). That is exactly what
Sysmon Event ID 7's signature telemetry (Lab 04) provides, and why an
image-name allow-list is a starting point, not a finished control.

### Sibling precedence - a second data point for Lab 01
Both 92900 and 100500 match the `0x1010` event, yet **100500 (level 13) won it**;
92900 (level 12) did not fire on that event. In Lab 01, level-4 rule 92027 beat
level-3 rule 92007. Two independent cases, both won by the **higher-level**
sibling. Wazuh sibling precedence favouring the higher-severity rule is now a
supported hypothesis rather than a single observation - and it means 100500 was
made to win the race *by design* by rating it 13.

The limit: 92900 still false-positives on `0x101000`, because 100500 does not
match that event, leaving 92900 the sole matcher. **Winning a shared race does
not suppress a rule on events only it matches.** Fully eliminating the Defender
FP requires overwriting the shipped rule (`<rule id="92900" overwrite="yes">`)
with corrected logic - noted as the production remediation.

## Investigation steps
1. **Treat a 100500 alert as active credential theft.** Legitimate LSASS memory
   reads are rare and come from a short list of signed processes.
2. **The mask and source image are in the alert.** `grantedAccess` distinguishes
   a memory read (VM_READ set) from benign status polling; `sourceImage` names
   the accessor.
3. **Correlate the source process backward.** How did it start? Signed? Parent?
   An unsigned or oddly-parented process reading LSASS is the strong signal.
4. **Check whether PPL was disabled.** A `RunAsPPL` change or a suspicious driver
   load immediately before the access suggests a PPL bypass - itself an alert
   worth building.

## Notes and limitations
- **PPL is the frontline; the SIEM rule is the backstop.** With PPL on (the
  endpoint's normal state), no simple userland method generates the telemetry at
  all. The detection matters when PPL is off, unconfigured, or bypassed.
- **Denied access is invisible to EID 10.** The rule fires only on *granted*
  access; a PPL-blocked attempt produces no event. Defender's behavioural block
  (Method 1) is what covers the blocked-attempt case, not this rule.
- **Name-based exclusion is bypassable.** An attacker naming their tool
  `MsMpEng.exe` would be excluded. The durable fix is to gate the exclusion on
  Authenticode signature (Lab 04), not image name.
- **Enumerated masks are not exhaustive.** A tool requesting an unlisted
  read-capable mask would slip past. Bit-testing `0x10` would be more robust but
  is not expressible in pcre2; a decoder-side computed field would be the way.
- **Validated with PPL temporarily disabled**, then restored to `RunAsPPL = 2`.
  The result describes detection behaviour on an endpoint where PPL is absent or
  bypassed - which is the only condition under which the technique produces
  telemetry.

## Lessons learned
- **A rule can be noisy and blind at once.** 92900 alerts on Defender and misses
  full-access dumps for the same root cause: it reasons about the access mask as
  a substring instead of a value. Anchoring and enumerating fixed both.
- **Read the access mask, not just the target.** "Something touched LSASS" is not
  the signal; "something opened LSASS with VM_READ" is. `0x101000` and `0x1010`
  differ by one bit that is the entire difference between benign and malicious.
- **Modern endpoints defend in depth.** Two independent controls (Defender
  behavioural block, LSASS PPL) stopped this attack before the SIEM saw it. A
  homelab whose endpoint lacks PPL would "detect" the dump and learn the wrong
  lesson - that the SIEM is the thing standing between the attacker and the
  credentials.
- **Your improved rule will have its own false positives.** 100500 immediately
  caught MRT.exe. Detection engineering is iterative tuning against observed
  benign activity, not a rule written once and trusted.
- **Severity is a precedence lever, not just a label.** Rating 100500 at level 13
  made it win the evaluation race against the shipped level-12 rule - the Lab 01
  precedence mechanism, used deliberately.

## MITRE ATT&CK mapping
```
OS Credential Dumping: LSASS Memory (T1003.001)
  |
  +-- comsvcs MiniDump  --> Defender behavioural block      [attack stopped, no EID 10]
  +-- OpenProcess(VM_READ) --> LSASS PPL denies handle      [attack stopped, no EID 10]
  |
  +-- (PPL off / bypassed) --> Sysmon Event 10 (ProcessAccess)
        |
        +--> sysmon_event_10  (rule 61612, level 0)
               |
               +--> 92900  L12  unanchored mask  [FP on Defender 0x101000; EVADES 0x1fffff]
               |
               +--> 100500 L13  anchored + enumerated + exclude-by-name
                      [catches 0x1010 AND 0x1fffff; silent on Defender; wins the L13>L12 race]
```

## Status
Complete - Sysmon Event ID 10 enabled by a targeted config amendment, and custom
rule **100500** (level 13) confirmed firing on a live Windows 11 endpoint for
both the Mimikatz-style `0x1010` read and the `0x1fffff` full-access open that the
shipped rule 92900 evades, while staying silent on Windows Defender's benign
`0x101000` access that 92900 false-positives on.

The lab documented that the endpoint's **LSASS PPL** and **Defender behavioural
detection** each block classic credential dumping before it reaches the SIEM, so
the detection is a backstop against a PPL bypass rather than a frontline control;
that shipped rule 92900 carries three defects (an unanchored mask regex that
false-positives on Defender, a path-prefix exclusion that misses Defender's real
directory, and an exact-mask allow-list evaded by full access); and that the
improved rule, after fixing all three, surfaced its own false positive on
`MRT.exe` and was tuned against it. A second data point confirmed the Lab 01
sibling-precedence hypothesis: the higher-level rule wins a shared-event race.
LSASS PPL was restored to `RunAsPPL = 2` after validation.
