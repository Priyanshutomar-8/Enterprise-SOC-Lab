# Lab 04 - Defense Evasion: DLL Side-Loading and Code-Signing Telemetry (T1574.002)

## Objective
Detect an attacker loading an **unsigned DLL into a signed, trusted process** - the
core of DLL side-loading - and discover in the process that the shipped ruleset has
**no signature-based coverage at all** (its seven Event ID 7 rules key on specific
named DLLs, never on the signature), that **how a DLL is loaded decides whether
Sysmon even sees it**, and that a naive signature rule **false-positives on every
Microsoft Store app** because UWP packages are signed as a unit, not per file.

**DLL side-loading (T1574.002)** abuses the Windows DLL search order: a legitimate
signed executable is made to load a malicious DLL the attacker planted, because
Windows searches the application's own directory for a DLL *before* the protected
system directories. The signed process stays signed; the attacker's code rides in
on the DLL. Application allow-listing waves the trusted `.exe` through, and the
loaded module looks like a normal dependency. The tell is not the process and not
the DLL's metadata (which the attacker copies from a real Microsoft file) - it is
the **signature** of the loaded module.

Native Windows logs do not record which DLLs a process loads. Only **Sysmon Event
ID 7 (ImageLoad)** does, and only that event carries the `Signed`, `Signature` and
`SignatureStatus` fields this detection is built on - which is why this lab depends
on Module 05 Lab 01, and why it is the clearest demonstration of code-signing
telemetry the module produces.

## MITRE ATT&CK
| Field | Value |
|---|---|
| Tactic | Persistence, Privilege Escalation, Defense Evasion |
| Technique | T1574.002 - Hijack Execution Flow: DLL Side-Loading |
| Related | T1036 - Masquerading (the DLL's copied Microsoft metadata) |
| Reference | https://attack.mitre.org/techniques/T1574/002/ |

## Environment
| Component | Details |
|---|---|
| Endpoint | Windows 11 - agent ID 002 `windows` |
| Manager | Ubuntu Server, Wazuh 4.14.6 all-in-one |
| Sensor | Sysmon v15.21, SwiftOnSecurity config (amended, see below) |
| New event | Sysmon **Event ID 7** - ImageLoad |
| Custom rule | **100502** (level 12), `local_rules.xml` |

## Prerequisite - Event ID 7 is shipped disabled
The SwiftOnSecurity config (source version 74) ships `ImageLoad` as an **empty
include allow-list** - it logs nothing at all:

```xml
<ImageLoad onmatch="include">
  <!--NOTE: Using "include" with no rules means nothing in this section will be logged-->
</ImageLoad>
```

This corrects the Lab 01 audit table, which described EID 7 as an "allow-list of a
few known-abused DLLs." Reading the live config proved it is *fully off*, exactly
like EID 10 in Lab 02 - the community author disables it because signature
verification on every image load is expensive ("Can cause high system load,
disabled by default").

The config was amended with a single targeted entry - log any image load whose
module is **unsigned**:

```xml
<ImageLoad onmatch="include">
  <Signed condition="is">false</Signed>
</ImageLoad>
```

Reloaded without reinstalling: `Sysmon64.exe -c sysmonconfig.xml`.

**Idle rate after enabling: 0 unsigned image loads in 60 seconds.** Almost every
DLL on a stock Windows host is Microsoft- or vendor-signed, so filtering to
`Signed=false` gives a near-silent baseline - any unsigned load that appears is
inherently interesting, and the 3 GB manager is never flooded. (0 at idle proves
low noise, not that the pipeline works; that was proven when the sideload fired.)

Logging unsigned loads at the *sensor* and alerting on the dangerous ones at the
*rule* is deliberate layering: full visibility below, precise alerting above.

## What the shipped ruleset covers - and does not
`0820-sysmon_id_7.xml` ships seven EID 7 detections (92151 - 92157):

| Rule | Keys on | Catches |
|---|---|---|
| 92151 | `System.Management.Automation.dll` loaded | unmanaged PowerShell |
| 92152 | spool driver DLL in `spoolsv` | PrintNightmare (CVE-2021-34527) |
| 92153 | `vaultcli.dll` | credential-vault dumping |
| 92154 / 92155 | `taskschd.dll` (escalates for `mshta`) | scheduled-task abuse |
| 92156 | `VBEUI.DLL` into Office | VBA scripting |
| 92157 | any DLL from `\Windows\Temp\` (level 6) | generic temp-dir load |

**Every shipped rule keys on a specific named DLL or a fixed path. Not one inspects
the signature.** There is no generic DLL side-loading coverage - nothing that says
"a signed process loaded an *unsigned* module." That is the T1574.002 blank, the
same shape as Lab 03's `regsvr32` gap and Lab 08's T1490 gap. 92157 is the
near-miss: it catches DLLs from `\Windows\Temp`, but a real sideload drops the DLL
*next to the host binary*, not in Temp - so 92157 stays silent on the technique.

The EID 7 group is **`sysmon_event7`** (no underscore) - like EID 1's
`sysmon_event1`, and unlike EID 10's `sysmon_event_10` from Lab 02. Chaining a
custom rule to the wrong form silently never fires. This naming inconsistency has
now bitten across three event types in this module.

## The detection signal - signature, not metadata
Every EID 7 event carries the loaded module's `Signed`, `Signature` and
`SignatureStatus`. A legitimate dependency is signed and valid; a sideloaded
payload is unsigned or its signature no longer validates. Crucially, the module's
*descriptive* fields can be forged - an attacker copies them from a real Microsoft
DLL:

| Field | Trust | Why |
|---|---|---|
| `originalFileName`, `company`, `product` | **Untrustworthy** | Copied from the impersonated file. In this lab they read `VERSION.DLL` / `Microsoft Corporation` on a tampered file. |
| `signed`, `signatureStatus` | **Trustworthy** | Cannot be forged by copying metadata - the bytes either verify against a signature/catalog or they do not. |

This is the inverse of Lab 03, where `originalFileName` was the reliable field. The
reliable field is technique-specific, and knowing which one to trust is the skill.

## Attack simulation - and two findings the payload forced

### Finding 1 - a managed .NET DLL load does not surface as EID 7
The first payload was a benign unsigned DLL compiled in-place with PowerShell:

```powershell
Add-Type -TypeDefinition 'public class Lab04Proxy { public static void Run() { ... } }' `
  -OutputAssembly "C:\Tools\lab04\lab04proxy.dll" -OutputType Library
```

`Get-AuthenticodeSignature` confirmed `NotSigned`. But loading it into a signed
process produced **no EID 7 at all** - neither through a native `LoadLibrary`
(`rundll32.exe lab04proxy.dll,Run`, which reached the "Missing entry: Run" stage,
proving the DLL *was* mapped) nor through the CLR
(`[Reflection.Assembly]::LoadFile(...)` inside signed `powershell.exe`).

**How a DLL is loaded decides whether Sysmon records it.** Shipped rule 92151
catches a managed DLL (`System.Management.Automation.dll`) because the CLR maps it
as an image at process start; a *runtime* managed-assembly load did not raise the
image-load notification Sysmon EID 7 hooks. The payload, not the config, was the
problem: the detection needs a **native** module load.

### Finding 2 - stripping a catalog signature, the hard way
A native DLL was made by copying a real Windows DLL and removing its trust:

```powershell
Copy-Item C:\Windows\System32\version.dll C:\Tools\lab04\version.dll
```

The first attempt - parsing the PE and deleting the embedded signature blob - left
the file reporting `Valid`. **`version.dll` has no embedded signature** (its
security data directory size is 0); its trust comes from a system **catalog
(`.cat`)** that vouches for the file's *hash*. A byte-identical copy still matches
the catalog. The fix was to change the hash so no catalog matches it:

```powershell
$fs = [System.IO.File]::Open($dst,'Append'); $fs.Write((New-Object byte[] 16),0,16); $fs.Close()
```

Appending 16 bytes (harmless trailing overlay - ignored by the loader) broke the
catalog hash match. `Get-AuthenticodeSignature` now returned **`NotSigned`**: a
native DLL, loadable, and unsigned. Embedded vs catalog signing is a real
code-signing distinction, and this is the lab where it mattered.

### The captured event
```powershell
rundll32.exe C:\Tools\lab04\version.dll,GetFileVersionInfoW
```

Sysmon EID 7 (`Signed=false` matched the amended config filter):

```
Image:            C:\Windows\System32\rundll32.exe      (SIGNED - the trusted parent)
ImageLoaded:      C:\Tools\lab04\version.dll            (the sideload)
OriginalFileName: VERSION.DLL                           (copied - a masquerade)
Company:          Microsoft Corporation                 (copied - a masquerade)
Signed:           false                                 (THE TELL)
SignatureStatus:  Unavailable                           (THE TELL)
```

A signed `rundll32` loaded a DLL whose metadata is a perfect Microsoft
impersonation. Only `Signed`/`SignatureStatus` expose it. A rule built on the
metadata fields would be blind here; a rule built on the signature is not.

> `rundll32` loading a named DLL is technically *proxy loading* rather than a
> search-order plant, but it produces the **identical EID 7 signature** - a signed
> image loading an unsigned module - and rule 100502 keys on that signature, not on
> how the load was arranged. It therefore exercises the exact telemetry a real
> side-load produces. A true search-order plant is noted under Limitations.

## Detection rule (on the manager)
Added to `/var/ossec/etc/rules/local_rules.xml`, in its own group (house style -
one group per rule-family):

```xml
<group name="local,windows,defense_evasion,">
  <rule id="100502" level="12">
    <if_group>sysmon_event7</if_group>
    <field name="win.eventdata.signed" type="pcre2">(?i)^false$</field>
    <field name="win.eventdata.imageLoaded" type="pcre2" negate="yes">(?i)^C:\\Windows\\|\\WindowsApps\\</field>
    <options>no_full_log</options>
    <description>DLL side-loading [T1574.002]: unsigned DLL $(win.eventdata.imageLoaded) (SignatureStatus $(win.eventdata.signatureStatus)) loaded by $(win.eventdata.image)</description>
    <mitre>
      <id>T1574.002</id>
    </mitre>
  </rule>
</group>
```

Design, each choice mapped to an interviewer's probe:

- **`if_group sysmon_event7`** - EID 7's shipped group has no underscore (contrast
  EID 10's `sysmon_event_10` in Lab 02). Chaining to the wrong form never fires.
- **Field 1 - `signed = false`.** The primary discriminator, and the one field a
  metadata masquerade cannot forge. This is the whole detection.
- **Field 2 - `imageLoaded` not under `C:\Windows\` or any `WindowsApps` path
  (negate).** The false-positive reducer (see tuning below). Two ANDed fields -
  signature identity *and* location - mirrors the Lab 03 design pattern.
- **Level 12, no sibling race.** Shipped 92151 - 92157 key on named DLLs that
  `version.dll` is not, and 92157 keys on `\Windows\Temp\` (this loads from
  `\Tools\`). 100502 is the sole matcher; severity is pure signal, as in Lab 03.
- **`SignatureStatus` in the description, not as a match field** - so the analyst
  sees `Unavailable`/`Invalid` at a glance without narrowing the match.
- **Deliberately not keyed on `originalFileName`/`company`** - the captured event
  proves those are forgeable.

## The false positive the negative control found - and the tune
The negative control (load the *signed* original `version.dll`) passed at the
sensor: `Signed=true`, so it never became an EID 7 event. But checking every
100502 alert surfaced a false positive the test was not looking for:

```
C:\Program Files\WindowsApps\Microsoft.StorePurchaseApp_...\StoreExperienceHost.dll
C:\Program Files\WindowsApps\Microsoft.WindowsStore_...\WinStore.App.dll
```

**Legitimate Microsoft Store (UWP) app DLLs report `Signed: false`.** UWP packages
are **signed as a unit** (the `.appx`/`.msix` package and its catalog are signed),
so the individual DLLs inside carry no per-file Authenticode signature - exactly
like the tampered `version.dll`. And `WindowsApps` sits under `Program Files`, not
`C:\Windows\`, so the first-pass path filter did not exclude it. Same class of
problem as Lab 02's `MRT.exe` false positive: the rule was right about the
signature and naive about a benign source.

The tune adds `\WindowsApps\` to the exclusion. It is safe: `WindowsApps` is
ACL-locked by TrustedInstaller, so an attacker cannot generally plant a sideload
there - the exclusion costs no realistic coverage. Tuning was done at the **rule**,
not the sensor, keeping full unsigned-load visibility in the logs.

## Detection results - full test matrix
Verified post-tune on the live endpoint, timestamps checked against the tune
restart (23:10 UTC):

| Input | Signature | Reached SIEM? | Rule | Level | Verdict |
|---|---|---|---|---|---|
| `rundll32 C:\Tools\lab04\version.dll` (tampered) | unsigned | yes (EID 7) | **100502** | 12 | true positive (23:18, post-tune) |
| `rundll32 C:\Windows\System32\version.dll` (original) | signed | **no - filtered at sensor** | - | - | silent - correct |
| `rundll32 C:\Tools\lab04\WindowsApps\version.dll` (same bytes, UWP-like path) | unsigned | yes (EID 7) | - | - | **suppressed by tune - correct** (post-tune, absent) |
| Real UWP Store DLLs (`WinStore.App.dll`, ...) | unsigned (package-signed) | yes (EID 7) | 100502 | 12 | **false positive - pre-tune only, does not recur** |
| Idle (60s) | - | no | - | - | silent - correct |

The controlled negative (same unsigned bytes, only the path differs) isolates the
exclusion: it proves the tune suppresses on *path*, not by accident.

## Investigation steps
1. **Treat a 100502 alert as code execution inside a trusted process.** The signed
   parent is not the anomaly; the unsigned module it loaded is.
2. **Read `imageLoaded` and its directory.** A DLL loaded from a user-writable path
   (`\Users\`, `\ProgramData\`, `\Temp\`, an app's own folder) is the sideload
   pattern; correlate against where that application normally lives.
3. **Distrust the metadata, trust the signature.** `originalFileName`/`company` may
   impersonate Microsoft. `signed=false` / `signatureStatus` is the ground truth.
4. **Pivot on the parent (`image`) and the hashes.** Reconstruct what launched the
   host process; hash the DLL (`Hashes` field) for reputation and threat-intel.
5. **Rule out benign package-signed sources.** UWP/Store, some installers, and
   certain dev tools ship unsigned per-file DLLs - confirm the path is not an
   ACL-protected package store before escalating.

## Notes and limitations
- **The detection fires on the load, not on payload success.** The tampered
  `version.dll` was caught even though `rundll32` then failed to find its export.
  The signature of the loaded module is the signal (a strength - it catches
  attempts; and a caveat - an alert is not proof of successful execution).
- **Proxy load vs true search-order side-load.** This lab used `rundll32` to
  guarantee a native load; a genuine T1574.002 plants the DLL beside a
  search-order-vulnerable signed app. Both yield the identical EID 7 signature, and
  the rule keys on the signature, so coverage is equivalent - but a true plant was
  not staged here and is the natural next variant.
- **Managed-assembly loads are a blind spot for this EID 7 config.** Runtime
  `Assembly.Load*` of a .NET DLL did not raise EID 7. Detecting managed side-loads
  needs a different signal (e.g. CLR/ETW telemetry, or EID 7 on `clr.dll`/`coreclr`
  host context) - out of scope here, but a real gap to record.
- **`logall_json` was not used.** Rule 100502 is level 12, so its alerts land in
  `alerts.json` directly (as Lab 03 established); the decoded EID 7 field names were
  taken from the shipped `0820` rules plus Wazuh's deterministic field-name
  lowercasing. This improves on the earlier plan to re-enable `logall_json`, which
  had starved the 3 GB manager on restart.
- **Production needs a baseline.** `signed=false` plus a path exclusion is a lab-
  grade rule. A real deployment would allow-list known unsigned-but-benign DLLs by
  hash/full path and baseline which applications legitimately load unsigned modules
  before turning this to a paging severity.
- **The append-bytes trick invalidates catalog trust, not embedded signatures.** It
  worked because `version.dll` is catalog-signed. A file with an *embedded*
  signature would need the blob removed or a byte changed inside the signed region.

## Lessons learned
- **For a sideload, the metadata lies and the signature tells the truth.** The
  tampered DLL impersonated Microsoft in every descriptive field. Only
  `signed`/`signatureStatus` could not be forged. Build on the field the attacker
  cannot copy.
- **How a DLL is loaded decides whether you see it.** Native `LoadLibrary` and CLR
  assembly loads are different code paths with different EID 7 visibility. A
  detection assumed to cover "DLL loads" may silently miss managed ones.
- **Package-signed is not per-file signed.** UWP/Store DLLs read `Signed=false`
  legitimately. A signature rule that does not know this pages on the Microsoft
  Store - the negative control is what caught it.
- **Negative controls find the false positives the positive test never will.** The
  control here was designed to prove a signed load stays silent; it did, and it
  *also* exposed the UWP false positive - the more valuable finding.
- **Log broadly at the sensor, alert precisely at the rule.** The Sysmon filter
  keeps logging every unsigned load (visibility); the rule excludes benign sources
  (precision). Tuning the rule never blinds the logs.
- **Embedded vs catalog signing is operational, not trivia.** It decided how the
  unsigned test DLL had to be produced, and it explains why a legitimate Windows
  DLL and a Store DLL can both report the same `Signed` value for opposite reasons.

## MITRE ATT&CK mapping
```
DLL Side-Loading (T1574.002)
  |
  +-- managed .NET DLL loaded (rundll32 / CLR reflection) --> NO EID 7  [blind spot: how-loaded]
  |
  +-- native unsigned DLL loaded by signed rundll32       --> Sysmon EID 7
        |
        +--> sysmon_event7  (image load, level 0)
               |
               +--> 100502  L12  signed == false
                      AND imageLoaded NOT under \Windows\ or \WindowsApps\
                      [fires on the unsigned sideload; silent on signed loads
                       (filtered at sensor) and on benign UWP package DLLs (tuned)]
```

## Status
Complete - custom rule **100502** (level 12) confirmed firing on a live Windows 11
endpoint for an unsigned native DLL (`version.dll`, catalog trust broken by a
16-byte append) loaded into signed `rundll32`, while staying silent on the
identical *signed* DLL (filtered at the Sysmon sensor by the `Signed=false`
amendment) and on legitimate Microsoft Store / UWP package DLLs (excluded by the
`WindowsApps` tune, which the negative control surfaced as a false positive and
which was verified fixed by timestamp against the tune restart).

The lab documented that the shipped ruleset has **no signature-based EID 7
coverage** (its seven rules key on named DLLs or the Temp path, never on the
signature); that **the SwiftOnSecurity config ships EID 7 fully disabled** (an empty
include - correcting the Lab 01 audit), closed by a one-line `Signed=false`
amendment measured at **0 events/min idle**; that **a managed .NET DLL load does not
raise EID 7** in this configuration, forcing a native payload; that **`version.dll`
is catalog-signed, not embedded-signed**, which is why the signature had to be
broken by hash rather than stripped; that a sideloaded DLL **impersonates Microsoft
in every metadata field** so the detection must key on `signed`/`signatureStatus`;
and that **UWP/Store DLLs legitimately report `Signed=false`**, a false positive the
negative control caught and the `WindowsApps` exclusion fixed. `logall_json` was not
needed and remains disabled.
