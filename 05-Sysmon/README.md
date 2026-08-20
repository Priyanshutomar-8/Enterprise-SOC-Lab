# Module 05 - Sysmon

Process and host telemetry that native Windows event logs cannot produce.
Module 04 built eight detections from the Security, System, PowerShell and
Defender channels alone, and documented three gaps that exist *because* of that
constraint. This module deploys **Sysmon** as the sensor that closes them, then
builds detections on the event types only Sysmon provides.

## Environment note
The endpoint runs **Windows 11 Home**. Sysmon is installed from Sysinternals with
the **SwiftOnSecurity community config** (`sysmonconfig-export.xml`), and its
channel is shipped to the manager through the centralized `windows` agent group -
the same mechanism Labs 05 and 07 of Module 04 used, since the Windows VM has no
SSH.

The community config is a starting point, not a finished sensor. Two of its
event sections are effectively disabled by default (see Lab 01), and amending
them is part of the work in Labs 02 and 04 rather than a workaround.

## Labs

| # | Lab | Sysmon EID | MITRE | Custom Rule | Status |
|---|---|---|---|---|---|
| 01 | [Sysmon deployment, config audit, ingestion](Lab01-Sysmon-Deployment.md) | 1, 3, 13, 22 | T1562.001 (closing test) | - | **Complete** |
| 02 | [LSASS credential access](Lab02-LSASS-Credential-Access.md) | 10 | T1003.001 | 100500 | **Complete** |
| 03 | [LOLBin proxy execution (Squiblydoo / mshta / rundll32)](Lab03-LOLBin-Proxy-Execution.md) | 1 | T1218, T1059 | 100501 | **Complete** |
| 04 | [DLL side-loading and code-signing telemetry](Lab04-DLL-Sideloading.md) | 7 | T1574.002 | 100502 | **Complete** |
| 05 | [C2 beacon: network and DNS](Lab05-C2-Beacon-Network-DNS.md) | 3, 22 | T1071.001, T1071.004 | 100503, 100504, 100505 | **Complete** |
| 06 | Sysmon tampering and alternate data streams | 4, 15 | T1562.001, T1564.004 | 100506 | Planned |

Custom detection rules are namespaced at **100500+**, continuing from Module 04's
100400 block. Lab 01 writes no rule - it is a deployment and verification lab,
and its findings are all properties of the shipped ruleset and the community
config.

## Log source
One new channel for the whole module:

```xml
<localfile>
  <location>Microsoft-Windows-Sysmon/Operational</location>
  <log_format>eventchannel</log_format>
</localfile>
```

Most shipped Sysmon rules sit at level 0 - decoded but deliberately not alerted -
so `alerts.json` can look empty while ingestion works perfectly. `logall_json`
archives are one way to read the real decoded field names before writing a rule,
but it was **disabled after Lab 02** when it starved the 3 GB manager on restart.
Labs 03, 04 and 05 confirmed it is unnecessary for a level-12 custom rule (whose
alerts land in `alerts.json` directly) - decoded field names can be taken from the
shipped rules and Wazuh's field-name convention instead. It remains **off**.

## Each lab includes
- Objective and MITRE ATT&CK mapping
- Sysmon config prerequisites, and any amendment the community baseline requires
- Attack simulation commands
- Custom Wazuh detection rule
- Detection results with a full test matrix, including negative controls
- Notes, limitations, and lessons learned

## Status
In progress - Labs 01, 02, 03, 04 and 05 complete. Sysmon v15.21 is deployed and
verified end-to-end on the live Windows 11 endpoint, and six custom detections
(100500 credential access, 100501 LOLBin proxy execution, 100502 DLL side-loading,
100503 DNS tunneling, 100504/100505 C2 beacon) are built and confirmed firing.

**Three of the five detection labs so far found a *total* gap in the shipped
ruleset** - no `regsvr32` coverage (Lab 03), no signature-based EID 7 coverage
(Lab 04), no DNS coverage whatsoever (Lab 05). The pattern is not incidental: the
shipped Sysmon ruleset is built around process creation and barely models the
network.

Lab 05 headline: the shipped ruleset has **no DNS detection at all** - rule 61650
is a level-0 group tag and there is no `sysmon_id_22` rule file - and its ten
Event ID 3 rules key exclusively on **lateral-movement ports** (135, 389, 445,
3389, 5985); ports 80 and 443 appear nowhere. Worse, shipped rule **92101**
(`powershell.exe` + tcp, **level 0**) wins the first-match race against any custom
rule chained with `if_group sysmon_event3`, so a correctly-written, cleanly-validated
custom beacon rule fired **zero** times against twelve real events until it was
re-parented to `<if_sid>61605, 92101</if_sid>` - the same workaround Wazuh's own
rule 92110 uses. Rules 100503 (DNS label length) and 100504/100505 (rate + `same_field`
on destination IP *and* image) close the gaps; **no Sysmon config amendment was
needed**, a first for this module, and idle EID 22 volume was 0/5min. The negative
controls define the ceiling: built-in `curl.exe` is absent from the sensor's
include-list and produced **zero telemetry** for ten confirmed connections; a
45-character exfil label under `.msedge.net` was swallowed by the config's
**public** exclude-list; and a 40-second sleep defeated the beacon rule outright,
because `frequency`/`timeframe` measures rate, not periodicity. Live OneDrive
traffic validated `same_field` for free - it is beacon-shaped but rotates
destinations, and never tripped 100505.

Lab 04 headline: the shipped ruleset has **no signature-based EID 7 coverage** - its
seven rules (92151 - 92157) key on named DLLs or the Temp path, never on the
signature - and the SwiftOnSecurity config ships EID 7 **fully disabled** (an empty
include). A one-line `Signed=false` amendment (0 events/min idle) plus rule 100502
(level 12) close the gap: an unsigned DLL loaded by a signed process fires,
regardless of the DLL's *metadata*, which a sideload forges (the tampered
`version.dll` still reported `OriginalFileName=VERSION.DLL` / `Company=Microsoft` -
only `signed`/`signatureStatus` exposed it). The lab also found that **a managed
.NET DLL load does not raise EID 7** in this config (forcing a native payload) and
that **UWP/Store DLLs legitimately report `Signed=false`** - a false positive the
negative control caught and the `WindowsApps` path exclusion fixed. `logall_json`
was **not needed** for a level-12 rule and remains disabled.

Lab 03 headline: the shipped ruleset has **no `regsvr32` coverage at all**, catches
`mshta` **only under an Office parent** (rule 92047), and covers only narrow
`rundll32` cases. Rule 100501 (level 12) keys on `originalFileName` plus a
remote/scriptlet command-line indicator - catching Squiblydoo and standalone
`mshta` regardless of parent, while benign LOLBin use stays at the generic level-3
rule 67027. The endpoint's **AMSI** and **Defender** each blocked a *different*
variant before the SIEM saw it (the `.sct` authoring as `Backdoor:JS/Relvelshe.A`,
the remote scriptlet as `Trojan:Win32/Powemet.A!attk`), making the rule a backstop
for the quieter forms that slip past prevention. `logall_json` is
**disabled** (it starved the manager on restart and is not needed to alert on a
level-12 rule); Lab 04 confirmed it is not required and left it off.

Lab 02 headline: the shipped LSASS rule (92900) is both **noisy** - it
false-positives on Windows Defender's own `MsMpEng.exe` because its access-mask
regex is unanchored and matches `0x1010` inside Defender's benign `0x101000` -
and **blind** - it evades `0x1fffff` (full access, what ProcDump/comsvcs request)
because that mask is not in its allow-list. The endpoint's **LSASS PPL** and
**Defender behavioural detection** each block classic dumping before it reaches
the SIEM, making rule 92900 a backstop against a PPL bypass rather than a
frontline control. Rule 100500 (level 13) fixes the three shipped defects, was
tuned against its own false positive on `MRT.exe`, and confirmed the Lab 01
sibling-precedence hypothesis (higher-level rule wins a shared-event race).

Findings so far, from Lab 01:

- **Rule 92007 is shadowed by rule 92027.** Wazuh's shipped `Set-MpPreference`
  detection chain (92007 -> 92008, level 12, T1562.001) loses the first-match race
  to a level-4 "Powershell process spawned powershell instance" rule whenever the
  attack is launched from PowerShell - which is the ordinary shape of
  PowerShell-based tooling. Real Defender tampering is reported as routine
  execution, with the wrong severity, technique and description.
- **Rule 92008 is evaded by colon parameter binding.** Its regex requires
  whitespace before the value, so `-DisableRealtimeMonitoring:1` - functionally
  identical PowerShell - downgrades a level-12 alert to level 3.
- **Neither rule can see interactive execution.** Both depend on Sysmon EID 1
  (process creation); a command typed at an existing shell prompt spawns no
  process and is undetected, despite an interactive shell being the normal
  post-compromise condition.
- **The SwiftOnSecurity config disables the module's two most valuable event
  types.** `ProcessAccess` (EID 10, LSASS credential access) is an allow-list
  with no entries; `ImageLoad` (EID 7, signature and hash telemetry) is a narrow
  allow-list that a sideloaded DLL will not match. Labs 02 and 04 are blocked
  pending targeted amendments.
- **`wazuh-logtest -l EventChannel` does not replay eventchannel events.** It
  falls back to the generic `json` decoder and evaluates no rules at all.
