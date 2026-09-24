# Lab 02 - Tag Audit: Is Each Detection Labelled With What It Proves?

## Objective
Lab 01 established *which* detections exist. This lab checks whether each one is
**labelled correctly** - whether its ATT&CK technique describes what the rule
actually matches and what its lab actually proved. A wrong tag is not cosmetic:
the coverage map in Lab 03, and every SIEM's built-in ATT&CK view, is computed
from tags. An over-broad tag colours a cell the rule never earned; a wrong tag
colours the wrong cell and leaves the right one blank.

This is an **audit and correction lab - no new rule**. Three live rules change
their `<mitre>` block only; no match logic changes, so detection behaviour is
identical before and after.

## Framing
| Field | Value |
|---|---|
| Discipline | Detection engineering - detection metadata quality |
| Input | [`detection-inventory.csv`](detection-inventory.csv) from Lab 01 |
| Test for each tag | Does the rule's match logic, and the evidence in its lab, support this exact technique? |
| Live rules changed | 100302, 100303, 100501 (tags only) |
| Rule produced | None |
| Reference | https://attack.mitre.org/ |

## Environment
| Component | Details |
|---|---|
| Manager | Wazuh 4.14.6 all-in-one, Ubuntu, 192.168.56.79 |
| Rules file | `/var/ossec/etc/rules/local_rules.xml` (33 custom rules) |

## Audit rules
A tag stays only if all three hold:

1. **It matches the mechanism the rule keys on**, not the scenario around it.
2. **It is the most specific technique the evidence supports.** A parent ID is
   used only when the rule is deliberately sub-technique-agnostic.
3. **The proving lab exercised it.** If a lab only tested the *shape* of an
   attack, the tag is kept but marked, not silently counted.

## Findings and decisions

| # | Detection | Tag before | Problem | Decision | Changed in |
|---|---|---|---|---|---|
| 1 | 100302 (ncat reverse shell) | T1059.004, **T1071.001** | T1071.001 is *Web Protocols*. `ncat -e /bin/bash <ip> <port>` is raw TCP | **T1071.001 -> T1095** (Non-Application Layer Protocol) | Live + writeup |
| 2 | 100303 (socat reverse shell) | T1059.004 | Same raw-TCP channel as 100302, no C2 tag at all | **Add T1095** | Live + writeup |
| 3 | 100501 (LOLBin proxy exec) | T1218.010/.005/.011, **T1059** | Bare parent T1059 beside exact sub-techniques; the rule keys on the proxy binary, not an interpreter | **Remove T1059** | Live + writeup |
| 4 | 100401 (RDP variant) | T1021.001, T1078 | Undeployed RDP rule shares ID 100401 with the deployed privileged-logon rule | **Renumber to reserved 100412**, still not deployed | Writeup |
| 5 | 100701 | T1558.001 (live only) | Published rule block had no `<mitre>` element | **Add the block** to the writeup | Writeup |
| 6 | 5503 (shipped) | T1110.001 | Module 03 Lab 02 claims T1548.003, but 5503 fires on *any* PAM failure | **Map as T1110.001**; record that T1548.003 is not specifically detected | Inventory + writeup note |
| 7 | 100503 (DNS tunnel) | T1071.004, T1048.003 | Lab used random 45-char labels - exfil *shape*, no encoded data | **Keep, marked shape-tested only** | Inventory |
| 8 | 2502, 5902 (shipped) | T1110, T1136 | Wazuh ships parent IDs; the labs proved the specific sub-technique | **Count T1110.001, T1136.001** (new `mapped_techniques` column) | Inventory |
| 9 | 5402 (shipped) | T1548.003 | Module 03 README shows "Level 5"; live rule is level 3 | **No change** - the column is the highest level seen in that lab (5503, level 5, fired alongside) | - |

Two cases are worth the detail.

**Finding 1 was missed by Lab 01.** Lab 01 compared tags between two sources, and
both sources agreed on T1071.001 - so the diff was clean. Agreement between the
docs and the deployment says nothing about whether the tag is *right*. Only
reading the rule's match logic (`audit.command` = `ncat`, `-e`, a host and a raw
port) against the technique definition exposed it. For contrast, the Module 05
beacon (100504/100505) uses `Invoke-WebRequest http://...`, so its T1071.001 is
correct and stays.

**Finding 6 cannot be fixed in the rule.** Shipped rules live in
`/var/ossec/ruleset/rules/` and are overwritten on upgrade; editing their tags
would silently revert. The honest fix is in the mapping: count what 5503 proves
(an authentication failure) and state that sudo abuse specifically is not
detected. A sudo-specific child rule would close it - noted for Lab 05's gap list.

## Deploying the three live changes

Backup first, so the change is reversible and diffable:

```bash
sudo cp -p /var/ossec/etc/rules/local_rules.xml /var/ossec/etc/rules/local_rules.xml.bak-m08-lab02
```

Each edit is scoped to one rule's block (`/rule id="X"/,/<\/rule>/`) so no other
rule can be touched:

```bash
sudo sed -i \
  -e '/rule id="100501"/,/<\/rule>/{/<id>T1059<\/id>/d}' \
  -e '/rule id="100302"/,/<\/rule>/s#<id>T1071.001</id>#<id>T1095</id>#' \
  -e '/rule id="100303"/,/<\/rule>/s#<id>T1059.004</id>#<id>T1059.004</id><id>T1095</id>#' \
  /var/ossec/etc/rules/local_rules.xml
```

`<id>T1059<\/id>` must be followed immediately by `</id>`, so `T1059.004` elsewhere
cannot match.

Syntax check, and restart only if it passes:

```bash
sudo /var/ossec/bin/wazuh-analysisd -t && sudo systemctl restart wazuh-manager
```

## Verification

**1. Exactly three lines changed.**

```bash
sudo diff /var/ossec/etc/rules/local_rules.xml.bak-m08-lab02 /var/ossec/etc/rules/local_rules.xml
```

```
38c38
<     <mitre><id>T1059.004</id><id>T1071.001</id></mitre>
---
>     <mitre><id>T1059.004</id><id>T1095</id></mitre>
47c47
<     <mitre><id>T1059.004</id></mitre>
---
>     <mitre><id>T1059.004</id><id>T1095</id></mitre>
479d478
<       <id>T1059</id>
```

**2. Tags are as intended, and no rule was lost.**

```
100302: T1059.004 T1095
100303: T1059.004 T1095
100501: T1218.010 T1218.005 T1218.011
total rules: 33
```

**3. Manager healthy.** `wazuh-analysisd -t` passed; `wazuh-manager` restarted and
is `active`. `ossec.log` shows no rule errors (the only `ERROR` lines are
`wazuh-remoted` refusing stale `agent.conf.bak-*` files in the shared agent-group
directory - unrelated housekeeping).

**4. Live and published now agree.** Lab 01's order-insensitive diff, re-run:

| Source | Rules |
|---|---|
| Live manager | 33 |
| Published writeups | 35 |
| Differences | **100412** (RDP) and **100602** (LDAP) - both intentionally not deployed |

**Zero tag drift across the 33 deployed rules**, down from three mismatches in
Lab 01.

### A verification tool bug, again
The first check command used the filter `/^1003\/0[23]$|^100501$/` - a stray
escaped slash that can never match `100302` or `100303`. It printed only 100501,
which *looked* like the other two edits had failed. They had not: the filter was
wrong, not the file. Corrected filter: `/^(100302|100303|100501)$/`. Same lesson as
Lab 01's extractor - **when a check reports a surprising result, test the check
before believing it**, and confirm with an independent method (here, `diff`
against the backup).

## Result - inventory after the audit

[`detection-inventory.csv`](detection-inventory.csv) gains a `mapped_techniques`
column: the technique Module 08 *counts* for each detection (most specific
evidence-backed ID). `technique_ids` keeps the literal rule tags.

| Measure | Lab 01 | Lab 02 |
|---|---|---|
| Detections | 42 | 42 |
| Technique IDs counted | 38 (raw tags) | **36** (normalised) |
| Backed by a deployed rule | 34 | **32** |
| Paper-only | T1021.001, T1087, T1069, T1482 | unchanged |
| Tag drift, live vs published | 3 rules | **0** |

The count went **down**, and that is the correct direction: T1110, T1136 and T1059
were parent IDs double-counting coverage already credited to a sub-technique.
T1095 is a genuine addition (Command and Control via raw TCP) that the old tag
had hidden behind a wrong one.

## Key findings
- **Agreement is not correctness.** Lab 01's live-vs-docs diff passed 100302
  because both sides carried the same wrong tag. Tag quality needs a separate
  check: rule logic against the technique definition.
- **Over-broad parent tags inflate coverage.** Removing T1059 from 100501 and
  normalising two shipped parent tags cut the technique count from 38 to 36 with
  no loss of real detection.
- **Shipped-rule tags cannot be corrected in place** - upgrades overwrite them.
  The fix belongs in the mapping layer, stated explicitly.
- **Tags are metadata, so the change is zero-risk to detection** - but it is not
  zero-risk to the rules file. Scoped `sed`, a backup, `-t` before restart, and a
  `diff` afterwards made a three-line change provable.

## Result
Three live rules re-tagged (100302 and 100303 -> T1095; 100501 drops T1059), five
public writeups corrected, the 100401 ID collision resolved by reserving 100412,
and the inventory normalised to **36 techniques, 32 deployed-rule-backed**, with
**zero drift** between the manager and the published rules. **No custom rule.**
Next: **Lab 03 - the evidence-scored coverage map**.
