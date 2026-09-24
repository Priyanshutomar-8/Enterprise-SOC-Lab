# Lab 01 - Detection Inventory: What Is Actually Deployed?

## Objective
An ATT&CK coverage map is only as honest as the list it is built from. The usual
shortcut - read the rule tags out of the documentation and colour the matrix -
answers "what did we *intend* to detect?", not "what is running and proven?".
This lab builds the source-of-truth inventory for Module 08 from the **live
manager**, reconciles it against the published writeups, and records for every
detection what evidence exists that it fires.

This is an **audit lab - no custom rule**. Modules 03-07 each asked "can this
attack be detected?" Module 08 asks "across all of it, what is covered, how well,
and how do we know?" Lab 01 produces the data every later lab stands on:
[`detection-inventory.csv`](detection-inventory.csv).

## Framing
| Field | Value |
|---|---|
| Discipline | Detection engineering - coverage assessment |
| Question | Which ATT&CK techniques does this SIEM detect, per deployed rule, with what evidence? |
| Source of truth | `/var/ossec/etc/rules/local_rules.xml` on the manager (custom) and `/var/ossec/ruleset/rules/` (shipped) |
| Compared against | The rule blocks and verification sections of every lab writeup in Modules 03-07 |
| Rule produced | None |
| Reference | https://attack.mitre.org/ |

## Environment
| Component | Details |
|---|---|
| Manager | Wazuh 4.14.6 all-in-one, Ubuntu, 192.168.56.79 |
| Access | SSH from host to manager; rules read with `sudo` |
| Repo | This repository's Lab writeups, Modules 03-07 |

## Method

1. Extract every custom rule ID and its `<mitre>` technique IDs from the live
   `local_rules.xml`.
2. Extract the same pairs from every rule block published in the writeups.
3. Diff the two, order-insensitive.
4. Add the **shipped** Wazuh rules that Module 03 Labs 01-05 validated, the two
   Module 07 **hunts**, and the rules that were written but never deployed.
5. For each detection, record deployed yes/no and the evidence status from its
   lab's verification section.

Evidence status uses five values:

| Status | Meaning |
|---|---|
| `fired` | Fired on a live attack simulation; no known structural limit |
| `fired-with-limit` | Fires, but with a documented FP, evasion, race, or scope limit |
| `hunt-only` | Covered by a stored-data query, not by an alerting rule |
| `not-deployed` | Written or reserved, not running on the manager |
| (gap) | Nothing detects it - carried to Lab 03's map |

## Step 1 - Extract rule-to-technique pairs from the live manager

```bash
sudo ls -l /var/ossec/etc/rules/
```

One live file, `local_rules.xml`, plus 28 backup copies (`.bak-*`,
`.working-*`). None ends in `.xml`, so Wazuh does not load them - housekeeping,
not a coverage issue.

### The first extractor was wrong - silently

```bash
# FIRST VERSION - DO NOT USE
sudo awk '/<rule id=/{match($0,/id="[0-9]+"/); id=substr($0,RSTART+4,RLENGTH-5); t=""} /<id>/{gsub(/.*<id>|<\/id>.*/,""); t=t" "$0} /<\/rule>/{print id":"t}' /var/ossec/etc/rules/local_rules.xml
```

It printed 33 rules with no error. It was still wrong. Rules that keep several
techniques on one line - `<mitre><id>T1136.001</id><id>T1098</id></mitre>` - lost
all but the last: the greedy `gsub(/.*<id>/)` deletes everything up to the
**final** `<id>`. Four rules were under-reported:

| Rule | First extractor | Actual tags |
|---|---|---|
| 100300 | T1082 | T1057, T1082 |
| 100302 | T1071.001 | T1059.004, T1071.001 |
| 100401 | T1078 | T1021.001, T1078 (writeup - see Finding 1) |
| 100402 | T1098 | T1136.001, T1098 |

It was caught only because the same extraction was run against a second source
(the writeups) and the counts disagreed. **A coverage number from an unvalidated
tool is as untrustworthy as an untested rule.**

### Fixed extractor

```bash
sudo awk '/<rule id=/{match($0,/id="[0-9]+"/); id=substr($0,RSTART+4,RLENGTH-5); t=""} /<id>/{s=$0; while (match(s,/<id>[^<]+<\/id>/)) {t=t" "substr(s,RSTART+4,RLENGTH-9); s=substr(s,RSTART+RLENGTH)}} /<\/rule>/{print id":"t}' /var/ossec/etc/rules/local_rules.xml
```

The `while` loop takes each `<id>...</id>` in turn and strips it from the line
until none remain (`RLENGTH-9` removes the 4 + 5 characters of tag markup).
Result: **33 live custom rules**, 100300-100701.

## Step 2 - Diff live against published

The same parser run over every `Lab*.md` in Modules 03-07 yields 34 rule IDs.
Order-insensitive diff:

| Rule | Live manager | Published writeup | Finding |
|---|---|---|---|
| 100401 | T1078 | T1021.001, T1078 (RDP rule) + T1078 (logon rule) | Two different rules share one ID |
| 100602 | - (absent) | T1087, T1069, T1482 | Documented, never deployed |
| 100701 | T1558.001 | - (no `<mitre>` block) | Live rule tagged; published rule is not |

The other **30 rules match exactly**.

### Finding 1 - one rule ID, two rules (100401)
Module 04 Lab 02 publishes an RDP-logon rule (LogonType 10, T1021.001) that was
**written but not deployed** - Windows 11 Home cannot host RDP, so it could not be
verified - and a privileged-logon rule (4672, T1078) that was deployed. Both carry
`id="100401"`. The live manager runs only the second. Any map built from the
writeups would colour **T1021.001 (Lateral Movement) as covered. It is not.** Had
both ever been deployed, one would have silently replaced the other.

### Finding 2 - "reserved, not firing" means "not deployed" (100602)
Module 06 Lab 04 documents 100602 as reserved and not firing. The inventory makes
the distinction precise: it is **not on the manager at all**. That matters for the
map - "deployed but blind" and "never deployed" are different failure modes with
different fixes.

### Finding 3 - drift in the other direction (100701)
The live 100701 carries `<mitre><id>T1558.001</id></mitre>`; the rule block in
Module 07 Lab 04 names the technique only in its description text. The
documentation is *behind* the deployment, not ahead of it.

## Step 3 - Shipped rules validated in Module 03

Module 03 Labs 01-05 detected their attacks with **shipped** rules. They count as
coverage and were missing from a custom-rule-only inventory.

```bash
sudo grep -rl -E 'id="(5902|5503|5402|2502|550)"' /var/ossec/ruleset/rules/
```

```bash
sudo awk '/<rule id=/{match($0,/id="[0-9]+"/); id=substr($0,RSTART+4,RLENGTH-5); match($0,/level="[0-9]+"/); lv=substr($0,RSTART+7,RLENGTH-8); t=""; f=FILENAME; sub(/.*\//,"",f)} /<id>/{s=$0; while (match(s,/<id>[^<]+<\/id>/)) {t=t" "substr(s,RSTART+4,RLENGTH-9); s=substr(s,RSTART+RLENGTH)}} /<\/rule>/{if (id ~ /^(5902|5503|5402|2502|550)$/) print id" level="lv" ["f"]:"t}' /var/ossec/ruleset/rules/0020-syslog_rules.xml /var/ossec/ruleset/rules/0085-pam_rules.xml /var/ossec/ruleset/rules/0015-ossec_rules.xml
```

```
2502 level=10 [0020-syslog_rules.xml]: T1110
5902 level=8 [0020-syslog_rules.xml]: T1136
5402 level=3 [0020-syslog_rules.xml]: T1548.003
5503 level=5 [0085-pam_rules.xml]: T1110.001
550 level=7 [0015-ossec_rules.xml]: T1565.001
```

All five are present and above level 0, so all five alert. Against the Module 03
writeups:

| Rule | Detects | Wazuh tag | Writeup claim | Verdict |
|---|---|---|---|---|
| 2502 | Repeated SSH password failures | T1110 | T1110.001 | Writeup more specific - keep |
| 5902 | New local user | T1136 | T1136.001 | Writeup more specific - keep |
| 550 | FIM checksum changed | T1565.001 | T1565.001 | Match |
| 5402 | Successful sudo to root | T1548.003 | T1548 (README) | README corrected to T1548.003 |
| **5503** | **Any** PAM authentication failure | **T1110.001** | **T1548.003** | **Mismatch** |

### Finding 4 - the "failed sudo" detection is not a sudo detection (5503)
Module 03 Lab 02 maps a failed sudo to T1548.003. The rule that fired, 5503,
matches **every** PAM authentication failure - sudo, ssh, su, console login - and
Wazuh tags it **T1110.001**. Two consequences:

- On Wazuh's own MITRE dashboard, this lab's alerts count toward **Brute Force**,
  not Sudo. The tool's map and the writeup's map disagree about the same alert.
- A single failed password is neither brute force nor sudo abuse. The detection is
  real but generic, so the inventory records it as `fired-with-limit`.

5402 has the mirror-image limit: it fires on **every** successful admin `sudo`, at
level 3. It is an activity record, not an abuse detection - also
`fired-with-limit`.

## Step 4 - Evidence status

Each row's status comes from the verification section of the lab that built it,
not from the rule's existence. The `fired-with-limit` rows are the most useful
entries in the inventory:

| Detection | Technique | Limit (from the proving lab) |
|---|---|---|
| 5503 | T1110.001 | Generic PAM failure; not sudo-specific |
| 5402 | T1548.003 | Fires on all legitimate admin sudo |
| 100500 | T1003.001 | Fires on the LSASS access attempt; PPL + Defender blocked the dump before the SIEM |
| 100503 | T1071.004, T1048.003 | Exfiltration tag is shape-tested only - random labels, no real data encoded |
| 100505 | T1071.001 | A 40s beacon evades the rate threshold (rate is not periodicity) |
| 100507 | T1562.001 | Races Sysmon's log teardown - fired once, silent once |
| 100604 | T1558.001 | Demonstrated FP on a legitimate remote admin logon |
| 100701 | T1558.001 | Fires identically on legitimate and forged tickets |

## Result - the inventory

[`detection-inventory.csv`](detection-inventory.csv) - 42 rows, 12 columns:
`detection_id, type, module_lab, data_source, event_ids, detects, technique_ids,
tactics, deployed_live, evidence_status, evidence_note, writeup`.

| Type | Count |
|---|---|
| Custom rules, deployed | 33 |
| Custom rules, not deployed (100401-RDP, 100602) | 2 |
| Shipped rules validated in Module 03 | 5 |
| Hunts (Module 07) | 2 |
| **Total** | **42** |

| Evidence status | Count |
|---|---|
| `fired` | 30 |
| `fired-with-limit` | 8 |
| `hunt-only` | 2 |
| `not-deployed` | 2 |

**38 technique IDs** appear across the inventory; **34** are backed by at least
one deployed rule. Four exist **only on paper**: T1021.001 (RDP), T1087, T1069,
T1482 (LDAP reconnaissance). The 38 counts some parent/sub-technique pairs
separately (T1110 and T1110.001; T1136 and T1136.001; T1059 and its subs) -
normalising them is part of Lab 02.

## Fixes applied in this lab
- Module 03 README: Lab 03 `T1548` -> `T1548.003` (matches rule 5402); Lab 07
  `T1059` -> `T1059.004` (matches rule 100302).

## Carried to Lab 02 (tag audit)
- 100401 ID collision - renumber the undeployed RDP rule in the writeup.
- 100701 - add the `<mitre>` block to the published rule.
- 100501 - bare `T1059` parent tag alongside specific T1218 subs inflates coverage.
- 100503 - T1048.003 kept but marked shape-tested only.
- 5503 - decide how Module 03 Lab 02 is mapped (scenario T1548.003 vs rule T1110.001).
- Module 03 README lists 5402 at level 5; the live rule is level 3.
- Normalise parent/sub-technique double counting.

## Key findings
- **Documentation drifted from deployment in 3 of 34 rules**, in both directions:
  a documented rule that was never deployed, two rules sharing one ID, and a live
  tag missing from the published rule. A map built from docs would overstate
  coverage by at least one tactic (Lateral Movement).
- **The first inventory tool under-counted silently.** It dropped 4 techniques
  with no error; only a second-source cross-check exposed it.
- **Shipped rule tags and writeup claims disagree.** Wazuh files the "failed sudo"
  lab under Brute Force. Whatever a SIEM's built-in ATT&CK view shows reflects the
  shipped tags, not the analyst's intent.
- **Existence is not evidence.** 8 of 38 alerting detections carry a documented
  limit; 2 techniques are hunt-only; 4 exist only on paper.

## Result
A 42-row source-of-truth inventory built from the live manager, reconciled against
every published writeup, with evidence status per detection. Four findings: an ID
collision hiding a Lateral Movement gap, a reserved rule that was never deployed,
a live tag missing from the docs, and a shipped rule whose ATT&CK tag contradicts
the lab that relied on it. **No custom rule.** Next: **Lab 02 - Tag audit and
corrections**, then **Lab 03 - the evidence-scored coverage map**.
