# Module 08 - MITRE ATT&CK Mapping

Modules 03-07 built detections one lab at a time. This module steps back and asks
the question a SOC lead actually asks: **which ATT&CK techniques does this SIEM
detect, and how do we know?**

The common answer - read the rule tags and colour an ATT&CK Navigator matrix -
measures intent, not coverage. A tag does not prove a rule is deployed, fires, or
separates the attack from normal activity, and earlier modules produced counter-
examples of each: a reserved rule that never fired (Module 06 Lab 04), a rule that
fires identically on forged and legitimate tickets (Module 07 Lab 04), and attacks
blocked by Defender before the SIEM saw them (Module 05). This module builds the
map from the **live manager** and scores every technique by **evidence**.

## Scope
Every detection built or validated in Modules 03-07:

- **Custom rules** 100300-100701 (33 deployed, 2 written but not deployed)
- **Shipped rules** validated in Module 03 Labs 01-05 (5902, 5503, 5402, 2502, 550)
- **Hunts** from Module 07 (Golden Ticket anti-join, beacon periodicity)
- **Gaps and blind spots**, mapped deliberately rather than omitted

## Evidence scale
| Status | Meaning |
|---|---|
| `fired` | Fired on a live attack simulation; no known structural limit |
| `fired-with-limit` | Fires, with a documented FP, evasion, race, or scope limit |
| `hunt-only` | Found by a stored-data query, not by an alerting rule |
| `not-deployed` | Written or reserved, not running on the manager |
| gap | Nothing detects it |

## Labs

| # | Lab | Focus | Output | Status |
|---|---|---|---|---|
| 01 | [Detection inventory](Lab01-Detection-Inventory.md) | Live rules vs published writeups; evidence status per detection | [`detection-inventory.csv`](detection-inventory.csv) | **Complete** |
| 02 | Tag audit and corrections | Fix ID collision, missing/over-broad tags, parent/sub double counting | Corrected live rules + writeups | Planned |
| 03 | Evidence-scored coverage map | ATT&CK Navigator layer coloured by evidence; compared with Wazuh's built-in MITRE view; tactic summary | Navigator layer JSON | Planned |
| 04 | Detection regression test | Re-fire one attack per technique family against the current manager | Regression matrix | Planned |
| 05 | Threat-informed gap analysis | Overlay a real ransomware group targeting education/healthcare; rank gaps | Prioritised gap list | Planned |

No custom rules are written in this module - it measures the rules that exist.

## Lab 01 headline numbers
- 42 detections inventoried; 38 technique IDs; **34 backed by a deployed rule**.
- Evidence: 30 `fired`, 8 `fired-with-limit`, 2 `hunt-only`, 2 `not-deployed`.
- Documentation drifted from the live manager in **3 of 34** custom rules.
- Four techniques exist only on paper: T1021.001, T1087, T1069, T1482.
