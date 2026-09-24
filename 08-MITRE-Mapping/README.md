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
| 02 | [Tag audit and corrections](Lab02-Tag-Audit.md) | Wrong, over-broad and missing tags; ID collision; parent/sub normalisation | 3 re-tagged live rules, corrected writeups, `mapped_techniques` column | **Complete** |
| 03 | [Evidence-scored coverage map](Lab03-Coverage-Map.md) | Evidence layer vs the SIEM's own alert view; tactic summary; 100401 regression found | [`layer-evidence.json`](layer-evidence.json), [`layer-wazuh-alerts.json`](layer-wazuh-alerts.json), [`coverage-comparison.csv`](coverage-comparison.csv) | **Complete** |
| 04 | Detection regression test | Re-fire one attack per technique family against the current manager | Regression matrix | Planned |
| 05 | Threat-informed gap analysis | Overlay a real ransomware group targeting education/healthcare; rank gaps | Prioritised gap list | Planned |

No custom rules are written in this module - it measures the rules that exist.

## Lab 01 headline numbers
- 42 detections inventoried; 38 technique IDs; **34 backed by a deployed rule**.
- Evidence: 30 `fired`, 8 `fired-with-limit`, 2 `hunt-only`, 2 `not-deployed`.
- Documentation drifted from the live manager in **3 of 34** custom rules.
- Four techniques exist only on paper: T1021.001, T1087, T1069, T1482.

## Lab 02 headline numbers
- 3 live rules re-tagged: 100302 and 100303 -> T1095 (raw TCP shell, not Web
  Protocols); 100501 drops a bare T1059 parent tag.
- Undeployed RDP rule renumbered 100401 -> reserved **100412** (ID collision).
- Normalised count: **36 techniques, 32 backed by a deployed rule** (down from
  38/34 - parent IDs had double-counted).
- Tag drift between the live manager and the published rules: **0**.

## Lab 03 headline numbers
- Wazuh's own alert view lights **64** techniques; the evidence view proves **32**.
  28 lit cells come from shipped rules never exercised by a deliberate attack.
- Only **7.7%** of 380,938 alerts carry an ATT&CK tag; the hottest cells are
  logons, registry churn and admin sudo.
- **100401 regressed**: ~8,000 alerts, 98% from the DC's `DC01$` machine account
  after Module 06 added a domain controller.
- Empty tactics: **Lateral Movement, Collection**; Exfiltration shape-tested only.

Open the layers in ATT&CK Navigator:
[evidence view](https://mitre-attack.github.io/attack-navigator/#layerURL=https://raw.githubusercontent.com/Priyanshutomar-8/Enterprise-SOC-Lab/main/08-MITRE-Mapping/layer-evidence.json) |
[Wazuh alert view](https://mitre-attack.github.io/attack-navigator/#layerURL=https://raw.githubusercontent.com/Priyanshutomar-8/Enterprise-SOC-Lab/main/08-MITRE-Mapping/layer-wazuh-alerts.json)
