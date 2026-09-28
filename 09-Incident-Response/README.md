# Module 09 - Incident Response

Modules 03-07 built and measured detections. Module 08 Lab 05 overlaid a real
ransomware group - **INC Ransom (ATT&CK G1032)**, which targets education and
healthcare - on this SIEM and found **0 of 24 in-scope procedures proven**, then
ranked what to build. This module closes that loop: it emulates the top-ranked
links of INC's chain with **harmless stand-ins**, builds the detections Lab 05
called for, proves they fire, and then **works each alert as an incident** -
triage, scope, containment, timeline, report.

The output is two things at once: three new firing rules that fill Lab 05's top
gaps, and an incident-response narrative specific to the sector the detections are
meant to defend.

## Boundaries (defensive lab - not optional)
- **No real ransomware and no encryption of real data.** The "encryptor" is a
  benign stand-in binary (a renamed system EXE, or a script that writes a marker
  file). Every detection keys on **how a payload is deployed and run** - service
  install, deployment method, exfiltration channel - never on a malicious payload.
  That is what makes the detection reusable against the real thing.
- **No exploit code.** INC's initial access (Citrix CVE-2023-3519, phishing) has no
  data source in this lab and stays a documented gap, exactly as in Lab 05.
- **One Windows endpoint at a time** with the manager. Module 08 Lab 04 established
  that DC01 and the Windows endpoint cannot both run alongside the manager on this
  host without stalling; every lab here respects that, and the capstone is a paper
  walkthrough for the same reason.

## Environment
Same lab as Modules 06-08: manager (Wazuh 4.14.6 all-in-one, Ubuntu,
192.168.56.79), domain controller `DC01` (agent 004), Windows Sysmon endpoint
(agent 002), Kali + impacket (agent 001) as the activity generator. Rule namespace
**100900+**.

## Labs

| # | Lab | INC link (Lab 05 rank) | Rule | IR focus | Status |
|---|---|---|---|---|---|
| 01 | Incident-response foundation and plan | - | none | Scenario, phases, evidence and timeline format, what "contain" means for one analyst | **Planned** |
| 02 | Deployment detection | PsExec cluster (#1: T1570/T1569.002/T1036.005) | new (100900) | Triage - one host or many | Planned |
| 03 | Exfiltration detection | Cloud exfiltration (#2: T1537) | new | Scope - what left, when, over which channel | Planned |
| 04 | Lateral movement in context | RDP (#3: T1021.001) | deploy 100412 with context | Reconstruct the movement path | Planned |
| 05 | Capstone - work the whole chain | 02-04 end to end | none new | Full IR narrative: cross-rule timeline, scope, containment, report (paper walkthrough) | Planned |

Rule IDs are namespaced `100900+`. The capstone writes no new rule - its value is
the incident narrative built from the evidence Labs 02-04 already produced.

## Provenance
This module is the action side of Module 08 Lab 05's gap analysis. Every rule here
traces to a ranked gap and an INC Ransom procedure cited in ATT&CK; every "attack"
is a harmless stand-in for that procedure.
