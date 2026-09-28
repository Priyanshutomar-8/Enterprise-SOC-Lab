# Lab 01 - Incident-Response Foundation and Plan

## Objective
Before working any incident, decide how it will be worked. This lab sets the
scenario the module runs on, the response phases it uses, the evidence and timeline
format every later lab writes into, and - the part most home labs skip - an honest
definition of what "contain" and "recover" mean when the responder is one analyst
with one endpoint and no ticketing system, EDR, or second pair of hands.

**No rule, no attack.** This is the planning lab. Output: the scenario, the phase
model, and the reusable evidence/timeline templates.

## Framing
| Field | Value |
|---|---|
| Discipline | Incident response - preparation and process design |
| Scenario adversary | INC Ransom (ATT&CK G1032), the group ranked in Module 08 Lab 05 |
| Phase model | NIST SP 800-61r2: Preparation; Detection and Analysis; Containment, Eradication and Recovery; Post-Incident Activity |
| Lab infrastructure | None - desk work on the host |
| Rule produced | None |

## The scenario
A mid-size US university's SOC (this lab) runs Wazuh over a Windows domain. Over one
week, an intrusion consistent with INC Ransom unfolds: a valid account is used to
move in over RDP (T1021.001), a renamed PsExec deploys a service across hosts
(T1570/T1569.002/T1036.005), and data is staged and pushed to a cloud service
(T1537) - the double-extortion pattern that precedes encryption. Labs 02-04 build
the detection for one link each; Lab 05 works the whole chain as one incident.

The scenario is deliberately the **pre-encryption** chain. For education and
healthcare, the reportable breach is the exfiltration, and the window to act is
before the encryptor runs - which is exactly where Lab 05 said detection is worth
building.

## Phase model and what each phase means here
| NIST phase | In this lab | Honest limit |
|---|---|---|
| Preparation | Modules 03-08: the ruleset, archiving, the coverage map | Already done - this module assumes it |
| Detection and Analysis | Labs 02-04 fire a rule; triage confirms true/false positive and pulls the surrounding events | Single analyst - no tier-2 escalation |
| Containment | Isolate the endpoint (network), disable the abused account, stop the service | *Simulated* - see the containment note below |
| Eradication and Recovery | Remove the stand-in artefacts, re-enable with the abuse path closed | No real damage to recover; recovery is verifying the artefacts are gone and the detection still fires |
| Post-Incident Activity | The lab writeup itself; carried-forward rule tuning | This is the module's real deliverable |

### The containment honesty note (the point of this lab)
Containment actions in a home lab are **simulated, and the writeup must say so.**
Isolating agent 002 by pulling its host-only NIC is real and reversible;
"disabling the compromised domain account" on a lab DC is a demonstration, not a
production change-controlled action. An interviewer will respect "I isolated the
host at the network layer and documented the account-disable step I would take in
production" far more than a claim that a full IR containment ran end to end in a
VirtualBox lab. State the boundary; do not blur it.

## Reusable templates (Labs 02-05 write into these)

### Evidence record (one per confirmed alert)
```
Alert:        rule.id, level, description
Fired at:     <collector timestamp, UTC> (note agent-vs-collector clock skew)
Host / agent: <name / id>
Account:      <subjectUserName / targetUserName>
Trigger:      <the event and the fields that matched>
TP / FP:      <verdict + one line of why>
ATT&CK:       <technique, normalised to the ATT&CK version in use>
Raw event:    <path or query that returns it>
```

### Incident timeline (Lab 05 stitches per-lab rows into one)
```
| UTC time | Host | Phase | Observed event | Detection (rule) | Analyst action |
```
Timestamps are on the **collector clock** and normalised to UTC - Modules 05 and 07
both recorded multi-hour agent-vs-collector skew, so a timeline built on agent
local time is wrong. Every later lab records both the event's `timestamp` and any
skew it hit.

## Decisions fixed here (so later labs cannot drift)
1. **Timeline clock:** collector `timestamp`, UTC. Agent local time is recorded only
   as a noted skew, never used to order events.
2. **TP/FP discipline:** every fired alert in Labs 02-05 gets an explicit verdict.
   A fired rule is not a confirmed incident until triage says so - Module 08's whole
   argument.
3. **Containment is labelled real or simulated** on every action, per the note above.
4. **ATT&CK version:** Module 08 Lab 05 found the repo's layers are v17 while current
   ATT&CK is v19. This module tags techniques at **v19** and notes the v17 origin
   where a rule predates it.

## Key findings
- The scenario is scoped to the **pre-encryption** chain, where detection has value
  for the target sector - not the encryption event, which only reports the damage.
- **Containment in a single-analyst VM lab is partly simulated;** the credible
  deliverable is documenting the boundary, not overclaiming a full IR.
- The evidence and timeline templates force **collector-clock UTC** and an explicit
  **TP/FP verdict** into every later lab, carrying Modules 05/07/08's lessons forward.

## Carried forward
- Lab 02: build and fire the deployment rule (100900); triage it as one host vs many.

**No rule, no attack.** Next: **Lab 02 - deployment detection.**
