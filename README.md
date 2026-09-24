# Enterprise SOC Lab

A self-built Security Operations Center (SOC) lab for detection engineering against
real attack simulation. Every detection in this repository was deployed to a live
Wazuh SIEM and then validated by running the attack and confirming the alert fired -
or by documenting, in writing, why it did not.

Thirty-seven lab writeups across eight modules. Thirty-four custom rules. Each lab
carries its attack commands, the raw telemetry, the rule, the verification, and a
section on what the detection cannot see.

---

## Lab environment

| Component | Details |
|---|---|
| SIEM platform | Wazuh 4.14.6 (Manager + Indexer + Dashboard, all-in-one) |
| Manager node | Ubuntu Server - 192.168.56.79 |
| Linux endpoint / attacker | Kali GNU/Linux - agent 001 - 192.168.56.80 |
| Windows endpoint | Windows 11 Home - agent 002 - 192.168.56.103 |
| Domain controller | Windows Server 2022 Standard (Desktop Experience) - agent 004 - `DC01`, forest `lab.local` - 192.168.56.10 |
| Hypervisor | Oracle VirtualBox (host-only network, 192.168.56.0/24) |
| Endpoint telemetry | Sysmon v15 (SwiftOnSecurity config, amended per lab), Windows Security / PowerShell channels, auditd |
| Status | Active - all agents reporting |

---

## Modules

| # | Module | Labs | Custom rules | Status |
|---|---|---|---|---|
| 01 | [Wazuh Installation](./01-Wazuh-Installation/) | - | - | Complete |
| 02 | [Agent Enrollment](./02-Agent-Enrollment/) | - | - | Complete |
| 03 | [Linux Detection Lab](./03-Linux-Detection-Lab/) | 9 | 100300-100307 | Complete |
| 04 | [Windows Detection Lab](./04-Windows-Detection-Lab/) | 9 | 100400-100411 | Labs 01-08 complete; Lab 09 capstone partial (AI-triage half verified in mock mode, live-LLM leg open) |
| 05 | [Sysmon](./05-Sysmon/) | 6 | 100500-100508 | Complete |
| 06 | [Active Directory](./06-Active-Directory/) | 6 | 100600-100604 | Complete - Labs 01-06 (100602 reserved, non-firing) |
| 07 | [Threat Hunting](./07-Threat-Hunting/) | 4 | 100701 | Complete - Labs 01-04 (Labs 01-03 are hunts, no rule) |
| 08 | [MITRE ATT&CK Mapping](./08-MITRE-Mapping/) | 2 | - | In progress - Labs 01-02 complete (inventory, tag audit; no rule) |
| 09 | [Incident Response](./09-Incident-Response/) | - | - | Planned |

Custom rules are namespaced `100300+`, one block per module. Nearly all fire on
live attack simulation. `100602` is deliberately published as a **reserved,
non-firing rule** next to the investigation that explains why (Module 06 Lab 04),
and Module 06 Lab 06A / Module 07 Labs 01-03 are rigorous **investigations that publish
no rule** - a Golden Ticket's true signal (a missing 4768) and a SIEM's retention
blind spot are both things a single stateless rule cannot express.

---

## What this lab found

These are findings from the labs, not claims about the tools:

- **A level-0 rule is a filter, not a no-op.** Wazuh evaluates first-match-wins, so a
  shipped rule that produces no alert silently consumes events your rule never sees.
  Two separate modules hit this - rule `92101` on Sysmon network events, rule `92651`
  on Kerberos service-ticket requests. Wazuh's own ruleset does it to itself elsewhere.
- **Coverage gaps in the shipped ruleset.** No DNS query rules at all. Egress rules that
  cover only a handful of internal ports. No rule matching event 4768. No coverage for
  shadow-copy deletion (T1490). None of these are documented as gaps anywhere.
- **Forwarded is not delivered.** Sysmon config-change and driver-unload events were
  written locally and never arrived at the manager, on a channel configured for
  forwarding. The shipped detection keys on a different, out-of-band signal that does.
- **Hardening that does not harden.** Forcing AES on an account does not protect it from
  AS-REP roasting - that setting governs a later Kerberos stage and the RC4 key persists.
  Documented as a gap in the coverage matrix, not claimed as a control.
- **Syntax validation is not reachability.** `wazuh-analysisd -t` confirms a rule parses.
  It says nothing about whether the rule can ever be reached. Only live fire does.

---

## Method

Every lab follows the same shape:

1. Objective, MITRE ATT&CK technique, and the environment it runs in
2. Attack simulation - the exact commands, run against a live endpoint
3. Raw telemetry - what the sensor actually emitted, before any rule
4. Detection logic - the rule, and why it keys on the field it keys on
5. Verification - the alert firing, plus a negative control where one exists
6. Tuning - the false positives found and how they were excluded
7. **Coverage limits** - what this detection cannot see

Step 7 is the one most writeups skip. A detection whose limits you cannot state is
not a control.

---

## Skills demonstrated

- Wazuh SIEM deployment, multi-agent enrollment, and manager troubleshooting
- Windows, Linux, and Active Directory attack simulation
- Custom detection rule authoring, chaining, and false-positive tuning
- Sysmon configuration auditing and telemetry gap analysis
- Kerberos, LDAP, and domain-controller event analysis
- MITRE ATT&CK mapping and coverage-matrix documentation

---

*Built, attacked, and documented by Priyanshu Tomar - ongoing project*
