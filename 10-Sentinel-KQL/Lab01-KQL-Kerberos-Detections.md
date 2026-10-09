# Lab 01 - Kerberos Detections in KQL: the Anti-Join Wazuh Could Not Express

## Objective
Rebuild three Active Directory detections from Modules 06-07 in **KQL**, the query
language of Microsoft Sentinel - including the one Wazuh could not express at all:
the Golden Ticket **anti-join** (a service ticket with no TGT behind it). Prove the
logic step by step against a controlled dataset, hit each known trap on purpose, and
end with a single query shaped like a Sentinel scheduled analytics rule.

**This lab uses SYNTHETIC data.** It proves query *logic*, not detection on live
telemetry. Live-fire against DC01 in a real Sentinel workspace is Lab 03+ (see Next).

## Framing
| Field | Value |
|---|---|
| Discipline | Detection engineering - porting stateful detections to KQL |
| ATT&CK | T1558.001 (Golden Ticket), T1558.003 (Kerberoasting), T1558.004 (AS-REP Roasting) |
| Engine | Kusto (Azure Data Explorer free cluster) - same KQL as Sentinel / Log Analytics |
| Data | 8 hand-built events in Sentinel's `SecurityEvent` column names, via `datatable()` |
| Cost / subscription | None - free cluster, personal Microsoft account, no Azure subscription |
| Wazuh lineage | 100600 (Kerberoast), 100601 (AS-REP), Module 06 Lab 06A + Module 07 Labs 02/04 (Golden Ticket anti-join) |

## Why this lab exists
Module 06 Lab 06A showed that a working Golden Ticket's 4769 is **field-identical** to
a legitimate one; the only signal is the **missing 4768**. Module 07 Lab 02 hunted it
manually, and Lab 04 concluded that Wazuh's stateless, first-match engine cannot turn
"an event that did not happen" into a rule. KQL can: `join kind=leftanti` returns the
rows on the left with **no match** on the right. This lab builds that rule.

## Environment
- **Azure Data Explorer free cluster**, signed in with a personal Microsoft account.
  No employer tenant (deliberate - lab attack data does not belong in a corporate
  sign-in trail), no Azure subscription.
- `datatable()` builds the `SecurityEvent` table inside the query, so nothing is
  ingested. A query still needs a database context to run in (the first run failed
  with *"Select a database to execute queries"* until one was selected).
- Microsoft's Log Analytics demo workspace was rejected: it requires a work/school
  sign-in. OTRF Security-Datasets was checked for real recordings and has **no**
  Golden Ticket, Kerberoasting or AS-REP datasets (only Rubeus `asktgt`, which
  produces 4768s - the opposite of what the anti-join hunts).

## The dataset - five stories in eight rows
| Time | EventID | User | Service | Enc | PreAuth | Source | Story |
|---|---|---|---|---|---|---|---|
| 10-06 23:00 | 4768 | night-shift | krbtgt | 0x12 | 2 | .21 | TGT obtained last night |
| 10-07 08:00 | 4768 | svc-sql | krbtgt | 0x12 | 2 | .20 | normal logon, step 1 |
| 08:01 | 4769 | svc-sql@LAB.LOCAL | DC01$ | 0x12 | - | .20 | normal logon, step 2 |
| 08:10 | 4769 | night-shift@LAB.LOCAL | DC01$ | 0x12 | - | .21 | **stale-TGT trap** (valid TGT, old 4768) |
| 09:30 | 4769 | it-admin@LAB.LOCAL | DC01$ | 0x12 | - | .30 | **Golden Ticket** - no 4768 ever |
| 09:58 | 4768 | jdoe | krbtgt | 0x12 | 2 | .30 | attacker's foothold account logs on |
| 10:00 | 4769 | jdoe@LAB.LOCAL | svc-sql | **0x17** | - | .30 | **Kerberoast** - RC4 ticket for a user SPN |
| 10:05 | 4768 | asrep-user | krbtgt | **0x17** | **0** | .30 | **AS-REP roast** - no pre-authentication |

`192.168.56.30` plays the attacker (Kali). In real data nothing labels it.

## Building the Golden Ticket rule - test matrix
Each step was run and its row count recorded before moving on.

| # | Query change | Predicted | Observed | Lesson |
|---|---|---|---|---|
| 1 | Read the table | 8 | **8** | dataset loaded |
| 2a | `leftanti` on raw `TargetUserName` | 4 | **4** | **normalization trap** - 4769 writes `user@REALM`, 4768 writes `user`; nothing matches, every ticket looks forged (100% FP) |
| 2b | Normalize both sides: `tolower(tostring(split(TargetUserName,"@")[0]))` | 1 | **1** (it-admin) | anti-join works |
| 2c | Same 4h window on both sides | 2 | **2** (night-shift, it-admin) | **stale-TGT FP** - night-shift's valid TGT predates the window |
| 2d | TGT side looks back `Window + 10h` (TGT lifetime) | 1 | **1** (it-admin) | lookback asymmetry fixes the FP |
| 3 | Kerberoast: 4769, `0x17`, service not ending `$`, not `krbtgt` | 1 | **1** (jdoe -> svc-sql) | same logic as Wazuh 100600 |
| 4 | AS-REP: 4768, `PreAuthType == "0"` | 1 | **1** (asrep-user) | same logic as Wazuh 100601 |
| 5 | All three combined with `union` (analytics-rule shape) | 3 | **3** | see below |

Final combined result (step 5):
```
TimeGenerated     Detection                                          Technique  User        ServiceName  IpAddress
10/7 09:30        Golden Ticket: service ticket with no TGT          T1558.001  it-admin    DC01$        192.168.56.30
10/7 10:00        Kerberoasting: RC4 ticket for user service account T1558.003  jdoe        svc-sql      192.168.56.30
10/7 10:05        AS-REP roasting: TGT without pre-auth              T1558.004  asrep-user  krbtgt       192.168.56.30
```
`svc-sql` (legitimate) and `night-shift` (stale TGT) correctly absent.

Full query: [`Lab01-KQL-Kerberos-Detections.kql`](Lab01-KQL-Kerberos-Detections.kql).

## The core logic
```kql
let TGTs = SecurityEvent
    | where TimeGenerated between ((Now - Window - TgtLifetime) .. Now)
    | where EventID == 4768
    | extend User = tolower(tostring(split(TargetUserName, "@")[0]))
    | distinct User;
SecurityEvent
| where TimeGenerated between ((Now - Window) .. Now)
| where EventID == 4769
| extend User = tolower(tostring(split(TargetUserName, "@")[0]))
| join kind=leftanti TGTs on User
```
- **Asymmetric windows.** Alert only on 4769s inside the rule window; search for
  4768s across window + TGT lifetime. Equal windows = stale-TGT false positives.
- **Normalize before joining.** Same identity, two spellings, across two event IDs.
- **`distinct`, not `project`,** on the lookup side - a user with many TGTs would
  otherwise multiply rows.

## Findings
1. **The anti-join is expressible and short in KQL** - one `join kind=leftanti` - where
   Wazuh's engine could not express it (Module 06 Lab 06A, Module 07 Lab 04).
2. **Both failure modes Module 07 found by hand reproduce in KQL**, and each has a
   concrete fix: normalization (2a->2b) and lookback asymmetry (2c->2d).
3. **The anti-join is per-user, not per-ticket - so it can be masked.** If `it-admin`
   had also authenticated legitimately (a real 4768) inside the lookback, step 2d
   returns **0 rows** and the forged use is invisible. This is the Module 07 Lab 04
   false negative, unchanged by the engine. Joining on user **and** source IP narrows
   it, but an attacker operating from the victim's own host still evades.
   **Conclusion: a triage lead, not a standalone alarm.**
4. **Correlation is the payoff of putting the three together.** All three hits share
   one source IP inside 35 minutes. Separately they are three medium alerts; grouped
   by source they are one intrusion. Sentinel's incident grouping (Lab 03+) is built
   for this.

## Known limitations (documented, not closed)
- **Synthetic data.** Proves the logic only. Real-telemetry behaviour is unproven
  until live-fire in Sentinel.
- **Schema not yet verified against real `SecurityEvent`.** Column names mirror
  Sentinel's, but whether fields like `PreAuthType` and `TicketEncryptionType` arrive
  as top-level columns (vs. inside `EventData` XML) via the Azure Monitor Agent must
  be confirmed on first ingest. Adjust with `parse_xml()` if not.
- **TGT renewal (4770) is not in the lookup side.** A TGT renewed beyond its 10h
  lifetime produces 4770, not a new 4768, so a long-running session would look
  orphaned. Next revision: `EventID in (4768, 4770)` on the TGT side.
- **Masking false negative** (finding 3) and **cross-DC blind spot**: with several
  DCs, the 4768 and the 4769 can land on different DCs - all DCs must be collected.
- **Fixed clock.** `Now` is pinned for the static dataset; a deployed rule uses
  `now()`, and Sentinel caps a scheduled rule's lookback (verify current limits when
  building it).

## Next (Module 10 roadmap)
- **Lab 03** - Azure subscription (pay-as-you-go; free trial already used), Sentinel workspace, budget alert; DC01
  onboarded via Azure Arc + Azure Monitor Agent, collection filtered to
  4624/4768/4769/4770 to keep ingestion near zero. Verify the real schema.
- **Lab 04** - deploy the three detections as scheduled analytics rules with entity
  mapping; live-fire from Kali (impacket `ticketer`, `GetUserSPNs`, `GetNPUsers`);
  confirm incidents and grouping; re-run the masking and stale-TGT cases on real data.

## Files
- [`Lab01-KQL-Kerberos-Detections.kql`](Lab01-KQL-Kerberos-Detections.kql) - dataset +
  combined detection query, runnable as-is in any Kusto engine.

## Evidence (screenshots)
One per test-matrix step above.

| Step | Shows |
|---|---|
| 1 | [The 8-row synthetic dataset](../11-Screenshots/10-Sentinel-KQL/Lab01-1-synthetic-dataset.png) |
| 2a | [Raw anti-join - 4 rows (normalization trap)](../11-Screenshots/10-Sentinel-KQL/Lab01-2-raw-antijoin-4-rows.png) |
| 2b | [Normalized - 1 row](../11-Screenshots/10-Sentinel-KQL/Lab01-3-normalized-1-row.png) |
| 2c | [Same window - 2 rows (stale-TGT FP)](../11-Screenshots/10-Sentinel-KQL/Lab01-4-same-window-2-rows.png) |
| 2d | [Asymmetric lookback - 1 row](../11-Screenshots/10-Sentinel-KQL/Lab01-5-asymmetric-lookback-1-row.png) |
| 5 | [Combined - 3 detections](../11-Screenshots/10-Sentinel-KQL/Lab01-6-combined-3-detections.png) |
