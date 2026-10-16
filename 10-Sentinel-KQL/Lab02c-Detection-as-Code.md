# Lab 02c - Sentinel Analytics Rules as Code, Tested Without a Workspace

## Objective
Labs 01-02b produced four detections as loose KQL and Wazuh XML. In Sentinel, a detection
is shipped as an **analytics-rule YAML file**: the query plus its schedule, MITRE mapping,
entity mapping and alert formatting. Teams keep these files in git and test them before
import. This lab packages the four detections that way and tests them **without a Sentinel
workspace**:

1. a **linter** that catches the field and limit errors that break an import;
2. a **replay harness** that runs each rule's query verbatim, as one scheduled run at a
   chosen time, against the real DC01 events from Labs 01b/02;
3. a **schema test**: the same rule must give the same answer whether the Kerberos fields
   are table columns or only exist inside the raw `EventData` XML.

**This is not a Sentinel deployment.** The rules were never imported into a workspace.
The claim is "authored and validated in ADX against replayed telemetry".

## Framing
| Field | Value |
|---|---|
| Discipline | Detection engineering - detection-as-code, rule testing |
| ATT&CK | T1558.003 Kerberoasting, T1558.004 AS-REP Roasting, T1558.001 Golden Ticket, T1070.006 (nearest fit for a clock change, see Lab 02b) |
| Data | 298 real DC01 Kerberos events (4768/4769) + Wazuh receive time (Labs 01b/02); event 4616 **reconstructed** from Lab 02b values plus labelled synthetic rows |
| Engine | Azure Data Explorer free cluster (same KQL engine as Sentinel) |
| Cost / subscription | None |

## The rules
All four are in [`Lab02c-rules/`](Lab02c-rules/), in the Azure-Sentinel repository's
YAML template format.

| Rule | Event | Logic | Severity | Ported from |
|---|---|---|---|---|
| `kerberoasting-rc4-user-spn` | 4769 | RC4 (`0x17`) ticket for a non-`$`, non-krbtgt service | Medium | Wazuh 100600, Lab 01/01b |
| `asrep-roasting-no-preauth` | 4768 | `PreAuthType` 0 | Medium | Wazuh 100601, Lab 01 |
| `golden-ticket-tgs-without-tgt` | 4769 vs 4768 | `leftouter` join + "no TGT for this user in 10 h" | Medium (triage lead) | Module 07 Lab 02/04, Lab 01b |
| `dc-clock-change-unexpected-process` | 4616 | process not VBoxService/svchost; High if the host is on the `DomainControllers` watchlist | High / Medium (dynamic) | Wazuh 101000/101001, Lab 02b |

### Design decisions carried over from the earlier labs
- **New events are picked by `ingestion_time()`, not `TimeGenerated`.** Every rule runs
  hourly (`queryFrequency: 1h`) and treats an event as new if it *arrived* in the last
  hour. `queryPeriod: 1d` bounds `TimeGenerated`. This is because DC01's clock lies after
  boot (Lab 02: 21/298 events mis-dated), and a clock-change attack stamps its own 4616
  with the forged time (Lab 02b). An event-time window misses both.
- **Read the field as a column, or from `EventData` if the column is missing or empty.**
  It is not verified whether Sentinel's `SecurityEvent` table stores `TicketEncryptionType`,
  `PreAuthType` and `ProcessName` as populated columns for these events. The rules use
  `column_ifexists()` and fall back to a regex on `EventData`, so one file works on both layouts.
- **One `Set-Date` is one alert.** Lab 02b got two 4616 events (and two Wazuh alerts) per
  clock change. The clock-change rule groups by host, user and process in 5-minute
  ingestion bins.
- **DC scoping is a watchlist.** Wazuh used a CDB list (`etc/lists/domain-controllers`);
  the Sentinel equivalent is `_GetWatchlist('DomainControllers')`. The test harness
  replaces it with a stub.
- **The Golden Ticket rule is unchanged from Lab 01b on purpose.** Lab 01b's batch result is the
  regression baseline: the scheduled rule must reproduce it, including its known false
  positives and its missed forgery. Tuning is a separate change.

## Part 1 - The linter
[`Lab02c-lint.ps1`](Lab02c-lint.ps1) is a line-based PowerShell 5.1 checker (no YAML
parser available on the host). It checks:
- required keys;
- GUID `id`, with no duplicates across files;
- severity, kind, version and trigger values;
- `queryFrequency`/`queryPeriod` within 5m-14d, with `queryPeriod >= queryFrequency`;
- valid tactics, and technique IDs in `Txxxx[.yyy]` form;
- query length within Sentinel's 10,000-character limit;
- entity and custom-detail limits;
- **every column named in entity mappings, custom details or the alert-name template
  appears in the query.**

A house-rule warning flags any query that never uses `ingestion_time()`.

| # | Test | Expected | Observed |
|---|---|---|---|
| L1 | 4 rule files | 4 PASS | 4 PASS |
| L2 | Entity column `SrcIp` changed to `SrcIP` | FAIL | **PASS - linter bug** |
| L3 | Same, after the fix | FAIL | FAIL: `column 'SrcIP' ... never appears in the query` |
| L4 | Tactic `CredentialAccess` changed to `credentialaccess` | FAIL | FAIL: `unknown tactic` |

**Finding L2.** The first version used PowerShell's `-match`/`-notin`, which ignore case.
KQL column names are case-sensitive, so a mapping to `SrcIP` would bind to nothing in
Sentinel, but the linter passed it. The fix is case-sensitive operators (`-cnotmatch`,
`-cnotin`, `-cne`). Only the deliberately broken input caught this: a linter that has
never been shown a bad file has not been tested.

## Part 2 - The replay harness
[`Lab02c-render.ps1`](Lab02c-render.ps1) takes a rule file, a shim and a run time, and
prints a query for ADX:
- The rule's `query:` block is copied **verbatim**. The only edit is
  `ingestion_time()` -> `_Ingest`.
- A **shim** from [`Lab02c-shims/`](Lab02c-shims/) defines `SecurityEvent` from the ADX
  tables. It shifts every timestamp by `now() - RunAt`, so the rule's `ago()` lands on
  `RunAt`. It sets `_Ingest` to the Wazuh manager receive time and hides every row not yet
  received at `RunAt` or outside `queryPeriod`.
- The result gets a `RealEventTime` column so the shifted times can be read.

ADX cannot fake `ingestion_time()` (it returns the date the rows were loaded) or `now()`.
The time shift and the `_Ingest` column are how a single run is replayed.

### Part A - expected results
Lab 01b's batch logic, with the hourly run that should raise each hit. A run ending at
`RunAt` covers events received in the hour before it.

| Rule | Event time (UTC) | Received | RunAt | User -> service |
|---|---|---|---|---|
| Kerberoast | 2026-08-28 21:48:34 | 21:48:58 | 22:00 | jdoe -> svc-sql |
| Golden Ticket | 2026-09-15 15:56:14 | 15:59:41 | 16:00 | DC01$ -> DC01$ (`::1`) |
| Golden Ticket | 2026-09-17 19:32:50 | 19:33:48 | 20:00 | svc-sql -> DC01$ |
| Golden Ticket | 2026-09-22 21:32:55 | 21:33:41 | 22:00 | svc-sql -> DC01$ |
| Golden Ticket (missed) | 2026-09-22 21:41:56 | 21:42:02 | 22:00 | svc-sql (Module 07 Lab 04 forgery) |

### Harness runs
| # | Rule | Shim | RunAt (UTC) | Expected | Observed | Result |
|---|---|---|---|---|---|---|
| 1 | Kerberoast | columns | 08-28 22:00 | jdoe -> svc-sql, `0x17`, IP `192.168.56.80` | same, `::ffff:` stripped | Pass |
| 2 | Kerberoast | **EventData only** | 08-28 22:00 | identical to run 1 | identical | **Pass - fallback works** |
| 3 | Golden Ticket | columns | 09-15 16:00 | DC01$ (archive-start FP) | DC01$, `::1` | Pass |
| 4 | Golden Ticket | columns | 09-17 20:00 | svc-sql forgery (TP) | svc-sql, `192.168.56.80` | Pass |
| 5 | Golden Ticket | columns | 09-22 22:00 | 21:32:55 stale-TGT FP only; 21:41:56 forgery **not** flagged | exactly that, 1 row | Pass (known FN reproduced) |
| 6 | AS-REP | columns + 1 synthetic row | 09-10 13:00 | the synthetic row | `synthetic-asrep`, PreAuth 0 | Pass (synthetic) |
| 7 | AS-REP | columns (real only) | 09-10 13:00 | 0 rows | 0 rows | Pass (negative) |
| 8 | Clock change | reconstructed 4616 | 10-15 17:00 | DC01 **High**, 1 alert for 2 events, 180 s; ENDPOINT01 **Medium**; VBoxService and svchost silent | DC01 High, `Changes=2`, `MaxShiftSec=180.0244`; ENDPOINT01 Medium (alice, 300 s); 2 rows total | Pass |
| 9 | Direct column reference under the EventData layout | - | - | fails loudly | `Semantic error: ... failed to resolve ... 'TicketEncryptionType'` | Confirms the fallback is needed |

Run 9 matters for the design. If the column is **absent**, a plain column reference does
not silently return nothing; the rule fails to save. The quiet failure is a column that
**exists but is empty** for these events. That is the case the `isempty()` fallback is for.

## Part 3 - Event-time vs. ingestion-time windows (all 298 events)
Each event lands in exactly one hourly window of each kind:
- **A (event time):** Sentinel runs about 5 minutes after the window closes, so an event is
  seen only if it arrived by then. This is Lab 02's 1h/1h configuration.
- **B (this lab's rules):** an event is seen if it is less than 1 day old (`queryPeriod`)
  when it arrives.

| Events | Missed by A | Missed by B | A misses that are not DC01$ |
|---|---|---|---|
| 298 | **21** | **0** | 0 |

The 21 are Lab 02's boot-time mis-dated events. All belong to the DC's machine account,
so no attack event in this dataset was late. **Caveat:** B's zero is close to true by
construction. An ingestion window cannot miss an event except through the `queryPeriod`
bound, and the worst mis-dating here was about 26 minutes. The result shows that a
1-day bound is enough for this data. It does not show that B is free: a wider
`queryPeriod` costs query time, and B depends on `ingestion_time()` being enabled on the
table (the default in Log Analytics).

## Findings
1. **The packaging did not change the answers.** The scheduled, replayed rules reproduced
   Lab 01b exactly (1 Kerberoast TP; Golden Ticket 1 TP / 2 FP / 1 masked FN), and
   each hit appeared in the run predicted from its receive time.
2. **Ingestion-time windowing closes Lab 02's gap for free.** It catches 21 of 21
   mis-dated events that an event-time schedule drops, with no change to rule logic.
3. **The linter was wrong until it was given a bad file.** Case-insensitive matching let a
   broken entity mapping through. Negative tests apply to tooling too, not only to rules.
4. **Schema uncertainty can be coded around.** `column_ifexists()` plus an `EventData`
   fallback gave identical results on both layouts. A plain column reference fails to compile.
5. **A rule file can fix an operational nuisance found in another lab.** Lab 02b's
   two-alerts-per-change becomes one alert through grouping. This is shown on
   reconstructed data, not live.

## Known limitations
- **No Sentinel import.** The YAML has not been accepted by a real workspace or by
  Microsoft's own template validator. The linter is a pre-check.
- **`SecurityEvent` layout unverified** for `TicketEncryptionType`, `PreAuthType`,
  `ProcessName` and `ServiceName` on AMA-collected 4768/4769/4616. The fallback covers the
  first three; `ServiceName`, `TargetUserName` and `IpAddress` are assumed to be columns.
- **Clock-change data is reconstructed.** Rows 1-2 use Lab 02b's live-fire values (the
  process path is assumed standard). Rows 3-5 are synthetic. The two boot-time
  VBoxService steps from Lab 02b are left out because they were never collected, which
  is Lab 02b's finding.
- **AS-REP has no real positive.** The Wazuh archive holds no `PreAuthType` 0 events.
- **Single-run replay.** Each harness run is one scheduled run at a chosen time, not a
  sweep of every hour. Part 3 covers the whole dataset, but only for the window logic.
- **5-minute grouping bins can split a burst** that crosses a bin boundary into two
  alerts. Not tested.
- **Watchlist behaviour is a stub.**

## Files
- Rules: [`Lab02c-rules/`](Lab02c-rules/)
- Shims: [`Lab02c-shims/`](Lab02c-shims/)
- Tools: [`Lab02c-lint.ps1`](Lab02c-lint.ps1), [`Lab02c-render.ps1`](Lab02c-render.ps1)
- Non-harness queries (Part A, Part 3): [`Lab02c-Detection-as-Code.kql`](Lab02c-Detection-as-Code.kql)
