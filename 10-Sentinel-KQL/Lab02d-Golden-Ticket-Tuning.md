# Lab 02d - Tuning the Golden Ticket Rule Behind a Regression Gate

## Objective
Lab 02c shipped the Golden Ticket rule as v1.0.0 with logic deliberately unchanged from
Lab 01b: 3 alerts on the replayed history, 1 true positive, 2 false positives, and 1 forgery
missed. This lab treats that as a baseline and asks the tuning question properly: **which
change removes false positives without losing the true positive, and what does each change
cost?** Every candidate is replayed over the **whole history, every hourly run**, and diffed
against v1.0.0 before anything is committed.

**This is not a Sentinel deployment.** Same engine and data as Lab 02c: the ADX free cluster
and 298 real DC01 events with Wazuh receive times.

## Framing
| Field | Value |
|---|---|
| Discipline | Detection engineering - tuning, regression testing, rule versioning |
| ATT&CK | T1558.001 Golden Ticket |
| Rule | `Lab02c-rules/golden-ticket-tgs-without-tgt.yaml`, v1.0.0 -> **v1.1.0** |
| Ground truth | Two forged-ticket 4769s for svc-sql: 09-17 19:32:50 (Module 07 Lab 02) and 09-22 21:41:56 (Module 07 Lab 04). Every other alert is a false positive |
| Engine / cost | Azure Data Explorer free cluster / none |

## Method - replaying every hourly run at once
With an ingestion-time window (Lab 02c), every 4769 is evaluated by **exactly one** hourly
run: the run ending at the top of the hour after it was received. The whole history can
therefore be replayed without looping over runs:
1. give each 4769 its `RunAt`;
2. apply the rule as that run would see it - the TGT must already have been **received** by
   `RunAt`, and both sides must be inside `queryPeriod`.

This is an equivalent rewrite of the rule, not the verbatim query. It is checked two ways:
- **v1.0.0 sweep = the Lab 02c verbatim harness results**, row for row;
- **the chosen v1.1.0 is re-run through the verbatim harness** at the runs that changed.

Candidates (all from [`Lab02d-Golden-Ticket-Tuning.kql`](Lab02d-Golden-Ticket-Tuning.kql)):

| Variant | Change | Hypothesis |
|---|---|---|
| 1.0.0 | baseline | - |
| a | drop 4769s from `::1` (the DC requesting a ticket from itself) | removes the DC01$ FP |
| b | drop computer accounts (`$`) | same FP, wider blind spot |
| c | TGT lookback 10h -> 24h (`queryPeriod` 2d) | clears stale-TGT FPs |
| d | TGT lookback 10h -> 7d (max renewal; `queryPeriod` 8d) | clears more FPs, may mask the TP |

## Predictions (written before the first run)
| Variant | Predicted |
|---|---|
| 1.0.0 | 3 alerts: TP 09-17, FP DC01$ `::1` 09-15, FP svc-sql 09-22 21:32:55; Lab 04 forgery missed |
| a | 2: drops the DC01$ FP only |
| b | 2: same as a |
| c | unknown - depends on svc-sql's earlier TGTs |
| d | the TP gets masked (a longer lookback trades TPs for fewer FPs) |

## Results - hourly full-history sweep
| Variant | Alerts | Hourly runs that alerted | TP | FP | vs 1.0.0 |
|---|---|---|---|---|---|
| **1.0.0** | 3 | 3 | 1 | 2 | baseline - matches Lab 02c exactly |
| **a -loopback** | **2** | 2 | **1** | **1** | -DC01$ 09-15 FP; TP kept |
| b -machine$ | 2 | 2 | 1 | 1 | same rows as a |
| c 24h | 3 | 3 | 1 | 2 | **no change** |
| d 7d | 3 | 3 | 1 | 2 | **no change - prediction wrong** |

- No variant flags the Module 07 Lab 04 forgery: a legitimate 4768 for svc-sql 4 min 21 s
  earlier masks it. Per-user correlation cannot see through that (Lab 01b).
- **No duplicates.** Each alert appeared in exactly one hourly run. With ingestion-time
  windows this holds by construction, and the sweep confirms it.

## Why the longer lookbacks did nothing
The prediction for d assumed svc-sql had TGTs in the days before each ticket. The archive
says otherwise:

| svc-sql event | Count | Times |
|---|---|---|
| 4768 (TGT issued) | **1** | 09-22 21:37:35 (RC4) |
| 4769 (service ticket) | 4 | 09-17 19:32:50 (forged), 09-22 21:32:55, 21:37:36, 21:41:56 (forged) |

In 26 days of archived telemetry, svc-sql has **one** TGT event, and it comes *after* the
21:32:55 false positive. Whatever TGT that ticket was cut from was never collected. A
lookback window cannot find an event that is not in the data. **The 09-22 FP is a
collection gap, not a lookback problem**, so no lookback setting fixes it.

## Rejected: a "telemetry just resumed" guard
Both FPs look like data gaps, so the obvious fix is to suppress alerts in the first minutes
after the DC's event stream resumes. Measured, with a session starting after any gap of
more than 60 minutes in the Kerberos stream:

| Alert | Minutes after the stream resumed |
|---|---|
| FP DC01$ `::1` (09-15 15:56:14) | **0** - it is the first event after an 11.2-day gap (previous event 09-04 02:26) |
| **TP** forgery (09-17 19:32:50) | **2.8** |
| FP svc-sql (09-22 21:32:55) | 4.2 |
| Lab 04 forgery, missed (09-22 21:41:56) | 13 |

In this lab, attacks happen minutes after the DC is booted, so true and false positives are
indistinguishable by timing. Any guard long enough to drop the svc-sql FP also drops the
true positive. **Rejected.** In production a DC runs continuously and such a guard could be
cheap, but this lab cannot show that.

*(Analysis trap, recorded because it happened: the first run of the session query typed the
alert times to the second, while the real events carry sub-second fractions. The session
starting exactly at the DC01$ alert was excluded, and the query reported "15,930 minutes into a
session". Fixed by comparing with a 1-second margin.)*

## Decision - v1.1.0 = variant a
```kql
let tgs = SecurityEvent
    | where EventID == 4769
    | where ingestion_time() > ago(runWindow)
    | where tostring(IpAddress) != "::1"   // 1.1.0: DC's own loopback requests (Lab 02d)
    | extend AccountName = tolower(tostring(split(TargetUserName, "@")[0]));
```

**Why a and not b.** Both remove the same row. b does it by ignoring every computer account,
which blinds the rule to forged tickets **for** machine accounts - including a forged
DC computer-account ticket, a known route to DCSync. a ignores only requests the DC makes
to itself. **Accepted blind spot:** a forged ticket used *on* the domain controller, which
means the attacker already has code execution on the DC.

**Why not c or d.** Zero gain on this data. The cost is a longer query period and a wider
masking window, which makes it easier for a legitimate TGT to hide a forgery.

**What v1.1.0 does not fix:** the svc-sql collection-gap FP, and the masked Lab 04 forgery.
Both are data or correlation limits, not filter problems.

### Verbatim confirmation
The v1.1.0 YAML was rendered through the Lab 02c harness unchanged and run at the two runs
that matter:

| RunAt | v1.0.0 (Lab 02c) | v1.1.0 |
|---|---|---|
| 09-15 16:00 | DC01$ `::1` FP | **0 rows** |
| 09-17 20:00 | svc-sql TP | **svc-sql TP** (kept) |

The linter passes all four rule files after the version bump.

## Regression diff, v1.0.0 -> v1.1.0
| | v1.0.0 | v1.1.0 |
|---|---|---|
| Alerts on replayed history | 3 | 2 |
| True positives | 1 | 1 |
| False positives | 2 | 1 |
| Precision | 33% | 50% |
| Forgeries detected / in data | 1 / 2 | 1 / 2 |

## Findings
1. **The tuning lever was not where I predicted.** I expected lookback length to trade true
   positives for false positives. In this data it does nothing either way, because the
   user involved has one TGT event in 26 days. Measure the data before choosing the knob.
2. **The remaining FP is a collection problem.** A missing 4768 looks exactly like a forged
   ticket to an anti-join. The rule's precision depends on how complete the TGT stream is,
   which ties back to Lab 02b: events written before the agent starts are never collected.
3. **The narrowest exclusion wins on equal gain.** `::1` and `$` remove the same false
   positive. The difference is entirely in what each one blinds you to.
4. **A plausible guard was disproved by measurement.** "Ignore the first minutes after a
   gap" would have removed the TP too: the forgery came 2.8 minutes after the DC resumed.
5. **Full-history replay is cheap with ingestion windows.** One event belongs to one run, so
   every hourly run is replayed in a single query, with no duplicates.

## Known limitations
- **Two forgeries in the ground truth.** Precision and recall here are illustrations, not
  rates.
- **The sweep is a rewrite.** It matches the verbatim harness at every alerting run checked
  (Lab 02c and this lab), but was not checked at every one of the ~620 hourly runs (26 days).
- **Why the svc-sql TGT was not collected is unknown.** Candidates are a 4768 written
  before the agent was shipping events, or a renewal (4770, not collected). Neither was
  tested.
- **Blind-spot claim for `::1` is reasoned, not tested.** No forged ticket was replayed from
  the DC itself.
- Pre-09-15 data is sparse (the archive was not fully on); the 11.2-day gap reflects that.

## Files
- Rule (now v1.1.0): [`Lab02c-rules/golden-ticket-tgs-without-tgt.yaml`](Lab02c-rules/golden-ticket-tgs-without-tgt.yaml)
- Sweep, svc-sql history and session-gap queries: [`Lab02d-Golden-Ticket-Tuning.kql`](Lab02d-Golden-Ticket-Tuning.kql)
