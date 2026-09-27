# Lab 04 - Regression Test: Do the Detections Still Work Today?

## Objective
Every rule in this repository was verified once, on the day its lab was written.
Lab 03 showed that is not enough: rule 100401 was correct when tested, then
silently turned into a 98% false-positive generator when Module 06 added a domain
controller. This lab asks whether the detections still hold **now**, against the
current manager and environment, in three parts:

- **Part A - change-driven regression.** Re-verify, live, the one rule whose match
  logic changed in this module (100401).
- **Part B - detection health check.** Use every custom rule's alert history to
  find rules that have drifted - gone noisy, or have no evidence at all.
- **Part C - per-family live re-fire.** Re-run one attack per detection family.

**No new rule.** One rule fixed in Lab 03 is verified here; two new regressions are
found and carried forward.

## Framing
| Field | Value |
|---|---|
| Discipline | Detection engineering - regression testing and detection health monitoring |
| Part A target | 100401 (privileged logon, 4672) - fix deployed 2026-09-24 20:51 UTC |
| Part B data | `wazuh-alerts-*`, weekly histogram per custom rule, 2026-07-24 -> 2026-09-27 |
| Output | [`rule-health.csv`](rule-health.csv), updated [`detection-inventory.csv`](detection-inventory.csv) and layers |
| Rule produced | None |

## Environment
| Component | Details |
|---|---|
| Manager | Wazuh 4.14.6 all-in-one, Ubuntu, 192.168.56.79, 4 vCPU / 4 GB |
| Domain controller | DC01, Windows Server 2022, `lab.local`, agent 004, 2 GB |
| Archiving | **Off** since 2026-09-24 - only rule-matched alerts are indexed |
| Host | 15.3 GB laptop; ~5.6 GB free after a reboot with background apps closed |

## Part A - 100401 live re-verification

The Lab 03 fix added `^DWM-\d+$`, `^UMFD-\d+$` and `\$$` to the rule's negated
`subjectUserName` list. An offline replay was not possible (`wazuh-logtest` does
not route these EventChannel events to the Windows rule chain - see Lab 03), so the
test had to be live.

### Test 1 - negative: machine-account logons must not alert
DC01 was booted and generated its own logons. With archiving off, raw 4672 events
cannot be counted in the index, so the proof uses their pair: every privileged
`DC01$` logon also produces a successful-logon 4624, which still alerts as shipped
rule 60106.

```bash
# 60106 logons on DC01 since the fix, by account; and 100401 over the same window
"query": {"bool": {"filter": [{"term": {"rule.id": "60106"}}, {"term": {"agent.name": "DC01"}},
          {"range": {"timestamp": {"gte": "2026-09-24T20:51:00Z"}}}]}},
"aggs":  {"u": {"terms": {"field": "data.win.eventdata.targetUserName"}}}
```

### Test 2 - positive: a human admin logon must still alert
`LAB\Administrator` logged in at the DC01 console.

### Result
| Since the fix (2026-09-24 20:51 UTC) | Logons (60106) | 100401 alerts | Verdict |
|---|---|---|---|
| `DC01$` / `DC01$@LAB.LOCAL` | 75 | **0** | PASS |
| `LAB\Administrator` | 1 | **1** (level 8, event 2026-09-27 20:46:03 UTC) | PASS |

Before the fix those 75 machine logons would have produced ~75 false alerts; the
human logon still fires. **100401 is restored to `fired`.**

### What nearly invalidated the test
The first positive attempt showed no alert for twelve minutes. A console
screenshot showed why: DC01's lock-screen clock was frozen - the VM had stalled
under host memory pressure (Windows paging ~3,100 pages/s) before the logon event
was shipped. Saving the VM state, freeing host memory and resuming it delivered the
queued event. Had the silence been read as a result, a working rule would have
been recorded as broken. **A negative result needs proof that the pipeline was
alive when the event should have arrived.**

## Part B - detection health check (all custom rules)

One aggregation returns, for every custom rule, its total alerts, first and last
alert, and a weekly histogram - exported to [`rule-health.csv`](rule-health.csv).

```bash
"query": {"range": {"rule.id": {"gte": "100300", "lte": "100799"}}},
"aggs": {"r": {"terms": {"field": "rule.id", "size": 100},
         "aggs": {"first": {"min": {"field": "timestamp"}}, "last": {"max": {"field": "timestamp"}},
                  "w": {"date_histogram": {"field": "timestamp", "calendar_interval": "week", "min_doc_count": 1}}}}}
```

(`rule.id` is a keyword, so the range is lexicographic and also returned shipped
rule `1004` - excluded.)

**32 of the 33 deployed custom rules have alerts on record. Two patterns stand out.**

### Finding 1 - a second noise regression (100502)
| Week | 08-10 | 08-17 | 08-24 | 09-14 | 09-21 |
|---|---|---|---|---|---|
| 100502 alerts | 6 | 397 | 46 | 253 | 416 |

In its lab week, 100502 (unsigned DLL load, Sysmon EID 7) fired on the test DLL and
a Microsoft Store false positive that was tuned out. Since September the volume
comes from routine Windows .NET housekeeping:

| Loading image | Alerts since 2026-09-01 |
|---|---|
| `mscorsvw.exe` (64- and 32-bit) - .NET native-image generation | 297 |
| `svchost.exe` loading `SSShim.dll` | 168 |
| `powershell.exe` (64- and 32-bit) loading `.ni.dll` native images | 171 |

The rule keys on `signed=false`, and .NET native images (`*.ni.dll`) generated
locally by `mscorsvw` are **unsigned by design**. The lab-week environment had not
yet run a .NET servicing cycle. Like 100401, the rule was right when tested and
drifted with the environment - this time a Windows update, not a new server.
**Status: `fired-with-limit`.** Tuning (exclude `mscorsvw.exe` as the loader and
the `NativeImages_*` path, then re-fire the Lab 04 side-load) needs the Windows
endpoint and is carried forward.

### Finding 2 - a verified rule with no evidence (100307)
100307 (direct root login via `sshd`/`login`) is the only deployed custom rule with
**zero** alerts. The Module 03 Lab 09 writeup states it fired and quotes an alert.
The search went beyond the index:

| Source | 100307 alerts |
|---|---|
| `wazuh-alerts-*` index, all dates | 0 |
| On-disk `ossec-alerts-*.json.gz`, every day since July | 0 (one false match: an audit serial number `...:100307)` inside an 80792 alert) |
| Sibling 100306 on the Lab 09 day (2026-07-27) | 3 - present in both index and disk |

The index and disk agree for other days (e.g. 2026-08-30: 37,835 vs 37,835), so
this is not an indexing gap. **No record on this manager supports the claim that
100307 fired.** The manager's `sshd` is now at Ubuntu's default
`PermitRootLogin prohibit-password`, so the Lab 09 procedure cannot be repeated as
written. **Status: new value `unverified`.** Coverage of T1078.003 is unaffected -
100306 proves it.

### What silence does and does not mean
Most attack rules fired only in their lab week and never again. For a rule that
detects an attack, silence is the **expected** state and says nothing about whether
it still works. Part B can catch rules that get **louder** (100401, 100502) and rules
with **no evidence at all** (100307). It cannot catch a rule that has quietly
stopped matching - only a scheduled re-fire can. That is why Part C exists.

## Part C - per-family live re-fire (not run)

| Family | Rule | Test | Needs |
|---|---|---|---|
| AD | 100601 AS-REP roast | `GetNPUsers -no-pass` | DC01 + Kali |
| AD | 100600 Kerberoast | `GetUserSPNs -request` | DC01 + Kali |
| AD | 100603 DCSync | `secretsdump -just-dc-user krbtgt` | DC01 + Kali |
| Linux | 100301 recon burst | `whoami; id; uname -a; ps aux` | Kali |
| Windows | 100400 brute force | 6 failed `runas` | Windows |
| Sysmon | 100503 DNS tunnel | 45-char random labels | Windows |
| Windows | 100411 shadow-copy deletion | `vssadmin delete shadows` | Windows |
| Linux | 100307 direct root login | key-based `ssh root@localhost` | manager |

**Not executed.** Running DC01 alongside the manager already exhausted host memory
(Part A); DC01 + Kali needs ~3.5 GB and the Windows endpoint ~3 GB, against ~2.9 GB
free. These are recorded as the open regression matrix rather than run on a host
that would stall mid-test and produce the false negatives Part A nearly recorded.

## Result - inventory after Lab 04

| Detection | Before | After | Why |
|---|---|---|---|
| 100401 | `fired-with-limit` | **`fired`** | Fix re-verified live (Part A) |
| 100502 | `fired` | **`fired-with-limit`** | .NET native-image noise regression |
| 100307 | `fired` | **`unverified`** | No alert on record anywhere |

| Evidence status (42 detections) | Count |
|---|---|
| `fired` | 28 |
| `fired-with-limit` | 9 |
| `unverified` | 1 |
| `hunt-only` | 2 |
| `not-deployed` | 2 |

Technique coverage is unchanged at **32 proven** (26 `fired`, 6 `fired-with-limit`):
T1078 moved up with 100401's re-verification; T1574.002 moved down with 100502.

[`build-layers.sh`](build-layers.sh) gained the `unverified` status (orange in the
evidence layer). It also had a latent bug: its carriage-return strip had been
flattened by shell escaping into `sub(/$/, "")`, a no-op that only worked because
the input CSV had been cleaned by hand. Fixed to `sub(/\r$/, "")`.

## Key findings
- **100401's fix holds live:** 75 machine logons, 0 alerts; the human admin logon
  still fires.
- **A second rule drifted noisy without warning** - 100502, from locally generated,
  unsigned-by-design .NET native images. Two of 33 rules degraded between their lab
  and today; neither raised any signal about itself.
- **A rule documented as verified has no evidence anywhere** (100307). Lab writeups
  are claims; the alert record is evidence, and here they disagree.
- **A silent test is not a failed test** until the pipeline is proven alive - DC01
  froze before shipping the event the test depended on.
- **Alert history catches rules that get louder, not rules that go quiet.** Only
  scheduled re-fires close that gap.

## Carried forward
- Tune 100502 (loader `mscorsvw.exe`, `NativeImages_*` path) and re-fire the side-load.
- Re-fire 100307 with a root key, or retire the claim in Module 03 Lab 09.
- Run the Part C matrix when host memory allows (one family per session).

## Result
100401's regression fix is verified live. The health check across all 33 custom
rules found a second noise regression (100502) and one rule with no evidence
(100307); the inventory, layers and scoring script are updated to say so. The
per-family re-fire matrix is defined but not run - host memory cannot support it
without stalling the tests. **No custom rule.** Next: **Lab 05 - threat-informed gap
analysis**.
