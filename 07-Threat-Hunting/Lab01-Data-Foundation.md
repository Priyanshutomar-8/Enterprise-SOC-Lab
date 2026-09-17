# Lab 01 - Data Foundation: What Can You Actually Hunt?

## Objective
Threat hunting searches stored telemetry for attacker activity that no rule
alerted on. That only works if the telemetry was **kept and made searchable** in
the first place. This lab audits what a default Wazuh install actually retains,
finds the blind spot, fixes it, and proves the fix - before any hunt is written.

This is an **investigation and setup lab - no custom rule**. Modules 04-06 asked
"can this one event be detected?" Module 07 asks "what can a query over stored
data find that a single-event rule cannot?" Lab 06A already showed the motivating
case: a Golden Ticket is field-identical to a legitimate ticket, and its real
signal - a *missing* 4768 - is something Wazuh's stateless, first-match engine
cannot express. A hunt over stored events can. But only if the events are stored.

## Framing
| Field | Value |
|---|---|
| Discipline | Threat Hunting - hypothesis-driven search over historical telemetry |
| Data source concern | Log completeness / retention (MITRE ATT&CK Data Sources: the pre-condition for detection engineering, not a technique) |
| What is audited | `wazuh-alerts-*` vs `wazuh-archives-*` indices; on-disk archive files; index retention; query engine |
| Rule produced | None - this lab is the data foundation the rest of Module 07 stands on |
| Reference | https://attack.mitre.org/datasources/ |

## Environment
| Component | Details |
|---|---|
| Manager | Wazuh 4.14.6 all-in-one, Ubuntu, 192.168.56.79 (indexer + dashboard + manager) |
| Domain controller | `DC01` (Windows Server 2022), `lab.local`, 192.168.56.10, agent **004** |
| Attacker / generator | Kali + impacket, 192.168.56.80, agent **001** |
| Sysmon endpoint | `windows` agent **002** - parked (off) for this lab to keep event volume low |
| Access | SSH from host to manager; indexer queried by client certificate (`admin.pem`) or `admin` user; dashboard from host browser at https://192.168.56.79 |

## The blind spot

A default Wazuh install indexes only **alerts** - events that matched a rule at
**level 3 or higher**. Everything a rule scored at level 0 (the vast majority of
raw telemetry) is evaluated and discarded. The archive path - a full copy of
*every* decoded event - exists but ships **off**.

Two switches gate it, and both were `no`/`false` out of the box:

| Switch | File | Meaning |
|---|---|---|
| `<logall_json>` | `/var/ossec/etc/ossec.conf` | Manager writes every event to `archives.json` on disk |
| `archives: enabled` | `/etc/filebeat/filebeat.yml` (line 26) | Filebeat ships that file into the `wazuh-archives-*` index |

With both off, a level-0 event is **nowhere**: not in the alerts index, not on
disk, not searchable. The AS-REP roast telemetry from Module 06 Lab 03, the
normal 4768/4769 baseline a Golden Ticket hunt needs - all invisible.

### Evidence 1 - the index inventory
`_cat/indices/wazuh-*` returned only `wazuh-alerts-4.x-<date>` buckets (plus
`monitoring`, `statistics`, `states-inventory` - none of which are security
events). **No `wazuh-archives-*` bucket existed at all.** Alerts were retained
from 2026-07-24 onward with no rotation (effectively "keep forever" at lab scale).

### Evidence 2 - missing days are a blind spot before detection is
Seven calendar gaps in the alerts buckets (Aug 2, 16, 23, 29; Sep 7, 12, 13) -
days the lab was off. A hunt over "last 30 days" that returns nothing has to
account for days that were **never recorded**. The manager also archived its own
kernel log line `soft lockup - CPU#3 stuck for 29058s` - an **8-hour window on
Sep 4** during which the SIEM analysed nothing. A hunter who searches that window,
finds nothing, and calls it clean has reached the wrong conclusion.

## Enabling and indexing archives

Only DC01 (004) and Kali (001) were reporting; the Sysmon Windows agent (002) was
parked. That low event volume is what makes a manager restart safe here - the
documented starvation risk needs the Sysmon agent forwarding. Windows stayed
parked for the whole lab.

```bash
# Switch 1 - manager writes every event to disk (back up first)
sudo cp -p /var/ossec/etc/ossec.conf /var/ossec/etc/ossec.conf.bak-m07l01
sudo sed -i 's|<logall_json>no</logall_json>|<logall_json>yes</logall_json>|' /var/ossec/etc/ossec.conf
# left plain <logall> as no - it writes a second, text-format copy and wastes disk

# Switch 2 - Filebeat ships the archive file to the indexer (line 26 only)
sudo cp -p /etc/filebeat/filebeat.yml /etc/filebeat/filebeat.yml.bak-m07l01
sudo sed -i '26s/enabled: false/enabled: true/' /etc/filebeat/filebeat.yml
sudo filebeat test config      # -> Config OK

# Park nothing new; restart with load check
cat /proc/loadavg               # first figure must be < 2 before restarting
sudo systemctl restart wazuh-manager
sudo systemctl restart filebeat
sudo filebeat test output       # -> talk to server... OK
```

Within two minutes a `wazuh-archives-4.x-2026.09.15` bucket appeared and began
filling. The restart was clean (load 0.06 -> 0.57), because only the low-volume
agents were active.

### Finding - enabling archives does NOT backfill the past
The live `archives.json` still held ~17 MB of events from Sep 4, and **none of it
was indexed**. Cause: `archives.json` is a **hard link** to the day's real file
(link count `2`, same inode as `ossec-archive-15.json`). At restart the manager
repointed the "today" link to a fresh file and dropped the stale Sep 4 link;
Filebeat only ever watched the `archives.json` name, so it never read the old
events. **Past days survive only as compressed `.json.gz` on disk, searchable with
`zcat | grep`, never in the dashboard.** Archiving is prospective only - a hunter
who turns it on today cannot hunt yesterday.

This is why the Module 06 DCSync (Lab 05) and Golden Ticket (Lab 06) telemetry is
unhuntable: `archives.json` had not been written since **Sep 4 19:41**, so both
labs ran with archiving off. Lab 02 must re-run the attack with archives on.

## Controlled proof - a successful ticket request lands in archives, not alerts

Hunting off inference is weak; the point was made reproducible. Two events were
created deliberately from Kali (known IP 192.168.56.80) and traced to their index:

| Event created | Event ID | Level | In `wazuh-alerts`? | In `wazuh-archives`? |
|---|---|---|---|---|
| Failed Kerberos auth (wrong password) | **4771**, status `0x18` | 5 | **Yes** (rule 60104) | Yes |
| Successful TGT request (`impacket-getTGT`) | **4768** | **0** | **No** | **Yes** |

The successful 4768 (`targetUserName: Administrator`, `ipAddress:
::ffff:192.168.56.80`, no `rule` field) was present in archives and absent from
alerts. The failed attempt - noisier, less dangerous - **did** alert at level 5.

### The asymmetry that defines the module
**Wazuh alerts on failed Kerberos auth but is silent on successful ticket
requests.** A Golden Ticket, a Kerberoast, an AS-REP roast all produce
*successful* tickets. So the events a hunter most needs are exactly the ones that
never became alerts, while the noisy failures are well covered. The hunt target
*is* the blind spot.

### Anti-join lookback constraint (sets up Lab 02)
Stack-counting DC01's own event IDs showed a normal 4769 with **no preceding
4768** in the same window - completely legitimate, because a TGT is valid for
**10 hours** and that user's 4768 predated archiving. Consequence for the Golden
Ticket hunt: an anti-join's lookback window **must exceed the ticket lifetime**,
or every normal user looks forged. Archives must run at least 10 hours before the
Lab 02 hunt is meaningful.

## How big is the blind spot

Two independent measurements agreed:

| Measure | Alerted (has rule) | Not alerted (blind) | Blind share |
|---|---|---|---|
| Today's DC events, by `rule.id` existence | 722 | 1,675 | **~70%** |
| All events, last 24h (`_count`) | 9,993 (`wazuh-alerts-*`) | - | - |
| All events, last 24h total | - | 30,710 (`wazuh-archives-*`) | **~67%** |

Only ~⅓ of telemetry ever reached the default searchable view - and that third is
**inflated** by Kali's `80792` "Audit: Command" alerts (level 3, auditd execve
noise). Strip that noise and the blind share is larger still.

Confirmed mechanically: an archive event carries a `rule` field **only** when it
became an alert (722 with-rule vs 709 alerts in the same window). The ~1,675
rule-less archive events are the pool every Module 07 hunt searches.

### Volume baseline (for Lab 03)
Idle, with DC01 + Kali + manager only: **~57-60 events/min (~82k/day, ~150 MB/day,
~100 KB/min on disk)**. Note this baseline was itself invisible before archiving -
the "DC is ~1 event/min" figure from earlier modules only counted events that
*alerted*. When the Sysmon agent (002) rejoins in Lab 03, volume is re-measured
against this line; the delta is Sysmon's disk cost.

## Query capability - present at the engine, hidden at the UI

The Wazuh dashboard ships trimmed: no **Query Workbench** menu app, and **Dev
Tools** is not surfaced in the menu (reachable directly at
`/app/dev_tools`). But the query engine underneath is fully installed:

- `opensearch-sql` plugin present; both `_plugins/_sql` and `_plugins/_ppl` REST
  endpoints return `200` with results.
- PPL does the core hunting primitive natively:

```
POST _plugins/_ppl
{ "query": "source=wazuh-archives-* | stats count() by rule.level" }

  rule.level = null -> 42,693     # archives-only, no rule ever matched (the blind pool)
  rule.level = 3    -> 16,944     # the Kali audit noise
  rule.level = 5    -> 37
  ...
```

**Design decision for Lab 03:** `stats count() by <field>` is exactly the
stack-counting primitive needed for rare-event and beaconing hunts, so hunts can
run in PPL via Dev Tools or the API - **no external export/Python required.**

Also created: the `wazuh-archives-*` **index pattern** in the dashboard (time
field `timestamp`). A fresh install ships only the `wazuh-alerts-*` pattern, so
even with archiving on, the data is invisible in Discover until a hunter creates
this pattern. One more silent gate between "I enabled archives" and "I can hunt."

## Takeaway

> **In plain terms:** the SIEM was only saving and analysing logs that tripped an
> existing rule. An attacker using a stealthy technique that didn't trip a
> specific alarm was effectively invisible. Activating and indexing the raw log
> archives restores the full picture - the events that never alerted can now be
> hunted, and past activity investigated with full context.

Defensible one-liner for interview: *"My SIEM only kept what a rule already cared
about, so attacks that don't trip a rule were invisible until I turned on and
indexed archives - and even then, only prospectively."*

## Key findings
- **~67-70% of telemetry never reached the default searchable index**, measured
  two independent ways.
- **Failed auth alerts; successful ticket requests do not.** The hunt target is
  the blind spot.
- **Archiving is prospective only** - a hard-link rotation means enabling it does
  not backfill; past days live only as on-disk `.json.gz`.
- **Retention/completeness is a hunting precondition** - 7 missing days plus a
  recorded 8-hour analysis outage are false-negative traps before any rule exists.
- **Anti-join lookback must exceed the 10h TGT lifetime** or normal users read as
  forged (constrains Lab 02).
- **PPL/SQL engine is present** though the UI apps are hidden; `stats count() by`
  is available for stack-counting.

## Result
A default Wazuh deployment indexed only rule-matched alerts, leaving ~⅔ of
telemetry - including every successful-ticket credential-access event - unhuntable.
Archive logging and indexing are now enabled and verified end to end with a
controlled 4768 that lands in archives but not alerts. The volume baseline, query
capability, and anti-join lookback constraint are established. **No custom rule -
this lab is the foundation the rest of Module 07 stands on.** Next: **Lab 02 -
Golden Ticket anti-join** (hunting the *missing* 4768 that Wazuh's stateless
engine cannot express), custom rule namespace **100700+**.
