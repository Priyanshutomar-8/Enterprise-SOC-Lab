# Lab 03 - Beacon Periodicity Hunt

## Objective
A command-and-control **beacon** is defined not by *how much* it talks but by
*how regularly* it does. Module 05 Lab 05 proved a single-event rule engine
cannot see that regularity: its rate rule (`frequency=8 / timeframe=120`, rule
100505) fired on a fast beacon but a **40-second sleep walked straight past it**,
and the lab's own Finding #1 was "rate is not periodicity." This lab does what
that rule could not - it computes the **inter-arrival interval and its variance**
over stored Sysmon EID3 telemetry and isolates a beacon from human traffic by the
*regularity* of its callbacks, including a slow beacon that no rate rule catches.

This is a **threat hunt - no custom rule** (rule 100701 stays reserved). The
periodicity computation needs the delta between consecutive events per
destination, a stateful window operation Wazuh's stateless, first-match rule
engine cannot express - the same structural reason Lab 02's anti-join stayed a
hunt. Promotion to a rule is the explicit question of the Lab 04 capstone; this
lab is the hunt and the evidence.

## MITRE ATT&CK
| Field | Value |
|---|---|
| Tactic | Command and Control (TA0011) |
| Technique | **T1071.001** - Application Layer Protocol: Web Protocols (beaconing) |
| Log source | Sysmon **Event ID 3** (NetworkConnect), Windows agent 002, from `wazuh-archives-*` |
| Detection type | Threat hunt (stateful interval / variance analysis), not a rule |
| Reference | https://attack.mitre.org/techniques/T1071/001/ |

## Environment
| Component | Details |
|---|---|
| Sensor | `windows` agent **002**, 192.168.56.103, Sysmon v15 (SwiftOnSecurity config), `powershell.exe` in the NetworkConnect include-list |
| C2 stand-in | manager 192.168.56.79 running three `python3 -m http.server` listeners on ports **8000 / 8080 / 8090** |
| Manager | Wazuh 4.14.6, Ubuntu, 192.168.56.79; **archives indexed** (Lab 01); OpenSearch queried by admin client cert |
| Query engine | OpenSearch `_search` + `_plugins/_ppl` (Dev Tools / REST) |

## Prerequisite - the data foundation (Lab 01)
A **successful** outbound connection is a level-0 Sysmon event: with a default
install it is evaluated and discarded, never indexed. Lab 05 could only see its
beacons as *alerts*, where the shipped level-0 rule **92101** (`powershell.exe` +
tcp) silently shadowed the custom rules. This hunt reads `wazuh-archives-*`
instead, where **every** decoded EID3 lands regardless of rule outcome - so the
92101 shadow is irrelevant here. Archiving (Lab 01) is the precondition; without
it there is nothing to hunt.

## Method - generate three channels, tell them apart by regularity

Three traffic patterns were generated from agent 002, each to its own port so the
hunt can `group by destinationPort` and score each "channel" independently. All
three are `Invoke-WebRequest` from `powershell.exe` (in the sensor include-list ->
each request = one EID3, because `python3 -m http.server` speaks HTTP/1.0 and
closes per request):

| Port | Pattern | Callbacks | Interval | Purpose |
|---|---|---|---|---|
| 8000 | tight beacon | 12 | fixed 20s | obvious beacon |
| 8080 | **slow beacon** | 10 | fixed 45s | **evades rate rule 100505** (only 2-3 events per 120s window) |
| 8090 | human noise | 18 | random 3-30s | control - must NOT be flagged |

```powershell
$jA = Start-Job -Name beaconA -ScriptBlock { 1..12 | % { try{Invoke-WebRequest "http://192.168.56.79:8000/beaconA" -UseBasicParsing -TimeoutSec 4|Out-Null}catch{}; Start-Sleep 20 } }
$jB = Start-Job -Name beaconB -ScriptBlock { 1..10 | % { try{Invoke-WebRequest "http://192.168.56.79:8080/beaconB" -UseBasicParsing -TimeoutSec 4|Out-Null}catch{}; Start-Sleep 45 } }
$jC = Start-Job -Name noiseC  -ScriptBlock { 1..18 | % { try{Invoke-WebRequest "http://192.168.56.79:8090/noiseC" -UseBasicParsing -TimeoutSec 4|Out-Null}catch{}; Start-Sleep (Get-Random -Min 3 -Max 31) } }
```

Each listener logs every request with a server-side timestamp - an independent
ground truth on the manager's own clock, which matters because the guest clock is
not trustworthy (see Finding 3).

## What was captured - zero loss into archives

| Port | Server log (ground truth) | Archive EID3 (`wazuh-archives-*`) |
|---|---|---|
| 8000 | 12 | 12 |
| 8080 | 10 | 10 |
| 8090 | 18 | 18 |

Every generated connection produced an EID3 that reached the archive index - a
clean 40/40. (This is the payoff of Lab 01: the same events, as *alerts*, would
have been shadowed by 92101 or scored level-0 and dropped.)

## The hunt

### View 1 - rate / stack-count (what a volume detector sees)
The stack-count primitive Lab 01 promised, run in PPL:

```
source=`wazuh-archives-4.x-2026.09.21`
| where data.win.system.eventID='3'
    and data.win.eventdata.destinationIp='192.168.56.79'
    and agent.ip='192.168.56.103'
| stats count() as hits by data.win.eventdata.destinationPort | sort - hits
```
```
  8090 (noise)        18   <- rate ranks the BENIGN channel first
  8000 (tight beacon) 12
  8080 (slow beacon)  10   <- rate ranks the stealthiest beacon LAST
```
Rate is actively misleading: it prioritises the harmless human traffic and
buries the slow beacon. This is why Lab 05's frequency rule missed the 40s case.

### View 2 - periodicity (interval variance)
The hunt pulls every EID3 to the C2 host, sorts by the manager's ingest
`timestamp`, computes the gaps between consecutive events per port, and scores
each channel by **coefficient of variation** (CV = stdev / mean) - low CV = a
machine keeping time, high CV = a human:

```
port  pattern              n    mean   stdev     CV     verdict
8000  tight-beacon ~20s   12   20.06s   0.44   0.022    BEACON (regular)
8080  slow-beacon ~45s    10   45.14s   0.31   0.007    BEACON (regular)   <-- lowest CV of all
8090  human-noise rand    18   18.73s   7.59   0.405    human/irregular
```
Intervals (seconds):
- 8000: 20.3 20.0 20.2 19.7 20.3 20.6 20.4 18.9 20.3 19.9 20.2
- 8080: 45.5 45.0 45.0 45.1 44.7 44.7 45.7 45.2 45.3
- 8090: 22.3 26.7 26.5 28.2 27.0 3.8 25.9 23.3 24.8 9.1 11.0 15.1 15.3 9.8 9.1 21.2 19.1

A threshold of **CV < 0.15** cleanly separates the two beacons (0.007-0.022) from
the human channel (0.405) - a ~20-50x gap. Full analysis in
[`Lab03-hunt.py`](Lab03-hunt.py) (queries the archive by client cert, groups by
port, computes mean/stdev/CV per channel).

## Key findings

1. **The stealthiest beacon has the lowest variance.** The 45s beacon (8080)
   posted the **lowest CV of all three (0.007)** - the most machine-regular
   channel in the data - while being the one Lab 05's rate rule 100505
   structurally cannot catch (2-3 events per 120s window never reaches
   `frequency=8`). Rate missed it; periodicity ranked it *most* suspicious. This
   is the whole thesis of hunting in one number.

2. **Rate and periodicity disagree, and periodicity is right.** By event volume
   the benign noise (18) outranks both beacons (12, 10). A volume/threshold
   detector inverts the true priority; the interval-variance hunt corrects it.
   Rate answers "how loud"; periodicity answers "how mechanical" - only the
   second distinguishes a beacon.

3. **Three clocks, 112 seconds apart - use the right one.** A single EID3 carried
   `timestamp` (Wazuh ingest) `19:59:07.660`, Sysmon `utcTime` `20:00:21.388`,
   and channel `systemTime` `20:00:59.867` - spanning ~112s (NTP is inactive on
   this lab; the guest clock drifts). Computing intervals off Sysmon `utcTime`
   would distort them. The manager **ingest `timestamp`** matched the server
   listener log to the second and yielded clean 20.06 / 45.14 means, so it was
   the interval clock. Extends the Lab 05 Sysmon-clock finding: **on a host with
   an untrusted clock, time your intervals on the collector, not the endpoint.**

4. **The hunt sidesteps the 92101 alert-shadow entirely.** Because it reads
   archives, not `wazuh-alerts-*`, the level-0 rule that hid these beacons from
   Lab 05's alert pipeline never enters the picture - archive telemetry is
   pre-rule.

## Limitations and honest notes
1. **Zero jitter is the easy case.** Real beacons jitter their sleep (+/-10-20%).
   Jitter raises CV, but a jittered beacon still sits far below human CV - the
   separation shrinks, it does not vanish. A production threshold must be tuned
   against real traffic, not this clean lab; CV<0.15 is a lab value.
2. **One long-lived connection = one EID3.** A C2 using HTTP keep-alive or a
   WebSocket emits a single NetworkConnect and has no interval to measure. This
   hunt sees *connection-per-callback* beacons (the common case, and what
   `http.server`'s HTTP/1.0-close produced), not session-persistent ones.
3. **Sensor coverage is image-based (Lab 05 carries over).** EID3 fires only for
   processes in the Sysmon include-list. A beacon from `curl.exe` (absent from
   the community config) would generate **zero** telemetry and be unhuntable -
   the hunt is only as complete as the sensor's include-list.
4. **Small sample.** 10-18 callbacks per channel is enough to separate CVs by
   20-50x here, but a handful of events gives a noisy stdev; a real hunt wants
   dozens of intervals before trusting a CV.
5. **Query-engine gotchas (Dev Tools).** PPL rejected the dotted index name until
   it was **backtick-quoted**, rejected IP values until **single-quoted**, and
   rejected `eventID=3` because the field is a string (`='3'`). A hunter typing
   these live will hit all three.

## Sentinel translation (KQL - untested, not run in Sentinel)
The interval math that Wazuh's engine cannot express as a rule **is** expressible
as a scheduled analytics rule in Sentinel, because KQL has ordered window
functions (`serialize` + `prev()`) and `stdev()`:

```kql
DeviceNetworkEvents
| where RemoteIP == "192.168.56.79" and InitiatingProcessFileName == "powershell.exe"
| order by RemotePort asc, Timestamp asc
| serialize
| extend delta = iff(RemotePort == prev(RemotePort),
                     datetime_diff('second', Timestamp, prev(Timestamp)), real(null))
| summarize n=count(), avg=avg(delta), sd=stdev(delta) by RemotePort
| extend cv = sd / avg
| where n >= 6 and cv < 0.15        // regular callbacks = candidate beacon
```
This is precisely the Lab 04 capstone question: a hunt that **must** stay a hunt
in Wazuh (stateless engine) can become a **rule** in a stateful engine. Labelled
untested - the technique maps directly to a Detection Engineer / Sentinel role,
but the KQL was not executed.

## Result
Over indexed archive telemetry, an interval-variance hunt isolated two C2 beacons
from human traffic by the **regularity** of their callbacks (CV 0.007-0.022 vs
0.405), including a 45-second beacon that the Module 05 rate rule structurally
cannot detect - and it did so despite the rate/volume view ranking the benign
channel highest. The discriminator is coefficient of variation over inter-arrival
intervals, timed on the collector clock because the endpoint's is untrustworthy.
**No custom rule** - the computation is a stateful window operation Wazuh's
engine cannot express, which is the finding; rule 100701 stays reserved. Next:
**Lab 04 - hunt-to-detection capstone**, which decides whether any hunt in this
module (this one, via Sentinel's window functions; or Lab 02's anti-join)
promotes to a rule, or is documented as permanently hunt-only in Wazuh.
