# Lab 02f - Events Written Before the Agent Starts: Testing `only-future-events`

## Objective
Lab 02b Finding 5: on every cold boot, DC01 logged a large clock step (event 4616) about
24 s **before** the Wazuh agent started, and none of those events ever reached the manager.
The suspected cause was the agent's `eventchannel` option `only-future-events`. Its default
is `yes`, which skips events written while the agent was not running. This lab tests that
suspicion and the obvious fix, `only-future-events no`.

**Investigation lab, partly unresolved.** The fix was pushed through the manager's
centralized `agent.conf` and had **no observable effect**. The reason could not be confirmed
from the manager side. As in Module 06 Lab 06A, the result is published with its open
question.

## Framing
| Field | Value |
|---|---|
| Discipline | Detection engineering - log collection coverage |
| Engine | Wazuh 4.14.6 manager; agent 004 on DC01 (Windows Server 2022) |
| Changed | `/var/ossec/etc/shared/default/agent.conf` (centralized, group `default`) - reverted after the lab |
| Not changed | DC01's local `ossec.conf` (needs an interactive DC01 login, which this run did not use) |
| Cost | None |

## Method
The direct marker test (stop the agent, run `Set-Date`, start the agent) needs a login on
DC01. This run instead used reboots, driven entirely from the host:

- Every boot writes Security events before the agent is up (logons by SYSTEM, service
  ticket requests and so on). Many of them, 4624 / 4769, raise level-3 alerts (60106)
  once delivered.
- **Measure:** compare Security **event record IDs** delivered before a reboot with those
  delivered after it. Records missing between the two are events nobody shipped.
  `logall_json` is off, so non-alerting events also leave gaps; small gaps (1-5) are
  normal and only the boot-window gap matters.
- Run A: default config. Run B: `only-future-events no` for `Security`, pushed centrally.

## Findings in order of occurrence

### 1. A saved-state resume IS delivered, even across a manager outage
DC01 was resumed from a saved state four days old. The Guest Additions stepped its clock and
logged 4616, while the agent was already running but the manager was still down:

| Field | Value |
|---|---|
| Rule | 60132 "System time changed" (L5) |
| Process | `C:\Windows\System32\VBoxService.exe` |
| Clock | 2026-10-15 17:17:29 -> 2026-10-19 20:59:14 (**+4 d 3 h 42 m**) |
| Event time / manager receipt | 20:59:14 / 21:08:03 (agent buffered it for **8 min 49 s**) |

This confirms the Lab 02b explanation for the 133 historical VBoxService 60132 alerts: they
are resume steps, written while the agent was running.

### 2. A VirtualBox BIOS clock offset does NOT reproduce a boot-time clock step
Plan: boot DC01 with `VBoxManage modifyvm DC01 --biossystemtimeoffset -1800000` (30 min
behind) and let the Guest Additions step it after boot. **They never did.** Guest Additions
were running from 21:11:12, but the DC clock, polled from the host with
`w32tm /stripchart`, stayed **1,798 -> 1,832 s behind** for over three minutes. The Guest
Additions sync to the VM's own notion of host time, which includes the offset. **Method
finding: an offset cannot produce the Lab 02b boot step.** The offset run did reproduce Lab
02's mis-dating: events reached the manager stamped 30 min in the past (systemTime 20:44,
received 21:14).

During that run the DC clock also *lost* ground, about 0.5 s per second from 21:16:40, while
the host was short of RAM. That is Lab 02b Finding 4c again.

### 3. Run A - default config: no boot-window events delivered
Agent started (DC time) 20:44:01; earliest delivered event 20:44:23. No delivered Security
event predates the agent start.

### 4. Run B - `only-future-events no` pushed centrally: still nothing from the boot window
`agent.conf` for group `default`:

```xml
<agent_config os="Windows">
  <localfile>
    <location>Security</location>
    <log_format>eventchannel</log_format>
    <only-future-events>no</only-future-events>
  </localfile>
</agent_config>
```

Deployed by scp + md5 on both ends; `verify-agent-conf` OK. The agent received it: its
configuration hash changed to the file's md5 `7aa974b3...` and it restarted itself
(506/503 at 21:17:19-21). Then DC01 was hard-cycled twice (the first boot stalled under host
RAM pressure; the second served in 53 s).

| | Record ID | Event time | Received |
|---|---|---|---|
| Last Security record delivered before the power-off | **47929** | 21:17:02 (real) | before 21:17:45 |
| First Security record delivered after the reset boot | **48003** | 21:47:30 | 21:47:30 |
| Agent start (503) | - | - | 21:47:06 |
| **Never delivered** | **73 records** (47930-48002) | | |

The 73 cover the agent's own config restart, the power-off, and two boots. Boot-time logons
raise 60106 when delivered (dozens did immediately after the agent started), so a working
`no` would have produced alerts with event times before 21:47:06. **None arrived.**

It also did not create a second reader: in the 75 Security alerts after the change, every
record ID appeared exactly once.

### Why - unresolved
Two explanations fit and could not be separated from the manager:
1. **The centralized `Security` entry is ignored** because the agent's local `ossec.conf`
   already defines that channel, so the local default `yes` stays in force. The absence of
   duplicates fits this.
2. **The option was applied, but the hard power-offs left no usable read position
   ("bookmark")** for it to resume from.

The agent's own `ossec.log` on DC01 would settle it, and reading it needs an interactive
DC01 login, which this run did not use. The manager-side query for the agent's active
config (`get_agent_config(..., "logcollector", "localfile")`) returned **Error 1116 -
requested component configuration does not exist**.

## Test matrix
| # | Test | Expected | Observed | Result |
|---|---|---|---|---|
| 1 | Saved-state resume, manager down | 60132 delivered late | Delivered after 8 m 49 s buffering | **Pass** |
| 2 | BIOS offset -30 min, wait for Guest Additions step | Clock stepped after boot | Never stepped (offset treated as host time) | **Method invalid** |
| 3 | Default config, boot | 0 pre-start events | 0 | Pass (baseline) |
| 4 | `only-future-events no` via `agent.conf`, boot x2 | Pre-start events delivered | 0; 73 records missing | **Fail - cause unresolved** |
| 5 | Same, duplicate check | - | 0 duplicates in 75 | Second reader not created |

## Findings
1. **Boot-window telemetry is still lost**, and the centralized fix did not recover it.
   Anything that happens on a DC in the seconds before the agent starts (including a clock
   step that mis-dates everything after it) is invisible to the SIEM.
2. **Do not trust a pushed config just because the agent took it.** The hash matched and the
   agent restarted, yet the behavior did not change. Verify the effect, not the delivery.
3. **Record-ID gaps measure what never arrived.** Missing record numbers are hard evidence
   of uncollected events; an absence of alerts is not.
4. **A saved-state resume is not a boot.** Its clock step is collected; a cold-boot step is
   not. Lab 02b's two cases have different collection outcomes.
5. **BIOS offsets are useless for simulating clock steps** in VirtualBox with Guest
   Additions time sync on.

## Known limitations
- No interactive DC01 login was used, so the agent's local config and logs were not
  read, and the `Set-Date` marker test was not run.
- `logall_json` is off, so non-alerting events cannot be counted directly. The boot-window
  conclusion rests on the record-ID gap and on boot logons being alert-generating.
- Host RAM pressure stalled one boot and a browser relaunched three times during the run.
  Timings are from a stressed host.
- Lab state at the end: shared `agent.conf` reverted (hash `ab73af41...`), but DC01 was
  parked **before** it re-synced. It still holds the Run B config until its next connection.
  BIOS offset reset to 0. On the manager, indexer, dashboard and filebeat were stopped to
  free RAM; it was shut down cleanly.

## Next step that would resolve it
With a DC01 login: add `<only-future-events>no</only-future-events>` to the **local**
`Security` `<localfile>` in `ossec.conf`, read `ossec.log` for logcollector messages,
then run the marker test (stop the agent, `Set-Date -Adjust -0:00:30` and back, start the
agent) and a graceful reboot, so the agent can save its read position.
