# Module 07 - Threat Hunting

Modules 04-06 built one detection rule per lab and asked "can this event be
detected?" Threat hunting asks the opposite question: **what got past the rules?**
A hunt is a hypothesis-driven search over stored telemetry for attacker activity
that no rule alerted on - which only works if the telemetry was kept and made
searchable. Lab 06A set the theme: a Golden Ticket's real signal is a *missing*
4768, an absence-correlation Wazuh's stateless, first-match engine cannot express
as a rule. A query over stored events can.

## Environment note
This module hunts over the same lab as Module 06 - manager (Wazuh 4.14.6 all-in-one,
Ubuntu, 192.168.56.79), domain controller `DC01` (agent 004), and Kali + impacket
(agent 001) as the activity generator. The key change is **archive indexing**: the
default install indexes only rule-matched alerts, so Lab 01 enables and indexes the
raw event archives (`wazuh-archives-*`) that hunting depends on. Hunts run in
**PPL/SQL** via the OpenSearch Dev Tools console or REST API.

## Labs

| # | Lab | Focus | MITRE | Custom Rule | Status |
|---|---|---|---|---|---|
| 01 | [Data Foundation - what can you actually hunt?](Lab01-Data-Foundation.md) | Archive indexing, blind-spot audit, query engine | Data Sources (foundation) | - | **Complete** |
| 02 | Golden Ticket anti-join | Hunt the *missing* 4768 an anti-join finds but a rule cannot | T1558.001 | 100700 (planned) | Planned |
| 03 | Beacon periodicity | Stack-count time gaps between Sysmon EID3 connections | T1071 | 100701 (planned) | Planned |
| 04 | Hunt-to-detection (capstone) | Promote one hunt to a rule, or document why it must stay a hunt | - | 100702 (planned) | Planned |

Custom detection rules are namespaced at **100700+**, continuing from Module 06's
100600 block. Lab 01 writes no rule - it is the data-foundation and verification
lab the rest of the module stands on, the same pattern as Lab 06A: a rigorous
investigation is publishable with no rule when it is framed as one.

## Why archives, not alerts

A default Wazuh install indexes only events that matched a rule at **level 3+**.
Everything scored level 0 - the majority of raw telemetry, including every
*successful* Kerberos ticket request - is evaluated and discarded. Lab 01 measured
the blind spot two independent ways and found **~67-70% of telemetry never reached
the default searchable index**. Two switches turn the full-fidelity archive path
on:

```
<logall_json>yes</logall_json>          # /var/ossec/etc/ossec.conf - write every event to disk
archives: enabled: true                 # /etc/filebeat/filebeat.yml line 26 - ship it to the indexer
```

Enabling them is **prospective only** - a hard-link rotation means the past is not
backfilled; days recorded before archiving live only as on-disk `.json.gz`. Hunt
lookback is therefore bounded below by when archiving was switched on.

## Method
Hunts use PPL's `stats count() by <field>` for stack-counting (rare processes,
beacon intervals) and `bool`/`range` queries for anti-joins and time-window
correlation. Each hunt is paired with a **Sentinel KQL translation, labelled
untested (not run in Sentinel)** - the technique maps directly to a Detection
Engineer / Sentinel role, but the KQL is not claimed as executed.
