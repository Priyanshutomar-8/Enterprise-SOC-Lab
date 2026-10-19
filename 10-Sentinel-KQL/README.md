# Module 10 - Microsoft Sentinel and KQL

Modules 06-07 ended at a wall: the true signal of a Golden Ticket is an event that
**did not happen** (no 4768 before a 4769), and Wazuh's stateless, first-match rule
engine cannot express that. This module moves the detections to **Microsoft
Sentinel**, whose query language (KQL) can join, anti-join, aggregate and correlate
across events - and measures what that buys, and what it still cannot see.

## Boundaries
- **Personal tenant only.** No employer Azure tenant or account is used for any lab.
- **Cost-capped.** Data collection is filtered to the event IDs a lab needs, and a
  budget alert is set before any data connector is enabled.
- **Honest data labels.** Labs on synthetic data say so in the title section; only
  live-fire labs claim detection on real telemetry.

## Labs

| # | Lab | Data | Detections | Status |
|---|---|---|---|---|
| 01 | [Kerberos detections in KQL](Lab01-KQL-Kerberos-Detections.md) | Synthetic (`datatable`), ADX free cluster | Golden Ticket anti-join, Kerberoast, AS-REP | **Complete** |
| 01b | [Lab 01's KQL against real DC01 telemetry](Lab01b-KQL-on-Real-Telemetry.md) | Real, replayed from the Wazuh archive (298 events), ADX free cluster | Same three - Golden Ticket: 1 TP / 2 FP / 1 FN (masked forgery) | **Complete** |
| 02 | [Scheduled rules vs. late events](Lab02-Scheduled-Rule-Latency.md) | Real, replayed + manager receive time, ADX free cluster | Lab 01b rules simulated on a schedule - 21/298 events mis-dated by DC01's boot-time clock, silently dropped | **Complete** |
| 02b | [Detecting a DC clock change](Lab02b-DC-Time-Change-Detection.md) | Live-fire, Wazuh (DC01) | 101000 / 101001 - L12 fired on `Set-Date`; the slewed repair and boot-time steps never reach the SIEM | **Complete** |
| 02c | [Analytics rules as code](Lab02c-Detection-as-Code.md) | Real replay + reconstructed 4616, ADX free cluster | 4 Sentinel rule YAMLs (Kerberoast, AS-REP, Golden Ticket lead, clock change) - linted, replayed per scheduled run, 9/9 harness runs as predicted | **Complete** |
| 02d | [Tuning the Golden Ticket rule behind a regression gate](Lab02d-Golden-Ticket-Tuning.md) | Real replay, every hourly run, ADX free cluster | Golden Ticket v1.0.0 -> v1.1.0 (exclude `::1`): 3 -> 2 alerts, TP kept; longer lookbacks change nothing, the remaining FP is a collection gap | **Complete** |
| 02e | [ASIM normalization vs. Kerberos detections](Lab02e-ASIM-Kerberos.md) | Real replay through a custom ASIM parser, two table layouts, ADX free cluster | Microsoft's Windows ASIM parser keeps 0/298 Kerberos events; custom parser identical across layouts, but none of the 3 detections fit pure ASIM fields | **Complete** |
| 03 | Sentinel workspace + DC01 onboarding (Arc + AMA) | Live | - | Planned (needs a paid subscription) |
| 04 | Analytics rules, entity mapping, live-fire from Kali | Live | Lab 01 rules on real data | Planned (needs a paid subscription) |
