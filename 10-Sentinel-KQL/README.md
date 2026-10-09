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
| 03 | Sentinel workspace + DC01 onboarding (Arc + AMA) | Live | - | Planned (needs a paid subscription) |
| 04 | Analytics rules, entity mapping, live-fire from Kali | Live | Lab 01 rules on real data | Planned (needs a paid subscription) |
