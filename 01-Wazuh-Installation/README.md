# Module 01 — Wazuh Installation

## Objective
Deploy a fully operational Wazuh 4.14.5 SIEM stack on Ubuntu Server,
including Manager, Indexer, and Dashboard components.

## Environment
- OS: Ubuntu Server 24.04.3 LTS
- IP: 192.168.1.79
- Platform: Oracle VirtualBox (NAT + Bridged adapters)

## Components installed
| Component | Purpose |
|---|---|
| Wazuh Manager | Central analysis engine, rule matching, alert generation |
| Wazuh Indexer | OpenSearch-based storage and search engine |
| Wazuh Dashboard | Web-based SOC interface (HTTPS port 443) |

## Key configuration decisions
- Bridged network adapter added for agent communication
- JVM heap reduced to 512m for lab-scale stability
- Startup order enforced: Indexer → Manager → Dashboard
- SSL certificates generated for agent enrollment service (authd)

## Verification
- Dashboard accessible at https://192.168.1.79
- All manager sub-services running (remoted, analysisd, authd, syscheckd, logcollector)
- Ports 1514, 1515, 9200, 55000, 443 confirmed listening

## Status
Complete — platform operational
