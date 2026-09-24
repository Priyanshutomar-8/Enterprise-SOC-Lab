#!/usr/bin/env bash
# Module 08 Lab 03 - build the evidence-scored and Wazuh-alert ATT&CK Navigator layers
# and the per-technique comparison from:
#   detection-inventory.csv      (Lab 01/02 - evidence per detection)
#   wazuh-alert-techniques.csv   (indexer aggregation of rule.mitre.id over wazuh-alerts-*)
# Outputs: coverage-comparison.csv, layer-evidence.json, layer-wazuh-alerts.json
set -euo pipefail
cd "$(dirname "$0")"

awk -F, '
BEGIN {
  # Primary ATT&CK tactics for every technique in the evidence map
  split("T1003.001=credential-access T1003.006=credential-access T1021.001=lateral-movement T1048.003=exfiltration T1053.003=execution;persistence;privilege-escalation T1053.005=execution;persistence;privilege-escalation T1057=discovery T1059.001=execution T1059.004=execution T1069=discovery T1070.001=defense-evasion T1071.001=command-and-control T1071.004=command-and-control T1078=initial-access;persistence;privilege-escalation;defense-evasion T1078.003=initial-access;persistence;privilege-escalation;defense-evasion T1082=discovery T1087=discovery T1095=command-and-control T1098=persistence;privilege-escalation T1105=command-and-control T1110.001=credential-access T1136.001=persistence T1218.005=defense-evasion T1218.010=defense-evasion T1218.011=defense-evasion T1482=discovery T1490=impact T1543.003=persistence;privilege-escalation T1548.003=privilege-escalation;defense-evasion T1558.001=credential-access T1558.003=credential-access T1558.004=credential-access T1562.001=defense-evasion T1564.004=defense-evasion T1565.001=impact T1574.002=persistence;privilege-escalation;defense-evasion", m, " ")
  for (i in m) { split(m[i], kv, "="); tac[kv[1]] = kv[2] }
  rank["fired"]=4; rank["fired-with-limit"]=3; rank["hunt-only"]=2; rank["not-deployed"]=1
  name[4]="fired"; name[3]="fired-with-limit"; name[2]="hunt-only"; name[1]="not-deployed"
  color[4]="#2e7d32"; color[3]="#f9a825"; color[2]="#1e88e5"; color[1]="#9e9e9e"
}
{ sub(/$/, "") }
FNR==1 { next }
FILENAME ~ /detection-inventory/ {
  n = split($8, ta, ";")
  for (i = 1; i <= n; i++) {
    r = rank[$11]; if (r > best[ta[i]]) best[ta[i]] = r
    dets[ta[i]] = dets[ta[i]] (dets[ta[i]] ? " " : "") $1
    all[ta[i]] = 1
  }
  next
}
{ cnt[$1] = $2; rules[$1] = $3; all[$1] = 1 }
END {
  print "technique,evidence_status,detections,wazuh_alerts,wazuh_top_rules,category" > "coverage-comparison.csv"
  ev = "layer-evidence.json"; wz = "layer-wazuh-alerts.json"
  hdr = "\"versions\":{\"attack\":\"17\",\"navigator\":\"5.1.0\",\"layer\":\"4.5\"},\"domain\":\"enterprise-attack\""
  printf "{\"name\":\"Evidence-scored coverage (Module 08 Lab 03)\",%s,\"description\":\"Colour = best evidence from a live test, not the rule tag\",\"techniques\":[", hdr > ev
  printf "{\"name\":\"Wazuh alert view (Module 08 Lab 03)\",%s,\"description\":\"Every technique that produced at least one alert, Jul-Sep 2026. Score = order of magnitude of alert count\",\"gradient\":{\"colors\":[\"#fce4ec\",\"#c2185b\"],\"minValue\":1,\"maxValue\":5},\"techniques\":[", hdr > wz
  se = ""; sw = ""
  for (t in all) {
    b = best[t] + 0; c = cnt[t] + 0
    if (b >= 3 && c > 0) cat = "agree"
    else if (b >= 3) cat = "evidence-no-alerts"
    else if (b == 2) cat = "hunt-only"
    else if (b == 1 && c > 0) cat = "wazuh-lit-our-rule-undeployed"
    else if (b == 1) cat = "paper-only"
    else if (t == "T1110" || t == "T1136" || t == "T1059") cat = "wazuh-parent-of-validated"
    else cat = "wazuh-only-unvalidated"
    printf "%s,%s,%s,%d,%s,%s\n", t, (b ? name[b] : "none"), dets[t], c, rules[t], cat > "coverage-comparison.csv"
    summary[cat]++
    if (b) {
      printf "%s{\"techniqueID\":\"%s\",\"color\":\"%s\",\"comment\":\"%s: %s\",\"enabled\":true,\"showSubtechniques\":true}", se, t, color[b], name[b], dets[t] > ev; se = ","
      if (b >= 3) { ntac = split(tac[t], tt, ";"); for (k = 1; k <= ntac; k++) { tc[tt[k] "|" name[b]]++; tacs[tt[k]] = 1 } }
    }
    if (c > 0) {
      s = (c >= 10000 ? 5 : c >= 1000 ? 4 : c >= 100 ? 3 : c >= 10 ? 2 : 1)
      printf "%s{\"techniqueID\":\"%s\",\"score\":%d,\"comment\":\"%d alerts: %s\",\"enabled\":true,\"showSubtechniques\":true}", sw, t, s, c, rules[t] > wz; sw = ","
    }
  }
  printf "],\"legendItems\":[{\"label\":\"Fired in live test\",\"color\":\"#2e7d32\"},{\"label\":\"Fires with documented limit\",\"color\":\"#f9a825\"},{\"label\":\"Hunt only\",\"color\":\"#1e88e5\"},{\"label\":\"Written, not deployed\",\"color\":\"#9e9e9e\"}]}\n" > ev
  printf "]}\n" > wz
  print "== categories"; for (k in summary) printf "%-32s %d\n", k, summary[k]
  print "== techniques per tactic (deployed evidence only)"
  split("reconnaissance resource-development initial-access execution persistence privilege-escalation defense-evasion credential-access discovery lateral-movement collection command-and-control exfiltration impact", order, " ")
  for (i = 1; i <= 14; i++) printf "%-22s fired=%d limit=%d\n", order[i], tc[order[i] "|fired"], tc[order[i] "|fired-with-limit"]
}' detection-inventory.csv wazuh-alert-techniques.csv
{ grep "^technique," coverage-comparison.csv; grep -v "^technique," coverage-comparison.csv | sort; } > coverage-comparison.tmp && mv coverage-comparison.tmp coverage-comparison.csv
