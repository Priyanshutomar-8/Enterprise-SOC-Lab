#!/usr/bin/env python3
# Extract Kerberos 4768/4769 events from Wazuh archives into a CSV shaped like
# Sentinel's SecurityEvent table (column names match SecurityEvent where one exists).
import csv, glob, gzip, json, os, sys

os.chdir("/var/ossec/logs/archives")
files = sorted(glob.glob("2026/*/ossec-archive-*.json.gz")) + ["archives.json"]
cols = ["TimeGenerated", "Computer", "EventID", "TargetUserName", "TargetDomainName",
        "ServiceName", "TicketEncryptionType", "TicketOptions", "PreAuthType", "Status",
        "IpAddress", "IpPort", "AgentName", "SourceFile"]
out = csv.writer(sys.stdout)
out.writerow(cols)
for f in files:
    opener = gzip.open if f.endswith(".gz") else open
    with opener(f, "rt", errors="replace") as fh:
        for line in fh:
            if '"eventID":"4768"' not in line and '"eventID":"4769"' not in line:
                continue
            try:
                ev = json.loads(line)
            except ValueError:
                continue
            win = ev.get("data", {}).get("win", {})
            s, d = win.get("system", {}), win.get("eventdata", {})
            out.writerow([
                s.get("systemTime", ev.get("timestamp", "")),
                s.get("computer", ""),
                s.get("eventID", ""),
                d.get("targetUserName", ""),
                d.get("targetDomainName", ""),
                d.get("serviceName", ""),
                d.get("ticketEncryptionType", ""),
                d.get("ticketOptions", ""),
                d.get("preAuthType", ""),
                d.get("status", ""),
                d.get("ipAddress", ""),
                d.get("ipPort", ""),
                ev.get("agent", {}).get("name", ""),
                f,
            ])
