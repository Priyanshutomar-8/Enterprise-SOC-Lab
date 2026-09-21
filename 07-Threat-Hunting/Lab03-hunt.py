import subprocess, json, statistics
from datetime import datetime
from collections import defaultdict

CERT="/etc/wazuh-indexer/certs/admin.pem"; KEY="/etc/wazuh-indexer/certs/admin-key.pem"
URL="https://127.0.0.1:9200/wazuh-archives-4.x-2026.09.21/_search"
q={"size":200,
   "query":{"bool":{"must":[
     {"term":{"data.win.system.eventID":"3"}},
     {"term":{"data.win.eventdata.destinationIp":"192.168.56.79"}},
     {"term":{"agent.ip":"192.168.56.103"}}]}},
   "sort":[{"timestamp":"asc"}],
   "_source":["timestamp","data.win.eventdata.destinationPort","data.win.eventdata.utcTime","data.win.system.systemTime"]}
out=subprocess.run(["curl","-sk","--cert",CERT,"--key",KEY,URL,"-H","Content-Type: application/json","-d",json.dumps(q)],capture_output=True,text=True).stdout
d=json.loads(out); hits=d["hits"]["hits"]
byport=defaultdict(list); skew=[]
for h in hits:
    s=h["_source"]; ed=s["data"]["win"]["eventdata"]
    byport[ed["destinationPort"]].append(s["timestamp"])
    skew.append((s["timestamp"], ed.get("utcTime"), s["data"]["win"]["system"].get("systemTime")))
def parse(ts):
    ts=ts.replace("Z","+0000")
    for fmt in ("%Y-%m-%dT%H:%M:%S.%f%z","%Y-%m-%dT%H:%M:%S%z"):
        try: return datetime.strptime(ts,fmt)
        except: pass
    raise ValueError(ts)
labels={"8000":"A tight-beacon ~20s","8080":"B slow-beacon ~45s","8090":"C human-noise rand"}
print(f"{'port':<6}{'label':<22}{'n':>3}{'mean':>8}{'stdev':>8}{'CV':>7}{'min':>7}{'max':>7}   verdict")
print("-"*90)
for port in ["8000","8080","8090"]:
    times=sorted(parse(t) for t in byport.get(port,[]))
    iv=[(times[i+1]-times[i]).total_seconds() for i in range(len(times)-1)]
    if not iv: continue
    mean=statistics.mean(iv); sd=statistics.pstdev(iv); cv=sd/mean if mean else 0
    verdict="BEACON (regular)" if cv<0.15 else "human/irregular"
    print(f"{port:<6}{labels[port]:<22}{len(times):>3}{mean:>8.2f}{sd:>8.2f}{cv:>7.3f}{min(iv):>7.1f}{max(iv):>7.1f}   {verdict}")
    print("   intervals(s):", [round(x,1) for x in iv])
print()
# clock-skew demo: Wazuh ingest timestamp vs Sysmon utcTime, first 3
print("clock check (Wazuh ingest ts  vs  Sysmon utcTime  vs  channel systemTime):")
for t in skew[:3]:
    print("  ", t[0], "|", t[1], "|", t[2])
