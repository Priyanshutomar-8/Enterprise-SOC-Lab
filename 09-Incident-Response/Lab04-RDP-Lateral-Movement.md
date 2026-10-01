# Lab 04 - RDP Lateral Movement in Context (T1021.001 / T1078.002)

## Objective
Deploy the Module 08 RDP rule (reserved 100412, never deployed) against a real RDP
logon and reconstruct the movement path. The finding reframes the rule entirely: RDP
is **not** an uncovered gap - the shipped ruleset already detects it - so a blanket
"any RDP" rule adds nothing. 100412 is redesigned to escalate only the case that
matters: RDP by the built-in Administrator to a domain controller.

**Benign stand-in.** The "attacker" is an RDP logon from the host (`192.168.56.1`)
into DC01 using a valid admin account - INC moves with valid accounts (T1078). No
exploit; the detection keys on *who* logs on over RDP *to what*, which is the real
lateral-movement signal.

## Framing
| Field | Value |
|---|---|
| Discipline | Detection engineering + IR path reconstruction |
| INC link (Lab 05 rank) | RDP, #3: T1021.001 |
| ATT&CK | T1021.001 (Remote Services: RDP), T1078.002 (Valid Accounts: Domain) |
| Data source | Windows Security **4624 LogonType 10** (RemoteInteractive) on the target |
| Target | **DC01** (Server 2022, agent 004) - Win 11 Home agent 002 cannot host RDP |
| Rule | **100412** - deployed as written, found redundant/shadowed, then redesigned |
| Namespace | 100900+ (100412 reserved in Module 08) |

## The attack (run from the host against DC01)
```
mstsc /v:192.168.56.10        # log in as LAB\Administrator
```
Produces **Event 4624, LogonType 10** on DC01: `targetUserName=Administrator`,
`targetUserSid=S-1-5-21-...-500` (built-in Administrator / RID 500),
`ipAddress=192.168.56.1`, `computer=DC01.lab.local`.

## Detection engineering

### The finding - RDP is already covered; the Module 08 "gap" was wrong
100412 was deployed **as written** from Module 08:
```xml
<rule id="100412" level="10"><if_sid>60106</if_sid>
  <field name="win.eventdata.logonType">^10$</field> ... </rule>
```
It **never fired.** The RDP logon was taken by a **shipped** rule, `92653` (level 3):
```
60106 (Windows Logon Success)
  -> 92651 (L0, Successful Remote Logon - any remote IPv4)
       -> 92653 (L3, "...logged using Remote Desktop Connection (RDP)", T1021.001)
```
`92653` sits **deeper** in the chain than 100412 (a direct child of 60106), so the
engine selects `92653` and 100412 is shadowed. The important correction: **Module 08
Lab 05's premise that RDP is an uncovered Lateral Movement gap is wrong** - the
shipped ruleset has a dedicated, correctly-tagged RDP rule (`92653`, T1021.001).

And a blanket "any RDP = alert" rule (what 100412 was) has **no detection value**:
every admin RDP session is identical to the attacker's, which is exactly why 92653 is
only level 3 and why 100412 was never deployed. Confirmed empirically, not assumed.

### The redesign - escalate the case that actually matters
RDP by the **built-in Administrator (RID 500)** to a **domain controller** is not
routine: mature environments disable or avoid the built-in Administrator, and its use
over RDP into a DC is textbook privileged lateral movement with the crown-jewel
credential (INC's T1078 valid-accounts pattern). So 100412 was rebuilt to refine
92653's output rather than duplicate it:
```xml
<rule id="100412" level="12">
  <if_sid>92653</if_sid>
  <field name="win.eventdata.targetUserSid" type="pcre2">^S-1-5-21-\d+-\d+-\d+-500$</field>
  <description>RDP logon by BUILT-IN Administrator (RID 500) to $(win.system.computer) from $(win.eventdata.ipAddress) - privileged lateral movement [T1021.001/T1078.002]</description>
  <mitre><id>T1021.001</id><id>T1078.002</id></mitre>
</rule>
```
- **Chains off `92653`** (not 60106): it only evaluates confirmed RDP logons and, as
  the deeper child, now wins - fixing the shadow the same way Labs 02/03 did.
- **RID 500 only:** fires above 92653's L3 for the built-in Administrator; ordinary
  named-admin RDP stays at 92653's L3 (not escalated).
- **Tripwire, not proof:** a lazy admin using the built-in Administrator over RDP
  trips it too (documented FP, cf. Module 06's 100604). The alert flags *review*, not
  confirmed malice.

## Test matrix (live fire on DC01, 2026-10-01)
| # | Event | Rule that alerted | Verdict |
|---|---|---|---|
| 1 | Admin RDP logon (100412 as-written) | **92653 L3** | shadowed - shipped RDP rule wins; "gap" disproven |
| 2 | Admin RDP logon (100412 redesigned) | **100412 L12** | built-in-Admin RDP escalated; supersedes 92653 |

Confirmed 100412 alert (evidence record):
```
Alert:        100412  level 12  "RDP logon by BUILT-IN Administrator (RID 500) to DC01.lab.local from 192.168.56.1 - privileged lateral movement"
Fired at:     2026-10-01T20:03:38 UTC (collector clock)
Host / agent: DC01.lab.local / 004
eventID:      4624  LogonType 10   targetUserSid: S-1-5-21-...-500   ipAddress: 192.168.56.1
MITRE:        T1021.001, T1078.002 (Lateral Movement)
```

## IR path reconstruction
- **Who/where:** `targetUserSid` (RID 500 = built-in Administrator), `computer`
  (DC01 = a DC), `ipAddress` (source foothold) name the actor, target and origin.
- **Movement path:** source host 192.168.56.1 -> RDP -> DC01 as built-in Administrator.
  In a real incident the source IP is the previously-compromised host; pivoting on it
  across agents reconstructs the chain (ties to the Module 07 hunt approach).
- **Containment (simulated, Lab 01):** isolate DC01's NIC, disable/rotate the built-in
  Administrator, require a jump host with NLA for DC RDP.

## Known limitations (documented, not closed)
- **ipAddress-blank RDP evades the chain.** RDP 4624s sometimes arrive with
  `ipAddress` empty; those fire `67023`/`60106`, not `92651->92653`, so 100412 (chained
  off 92653) misses them. A second logon event in the same connection showed exactly
  this. Robustly covering RDP needs a rule anchored on `logonType 10` + RID 500 that
  does not depend on the IP field - a refinement left for later.
- **Tripwire FP:** legitimate built-in-Administrator RDP trips it (see above).
- **Blanket RDP is a hunt/correlation problem.** Separating malicious from admin RDP
  needs context the single event lacks (source reputation, account baseline, time,
  target sensitivity) - i.e. hunting, not a single-event rule (Module 07).

## Lab-ops notes (cost real time this session)
- **DC01 at 2 GB RAM thrashed** - a Server 2022 DC with the GUI could not keep up
  (commands hung mid-type). Raised to **4 GB** (`VBoxManage modifyvm DC01 --memory
  4096`, VM off); booted fast and stable after.
- **RDP had to be enabled** (`fDenyTSConnections=0` + `Enable-NetFirewallRule
  -DisplayGroup "Remote Desktop"`) and **NLA disabled**
  (`UserAuthentication=0`) because the RDP client host is **not domain-joined** and
  could not complete NLA against the DC. Lab-only downgrade; production keeps NLA and
  RDPs from a domain-joined jump host.
- **RDP resumes sessions.** Disconnect/reconnect and even Start-menu sign-out from
  inside the session did **not** produce a fresh 4624 Type 10 - the session resumed.
  A full **sign-out at the DC01 console** (killing all Administrator sessions) was
  required before a new `mstsc` generated a genuine Type-10 logon.
- **`wazuh-logtest` is not a valid check here.** Replaying the real event through
  logtest did not reproduce the live rule match (the known eventchannel JSON-stdin vs
  live-agent discrepancy). Only live-fire confirmed 100412.

## Result
- Shipped `92653` already detects RDP (T1021.001); Module 08's "uncovered gap" was
  wrong, and a blanket RDP rule is why 100412 sat undeployed.
- **100412 (level 12)** redesigned to escalate built-in-Administrator RDP to a DC -
  privileged lateral movement - live-verified superseding 92653 on the same event.
- Documented the ipAddress-blank evasion and the tripwire FP honestly.

## Files
- Rule: `local_rules.xml` on the manager (100412, chained off shipped 92653).
- Namespace 100900+ ; next: Lab 05 (paper-walkthrough capstone - stitch Labs 02-04
  into one INC Ransom incident narrative, no new rule).
