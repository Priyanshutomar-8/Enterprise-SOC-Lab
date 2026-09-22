# Lab 04 - Hunt-to-Detection (capstone)

## Objective
The module's closing question: can any hunt from Labs 01-03 be **promoted to a
Wazuh rule**, or must it stay a hunt? Rather than assert the answer, this lab
*attempts the promotion on live fire*. It takes the Lab 02 Golden Ticket
anti-join, builds the closest single-event rule Wazuh can express (rule
**100701**), deploys it, and fires a **legitimate** svc-sql ticket and a
**forged** one at it back to back - to show, on real events, exactly where the
rule runs out and the hunt takes over.

The result is sharper than "Wazuh can't, Sentinel can": the promotable rule is a
proxy with an **irreducible false positive**, and the anti-join that beats it is
itself a **triage lead with its own FP/FN modes**, not a clean alarm. The
hunt/rule boundary is a property of the *engine*, not the attack.

## MITRE ATT&CK
| Field | Value |
|---|---|
| Tactic | Credential Access / Lateral Movement |
| Technique | **T1558.001** - Steal or Forge Kerberos Tickets: Golden Ticket |
| Log source | Security **4768** (AS-REQ / TGT) and **4769** (service ticket), agent 004 (DC01), from `wazuh-alerts-*` and `wazuh-archives-*` |
| Custom rule | **100701** (L10) - deployed and demonstrated *insufficient* (the finding) |
| Reference | https://attack.mitre.org/techniques/T1558/001/ |

## Environment
| Component | Details |
|---|---|
| Domain controller / KDC | `DC01` (agent 004), Windows Server 2022, forest `lab.local`, 192.168.56.10 |
| Attacker | Kali + impacket v0.14, 192.168.56.80 (agent 001) |
| Manager | Wazuh 4.14.6, Ubuntu, 192.168.56.79; archives indexed (Lab 01) |
| Impersonated principal | `svc-sql`, RID **1104** (real, low-noise service account) |

## The promotion attempt - rule 100701

The Lab 02 detection is: *a 4769 (service ticket request) for a user who has no
preceding 4768 (TGT request)* - because a Golden Ticket's TGT is forged offline
and never touches the KDC. Wazuh cannot express "no matching 4768": it has
`<frequency>`/`<timeframe>` correlation (counting) and `same_field`
(correlation on a shared value), but **no set anti-join and no absence
operator**. So the closest promotable rule is a single-event proxy - fire on a
4769 for a sensitive account:

```xml
<rule id="100701" level="10">
  <if_sid>60106, 92651</if_sid>
  <field name="win.system.eventID">^4769$</field>
  <field name="win.eventdata.targetUserName" type="pcre2">(?i)^svc-sql@</field>
  <field name="win.eventdata.ipAddress" negate="yes" type="pcre2">^(::1|127\.0\.0\.1|::ffff:127\.0\.0\.1)$</field>
  <description>Golden Ticket proxy: service account svc-sql requested a Kerberos service ticket ... [heuristic proxy - cannot confirm forgery, T1558.001]</description>
</rule>
```

Chaining note (the Module 06 lesson, reused): 4769 successes are claimed by
shipped **level-0** rule `92651` ("Successful Remote Logon"), which silently
shadows any custom child of `60106`. `<if_sid>60106, 92651</if_sid>` re-parents
the rule onto the shadowing leaf so it is not downgraded to L0.

**Why svc-sql and not Administrator (a deliberate choice).** Lab 06B's tripwire
`100604` keys on `^Administrator@`. But the Lab 02 Golden Ticket impersonated
**svc-sql**, so `100604` never fired on the attack that was actually built - a
**false negative**. 100701 broadens the proxy to the account that was really
forged. As the live fire shows, closing that FN forces an unavoidable FP: the
two failure modes are two sides of the same single-event coin.

Deployed by whole-file scp + md5 both ends (base64/heredoc paste corrupts -
Module 06 lesson), `wazuh-analysisd -t` clean, manager restarted with the Sysmon
agent parked (no starvation).

## Live fire

All times UTC. Both shots run from Kali against DC01; both are non-loopback, so
both pass 100701's IP filter.

**Credential note.** svc-sql's documented plaintext (`SummerLab#2026`, Lab 02)
was **rejected** (`KDC_ERR_PREAUTH_FAILED`) - the account password had rotated
since. Lab 05's DCSync'd **NT hash was still valid**, so the legit baseline used
overpass-the-hash (a real AS-REQ authenticated by the account key - it still
emits a genuine 4768). The krbtgt key from Lab 02 was still current (the DC
accepted the forged ticket). Lesson: dumped hashes outlive cracked plaintext;
verify creds at use time, not from the writeup.

### Shot A - legitimate baseline
```bash
impacket-getTGT lab.local/svc-sql -hashes :<svc-sql-nthash> -dc-ip 192.168.56.10
KRB5CCNAME=svc-sql.ccache impacket-getST -spn cifs/dc01.lab.local -k -no-pass lab.local/svc-sql -dc-ip 192.168.56.10
```
Emits a real **4768** then a legit **4769** for svc-sql.

### Shot B - forged Golden Ticket
```bash
impacket-ticketer -nthash <krbtgt-nthash> -domain-sid <domain-sid> -domain lab.local -user-id 1104 svc-sql
KRB5CCNAME=svc-sql.ccache impacket-getST -spn cifs/dc01.lab.local -k -no-pass lab.local/svc-sql -dc-ip 192.168.56.10
```
`ticketer` forges the TGT offline (**no DC contact, no 4768**); `getST` presents
it and the DC logs an **orphan 4769**.

## What the manager recorded

Full svc-sql timeline from `wazuh-archives` / `wazuh-alerts`:

| Time (UTC) | Event | etype | 4768 present? | 100701 fired? |
|---|---|---|---|---|
| 21:39:04.491 | **4768** legit TGT (Shot A) | 0x17 (RC4) | this is the 4768 | n/a (keys on 4769) |
| 21:33:41.593 | 4769 legit, from a pre-existing TGT | 0x12 (AES) | none in-window | **YES** |
| 21:39:04.533 | 4769 legit, paired with the 21:39 4768 | 0x12 (AES) | yes | **YES** |
| 21:42:02.315 | **4769 FORGED (Golden Ticket)** | 0x12 (AES) | **NONE** | **YES** |

100701 fired on **all three** 4769s, field-identical (`svc-sql@LAB.LOCAL`, AES
`0x12`, source `::ffff:192.168.56.80`). The rule cannot see any difference
between the forgery and the legitimate tickets.

## The hunt - anti-join, run over two windows

Per-account set difference `{accounts with a 4769} - {accounts with a 4768}`
(PPL two-pass; the engine has no join, so the diff is the hunt):

```
# List A - accounts requesting service tickets
source=wazuh-archives-* | where data.win.system.eventID='4769' | stats count() by data.win.eventdata.targetUserName
# List B - accounts requesting TGTs (normalize: strip @REALM from the 4769 side)
source=wazuh-archives-* | where data.win.system.eventID='4768' | stats count() by data.win.eventdata.targetUserName
# Suspects = normalize(A) - B
```

| Window | 4769 accounts | 4768 accounts | svc-sql verdict |
|---|---|---|---|
| **[21:40 -> now]** (account quiet, then a ticket) | {svc-sql} | {} | **FLAGGED** - forgery isolated |
| **[21:30 -> now]** (account also authed at 21:39) | {svc-sql} | {svc-sql} | **CLEARED** - forgery masked |

The first window is the win Lab 02 promised and rule 100701 cannot deliver: the
forged 4769 has no 4768, so the anti-join isolates it. The computation needs the
held *set* of all 4768 users - a stateful operation Wazuh's stateless,
first-match engine cannot express as a rule. That is the promotion verdict:
**hunt-only in Wazuh.**

## Key findings

1. **The promotable rule cannot separate forged from legitimate.** 100701 fired
   identically on two legit tickets and one forgery. A single-event rule keyed
   on any field of a 4769 guarantees a **false positive on every legitimate
   svc-sql ticket** and still cannot isolate the forgery - because the forged
   and legit 4769 are byte-identical (same eventID, account, AES etype, service,
   source). There is no field to key on.

2. **Fixing 100604's false negative costs a guaranteed false positive.** 100604
   (`^Administrator@`) missed this svc-sql Golden Ticket entirely. 100701 closes
   that FN by widening the account scope - and immediately inherits the FP,
   because scope is the only lever a single-event rule has. FN and FP are two
   faces of the same coin; you cannot tune your way to a clean rule.

3. **The anti-join wins - only when the account is quiet in the window.**
   Windowed after the legit baseline, the anti-join isolates the forged 4769
   (no 4768). This is the detection that is structurally impossible as a Wazuh
   rule.

4. **The anti-join has its own FP and FN (the honest caveat Lab 04 adds over
   Lab 02).**
   - **False negative (masking):** once svc-sql authenticates legitimately
     (the 21:39 4768), any forged 4769 within the TGT lifetime is cleared - the
     legit 4768 masks it. A service account that ever legitimately gets a TGT
     is a blind spot. This is Lab 01's "10h lookback floor" made concrete.
   - **False positive (stale TGT):** the 21:33 legit 4769 came from a
     pre-existing TGT, so it also has no in-window 4768 - a too-short window
     flags legitimate stale-TGT usage.
   - **Conclusion: even the hunt is a triage lead, not an alarm.** It narrows
     the field; an analyst confirms.

5. **Verdict.** The detection stays a **hunt** in Wazuh (no set-anti-join /
   absence operator), and even as a hunt it is an investigation trigger, not a
   clean detection. It promotes to a *scheduled analytic* in a stateful engine -
   but carries the same precision caveats there.

## Lab-ops lesson (banked the hard way this session)
Recovering DC01's lost host-only IP, a `VBoxManage startvm --type gui` **could
not render a window in the headless session and wedged VBoxSVC** (the VirtualBox
COM broker). Clearing the broker orphaned the running manager/Kali VMs and
stripped the host-only adapter's `.1`, taking the whole `192.168.56.0/24` subnet
down. Recovery: restore the host-only IP (`VBoxManage hostonlyif ipconfig`),
then restart every VM **headless**. **Rule: on a headless host, only ever
`startvm --type headless` - the GUI launcher cascades into a full-lab outage.** A
DC that lost its static IP after a link flap re-applies it from the persistent
store on a clean reboot.

## Sentinel translation (KQL - untested, not run in Sentinel)
The anti-join is a native `leftanti` join in a scheduled analytics rule:

```kql
let TGTs = SecurityEvent
    | where TimeGenerated > ago(10h) and EventID == 4768
    | distinct TargetUserName;                 // accounts that really got a TGT
SecurityEvent
| where TimeGenerated > ago(1h) and EventID == 4769
| extend acct = tostring(split(TargetUserName, "@")[0])   // normalize realm
| where acct !in (TGTs)                        // 4769 with no matching 4768
| where acct !endswith "$"                     // drop machine accounts
```

The 10h TGT-lifetime lookback and the realm normalization are the same caveats
proven here; Sentinel expresses the *logic* Wazuh cannot, but inherits the same
FP/FN modes (masking, stale TGTs). Labelled untested - technique maps to a
Detection Engineer / Sentinel role, not claimed as executed.

## Result
The hunt-to-detection experiment ran end to end on live fire. The closest Wazuh
rule (100701) fired identically on a legitimate and a forged svc-sql service
ticket - proving a single-event rule cannot express the detection, while
demonstrating that broadening the proxy to fix Lab 06B's false negative only buys
a guaranteed false positive. The Lab 02 anti-join isolated the forgery where the
rule could not, but revealed its own FP/FN modes - it is a triage lead bounded by
the TGT-lifetime window, not a clean alarm. **The detection is hunt-only in
Wazuh by the engine's design, and a lead-generating hunt even where a stateful
engine can run it.** Rule 100701 remains deployed as the documented proxy.

This closes **Module 07** and the six-lab arc from Module 06: level-0 shadowing,
coverage gaps, an unroutable channel, and - here and in Lab 02/06A - detections
that live in stored telemetry because the rule engine cannot hold state.
