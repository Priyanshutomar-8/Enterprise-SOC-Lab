# Lab 03 - AS-REP Roasting

## Objective
Detect AS-REP roasting - the abuse of Kerberos pre-authentication being disabled
on an account to extract an offline-crackable hash **without any credentials at
all**. Kerberoasting (Lab 02) still required one authenticated domain user;
AS-REP roasting requires nothing but a username. If an account carries the
`DONT_REQ_PREAUTH` flag, the KDC will hand its AS-REP - encrypted with the
account's password key - to an anonymous requester, who cracks it offline.

The lab plants a pre-auth-disabled account `svc-backup` on the DC from Lab 01,
runs the real unauthenticated attack from Kali + impacket, and builds Wazuh rule
**100601** on the resulting **4768** event. The headline is different from Lab 02:
this is not a level-0 sibling *shadowing* a matched event, it is a **flat coverage
gap** - the shipped ruleset has **no rule for event 4768 at all**, so the roast
lands on a generic level-0 parent and disappears. Kerberos's two roasting events
are defended asymmetrically out of the box, and the undefended one is the one that
needs no credentials.

## MITRE ATT&CK
| Field | Value |
|---|---|
| Tactic | Credential Access (TA0006) |
| Technique | **T1558.004** - Steal or Forge Kerberos Tickets: AS-REP Roasting |
| Log source | Windows Security channel, event **4768** (Kerberos Authentication Service / TGT request) |
| Reference | https://attack.mitre.org/techniques/T1558/004/ |

## Environment
| Component | Details |
|---|---|
| Domain controller / target | `DC01` (Windows Server 2022), `lab.local`, 192.168.56.10, Wazuh agent **004** |
| Attacker | Kali + impacket (`impacket-GetNPUsers`), 192.168.56.80, host-only |
| Manager | Wazuh 4.14.6 all-in-one, Ubuntu, 192.168.56.79 |
| Roastable target | `svc-backup`, Kerberos **pre-authentication disabled**, weak password |
| Custom rule | **100601**, level 12 |

## Planting the target

AS-REP roasting needs its own victim - a user account with **"Do not require
Kerberos preauthentication"** set. Lab 01's `svc-sql` was for Kerberoasting; a
fresh account keeps each technique's test matrix isolated.

```powershell
New-ADUser -Name "svc-backup" -SamAccountName "svc-backup" `
  -AccountPassword (ConvertTo-SecureString "..." -AsPlainText -Force) `
  -Enabled $true -PasswordNeverExpires $true
Set-ADAccountControl -Identity "svc-backup" -DoesNotRequirePreAuth $true
```

`-DoesNotRequirePreAuth $true` is the vulnerability - it flips the
`DONT_REQ_PREAUTH` bit (`0x400000`) in `userAccountControl`. Verification:

```
Name                  : svc-backup
DoesNotRequirePreAuth : True
userAccountControl    : 4260352
```

`4260352` decodes to `512` (NORMAL_ACCOUNT) `+ 65536` (DONT_EXPIRE_PASSWORD, from
`-PasswordNeverExpires`) `+ 4194304` (**DONT_REQ_PREAUTH**). The last bit is what
makes the account roastable.

## The detection problem

Event 4768 fires on every TGT request - every interactive logon, hundreds a day,
virtually all legitimate. You cannot alert on "a 4768 happened." A roast differs on
two fields:

| Signal | Normal 4768 | AS-REP roast 4768 |
|---|---|---|
| `preAuthType` | `2` (encrypted timestamp supplied) | **`0`** (no pre-auth) - the signature; only a `DONT_REQ_PREAUTH` account produces it |
| `ticketEncryptionType` | `0x12` (AES256) | `0x17` (RC4) - impacket downgrades; RC4 cracks far faster |

`preAuthType = 0` is the primary, high-signal discriminator (it is a property of
the misconfigured account, not something normal traffic produces); `0x17` is the
attack's RC4 downgrade. That pair is what rule 100601 keys on.

### Gap in the shipped ruleset - not a shadow

Lab 02's story was a level-0 sibling (`92651`) *shadowing* a matched 4769. Event
4768 is worse: it is **not matched at all**.

- `60106` ("Windows Logon Success", level 3) matches
  `^528$|^540$|^673$|^4624$|^4769$` - it lists **4769** (Kerberoasting) but **not
  4768**. AS-REP's event never enters that chain, so `92651` (a child of `60106`)
  never sees it either.
- `grep -rn '4768' ruleset/rules/` returns **nothing** - no shipped rule references
  event 4768 anywhere.

So a roast 4768 matches only the generic grouping parent **`60103`** ("Windows
audit success event", level 0, keyed on `severityValue ^AUDIT_SUCCESS$` with no
eventID constraint) and stops there. Level 0 means no alert, no `alerts.json`
entry. The shipped ruleset gives Kerberoasting's 4769 a level-3 baseline and gives
AS-REP roasting's 4768 nothing - the credential-free attack is the less-defended
one.

## The attack

Unlike Kerberoasting, AS-REP roasting is **clock-independent**: there is no
encrypted pre-auth timestamp for the KDC to validate, so `KRB_AP_ERR_SKEW` never
gates it. And it is **unauthenticated** - the whole point - so impacket can only
test usernames it is given, not enumerate them:

```
printf '%s\n' Administrator jdoe svc-sql svc-backup guest > users.txt
impacket-GetNPUsers lab.local/ -dc-ip 192.168.56.10 -usersfile users.txt -no-pass -request -format hashcat
```

- `lab.local/` with nothing after the slash, plus `-no-pass` - no credentials at
  all.
- `-usersfile` - candidate names (in a real intrusion these come from OSINT).
- `-request` - actually request the AS-REP (writes the 4768), not just check flags.

Output - every pre-auth-required account is rejected, only `svc-backup` yields a
hash, and the `23` is RC4 (0x17):

```
[-] User Administrator doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User jdoe doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User svc-sql doesn't have UF_DONT_REQUIRE_PREAUTH set
$krb5asrep$23$svc-backup@LAB.LOCAL:a19182a0...
```

## The 4768 it generates (from the DC)

```
A Kerberos authentication ticket (TGT) was requested.
    Account Name:           svc-backup
    Service Name:           krbtgt
    Client Address:         ::ffff:192.168.56.80
    Ticket Options:         0x50800000
    Result Code:            0x0
    Ticket Encryption Type: 0x17
    Pre-Authentication Type: 0
```

Confirmed on the DC with `Get-WinEvent` before touching the manager: the event is
written correctly, and `auditpol /get /subcategory:"Kerberos Authentication
Service"` reads `Success and Failure` - so the silence downstream is not an
auditing or generation problem.

## Custom rule 100601

```xml
<rule id="100601" level="12">
  <if_sid>60103</if_sid>
  <field name="win.system.eventID">^4768$</field>
  <field name="win.eventdata.preAuthType">^0$</field>
  <field name="win.eventdata.ticketEncryptionType">^0x17$</field>
  <description>AS-REP Roasting: RC4 no-preauth TGT for $(win.eventdata.targetUserName) requested from $(win.eventdata.ipAddress)</description>
  <mitre><id>T1558.004</id></mitre>
  <options>no_full_log</options>
  <group>asrep_roasting,pci_dss_10.2.4,gdpr_IV_35.7.d,</group>
</rule>
```

- `<if_sid>60103</if_sid>` - the crux, and simpler than Lab 02's dual parent. Since
  no shipped rule matches 4768, we chain off the nearest ancestor that *does* -
  the AUDIT_SUCCESS grouping parent the event actually reaches. There is no
  shadowing leaf to also register against, because nothing else matches.
- `preAuthType ^0$` - the primary discriminator. Normal accounts are `2`.
- `ticketEncryptionType ^0x17$` - the RC4 downgrade.

### Diagnosis method

`logall_json` was left **off** the entire lab. Rather than enable it and pay the
manager-starvation restart, the gap was diagnosed by reading the shipped rule chain
statically:

1. Roast fired, hash returned, **no alert**.
2. DC-side `Get-WinEvent` confirmed the 4768 exists with all four fields, and
   `auditpol` confirmed auditing is on - so it is not a generation problem.
3. `alerts.json` had **zero** 4768 alerts of any kind - a stronger tell than a
   shadow (a shadow still leaves loopback siblings alerting).
4. Reading the ruleset: `60106` omits 4768; nothing references 4768; `60103` is the
   only thing it hits, at level 0. Coverage gap, not a shadow.
5. Rule 100601 chained off `60103`. `wazuh-analysisd -t` clean (syntax only - it
   does not check reachability). Manager restarted (plain restart, `logall` still
   off, no starvation window). Re-fired -> **100601 fired, level 12.**

```
rule 100601  level 12
AS-REP Roasting: RC4 no-preauth TGT for svc-backup requested from ::ffff:192.168.56.80
preAuthType 0   ticketEncryptionType 0x17   T1558.004
```

## Detection results

| # | Stimulus | `preAuthType` | `enc` | Source | 100601 |
|---|---|---|---|---|---|
| 1 | AS-REP roast (impacket, RC4) | `0` | `0x17` | Kali (remote) | **Fires, level 12** |
| 2 | Same roast, `svc-backup` set AES-only (`msDS-SupportedEncryptionTypes=24`) | `0` | `0x17` (**still RC4**) | Kali (remote) | Fires - see below |
| 3 | Normal TGT for `jdoe` (`getTGT`, pre-auth performed) | `2` | `0x12` | Kali (remote) | No alert (pre-auth discriminator) |

**Specificity check:** across all traffic, exactly **3** genuine 100601 alerts
fired, **every one for `svc-backup`** - zero for `jdoe`, zero for any machine or
normal account. (A first count of "4" was a measurement artifact: a loose
`grep '"id":"100601"'` substring-matched an unrelated Kali `auditd` alert, rule
`80792` for `/usr/bin/ip`. The honest count comes from `jq 'select(.rule.id ==
"100601")'`, not a substring grep - the exact hygiene trap from Lab 02, repeated.)

**Row 3** isolates the primary discriminator cleanly: `jdoe`'s TGT request produces
the **identical event 4768** but with `preAuthType 2` (pre-auth was performed), so
100601 cannot match. Same event type, one field different, rule silent.

**Row 2 is a finding, not a clean cell.** Setting `svc-backup` to
`msDS-SupportedEncryptionTypes=24` (AES128+AES256, no RC4) - the exact move that
flipped Lab 02's Kerberoast to AES - **did not** force AES here. Three fires,
cache purged, and the DC event still read `0x17`. The account-level attribute
hardens the *TGS* (Kerberoasting, where the service account's key encrypts the
ticket) but not the *AS-REP*: the AS-REQ etype is **attacker-chosen** (impacket
requests RC4) and the account's RC4 key still exists, so the KDC keeps issuing RC4.
The only lever that removes RC4 from AS-REP is disabling it **domain-wide**
("Network security: Configure encryption types allowed for Kerberos"). The AES
evasion is therefore a *documented gap* rather than a fired negative control -
and the divergence from Kerberoasting is itself the sharper lesson.

## Notes, limitations, lessons learned

- **Coverage gap vs. shadow - two different causes of the same symptom.** A
  syntactically valid custom rule that never fires can mean two very different
  things. Lab 02: a level-0 sibling won the match and *shadowed* it (fix: chain off
  the shadowing leaf). Lab 03: **nothing matched the event at all** (fix: chain off
  the nearest matching ancestor, `60103`). You cannot tell which without reading the
  shipped chain - `60106`'s eventID list is the whole diagnosis. Same symptom,
  opposite root cause.
- **Kerberos's two roasting events are defended asymmetrically.** The shipped
  ruleset covers 4769 (via `60106`) but not 4768. The credential-free attack
  (AS-REP) is the one with no baseline coverage.
- **Account-level AES-only hardens Kerberoasting but not AS-REP roasting.** A
  non-obvious, empirically demonstrated divergence: `msDS-SupportedEncryptionTypes`
  gates the TGS etype but not the attacker-chosen AS-REQ etype while the RC4 key
  persists. Forcing AES on AS-REP requires disabling RC4 domain-wide. AES-roasting
  is thus a wider evasion surface here than in Lab 02.
- **AS-REP roasting is clock-independent.** No encrypted pre-auth timestamp means
  `KRB_AP_ERR_SKEW` never applies - unlike Kerberoasting, the attack fires
  regardless of attacker/KDC clock skew. One less prerequisite for the adversary.
- **`preAuthType = 0` is the account's signature; `0x17` is the attack's.** Keying
  on both is a deliberate cut: `preAuthType = 0` alone would also catch AES roasting
  but risks false positives from legitimate legacy no-preauth accounts (which should
  be alerted on anyway as misconfigurations). Production tuning: allowlist known
  pre-auth-disabled service accounts, or alert on `preAuthType = 0` regardless of
  encryption for the broader net.
- **`wazuh-analysisd -t` checks syntax, not reachability.** It confirmed 100601
  parsed while the event was still invisible to it. Only a live fire proves a rule
  matches.
- **Deployment hygiene - transfer bytes, do not paste them.** A base64 rule payload
  was corrupted in transit by Unicode homoglyphs (ASCII letters silently replaced by
  Cyrillic look-alikes); `base64 -d` choked mid-stream and appended a *truncated*
  block, breaking the XML (`End of file and some elements were not closed`). The fix
  was to `scp` the file and verify `md5sum` on both ends - byte-exact, no paste. Keep
  a `.bak` before any append.
- **Measurement hygiene, again.** Count alerts by `jq 'select(.rule.id=="X")'`, never
  a loose substring `grep` - the substring matched an unrelated auditd alert and
  inflated the count. This is the second module in a row the loose-grep trap has
  cost a miscount.

## Result
AS-REP roasting from a fully unauthenticated remote attacker is detected at level 12
on the DC's own 4768 telemetry, filling a **flat coverage gap** in the shipped
ruleset (no shipped rule matches event 4768). The `preAuthType = 0` discriminator is
verified by a normal-account negative control, and the RC4/AES boundary is
documented as an evasion gap after empirically establishing that account-level
AES-only does not harden AS-REP. Rule **100601** is live. Next: **Lab 04 - LDAP /
BloodHound reconnaissance** (events 4662/1644, rule 100602).
