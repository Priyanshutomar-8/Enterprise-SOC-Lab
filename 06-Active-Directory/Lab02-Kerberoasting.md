# Lab 02 - Kerberoasting

## Objective
Detect Kerberoasting - the abuse of Kerberos service-ticket issuance to extract an
offline-crackable hash for a service account. Any authenticated domain user can
request the service ticket (TGS) for an account that carries a Service Principal
Name; that ticket is encrypted with the service account's password key, so the
attacker takes it offline and brute-forces the password with no further contact
with the domain controller.

The lab plants that attack on the `svc-sql` account created in Lab 01
(`MSSQLSvc/dc01.lab.local:1433`), runs the real attack from Kali + impacket, and
builds Wazuh rule **100600** on the resulting **4769** event. The interesting part
is not the rule - it is that a **shipped level-0 rule silently swallowed every
remote 4769**, and finding that shadow is the whole detection-engineering story.

## MITRE ATT&CK
| Field | Value |
|---|---|
| Tactic | Credential Access (TA0006) |
| Technique | **T1558.003** - Steal or Forge Kerberos Tickets: Kerberoasting |
| Log source | Windows Security channel, event **4769** (Kerberos Service Ticket Operations) |
| Reference | https://attack.mitre.org/techniques/T1558/003/ |

## Environment
| Component | Details |
|---|---|
| Domain controller / target | `DC01` (Windows Server 2022), `lab.local`, 192.168.56.10, Wazuh agent **004** |
| Attacker | Kali + impacket (`impacket-GetUserSPNs`), 192.168.56.80, host-only |
| Manager | Wazuh 4.14.6 all-in-one, Ubuntu, 192.168.56.79 |
| Roastable target | `svc-sql`, SPN `MSSQLSvc/dc01.lab.local:1433`, weak password (planted Lab 01) |
| Custom rule | **100600**, level 12 |

## The detection problem

Event 4769 is the noisiest event a domain controller produces - it fires on every
Kerberos service-ticket request, hundreds per hour, virtually all legitimate. You
cannot alert on "a 4769 happened." A roasting request differs from normal traffic
on two fields:

| Signal | Normal 4769 | Kerberoast 4769 |
|---|---|---|
| `ticketEncryptionType` | `0x12` (AES256) | `0x17` (RC4) - attackers downgrade; RC4 derives straight from the NTLM hash and cracks far faster than AES |
| `serviceName` | a machine account (`DC01$`, ends in `$`) | a **user** account carrying an SPN (`svc-sql`) |

A user account with an SPN, whose ticket is requested with RC4, is the definition
of a roastable target. That pair is what rule 100600 keys on.

### Gap in the shipped ruleset
`grep -rniE 'ticketEncryptionType|0x17|rc4' ruleset/rules/` returns **nothing** -
no shipped rule looks at encryption type at all. The only shipped 4769 handling is:

- `60106` (level 3, "Windows Logon Success") - child of `60103` (AUDIT_SUCCESS),
  matches `4624|4769|...` on **eventID only**.
- `60131` (level 5, "Windows DC Logon Failure") - the failure path.

So a granted Kerberoast ticket is scored as an ordinary **level-3 logon success**,
indistinguishable from a user opening a file share. That is the gap 100600 fills.

## The attack

Clocks first: Kerberos rejects any request skewed more than 5 minutes from the KDC
(`KRB_AP_ERR_SKEW`). These lab VMs run no NTP, so the attacker clock is synced to
the DC before firing.

```
impacket-GetUserSPNs lab.local/jdoe:'SummerLab#2026' -dc-ip 192.168.56.10 -request
```

- `lab.local/jdoe:...` - authenticate as an ordinary low-priv user (any domain
  user can roast; that is the point).
- `-request` - actually request the ticket, which writes the 4769.

Output - the `23` is RC4 (0x17), the crackable hash:

```
$krb5tgs$23$*svc-sql$LAB.LOCAL$lab.local/svc-sql*$...
```

## The 4769 it generates (from the DC, RC4)

```
Account Name:            jdoe@LAB.LOCAL
Service Name:            svc-sql
Client Address:          ::ffff:192.168.56.80
Ticket Encryption Type:  0x17
Failure Code:            0x0
```

Decoded on the manager: `decoder windows_eventchannel`, `severityValue
AUDIT_SUCCESS`, `eventID 4769`, `serviceName svc-sql`, `ticketEncryptionType 0x17`,
`ipAddress ::ffff:192.168.56.80`.

## Custom rule 100600

```xml
<rule id="100600" level="12">
  <if_sid>60106, 92651</if_sid>
  <field name="win.system.eventID">^4769$</field>
  <field name="win.eventdata.ticketEncryptionType">^0x17$</field>
  <field name="win.eventdata.serviceName" negate="yes" type="pcre2">\$$</field>
  <description>Kerberoasting: RC4 service ticket for user SPN $(win.eventdata.serviceName) requested by $(win.eventdata.targetUserName) from $(win.eventdata.ipAddress)</description>
  <mitre><id>T1558.003</id></mitre>
  <options>no_full_log</options>
  <group>kerberoasting,pci_dss_10.2.4,gdpr_IV_35.7.d,</group>
</rule>
```

- `^0x17$` - RC4 only. AES is `0x12` and is the overwhelming majority of legitimate
  traffic.
- `serviceName negate \$$` (pcre2) - exclude machine accounts (they end in `$`). A
  4769 for a **user** account with an SPN is the roastable case. This single line
  kills the false-positive flood.
- `<if_sid>60106, 92651</if_sid>` - the crux. Explained below.

## The shadow hunt (the real content of this lab)

The rule was deployed, syntax-checked (`wazuh-analysisd -t`, rule count 8946 -> 8947),
and the attack fired. **No alert.** The debugging that followed is the lab:

1. **The event reaches the manager.** Confirmed with `logall_json` -> `archives.json`:
   the RC4 4769 arrives, decodes as `windows_eventchannel`, all fields correct. Not
   a forwarding problem, not a decode problem.
2. **A normal 4769 alerts, the roast does not.** Every one of 26 genuine 4769 alerts
   in `alerts.json` was `0x12` for `DC01$`/`krbtgt` and hit `60106` at level 3. The
   `svc-sql`/`0x17` events produced no alert at any level.
3. **`wazuh-logtest` is useless here.** Pasted JSON (even the real event's
   `full_log`) decodes as the generic `json` decoder, never `windows_eventchannel`,
   because logtest cannot set `location: "EventChannel"`. It cannot replay the live
   rule path - live testing via `logall` is the only authority for these events.
4. **The shadow.** Enumerating children of `60106` found rule **92651** (level 0,
   "Successful Remote Logon", in `0840-win_event_channel.xml`):

   ```xml
   <rule id="92651" level="0">
     <if_sid>60106</if_sid>
     <field name="win.eventdata.ipAddress" type="pcre2">(?:[0-9]{1,3}\.){3}[0-9]{1,3}</field>
     <field name="win.eventdata.ipAddress" type="pcre2" negate="yes">127\.0\.0\.1</field>
   </rule>
   ```

   92651 matches **any** 4769/4624 from a remote IPv4 address (no eventID
   constraint) and downgrades it to **level 0**. It and the custom rule were both
   children of 60106; 92651 won the sibling evaluation and shadowed the custom rule,
   so the remote roast silently dropped to level 0 - no alert.

   The `DC01$` machine 4769s escaped because their `ipAddress` is `::1` (loopback):
   92651's IPv4 pattern does not match, 60106 stays at level 3, and they log.

5. **The fix** is the Module 05 pattern exactly: chain off the leaf that actually
   fires, not the semantic parent. `<if_sid>60106, 92651</if_sid>` registers 100600
   as a child of **both** - so a remote roast (60106 -> 92651) and a hypothetical
   local roast (60106, where 92651 does not match) both reach the custom rule and
   escalate to level 12.

After re-pointing the rule and re-firing, 100600 fired:

```
rule 100600  level 12
Kerberoasting: RC4 service ticket for user SPN svc-sql requested by jdoe@LAB.LOCAL from ::ffff:192.168.56.80
mitre T1558.003
```

## Detection results

| # | Stimulus | 4769 encryption | Source | 100600 |
|---|---|---|---|---|
| 1 | Kerberoast (impacket, RC4) | `0x17` | Kali (remote) | **Fires, level 12** |
| 2 | Same roast, RC4 disabled on `svc-sql` (AES) | `0x12` | Kali (remote) | No alert (evasion) |
| 3 | Machine TGS (`DC01$`) | `0x12` | loopback | No alert (26 natural events) |
| 4 | `krbtgt` TGS | `0x12` | loopback | No alert |

Row 1 vs row 2 isolates the RC4 discriminator: `svc-sql` was set to
`msDS-SupportedEncryptionTypes=24` (AES-only), the identical attack returned an
`$krb5tgs$18$` (AES) hash, and 100600 stayed silent while everything else was held
constant. Rows 3-4 confirm the machine-account and loopback exclusions from natural
DC traffic. The account was reverted to `0` after the test.

## Notes, limitations, lessons learned

- **Shadowing by a level-0 sibling is the recurring Module 05 lesson in a new
  place.** A custom rule that is syntactically correct and matches the event still
  never fires if a shipped sibling at level 0 wins the match first. The fix is
  always to chain off the shadowing leaf (`if_sid` accepts a comma list), never the
  semantic parent - and level does not decide the winner.
- **AES-roasting evades this rule** (demonstrated, row 2). Keying on `0x17` is a
  deliberate trade: alerting on all encryption types would drown in normal AES
  traffic. Detecting the common, high-value RC4 case is the right first cut;
  AES-roasting is a documented gap, not an oversight.
- **False-positive surface:** any legitimate application still requesting RC4
  tickets for a user-SPN account would trip this. Production tuning would allowlist
  known service accounts or pivot to a frequency/burst model (roasting tools request
  every SPN at once).
- **`wazuh-logtest` cannot replay eventchannel events** - it decodes pasted JSON as
  `json`, not `windows_eventchannel`, so it never traverses the `60103` chain.
  Syntax-check with `wazuh-analysisd -t`; prove logic against live events with
  `logall`.
- **Measure clean.** Two self-inflicted artifacts wasted time: the manager's own
  auditd logged the diagnostic `sudo grep svc-sql` commands (rule 5402) and they
  matched the grep; and rule 1002 ("Unknown problem") fired on placeholder data
  containing the substrings "attack" and "Failure". Use realistic test values and
  grep exact fields (`"serviceName":"svc-sql"`), not loose substrings.
- **Kerberos is clock-bound.** `KRB_AP_ERR_SKEW` blocks every attack until the
  attacker clock is within 5 minutes of the KDC. The lab VMs run no NTP;
  VirtualBox Guest Additions timesync silently corrected Kali to host time and
  overrode a manual `date -s`.

## Result
Kerberoasting from a remote attacker is detected at level 12 on the DC's own 4769
telemetry, with the RC4 + user-SPN discriminators verified by a four-cell matrix
including an encryption-isolated evasion boundary. Rule **100600** is live. Next:
**Lab 03 - AS-REP roasting** (event 4768, rule 100601).
