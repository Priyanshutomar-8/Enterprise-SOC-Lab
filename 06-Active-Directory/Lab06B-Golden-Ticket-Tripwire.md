# Lab 06B - Golden Ticket: a pragmatic tripwire

## Objective
Lab 06A proved a Golden Ticket cannot be detected by a clean single-event
signature: a working ticket for a real account produces a 4769 identical to a
legitimate one, and the true signal (a missing 4768) is an absence-correlation
Wazuh's stateless engine cannot express. This lab builds the **honest backstop**
that remains - a low-fidelity **tripwire**, rule **100604**, that keys on the one
cheap, observable behaviour left: the built-in **Administrator** requesting a
service ticket from a **remote** host. It fires on the attack, stays silent on the
DC's own housekeeping, and - by design - also fires on a legitimate remote admin
logon. That last property is not a bug to hide; it is documented and demonstrated,
because a detection engineer who ships a heuristic must be clear about its ceiling.

## MITRE ATT&CK
| Field | Value |
|---|---|
| Tactic | Credential Access (TA0006) |
| Technique | **T1558.001** - Steal or Forge Kerberos Tickets: Golden Ticket |
| Log source | Windows **Security** channel, event **4769** |
| Reference | https://attack.mitre.org/techniques/T1558/001/ |

## Environment
| Component | Details |
|---|---|
| Domain controller / target | `DC01` (Windows Server 2022), `lab.local`, 192.168.56.10, Wazuh agent **004** |
| Attacker | Kali + impacket, 192.168.56.80, host-only |
| Manager | Wazuh 4.14.6 all-in-one, Ubuntu, 192.168.56.79 |
| Custom rule | **100604**, level **10** |

## Design: a tripwire, not a signature

Given 06A, the rule cannot claim to *identify* Golden Tickets. What it can do is
flag the behaviour a Golden Ticket most often exhibits and that is otherwise
unusual: the **built-in Administrator (RID 500) requesting a service ticket from
off-box**. In a mature domain RID 500 is rarely used interactively, still less for
remote service tickets, so a remote Administrator 4769 is worth a look - whether it
is a forged ticket or a real admin who should be using a named account. Two
discriminators:

- **`targetUserName` is the built-in Administrator** - the classic forge target;
  machine accounts (`$` suffix) never match `Administrator@`.
- **`ipAddress` is not loopback** - the request came from another host. Local DC
  operation (`::1`) is excluded so routine housekeeping stays silent.

### Chaining - the module's recurring first-match lesson
4769 successes are claimed by the shipped rule **92651** ("Successful Remote
Logon", `level="0"`), a child of **60106**. A standalone custom rule would be a
sibling, lose the first-match race, and never fire - the exact shadow that bit
Kerberoasting (rule 100600) earlier in the module. So 100604 chains off both:
`<if_sid>60106, 92651</if_sid>`.

### Calibration - level 10, deliberately
The high-confidence AD rules in this module (Kerberoasting 100600, DCSync 100603)
are level 12. This one is **level 10, one notch lower, on purpose**: severity should
track *confidence*, and this rule carries expected false positives. It is a review
signal, not a page. In production it would be raised to 12 only after allow-listing
the known admin jump hosts by source IP - at which point a remote RID-500 ticket
from anywhere *else* becomes high-confidence.

## Custom rule 100604

```xml
<group name="windows,active_directory,kerberos,">
  <rule id="100604" level="10">
    <if_sid>60106, 92651</if_sid>
    <field name="win.system.eventID">^4769$</field>
    <field name="win.eventdata.targetUserName" type="pcre2">(?i)^Administrator@</field>
    <field name="win.eventdata.ipAddress" negate="yes" type="pcre2">^(::1|127\.0\.0\.1|::ffff:127\.0\.0\.1)$</field>
    <description>Golden Ticket tripwire: built-in Administrator requested a Kerberos service ticket from remote host $(win.eventdata.ipAddress) for service $(win.eventdata.serviceName) [heuristic - T1558.001]</description>
    <mitre><id>T1558.001</id></mitre>
    <options>no_full_log</options>
    <group>golden_ticket,pci_dss_10.2.4,gdpr_IV_35.7.d,</group>
  </rule>
</group>
```

- `<if_sid>60106, 92651</if_sid>` - chained under the rules that claim a live 4769
  success (the reachability fix).
- `targetUserName` PCRE2 `(?i)^Administrator@` - the built-in admin, case-insensitive;
  excludes machine accounts by construction.
- `ipAddress` **negated** against the loopback set - fires only on off-box requests.

> Deployment note: the wrapper `<group name="...golden_ticket,">` used at deploy
> time duplicated the `golden_ticket` tag already on the rule, so the live alert's
> `groups` array shows it twice. Cosmetic only; the wrapper is set to
> `windows,active_directory,kerberos,` above to remove the duplicate.

Deployed the Lab-05 way - `scp` of the rule file + `md5sum` verified on both ends
(3223 bytes, `ebbc30f5...`), never a terminal paste (the Lab 03 homoglyph
corruption); appended to `local_rules.xml` after a dated backup; syntax-checked with
`wazuh-analysisd -t`; manager restarted (`logall_json` confirmed `no` first, to
avoid the archive-firehose starvation this manager has hit before).

## Detection results

Live-fire only - the sole proof that counts on a Windows channel (Lab 04's finding
that `wazuh-logtest` can match an event the live agent path never routes).

| # | Test | Expectation | Result |
|---|---|---|---|
| 1 | Golden Ticket (remote Administrator via forged TGT) | 100604 fires | **fired, level 10**, `ipAddress ::ffff:192.168.56.80`, decoder `windows_eventchannel` |
| 2 | DC's own local Administrator 4769 (`::1`, housekeeping) | **no** alert | **0** - loopback excluded; only the remote request fired |
| 3 | **Legitimate** remote Administrator logon (real TGT, real password) | **fires too** (documented FP) | **fired** - count rose to 2; rule cannot distinguish forged from real |

Test 2 is the negative control and it is inherent: DC01 emits local `::1`
Administrator 4769s continuously, and across the run 100604 fired only on the
remote request (`firedtimes:1` at that point). Test 3 is the honest limitation made
concrete - a real admin logon trips the identical rule.

The live alert on the Golden Ticket, abbreviated:

```json
"rule":{"level":10,"id":"100604",
  "description":"Golden Ticket tripwire: built-in Administrator requested a Kerberos service ticket from remote host ::ffff:192.168.56.80 for service DC01$ [heuristic - T1558.001]",
  "mitre":{"id":["T1558.001"],"tactic":["Credential Access"],"technique":["Golden Ticket"]}},
"agent":{"id":"004","name":"DC01"},
"data":{"win":{"system":{"eventID":"4769","channel":"Security"},
  "eventdata":{"targetUserName":"Administrator@LAB.LOCAL","serviceName":"DC01$",
    "ticketEncryptionType":"0x12","ipAddress":"::ffff:192.168.56.80","status":"0x0"}}}}
```

The false-positive test, side by side with the event that *should* distinguish it
but cannot be seen by the rule:

```
100604 alert count after the legit logon : 2   (forgery + legit auth both fired)
legit Administrator 4768 from Kali        : 1   (0 at Golden-Ticket time)
```

## Notes, limitations, lessons learned

- **This is a tripwire, not a Golden Ticket detector - say it out loud.** 06A
  proved the signature cannot exist on a single 4769. 100604 flags anomalous
  privileged-ticket *usage*; a forged ticket is one cause, a misbehaving admin is
  another, and the rule cannot tell them apart. Claiming it "detects Golden Tickets"
  would misrepresent it.
- **The documented FP is the honest core, and it is demonstrated, not asserted.**
  A real remote Administrator logon fired the same rule. That is acceptable for a
  level-10 review signal; it would not be acceptable at page severity without an
  allow-list.
- **Brittleness.** Keying on the name `Administrator` breaks if the built-in admin
  is renamed (a common hardening step). A production version would key on the
  well-known RID-500 SID instead - but 4769 does not expose the client SID (only the
  service SID), so on Wazuh this would need the SID surfaced another way. Documented,
  not pretended away.
- **Why not just alert on all remote 4769?** Volume - the DC issues service tickets
  constantly. Narrowing to the built-in admin from off-box is what keeps this a
  review-able signal rather than noise; the negative control (local housekeeping
  silent) is the evidence it worked.
- **The real defence is upstream.** Per 06A: catch the DCSync (Lab 05, rule 100603),
  rotate `krbtgt`. This tripwire is a late-stage backstop, and it is framed as one.

## Status
**Complete.** Rule 100604 deployed at level 10 and live-fired: true positive on the
forged ticket, silent negative control on local housekeeping, and a demonstrated
false positive on a legitimate remote admin logon - the ceiling of a heuristic,
documented rather than hidden. Together with **Lab 06A**, this closes Module 06:
the capstone ends on both an honest account of what log-based detection *cannot* do
against Golden Tickets and the pragmatic tripwire that remains.
