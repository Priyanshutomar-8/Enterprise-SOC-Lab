# Lab 06A - Golden Ticket: the limits of log-based detection

## Objective
Take the `krbtgt` key stolen in Lab 05 and forge a **Golden Ticket** - a
Kerberos TGT minted offline by the attacker, signed with the domain's `krbtgt`
key, claiming any identity and any privilege. Then answer one question honestly:
**can a Golden Ticket be detected from Windows event logs at all?**

This is the capstone's investigation half. Its finding is a *negative* one, and
that is the point: the earlier labs in this module each ended in a firing rule; a
mature detection engineer also has to recognise the attacks where a clean
single-event signature **does not exist**, say so, and explain why. Lab 06B then
builds the pragmatic backstop that remains. No custom rule ships in 06A - like
Lab 04, the deliverable is the evidence and the reasoning.

## MITRE ATT&CK
| Field | Value |
|---|---|
| Tactic | Credential Access (TA0006) / Persistence |
| Technique | **T1558.001** - Steal or Forge Kerberos Tickets: Golden Ticket |
| Log source | Windows **Security** channel, event **4769** (Kerberos service-ticket request); event **4768** (TGT issuance) by its *absence* |
| Reference | https://attack.mitre.org/techniques/T1558/001/ |

## Environment
| Component | Details |
|---|---|
| Domain controller / target | `DC01` (Windows Server 2022), `lab.local`, 192.168.56.10, Wazuh agent **004** |
| Attacker | Kali + impacket (`ticketer`, `smbclient`, `getTGT`), 192.168.56.80, host-only |
| Manager | Wazuh 4.14.6 all-in-one, Ubuntu, 192.168.56.79 |
| Forging inputs | `krbtgt` NT hash `e4e62d01...` (Lab 05 DCSync) + domain SID `S-1-5-21-1510813927-2919259697-3260277280` |
| Custom rule | **none** (investigation) |

## How a Golden Ticket differs from every prior attack in this module

Kerberoasting, AS-REP roasting and DCSync all *ask the DC for something* and are
caught because the request is audited. A Golden Ticket is different in kind:

1. The attacker already holds the `krbtgt` key (from DCSync, Lab 05).
2. They **forge the TGT offline**, on their own machine. The KDC is never
   contacted to issue it, so **event 4768 - the TGT-issuance event - never fires.**
3. They present the forged TGT to request service tickets. *That* is the only step
   that touches the DC, and it emits **event 4769** like any normal service-ticket
   request.

So the entire on-DC footprint of a Golden Ticket is a 4769 that looks exactly like
a legitimate one, with the distinguishing event (the missing 4768) defined by its
*absence*. Everything below is the consequence of that.

## The attack

Forging is offline (`impacket-ticketer`); using it is a normal Kerberos exchange
(`impacket-smbclient -k`). The `krbtgt` NT hash and domain SID are the only inputs.

```bash
# Forge a TGT for the built-in Administrator, signed with the stolen krbtgt key
impacket-ticketer -nthash e4e62d01... -domain-sid S-1-5-21-1510813927-2919259697-3260277280 \
  -domain lab.local Administrator
export KRB5CCNAME=$PWD/Administrator.ccache
impacket-smbclient -k -no-pass lab.local/Administrator@dc01.lab.local
```

Two environment findings surfaced here before any detection work:

- **Clock skew is a hard gate.** The forged ticket carries timestamps from Kali's
  clock; the DC rejects anything outside +/-5 minutes with `KRB_AP_ERR_SKEW`. The
  lab's clocks are unmanaged (no NTP), so Kali had to be synced to the DC's UTC and
  the ticket re-forged before it was accepted. Same Kerberos-clock discipline as
  Lab 02.
- **The naive "fake superuser" Golden Ticket is dead on a patched DC.** Forging a
  ticket for a *non-existent* principal (`hackerman`) forged fine but was rejected
  on use with **`KDC_ERR_TGT_REVOKED`** - the post-2021 Kerberos hardening
  (CVE-2021-42287/42278 and follow-ups) makes the KDC verify the principal exists.
  **It also logged no 4769 at all** - the rejection happens at the KDC without a
  service-ticket audit event. So that variant is both *defeated* and *invisible*;
  a working Golden Ticket must forge a **real** account, which is what the rest of
  this lab uses.

## Measure-first: the golden 4769 beside a legitimate one

The measure-first discipline from Labs 04/05 applies with force here, because the
whole question *is* "is there a difference to key on?" A legitimate baseline 4769
(and the 4768 that accompanies it) was captured first, then the Golden Ticket was
fired and its 4769 pulled. Side by side:

| 4769 field | Legit Administrator | **Golden-ticket Administrator** | Usable discriminator? |
|---|---|---|---|
| `targetUserName` | `Administrator@LAB.LOCAL` | `Administrator@LAB.LOCAL` | no - identical |
| `serviceName` | `DC01$` | `DC01$` | no - identical |
| `ticketEncryptionType` | **`0x12` (AES256)** | **`0x12` (AES256)** | **no - identical (see below)** |
| `status` (Failure Code) | `0x0` | `0x0` | no - identical |
| `logonGuid` | populated | populated | no - both populated |
| `ipAddress` | `::1` (local) | `::ffff:192.168.56.80` (remote) | weak - lab-only |
| `ticketOptions` | `0x40810000` | `0x40810010` | fragile - impacket artifact |

The two events are, for practical purposes, **the same event**. The only fields
that differ are the client address (remote - but in a real domain admins get
service tickets from many hosts, so it is not anomalous) and a single ticket-option
bit that is an impacket client artifact, not a Golden Ticket property.

### Why the RC4 tell does not apply here
Kerberoasting (Lab 02) and AS-REP roasting (Lab 03) both keyed on
`ticketEncryptionType 0x17` (RC4). It is natural to expect the same here, since the
ticket was forged with the RC4 `krbtgt` hash. **It does not work**, and the reason
is important: the encryption type in a 4769 is the etype of the **service ticket**,
chosen from the *target service account's* supported types - here `DC01$`, which
supports AES - **not** the etype of the presented TGT. The forged RC4 TGT still
yields an **AES (`0x12`)** service ticket. Even forging with `-aesKey` changes
nothing. The RC4 discriminator that carried two earlier labs is structurally
unavailable for Golden Tickets.

## The only real signal is an absence - and Wazuh cannot express it

The textbook Golden Ticket detection is **"a 4769 with no preceding 4768"**: the
account presented a TGT the DC never issued, so a service-ticket request appears
with no corresponding TGT-issuance. That signal is real and it is present in this
lab's data - but two things make it uncatchable by a Wazuh rule.

**First, it is not a per-source count.** The obvious version - "count 4768 from the
attacker's IP" - fails, because the attacker host does legitimate Kerberos too.
Measured on DC01, the golden-ticket source (192.168.56.80) had:

```
4769 from 192.168.56.80 : 1     (the Golden Ticket)
4768 from 192.168.56.80 : 6     (NOT zero)
```

Those six TGTs break the naive rule - but their accounts tell the real story:

```
08/31  jdoe          08/31  svc-backup      08/31  svc-backup
08/31  svc-backup    08/31  svc-backup      08/31  jdoe
```

All six are `jdoe` / `svc-backup` from earlier labs' legitimate Kerberos - **not
one is `Administrator`.** So for the *forged principal specifically*, the TGT
issuance really is absent. The correct signal is therefore per-**principal**,
per-**ticket**, within the TGT's lifetime - "this Administrator 4769 has no
Administrator 4768 that could have issued its TGT."

**Second, that is a stateful *absence* correlation, and Wazuh's engine cannot do
it.** Wazuh is first-match-wins and stateless. Its only correlation primitives -
`if_matched_sid`/`if_matched_group` with `frequency`/`timeframe`, and `same_field`
- all fire on the **presence** of prior matching events, never on their absence.
There is no rule construct for "fire on B when A did *not* occur." The canonical
Golden Ticket analytic is an anti-join, and an anti-join is not something a
stateless rule engine can represent.

### The FP demonstration that proves it
To make the absence-signal concrete, a **legitimate** remote Administrator logon
was run (a real TGT obtained with the actual password via `impacket-getTGT`, then
reused). It is indistinguishable to any 4769-only rule - and now the distinguishing
event exists:

```
100604 alert count after legit logon : 2   (fired on BOTH the forgery and the legit auth)
legit Administrator 4768 from Kali    : 1   (was 0 at Golden-Ticket time)
```

The one event that separates the forgery from the real logon - a 4768 that exists
for the legit auth and never existed for the Golden Ticket - is exactly the event a
Wazuh rule cannot correlate against. (That count of `2` is rule 100604 from Lab 06B,
included here to close the argument.)

## What a stateful SIEM would do (Sentinel / KQL)
The same detection *is* expressible where the engine can join across event types
over a time window. In Sentinel:

```kql
let tgs = SecurityEvent | where EventID == 4769 | where TargetUserName !endswith "$";
let tgt = SecurityEvent | where EventID == 4768;
tgs | join kind=leftanti tgt on $left.TargetUserName == $right.TargetUserName
// a 4769 with no matching 4768 for that principal in the window
```

`join kind=leftanti` is precisely the anti-join Wazuh lacks. This is the concrete,
interview-ready contrast between a stateless log-matcher (Wazuh) and a stateful
analytics engine (Sentinel), and a direct SC-200 touch-point.

## Conclusion - why 06A ships no rule
A working Golden Ticket for a real privileged account produces a Security-log
footprint that is identical to legitimate activity on every field a single-event
rule can read; the one true discriminator is an *absence* that Wazuh's engine
cannot express. Shipping a "Golden Ticket rule" that claimed to detect the
technique on a single 4769 would be dishonest - it would either be the 06B tripwire
(which is a heuristic, not a signature, and is framed as such) or a false-confidence
signature. So 06A ships no rule and states the limit plainly. The real defences are
**upstream and structural**, not a 4769 signature:

- **Detect the DCSync that harvests `krbtgt`** - already built in Lab 05 (rule
  100603). That is the earlier, catchable kill-chain step.
- **Rotate `krbtgt` twice** to invalidate any forged tickets.
- **Protect and monitor privileged-account use**; treat RID-500 remote activity as
  worth review - the pragmatic backstop of Lab 06B.

## Status
**Complete (investigation).** Golden Ticket forged and used; real-account 4769
proven indistinguishable from legitimate; fake-account variant proven defeated and
unlogged on patched Server 2022; the RC4 tell proven inapplicable; the true signal
(missing 4768) proven to be an absence-correlation inexpressible in Wazuh, with the
Sentinel anti-join as the counterpart. No rule by design. Continues in **Lab 06B**,
which builds the honest heuristic tripwire that remains available.
