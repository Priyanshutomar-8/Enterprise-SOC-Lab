# Lab 02e - ASIM Normalization vs. Kerberos Detections

## Objective
Sentinel's **Advanced Security Information Model (ASIM)** promises source-agnostic
detections: write a rule once against a normalized schema such as `imAuthentication`, and it
runs over every source that has a parser. This lab asks whether that promise holds for the
three Kerberos detections built in Modules 06-07 and Labs 01-02d (Kerberoasting, AS-REP
roasting, Golden Ticket lead).

1. Does Microsoft's own Windows Authentication parser deliver Kerberos events at all?
2. If a custom parser carries them, can the detections be written in **normalized fields
   only**?
3. Does the parser give identical output from both Windows table layouts (`SecurityEvent`
   and `WindowsEvent`)?

**This is not a Sentinel deployment.** ADX free cluster, the 298 real DC01 4768/4769 events
from Lab 01b, batch evaluation (scheduling was covered in Lab 02c).

## Framing
| Field | Value |
|---|---|
| Discipline | Detection engineering - data normalization, parser development |
| ATT&CK | T1558.001 / .003 / .004 |
| Schema | ASIM Authentication 1.0.0 (Microsoft Learn, page last updated 09/17/2026) |
| Microsoft parser checked | `Parsers/ASimAuthentication/Parsers/ASimAuthenticationMicrosoftWindowsEvent.yaml`, parser Version 0.2.2, LastUpdated Sep 22, 2026 (Azure-Sentinel GitHub, read 2026-10-19) |
| Engine / cost | Azure Data Explorer free cluster / none |

## Part 1 - Microsoft's Windows parser drops every Kerberos event
The Microsoft parser's description reads "Windows Authentication events (4624, 4625, 4634,
and 4647)", and its first filter enforces it:

```kql
let LogonEvents=dynamic([4624, 4625]);
let LogoffEvents=dynamic([4634, 4647]);
...
| where EventID in (LogonEvents) or EventID in (LogoffEvents)
```

Applied to the replay data (**T1**): **0 of 298** events survive. Every event is a 4768 or
4769.

**Consequence:** a team that moves its Kerberos detections to `imAuthentication` to "go
source-agnostic" gets rules that save, run, and return nothing. No error. This is the same
failure mode as Lab 02 (events silently outside a window) and Module 05 (a rule that can
never match), at the schema layer.

## Part 2 - A custom Kerberos parser
Built as stored ADX functions in folder `Lab02e` (full text in
[`Lab02e-ASIM-Kerberos.kql`](Lab02e-ASIM-Kerberos.kql)):

| Function | Role |
|---|---|
| `SecurityEvent()` | Stand-in for the SecurityEvent table - Kerberos fields as columns |
| `WindowsEvent()` | Stand-in for the WindowsEvent table - fields only inside a dynamic `EventData` bag, as Microsoft's parser reads it (`EventData.ProcessName`) |
| `vimAuthenticationMicrosoftWindowsKerberos(starttime, endtime, disabled)` | ASIM filtering parser for 4768/4769, one branch per table, `union isfuzzy=true` - same structure as Microsoft's |

Mapping:

| ASIM field | 4768 (TGT) | 4769 (service ticket) |
|---|---|---|
| `EventType` | Logon | Logon |
| `EventResult` | Success if Status `0x0`, else Failure | same |
| `LogonProtocol` | Kerberos | Kerberos |
| `TargetUsername` / `TargetUsernameType` | as logged (`jdoe`) / **Simple** | as logged (`jdoe@LAB.LOCAL`) / **UPN** |
| `TargetAppName` | `krbtgt` | the service (`svc-sql`, `DC01$`, ...) |
| `SrcIpAddr` | `IpAddress` with `::ffff:` stripped | same |
| `EventOriginalType` | `4768` | `4769` |
| `AdditionalFields` | `TicketEncryptionType`, `PreAuthType` | same |

`TargetUsername` keeps the source's format, as the schema asks ("including domain information
when available"), and `TargetUsernameType` records which format it is.

**ADX trap:** in a `.create function` command, a parameter named `disabled` (ASIM's
standard parameter) is a **syntax error**: "A recognition error occurred". `flag:bool=false`
works. The parameter is quoted as `['disabled']` to keep the ASIM name.

## Part 3 - Tests
Predictions were written in the `.kql` file before the first run.

| # | Test | Predicted | Observed |
|---|---|---|---|
| T1 | Microsoft parser's EventID filter | 0 / 298 | **0 / 298** |
| T2 | Custom parser rows per layout | 93 x 4768 + 205 x 4769 | 93 (all Simple) + 205 (all UPN), both layouts |
| T3 | Rows present in one layout but not the other | 0 / 0 | **0 / 0** (298 each) |
| T4 | Golden Ticket lead joined on `TargetUsername` as normalized | many alerts | **31 alerts = every non-loopback service ticket**, 4 users |
| T5 | Golden Ticket lead on a normalized key + v1.1.0 `::1` exclusion | 2 per layout | **2**: 09-17 19:32:50 svc-sql (TP), 09-22 21:32:55 svc-sql (FP) - identical to Lab 02d |
| T6 | Both layouts unioned | 4, all duplicated | **4** |
| T7 | Kerberoast via `AdditionalFields.TicketEncryptionType` | 1 per layout | **1**: jdoe -> svc-sql |
| T8 | AS-REP via `AdditionalFields.PreAuthType` | 0 | **0** (no source events archived) |

### Finding T4 - normalization does not normalize the join key
The schema keeps usernames in their source format, so 4768 says `jdoe` and 4769 says
`jdoe@LAB.LOCAL`. A Golden Ticket rule written on `TargetUsername` matches **nothing**:
all 31 non-loopback service tickets look like forgeries. This is the Module 07 Lab 02
"normalization trap", and ASIM does not remove it. `TargetUsernameType` tells you the formats
differ; the rule still has to canonicalize the key itself. A SID would be the robust key,
but 4769 carries no user SID field.

### Finding T4b - "TGT issued" is not expressible in ASIM fields
The first T4 run defined the TGT side as `TargetAppName == "krbtgt"` and got **10** alerts,
not 31. The other 21 DC01$ tickets "found" a TGT. They had joined to **25 4769 events for
the `krbtgt` service** (TGT renewals/referrals). Those events share the `user@REALM` format,
so they matched even on the raw key.

In the normalized model, an AS exchange (4768, a TGT is *issued*) and a TGS request *for*
krbtgt (4769) both become `Logon` to `TargetAppName = krbtgt`. The schema has no field for
the Kerberos exchange type. On this data the two definitions give the same final 2 alerts.
In principle, though, a forged TGT that requests a krbtgt ticket would count as its own
"TGT seen" and mask itself. That was **reasoned, not tested** with a forged renewal. The
working rule uses `EventOriginalType == "4768"`, which is a source-specific value.

### Finding T6 - dual collection duplicates every alert
Microsoft's parser, and this one, union `SecurityEvent` and `WindowsEvent`. A host that
sends the same events to both (for example during an agent migration) produces every
normalized event twice and every alert twice. Nothing in the schema de-duplicates them.

## What is portable and what is not
| Detection | Normalized fields only? | What it still needs |
|---|---|---|
| Kerberoasting | No | `AdditionalFields.TicketEncryptionType` - a Windows value (`0x17`) |
| AS-REP roasting | No | `AdditionalFields.PreAuthType` - a Windows value (`0`) |
| Golden Ticket lead | No | `EventOriginalType` 4768 vs 4769 + a canonicalized user key |

**None of the three can be written purely in ASIM Authentication fields.** The parser gives a
common envelope (who, from where, to which service, success or failure), but every Kerberos
decision depends on a source-specific value inside it. ASIM still helps with the plumbing:
one rule body ran unchanged over both Windows table layouts. It does not make these
detections source-agnostic.

## Side observations from Microsoft's parser source (not tested)
- It maps logon type 8 to `EventSubType = 'NetworkCleartext'`. That value is not in the
  schema's allowed `EventSubType` list (System, Interactive, RemoteInteractive, Service,
  RemoteService, Remote, AssumeRole).
- It sets `EventSchemaVersion` to `'0.1.3'` (WindowsEvent branch) and `'0.1.0'`
  (SecurityEvent branch), while its header declares Normalization Version `'1.0.0'`.

Both are read from the source file, not run. They are recorded because a rule filtering on
these values would behave differently from what the schema page suggests.

## Known limitations
- **The two "tables" are stand-ins built from the same 298 rows.** T3 proves that the
  parser's two branches (column vs. dynamic-bag extraction) produce identical output. It
  does not prove that real SecurityEvent and WindowsEvent tables carry identical values.
- **The real SecurityEvent column set for 4768/4769 is still unverified** (as in Lab 02c).
  Microsoft's parser projects `IpAddress`, `TargetUserName`, `TargetDomainName`, `Status`
  and others as columns for 4624/4625. That confirms those columns exist, but not
  `TicketEncryptionType` or `PreAuthType`.
- **The 4768 user format is taken from this dataset** (bare name, with the domain in a field
  this replay table did not keep). A parser on real tables could build `DOMAIN\user`
  (`Windows` type) from `TargetDomainName`. The key still differs from 4769's UPN.
- **No forged-renewal test** for Finding T4b.
- **Batch only.** The ingestion-time scheduling from Lab 02c was not combined with the
  parser.

## Files
- Functions, tests and results: [`Lab02e-ASIM-Kerberos.kql`](Lab02e-ASIM-Kerberos.kql)
- Stored in ADX: `MyDatabase`, function folder `Lab02e`
