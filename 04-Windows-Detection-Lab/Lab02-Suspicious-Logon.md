# Lab 02 - Suspicious Logon Detection (T1078 / T1021.001)

## Objective
Surface a **successful** logon that carries elevated risk - specifically an
**administrative logon** (an account granted sensitive privileges at logon) -
so a defender sees *who* obtained admin rights, *from where*, and *when*.
Where Lab 01 caught the *failed*-logon burst of a brute force, Lab 02 catches
the *successful* privileged access that follows a compromise.

## MITRE ATT&CK
| Field | Value |
|---|---|
| Tactic | Defense Evasion, Persistence, Privilege Escalation, Initial Access |
| Technique | T1078 - Valid Accounts |
| Related | T1021.001 - Remote Services: RDP (documented, not deployed - see below) |
| Reference | https://attack.mitre.org/techniques/T1078/ |

## The two "suspicious logon" signals - and which is testable here
"Suspicious logon" on Windows has two high-value shapes:

| Signal | Event | Technique | Testable on this endpoint? |
|---|---|---|---|
| **Admin/privileged logon** | 4672 (special privileges assigned) | T1078 | **Yes** - deployed as 100401 |
| **RDP / RemoteInteractive** | 4624, LogonType **10** | T1021.001 | **No** - Win 11 **Home** cannot host RDP |

**Windows 11 Home has no Remote Desktop *host*** (RDP server is Pro/Enterprise
only), so a genuine `LogonType 10` cannot be produced on this endpoint. Per the
Lab 07 principle - *a detection you cannot verify against its target is worse
than a documented gap* - the RDP rule is **written up but not deployed**, rather
than shipped untested. It belongs on a Pro/Server endpoint:

```xml
<!-- Deploy on a Pro/Server RDP host, NOT verifiable on Win 11 Home -->
<rule id="100401" level="10">
  <if_sid>60106</if_sid>
  <field name="win.eventdata.logonType">^10$</field>
  <description>RDP / RemoteInteractive logon for $(win.eventdata.targetUserName) from $(win.eventdata.ipAddress) [T1021.001]</description>
  <mitre><id>T1021.001</id><id>T1078</id></mitre>
</rule>
```

The **deployed and verified** rule for this lab is the admin-logon detector below.

## The design decision: exclude the machine, keep the human
Event **4672** ("Special privileges assigned to new logon") fires whenever a
logon session receives sensitive privileges (SeDebugPrivilege, SeTcbPrivilege,
etc.) - i.e. an **admin-equivalent** logon. The naive rule "alert on 4672" is
useless, because **SYSTEM, LOCAL SERVICE, and NETWORK SERVICE trigger 4672
constantly** during normal operation. Alerting on all of them buries the signal.

So 100401 **excludes the service/machine identities** and keeps only
interactive *human* admin logons. Isolating the signal by removing the
built-in noise source is the same detection-engineering judgment as Lab 09
(which excluded `pam_unix(sudo:session)` so a root-session rule doesn't fire on
every `sudo`). Wazuh also ships **no dedicated 4672 rule**, so this is net-new
coverage, not a rebuild.

## Environment
| Component | Details |
|---|---|
| Endpoint | Windows 11 Home (agent, Wazuh v4.14.6, ID 002 `windows`) |
| Manager | Ubuntu Server, Wazuh 4.14.6 all-in-one |
| Log source | Windows Security channel (eventchannel) |
| Audit prereqs | `auditpol` - Logon **success** + **Special Logon** success |

## Prerequisites - enable success auditing (on the endpoint)
Lab 01 enabled Logon *failure* auditing (for 4625). Lab 02 needs **success**
auditing, plus the **Special Logon** subcategory that emits 4672:

```powershell
auditpol /set /subcategory:"Logon" /success:enable
auditpol /set /subcategory:"Special Logon" /success:enable
auditpol /get /subcategory:"Special Logon"     # must show: Success
```

Without Special Logon auditing, no 4672 is generated and the rule is silent.

## Detection rule (on the manager)
Added to `/var/ossec/etc/rules/local_rules.xml`.

```xml
<group name="local,windows,windows_security,authentication,">
  <rule id="100401" level="8">
    <if_sid>60103</if_sid>
    <field name="win.system.eventID">^4672$</field>
    <field name="win.eventdata.subjectUserName" negate="yes">^SYSTEM$|^LOCAL SERVICE$|^NETWORK SERVICE$</field>
    <description>Privileged (admin) logon: special privileges assigned to $(win.eventdata.subjectUserName) [T1078]</description>
    <options>no_full_log</options>
    <mitre><id>T1078</id></mitre>
  </rule>
</group>
```

Design notes:
- **Parent 60103** = Windows audit-success (no dedicated 4672 rule exists, so
  match `eventID 4672` under the success branch).
- **`negate="yes"` on `subjectUserName`** drops SYSTEM / LOCAL SERVICE /
  NETWORK SERVICE - the constant-noise source - and keeps human admin logons.
- **Level 8**, deliberately: an admin logon is *enrichment/context*, not a
  confirmed incident. It becomes actionable when correlated with *where from*
  (workstation / IP), *when* (off-hours), or a preceding brute force (Lab 01).
  Alerting an admin logon at level 12 would cry wolf on legitimate admin work.

## Attack simulation (on the endpoint)
Generate a fresh privileged logon session. `runas` performs an interactive
(type 2) logon as the admin account, which - being an administrator - is
assigned special privileges and emits 4672:

```powershell
runas /user:vboxuser "cmd /c exit"
# enter the account password when prompted; a cmd window flashes and closes
```

This produced **Event 4624 (LogonType 2)** + **Event 4672** for `vboxuser`.

## Detection results
Confirmed firing on live endpoint telemetry.

```
level:      8
id:         100401
description: Privileged (admin) logon: special privileges assigned to vboxuser [T1078]
agent:      windows (002)
subjectUserName: vboxuser
```

- Raw **4672** reached the manager for `subjectUserName: vboxuser`; 100401
  matched it once.
- **4624 (LogonType 2)** logons flowed alongside, confirming success auditing.
- 100401 fired **once, for the human admin logon only** - the SYSTEM/service
  exclusion is what prevents this rule from firing on Windows' constant
  machine-account 4672 traffic.

| Rule ID | Description | Severity | Result |
|---|---|---|---|
| 100401 | Privileged (admin) logon (4672, non-service) | Level 8 | **Confirmed firing** |

## Investigation steps
1. Open the **100401** alert - `subjectUserName` (which account got admin) and
   the agent (which host).
2. **Context is everything at level 8:** pull the paired **4624** for the same
   `targetLogonId` - the `LogonType` says *how* (2 = console, 10 = RDP, 3 =
   network) and `ipAddress`/`workstationName` says *from where*.
3. **Correlate backwards:** was there a preceding **4625** brute-force burst
   (Lab 01 / rule 100400) against this account? A brute force followed by a
   successful admin logon is a credential-compromise storyline.
4. **Time/context:** is this admin logon expected (a known operator, business
   hours, a change ticket) or anomalous (off-hours, unfamiliar source)?
5. If unauthorised: disable/reset the account, and hunt what the admin session
   did next (process creation, service installs - Labs 04+).

## Notes and limitations
- **RDP (LogonType 10) is not exercised here** - Win 11 Home cannot host RDP.
  The type-10 rule (above) is documented for a Pro/Server endpoint but not
  deployed, per the "don't ship an unverifiable detection" rule from Lab 07.
- **Level 8 is intentional.** This fires on legitimate admin logons too; it is
  a correlation input, not a standalone incident. Raising it to 4624+4672
  composite correlation (same `targetLogonId`) or scoping to off-hours/unusual
  source would raise fidelity - a good follow-on.
- **Success auditing must be on.** Only failure auditing was enabled in Lab 01;
  4672/4624 do not exist without the success + Special Logon subcategories.
- **`runas` uses the Secondary Logon service.** If it is disabled, the sim
  fails; a test-account + `LogonUser` (valid creds) is the fallback generator.

## Lessons learned
- Match the detection to what the endpoint can actually *prove*. RDP was the
  obvious "suspicious logon" pick, but a Home host can't produce it - so the
  verifiable, still-valuable admin-logon detector is what ships, and RDP is
  documented honestly.
- Noise exclusion is the whole rule. 4672 without the SYSTEM/service negate is
  an alert storm; the exclusion is the detection-engineering content (cf. Lab 09).
- Severity must match certainty. An admin logon isn't an attack - level 8 keeps
  it as context, not a false-alarm generator.

## MITRE ATT&CK mapping
```
Valid Accounts (T1078)
  |
  Event 4672 (special privileges assigned) --> Rule 100401  Level 8  [DETECTED]

Remote Services: RDP (T1021.001)
  |
  Event 4624 LogonType 10 --> rule documented, NOT deployed (Win 11 Home has no RDP host)
```

## Status
Complete - Rule 100401 (level 8) confirmed firing on a live Windows 11 endpoint:
a `runas` privileged logon produced Event 4672 for `vboxuser`, matched with the
SYSTEM/service noise excluded. The RDP / LogonType-10 detection (T1021.001) is
documented as a Pro/Server extension - not deployable on Win 11 Home, which
cannot host RDP.
