# Lab 01 - Domain Controller Deployment, AD Auditing, and Ingestion

## Objective
Stand up the first domain controller of a new Active Directory forest, populate
it with an attackable object, switch on the audit policy that actually writes
Kerberos and directory events, and enroll the DC into Wazuh so it ships its
Security channel to the manager.

Modules 04 and 05 built their detections on a single Windows 11 endpoint. Every
flagship Active Directory attack this module targets - Kerberoasting, AS-REP
roasting, DCSync, LDAP reconnaissance - leaves its fingerprint in events that
**only a domain controller produces**:

| Event | Written by | Attack it exposes |
|---|---|---|
| 4768 | KDC (Kerberos AS) | AS-REP roasting (Lab 03) |
| 4769 | KDC (Kerberos TGS) | Kerberoasting (Lab 02) |
| 4662 | Directory Service | DCSync / LDAP recon (Labs 04-05) |

No domain controller means those events exist nowhere in the lab. This lab builds
the sensor and the target the rest of Module 06 stands on. It writes **no custom
rule** - rule namespace **100600+** is reserved for the attack labs - so it ends
on a falsifiable check instead: confirm the DC is `Active` on the manager **and**
that its events are delivered into `alerts.json`, not merely forwarded.

## MITRE ATT&CK
The deployment itself maps to nothing; enabling the audit subcategories is what
makes the later techniques observable.

| Field | Value |
|---|---|
| Tactic | (foundation - no attack executed) |
| Related | T1558 Kerberos ticket abuse, T1003.006 DCSync, T1087 account discovery |
| Reference | https://attack.mitre.org/tactics/TA0006/ |

## Environment
| Component | Details |
|---|---|
| Domain controller | Windows Server 2022 Standard (Desktop Experience), Eval - agent ID **004** `DC01`, 192.168.56.10 |
| Forest / domain | `lab.local` (NetBIOS `LAB`), functional level Windows Server 2016 (`WinThreshold`) |
| Manager | Ubuntu Server, Wazuh 4.14.6 all-in-one, 192.168.56.79 |
| Attacker (later labs) | Kali + impacket, host-only, powered off for this lab |
| New log source | Windows `Security` event channel |
| Networking | NIC1 NAT (internet), NIC2 host-only 192.168.56.0/24 (lab wire) |

The endpoint runs **Windows Server 2022**, not the Windows 11 Home box from
Modules 04-05: Home cannot host a domain or even join one, so the earlier agent
could not carry this module at all.

## Build

The DC is built in six ordered phases. Order matters - each depends on the last.

### A - Rename before promotion
The hostname is baked into the DC's SPNs, DNS records, and NTDS identity, so it is
set **before** promotion, not after.

```powershell
Rename-Computer -NewName "DC01" -Restart
```

```
PS C:\> hostname
DC01
```

### B - Static IP on the host-only wire
A domain controller must have a static IP, and its DNS must point at itself
because it is about to become the domain's DNS server. The static address goes on
the **host-only** adapter; the NAT adapter keeps DHCP for internet.

Adapters are identified by **IP, never by name** - Windows enumerated the NAT
adapter as `Ethernet 2` and the host-only adapter as `Ethernet`, the reverse of
the interface order:

```powershell
Get-NetIPConfiguration
# Ethernet 2 -> 10.0.2.15   (NAT)
# Ethernet   -> 192.168.56.x (host-only)  <- static goes here

New-NetIPAddress -InterfaceAlias "Ethernet" -IPAddress 192.168.56.10 -PrefixLength 24
Set-DnsClientServerAddress -InterfaceAlias "Ethernet" -ServerAddresses 127.0.0.1
```

```
PS C:\> Test-Connection 192.168.56.79 -Count 2
Destination     : 192.168.56.79
Time(ms)        : 6
```

### C - Promote to domain controller
```powershell
Install-WindowsFeature AD-Domain-Services -IncludeManagementTools

Install-ADDSForest -DomainName "lab.local" -DomainNetbiosName "LAB" `
  -ForestMode "WinThreshold" -DomainMode "WinThreshold" -InstallDns `
  -SafeModeAdministratorPassword (Read-Host -Prompt "DSRM password" -AsSecureString) `
  -Force
```

Two warnings appear and are **expected** in an isolated lab: DNS delegation cannot
be created (no parent zone), and a legacy-cryptography compatibility note. The DC
reboots automatically; login is then `LAB\Administrator`. Verified:

```
PS C:\> nltest /dsgetdc:lab.local
           DC: \\DC01.lab.local
     Dom Name: lab.local
        Flags: PDC GC DS LDAP KDC TIMESERV WRITABLE DNS_DC DNS_DOMAIN DNS_FOREST ...
```

The `KDC`, `LDAP`, and `DNS_DC` flags confirm the Kerberos, directory, and DNS
services are live - the DC is now issuing tickets.

### D - Populate the directory and plant the Kerberoast target
```powershell
New-ADUser -Name "Jane Doe" -SamAccountName "jdoe" -UserPrincipalName "jdoe@lab.local" `
  -AccountPassword (ConvertTo-SecureString "<lab-password>" -AsPlainText -Force) -Enabled $true

# svc-sql gets a deliberately weak, human password so the Lab 02 offline crack succeeds
New-ADUser -Name "svc-sql" -SamAccountName "svc-sql" -UserPrincipalName "svc-sql@lab.local" `
  -AccountPassword (ConvertTo-SecureString "<weak-lab-password>" -AsPlainText -Force) `
  -Enabled $true -PasswordNeverExpires $true

setspn -S MSSQLSvc/dc01.lab.local:1433 svc-sql
```

```
PS C:\> Get-ADUser svc-sql -Properties ServicePrincipalName | Select ServicePrincipalName
ServicePrincipalName : {MSSQLSvc/dc01.lab.local:1433}
```

A user account carrying an SPN is the definition of a Kerberoastable target: any
authenticated domain user can request its service ticket, which returns encrypted
with the account's password hash. The deliberately human password makes the Lab
02 offline crack succeed, mirroring the real-world weakness.

### E - Enable the audit subcategories (the make-or-break step)
By default the KDC does not log ticket requests and the directory does not audit
object access. Without this, every attack in the module runs silently.

```powershell
auditpol /set /subcategory:"Kerberos Authentication Service"     /success:enable /failure:enable
auditpol /set /subcategory:"Kerberos Service Ticket Operations"  /success:enable /failure:enable
auditpol /set /subcategory:"Directory Service Access"            /success:enable /failure:enable
auditpol /set /subcategory:"Directory Service Changes"           /success:enable /failure:enable
auditpol /set /subcategory:"Credential Validation"              /success:enable /failure:enable
```

```
PS C:\> auditpol /get /category:"Account Logon","DS Access"
  Kerberos Service Ticket Operations       Success and Failure   <- event 4769
  Kerberos Authentication Service          Success and Failure   <- event 4768
  Directory Service Access                 Success and Failure   <- event 4662
```

On a production DC this is pushed through the Default Domain Controllers GPO; on
a single lab DC, local `auditpol` is immediate and sufficient. A later GPO refresh
can silently revert it, so `auditpol /get` is the first thing to re-check if
events ever go missing.

### F - Enroll the Wazuh agent
```powershell
# DNS forwarder so the DC resolves internet names, then pull the agent
Add-DnsServerForwarder -IPAddress 8.8.8.8
Invoke-WebRequest -Uri "https://packages.wazuh.com/4.x/windows/wazuh-agent-4.14.6-1.msi" `
  -OutFile "$env:TEMP\wazuh-agent.msi"

msiexec.exe /i "$env:TEMP\wazuh-agent.msi" /q `
  WAZUH_MANAGER="192.168.56.79" WAZUH_AGENT_NAME="DC01" WAZUH_REGISTRATION_SERVER="192.168.56.79"
Start-Service WazuhSvc
```

The default Windows agent config already ships the `Security` channel, so no
`ossec.conf` amendment is needed for this module's event sources.

## Detection results

Lab 01 writes no rule; the "detection" is proof of delivery, taken from the
manager, not the agent.

| Check | Command (on manager) | Result |
|---|---|---|
| Agent registered | `agent_control -l` | `ID 004 DC01 ... Active` |
| Agent metadata | `agent_control -i 004` | OS `Windows Server 2022`, client `v4.14.6`, keepalive current |
| Events **delivered** | `grep -ac DC01 alerts/alerts.json` | **399** (and climbing) |
| Enrollment listening | `wazuh-control status` | `wazuh-authd` + `wazuh-remoted` running, 1515/1514 listening |

`archives.json` shows `0` by design - `logall_json` is disabled from Module 05.
`alerts.json` is the channel that proves events are processed, not just forwarded.

## Notes, limitations, lessons learned

The build fought back at every layer; each failure is a real production mode.

- **Identify NICs by IP, never by name or order.** Windows named the NAT adapter
  `Ethernet 2` and the host-only adapter `Ethernet` - the reverse of the VirtualBox
  NIC order. Trusting the name put the static IP on the wrong adapter first.
- **Assigning a static IP silently disables DHCP on that adapter.** Removing the
  address does **not** re-enable it. This was the entire cause of the NAT adapter
  sitting on an APIPA `169.254.x` address with no internet - fixed with
  `Set-NetIPInterface -Dhcp Enabled` + `ipconfig /renew`.
- **Server 2022 hangs on a black screen at 100% CPU with the VBoxSVGA adapter.**
  The graphical installer runs on basic VGA and works; the hang begins the moment
  Windows loads its own VBoxSVGA driver. Switching the VM to the legacy **VBoxVGA**
  controller cleared it permanently.
- **Wazuh agent key-mismatch enrollment deadlock (the headline).** The agent first
  enrolled while the manager was still powered off, then again after it came up,
  leaving the manager and agent holding **different** keys. `wazuh-remoted` rejected
  every message with `(1408): Invalid ID 003 for the source ip: 192.168.56.10`, and
  the agent's attempts to self-heal were refused with `Duplicate name 'DC01' ...
  doesn't comply with the registration time to be removed`. Removing the stale
  agent with `manage_agents -r` cleared `client.keys` but authd still saw the name
  as a duplicate (the record persists in the agent database). The reliable fix was
  a **manual re-key**: add the agent on the manager, then write that exact
  `client.keys` line onto the agent so both sides match - which lets it connect
  with the pre-shared key and skip authd entirely. Final agent ID is **004**.
- **A DC's first boot is slow.** "Applying computer settings" lingered several
  minutes while SYSVOL, NETLOGON, DNS zones, and Group Policy initialized - normal
  on a RAM-tight host, not a hang (CPU stayed active).
- The manager being **powered off** (the host had rebooted between sessions)
  presented first as an empty dashboard and an SSH timeout - a reminder to verify
  the manager is running before debugging the agent.

## Result
A single-DC `lab.local` forest, an SPN-bearing service account, Kerberos and
directory auditing enabled, and `DC01` streaming its Security log into Wazuh as
agent 004. This is the foundation every remaining Module 06 lab attacks and
defends. Next: **Lab 02 - Kerberoasting** (rule 100600).
