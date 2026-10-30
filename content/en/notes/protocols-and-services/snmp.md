+++
title = 'SNMP'
date = 2026-10-30
type = 'notes'
weight = 500
toc = true
tags = ['protocols', 'services', 'snmp']
+++

Simple Network Management Protocol (SNMP) is used to monitor and manage devices on a network — routers, switches, firewalls, printers, UPSes, and NAS appliances. It exposes device information through **Object Identifiers (OIDs)** organised in a **Management Information Base (MIB)** tree, and it frequently contains **logs, configuration, and credentials**.

**Ports:** **UDP/161** for agent queries, **UDP/162** for traps.

> **The most common reconnaissance failure is scanning only TCP.** SNMP is UDP-only. A TCP-only scan reports the host as having no SNMP service, and the entire attack surface is missed.

> **2025–2026 context:** SNMPv3 was supposed to fix the protocol, and a **19-agency joint advisory (AA26-194A, July 2026)** recommended upgrading to it after Russian FSB actors were observed exploiting weak SNMP configurations on critical-infrastructure routers. The **Malanta research** published two weeks later showed that the upgrade is **necessary but incomplete**: SNMPv3's pre-authentication exchanges leak the device vendor, **valid usernames**, and likely encryption settings **before a single credential is tested** — across **~470,000 internet-exposed devices**.

---

## 1. Versions and Their Security Posture

| Version | Authentication | Encryption | Attack surface |
|---|---|---|---|
| **SNMPv1** | Cleartext community string | None | Community bruteforce, full plaintext |
| **SNMPv2c** | Cleartext community string | None | Community bruteforce, full plaintext |
| **SNMPv3** | User + auth protocol (MD5/SHA) | Optional (DES/AES) | **Pre-auth username enumeration**, credential guessing |

> **Community strings are the entire authentication for v1/v2c.** `public` is read-only, `private` is read-write by convention — but the convention is frequently reversed or replaced with something equally guessable (`internal`, `cisco`, `manager`, `monitor`, `secret`, `ILMI`).

---

## 2. Enumeration

### 2.1 Discovery

```bash
# Always scan UDP — TCP will miss it
nmap -sU -p161,162 --open <target>

# Service fingerprint
nmap -sU -p161 -sV --script snmp-info <target>

# SNMPv3 engineID — leaks the vendor without credentials
nmap -sU -p161 --script snmp-info <target>
```

### 2.2 Community-string bruteforce

```bash
# onesixtyone — fastest first pass
onesixtyone -c /usr/share/seclists/Discovery/SNMP/common-snmp-community-strings.txt <target>

# Multiple targets
onesixtyone -i targets.txt -c communities.txt -o found.txt

# Nmap NSE
nmap -sU -p161 --script snmp-brute --script-args snmp-brute.communitiesdb=communities.txt <target>

# Hydra
hydra -P communities.txt -s 161 <target> snmp

# braa — mass OID querying with a known community
braa public@<target>:.1.*
```

**Common community strings:** `public`, `private`, `internal`, `manager`, `monitor`, `cisco`, `admin`, `secret`, `community`, `write`, `all`, `snmpd`, `default`, `ILMI`.

> **`public` and `private` are still the defaults on shipped appliances**, and **CVE-2025-12217** (Azure Access Technology BLU-IC2/BLU-IC4) is a 2025 example of a product shipping `public` as its default community. **CVE-2026-93338** (Grandstream GWN7660ELR) is a 2026 example of the same flaw.

### 2.3 Walking the tree

```bash
# Basic walk
snmpwalk -v2c -c public <target>

# Walk everything
snmpwalk -v2c -c public <target> .1

# Bulk walk — far faster on routers/switches
snmpbulkwalk -v2c -c public -Cr1000 <target> .1

# -Oa suppresses "Hex-STRING:" formatting so readable text is visible
snmpwalk -v2c -c public -Oa <target>

# Human-friendly enumeration (users, processes, software, ports)
snmp-check <target> -c public
snmp-check <target> -c public -v 2c

# Tabular MIB objects — more readable than a walk
snmptable -v2c -c public <target> hrSWRunTable
```

> **`snmp-check` is the single best first-pass tool** — it presents users, processes, installed software, listening ports, and shares in a readable format instead of a raw OID dump.

### 2.4 Useful OIDs

| OID | Data |
|---|---|
| `1.3.6.1.2.1.1.1.0` | `sysDescr` — OS and hardware description |
| `1.3.6.1.2.1.1.5.0` | `sysName` — hostname (writable with an RW community) |
| `1.3.6.1.4.1.77.1.2.25` | Windows local users |
| `1.3.6.1.2.1.25.4.2.1.2` | Running process names (`hrSWRunName`) |
| **`1.3.6.1.2.1.25.4.2.1.5`** | **Process command-line arguments** (`hrSWRunParameters`) — **passwords are frequently passed on the command line** |
| `1.3.6.1.2.1.25.6.3.1.2` | Installed software |
| `1.3.6.1.2.1.6.13.1.3` | TCP listening ports |
| **`NET-SNMP-EXTEND-MIB::nsExtendObjects`** | **Extended MIB objects** — custom script output, and an **RCE primitive** (§5) |

**Hunt for credentials in process arguments:**

```bash
snmpwalk -v2c -c public <target> 1.3.6.1.2.1.25.4.2.1.5 \
  | grep -iE 'pass|pwd|login|token|user|secret|key'
```

> **This is the highest-value single query on a Windows host.** Windows services and scheduled tasks routinely pass database passwords, service-account credentials, and API tokens as command-line arguments — and `hrSWRunParameters` exposes them in plaintext.

### 2.5 Write access (`snmpset`)

A read-write community (often `private`) allows modifying OIDs.

```bash
# Change the hostname
snmpset -v2c -c private <target> 1.3.6.1.2.1.1.5.0 s hacker

# Change the location
snmpset -v2c -c private <target> 1.3.6.1.2.1.1.6.0 s "pwned"
```

> **Changing SNMP values on a production device is disruptive.** On exam and lab targets, prefer read-only enumeration; use `snmpset` only when it is the demonstrated path.

---

## 3. SNMPv3 — The Pre-Authentication Leakage Problem

SNMPv3 replaced community strings with **users** and **authentication/privacy protocols**. The security levels are:

| Level | Authentication | Encryption |
|---|---|---|
| **`noAuthNoPriv`** | Username only | None |
| **`authNoPriv`** | Username + auth protocol | None |
| **`authPriv`** | Username + auth protocol | Encryption |

```bash
# authPriv — full security
snmpwalk -v3 -l authPriv -u <user> -a SHA -A '<auth-pass>' \
  -x AES -X '<priv-pass>' <target> .1

# authNoPriv — authentication only
snmpwalk -v3 -l authNoPriv -u <user> -a SHA -A '<auth-pass>' <target> .1
```

### 3.1 The 2026 pre-auth roadmap — Malanta research

SNMPv3's **engine discovery** and **USM Report** messages return **distinguishable responses before authentication succeeds**. Three signals chain together into a pre-login roadmap:

1. **The `engineID` reveals the device vendor and family.**
2. **The vendor narrows the likely authentication and privacy protocols** the device supports.
3. **USM Report messages confirm valid usernames** — an invalid user and a valid user produce different responses.

The result: a **multi-dimensional bruteforce** (unknown username × unknown protocol × unknown password) **collapses into a focused password guess** against a confirmed username and a narrowed protocol set.

> **This is standards-compliant and was confirmed as intentional by the IETF** — it is not a bug to be patched. It is a **design tradeoff**, and it means SNMPv3 is **not a complete fix** for SNMP exposure.

### 3.2 SNMPv3 tooling

```bash
# snmpwn — username enumeration and password guessing
./snmpwn.rb --hosts targets.txt --users users.txt \
  --passlist passwords.txt --enclist passwords.txt

# SNMPv3-Spray — full-coverage spray across every security level and
# auth/privacy protocol combination
# (most spray scripts assume a fixed security level — this one does not)
```

**SNMPv3-Spray** is the 2026 tool that addresses the protocol-combination problem directly: a device might reject `authNoPriv` outright and only accept `authPriv`, or use **SHA-256** instead of MD5/SHA — a spray that assumes one combination fails silently against it.

### 3.3 Cisco config exfiltration over SNMPv3

Once a **read-write SNMPv3 user** is recovered, Cisco's **config-copy MIB** can exfiltrate or merge the device configuration:

```bash
./config-dump.py -t 192.168.66.1 -a SHA -A 'AuthPass!' -x AES -X 'PrivPass!'
```

> **A read-write SNMPv3 user on a Cisco device is equivalent to administrative access** — the config-copy MIB downloads the running configuration, which contains every credential the device holds.

### 3.4 Shared USM keys

**GHSA-5754-6W67-33HX (Huawei openUBMC)**: the product ships a **default SNMPv3 USM key that uses one value for both authentication and privacy**. An attacker who holds the key can **authenticate and decrypt SNMPv3 traffic** — and SNMP access is mapped to **full device administration**, including system reset and firmware upgrade.

> **A shared USM key is worse than a weak password** — it is a per-product secret, so a single disclosure compromises every deployment.

### 3.5 Cisco SNMPv3 ACL truncation — CVE-2025-20151

Long `snmp-server user ... access <ACL>` lines can be **truncated on reload**, leaving the user **without the expected ACL** — allowing polling from sources that should be denied. The device appears correctly configured until it reboots.

---

## 4. Recent SNMP CVEs (2025–2026)

| CVE | Product | Primitive |
|---|---|---|
| **CVE-2025-68615** | **Net-SNMP `snmptrapd`** | **CVSS 9.8** — buffer overflow from a crafted trap packet, **unauthenticated**, leading to crash, privilege escalation, or information disclosure. Fixed in **5.9.5** and **5.10.pre2** (Dec 2025) |
| **CVE-2026-28775** | **International Datacasting SFX SuperFlex** | **CVSS 9.8** — **unauthenticated RCE** via `NET-SNMP-EXTEND-MIB` directives. The SNMP agent runs as **root**, and the bundled net-snmp is **pre-5.8** |
| **CVE-2026-89147** | **Net-SNMP ≤ 5.9.5.2** | **DoS** — `smux_accept()` performs an **unauthenticated blocking read without a timeout** |
| **CVE-2026-42924** | **F5 BIG-IP** | Authenticated **privilege escalation** — Resource Administrator creates SNMP configuration objects through **iControl SOAP** without proper authorisation checks (CWE-285) |
| **CVE-2025-12217** | Azure Access BLU-IC2/BLU-IC4 | **Default community string `public`** → unauthorised access |
| **CVE-2026-93338** | Grandstream GWN7660ELR | **Default community string `public`** → unauthenticated information disclosure |
| **CVE-2026-84193** | LibreNMS ≤ 26.2.0 | **Stored XSS** — SNMP-sourced data (BGP peer descriptions, VRF names, process info) rendered unescaped |
| **GHSA-5754-6W67-33HX** | Huawei openUBMC | **Default SNMPv3 USM key** shared between auth and privacy → full device admin |

> **The split in the 2026 CVE feed is informative.** The **critical** findings are in **Net-SNMP** and **embedded appliances** (`snmptrapd` 9.8, IDC 9.8) — not in the protocol. The **default-community-string** findings (CVE-2025-12217, CVE-2026-93338) are shipping-product defects, not configuration mistakes.

---

## 5. `NET-SNMP-EXTEND-MIB` — The RCE Primitive

`NET-SNMP-EXTEND-MIB::nsExtendObjects` exposes the output of **custom scripts** configured in `snmpd.conf`. On a misconfigured device, this is a **command-execution channel**.

### 5.1 Reading extend output

```bash
snmpwalk -v2c -c public <target> NET-SNMP-EXTEND-MIB::nsExtendObjects
```

If the administrator has configured an extend directive that runs a shell command, this returns the command's output — **unauthenticated** if the community string is known.

### 5.2 Writing an extend directive

If the community is **read-write**, `nsExtendConfigTable` can be modified to **add a new extend directive** — and the agent executes it.

**CVE-2026-28775** is exactly this: an unauthenticated attacker uses `NET-SNMP-EXTEND-MIB` directives to execute arbitrary OS commands **as root**, because the SNMP agent runs as root and the bundled net-snmp is pre-5.8.

> **`nsExtendObjects` is not just an enumeration target — it is an RCE target on read-write devices.** Always test write access with a harmless OID first (`sysName`), then decide whether to modify `nsExtendConfigTable`.

---

## 6. Tooling

| Tool | Purpose |
|---|---|
| **`snmp-check`** | Human-readable enumeration — users, processes, software, ports, shares |
| **`onesixtyone`** | Fastest community-string scanner — async `sysDescr` requests |
| **`snmpwalk` / `snmpbulkwalk`** | OID walking — `bulkwalk` for speed |
| **`snmptable`** | Tabular MIB objects — far more readable than a raw walk |
| **`braa`** | **Mass** SNMP scanner — dozens or hundreds of hosts in one process |
| **`snmpwn`** | SNMPv3 username enumeration and password guessing |
| **`SNMPv3-Spray`** | Full-coverage spray across **every** security level and auth/privacy combination |
| **`config-dump.py`** | Cisco config exfiltration over SNMPv3 |
| **`gosnmptk`** | Go toolkit — GET/WALK/BULK, vendor fingerprinting, GUI |
| **`fingerprintx`** | Service fingerprinting — identifies SNMP alongside other services |
| **Nmap `snmp-*` NSE** | `snmp-brute`, `snmp-info`, `snmp-interfaces`, `snmp-sysdescr` |

---

## 7. Hardening

| Control | How |
|---|---|
| **Upgrade to SNMPv3** | Necessary but **not sufficient** — the pre-auth leakage remains |
| **Use `authPriv` everywhere** | `authNoPriv` still sends data in plaintext |
| **Replace default community strings** | Never ship `public` or `private` — CVE-2025-12217, CVE-2026-93338 |
| **Use unique, long community strings** | No dictionary words, no vendor names |
| **Restrict to a management VLAN** | Never expose 161/162 to the internet — the 470k exposed endpoints in the Malanta research are the result of exactly this |
| **ACL on the SNMP agent** | `rocommunity public 10.0.0.0/8` — restrict by source |
| **Do not run `snmpd` as root** | Limits the impact of `nsExtendObjects` RCE |
| **Remove extend directives you do not need** | `NET-SNMP-EXTEND-MIB` is an RCE primitive |
| **Patch Net-SNMP** | CVE-2025-68615 (9.8), CVE-2026-89147 |
| **Disable SNMP if it is not used** | The only complete fix |
| **Restrict `snmptrapd`** | CVE-2025-68615 — do not expose trap reception broadly |
| **Monitor SNMP config changes** | CVE-2026-42924 — SNMP objects created via iControl SOAP are a persistence vector |

---

## 8. Testing Methodology

```text
1. Discover — UDP only
   - nmap -sU -p161,162 --open <target>
   - nmap -sU -p161 --script snmp-info    (engineID → vendor)

2. Community strings (v1/v2c)
   - onesixtyone -c common-snmp-community-strings.txt
   - Try: public, private, internal, cisco, manager, monitor, secret, ILMI

3. Enumerate with a working string
   - snmp-check <target> -c <string>
   - snmpwalk -v2c -c <string> <target> .1
   - snmpwalk ... 1.3.6.1.2.1.25.4.2.1.5 | grep -i pass   (cmdline creds)

4. SNMPv3
   - If v1/v2c fails, v3 may still be present
   - engineID → vendor; USM Report → valid usernames
   - snmpwn / SNMPv3-Spray across every security level
   - Recover RW user → Cisco config-dump

5. Write access
   - snmpset ... sysName s test
   - If RW: NET-SNMP-EXTEND-MIB for RCE (CVE-2026-28775 class)

6. Patch level
   - Net-SNMP ≥ 5.9.5 / 5.10.pre2   (CVE-2025-68615, CVSS 9.8)
   - Check for default community strings (CVE-2025-12217, CVE-2026-93338)
```

---

## 9. Field Notes

- **UDP/161 is the service people forget to scan.** A TCP-only scan reports no SNMP and misses the entire attack surface.
- **`snmp-check` is the best first pass** — it renders users, processes, software, and ports in a readable format instead of a raw OID dump.
- **`hrSWRunParameters` (`1.3.6.1.2.1.25.4.2.1.5`) is the highest-value query on Windows** — process command lines routinely contain database passwords and service credentials.
- **`public` and `private` are still shipping defaults in 2026** — CVE-2025-12217 and CVE-2026-93338 are both current examples.
- **`NET-SNMP-EXTEND-MIB` is an RCE primitive, not just enumeration.** CVE-2026-28775 (CVSS 9.8) is an unauthenticated root RCE through extend directives on a device running net-snmp pre-5.8.
- **CVE-2025-68615 is a CVSS 9.8 unauthenticated buffer overflow in `snmptrapd`** — do not expose trap reception broadly; patch to 5.9.5 or 5.10.pre2.
- **SNMPv3 is necessary but not sufficient.** The Malanta research shows the pre-auth exchanges leak the vendor and **confirm valid usernames** before authentication — validated across ~470,000 internet-exposed devices.
- **The IETF considers the SNMPv3 pre-auth leakage intentional.** It is a design tradeoff, not a bug — do not expect a patch.
- **SNMPv3-Spray exists because most spray scripts assume one security level.** A device that only accepts `authPriv` with SHA-256 will silently reject a spray that assumes `authNoPriv` with MD5.
- **A read-write SNMPv3 user on Cisco is administrative access.** The config-copy MIB downloads the running configuration, which contains every credential the device holds.
- **CVE-2025-20151 truncates long SNMPv3 ACL lines on reload** — the device appears correctly configured until it reboots, then accepts polling from sources that should be denied.
- **Do not run `snmpd` as root.** It is the difference between an extend-directive read and a root RCE.
