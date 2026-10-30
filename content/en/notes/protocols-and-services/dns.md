+++
title = 'DNS'
date = 2026-10-30
type = 'notes'
weight = 500
toc = true
tags = ['protocols', 'services', 'dns']
+++

DNS translates domain names to IP addresses and is the foundation of every other enumeration path — subdomain discovery feeds HTTP probing, zone transfers expose the entire internal namespace, and misconfigured records enable takeover and cache poisoning. It typically runs on **port 53 UDP**, with **TCP/53** used for large responses, DNSSEC, and zone transfers.

> **2025–2026 context:** zone transfers are **thirty years old and still misconfigured in 18% of enterprise DNS setups**, and a 2022 survey found **12% of organisations** had at least one nameserver allowing unauthorised AXFR. At the same time, **DNS rebinding has become a first-class vulnerability class** — Microsoft Playwright MCP Server (CVE-2025-9611), Glances (CVE-2026-32632), Rojo (RUSTSEC-2026-0279), and multiple Rust MCP servers were all rebindable in 2026. Cache poisoning returned with **BIND 9 CVE-2025-40778 (CVSS 8.6)** and the weak-PRNG **CVE-2025-40780**.

**Useful resources:**
- [HackTricks — Pentesting DNS](https://book.hacktricks.xyz/network-services-pentesting/pentesting-dns)
- [HackTricks — 53 Pentesting DNS (2026)](https://mintlify.wiki/HackTricks-wiki/hacktricks/network-services-pentesting/pentesting-dns) — includes DNSSEC auditing and recursion DDoS

---

## 1. DNS Records

| Record | Description |
|---|---|
| **A** | IPv4 address of the domain |
| **AAAA** | IPv6 address of the domain |
| **MX** | Responsible mail servers |
| **NS** | Nameservers (DNS servers) of the domain |
| **TXT** | Arbitrary text — Google Search Console validation, SSL validation, **SPF, DKIM, DMARC** |
| **CNAME** | Alias — one name points to another |
| **PTR** | Reverse lookup — IP to domain name |
| **SOA** | Zone information and the administrative contact email |
| **SRV** | Service location — `_ldap._tcp`, `_kerberos._tcp`, `_gc._tcp` (AD) |
| **CAA** | Which CAs may issue certificates for the domain |
| **NSEC / NSEC3** | DNSSEC proof of non-existence — **enumerable** |

---

## 2. Basic Interaction

| Command | Description |
|---|---|
| `dig ns <domain.tld> @<dns-ip>` | NS query against a specific nameserver |
| `dig any <domain.tld> @<dns-ip>` | ANY query — often filtered, but worth one attempt |
| `dig axfr <domain.tld> @<dns-ip>` | **AXFR (zone transfer)** against a nameserver |
| `dig +short <domain.tld>` | Compact A record output |
| `dig -x <ip> @<dns-ip>` | Reverse (PTR) lookup |
| `dig version.bind CHAOS TXT @<dns-ip>` | **Banner grab** — BIND version, if `version` is not hidden |
| `fierce --domain zonetransfer.me` | Zone transfer discovery |
| `fpdns <ip>` | DNS server fingerprinting |
| `nmap -n --script dns-nsid <ip>` | Nameserver ID disclosure |

**AD service records:**

```bash
dig -t _gc._tcp.lab.domain.com
dig -t _ldap._tcp.lab.domain.com
dig -t _kerberos._tcp.lab.domain.com
nmap --script dns-srv-enum --script-args "dns-srv-enum.domain='domain.com'"
```

---

## 3. Zone Transfer (AXFR)

A successful AXFR returns the **complete host inventory** of a domain — internal servers, naming conventions, subdomains, and infrastructure names that reveal function (`vpn`, `dc01`, `backup`).

### 3.1 Manual

```bash
# Without specifying a domain
dig axfr @<DNS_IP>

# With a domain
dig axfr @<DNS_IP> <DOMAIN>

# fierce
fierce --domain <DOMAIN> --dns-servers <DNS_IP>

# host
host -l <DOMAIN> <DNS_IP>
```

### 3.2 Automated — the 2026 tools

| Tool | What it adds |
|---|---|
| **`lupaxa-zone-transfer`** | Discovers authoritative NS records, resolves every IPv4/IPv6 address, and **tries AXFR against every discovered endpoint** |
| **`DNS-AXFR_SubdomainEnumerator`** | Attempts AXFR against one or more authoritative nameservers and enumerates owner names |
| **`dnsrecon -t axfr`** | Multi-technique enumeration — NS records, reverse lookups, and **zone transfers** |
| **Recursive AXFR bruteforcers** | Depth-limited recursive brute force that **attempts AXFR against each authoritative nameserver** in active mode |

```bash
# dnsrecon — full enumeration including AXFR
dnsrecon -d <domain.tld> -n <dns-ip> -t std,axfr

# lupaxa
lupaxa-zone-transfer --domain <domain.tld>
```

> **Zone transfer returns the entire namespace in one request** — it is the highest-value DNS finding, and the fix is a single `allow-transfer` directive in BIND.

---

## 4. Subdomain Enumeration

### 4.1 Passive sources

| Tool | Method |
|---|---|
| `subfinder -d test.com -v` | Aggregates dozens of passive sources |
| `sublist3r.py -d test.com` | Search engines, CT logs, DNSdumpster |
| `assetfinder --subs-only test.com` | Lightweight passive discovery |
| `curl -s "https://crt.sh/?q=%25.test.com&output=json" \| jq -r '.[].name_value'` | Certificate Transparency |

### 4.2 Active brute force — modern resolver stack

The 2026 pipeline replaces naive `for` loops with **wildcard-aware mass resolvers**.

| Tool | Role |
|---|---|
| **`massdns`** | High-performance C stub resolver for bulk lookups — the engine under most other tools |
| **`puredns`** | Fast resolver and bruteforcer that **accurately filters wildcard subdomains and DNS-poisoned entries** |
| **`dnsx`** | Multi-purpose DNS toolkit — user-supplied resolvers, brute force, reverse lookups, **wildcard filtering** |
| **`shuffledns`** | Go wrapper over massdns — active brute force with **wildcard filtering** and easy I/O |
| **`mksub`** | Generates the candidate list; feed it to `puredns` or `dnsx` |
| **`alterx`** | Target-specific permutation candidates for the resolver |

**puredns:**

```bash
# Brute force
puredns bruteforce wordlist.txt example.com --resolvers resolvers.txt

# Brute force multiple domains
puredns bruteforce all.txt -d domains.txt

# Resolve an existing list (dedupe + wildcard filter)
puredns resolve candidates.txt --resolvers resolvers.txt

# Pipe from stdin
cat wordlist.txt | puredns bruteforce domain.com
```

**dnsx:**

```bash
# Resolve a host list, show the answer
dnsx -l hosts.txt -resp -a

# Brute force with a wordlist, filter wildcards
dnsx -d example.com -w wordlist.txt -a -cname -wildcard-domain example.com

# Query every record type in one pass
dnsx -l hosts.txt -recon -json

# Enrich with ASN / CDN
dnsx -l hosts.txt -asn -cdn
```

**shuffledns:**

```bash
shuffledns -d example.com -w wordlist.txt -r resolvers.txt
```

> **Wildcard filtering is the difference between a usable list and 40,000 garbage hits.** A wildcard `*.example.com` makes every random name resolve; `puredns` and `dnsx` detect the pattern and strip it.

### 4.3 Subdomain fuzzing (HTTP-layer)

```bash
ffuf -w wordlist.txt:FUZZ -u https://FUZZ.server.com/
gobuster dns -d example.com -w wordlists.txt
```

### 4.4 VHost fuzzing — one IP, many sites

```bash
ffuf -w wordlist.txt:FUZZ -u http://academy.htb:PORT/ \
  -H 'Host: FUZZ.academy.htb' -fs <baseline-size>

gobuster vhost --url test.example \
  --wordlist /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt \
  --append-domain
```

### 4.5 Reverse DNS and reverse brute force

```bash
# Reverse lookup
dig -x 192.168.0.2 @<dns-ip>

# Reverse brute force a subnet
dnsrecon -r 127.0.0.0/24 -n <dns-ip>
dnsrecon -r <dns-ip>/24 -n <dns-ip>
dnsrecon -d active.htb -a -n <dns-ip>
```

> **If subdomains resolve to internal IPs, reverse DNS brute-force the entire range** — it uncovers hosts that have no forward record and therefore never appear in brute-force results.

### 4.6 DNSSEC NSEC walking

`nmap -sSU -p53 --script dns-nsec-enum --script dns-nsec3-enum <ip>` enumerates zones that use NSEC/NSEC3, revealing names the zone did not intend to disclose.

---

## 5. Modern DNS Reconnaissance (2025–2026)

### 5.1 enumdns — modular recon

`enumdns` resolves hosts from **wordlists, BloodHound files, and Active Directory environments**, and adds **threat analysis** with eight detection techniques — typosquatting, bitsquatting, homographic attacks, and malicious-domain detection.

```bash
enumdns recon -d test.com -o enumdns.txt
enumdns brute -d test.com -w /tmp/wordlist.txt -o enumdns.txt
enumdns resolve bloodhound -L /tmp/bloodhound_computers.json -o enumdns.txt
enumdns threat-analysis -d example.com --all-techniques -o threats.txt
```

**Features worth knowing:** auto-identification of cloud provider services, multi-record retrieval (CNAME/A/AAAA), SOA linking per zone, **AD domain controller enumeration**, and **SOCKS4/SOCKS5 proxy support**.

### 5.2 trident — keyless OSINT

A single binary with **no API keys, no registration, no configuration** — DNS lookups, ASN info, certificate transparency, threat intelligence, and PGP key search.

### 5.3 DNS-based OSINT via TXT records

Large-scale **TXT record analysis** uncovers hidden services and technology dependencies. The technique identified the **Drift service** across infrastructure in the August–September 2025 Salesloft breach.

```bash
dig txt <domain> +short | grep -i "verify\|site\|domain"
```

---

## 6. DNS Rebinding (2025–2026)

A DNS rebinding attack exploits the gap between the DNS resolution used for **validation** and the resolution used for the **actual fetch**. The attacker's domain first resolves to a public IP (passing any allowlist), then re-resolves to `127.0.0.1` or an internal address after the TTL expires.

### 6.1 The 2026 rebinding CVEs

| Advisory | Product | Primitive |
|---|---|---|
| **CVE-2025-9611 / GHSA-6FG3-HVW7-2FWQ** | Microsoft Playwright MCP Server < 0.0.40 | **Missing `Origin` header validation** — a malicious page rebinds and sends requests to the local MCP server |
| **CVE-2026-32632** | Glances < 4.5.2 | MCP endpoint rebindable — **same-origin policy stops protecting the API** once the browser considers the rebinding domain the origin |
| **RUSTSEC-2026-0279** | Rojo `rojo serve` | Unauthenticated localhost HTTP API — a developer visiting a malicious page gives **read/write access and local program execution** |
| **RUSTSEC-2026-0189** | `rmcp` < 1.4.0 | **No `Host` header validation** — rebinding to a loopback/private MCP server |
| **RUSTSEC-2026-0140** | dynoxide MCP transport | Rebinding via `rmcp` dependency + cross-origin CSRF |

### 6.2 Testing

**Precondition:** the target validates the **hostname** but not the **resolved IP** at request time — the classic TOCTOU.

```bash
# Public rebinding service
# https://lock.cmpxchg8b.com/rebinder.html

# Or host your own with a 1-second TTL alternating between
# a public IP and 127.0.0.1
```

> **The fix is DNS pinning** — resolve once, then use `CURLOPT_RESOLVE` (or the language equivalent) to force the same IP for the fetch. Validating the hostname without pinning the IP is not a defence.

---

## 7. Subdomain Takeover

A subdomain takeover occurs when a DNS record points to a service the organisation **no longer controls** — an unclaimed Heroku app, a deleted GitHub Pages repo, an expired S3 bucket.

### 7.1 Detection

```bash
# Nuclei — fastest and most comprehensive
nuclei -l all_subs_resolved.txt -t takeovers/ -o takeovers.txt

# subjack
./subjack -w all_subs_resolved.txt -t 100 -timeout 30 -o subjack.txt -ssl

# sub404
python3 sub404.py -f all_subs_resolved.txt

# Manual — check the CNAME, then visit the target
dig CNAME dev.target.com
```

### 7.2 Fingerprints

| Service | Fingerprint |
|---|---|
| **GitHub Pages** | "There isn't a GitHub Pages site here" |
| **Heroku** | "No such app" |
| **AWS S3** | "NoSuchBucket" |
| **Azure** | "404 Web Site not found" |
| **Shopify** | "Sorry, this shop is currently unavailable" |
| **Fastly** | "Fastly error: unknown domain" |
| **Tumblr** | "There's nothing here" |
| **UserVoice** | "This UserVoice subdomain is currently available" |
| **Ghost** | "The thing you were looking for is no longer here" |
| **Bitbucket** | "Repository not found" |
| **Zendesk** | "Help Center Closed" |
| **Desk.com** | "Sorry, We Couldn't Find That Page" |

### 7.3 The 2026 refinement — dangling cloud IPs

**A record pointing directly to a reusable cloud IP** is a takeover primitive even without a CNAME. The attacker obtains the same IP, and can then obtain **trusted TLS certificates** for the hostname and serve attacker-controlled content from it.

> **CVE-2026-54588 (Poweradmin)** chains **host-header injection** to **subdomain takeover** and **ACME DNS-01 abuse** — the takeover is not the end goal, it is the primitive that enables wildcard certificate issuance.

---

## 8. DNS Cache Poisoning (2025–2026)

| CVE | Product | Primitive |
|---|---|---|
| **CVE-2025-40778** | BIND 9 | **CVSS 8.6** — cache poisoning with **unsolicited RRs** — remote attacker injects forged records into the resolver cache |
| **CVE-2025-40780** | BIND 9 | **Weak PRNG** → cache poisoning |
| **CVE-2025-59023** | Recursor | **Crafted delegations or IP fragments** poison cached delegations |
| **CVE-2025-11411** | Unbound (OpenBSD) | Cache poisoning → domain hijacking |
| **CVE-2025-8677** | BIND 9 | Cache poisoning / DoS |

**Kaminsky-style attack precondition:** the resolver accepts **unsolicited RRs** for a name it did not query, or uses a **predictable transaction ID / source port**.

```bash
# Check the transaction-ID randomness and source-port randomness
nmap -n --script dns-random-txid <ip>
nmap -n --script dns-random-srcport <ip>
```

---

## 9. DNS Tunneling and Exfiltration

DNS is frequently the **only egress protocol allowed**, which makes it the channel of choice for data exfiltration and C2.

### 9.1 Detection signals

| Signal | Meaning |
|---|---|
| **High-volume TXT / NULL queries** | Classic tunneling record types |
| **Long, high-entropy subdomain labels** | Encoded payload |
| **Unusually frequent queries to one domain** | Beaconing |
| **Non-native tools making DNS queries** | `curl`, `osascript`, AppleScript with encoded subdomains — a MITRE ATT&CK detection |
| **Low-rate exfiltration** | Evades volume thresholds — requires per-query analysis |

### 9.2 Defensive tooling

**TunTight** is the first **in-path per-query DNS tunneling prevention** system — it detected **349 confirmed tunnels at the very first query** with negligible false positives or negatives.

---

## 10. Notable DNS CVEs (2025–2026)

| CVE | Product | Impact |
|---|---|---|
| **CVE-2026-85903** | Windows DNS Server (up to Server 2025) | **Null pointer dereference** — rated very critical |
| **CVE-2026-50487** | Windows DNS Client | **Use-after-free** — network attacker elevates privileges |
| **CVE-2026-19662** | BIND 9 | **DoS via crafted DNSSEC responses** |
| **CVE-2026-2291 / 4890 / 4891 / 4892** | dnsmasq | **DNS redirect, privilege escalation, heap manipulation** |
| **CVE-2025-59029** | DNS server | Assertion failure via crafted records → **ANY query DoS** |

---

## 11. Testing Methodology

```text
1. Banner and version
   - dig version.bind CHAOS TXT @<dns>
   - nmap --script dns-nsid

2. Zone transfer
   - dig axfr @<dns> <domain>
   - dnsrecon -d <domain> -n <dns> -t axfr
   - lupaxa-zone-transfer --domain <domain>

3. Subdomain enumeration
   - Passive: subfinder, crt.sh, assetfinder
   - Active: puredns bruteforce / dnsx -d -w / shuffledns
   - VHost: ffuf -H "Host: FUZZ.<domain>"
   - Reverse: dnsrecon -r <cidr>

4. DNSSEC walking
   - nmap --script dns-nsec-enum,dns-nsec3-enum

5. Takeover
   - nuclei -t takeovers/
   - Check CNAMEs and dangling A records to cloud IPs

6. Rebinding
   - Does the target validate resolved IP or only hostname?
   - Test with a 1-second TTL rebinding domain

7. Cache poisoning
   - nmap --script dns-random-txid,dns-random-srcport
   - Check whether unsolicited RRs are accepted

8. AD service records
   - dig -t _gc._tcp / _ldap._tcp / _kerberos._tcp
```

---

## 12. Hardening

| Control | How |
|---|---|
| **Restrict AXFR** | `allow-transfer { secondary-servers; };` in BIND — never `any` |
| **Disable recursion on authoritative servers** | Split-horizon: authoritative-only external, recursive internal |
| **Patch BIND / Unbound / Windows DNS** | CVE-2025-40778, CVE-2026-85903 |
| **DNSSEC** | Sign zones; validate at the resolver |
| **DNS pinning** | Resolve once, force the IP for the fetch — prevents rebinding |
| **`Host` header validation** | Reject non-loopback `Host` on localhost-bound services |
| **Remove dangling records** | Audit CNAMEs to third-party services; delete records pointing to unclaimed resources |
| **Monitor TXT / NULL volume** | Detect tunneling at the resolver |
| **SPF / DKIM / DMARC** | 81.6% of top 10M domains lacked a DMARC record; only **3.9% enforced reject** |

---

## 13. Field Notes

- **Zone transfers are still the highest-value DNS finding.** 18% of enterprise setups remain misconfigured, and one AXFR returns the entire internal namespace.
- **Wildcard filtering is what makes brute force usable.** `puredns` and `dnsx` strip wildcard noise; a raw `for` loop does not.
- **Reverse DNS brute force finds hosts that forward brute force cannot.** If subdomains resolve internally, sweep the IP range.
- **DNS rebinding is a 2026 growth area.** Playwright MCP, Glances, Rojo, and multiple Rust MCP servers were all rebindable — the common failure is **validating the hostname without pinning the IP**.
- **Dangling A records to cloud IPs are takeovers too** — not just CNAMEs, and they enable trusted TLS certificate issuance.
- **Poweradmin CVE-2026-54588 chains host-header injection → subdomain takeover → ACME DNS-01** — takeover as a primitive, not an end goal.
- **BIND cache poisoning returned in 2025.** CVE-2025-40778 (CVSS 8.6) and the weak-PRNG CVE-2025-40780 are the current resolver patches.
- **DNS is the egress channel of choice.** Long high-entropy labels, TXT/NULL volume, and non-native tooling are the detection signals — TunTight catches 349 tunnels at the first query.
- **81.6% of top domains lack DMARC, and only 3.9% enforce reject** — email spoofing is still largely open.
- **`enumdns` bridges DNS recon and AD** — it resolves hosts from BloodHound files and enumerates domain controllers directly.
