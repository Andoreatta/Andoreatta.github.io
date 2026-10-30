+++
title = 'Information Gathering'
date = 2026-10-30
type = 'notes'
weight = 10
toc = true
tags = ['web', 'recon', 'osint']
+++

Reconnaissance in 2025–2026 is a **pipeline**, not a collection of individual commands. The modern workflow moves from passive archive sources → active resolution → live probing → crawling → content discovery → vulnerability scanning, with each stage feeding the next. This file covers both the classic techniques and the tools that have become standard since 2024.

---

## 1. Passive Information Gathering & OSINT

These techniques refer to gaining information from publicly available sources. By doing so, the attacker gains information about the target **without any active scanning** — the target is never aware that information is being obtained.

### External resources

- [OSINT Cheatsheet](https://www.cheatsheet.wtf/OSINT/)
- [Compass Security OSINT Cheat Sheet](https://www.compass-security.com/fileadmin/Research/White_Papers/2017-01_osint_cheat_sheet.pdf)
- [OSINT Packet 2019](https://bigdata-ir.com/wp-content/uploads/2021/02/OSINT_Packet_2019.pdf)

---

## 2. Google Dorks

Google’s crawling capabilities can find exposed files, scripts, and critical resources in web applications.

- [Google Hacking Database (Exploit-DB)](https://www.exploit-db.com/google-hacking-database)
- [Pentest-Tools Google Hacking](https://pentest-tools.com/information-gathering/google-hacking)
- [FreeCodeCamp Google Dorking Tutorial](https://www.freecodecamp.org/news/google-dorking-for-pentesters-a-practical-tutorial/)

### Generic queries

```
site:*.target.com intext:uncaught
site:*.target.com intext:error
site:*.target.com intext:parameter
site:*.target.com intext:missing
site:*.target.com intext:"stack trace"
site:*.target.com intext:php
site:*.target.com intext:jsp
site:*.target.com intext:asp
site:*.target.com intext:include_path
site:*.target.com intext:undefined
site:*.target.com intext:sql
site:*.target.com intext:invalid
site:*.target.com intext:exception
site:*.target.com intext:fatal
site:*.target.com intext:CONFIG
site:*.target.com intext:login
site:*.target.com intitle:"index of"
site:*.target.com inurl:prod
site:*.target.com inurl:&
site:*.target.com inurl:dev
site:*.target.com inurl:staging
site:*.target.com inurl:stg
site:*.target.com inurl:debug
site:*.target.com inurl:admin
site:*.target.com inurl:internal
```

### Apache services

```
site:*.target.com intitle:"apache tomcat/"
site:*.target.com "Apache Tomcat examples"
site:*.target.com intext:"apache"
site:*.target.com intitle:"Solr Admin"
site:*.target.com intext:"This is the default welcome page used to test the correct operation of the Apache2 server"
site:*.target.com intitle:"index of" "powered by apache "
site:*.target.com intext:"Apache server status for"
site:*.target.com intitle:"Apache2 Ubuntu Default Page: It works"
site:*.target.com intitle:"WAMPSERVER homepage" "Server Configuration" "Apache Version"
site:*.target.com intitle:"Test Page for the Apache HTTP Server"
```

### Files

```
site:*.target.com ext:txt
site:*.target.com ext:php
site:*.target.com ext:php5
site:*.target.com ext:phtml
site:*.target.com ext:xhtml
site:*.target.com ext:key
site:*.target.com ext:pem
site:*.target.com ext:ovpn
site:*.target.com ext:log
site:*.target.com ext:asp
site:*.target.com ext:aspx
site:*.target.com ext:jsp
site:*.target.com ext:dat
site:*.target.com ext:yml
site:*.target.com ext:bak
site:*.target.com ext:zip
site:*.target.com ext:yaml
site:*.target.com ext:json
site:*.target.com ext:xml
site:*.target.com ext:env
site:*.target.com ext:conf
site:*.target.com ext:ini
site:*.target.com ext:cfg
site:*.target.com ext:cgi
site:*.target.com ext:ccm
site:*.target.com ext:sql
site:*.target.com ext:cdx
site:*.target.com ext:ics
```

### GraphQL queries

```
site:*.target.com intext:"GRAPHQL_PARSE_FAILED"
site:*.target.com intext:"GRAPHQL_VALIDATION_FAILED"
site:*.target.com intext:"BAD_USER_INPUT"
site:*.target.com intext:"UNAUTHENTICATED"
site:*.target.com intext:"FORBIDDEN"
site:*.target.com intext:"PERSISTED_QUERY_NOT_FOUND"
site:*.target.com intext:"PERSISTED_QUERY_NOT_SUPPORTED"
site:*.target.com intext:"INTERNAL_SERVER_ERROR"
```

---

## 3. Certificate Transparency & Passive Domain Enumeration

### Crt.sh — certificate transparency

```bash
# Download JSON
curl -s "https://crt.sh/?q=test.com&output=json" | jq .

# Extract unique subdomains
curl -s "https://crt.sh/?q=test.com&output=json" \
  | jq -r '.[] | "\(.name_value)\n\(.common_name)"' \
  | sort -u
```

### Passive subdomain tools

| Command | Description |
|---|---|
| `subfinder -d $TARGET -all -recursive -o subs_subfinder.txt` | Passive aggregation across dozens of sources; `-recursive` improves coverage  |
| `amass enum -passive -d $TARGET` | Passive subdomain enumeration with Amass |
| `assetfinder --subs-only $TARGET` | Lightweight passive discovery |
| `findomain -t $TARGET` | Fast passive discovery (Rust) |
| `theHarvester -d $TARGET -b source` | Search multiple sources for subdomains and emails |

### Infrastructure identification

| Resource | Description |
|---|---|
| Netcraft | https://searchdns.netcraft.com/ |
| VirusTotal | https://www.virustotal.com/gui/home/url |
| Censys | https://censys.io/ |
| Shodan | `shodan host <IP>` for each resolved IP |
| WayBack Machine | http://web.archive.org/ |
| `waybackurls -dates https://$TARGET > waybackurls.txt` | Historical URLs with dates |

### Automated OSINT frameworks (2025–2026 status)

| Framework | Style | Notes |
|---|---|---|
| **BBOT** | Recursive pipeline, YAML presets | **Preferred maintained OSS automation** — fast passive enum, recursive  |
| **Recon-ng** | Workspace + modules | “Metasploit for OSINT” — modular, scriptable  |
| **SpiderFoot** | Event-driven modules | **Open-source edition effectively abandoned** since the Intel 471 acquisition (no releases in 2+ years); capability moved to commercial TITAN. Prefer BBOT or Recon-ng  |
| **sn0int** | Rust engine | Modules as packages  |
| **sn1per** | Orchestrator | Runs 90+ underlying tools in a full passive-then-active chain into a named workspace  |

---

## 4. The Modern Reconnaissance Pipeline (2025–2026)

The single most important change in recent years is that **recon is chained**. The standard pipeline is:

```
subfinder (passive) → shuffledns/puredns (active brute + resolve) → dnsx (validate)
→ httpx (live hosts) → katana + gau + waybackurls (URLs) → ffuf/feroxbuster (content)
→ nuclei (vulnerability scan)
```

A minimal implementation :

```bash
subfinder -d target.com -all | anew subs.txt
shuffledns -d target.com -r resolvers.txt -w subdomains-huge.txt | anew subs.txt
dnsx -l subs.txt -a -resp | tee resolved.txt
httpx -l subs.txt -ports 80,443,8080,8443 -title -tech-detect -o live.txt
```

> **Key principle:** every stage **feeds** the next, and every stage **filters** — raw archive output for a large target is hundreds of thousands of URLs, most of them images, fonts, and near-identical paginated variants. Reducing that to a few thousand distinct, parameterised, live endpoints is most of the work .

---

## 5. Active Subdomain Enumeration — DNS Resolution and Brute Force

### Why `puredns` replaced naive brute force

Wildcard DNS makes every random name resolve, so a naive brute-force fills with junk. **`puredns`** wraps `massdns` and adds a **wildcard-detection algorithm** that strips wildcard hits and poisoned answers, so the survivors are names that resolve for real .

```bash
# Resolve an existing list
puredns resolve subdomains.txt -r resolvers.txt -w resolved.txt

# Brute force with wildcard filtering
puredns bruteforce subdomains-top1million-110000.txt target.com -r resolvers.txt -w found.txt
```

**`shuffledns`** is the ProjectDiscovery Go wrapper over the same `massdns` engine — faster to install if you already use the PD toolchain .

### DNS enumeration commands

| Command | Description |
|---|---|
| `nslookup $TARGET` / `dig $TARGET` | A record |
| `nslookup -query=PTR <IP>` / `dig -x <IP>` | PTR record |
| `nslookup -query=ANY $TARGET` / `dig any $TARGET` | ANY records |
| `nslookup -query=TXT $TARGET` / `dig txt $TARGET` | TXT records (SPF, DKIM, verification tokens) |
| `nslookup -query=MX $TARGET` / `dig mx $TARGET` | MX records |
| `dig axfr "$TARGET" @"$NS"` | Zone transfer — rarely works on properly configured domains  |
| `gobuster dns -q --domain "${TARGET}" --resolver "${NS}" -w "${WORDLIST}"` | Subdomain brute force (gobuster 3.8+ long flags) |
| `dnsrecon -d example.com -D wordlist.txt -t brt` | Subdomain brute force |
| `dnsenum example.com` | Automated enumeration |

> **Reverse DNS sweeps** query PTR records for IP ranges owned by the organization to find hostnames that are not obvious from the domain — a useful enrichment step that most brute-force-only workflows miss .

### TLD expansion — `tlsx`

`tlsx` grabs **certificate SANs** (Subject Alternative Names) from live TLS endpoints, which frequently reveal subdomains that never appear in CT logs because they use a wildcard certificate or an internal CA:

```bash
tlsx -l live.txt -san -cn -silent
```

---

## 6. HTTP Probing and Live Host Discovery

Before fuzzing or crawling, confirm which hosts actually respond and what technology they run.

```bash
httpx -l subs.txt -ports 80,443,8080,8443,8000,8888 -title -tech-detect -status-code -o live.txt
```

`httpx` replaces the manual `curl -I` loop and adds **title extraction**, **technology detection**, **status codes**, and **CDN/WAF identification** .

### Active infrastructure identification

| Command | Description |
|---|---|
| `curl -I "http://${TARGET}"` | HTTP headers |
| `whatweb -a 3 https://$TARGET -v` | Technology identification (`-a` 1/3/4) |
| `wafw00f -v https://$TARGET` | WAF fingerprinting |
| `cat subdomains \| aquatone -out ./aquatone -screenshot-timeout 1000` | Screenshots of all subdomains |
| `WitnessMe` | Web inventory with headless Chrome screenshots  |

---

## 7. Virtual Host (Vhost) Discovery

One IP often serves several sites, and the IP root is frequently a decoy. Vhost fuzzing is **essential** before directory brute force.

```bash
# ffuf — compare against a random Host baseline
ffuf -w subdomains-top1million-5000.txt -u http://$TARGET \
  -H "Host: FUZZ.$DOMAIN" -fs <baseline-size>

# gobuster vhost
gobuster vhost -u http://$TARGET -w <wordlist> --append-domain --domain $DOMAIN \
  --exclude-length <length>
```

> **Key rules:** compare response **size/length** against a request with a random Host header, or every result looks valid. Add the discovered name to `/etc/hosts` and enumerate it separately — it usually has a different application. Also try `X-Forwarded-Host` and `X-Forwarded-For: 127.0.0.1` for access-control bypasses.

---

## 8. URL Collection — Archives, Crawling, and JavaScript

Collecting every URL a target has ever exposed is what turns a list of hostnames into an actual map of the application’s attack surface . Four sources find things the others miss:

| Source | Tool | Finds |
|---|---|---|
| **Web archives** | `gau`, `waybackurls` | Historic URLs — endpoints removed from the UI but often still live on the server  |
| **Live crawl** | `katana` | Current URLs, including ones only reachable through JavaScript  |
| **JS references** | `subjs`, `katana -jc` | Script URLs, which yield more endpoints when mined  |
| **Content discovery** | brute force | Paths nobody ever linked to  |

### `gau` — Get All URLs

`gau` queries the **Wayback Machine, Common Crawl, AlienVault OTX, and URLScan** .

```bash
cat live.txt | gau --subs --threads 5 --o gau-urls.txt

# Useful flags:
# --subs          include subdomains
# --blacklist     skip image/font extensions
# --mc / --fc     match/filter by status code
# --from / --to   date range, YYYYMM
# --fp            remove duplicate parameter variants
```

### `katana` — modern crawler

`katana` is a next-generation crawler that handles **JavaScript-rendered content** and headless mode .

```bash
katana -list live.txt -js-crawl -kf all -silent -o katana-urls.txt

# Key flags:
# -js-crawl / -jc    parse JavaScript for endpoints
# -kf all            crawl known files (robots.txt, sitemap.xml, etc.)
# -hl                headless mode
# -aff               automatic form filling
```

### Merging and filtering

```bash
cat gau-urls.txt katana-urls.txt waybackurls.txt | anew all-urls.txt
# Filter to parameterised, interesting endpoints
grep -E '\?|=|\.php|\.asp|\.jsp' all-urls.txt | sort -u > interesting.txt
```

### JavaScript analysis

JavaScript bundles hide API endpoints, keys, and undocumented routes .

```bash
# 1. Collect JS files
cat live.txt | subjs | anew js-files.txt

# 2. Extract endpoints
python3 linkfinder.py -i js-files.txt -o cli

# 3. Mine secrets
python3 SecretFinder.py -i js-files.txt -o cli
```

| Tool | Purpose |
|---|---|
| **LinkFinder** | Extracts endpoints and routes from JS  |
| **SecretFinder** | Finds API keys, tokens, JWTs  |
| **JSluice** | Modern JS analysis pipeline  |
| **subjs** | Fetches JS files from a list of URLs/subdomains  |
| **trufflehog** | Secret scanning across the JS directory  |

---

## 9. Web Content Fuzzing and Discovery

### Tool comparison (2025 status)

| Tool | Best for | Language | Status |
|---|---|---|---|
| **ffuf** | General fuzzing, API testing | Go | **Still the king** — added rate limiting, plugins, improved recursion  |
| **feroxbuster** | **Recursive** directory discovery | Rust | **Top-tier** — massive improvements, rate limiting, scan resume  |
| **gobuster** | Quick directory/DNS/vhost scans | Go | Active; added TFTP mode, better vhost detection  |
| **dirsearch** | Beginners, pretty output | Python | Active  |
| **katana** | Crawling + fuzzing workflow | Go | Active (new)  |
| **x8** | Hidden parameter discovery | Rust | Active (new)  |
| **kiterunner** | **API endpoint discovery** | Go | Active (new)  |

### `nomore403` — the 403 bypass step

**`nomore403`** is designed to be run **immediately after content discovery** . It reads the URLs your fuzzer flagged as `403`, auto-calibrates against a non-existent path to learn the target’s default error behaviour, and runs **eight bypass techniques** — HTTP verb tampering, header injection, path case switching, double encoding .

```bash
nomore403 -u https://target.tld/admin
```

### Parameter discovery

```bash
# x8 — hidden parameter discovery
x8 -u "https://target.tld/api" -w parameters.txt

# Arjun
arjun -u https://target.tld/api

# paramspider — mine parameters from archives
paramspider -d target.tld
```

---

## 10. Cloud Asset Discovery

Cloud storage misconfigurations are a frequent finding and a distinct recon surface from subdomains.

### `cloud_enum` — multi-cloud OSINT

Enumerates **AWS S3 buckets, Azure blob storage, and GCP buckets** .

```bash
# Permutation sweep — derive candidate names from the org
cloud_enum -k company -k company-prod -k brand
```

It tests **open and protected buckets**, Azure **storage accounts and hosted databases**, and GCP **buckets and apps** . Three wordlists are bundled: `fuzz_small.txt` (~100 words), `fuzz.txt` (~1,100), and `fuzz_large.txt` (~1,800) .

### `S3Scanner`

```bash
S3Scanner -bucket target-bucket
```

Dumps the contents of open S3 buckets .

### CloudFlare origin bypass

```bash
# CloudFail — find the origin IP behind CloudFlare via DNS history
cloudfail -t target.com
```

A `cloud-recon`-style workflow sweeps public S3/Azure/GCP buckets via `S3Scanner` and `cloud_enum`, plus **CloudFlare-bypassed origin IPs** via `CloudFail` or built-in DNS-history fallback .

### Secret scanning in repositories

```bash
# gitleaks — hardcoded secrets in git repos
gitleaks detect --source ./repo --verbose
```

`gitleaks` is a SAST tool for detecting hardcoded passwords, API keys, and tokens in git repositories .

---

## 11. Metadata and Document OSINT

Publicly available documents leak usernames, internal hostnames, software versions, and sometimes credentials.

```bash
# ExifTool — reads metadata from 100+ file formats
exiftool document.pdf

# GotMeta — discover and download public files, then extract metadata
gotmeta -d target.com
```

**ExifTool** reads metadata from over **100 file formats** — images, videos, audio, documents . **GotMeta** discovers, downloads, and extracts metadata from publicly available files on a target domain . **MetaDetective** extracts 25+ fields including authors, software, creation dates, internal hostnames, and serial numbers .

---

## 12. NMAP — Active Scanning

NMAP reveals services, open ports, versions, and operating system information. After gaining a lay of the land, refer to the Protocols and Services notes for exploitation.

### Scanning options

| Option | Description |
|---|---|
| `10.10.10.0/24` | Target network range |
| `-sn` | Ping scan: host discovery only |
| `-Pn` | Skip host discovery — **required** when ICMP is blocked |
| `-n` | Disable DNS resolution |
| `-PE` | Ping scan with ICMP Echo Requests |
| `--packet-trace` | Show all packets sent/received |
| `--reason` | Display the reason for a result |
| `--disable-arp-ping` | Disable ARP ping |
| `--top-ports=<num>` | Scan the top N most frequent ports |
| `-p-` | Scan all ports |
| `-p22-110` | Scan a port range |
| `-p22,25` | Scan specific ports |
| `-F` | Scan top 100 ports |
| `-sS` | TCP SYN scan |
| `-sA` | TCP ACK scan — maps firewall rules, **not** open ports |
| `-sU` | UDP scan (requires root, much slower) |
| `-sV` | Service version detection |
| `-sC` | Default script scan |
| `-sL` | List scan — resolves names, sends no packets |
| `--script <script>` | Custom script scan |
| `-O` | OS detection |
| `-A` | OS detection + service detection + traceroute |
| `-D RND:5` | Random decoys |
| `-e` | Network interface |
| `-S 10.10.10.200` | Source IP |
| `-g` | Source port |
| `--dns-server <ns>` | Custom DNS server |

### Output options

| Option | Description |
|---|---|
| `-oA filename` | All formats |
| `-oN filename` | Normal format |
| `-oG filename` | Grepable format |
| `-oX filename` | XML format |

### Performance options

| Option | Description |
|---|---|
| `--max-retries <num>` | Port scan retries |
| `--stats-every=5s` | Status every 5 seconds |
| `-v/-vv` | Verbose output |
| `--initial-rtt-timeout 50ms` | Initial RTT timeout |
| `--max-rtt-timeout 100ms` | Maximum RTT timeout |
| `--min-rate 300` | Minimum packet rate |
| `-T <0-5>` | Timing template (0=paranoid, 5=insane) |

> **Full-port scan is not optional.** Footholds frequently live outside the top 1000 — `4555` (James admin), `61616` (ActiveMQ OpenWire), `22022` (SSH), `1337` (OliveTin), `8765` (motionEye), `5000` (internal API). Pair a TCP sweep with a **UDP `-sU --top-ports 50`** scan: SNMP/161, TFTP/69, NTP/123, DNS/53, IPMI/623 are easy to miss.

---

## 13. Putting It Together — One-Liner Pipeline

```bash
# 1. Passive subdomains
subfinder -d target.com -all -recursive -silent | anew subs.txt

# 2. Active brute force + wildcard filtering
puredns bruteforce subdomains-top1million-110000.txt target.com -r resolvers.txt -w brute.txt
anew subs.txt < brute.txt

# 3. Resolve and probe
dnsx -l subs.txt -a -resp -silent | tee resolved.txt
httpx -l resolved.txt -ports 80,443,8080,8443 -title -tech-detect -status-code -o live.txt

# 4. URL collection
cat live.txt | gau --subs --threads 5 | anew urls.txt
katana -list live.txt -js-crawl -kf all -silent | anew urls.txt
cat live.txt | waybackurls | anew urls.txt

# 5. JS analysis
cat live.txt | subjs | anew js.txt
python3 linkfinder.py -i js.txt -o cli | anew endpoints.txt
python3 SecretFinder.py -i js.txt -o cli | anew secrets.txt

# 6. Content discovery
feroxbuster -u https://target.com -w raft-large-directories.txt -d 2 -o dirs.txt

# 7. 403 bypass
grep ' 403 ' dirs.txt | awk '{print $NF}' | nomore403 -l -

# 8. Vulnerability scan
nuclei -l live.txt -severity critical,high -o nuclei.txt
```

---

## 14. Field Notes from the HTB List

- **Full-port scan is not optional.** Footholds live outside the top 1000: `4555` (James admin), `61616` (ActiveMQ OpenWire), `22022` (SSH), `1337` (OliveTin), `8765` (motionEye), `5000` (internal API). (Solidstate, Broker, Sunday, Enigma, Editorial, Cctv)
- **Vhosts before directories.** The IP root is often a decoy — fuzz `Host` with `-ac`, compare body size, and treat a **403 as a finding**. (BoardLight, Keeper, Editor, Linkvortex, Mentor, UnderPass)
- **`.git` and backups by hand.** `nmap --script http-git`, then `git-dumper`; read `git log -p`, `git diff --cached`, `settings.php`, `conf.php`, `*.old`, `*.bak` for credentials. (Pilgrimage, Dog, Linkvortex, Editorial, BoardLight)
- **Read the page source.** HTML comments leak paths and usernames. (Nibbles, Markup)
- **Version strings lie.** A plugin readme can admit a faked version (TartarSauce’s gwolle-gb: real 1.5.3, reported 2.3.10).
- **UDP/161.** SNMP leaks hostnames and **process command lines** that contain passwords. (Mentor, Pandora, UnderPass)

Full machine-by-machine context: [HTB Linux machines](/notes/oscp-labs/linux/), [Windows](/notes/oscp-labs/windows/).

---

## Quick Reference — New Tools Added (2025–2026)

| Tool | What it replaces / adds | Install |
|---|---|---|
| **puredns** | Wildcard-filtered DNS brute force; wraps massdns  | `go install github.com/d3mondev/puredns/v2@latest` |
| **dnsx** | DNS resolution, validation, record enrichment  | `go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest` |
| **katana** | JS-aware modern crawler  | `go install github.com/projectdiscovery/katana/cmd/katana@latest` |
| **gau** | Archived URL collection (Wayback, Common Crawl, OTX, URLScan)  | `go install github.com/lc/gau/v2/cmd/gau@latest` |
| **feroxbuster** | Recursive content discovery (Rust)  | `cargo install feroxbuster --locked` |
| **nomore403** | 403/40X bypass with 8 techniques  | `go install github.com/devploit/nomore403@latest` |
| **subjs** | Fetch JS files from URLs/subdomains  | `go install github.com/lc/subjs@latest` |
| **x8** | Hidden parameter discovery  | `cargo install x8` |
| **kiterunner** | API endpoint discovery  | `go install github.com/assetnote/kiterunner/cmd/kr@latest` |
| **cloud_enum** | Multi-cloud bucket enumeration (AWS/Azure/GCP)  | `git clone https://github.com/initstring/cloud_enum` |
| **S3Scanner** | Open S3 bucket discovery and dump  | `pip3 install s3scanner` |
| **BBOT** | Maintained OSINT automation (SpiderFoot successor)  | `pipx install bbot` |
| **tlsx** | Certificate SAN extraction  | `go install github.com/projectdiscovery/tlsx/cmd/tlsx@latest` |
