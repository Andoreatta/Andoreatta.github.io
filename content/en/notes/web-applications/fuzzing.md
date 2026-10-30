+++
title = 'Fuzzing (ffuf-first)'
date = 2026-10-30
type = 'notes'
weight = 20
toc = true
tags = ['web', 'fuzzing', 'ffuf']
+++

Fuzzing is systematic **content discovery** — proving what an application exposes rather than guessing from its sitemap. The highest-impact findings on real engagements frequently live behind a URL that was never meant to be reachable: a forgotten `/admin-old/`, a `config.php.bak` left after a hotfix, a staging vhost bound to the same IP, or an API version that was never deprecated. The only way to find them at scale is brute-force enumeration with a disciplined wordlist and ruthless filtering.

This reference is **ffuf-first**. feroxbuster appears where its recursion or ergonomics genuinely beat ffuf, but ffuf is the default tool because its keyword model handles every fuzz scenario — path, parameter, header, Host, JSON body — in one syntax.

---

## 1. Tool Selection — ffuf vs feroxbuster

| | **ffuf** | **feroxbuster** |
|---|---|---|
| **Language** | Go | Rust |
| **Core model** | Single-shot **keyword fuzzer** — `FUZZ` can appear anywhere in the request (path, parameter, header, Host, JSON) | Purpose-built **recursive directory discovery** — automatic recursion and link extraction |
| **Best at** | Parameter, header, Host, and tightly scoped path fuzzing | Broad recursive mapping of a content tree |
| **Recursion** | Basic — `-recursion` works but is crude on large targets | **Excellent** — depth-controlled, link-aware |
| **Wildcard handling** | `-ac` auto-calibration | Auto-tuned |
| **Verdict** | **Default for everything except broad recursion** | **First pass on a new site** |

**Practical workflow:** run feroxbuster once for a broad recursive first pass, then ffuf for every surgical task — a parameter, a Host header, an extension sweep, an LFI payload.

```bash
# feroxbuster — recursive by default
feroxbuster -u https://target.tld -w wordlist.txt

# ffuf — explicit keyword
ffuf -u https://target.tld/FUZZ -w wordlist.txt
```

---

## 2. Wordlists

Your results are only as good as your wordlist. A 200k-word list run against every endpoint wastes time and triggers WAFs; a curated list matched to the target's stack finds the interesting paths fast.

### 2.1 SecLists — the baseline

```bash
/usr/share/seclists/Discovery/Web-Content/
├── common.txt                          # small, fast triage pass
├── raft-medium-directories.txt         # sweet spot for time-boxed engagements
├── raft-large-directories.txt          # broad coverage
├── directory-list-2.3-big.txt          # ~1.2M — only with time and rate budget
├── quickhits.txt                       # first probe before a full brute-force
├── api/api-endpoints.txt               # JSON APIs — resource names, not directories
└── <tech>.txt                          # tomcat.txt, jboss.txt, IIS.txt, nginx.txt
```

**Pick by target, not by size.** If the response shows `X-Powered-By: PHP`, prioritize PHP files and add `.php` to the extension set. There is no point fuzzing `.aspx` against a Node app.

### 2.2 Target-shaped wordlists

```bash
# Words mined from the application itself
cewl -d 2 -m 5 -w custom.txt https://target.com

# Assetnote (wordlists.assetnote.io) — higher hit rate on SaaS/cloud apps
# automated.json, httparchive_directories
```

Mining the application's own JavaScript bundles for path and parameter names often produces a better hit rate than any generic dictionary.

---

## 3. Directory and File Fuzzing

### 3.1 Basic discovery

```bash
# ffuf — flat directory discovery
ffuf -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt \
  -u https://target.com/FUZZ

# ffuf — with auto-calibration (recommended default)
ffuf -w wordlist.txt -u https://target.com/FUZZ -ac
```

`-ac` (auto-calibrate) probes the target for wildcard/soft-404 behaviour and creates filters automatically, so you do not have to hand-tune `-fs`.

### 3.2 Extensions

```bash
# ffuf — comma-separated, no spaces
ffuf -w wordlist.txt -u https://target.com/FUZZ -e .php,.bak,.zip,.old,.txt,.json -ac

# Extension placement — FUZZ in the middle of the filename
ffuf -w wordlist.txt -u https://target.com/indexFUZZ
```

Include **backup and source extensions** — `.bak`, `.old`, `.zip`, `.txt`, `.json` catch files left after a hotfix, and they are frequently the fastest win on a PHP or Java application.

### 3.3 Recursive fuzzing

ffuf's recursion is **redirect-driven by default** — it recurses into a path only when the path returns a redirect (typically to a directory). That is the correct behaviour; the alternative, `greedy`, recurses on every match and is almost never what you want.

```bash
# ffuf — recurses into directories, depth 2
ffuf -w wordlist.txt -u https://target.com/FUZZ \
  -recursion -recursion-depth 2 -recursion-strategy default
```

> **Do not combine `-e .php` with deep recursion.** ffuf will try to recurse into `.php` paths, which produces garbage requests. Either drop the extensions for a recursive pass, or run extensions as a separate flat pass.

**When the tree is deep, use feroxbuster instead:**

```bash
# feroxbuster — recursive, depth 2
feroxbuster -u https://target.com -w wordlist.txt --depth 2

# feroxbuster — smart mode: link extraction + auto-tune + backup detection
feroxbuster -u https://target.com -w wordlist.txt --smart

# feroxbuster — exclude noisy paths from recursion
feroxbuster -u https://target.com -w wordlist.txt --dont-scan /static/ --dont-scan /assets/
```

> **`--depth 0` is infinite recursion in feroxbuster.** The default is 4. Set an explicit depth on anything that is not a lab.

---

## 4. Subdomain and VHost Fuzzing

One IP often serves several sites, and the IP root is frequently a decoy. Vhost fuzzing is **essential** before directory brute force.

### 4.1 Subdomain fuzzing (DNS-based)

```bash
ffuf -w subdomains.txt -u https://FUZZ.target.com
```

### 4.2 VHost fuzzing (Host-header-based)

This is the technique that finds **name-based sites behind one shared IP** that never appear in public DNS.

**Step 1 — establish the baseline.** Send a request with a random Host value and record the response size:

```bash
curl -s -o /dev/null -w "%{size_download}" -H "Host: randomvalue.target.com" http://target.com/
# → e.g. 4242
```

**Step 2 — fuzz with that size filtered:**

```bash
ffuf -w subdomains.txt -u http://target.com/ -H "Host: FUZZ.target.com" -fs 4242
```

`-ac` also works for vhosts and will auto-detect the wildcard size, but the manual baseline is more explicit and easier to verify:

```bash
ffuf -w subdomains.txt -u http://target.com/ -H "Host: FUZZ.target.com" -ac
```

> **A 403 is a finding.** It means the vhost exists but is ACL-blocked — queue it for the 403-bypass step in Section 8.

---

## 5. Parameter Fuzzing (GET / POST / JSON)

This is where ffuf's keyword model beats every alternative. `FUZZ` can be a **name** or a **value**, in a query string, a POST body, or a JSON field.

### 5.1 GET parameter names

```bash
ffuf -w params.txt -u "http://target.com/page?FUZZ=value" -ac
```

### 5.2 POST parameter names

```bash
ffuf -w params.txt -u http://target.com/page -X POST -d "FUZZ=value" \
  -H 'Content-Type: application/x-www-form-urlencoded' -ac
```

### 5.3 POST parameter values

```bash
# e.g. username enumeration
ffuf -w usernames.txt -u http://target.com/page -X POST -d "user=FUZZ" \
  -H 'Content-Type: application/x-www-form-urlencoded' -fw 56
```

### 5.4 JSON API parameters

```bash
ffuf -w params.txt -u http://target.com/api/users -X POST \
  -H 'Content-Type: application/json' -d '{"FUZZ":"value"}' -ac
```

### 5.5 Filtering for parameter fuzzing

Use **`-fw` (word count)** rather than `-fs` (size) for parameter fuzzing. The baseline page often varies slightly in byte size but not in word count, so `-fw` produces far fewer false positives.

```bash
ffuf -w params.txt -u "http://target.com/page?FUZZ=value" -fw 56
```

**Dedicated alternatives** — `x8` and `arjun` handle large parameter lists and JSON bodies better than ffuf:

```bash
x8 -u "https://target.com/api" -w params.txt
arjun -u https://target.com/api
```

---

## 6. LFI and Path Traversal Fuzzing

### 6.1 Two passes — find the parameter, then fuzz the payload

```bash
# Pass 1 — find the vulnerable parameter
ffuf -w params.txt -u "http://target.com/index.php?FUZZ=value" -ac

# Pass 2 — fuzz LFI payloads, matching on a known string
ffuf -w /usr/share/seclists/Fuzzing/LFI/LFI-Jhaddix.txt \
  -u "http://target.com/index.php?language=FUZZ" -mr 'root:x:0:0'
```

### 6.2 Why `-mr` beats `-fs` for LFI

Filtering by response size (`-fs`) is unreliable for LFI because the error page and a successful include can differ by only a few bytes, and the difference is not consistent. **Match on a known string instead:**

```bash
# Match on the root line of /etc/passwd — the most reliable signal
ffuf -w LFI-Jhaddix.txt -u "http://target.com/?page=FUZZ" -mr 'root:x:0:0'

# Or filter failed requests by status code (many LFI failures return 500)
ffuf -w LFI-Jhaddix.txt -u "http://target.com/?page=FUZZ" -fc 500
```

### 6.3 Fuzz the webroot path and server configs

```bash
# Webroot traversal
ffuf -w /usr/share/seclists/Discovery/Web-Content/default-web-root-directory-linux.txt \
  -u 'http://target.com/index.php?language=../../../../FUZZ/index.php' -mr 'root:x:0:0'

# Server configuration files
ffuf -w ./LFI-WordList-Linux \
  -u 'http://target.com/index.php?language=../../../../FUZZ' -mr 'root:x:0:0'
```

> **`LFI-Jhaddix.txt`** is the standard list because it contains traversal bypasses and common sensitive files, not just plain paths.

---

## 7. Filtering — Turning Noise into Findings

This is the part most people skip, and it is why their scan output is unusable. Run **one unfiltered pass**, read the dominant response size/word count, then filter it.

### 7.1 ffuf filtering and matching flags

| Flag | Filters by |
|---|---|
| `-fc` | HTTP status code |
| `-fs` | Response size (bytes) |
| `-fw` | Response word count |
| `-fl` | Response line count |
| `-fr` | Regex in response body |
| `-mc` | **Match** only these status codes |
| `-mr` | **Match** responses containing a string |
| `-ac` | **Auto-calibrate** — removes most false positives without manual tuning |
| `-sf` | Stop when >95% of responses are 403 (WAF / wrong directory) |

### 7.2 The practical filter workflow

```bash
# Step 1 — run unfiltered, read the dominant size/word count
ffuf -w wordlist.txt -u https://target.com/FUZZ

# Step 2 — filter the baseline manually
ffuf -w wordlist.txt -u https://target.com/FUZZ -fs 1234 -fw 56 -fl 7 -fr 'Not Found'

# Step 3 — or just let auto-calibration handle it
ffuf -w raft-large-directories.txt -u https://target.com/FUZZ -ac

# Step 4 — include 403/401/405 as findings, not noise
ffuf -w wordlist.txt -u https://target.com/FUZZ \
  -mc 200,204,301,302,307,401,403,405 -fc 404
```

> **`-ac` is the single most useful flag in ffuf.** It auto-calibrates against the target's wildcard behaviour and removes soft-404 noise that would otherwise bury every real finding.

### 7.3 feroxbuster filtering (for the recursive pass)

```bash
# Filter by status, size, or words
feroxbuster -u http://target.com -w common.txt -C 404 -S 1234 -W 56

# Filter pages similar to a known soft-404 page
feroxbuster -u http://target.com -w wordlist.txt --filter-similar-to http://target.com/404page

# Keep the scan stable on fragile targets
feroxbuster -u http://target.com -w wordlist.txt --auto-tune --auto-bail
```

`--auto-tune` lowers the request rate when the target starts erroring; `--auto-bail` stops the scan entirely rather than hammering a struggling server.

---

## 8. 403 Bypass — `nomore403`

403 responses are **not** dead ends. A 403 usually means the path is **real but ACL-blocked** — which makes it a candidate for an access-control bypass.

`nomore403` is a focused bypass tester, not a discovery tool: feed it forbidden URLs from your fuzzer and it reshapes the request in ways the access rule may not account for.

```bash
# Single URL
nomore403 -u https://target.tld/admin

# From a file of 403 URLs
nomore403 -f forbidden.txt

# From stdin — pipe the 403s straight out of ffuf
ffuf -w wordlist.txt -u https://target.com/FUZZ -mc 403 -s | nomore403
```

**What it does:** auto-calibrates against the target's base response, then tries **8 techniques** — HTTP verb tampering, header injection (including `X-Forwarded-For: 127.0.0.1`), path case switching, suffix tricks, and raw desync variants in v2.0.0.

> **Interpreting results:** a change from `403 → 200` is a bypass. A change from `403 → 400` or `403 → 404` usually indicates a **parser or routing difference**, not a bypass — do not report those as findings.

---

## 9. Advanced ffuf Features

### 9.1 Multiple wordlists — `-mode clusterbomb` / `pitchfork`

When a request needs two independent values (username + password, user ID + resource ID), ffuf can iterate two wordlists in one run:

```bash
ffuf -w usernames.txt:USER -w passwords.txt:PASS \
  -u https://target.com/login -X POST \
  -d "username=USER&password=PASS" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -mode clusterbomb
```

- **`clusterbomb`** — every combination (cartesian product). Slow, thorough.
- **`pitchfork`** — iterate both lists in lockstep. Fast, for paired values.

### 9.2 Raw request replay — fuzz an authenticated endpoint

When a request has many headers, cookies, or a complex body, copy it from Burp to a file and fuzz inside it. This is the cleanest way to fuzz an authenticated endpoint without re-encoding every header.

```bash
# Save the Burp request to request.txt, put FUZZ where you want substitution
ffuf -request request.txt -request-proto https -w wordlist.txt -ac
```

### 9.3 Structured output

```bash
ffuf -w wordlist.txt -u https://target.com/FUZZ -o out.json -of json
ffuf -w wordlist.txt -u https://target.com/FUZZ -o out.html -of html
```

`-of` accepts `json`, `html`, `md`, `csv`, and `all`. Structured output is what lets you feed results into `nomore403` or a report.

### 9.4 Rate limiting and stability

```bash
ffuf -w wordlist.txt -u https://target.com/FUZZ -t 10 -p 0.1-0.5
```

`-t` is threads (default 40); `-p` is delay between requests, either a fixed number or a range for jitter. On fragile targets or under a WAF, lower both.

---

## 10. Putting It Together — One Pipeline

```bash
# 1. Broad recursive mapping with feroxbuster
feroxbuster -u https://target.com \
  -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt \
  --depth 2 --smart -x php,bak,old,zip \
  -o ferox.json --json

# 2. Surgical extension sweep with ffuf
ffuf -u https://target.com/FUZZ \
  -w /usr/share/seclists/Discovery/Web-Content/common.txt \
  -e .php,.bak,.zip,.old,.txt,.json -ac \
  -o ffuf.json -of json

# 3. Vhost discovery on the same IP
ffuf -u http://target.com/ -H "Host: FUZZ.target.com" \
  -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -ac

# 4. Collect 403s and try to bypass them
ffuf -u https://target.com/FUZZ -w wordlist.txt -mc 403 -s | nomore403

# 5. Parameter discovery on the interesting endpoints
ffuf -w params.txt -u "https://target.com/api/users?FUZZ=test" -fw 56
```

---

## 11. Best Practices and Pitfalls

- **Cap recursion.** `--depth 0` is infinite in feroxbuster; a directory with hundreds of variants will generate an enormous request volume. ffuf's `-recursion-depth` should also be explicit.
- **Do not combine `-e` with deep ffuf recursion.** It will try to recurse into `.php` paths and produce garbage requests.
- **Exclude noisy paths.** `/static/`, `/assets/`, and CDN paths contain hundreds of files with no security relevance — use `--dont-scan` in feroxbuster.
- **Run unfiltered first, then filter.** You cannot choose `-fs` / `-fw` / `-fl` until you have seen the baseline response.
- **`-ac` is your default.** Auto-calibration beats manual size guessing on any target with a wildcard response.
- **Treat 403 as a finding.** It means the path exists; queue it for `nomore403`.
- **Use `-fw` for parameter fuzzing.** Word count is more stable than byte size when the baseline page varies.
- **Use `-mr` for LFI.** Matching on `root:x:0:0` is far more reliable than `-fs`.
- **Lower threads and add delay on production targets.** `-t 10 -p 0.1-0.5` in ffuf, or `--auto-tune` in feroxbuster, prevents self-inflicted outages.
- **Export structured output.** `-o out.json -of json` in ffuf, `--json` in feroxbuster — so the next phase or your report can consume the results.
- **Match the wordlist to the stack.** Fuzzing `.aspx` against a Node app is wasted requests; fingerprint first with `whatweb` or Wappalyzer.
- **Crawl the JS bundles.** The highest hit rate often comes from words the application itself uses, not from a generic dictionary.
- **Always have written authorization.** Brute-forcing paths against a host you do not own is noisy and, in most jurisdictions, illegal.

---

## 12. ffuf Quick Reference Card

```bash
# ---- Directory & file discovery ----
ffuf -w list.txt -u https://t.tld/FUZZ -ac                                  # basic + auto-calibrate
ffuf -w list.txt -u https://t.tld/FUZZ -e .php,.bak,.zip -ac                # extensions
ffuf -w list.txt -u https://t.tld/FUZZ -recursion -recursion-depth 2 \
     -recursion-strategy default                                            # recursive

# ---- VHost ----
curl -s -o /dev/null -w "%{size_download}" \
     -H "Host: random.t.tld" http://t.tld/                                  # baseline
ffuf -w subs.txt -u http://t.tld/ -H "Host: FUZZ.t.tld" -fs <baseline>      # filter by size
ffuf -w subs.txt -u http://t.tld/ -H "Host: FUZZ.t.tld" -ac                 # or auto-calibrate

# ---- Parameters ----
ffuf -w params.txt -u "https://t.tld/page?FUZZ=value" -ac                   # GET name
ffuf -w params.txt -u https://t.tld/page -X POST -d "FUZZ=value" \
     -H 'Content-Type: application/x-www-form-urlencoded' -ac               # POST name
ffuf -w ids.txt -u https://t.tld/page -X POST -d "id=FUZZ" \
     -H 'Content-Type: application/x-www-form-urlencoded' -fw 56            # POST value
ffuf -w params.txt -u https://t.tld/api -X POST \
     -H 'Content-Type: application/json' -d '{"FUZZ":"value"}' -ac          # JSON

# ---- LFI ----
ffuf -w LFI-Jhaddix.txt -u "https://t.tld/?page=FUZZ" -mr 'root:x:0:0'      # match on passwd

# ---- Advanced ----
ffuf -w users.txt:USER -w pass.txt:PASS -u https://t.tld/login \
     -X POST -d "u=USER&p=PASS" -mode clusterbomb                           # two wordlists
ffuf -request req.txt -request-proto https -w list.txt -ac                  # raw request
ffuf -w list.txt -u https://t.tld/FUZZ -o out.json -of json                 # structured output
ffuf -w list.txt -u https://t.tld/FUZZ -t 10 -p 0.1-0.5                     # rate limit
ffuf -w list.txt -u https://t.tld/FUZZ -sf                                  # stop on 403 flood
```

---

This file sits alongside the **Information Gathering** notes: the discovery pipeline there produces the hostnames and URLs, and this file turns them into an actual map of the application's attack surface.
