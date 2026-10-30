+++
title = 'Web Cache Poisoning & Web Cache Deception'
date = 2026-10-30
type = 'notes'
weight = 120
toc = true
tags = ['web', 'web-attacks', 'cache-poisoning']
+++

Web caches sit between the client and the origin server to reduce latency and load. A **cache key** — a subset of request attributes — decides whether two requests may share a cached response. Every bug in this class is a **disagreement between the cache and the origin about what the request means**: either the cache keys on something the origin ignores (poisoning), or the cache serves a private response as if it were public (deception).

> **2025–2026 context:** the class has split into two distinct disciplines that are often conflated. **Cache poisoning** is an *integrity* attack — inject a harmful response into the cache and serve it to everyone. **Cache deception** is a *confidentiality* attack — trick the cache into storing an authenticated response under a public URL. The 2025–2026 CVE feed is dominated by **framework and library caching layers** rather than CDN-vs-origin mismatches: Next.js RSC cache key confusion (CVE-2025-49005), Varnish HTTP/2 desync (CVE-2026-50052), `Vary` header omissions in Django and `http-cache-semantics`, and Unicode-normalization collisions in Litestar's cache backend.

---

## 1. Useful Resources & Tools

| Resource / Tool | What it does |
|---|---|
| [Practical Web Cache Poisoning](https://portswigger.net/research/practical-web-cache-poisoning) | The foundational PortSwigger research |
| [Web Cache Entanglement](https://portswigger.net/research/web-cache-entanglement) | Cache poisoning + request smuggling chains |
| [Gotta Cache 'em All](https://portswigger.net/research/gotta-cache-em-all) | **Path confusion** — delimiter discrepancies between CDN and origin |
| **Web-Cache-Vulnerability-Scanner (WCVS) 2.0.0** | Hackmanit's CLI scanner — **10 poisoning techniques** and **9+ deception techniques**, built-in crawler, distribution package (Aug 2025) |
| **Param Miner** (Burp) | Unkeyed-header and unkeyed-parameter discovery — still the best manual probe |
| **Cache Killer** (Burp) | Adds a cache-busting parameter automatically |
| **HTTP Request Smuggler** (Burp) | Detects the desync primitives that feed cache poisoning |
| **Burp Repeater / Turbo Intruder** | Manual timing attacks against cache expiry |
| **`curl` + `X-Cache-Status`** | Manual keyed/unkeyed classification |

**WCVS 2.0.0 quick reference:**

```bash
# Package (2.0.0)
sudo apt install web-cache-vulnerability-scanner

# Scan a target — poisoning + deception
wcvs -u https://target.example -w wordlist.txt

# Force specific techniques
wcvs -u https://target.example -pt unkeyed-header -dt path-confusion

# Crawl first, then test discovered URLs
wcvs -u https://target.example -crawl

# Docker
docker run --rm hackmanit/wcvs -u https://target.example
```

> **WCVS 1.4.0 added parameter pollution** as a detection technique, and **2.0.0** expanded to 10 poisoning classes including cache-key injection and cache-key normalization — the two techniques that dominate the 2026 CVEs.

---

## 2. Cache Poisoning vs Cache Deception — The Distinction That Matters

The two bug classes share one root cause — **the cache key** — and are frequently tested together, but they are different attacks with different impact and different fixes.

| | **Cache poisoning** | **Cache deception** |
|---|---|---|
| **Goal** | Inject a **harmful** response | Retrieve a **sensitive** response |
| **Mechanism** | An **unkeyed input** changes the response; the poisoned response is cached and served to others | The origin treats a URL as **authenticated**, the cache treats it as **public** (or vice versa) and stores the private response |
| **Typical payload** | `X-Forwarded-Host: evil.com` reflected into a link | `/account/profile.css`, `/account/;.js`, `/account%0a.css` |
| **Impact** | Stored XSS, open redirect, defacement | PII disclosure, session token theft, account takeover |
| **Victim interaction** | None — the victim requests the URL normally | The victim must visit the crafted URL once |
| **Fix** | Key on every input that affects the response | Enforce `Cache-Control: private` and `Vary: Cookie, Authorization` |
| **CWE** | CWE-525 / CWE-524 | CWE-525 / CWE-524 |

> **The shared root cause in one sentence:** the cache and the origin resolve the same request to different resources, or the cache stores a response that is only valid for one user.

---

## 3. Cache Key Fundamentals

### 3.1 What is in the key

By default, a cache key is composed of:

- **Request path** (often **normalized** — see §7)
- **Query parameters** (keyed, unkeyed, or individually whitelisted)
- **`Host` header** (usually keyed)
- **A subset of headers** configured by the operator (`Vary`-driven)

Everything else is **unkeyed**. The attack surface is every input that is **unkeyed but still influences the response**.

| Term | Meaning |
|---|---|
| **Keyed input** | Part of the cache key — two requests with different values produce different cache entries |
| **Unkeyed input** | **Not** part of the cache key — it can differ between the request that populates the cache and the request that reads it |
| **Cache buster** | A keyed parameter with a unique value, added to every test request so a poisoned response never reaches a real user |

### 3.2 Cache deception is the inverse

In cache deception, the **key is the path** — and the path is where the discrepancy lives. The origin sees `/account` (authenticated, private); the cache sees `/account/profile.css` (static, public) and stores the response.

---

## 4. Initial Enumeration

### 4.1 Cache busters

Every test request must carry a **unique keyed parameter** so the poisoned response is never served to a real user:

```
?cachebuster=8f3a1c9e
```

If the application has no keyed parameter available, add a **keyed header** (`Vary`-based) or a random path segment that the origin normalizes away.

> **Do not skip this.** On a production target, a poison test without a buster can take the site down or serve a payload to every visitor within seconds.

### 4.2 `X-Cache-Status` — the easy case

Many deployments expose their cache state:

| Value | Meaning |
|---|---|
| **HIT** | Served from cache |
| **MISS** | Fetched from origin and cached |
| **BYPASS** | Cache skipped (e.g. `Cache-Control: no-cache`) |
| **EXPIRED** | Stale entry; origin fetched a fresh copy |
| **STALE** | Origin unreachable; stale response served |

**Keyed/unkeyed classification:**

1. Send request **A** — expect `MISS`, then `HIT` on repeat.
2. Change **one** parameter. If the result is `MISS`, the parameter is **keyed**. If it is `HIT` with the same body, the parameter is **unkeyed**.

Repeat for every parameter and header that changes the response body.

### 4.3 Forcing a fresh response for yourself

To see what the origin returns **with your injected payload** while a cached entry exists:

```http
Cache-Control: no-cache
Pragma: no-cache
```

The cache forwards the request to the origin and returns a fresh response — **without replacing the cached entry**. This confirms the payload works **before** you wait for expiry.

> **This is not a poison.** `no-cache` affects only your request. To actually poison, the existing entry must expire (or the cache must evict it), and your request must arrive in the window when the cache is ready to store a new response.

### 4.4 Timing the expiry

Read the `Cache-Control: max-age` from the response — or `Age`, `Expires`, `s-maxage` — to estimate when the entry expires. Send the poison request at that moment.

On high-traffic targets, **multiple threads** may be required to win the race: one thread continuously requests the URL (keeping it hot), another sends the poison at the expiry boundary.

---

## 5. Cache Poisoning Techniques

### 5.1 Unkeyed header injection

Any header that the origin reflects into the response — and the cache does not key on — is a poison primitive.

| Header | Where it appears |
|---|---|
| `X-Forwarded-Host` | Absolute URLs in links, redirects, `<script src>` |
| `X-Forwarded-Scheme` | Scheme in generated links |
| `X-Forwarded-For` / `X-Real-IP` | Logging, geo, rate-limit responses |
| `X-Host` / `X-Forwarded-Server` | Host fallback in frameworks |
| `X-Original-URL` / `X-Rewrite-URL` | Path override in some frameworks |
| `User-Agent` / `Referer` | Reflected into analytics or error pages |
| `Accept-Language` | Language selection (often unkeyed) |

**Canonical payload:**

```http
GET /?cb=8f3a1c9e HTTP/1.1
Host: target.example
X-Forwarded-Host: evil.example
```

If the response contains `<link href="https://evil.example/...">`, the header is reflected and unkeyed.

**The 2026 refinement — HTTP/2 header smuggling:** HTTP/2 and HTTP/3 allow **duplicate** `Host` and `X-Forwarded-Host` headers in a single request. Different proxies in the chain may resolve different values — the cache keys on one, the origin reflects the other. Test by sending multiple copies and observing which one appears in the response.

**RUSTSEC-2026-0388 (Pingora):** a mismatch between HTTP/2 `:authority` and `Host` enabled both cache poisoning and host-based access-control bypass. Pingora now returns `400` for a mismatch.

### 5.2 Unkeyed parameter injection

A query parameter that is **not** in the cache key but **is** processed by the origin.

```
?cb=8f3a1c9e&utm_campaign=<script>alert(1)</script>
```

**CVE-2026-11101** — a cache used only the URL path as the key and ignored query parameters entirely, so a payload in `utm_campaign` was cached and served to every visitor as stored XSS.

**CVE-2026-74916 (WP Fastest Cache 0.8.7.7–1.5.0):** the plugin did not include **tracking-related query parameters** in its page-cache key while still caching pages — unauthenticated cache poisoning via unkeyed tracking parameters.

**Testing:** append a random value to each candidate parameter and check whether the response changes while `X-Cache-Status` remains `HIT`.

### 5.3 Fat GET

A `GET` request with a **body**. The HTTP specification does not forbid it and does not define semantics, so most caches **ignore the body** when building the key — while many origin frameworks still parse it.

```http
GET /?cb=8f3a1c9e HTTP/1.1
Host: target.example
Content-Length: 42

param=<script>alert(1)</script>
```

If the origin reads `param` from the body and reflects it, the parameter is **unkeyed** — the cache stores the poisoned response under the query-string key.

> **WCVS 2.0 includes a fat-GET test class.** It surfaces the technique but does not always confirm exploitation — verify manually that the body parameter reaches the response.

### 5.4 Parameter cloaking

The cache and the origin **parse the query string differently**. A parameter the origin treats as keyed is invisible to the cache, or vice versa.

**Bottle CVE-2020-28473** is the reference case: Bottle accepts `;` as a parameter separator, while the proxy treats `;` as part of the value.

```
GET /?language=en&random=b;language=de
```

- The **cache** sees `language=en` (keyed) and `random=b;language=de` (unkeyed).
- **Bottle** sees `language=en`, `random=b`, `language=de` — and the **last** `language` wins.

Result: a German response stored under the English cache key.

**Generalized testing:** try `;`, `%3b`, `%26`, `&&`, `#`, and `?` as alternate separators. Any character one parser treats as a delimiter and the other does not is a cloaking primitive.

### 5.5 Cache-key injection and normalization

A **cache-key injection** bug occurs when the cache builds its key by **concatenating** request components without a separator, so an attacker can craft two different requests that map to the same key.

**Nginx cache key injection (2026):** deployments that construct keys by concatenating the scheme, host, and path without separators are vulnerable to scheme/host confusion and persistent XSS.

**CVE-2026-34475 (Varnish Cache):** a request URL containing **only** the path `/` is not properly normalized before reaching the cache layer, allowing an attacker to manipulate cached content or bypass authentication.

**Litestar FileStore (2026):** cache keys are mapped to filenames using **Unicode NFKD normalization** and `ord()` substitution **without separators**, producing **key collisions** between different request paths. An unauthenticated attacker can craft paths that collide with another user's cached response — cache mixup and poisoning.

**The test:** send two paths that differ only in a character that normalizes to the same value (`ﬁ` vs `fi`, `Ａ` vs `A`, a trailing slash, a null byte) and check whether they return the same cached content.

### 5.6 Vary header omissions and mismatches

The `Vary` header tells the cache **which request headers** must be part of the key. When it is **missing**, **incomplete**, or **mis-compared**, the cache serves a response generated for one user to another.

| CVE | Product | Failure |
|---|---|---|
| **CVE-2026-93750** | `http-cache-semantics` ≤ 4.2.0 | `_varyMatches()` compares `Vary` wildcards **byte-for-byte**, so `Vary: *` and case variants do not match → cache poisoning with **sensitive data intended for other users, including auth tokens** |
| **CVE-2026-35193** | Django | `UpdateCacheMiddleware` does **not add `Authorization` to `Vary`** when the request carries that header without `Cache-Control` → **critical cache poisoning and information disclosure** |
| **CVE-2025-69202** | `axios-cache-interceptor` < 1.11.1 | Cache key generated **only from the URL**, ignoring `Authorization` despite `Vary: Authorization` → **authorization bypass** across authenticated sessions |
| **CVE-2025-49005** | Next.js App Router 15.3.0–15.3.2 | **`Vary` header omitted** when caching App Router data → **RSC payloads cached and served in place of HTML** under middleware rewrites/redirects |

> **The pattern:** the `Vary` header is the **only** mechanism that tells a cache "this response depends on a request header." A missing or mis-compared `Vary` is a **confidentiality** bug as much as an integrity bug.

### 5.7 Response splitting → cache poisoning

**CVE-2026-66746 (rouille 0.4.0–3.6.2):** CR/LF bytes in attacker-controlled input are injected into **response headers**, enabling **cache poisoning, session fixation, and security-header override** (CSP/CORS bypass).

```
X-Injected: value%0d%0aContent-Type:%20text/html%0d%0a%0d%0a<script>alert(1)</script>
```

If the cache stores the split response, every subsequent visitor receives the injected body.

### 5.8 HTTP/2 request desync → cache poisoning

A **backend request desync** (request smuggling) lets an attacker prepend a partial request to the next user's request — which the cache then stores as that user's response.

**CVE-2026-50052 (Varnish Cache < 9.0.3, Vinyl Cache < 9.0.1):** a deficiency in **HTTP/2 request parsing** enables a backend desync that can be used for **cache poisoning, authentication bypass, and information disclosure**. The vector exists only when `+http2` is enabled.

**Testing:** send an HTTP/2 request with conflicting `Content-Length` / `:path` / `Host` values and observe whether the next request receives a response it did not ask for.

### 5.9 Framework-internal cache poisoning

The cache is not always a CDN. **Application frameworks maintain their own response caches**, and the same keyed/unkeyed logic applies — often with worse defaults.

| CVE | Product | Primitive |
|---|---|---|
| **CVE-2025-49005** | Next.js App Router | RSC payloads cached and served as HTML — **RSC/HTML cache key confusion** with omitted `Vary` |
| **CVE-2025-57752 / CVE-2025-55173** | Next.js | **Cache key confusion / cache deception** and **content injection / arbitrary file delivery** — fixed in 15.5.15 |
| **CVE-2026-25540** | Mastodon < 4.3.19 / 4.4.13 / 4.5.6 | ActivityPub collection responses are **signature-dependent** but cached under **signature-independent keys** when `AUTHORIZED_FETCH` is on — one actor's signed response is served to another |
| **CVE-2026-24472** | Hono cache middleware < 4.11.7 | **Ignores `Cache-Control: private`** → authenticated response cached and served to other users — **cache deception** |
| **CVE-2026-27118 (SvelteSpill)** | SvelteKit + Vercel | **Cache deception** in the framework's own caching layer |

**Next.js `__nextDataReq` research (zhero, 2025):** `__nextDataReq` converts a response to JSON but is **not part of the cache key**. Combined with `x-now-route-matches`, it poisons the **internal** Next.js cache with a stored XSS payload. This is a **framework-internal** cache, not a CDN mismatch — the same primitive applies to any SSR framework with a data-fetch cache.

---

## 6. Web Cache Deception

### 6.1 The mechanism

The victim is authenticated. The attacker sends them a link:

```
https://target.example/account/profile.css
```

- The **origin** routes `/account/profile.css` to the `/account` handler (it ignores or normalizes the suffix), returning the **private profile**.
- The **cache** sees a `.css` path, treats it as **static**, and stores the response under a **public** key.
- The attacker requests `/account/profile.css` and receives the victim's profile.

### 6.2 Path confusion — the 2026 technique

The **Gotta Cache 'em All** research shows that Nginx, Node, Cloudflare, CloudFront, and Google Cloud **decode certain delimiter characters before interpreting the pathname** — and Cloudflare/CloudFront can be configured to decode the path for caching or access control.

**Path confusion payloads:**

```
/account%0a.css
/account/;.js
/account?
/account#
/account/..%2fprofile.css
/account%2f.css
/account;.css
```

| Character | Effect |
|---|---|
| `%0a` | Newline — origin normalizes, cache treats as part of the extension |
| `;` | Matrix parameter — origin ignores, cache treats as a static suffix |
| `?` / `#` | Delimiter — origin and cache disagree on what is the path |
| `/..%2f` | Encoded traversal — origin resolves, cache does not |
| Trailing `/.` or `/..` | Normalization discrepancy |

**The test:** for each delimiter, request `/account<delimiter>.css` with an authenticated session and check whether (a) the origin returns the private page and (b) a **second, unauthenticated** request to the same URL returns the same content.

### 6.3 Cache deception vs cache poisoning — the 2026 split

The two classes now have **separate tooling and separate CVEs**:

- **WCVS 2.0** supports **9+ deception techniques** alongside its **10 poisoning techniques**.
- The 2025–2026 CVE feed contains **four pure deception bugs** (Hono, SvelteSpill, Next.js CVE-2025-57752, and the `Cache-Control: private` class) and **six pure poisoning bugs** (Varnish, Litestar, WP Fastest Cache, Mastodon, Django, `http-cache-semantics`).

> **Do not test only one.** A host that is clean for poisoning may be vulnerable to deception — the key and the origin disagree in the opposite direction.

### 6.4 The `Cache-Control: private` failure

If the origin sets `Cache-Control: private` on an authenticated response, the cache **must not** store it. **CVE-2026-24472 (Hono)** is the canonical failure: the middleware **ignores** the directive and caches the response anyway.

**Test:** authenticate, request `/account`, check for `Cache-Control: private`, then request `/account.css` and see whether the response is cached and retrievable **without** the session cookie.

---

## 7. Recent CVEs (2025–2026)

| CVE / Advisory | Product | Class |
|---|---|---|
| **CVE-2026-66746** | rouille 0.4.0–3.6.2 | **Response splitting** → cache poisoning, session fixation, CSP/CORS override |
| **CVE-2026-93750** | `http-cache-semantics` ≤ 4.2.0 | **`Vary` wildcard mismatch** → poisoning with sensitive data / tokens |
| **CVE-2026-50052** | Varnish < 9.0.3 / Vinyl < 9.0.1 | **HTTP/2 desync** → poisoning, auth bypass |
| **CVE-2026-0035** | Pingora < 0.8.0 | **Insecure default cache key** — only the URI path, excluding critical components |
| **RUSTSEC-2026-0388** | Pingora < 0.9.0 | **`:authority` / `Host` mismatch** → poisoning + access-control bypass |
| **CVE-2026-34475** | Varnish Cache | **Path `/` normalization failure** → cache manipulation / auth bypass |
| **PGV-2610611** | Litestar FileStore | **Unicode NFKD key collisions** → cache mixup / poisoning |
| **CVE-2026-25540** | Mastodon | **Signature-dependent content cached under signature-independent keys** |
| **CVE-2026-24472** | Hono < 4.11.7 | **Ignores `Cache-Control: private`** → cache deception |
| **CVE-2026-27118** | SvelteKit + Vercel | **SvelteSpill** — cache deception |
| **CVE-2026-35193** | Django | **`Authorization` missing from `Vary`** → poisoning + disclosure |
| **CVE-2025-69202** | axios-cache-interceptor < 1.11.1 | **`Vary: Authorization` ignored** → auth bypass |
| **CVE-2025-49005** | Next.js 15.3.0–15.3.2 | **`Vary` omitted** → RSC payload served as HTML |
| **CVE-2025-57752 / 55173** | Next.js | **Cache key confusion / deception** + **content injection** |
| **CVE-2026-11101** | Generic | **Unkeyed query parameter** (`utm_campaign`) → stored XSS |
| **CVE-2026-74916** | WP Fastest Cache 0.8.7.7–1.5.0 | **Unkeyed tracking parameters** → unauthenticated poisoning |
| **CVE-2020-28473** | Bottle | **Parameter cloaking** (`;` separator) — still the reference case |

---

## 8. Impact and Chaining

Cache poisoning is an **amplifier** — it rarely creates a vulnerability on its own and instead turns an existing one into a **stored, site-wide** issue.

| Existing bug | Poisoned into |
|---|---|
| **Reflected XSS** | **Stored XSS** — served to every visitor, no victim interaction |
| **Self-XSS** (in an unkeyed header) | **Reflected XSS** for all users |
| **Open redirect** | Site-wide redirect to an attacker domain |
| **Host header injection** | Password-reset link poisoning, cookie injection |
| **Request smuggling** | Backend desync → cache poisoning → auth bypass (CVE-2026-50052) |
| **Path confusion** | **Cache deception** — PII, session tokens, API keys |

**Cache deception impact** is the inverse: it turns a **private** response into a **public** one — PII, session tokens, API keys, and in some cases full account takeover.

> **The highest-value chain in 2026:** path confusion (deception) → authenticated response cached under a public URL → attacker retrieves session token or PII → account takeover. The "Gotta Cache 'em All" research found a single finding that gave **effective control over approximately 24 million websites** through CDN cache poisoning.

---

## 9. Testing Methodology

```text
1. Identify the cache
   - Look for X-Cache, X-Cache-Status, CF-Cache-Status, Age, Via
   - Determine the provider (Cloudflare, Akamai, Fastly, Varnish, Nginx, Next.js)

2. Establish a baseline
   - Request A → MISS, repeat → HIT
   - Record the response body and the cache headers

3. Add a cache buster
   - ?cb=<random> on every test request
   - Never poison without one

4. Classify keyed vs unkeyed
   - Change one parameter/header at a time
   - HIT with a changed body → unkeyed
   - MISS → keyed

5. Test poisoning
   - Unkeyed header → reflect into body (X-Forwarded-Host, X-Host, X-Forwarded-Scheme)
   - Unkeyed parameter → utm_*, tracking, callback
   - Fat GET → move a keyed param into the body
   - Parameter cloaking → ; %3b %26 && #
   - HTTP/2 header smuggling → duplicate Host / X-Forwarded-Host
   - Response splitting → CRLF in a reflected header

6. Test cache-key injection
   - Colliding paths: ﬁ/fi, Ａ/A, trailing /, null byte
   - Nginx concatenation without separators
   - Varnish "/" normalization (CVE-2026-34475)

7. Test deception
   - Authenticate, request /account, note Cache-Control
   - Request /account%0a.css, /account/;.js, /account?.css
   - Second request WITHOUT the cookie — is the content still served?
   - Check Cache-Control: private handling (Hono class)

8. Test Vary
   - Does the response depend on Authorization / Cookie / Accept-Language?
   - Is Vary present and correct?
   - Is Vary: * handled correctly? (http-cache-semantics class)

9. Time the poison
   - Read max-age / s-maxage
   - Send the poison at expiry, with concurrent requests to win the race

10. Verify impact
    - Request the URL from a clean browser / incognito / different IP
    - Confirm the payload is served without the attacker's session
```

---

## 10. Field Notes

- **Cache poisoning is an amplifier, not a primary bug.** Look for a reflected header or parameter first, then ask whether the cache keys on it.
- **Cache deception is the 2026 growth area.** WCVS 2.0 added 9+ deception techniques because the CVEs moved there — Hono, SvelteSpill, Next.js, and the `Cache-Control: private` class are all confidentiality bugs.
- **Path confusion is the technique.** `/account%0a.css`, `/account/;.js`, `/account?.css` — the delimiter that the origin normalizes away and the cache does not is the whole attack.
- **`Vary` is the most under-tested header in the stack.** CVE-2026-93750, CVE-2026-35193, CVE-2025-69202, and CVE-2025-49005 are all `Vary` failures — and three of the four are **library defaults**, not developer mistakes.
- **HTTP/2 introduced new smuggling vectors.** Duplicate `Host` / `X-Forwarded-Host` and `:authority` mismatch (Pingora) are 2026-specific primitives that HTTP/1.1 could not express.
- **Framework-internal caches are in scope.** Next.js `__nextDataReq`, RSC payloads, Mastodon `Rails.cache`, and Hono's middleware are all caches — and they are frequently **less hardened** than the CDN.
- **Always use a cache buster.** A poison test without one is a live attack on every user of the application.
- **`Cache-Control: no-cache` confirms, it does not poison.** It forces a fresh response for **you** — it does not replace the cached entry.
- **Win the race with threads.** On a hot URL, the entry is refreshed constantly; a single poison request will be overwritten before a victim sees it.
- **WCVS 2.0 is the fastest breadth sweep.** It covers 10 poisoning and 9+ deception classes with a crawler — then verify every finding by hand, because the tool cannot judge impact.
