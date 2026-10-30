+++
title = 'Insecure Direct Object References (IDOR)'
date = 2026-10-30
type = 'notes'
weight = 100
toc = true
tags = ['web', 'web-attacks', 'idor', 'authorization']
+++

IDOR (CWE-639) occurs when an application exposes an internal object reference — a database key, filename, UUID, or account identifier — and **fails to verify that the requesting user is authorised to access that specific object**. It is not a missing authentication problem; it is a missing **authorisation** problem. The user is authenticated, the request is legitimate, and the server simply trusts the identifier the client supplied.

IDOR is the most common and impactful API vulnerability. OWASP ranks **Broken Access Control (A01)** as the #1 web application risk in 2025, and **Broken Object Level Authorization (BOLA / API1)** as the #1 API risk. Roughly **33% of APIs have IDOR**, with typical bug-bounty payouts of **$500–$10k**.

> **IDOR vs BOLA:** the terms are often used interchangeably. BOLA is the API-specific term for object-level authorisation failure. The same root cause underlies both: **the server reads the object ID from the request instead of deriving the accessible object set from the authenticated user's identity**. A related variant, **BOPLA**, applies the same failure to object **properties** rather than objects.

---

## 1. Where Object References Live

Before testing, systematically map **every location** where the application references an object. A single endpoint often has several candidate parameters, and the vulnerable one is frequently the one the UI does not use.

| Location | Examples |
|---|---|
| **URL path** | `/api/users/1042`, `/documents/download/8291`, `/invoices/456` |
| **Query string** | `?user_id=1042`, `?file=report.pdf`, `?account=abc-def` |
| **Request body** | `{"account_id": 1042}`, `{"orderId": 8291}` |
| **HTTP headers** | `X-User-Id: 1042`, `X-Tenant-ID: 7`, `X-Customer-Id: 42` |
| **Cookies** | `user_session=base64(user_id:1042)` |
| **JWT claims** | `sub`, `user_id`, `tenant`, `role`, `org_id` |
| **File paths** | `/uploads/user_1042/avatar.jpg` |
| **GraphQL arguments** | `query { user(id: "1042") { ... } }` |
| **GraphQL variables** | `{"userId": "1042"}` |
| **WebSocket subscriptions** | `{"action":"subscribe","channel":"orders","uid":1042}` |

> **Hidden parameters:** if an endpoint does not expose an ID parameter, test whether it accepts one anyway. Tools such as **Arjun** and **paramminer** brute-force common ID parameter names (`id`, `user_id`, `account_id`, `uid`, `pid`, `uuid`, `tenant`, `org`).

---

## 2. Set Up Test Accounts

You need **at least two accounts** to test IDOR properly, and a third if vertical escalation is in scope.

| Account | Role | Purpose |
|---|---|---|
| **A — Attacker** | Regular user | The session that sends the forged request |
| **B — Victim** | Regular user, same privilege | Horizontal IDOR: A accesses B's resources |
| **C — Admin** | Administrator | Vertical IDOR: A accesses admin resources |

Create test objects under each account — an order, a document, a profile — and record their identifiers. The test matrix is:

- **A accessing B's object** → horizontal privilege escalation.
- **A accessing C's object / admin endpoint** → vertical privilege escalation.
- **Unauthenticated request** → authentication bypass.

---

## 3. Detection and Parameter Tampering

### 3.1 Numeric IDs

The simplest case: the identifier is a sequential integer. Walk the range **up, down, and around the edges**.

```http
GET /api/profile?id=1042      # Your own ID
GET /api/profile?id=1043      # Next user — IDOR?
GET /api/profile?id=1041      # Previous user
GET /api/profile?id=1         # Often the first / admin user
GET /api/profile?id=0         # Edge case
GET /api/profile?id=-1        # Edge case
```

### 3.2 String, slug, and email identifiers

Usernames, email addresses, and slugs are just as testable:

```http
GET /api/users/john.doe       # Your own account
GET /api/users/admin          # Privileged account
GET /api/users/jane.smith     # Another user
```

### 3.3 Encoded and hashed IDs

If the identifier is Base64, hex, or a hash, **decode it first** — the underlying value is often sequential or structurally predictable.

```bash
# Base64
echo 'eyJ1c2VyIjoxMDQyfQ==' | base64 -d
# {"user":1042}

# Try the sibling value
echo '{"user":1043}' | base64
# eyJ1c2VyIjoxMDQzfQ==

# MD5 / SHA1 — test whether the hash is of a known, guessable input
echo -n '1042' | md5sum
```

### 3.4 UUIDs are not automatically safe

Only **UUIDv4** is random. **UUIDv1 is time-based and partially predictable**, especially when the MAC address is known or can be deduced — a UUIDv1 used as an object reference or password-reset token is guessable.

```bash
# Check the UUID version — the first character of the third group
# v1: 550e8400-e29b-11d4-a716-446655440000   ← 1 = v1, predictable
# v4: 550e8400-e29b-41d4-a716-446655440000   ← 4 = v4, random
```

Also test the **nil UUID** (`00000000-0000-0000-0000-000000000000`), short IDs, and truncated UUIDs.

---

## 4. Bypass Techniques When the Obvious Tamper Fails

A direct `id=1043` swap is often blocked by a naive filter. The techniques below bypass common defences without changing the underlying authorisation flaw.

### 4.1 HTTP Parameter Pollution (HPP)

Supplying the same parameter **multiple times** causes different layers to disagree on which value is authoritative. The WAF may inspect the first value while the application reads the last — or vice versa.

```http
GET /api/profile?id=1042&id=1043
GET /api/profile?id=1043&id=1042
POST /api/profile
id=1042&id=1043
```

Some frameworks read the **first** occurrence, others the **last**, and some concatenate them. Test both orders.

### 4.2 Method switching

A parameter may be validated on `GET` but not on `POST`, `PUT`, or `PATCH` — or the other way around. If the UI only uses `GET`, try the same identifier in a `POST` body, or a `PUT` path.

```http
GET  /api/profile?id=1043
POST /api/profile    {"id": 1043}
PUT  /api/profile/1043
```

### 4.3 Encoding and format tampering

Filters that match a raw string can be bypassed by changing the encoding or format of the same value.

```text
1043            →  1043
%31%30%34%33   →  URL-encoded
MTA0Mw==       →  Base64
0x413          →  Hex
1043.0         →  Float
01043          →  Leading zero
1043%00        →  Null byte
10 43          →  Whitespace
```

### 4.4 JWT claim trust

A JWT is **not** a finding on its own — the finding is a **server that trusts a forged claim**. If the handler reads `user_id` from the token but also accepts a `user_id` query parameter as an override, test whether the override path enforces the same authorisation check.

```bash
# Decode the token
echo '<payload>' | base64 -d

# Tamper sub / user_id / tenant / role
# If the server acts on the modified claim (200 + other user's data), it trusts client-controlled claims
```

The test is **whether the change is trusted**: a `401` means the server verified; a `200` that returns another user's data is the finding.

### 4.5 Header and path normalisation

Case-sensitive paths and path-normalisation differences can bypass route-level ACLs.

```http
GET /Admin/profile
GET /admin/profile
GET /admin//profile
GET /./admin/profile
GET /admin/profile/..
GET /%2e/admin/profile
```

---

## 5. Advanced Vectors

### 5.1 GraphQL IDOR

GraphQL exposes every type, field, and argument through **introspection** — which makes it the highest-yield IDOR surface, because the schema tells you exactly which queries and mutations take an `id` argument.

```bash
# Introspect the schema
curl -X POST https://target.com/graphql \
  -H 'Content-Type: application/json' \
  -d '{"query":"{ __schema { types { name fields { name args { name type { name } } } } } }"}'
```

Any query or mutation field that takes an `id` argument **and lacks an ownership directive** (`@auth(requires: OWNER)`) is a candidate. **Mutations are higher value** because they often forget the ownership check that the read path has.

```graphql
# Read IDOR
query { user(id: "1043") { email, apiKey } }

# Mutation IDOR — often unprotected
mutation { updateUser(id: "1043", input: { email: "attacker@evil.com" }) { id } }
```

**Tools:** **GraphQLer** performs context-aware IDOR replay across GraphQL APIs, and **vamp-graphql-audit** fuzzes every ID-shaped argument with values such as `1`, `2`, `999`, `-1`, `"admin"`, and `null`. **graphql-mutation-idor** specifically tests whether Account B can execute privileged mutations on Account A's resources.

### 5.2 WebSocket IDOR

WebSocket subscriptions and broadcast channels are a frequently overlooked IDOR surface. If the client sends a `uid`, `channel`, or `tenant` parameter when subscribing, test whether another user's value is accepted.

```json
{"action":"subscribe","channel":"orders","uid":1043}
```

The WebSocket equivalent of an IDOR is a **broadcast channel authorisation failure**: a user subscribes to a channel they should not receive, and the server pushes other users' data in real time.

### 5.3 Multi-tenant IDOR

In a multi-tenant application, the tenant identifier (`org_id`, `tenant`, `customer_id`) is the object boundary. Test whether a request from Tenant A can access Tenant B's data by swapping the tenant parameter while keeping a valid session.

```http
GET /api/invoices/1001    X-Tenant-ID: A
GET /api/invoices/1001    X-Tenant-ID: B   ← cross-tenant leak?
```

**Tenant Isolation Mapper** automates this: send a request as Tenant A, enter Tenant B's cookie or auth header, and it returns a verdict of `VULNERABLE`, `LIKELY_VULNERABLE`, or `NOT_VULNERABLE` based on response similarity.

### 5.4 Blind and timing-based IDOR

When the response gives no direct data, **timing and error differences** can still confirm the flaw.

- **Timing side channel:** if valid IDs take longer to process than invalid ones, a difference in response time can confirm whether an object exists.
- **Error-message discrepancy:** a different error for "not found" versus "not authorised" leaks whether the object exists — even if access is denied.
- **Identifier walking:** sequential progression through the `id` parameter at machine cadence is cheap and has near-zero false positives on customer roles, though it is blind to targeted access.

### 5.5 Mass assignment / property-level IDOR

If the request body accepts fields the UI does not send, test adding `role`, `is_admin`, `tenant`, or `owner_id`. The server may bind them directly to the object without checking whether the caller is permitted to change them. This is **BOPLA** — the property-level variant of the same authorisation failure.

```json
{"name":"attacker","email":"a@evil.com","role":"admin","isAdmin":true}
```

---

## 6. Tooling

### 6.1 Burp Suite extensions

| Tool | What it does |
|---|---|
| **Repeater Strike** (PortSwigger, 2025) | AI-powered; analyses Repeater traffic, generates response regexes, mutates probes, and applies them across proxy history — turning one IDOR into a broader set of findings |
| **Autorize** | Replays every request with a lower-privileged session and flags responses that should have been denied |
| **AutorizePro** | Autorize with AI-assisted analysis; significantly lower false-positive rate |
| **ZeroX** | Firefox-container–aware session swapping; auto-replaces `Authorization` headers and generates an **Auth Matrix** across all cached sessions in one click |
| **Tenant Isolation Mapper** | Automated cross-tenant IDOR/BOLA testing with a similarity-based verdict and HTML report export |
| **Auto-IDOR-Hunter** | Passive, Python-based; uses **12 distinct bypass techniques**, including HPP, method switching, and parameter addition |
| **IDOR-Scanner** | Automates detection and enumeration of numeric fields |

### 6.2 CLI and framework tools

| Tool | What it does |
|---|---|
| **LogicPWN** | Python framework for business-logic testing; intelligent ID generation, role-based access testing, multi-tenant isolation, async across thousands of endpoints |
| **LeakRadar** | Open-core DAST for REST APIs; **cross-token pairwise heuristic matrix** with near-zero false positives; parses JWT claims, replays as User B, and exports redacted PoCs |
| **endpointscanner** | Replaces `{id}` variables with `1` across endpoints to automate IDOR/BAC testing |
| **GraphQLer** / **vamp-graphql-audit** / **graphql-mutation-idor** | GraphQL-specific IDOR fuzzing and cross-account mutation replay |
| **Arjun** / **paramminer** | Brute-force hidden ID parameter names |
| **Burp AI in Repeater** (2026) | On-demand assistant that checks related endpoints for similar behaviour and summarises a confirmed IDOR for reporting |

---

## 7. Real-World IDOR Examples (2025–2026)

| CVE / Advisory | Product | Primitive |
|---|---|---|
| **SuperAGI** (2026) | `update_user` | Authenticated user changes **any** user's password by supplying the target `user_id`; JWT is validated but never tied to the URL ID → **account takeover** |
| **Flowise ≤ 3.0.12** | User controllers | `checkPermission()` protects `POST`/`PUT`/`DELETE`, but the **`GET` read routes have no permission middleware** → read any user/organisation/workspace |
| **CVE-2026-79957** | ServiceNext | `/api/Usuario/GetUsuarios` accepts a user-controlled numeric ID without verifying ownership |
| **Open WebUI** (GHSA-4G37-7P2C-38R9) | Retrieval API | IDOR bypasses knowledge-base access controls |
| **Vikunja** (GHSA-MR3J-P26X-72X4) | Task comments | Read any task comment by ID regardless of access to the parent task |
| **IDURAR ERP CRM** (CVE-2026-81031) | Password update | Changes the password of whichever account a request names, not the requesting account |
| **CVE-2026-30823** | SSO configuration | IDOR → account takeover and enterprise feature bypass |

> **The common pattern in every case:** authentication is present and working. The failure is that the handler **reads the object ID from the request** and queries the database without an ownership or tenant filter.

---

## 8. Testing Methodology

```bash
# 1. Map every object reference
#    URL path · query · body · headers · cookies · JWT · GraphQL · WebSocket

# 2. Create A (attacker), B (victim), C (admin) accounts
#    Record each account's object IDs

# 3. Horizontal test — A accesses B's object
#    Try increment, decrement, and edge values
GET /api/profile?id=1043          # using A's session

# 4. Vertical test — A accesses C's object / admin endpoint
GET /api/admin/users/1001         # using A's session

# 5. If the direct swap fails, bypass:
#    - HPP:          ?id=1042&id=1043
#    - Method:       POST / PUT with the same ID
#    - Encoding:     base64, URL-encode, leading zero
#    - JWT claim:    tamper sub/user_id/tenant and observe
#    - Path:         /Admin vs /admin, /./admin

# 6. GraphQL — introspect, then fuzz every ID argument
#    Prioritise mutations

# 7. WebSocket — subscribe with another user's uid/channel

# 8. Multi-tenant — swap X-Tenant-ID / org_id with A's session

# 9. Blind — watch for timing and error-message differences

# 10. Chain — combine IDOR with SQLi, path traversal, or mass assignment
```

---

## 9. Field Notes

- **IDOR is the #1 bug-bounty payout because scanners cannot find it.** Authorisation is business logic — automated tools see a `200` and cannot tell whether the data belongs to the caller.
- **Map every parameter, not just the one the UI sends.** The vulnerable parameter is often a hidden or legacy one that the front end stopped using.
- **Read routes are the most common miss.** Flowise protected `POST`/`PUT`/`DELETE` with `checkPermission()` but left `GET` unprotected — a pattern that repeats across frameworks.
- **Mutations in GraphQL are higher value than queries.** The read path often has an ownership directive; the mutation does not.
- **UUIDv1 is predictable.** A time-based UUID used as an object reference or reset token is guessable; only v4 is random.
- **The JWT is not the finding — a server that trusts a forged claim is.** Decode, tamper, and observe whether the change is acted on.
- **HPP is the cheapest bypass.** `?id=1042&id=1043` costs nothing and frequently works because the WAF and the application disagree on which value is authoritative.
- **WebSocket subscriptions are an under-tested IDOR surface.** If the client sends a `uid` or `channel` on subscribe, swap it.
- **Chain IDOR with other bugs.** Combine it with SQLi, path traversal, or mass assignment to maximise impact — a simple read becomes account takeover.

---

## 10. Quick Reference

| Technique | Example |
|---|---|
| **Numeric tamper** | `?id=1042` → `?id=1043`, `?id=1`, `?id=0`, `?id=-1` |
| **String tamper** | `/users/john.doe` → `/users/admin` |
| **Base64 decode** | `eyJ1c2VyIjoxMDQyfQ==` → `{"user":1042}` → re-encode with `1043` |
| **UUIDv1** | `550e8400-e29b-11d4-...` — time-based, predictable |
| **HPP** | `?id=1042&id=1043` (test both orders) |
| **Method switch** | Same ID in `POST` body or `PUT` path |
| **Encoding** | URL-encode, double-encode, leading zero, null byte |
| **JWT claim** | Tamper `sub` / `user_id` / `tenant`; observe if trusted |
| **Path normalisation** | `/Admin`, `/./admin`, `/admin//profile`, `/%2e/admin` |
| **GraphQL** | Introspect → fuzz every `id` argument → prioritise mutations |
| **WebSocket** | Subscribe with another user's `uid` / `channel` |
| **Multi-tenant** | Swap `X-Tenant-ID` / `org_id` with a valid session |
| **Blind** | Timing difference, error-message discrepancy, identifier walking |
| **Mass assignment** | Add `role`, `isAdmin`, `owner_id` to the request body |

This file sits alongside the **CSRF** and **HTTP Verb Tampering** notes: verb tampering bypasses method-specific ACLs, CSRF forces requests the victim did not intend, and IDOR abuses the object references those requests carry.
