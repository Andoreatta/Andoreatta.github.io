+++
title = 'OAuth Attacks'
date = 2026-10-30
type = 'notes'
weight = 80
toc = true
tags = ['web', 'web-attacks', 'oauth', 'authentication']
+++

OAuth is a standard designed to enable secure authorization between services and applications. It is widely used in Single Sign-On (SSO) scenarios, where a user can authenticate once and access multiple applications without sharing their credentials with each service.

> **2025–2026 context:** OAuth 2.0/2.1 is now the backbone of almost every authentication system, and the vulnerability classes have moved **out of the redirect_uri parameter** and into the **libraries that implement the flows**. The current CVE feed is dominated by **state-parameter persistence failures** (Authlib, fastapi-sso), **PKCE downgrade bypasses** (Cloudflare workers-oauth-provider), **OAuth email-linking account takeover** (Pingvin Share, AshAuthentication), **unauthenticated callback fallback** (Feathers, CVSS 9.8), and **dynamic client registration** that accepts arbitrary redirect URIs.

<details>

<summary>OAuth Basic Overview</summary>

#### OAuth Entities

- **Resource Owner** — the user who owns the protected resources.
- **Client** — the application requesting access on behalf of the user.
- **Authorization Server** — authenticates the user and issues access tokens.
- **Resource Server** — hosts the protected resources (may be the same as the authorization server).

#### OAuth Standard Communication Flow

1. The client requests authorization from the user.
2. The user consents, granting authorization.
3. The client presents the authorization grant to the authorization server.
4. The client receives an access token.
5. The client presents the access token to the resource server.
6. The client receives the resource.

#### Authorization Code Grant

The most common and secure OAuth flow. Tokens are exchanged **server-to-server**, never through the user's browser.

#### Implicit Grant

A simplified flow for clients that cannot securely store a client secret. The access token is sent from the OAuth service to the client **via the user's browser as a URL fragment** — less secure, deprecated in OAuth 2.1.

</details>

---

## 1. Identifying OAuth Authentication

Look for "Log in with …" options. All OAuth flows begin with a request to the `/authorization` endpoint with parameters:

```
response_type   code | token
client_id       the client's identifier
redirect_uri    where the auth server sends the user back
scope           requested permissions
state           anti-CSRF value (optional but critical)
code_challenge  PKCE (OAuth 2.1)
code_challenge_method  S256 | plain
```

`response_type=token` selects the **implicit grant**; `response_type=code` selects the **authorization code grant**.

**Discovery endpoints** often reveal more surface than the documentation:

```
/.well-known/oauth-authorization-server
/.well-known/openid-configuration
```

These return JSON with the **authorization endpoint**, **token endpoint**, **JWKS URI**, **supported grant types**, **scopes**, and **claims** — a complete map of the attack surface.

---

## 2. Stealing Access Tokens via `redirect_uri`

The authorization server must verify that the `redirect_uri` is one the client registered. When it does not, an attacker can redirect the victim's authorization code to their own server.

### 2.1 The attack

1. Craft an authorization URL with a `redirect_uri` pointing at the attacker's server, and a **fixed `state`** value (it must be identical for the entire attack).
2. Use the target application's `client_id` — obtain it by starting a legitimate OAuth flow.
3. Send the link to the victim. The victim authenticates, and the authorization server redirects them to the attacker's server with `?code=<victim-code>&state=<state>`.
4. The attacker captures the code and completes the token exchange themselves: `GET /client/callback?code=<stolen-code>&state=<state>`.
5. The client exchanges the code for a token, and the token is returned — the attacker now holds a valid token for the victim.

### 2.2 Redirect URI bypasses (2026)

The whitelist is usually a **string comparison** — prefix, suffix, or `contains` — rather than an **exact match**. The 2026 bypass suite covers **15–22 variants**:

| Technique | Payload (attacker owns `attacker.server`) |
|---|---|
| **Subdomain prefix** | `https://example.com.attacker.server/callback` |
| **`@` confusion** | `https://example.com@attacker.server` |
| **Query parameter** | `https://attacker.server/callback?a=https://example.com` |
| **Fragment** | `https://attacker.server/callback#https://example.com` |
| **Path traversal** | `https://example.com/cb/../../../steal` |
| **Prefix match** | `https://target.com.evil.com` |
| **Suffix match** | `https://evil.target.com` |
| **Null byte** | `https://target.com%00.attacker.server` |
| **Fragment injection** | `https://target.com/callback%23@evil.com` |
| **Port variation** | `https://target.com:8443/callback` |
| **Scheme variation** | `http://target.com/callback` |

**Automated tooling:** [OAUTH-Flow-Analyzer](https://github.com/Zeeshanafridai/OAUTH-Flow-Analyzer) tests 15+ `redirect_uri` variants, state CSRF, PKCE downgrade, scope escalation, and token leakage. It is **zero-dependency Python 3.6+** and accepts `--attacker <your-domain>` to generate the bypass URLs.

> A misconfigured `redirect_uri` is also an **open redirect and an SSRF primitive** — the authorization server fetches the redirect target in some configurations, and the open redirect can be chained to reach internal services.

### 2.3 Real-world `redirect_uri` CVEs (2025–2026)

| CVE / Advisory | Product | Primitive |
|---|---|---|
| **GHSA-X3F4-V83F-7WP2** | Authorizer | **6 endpoints** append tokens to an unvalidated `redirect_uri`; the GraphQL mutations and `verify_email` handler **skip validation entirely** → steal password-reset tokens, magic links, and full auth sessions (`access_token` + `id_token` + `refresh_token`) |
| **CVE-2026-117553** | Umbraco CMS < 17.7.2 / 18.2.2 | **Host-header poisoning** → register an attacker-controlled redirect URI, then use `response_mode=form_post` to capture codes |
| **CVE-2026-116672** | Authlib 0.15 – 1.9.1 | Changing `redirect_uris` after client registration is not validated |
| **CVE-2026-101062** | Obot ≤ 0.22.1 | Dynamic client registration **without authentication** and **without redirect URI restrictions** |

---

## 3. CSRF via Missing or Weak `state`

The `state` parameter is the OAuth flow's **anti-CSRF measure**. It must be **random**, **bound to the user's session**, and **validated on callback**. When any of those fail, the flow is vulnerable to **login CSRF** — the attacker tricks the victim into completing an OAuth flow with the **attacker's account**, binding the victim's session to the attacker's identity.

### 3.1 The attack

1. The attacker initiates an authorization request and captures the **authorization code** tied to **their own** account.
2. The attacker crafts the callback URL: `http://example.com/client/callback?code=<attacker-code>`.
3. The attacker delivers the link to the victim.
4. The victim's browser completes the flow and logs in as the **attacker**.

This is not a trivial finding: it lets the attacker **capture everything the victim does in that session** — saved payment methods, uploaded documents, personal data — because the victim is operating inside the attacker's account.

### 3.2 Why `state` fails in practice (2025–2026)

The `state` parameter is present and **looks** correct, but the **binding** is missing:

| CVE | Library | Failure |
|---|---|---|
| **CVE-2025-14546** | fastapi-sso < 0.19.0 | `get_login_url()` generates a state but **does not persist it**; `verify_and_process()` accepts any state from the query string without comparing it to a session value |
| **CVE-2025-68481** | Authlib (cache-backed storage) | `set_state_data()` writes the state blob to the **cache** under `_state_{app}_{state}`, and `get_state_data()` **disregards the session entirely** — any browser presenting the opaque value succeeds |
| **GHSA-FG6F-75JQ-6523** | Authlib | The same cache-backed flaw → **one-click account takeover** when the application links accounts on login |
| **CVE-2025-10752** | WordPress OAuth SSO plugin ≤ 6.26.12 | `state` is a **base64-encoded app name** with no randomness — predictable and replayable |
| **CVE-2026-48612** | Various | Improper state verification → account linking between victim and attacker |
| **CVE-2026-115910** | python-social-auth < 6.2.0 | Authorization-code interception and **state manipulation** in the OIDC implementation |

**The common pattern:** the library implements `state` as a **signed JWT that verifies cryptographically** but is **not bound to the initiating session**. The signature is valid, the expiry is valid, and the flow completes — for **whichever browser presents it**.

> **The correct implementation** stores the state in the **user's session** and compares the callback's state to that stored value. A signed JWT is not a session binding. Storing the state in a **shared cache** is not a session binding.

### 3.3 State XSS

If the `state` value is **reflected** into the page without encoding, it becomes an XSS vector inside the OAuth callback — the attacker controls the `state` in the authorization URL, and the callback page reflects it.

---

## 4. Token Leakage — Implicit Flow and PKCE Downgrade

### 4.1 Implicit flow token leakage

The implicit grant returns the access token in the **URL fragment** (`#access_token=...`). Fragments are:

- Stored in **browser history**
- Sent in the **`Referer` header** when the page loads an external resource
- Logged in **proxy and server logs** if the fragment is ever sent to the server
- Accessible to **any JavaScript** on the page, including third-party scripts

**CVE-2026-7571 (Keycloak)** — a low-privilege user with valid credentials and the client ID can **bypass the control that disables the implicit flow** by manipulating client data during a session restart. The access token that should not be available is issued, and it leaks into **server logs, proxy logs, and `Referer` headers**.

**CVE-2026-101062 (Obot)** and **CVE-2026-108718 (Rill)** both involve authorization codes issued to **dynamically registered clients without user consent** — another route to token leakage.

### 4.2 PKCE downgrade

PKCE (`code_challenge` / `code_verifier`) is the OAuth 2.1 defence against authorization-code interception. It is **required** in OAuth 2.1 and in the **MCP specification**.

A **PKCE downgrade** attack removes or weakens the PKCE parameters so the authorization server skips the check:

- **Omit `code_challenge`** from the authorization request — if the server treats PKCE as optional, it issues a code that does not require a verifier.
- **Use `code_challenge_method=plain`** instead of `S256` — the verifier is the challenge, so interception is trivial.
- **Strip the `code_verifier`** from the token request — if the server does not enforce it, the exchange succeeds.

**CVE-2025-4144 (@cloudflare/workers-oauth-provider)** — the OAuth provider used by the **MCP framework** had a PKCE implementation where an attacker could **cause the check to be skipped entirely**. The advisory states explicitly: *“This bug completely bypasses PKCE protection.”* It is fixed in **0.0.5**.

> **MCP servers are a 2026 hotspot.** The MCP specification requires OAuth 2.1, which requires PKCE — so a PKCE bypass in an MCP OAuth provider is a bypass of the framework's own security baseline.

---

## 5. Account Takeover via OAuth Email Linking

This is the **fastest-growing OAuth vulnerability class in 2025–2026**, and it does not require breaking the protocol at all. The flaw is in the **application's account-linking logic**.

### 5.1 The pattern

The application supports "Sign in with Google/GitHub/OIDC". When a user signs in, the application:

1. Receives the OAuth profile, including the `email` claim.
2. Looks up an existing local account **by email**.
3. Links the OAuth identity to that account — or signs in as that account.

**If the application does not check `email_verified`,** an attacker can:

1. Register an account with the **victim's email** at an OAuth provider that **does not verify emails** (or where the attacker controls the verification).
2. Sign in to the victim application with that OAuth identity.
3. The application matches the email to the **victim's local account** and signs the attacker in as the victim.

### 5.2 Real-world CVEs

| CVE / Advisory | Product | Primitive |
|---|---|---|
| **CVE-2026-108157 (GHSA-7P7C-6QWR-Q8J7)** | Pingvin Share X 0.19.0–1.22.0 | **Missing `email_verified` check** in `GenericOidcProvider` → register the victim's unverified email on an OAuth provider → sign in as the victim, **including administrators**, and **bypass TOTP** |
| **CVE-2026-88952** | AshAuthentication | Link an OAuth2 identity to an account that is **not the attacker's** → sign in as another user |
| **CVE-2026-49757** | AshAuthentication | OAuth2/OIDC sign-in resolves users **by email** (upsert on the email field) → account takeover of local users |
| **CVE-2026-29792 (GHSA-WG9X-QFGW-PXHJ)** | Feathers `@feathersjs/authentication-oauth` ≤ 5.0.41 | **CVSS 9.8** — an unauthenticated attacker sends a crafted `GET /oauth/:provider/callback` with a **forged profile in the query string**. Grant's session is empty (no authorize flow was started), so the fallback chain reaches `params.query` and **mints a valid JWT for an existing user without ever contacting the OAuth provider** |

> **The Feathers bug is the most severe of the class** because it requires **no OAuth provider interaction at all** — the callback handler trusts the query string when the session is empty. A missing state check and a permissive fallback chain combine into an unauthenticated account takeover.

---

## 6. Audience Injection Attacks (2026 research class)

A new class documented in 2026: **Audience Injection Attacks on Web-Based Authorization and Authentication Standards**. The attack manipulates the **`aud` (audience) claim** — or the equivalent audience parameter — so that a token issued for one service is **accepted by a different service**.

**Where it applies:** any multi-service deployment that shares an authorization server and relies on the audience claim to scope tokens. If the resource server validates the signature but not the audience — or validates it against an **attacker-influenced** value — a token minted for a low-privilege service is accepted by a high-privilege one.

This is the OAuth/OIDC analogue of **JWT `aud` confusion** and belongs in the testing checklist alongside `redirect_uri` and `state`.

---

## 7. Dynamic Client Registration Abuse

OAuth **Dynamic Client Registration (DCR)** lets a client register itself with the authorization server at runtime. When it is exposed **without authentication** and **without restricting `redirect_uris`**, an attacker can:

1. Register a new client with a `redirect_uri` they control.
2. Use that client to obtain authorization codes for the target application's users.

| CVE | Product | Primitive |
|---|---|---|
| **CVE-2026-101062** | Obot ≤ 0.22.1 | DCR **without authentication**, **without redirect URI restrictions** |
| **CVE-2026-93354** | Taskview Community < 1.56.0 | Unauthenticated DCR → arbitrary OAuth clients → account takeover |
| **CVE-2026-108718** | Rill 0.77.0–0.90.5 | Admin OAuth server issues codes to **dynamically registered clients without user consent** |

> **Testing:** send a `POST` to the registration endpoint (`/register`, `/oauth/register`, or the `registration_endpoint` from the discovery document) with a `redirect_uris` value you control. If it returns a `client_id`, DCR is open.

---

## 8. OIDC-Specific Issues

| Issue | Impact |
|---|---|
| **`id_token` with `alg: none`** | Forge an identity token — the resource server accepts it without verification |
| **Missing `nonce` validation** | Replay an `id_token` from a different session |
| **`email_verified` not checked** | Account takeover via email linking (§5) |
| **`iss` / `aud` not validated** | Accept tokens from a different issuer or audience (§6) |
| **UserInfo endpoint unauthenticated** | Enumerate user profiles |
| **`at_hash` not validated** | Bind an `id_token` to a different access token |
| **JWKS endpoint injection** | Supply your own key set via the `jku` / `x5u` claim |

**OAUTH-Flow-Analyzer** includes an OIDC module that checks `UserInfo` without auth, `alg:none` `id_token`, missing `nonce`, and `email_verified` bypass.

---

## 9. Testing Methodology

```bash
# 1. Map the flow
#    Intercept the /authorization request — record client_id, redirect_uri,
#    response_type, scope, state, code_challenge

# 2. Test redirect_uri
#    Try each bypass: subdomain, @, path traversal, fragment, null byte, port
#    Use OAUTH-Flow-Analyzer with --attacker <your-domain>

# 3. Test state
#    Remove it — does the flow still complete?
#    Replay an old state — is it accepted?
#    Start a flow, capture the state, complete it in a different browser

# 4. Test PKCE
#    Omit code_challenge — does the server still issue a code?
#    Use plain instead of S256
#    Omit code_verifier from the token request

# 5. Test token leakage
#    response_type=token — is the token in the fragment?
#    Check Referer headers, browser history, server logs

# 6. Test account linking
#    Register an OAuth account with the victim's email (unverified)
#    Sign in — does the application merge accounts?

# 7. Test the callback handler directly
#    GET /oauth/:provider/callback?profile=<forged>
#    If the session is empty, does the handler fall back to the query string?

# 8. Test DCR
#    POST to the registration endpoint with your redirect_uri

# 9. Test audience
#    Request a token for a low-privilege service, use it against a high-privilege one
```

---

## 10. Quick Reference — 2025–2026 CVEs

| CVE / Advisory | Product | Class |
|---|---|---|
| **CVE-2026-108157** | Pingvin Share X | Missing `email_verified` → account takeover + TOTP bypass |
| **CVE-2026-29792** | Feathers | **CVSS 9.8** — forged callback profile → JWT without provider |
| **CVE-2026-88952 / 49757** | AshAuthentication | OAuth identity linked to the wrong account |
| **CVE-2026-7571** | Keycloak | Implicit flow bypass + token leakage into logs/`Referer` |
| **CVE-2025-4144** | Cloudflare workers-oauth-provider | **PKCE completely bypassed** via downgrade |
| **CVE-2025-14546** | fastapi-sso | State generated but not persisted → CSRF |
| **GHSA-FG6F-75JQ-6523** | Authlib | Cache-backed state not session-bound → **1-click account takeover** |
| **CVE-2025-10752** | WordPress OAuth SSO | Predictable `state` (base64 app name) |
| **CVE-2026-115910** | python-social-auth < 6.2.0 | Code interception + state manipulation |
| **CVE-2026-117553** | Umbraco CMS | Host-header poisoning → attacker-controlled redirect URI |
| **CVE-2026-101062** | Obot | Unauthenticated DCR, unrestricted redirect URIs |
| **CVE-2026-93354** | Taskview Community | DCR → account takeover |
| **CVE-2026-108718** | Rill | Codes issued to dynamic clients without consent |
| **GHSA-X3F4-V83F-7WP2** | Authorizer | 6 endpoints append tokens to unvalidated `redirect_uri` |
| **CVE-2026-116672** | Authlib 0.15–1.9.1 | `redirect_uris` changes not validated |

---

## 11. Field Notes

- **The redirect_uri bypass is not dead — it moved into libraries.** GHSA-X3F4-V83F-7WP2 is a case where **6 endpoints** skipped validation while the rest of the application validated correctly. Test every callback and token-appending endpoint, not just `/authorize`.
- **State must be bound to the session, not just signed.** CVE-2025-14546 and GHSA-FG6F-75JQ-6523 are both cases where the state is cryptographically valid but not tied to the browser that started the flow.
- **PKCE downgrade is the OAuth 2.1 bypass.** CVE-2025-4144 "completely bypasses PKCE protection" in the MCP framework's own provider. Test whether `code_challenge` is optional.
- **The callback handler is the 2026 attack surface.** CVE-2026-29792 (Feathers) mints a JWT from a **forged query-string profile** when the session is empty. Send a direct `GET` to the callback without starting a flow.
- **`email_verified` is the account-takeover gate.** CVE-2026-108157 signs in as administrators and **bypasses TOTP** because the application linked an OAuth identity to a local account by unverified email.
- **DCR without restrictions is an open redirect with extra steps.** If you can register a client with your own `redirect_uri`, you can steal codes.
- **Implicit flow tokens leak everywhere.** Fragments reach the `Referer`, browser history, and logs — CVE-2026-7571 is exactly that.
- **Audience injection is the 2026 research class.** A token minted for one service must not be accepted by another; test `aud` validation.
- **OAUTH-Flow-Analyzer covers 15+ redirect_uri variants, state CSRF, PKCE downgrade, and OIDC checks** with zero dependencies — the fastest way to run the full suite against a target.
