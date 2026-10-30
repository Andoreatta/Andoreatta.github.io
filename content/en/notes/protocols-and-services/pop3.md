+++
title = 'POP3'
date = 2026-10-30
type = 'notes'
weight = 500
toc = true
tags = ['protocols', 'services', 'pop3']
+++

Post Office Protocol version 3 (POP3) is a mail retrieval protocol: a client connects to the mail server, authenticates, and **downloads** messages to the local machine. Unlike IMAP, POP3 is a **single-mailbox, download-and-store** protocol — it does not synchronise folders, flags, or server-side state.

**Default ports:**

| Port | Service | Encryption |
|---|---|---|
| **110** | POP3 | Plaintext — `STARTTLS` optional |
| **995** | **POP3S** | Implicit TLS |
| **110** | POP3 + `STLS` | STARTTLS upgrade |

> **2025–2026 context:** POP3 is legacy, and that is the entire security story. It is still deployed on mail appliances, cPanel/Plesk hosting, and industrial equipment because it is simple — and it is frequently **exposed to the internet without rate limiting**, with **plaintext credentials** on port 110, and with **no MFA**. The current attack surface is not the protocol itself but the **mail server implementation** (Dovecot, Courier, Cyrus, Exim, Postfix), where 2025–2026 produced a steady stream of CVEs in mail parsers, TLS handling, and authentication.

---

## 1. POP3 vs IMAP — What the Choice Tells You

The protocol in use determines what you can extract and how.

| | **POP3** | **IMAP** |
|---|---|---|
| **Mailbox model** | One INBOX, downloaded and deleted (or kept) | Multiple folders, server-side state |
| **State** | Stateless between sessions | Stateful — flags, read/unread, folders |
| **IDLE / push** | No | Yes — `IDLE` |
| **Typical port** | 110 / 995 | 143 / 993 |
| **What an attacker gains** | **Mail content only** — headers, bodies, attachments | **Mail content + folder structure + search + real-time monitoring** |

> **POP3 is a confidentiality target; IMAP is a live-intelligence target.** If the goal is credential discovery from mailbox content, POP3 is sufficient. If the goal is ongoing monitoring — password-reset emails, MFA codes, new-message alerts — IMAP `IDLE` is the better channel.

---

## 2. Basic Interaction

| Command | Purpose |
|---|---|
| `openssl s_client -connect <FQDN/IP>:pop3s` | Connect to POP3S (implicit TLS) |
| `openssl s_client -connect <FQDN/IP>:110 -starttls pop3` | STARTTLS upgrade on port 110 |
| `nc -nv <FQDN/IP> 110` | Raw banner grab |
| `telnet <FQDN/IP> 110` | Raw banner grab (alternative) |
| `hydra -L users.txt -p 'Company01!' -f <IP> pop3` | Login bruteforce |
| `hydra -L users.txt -P pass.txt <IP> pop3` | Credential pairing |
| `nmap -sV -p110,995 --script pop3-* <IP>` | Version and capability detection |

**Nmap scripts:**

```bash
nmap -sV -p110,995 --script "pop3-brute,pop3-capabilities,pop3-ntlm-info" <target>
```

`pop3-capabilities` returns the `CAPA` response without authenticating — **it is an unauthenticated enumeration primitive**.

---

## 3. POP3 Commands

| Command | Purpose |
|---|---|
| `USER username` | Identify the user |
| `PASS password` | Authenticate with the password |
| `STAT` | Number of saved emails and total size |
| `LIST` | Number and size of each email |
| `RETR id` | Retrieve a message by ID |
| `DELE id` | Mark a message for deletion (committed on `QUIT`) |
| `CAPA` | Server capabilities |
| `RSET` | Reset the session (unmark deletions) |
| `UIDL` | **Unique ID for each message** — survives reconnects |
| `TOP n lines` | Retrieve the headers and first `n` lines of a message |
| `NOOP` | No-op — keepalive |
| `QUIT` | Close the session (commits deletions) |
| `APOP user digest` | **MD5-based authentication** |
| `AUTH <mechanism>` | SASL authentication (PLAIN, LOGIN, CRAM-MD5, XOAUTH2, GSSAPI) |
| `STLS` | Upgrade to TLS (port 110 only) |

### 3.1 Manual session

```bash
nc -nv target 110
# +OK POP3 server ready
USER alice
# +OK
PASS P@ssw0rd
# +OK Logged in.
STAT
# +OK 3 4823
LIST
# +OK 3 messages
# 1 1204
# 2 2011
# 3 1608
RETR 1
# +OK 1204 octets
# (message contents)
QUIT
```

### 3.2 Scripted extraction

```bash
# List and retrieve every message in one session
(echo "USER alice"; echo "PASS P@ssw0rd"; echo "LIST"; echo "QUIT") | nc target 110
```

```bash
# Bulk retrieve with curl — supports POP3 natively
curl -k --user "alice:P@ssw0rd" "pop3s://target/1"    # message 1
curl -k --user "alice:P@ssw0rd" "pop3s://target/"      # mailbox listing
```

```bash
# Fetch the whole mailbox with fetchmail — writes a local mbox
fetchmail -k -p POP3 --ssl -u alice --password 'P@ssw0rd' target
```

> **`curl` and `fetchmail` handle the session state for you.** For an engagement where you need to extract 500 messages, `fetchmail` into an mbox and grep it is faster than scripting `RETR` in a loop.

### 3.3 `UIDL` — the enumeration primitive

`UIDL` returns a **persistent** identifier for each message. On some servers the UID is **derived from the message filename or content hash**, which leaks:

- **The server's internal mail directory layout**
- **Message arrival timestamps** (on servers that use `uidvalidity` + sequence)
- **Whether a message existed in a previous session** — useful for tracking new mail

```
UIDL
# +OK
# 1 whVmBcGZ
# 2 Xn2kOaPq
```

---

## 4. Authentication Attacks

POP3 has **no account lockout in the protocol** — lockout, rate limiting, and CAPTCHA are entirely server-side, and many deployments have none.

### 4.1 Bruteforce

```bash
# Hydra — single password against a user list, stop on first hit
hydra -L users.txt -p 'Company01!' -f <IP> pop3

# Hydra — user/password pairing
hydra -L users.txt -P /usr/share/wordlists/rockyou.txt <IP> pop3

# Medusa
medusa -h <IP> -U users.txt -P pass.txt -M pop3

# Nmap
nmap -p110 --script pop3-brute --script-args userdb=users.txt,passdb=pass.txt <IP>
```

> **POP3 bruteforce is frequently unrestricted.** CVE-2025-49195 (Media Server) is an FTP example of the same class — *“does not restrict authentication attempts”* — and POP3 servers are typically less hardened than FTP.

### 4.2 Password spraying

Spray **one password across every user**, respecting the server's lockout if it has one:

```bash
# Hydra with a single password and a user list
hydra -L users.txt -p 'Spring2026!' -f <IP> pop3

# Wait and repeat with the next password — do NOT loop inside one invocation
```

> **Check the lockout behaviour first.** Send 3–5 failed logins to a single account and observe whether the server responds `-ERR [AUTH]` (just an authentication failure) or `-ERR [IN-USE]` / `-ERR [SYS/TEMP]` (a lockout / throttle).

### 4.3 APOP — offline cracking

APOP authenticates with `APOP <user> <MD5(timestamp + shared-secret)>`. The server sends a timestamp in its banner, and the client returns an MD5 over that timestamp and the user's password.

```
+OK POP3 server ready <1896.697170952@dbc.mtview.ca.us>
APOP alice c4c9334bac560ecc979e58001b3e22fb
```

If the shared secret is the **password** (as it is in most implementations), a captured APOP exchange is a **crackable hash**:

```bash
# Format: <user>:<timestamp>:<MD5>
hashcat -m 20 hashes.txt /usr/share/wordlists/rockyou.txt
```

> **APOP is weaker than plaintext over TLS.** An attacker who captures the timestamp and digest can crack it offline **without the server** — and the timestamp is sent in the clear, so the digest is the only secret. Modern servers disable APOP for this reason; if `CAPA` lists it, it is still enabled.

### 4.4 SASL and OAuth2

```
CAPA
# +OK
# SASL PLAIN LOGIN CRAM-MD5 XOAUTH2
```

- **`PLAIN` and `LOGIN`** transmit the password base64-encoded — **equivalent to plaintext** if TLS is absent.
- **`CRAM-MD5`** is a challenge-response scheme — the hash is **crackable offline** but the password is not transmitted.
- **`XOAUTH2`** is the modern path — a leaked OAuth2 bearer token from a mail client, browser extension, or cloud tenant compromise authenticates **without the password**, and **without MFA**.

---

## 5. TLS and Credential Exposure

### 5.1 Is TLS actually enforced?

```bash
# Does the server advertise STARTTLS?
openssl s_client -connect target:110 -starttls pop3 -brief

# Is implicit TLS available?
openssl s_client -connect target:995 -brief

# Check the certificate
openssl s_client -connect target:995 -showcerts </dev/null 2>/dev/null | openssl x509 -noout -subject -dates
```

> **Port 110 without STARTTLS means credentials travel in the clear.** A network-positioned attacker — on the same VLAN, on a mirror port, or MITM — captures `USER`/`PASS` directly.

### 5.2 Downgrade and stripping

`STARTTLS` is **negotiated, not enforced**. An on-path attacker can strip the `STLS` capability from the `CAPA` response and the client falls back to plaintext — the classic **STARTTLS stripping** attack. The defence is **implicit TLS on 995** or **`require_ssl`** in the server configuration.

> **POP3S on 995 does not have this problem** — TLS starts immediately, and there is no negotiation to strip. This is why POP3S is preferred over `STARTTLS` for anything reachable.

### 5.3 Client-side TLS flaws

The same client-side class that affects IMAP and NFS applies to POP3 clients:

| Flaw | Impact |
|---|---|
| **No certificate validation** | The client accepts any certificate — a MITM proxy captures credentials |
| **No hostname verification** | A certificate for a different name is accepted |
| **Weak protocol versions** | TLS 1.0 / 1.1 still negotiated on legacy clients |

> **Thunderbird, Outlook, and mobile mail clients have all shipped with POP3 certificate-validation bugs.** If the engagement includes client-side testing, this is a distinct finding from the server configuration.

---

## 6. POP3 Mailbox as a Credential Source

A compromised mailbox is a **credential-discovery primitive**, not just an email-reading one. Mailboxes contain:

| Source | What it leaks |
|---|---|
| **Password reset emails** | Tokens and links for other services — often reusable |
| **Onboarding emails** | Initial passwords, VPN credentials, account names |
| **Vendor notifications** | API keys, monitoring alerts, infrastructure details |
| **Internal correspondence** | Usernames, org structure, system names |
| **Attachments** | Config files, backups, spreadsheets with credentials |
| **Headers** | Internal IPs, mail-server paths, SPF/DKIM infrastructure |

### 6.1 Extraction and grepping

```bash
# Fetch the mailbox into an mbox
fetchmail -k -p POP3 --ssl -u alice --password 'P@ssw0rd' target -f /tmp/alice.mbox

# Grep for credentials and tokens
grep -iE 'password|passwd|token|api[_-]?key|secret|vpn|reset' /tmp/alice.mbox

# Extract every URL — password resets, magic links, shared documents
grep -oE 'https?://[^" >]+' /tmp/alice.mbox | sort -u

# Extract every email address — for further spraying
grep -oE '[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}' /tmp/alice.mbox | sort -u
```

### 6.2 Password-reset interception

If the mailbox belongs to an account on the **same domain** as the target application, you can trigger a password reset on the application, **retrieve the reset email via POP3**, and complete the reset — **without knowing the original password**.

> **This is the account-takeover chain that makes a POP3 mailbox a critical finding.** The mailbox is the *recovery channel* for every other account tied to that address.

### 6.3 Headers as infrastructure reconnaissance

```
Received: from mail.internal.corp (10.0.5.12) by mx.corp.local
```

The `Received` chain reveals **internal mail servers, IP ranges, and hostnames** — the same information a DNS or SMTP banner grab provides, but **from inside the mailbox**, often with a more complete picture.

---

## 7. Recent CVEs in POP3 Mail Servers (2025–2026)

The POP3 protocol itself is stable; the **server implementations** are where the vulnerabilities live.

| CVE | Product | Primitive |
|---|---|---|
| **CVE-2025-59029** | Mail server (DNS) | Assertion failure via crafted records → **ANY query DoS** — affects mail servers using DNS lookups during delivery |
| **CVE-2025-49195** | Media Server | FTP login **does not restrict authentication attempts** — the same class applies to POP3 servers with no lockout |
| **CVE-2025-68206** | Linux kernel `nft_ct` | NAT sequence adjustment for FTP PASV — analogous POP3 data-channel issues exist in NAT'd deployments |
| **CVE-2026-XXXX** | Dovecot / Courier | Mail parser and TLS handling CVEs — check the specific version |
| **CVE-2026-XXXX** | Exim / Postfix | Mail transfer agent CVEs that affect mail delivery to POP3 mailboxes |

> **The pattern:** POP3 itself is not the vulnerability. The **mail server** — Dovecot, Courier, Cyrus, Exim, Postfix — and the **underlying libraries** (OpenSSL, the mail parser, the TLS stack) are where the exploitable bugs are. **Fingerprint the implementation and version**, then look up the CVEs for that specific product.

### 7.1 Fingerprinting

```bash
# Banner — reveals the server software and version on many deployments
nc -nv target 110
# +OK Dovecot ready.
# +OK Courier POP3 ready.
# +OK Cyrus POP3 v2.5.11 server ready.

# CAPA — capabilities reveal the SASL mechanisms and extensions
CAPA
# +OK Capability list follows
# TOP
# USER
# UIDL
# SASL PLAIN LOGIN
# IMPLEMENTATION Dovecot
```

---

## 8. Tooling

| Tool | Purpose |
|---|---|
| **`openssl s_client`** | TLS inspection, `STARTTLS` verification |
| **`nc` / `telnet`** | Manual protocol interaction |
| **`curl`** | `pop3://` and `pop3s://` support — scripting without a client |
| **`fetchmail`** | Bulk mailbox retrieval into mbox / Maildir |
| **Hydra / Medusa** | Authentication bruteforce |
| **`nmap --script pop3-*`** | Version, capabilities, NTLM info |
| **`swaks`** | SMTP, but also useful for testing the mail pipeline that feeds POP3 |
| **`hashcat -m 20`** | APOP digest cracking |

---

## 9. Testing Methodology

```text
1. Fingerprint
   - nc -nv target 110 → banner (Dovecot, Courier, Cyrus)
   - nmap -sV -p110,995 --script pop3-capabilities
   - CAPA → SASL mechanisms, UIDL, TOP

2. TLS posture
   - openssl s_client -connect target:110 -starttls pop3
   - openssl s_client -connect target:995
   - Is TLS enforced, or is STARTTLS strippable?

3. Authentication
   - Try default credentials (postmaster, admin, root)
   - Password spray one password across the user list
   - Hydra / Medusa if lockout is absent
   - APOP: capture the timestamp, crack the digest offline

4. Mailbox access
   - STAT / LIST → message count and sizes
   - UIDL → persistent IDs
   - RETR / TOP → retrieve headers and bodies
   - fetchmail → bulk mbox for grepping

5. Credential discovery
   - grep for password / token / api_key
   - Extract URLs → password resets, magic links
   - Extract email addresses → more spray targets
   - Received headers → internal infrastructure

6. Account takeover chain
   - Trigger a password reset on the target app
   - Retrieve the reset email via POP3
   - Complete the reset — no password required

7. Patch level
   - Identify the mail server implementation and version
   - Look up the CVEs for that specific product
```

---

## 10. Hardening

| Control | How |
|---|---|
| **Require TLS** | `ssl = required` in Dovecot; disable port 110 entirely if possible |
| **Prefer POP3S (995)** | Implicit TLS cannot be stripped, unlike `STARTTLS` |
| **Disable APOP** | `disable_plaintext_auth = yes` and remove `APOP` from `CAPA` |
| **Rate-limit authentication** | `auth_failure_delay`, fail2ban, or the server's native lockout |
| **Disable POP3 if IMAP is used** | Remove the POP3 service from the mail server |
| **Restrict reachability** | Firewall 110/995 to known client ranges; do not expose to the internet |
| **Per-application passwords** | Use app-specific credentials so a leaked mailbox password does not unlock the primary account |
| **MFA** | Where the mail server supports it (rare for POP3 — another reason to migrate to IMAP/OAuth) |
| **Patch the mail server** | Dovecot, Courier, Cyrus, Exim, Postfix — check the vendor advisories |
| **Monitor `CAPA` / `AUTH` failures** | A spike in failed `AUTH` from one source is a bruteforce |

---

## 11. Field Notes

- **POP3 is a confidentiality target, not a live-intelligence target.** It gives you the mailbox; IMAP `IDLE` gives you the mailbox *as it changes*.
- **`CAPA` is unauthenticated.** It reveals the server implementation, the SASL mechanisms, and whether `UIDL` and `TOP` are available — before you send a single credential.
- **APOP is weaker than plaintext over TLS.** A captured timestamp + digest is **offline-crackable** with `hashcat -m 20` — the password never needs to travel.
- **STARTTLS is strippable.** An on-path attacker removes `STLS` from `CAPA` and the client falls back to plaintext. **POP3S on 995 is immune** — use it.
- **POP3 has no protocol-level lockout.** Rate limiting is entirely server-side, and many deployments have none — Hydra is frequently unrestricted.
- **The mailbox is the recovery channel.** Trigger a password reset on the target app, retrieve the email via POP3, complete the reset — **no password required**.
- **`UIDL` leaks message identity.** Persistent IDs survive reconnects and, on some servers, encode the filename or arrival time.
- **Headers are infrastructure reconnaissance.** The `Received` chain reveals internal mail servers, IP ranges, and hostnames.
- **The CVEs are in the server, not the protocol.** Fingerprint Dovecot / Courier / Cyrus / Exim / Postfix and check *that* product's advisories.
- **POP3 is legacy.** The strongest security control is to disable it and migrate clients to IMAP over TLS with OAuth2 — which removes the plaintext password from the protocol entirely.
