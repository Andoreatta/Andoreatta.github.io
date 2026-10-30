+++
title = 'Pentesting Methodology'
date = 2026-10-30
type = 'notes'
weight = 10
toc = true
tags = ['oscp', 'methodology']
+++

> A methodology is a **decision loop**, not a linear checklist. You gather facts, choose the cheapest action that could confirm or kill a hypothesis, record the result, and re-enter the loop. Phases below are named for orientation; in practice you drop back to enumeration every time something new appears — a share, a password, a hostname, a service banner.
>
> **2025–2026 context:** This methodology is built for a landscape where **identity is the new perimeter** (OAuth, SAML, ADCS, cloud IAM), **defenders automate containment** (EDR, SOAR, automated account disabling), and **exploits are increasingly deterministic** (page-cache LPEs, parser differentials) rather than memory-corruption races. The loop is more important than ever: "Try harder" is not a strategy; "Read the source, check the clock, reuse the password" is.

The loop only runs inside authorization. Scope, rules of engagement and a named emergency contact come before the first packet, and every finding is written down as it happens, not reconstructed afterwards.

Companion pages: [commands](/notes/oscp-labs/commands/) · [patterns](/notes/oscp-labs/patterns/) · [Linux machines](/notes/oscp-labs/linux/) · [Windows](/notes/oscp-labs/windows/) · [AD](/notes/oscp-labs/ad/) · [lab index](/notes/oscp-labs/).

## Phase 0 — Scope and rules of engagement

Written authorization is the boundary of the entire engagement. If a target is not named in it, it is out of scope — including "adjacent" hosts you discover, cloud endpoints, and third-party services the client uses.

| Question | What to get in writing |
| -------- | ---------------------- |
| Who authorized this? | Signatory name, role, document reference/date |
| What is in scope? | CIDR ranges, hostnames, domains, **cloud accounts (AWS/Azure/GCP tenant IDs), OAuth/SSO applications**, credentials provided |
| What is explicitly out? | Production clusters, third parties, client endpoints, social engineering, DoS, **third-party SaaS APIs** |
| When may testing run? | Date range, allowed hours, blackout windows, change freezes |
| Which techniques are prohibited? | Destructive payloads, password spraying against production, phishing, physical entry, data exfiltration, **NTLM poisoning/relaying on shared segments** |
| How do we handle a critical finding? | Escalation contact, threshold, channel, whether to pause |
| What happens if we break something? | Emergency stop procedure and contact, rollback expectations |
| What is the objective? | "Prove domain compromise" differs from "test this web app" |

{{< hint warning >}}
A verbal "go ahead" is not scope. If the signed document and the request disagree, stop and get the document amended — the emergency contact is there for exactly this conversation, not only for outages.
{{< /hint >}}

**Pre-engagement checklist**

- [ ] Signed authorization / statement of work with the exact in-scope list attached.
- [ ] Rules of engagement reviewed with the client technical contact.
- [ ] Emergency contact, escalation path and stop phrase agreed in both directions.
- [ ] Testing window and blackout dates in the calendar, in the client's timezone.
- [ ] Prohibited techniques and rate limits written down (spraying, brute force, stress).
- [ ] Test accounts and provided credentials collected; source IPs allow-listed where needed.
- [ ] Out-of-band communication channel (not the target network) for the test team.
- [ ] Note vault created, directory structure and naming convention agreed.
- [ ] Clock/timezone noted; screenshots will carry timestamps.
- [ ] Data handling and deletion plan confirmed.

Log from minute zero: start time, source IP, target, command, output file, result. A finding you cannot reproduce or timestamp is a rumour, and the report will show it.

## Phase 1 — Reconnaissance

Reconnaissance answers "what exists and who owns it"; enumeration answers "how does it behave". Keep them separate so you do not start attacking before the asset list is stable.

| Mode | Examples | Trade-off |
| ---- | -------- | --------- |
| Passive | OSINT, WHOIS/RDAP, certificate transparency, DNS records, search engines, job ads, GitHub, breach data | No direct contact; may be stale, incomplete, or legally sensitive |
| Active | Port/service scans, DNS zone transfer attempts, vhost/subdomain fuzzing, banner grabbing, web crawling | Reliable and current; visible to defenders and IDS |

**What "enough" looks like**

- An asset list with an owner/purpose per entry, including hosts discovered but not yet reachable.
- Every in-scope host mapped to open TCP ports, UDP services where relevant, and a service/version guess.
- A shortlist of candidate entry points, ranked by cost: exposed admin panel, default-credential service, unauthenticated file access, known-vulnerable version, web bug.
- No unexplained open port: every port is either enumerated or explicitly deferred with a reason.

**When to switch from passive to active**

- Passive reconnaissance stops producing new assets or names.
- The scope is an IP range, so there is nothing to discover passively.
- The timebox for the passive phase expires — for most internal engagements that is well under an hour.

**Deliverables**

| Artifact | Content |
| -------- | ------- |
| Asset list | IP, hostname, role, OS guess, owner, in-scope flag |
| Service map | Port, protocol, banner/version, auth required, TLS details |
| Candidate credentials | Usernames, email pattern, defaults tried, secrets found |
| Attack surface notes | Vhosts, directories, APIs, shares, exposed files |
| Evidence log | Raw scan output, timestamps, source IP, tool versions |

Method and commands for this phase live in [Information Gathering](/notes/web-applications/information-gathering/) and [Fuzzing](/notes/web-applications/fuzzing/).

## Phase 2 — Enumeration

Enumeration is a **service-by-service loop**, repeated until a service either yields a path or is exhausted:

1. **Identify** — confirm protocol and product from the banner, behavior, and TLS certificate, not just the port number.
2. **Version** — get an exact version; check the artifact (binary, JAR, plugin readme) when the banner may lie.
3. **Defaults and configuration** — default credentials, anonymous/guest access, exposed config, directory listing, management endpoints.
4. **Content** — vhosts first, then directories and files; read page source, comments, headers, error messages.
5. **Known issues** — version → CVE, with the exploit's preconditions checked before running it.
6. **Credentials** — harvest from configs, shares, mail, source control, then reuse everywhere.
7. **Record** — update the host notes and move to the next service; return when new facts appear.

**Read before you fuzz.** Fuzzing is expensive and noisy; reading is cheap. Check the page source, `robots.txt`, `sitemap.xml`, linked JavaScript, API docs, error pages, response headers, and the application's own source (`.git`, backups, JAR/ZIP) before launching a wordlist. A path leaked by an HTML comment or a `readme.txt` beats a million requests. When you do fuzz, calibrate against a baseline response and filter by size/words, not status code alone — wildcard 200s and soft 404s make every result look valid.

**Version → CVE discipline**

- Confirm the exact version from the product itself (`--version`, changelog, bundled binary), not from a generic `Server:` header.
- Read the advisory/PoC: which versions, which endpoint, which preconditions, does it need auth?
- Check whether the target actually exposes the vulnerable component — a vulnerable library that is never reached is not a finding.
- Prefer the PoC that gives command output or a file read over one that needs a working reverse route.

**Decision table**

| Finding | Next action | Note page |
| ------- | ----------- | --------- |
| Port open outside the top 1000, or scan shows filtered | Full `-p-` scan, then `-sCV` on the new ports; check UDP separately | [Information Gathering](/notes/web-applications/information-gathering/) |
| HTTP server that looks like a decoy at the IP root | Vhost fuzz with `ffuf -H "Host: FUZZ.<domain>" -ac`; compare against a random Host baseline | [Fuzzing](/notes/web-applications/fuzzing/) |
| `.git`, `.svn`, backup archive, or config backup exposed | Dump/reconstruct, read history and diffs, search for credentials and endpoints | [Linux machines](/notes/oscp-labs/linux/) |
| Anonymous FTP / NFS export / SMB share | List and recurse; treat every document, script and config as a credential source | [FTP](/notes/protocols-and-services/ftp/), [NFS](/notes/protocols-and-services/nfs/), [SMB](/notes/protocols-and-services/smb/) |
| SMB null or guest session | `smbclient -N -L`, `rpcclient -U "" -N` → `enumdomusers`, `nxc smb --rid-brute` | [SMB](/notes/protocols-and-services/smb/), [AD](/notes/active-directory/checklist/) |
| SNMP reachable | Walk the tree; process command lines often contain passwords | [SNMP](/notes/protocols-and-services/snmp/) |
| Default product login (Tomcat, Jenkins, admin panels) | Try product defaults before any exploit; validate the session actually has privileges | [Password Attacks](/notes/utilities-scripts-and-payloads/password-attacks/) |
| Exact version matches a public CVE | Read the PoC, check preconditions, adapt paths/params, verify out-of-band | [Shells and Payloads](/notes/utilities-scripts-and-payloads/shells-and-payloads/) |
| Web form / upload / include / template | Work the bug class; try the least destructive primitive first (read → write → execute) | [Web Attacks](/notes/web-applications/web-attacks/) |
| Credentials in a config, share, mail or source | Spray across services, users and username formats; try `su`, SSH, WinRM, DB | [Password Attacks](/notes/utilities-scripts-and-payloads/password-attacks/) |
| 403 on a directory | Treat it as existing, not missing; try alternate paths, methods, headers | [Fuzzing](/notes/web-applications/fuzzing/) |
| Service on localhost only | Tunnel to it; it is usually unauthenticated or weakly configured | [Pivoting](/notes/utilities-scripts-and-payloads/pivoting-tunneling-port-forwarding/) |
| MSSQL reachable | Try provided creds, `-windows-auth`, `fn_my_permissions`, then coercion/`xp_cmdshell` | [MSSQL](/notes/protocols-and-services/mssql/) |
| Domain controller identified | Null/guest enumeration, kerbrute userenum, then BloodHound once you hold any account | [AD](/notes/active-directory/checklist/) |
| Web-app uses ADCS (CA present) | `certipy find -vulnerable` → ESC1, ESC4, ESC8, ESC15, ESC17 | [ADCS](/notes/active-directory/adcs-attacks/) |

## Phase 3 — Foothold

Choose the **cheapest path that produces execution**, not the most impressive one. Cost here means time, noise, risk of crashing the service, and how much cleanup it needs.

| Rank | Path | Typical cost | Use when |
| ---- | ---- | ------------ | -------- |
| 1 | Default or reused credentials | Minutes, low noise | Product login, admin panel, SSH/WinRM with a password already found |
| 2 | Known CVE with a public PoC | 15–60 min, medium noise | Exact version confirmed and preconditions met |
| 3 | Web application bug (upload, LFI/RFI, injection, deserialization, SSRF) | 30 min–2 h, medium | No creds, no matching CVE, but the app is custom or outdated |
| 4 | Password attack (spraying, then targeted brute force) | Hours, high noise, lockout risk | You have a valid user list and a policy that permits it |
| 5 | Client-side / phishing | Rarely authorized | Only when explicitly named in the rules of engagement |

**Proof-of-concept discipline**

- Read the exploit before running it; note hardcoded paths, endpoints, versions and payload assumptions.
- Change one thing at a time; if it fails, compare the request the PoC sends with the request the target expects.
- Prefer the primitive you understand: a file read that yields a key beats an RCE you cannot debug.
- Verify execution out-of-band (listener hit, file timestamp, DNS callback) before concluding "it didn't work".
- Keep the working command and its output. Reproducibility is the deliverable.

**Shell stabilization (Linux)**

```bash
# Upgrade a dumb shell to an interactive TTY
python3 -c 'import pty; pty.spawn("/bin/bash")'
# Ctrl-Z, then on the attack host:
stty raw -echo; fg
# back in the target shell:
export TERM=xterm; export SHELL=/bin/bash
stty rows 40 cols 120
```

Use `rlwrap nc -lvnp <port>` for a friendlier listener, and stage payloads as files when the execution context mangles pipes, quotes, or `$` (Java/Groovy/Node/PHP-FPM contexts especially). On Windows, prefer a stable channel (`evil-winrm`, WinRM, a service) over a raw `nc.exe` shell, and remember Defender/AppLocker may be why a payload silently does nothing. **2026 note:** if PowerShell is blocked by AMSI, use the C# alternatives (`SharpUp`, `Seatbelt`) or stage a reflection-based loader.

**Immediate post-shell enumeration (first 10 minutes)**

- [ ] `id` / `whoami /priv`, `hostname`, `uname -a` / `systeminfo`, current user's groups.
- [ ] Network: `ip a` / `ipconfig /all`, routes, `ss -tnl` / `netstat -ano` (localhost-only services).
- [ ] Home directory, shell history, SSH keys, saved credentials.
- [ ] `sudo -l` (Linux) / `whoami /priv` + service ACLs (Windows).
- [ ] Writable directories, recent files, unusual processes.
- [ ] Note the shell type and stability; open a second channel before doing anything risky.

**Avoid tunnel vision.** A foothold that took two hours does not owe you a privesc path. If the shell is low-value (no local creds, no writable service), pivot back to enumeration on another port or host and keep this shell as a beachhead.

## Phase 4 — Privilege escalation

Local enumeration follows a fixed order: **the cheapest misconfiguration first, the kernel last.** Kernel exploits can panic the host, break your shell, and cost the whole machine.

| Order | Linux | Windows |
| ----- | ----- | ------- |
| 1. Identity | `id`, `sudo -l`, groups, `getcap -r /` | `whoami /priv`, `whoami /groups`, `net localgroup administrators` |
| 2. Misconfigured sudo/rights | GTFOBins on every allowed binary, wildcards, `env_keep`, relative paths | `SeImpersonate`, `SeBackup`, `SeRestore`, `SeTakeOwnership`, `SeDebug` |
| 3. Scheduled/automated execution | cron, systemd timers, `pspy`, inotify triggers, writable scripts | Scheduled tasks, service binary paths, unquoted paths, writable install dirs |
| 4. Services and sockets | Writable unit files, sockets, localhost-only daemons | Service ACLs, `sc config`, weak service permissions, `AlwaysInstallElevated` |
| 5. SUID/SGID and capabilities | Unusual SUID binaries, PATH hijack, `cap_setuid`, `cap_dac_read_search` | — (covered by token rights above) |
| 6. Files and credentials | Configs, backups, `.env`, histories, SSH keys, DB files | `unattend.xml`, `web.config`, `*.kdbx`, PSReadLine history, DPAPI, Credential Manager |
| 7. Kernel/OS exploit | `uname -a` → suggester → compiled PoC | `systeminfo` hotfixes → suggester → compiled PoC |

**Why misconfigurations beat kernel exploits**

- They are version-independent, so a patched box still falls.
- They are usually reversible: restore a file, revert an ACL, remove an added user.
- They rarely crash the service you are standing on.
- They map directly to a finding and a remediation in the report.

**When a kernel exploit is justified**

- Every configuration path is exhausted and documented as failed.
- The kernel/build is confirmed vulnerable and a reliable PoC exists for that exact version and architecture.
- You have a second shell or a persistence mechanism that survives a crash.
- The client/exam rules allow it, and a panic will not take down shared infrastructure.

**2025–2026 kernel nuance: the page-cache LPEs.** Traditional kernel exploits (heap overflows, UAFs) are risky and often panic the box. The modern deterministic page-cache bugs (Copy Fail, Dirty Frag) overwrite the memory of a SUID binary without touching disk — they are stealthy, reliable, and don't crash the kernel, making them a safer "last resort" than older memory-corruption exploits.

**Rollback and cleanup**

- Revert every file you edited; restore the original content and permissions.
- Remove added users, SSH keys, cron entries, scheduled tasks, services and GPO links.
- Delete uploaded binaries, scripts and staging directories; check `/tmp`, `/dev/shm`, `%TEMP%`, `C:\ProgramData`.
- Record what you changed and when, even if the revert succeeded.

**Evidence capture**

```bash
# Keep transcript + context for every privileged action
script -q -f engagement/hosts/<host>/root-shell.log
whoami; id; hostname; date; cat /root/proof.txt
```

Screenshot the terminal with `whoami`/`hostname`/`ipconfig` and the flag file content in one frame. For Windows, include `whoami /priv` or the administrator context in the same shot.

## Phase 5 — Lateral movement & AD

Lateral movement is credential reuse plus a route. Do not treat it as a separate discipline; it is Phase 2 enumeration again, with a new network position.

**Credential reuse rules**

- Every secret is tested against every account, service and username format: `user`, `DOMAIN\user`, `user@domain`.
- A password found in an app config is a candidate OS password; a local SAM hash is not a domain credential (`--local-auth`).
- Re-spray after each new account or group membership; access is often granted by the new group, not the new password.
- Record negative results too — "tried `svc_backup` on WinRM: no" saves a repeat.

**Pivoting choices**

| Need | Option | Note |
| ---- | ------ | ---- |
| One or two specific ports | `ssh -L <lport>:127.0.0.1:<rport> user@host` | Simplest and most stable when SSH is available |
| Many ports / tools that ignore proxies | `ssh -D 1080 user@host` + proxychains | TCP only; UDP and some scanners behave poorly |
| Reverse direction (target cannot reach you) | `ssh -R`, or a reverse Chisel listener | Useful when egress filtering blocks inbound |
| No SSH, mixed OS | Chisel (`server` + `client ... socks`) | Single binary, works from Windows and Linux |
| Full network stack, many hosts | **Ligolo-ng** | TUN-based; needs a tunnel interface on the attack host. **Preferred in 2026** for multi-subnet pivots |
| One-off forward | `socat TCP4-LISTEN:8080,fork TCP4:<target>:80` | No auth, no encryption; keep it short-lived |

**AD attack order**

1. **Unauthenticated enumeration** — null SMB/RPC, guest access, RID brute, kerbrute userenum, LDAP/GC if exposed.
2. **First credentials** — shares, documents, GPP, web bugs, coercion, spraying (respect lockout policy).
3. **Authenticated enumeration** — **BloodHound CE** (or `bloodhound-python`), `certipy find`, shares, sessions, local admin rights.
4. **Read the graph** — the shortest path to Domain Admin is usually an ACL edge, a delegation right, or an ADCS misconfiguration, not a CVE.
5. **Escalate** — ACL abuse (ForceChangePassword, GenericAll/GenericWrite, WriteOwner, WriteDacl), Kerberos roasting, delegation, ADCS ESC paths (ESC1–ESC17, Certighost), group membership.
6. **Domain dominance** — DCSync or an equivalent (`secretsdump`, `nxc --ntds`), then prove it and stop.

**Avoid noisy or destructive actions**

- Do not spray without checking `--pass-pol`; a lockout of a service account can halt business.
- Do not run relay/poisoning on a production segment without explicit permission; it affects other hosts.
- Do not reset passwords or change ACLs you cannot revert; prefer read-only proof where it exists.
- Do not chase every host. Domain dominance is the objective; lateral movement is only a means.

## Phase 6 — Objective, exfiltration and cleanup

The objective is agreed in Phase 0. Prove it with the **minimum** data and the **least** intrusive action that is still convincing.

| Objective | Sufficient proof | Avoid |
| --------- | ---------------- | ----- |
| Domain compromise | DCSync output / `ntds.dit` hash count, DA shell with `whoami` | Dumping every user's mailbox |
| Sensitive file access | Redacted file header + metadata + path | Copying the whole share |
| Database access | Row count, schema, one redacted sample | Full table export |
| Code execution | `id`/`whoami` output with hostname | Persistence you do not need |
| Network access | Route to internal host + one service banner | Scanning the whole internal range |

**Exfiltration rules**

- Prefer hashes/proofs over plaintext bulk data; never take more than the report needs.
- Use an agreed channel and destination; encrypt at rest if the data is sensitive.
- Hash the evidence and record the hash in the report; note the collection time and source.

**Cleanup checklist**

- [ ] All uploaded tools, payloads, webshells and staging directories removed.
- [ ] Created accounts, keys, tokens, services, scheduled tasks and cron jobs removed.
- [ ] Modified configs, templates, ACLs and registry keys restored to original values.
- [ ] Test data and database rows deleted; original files restored from backup where touched.
- [ ] Tunnels, listeners and agents stopped; no background process left on a target.
- [ ] Cleanup verified by re-checking the path, not assumed from the command's success.
- [ ] Cleanup actions logged with timestamps for the report appendix.

## Phase 7 — Reporting

The report is the deliverable. A finding that cannot be reproduced from the report is not a finding.

| Section | Content |
| ------- | ------- |
| Executive summary | Business context, overall risk, what an attacker could achieve, top 3–5 issues, no jargon |
| Scope and rules of engagement | In-scope assets, dates, constraints, testing types, exclusions |
| Methodology | Phases used, standards referenced, tools and versions, what was not tested |
| Findings | One entry per issue: title, severity, CVSS, affected assets, impact, evidence, remediation |
| Appendices | Raw tool output, account/host inventory, cleanup log, evidence index |

**Finding entry structure**

- **Title** — the weakness and its location, e.g. "Unauthenticated RCE in OpenSTAManager 2.9.8 on `support.example.com`".
- **Severity / CVSS** — base score and vector, with a one-line justification of the chosen metrics.
- **Affected assets** — hostnames/IPs and versions.
- **Impact** — what an attacker gains in this environment, not a generic paragraph.
- **Evidence** — request/response, command and output, screenshot with timestamp and host identity.
- **Remediation** — specific, testable, with a reference (vendor advisory, config change).
- **References** — CVE, advisory, documentation.

**Findings-table template**

| ID | Title | Severity | CVSS | Affected asset | Impact | Evidence | Remediation |
| -- | ----- | -------- | ---- | -------------- | ------ | -------- | ----------- |
| F-01 | Default credentials on Tomcat Manager | Critical | 9.8 `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` | `app01` :8080 | Deploy WAR → SYSTEM | `evidence/F-01/` | Disable manager app, rotate creds, restrict 8080 |
| F-02 | SMB signing not required | High | 7.5 `AV:A/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H` | `dc01` | NTLM relay to SMB | `evidence/F-02/` | Enforce signing via GPO |
| F-03 | Password reuse across local admin accounts | High | 8.2 `AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H` | 12 hosts | One hash → all hosts | `evidence/F-03/` | LAPS, unique local admin passwords |

**Evidence standards**

- Every screenshot shows host identity, user context, timestamp and the relevant output.
- Commands are pasted verbatim with placeholders explained; paths and ports match the target.
- Redact secrets consistently, but keep enough to prove the claim.
- Store evidence under a per-finding directory and reference it by filename in the report.

**Common report mistakes**

- Severity inflated by generic impact ("could lead to full compromise") with no environment-specific path.
- Screenshots without context, or with the wrong host visible.
- Exploit output pasted without the command, so nobody can reproduce it.
- Findings that were fixed during the test presented as open, or vice versa.
- No negative results: the client cannot tell what was tested and found clean.
- Remediation that says "patch" without a version, owner, or verification step.

## Decision gates and timeboxes

Track time per **hypothesis**, not per phase. When a gate is reached, do the listed action rather than "one more try".

| If you have spent… | Do this |
| ------------------ | ------- |
| 15 min on an exploit that errors | Read the code once, adapt one parameter, then park it and record why |
| 20 min on a service with no usable banner | Move to the next service; return after the full sweep |
| 30–45 min on one web app with no progress | Switch to another port/vhost; revisit with source review |
| 1 h on a privesc path | Write down the failed path, move to the next enumeration class |
| 90 min on a box with no foothold (exam) | Leave a note, move to the next box, return with fresh eyes |
| 2 h on an AD set with no domain user | Re-check null/guest, shares, web bugs, kerbrute; do not keep spraying |
| 3 failed payload variants | Change payload class (staged, encoded, different language/interpreter) |
| 10 min after finding a credential | Spray it across all services and users before cracking anything |
| 2 h on a single host after foothold | Confirm the objective is still the best use of time; consider another path to the same objective |

**Stop conditions**

- The agreed objective is proven and documented.
- The scope is exhausted, or remaining paths are out of scope.
- Continuing would be destructive, destabilizing, or outside the RoE.
- The timebox for the engagement or exam ends.
- A critical finding requires immediate client notification and a pause.

**When to abandon a path**

- Three distinct adaptations failed and you cannot explain why.
- The required precondition is absent (wrong version, no route, feature disabled).
- Another path to the same objective is cheaper and already half-open.
- The path risks the host (kernel panic, service crash, lockout) more than it promises.
- You are repeating a step you already recorded as failed.

## Note-taking system

One directory per host, one page per host, five fixed sections: **facts, credentials, services, attempted, next**. Fixed sections mean you can resume a box after a context switch without re-reading everything.

| Element | Convention |
| ------- | ---------- |
| Engagement root | `engagement/<client-or-exam>/` |
| Host page | `hosts/<ip>-<hostname>.md` |
| Evidence | `evidence/<finding-id>/` with numbered screenshots |
| Screenshots | `YYYY-MM-DD_HHMM_<host>_<action>.png` |
| Command log | `hosts/<ip>.cmd.log`, appended with timestamps |
| Loot | `loot/` for hashes, keys, files — never inline in the report |

- Log the command **before** the result, not after; the failures are the useful part.
- Record source IP and interface for every command that touches the network.
- Keep a "next" section with the three most promising actions; update it after every finding.
- Never edit a shared lab artifact in place; append and re-check, other testers may overwrite it.
- Link the host page to the technique page that decided it, so the pattern is reusable.

```markdown
# <IP> — <hostname>

**Status:** recon | foothold | privesc | done
**OS / role:**
**In scope:** yes
**Started:** 2026-01-01 09:00

## Facts
- Kernel / build:
- Domain / workgroup:
- Users seen:
- Notes:

## Credentials
| User | Secret | Type (pw/hash/key) | Source | Valid on |
| ---- | ------ | ------------------ | ------ | -------- |
|      |        |                    |        |          |

## Services
| Port | Proto | Service / version | Auth | Notes |
| ---- | ----- | ----------------- | ---- | ----- |
|      |       |                   |      |       |

## Attempted
| Time | Action | Result | Why it failed |
| ---- | ------ | ------ | ------------- |
|      |        |        |               |

## Next
1.
2.
3.

## Evidence
- `evidence/F-01/01-initial.png`
```

## Common failure modes

Drawn from the recurring pitfalls across the lab pages:

- **Tunnel vision on one port, one vhost, or one exploit.** The box usually turns on the port you skipped or the service you called a decoy.
- **Trusting a banner or a version string.** Product banners lie, plugins fake their version, and a vulnerable library may not be reachable.
- **Not reusing a credential.** A DB password is often the OS password; a share password is often the domain password. Test every pair against every service and username format.
- **Skipping UDP and full port ranges.** Footholds hide above 10000 and on UDP; a top-1000 scan is a starting point, not an answer.
- **Ignoring localhost-only services.** `ss -tnl` / `netstat -ano` after every shell; the admin panel is usually bound to 127.0.0.1.
- **Fuzzing before reading.** The path, username or key is often in the page source, a config, a comment, or a `readme`.
- **Running exploit scripts unmodified.** Hardcoded paths, missing auth, wrong scheme, and target-specific parameters are the norm; adapt before concluding "patched".
- **Mistaking AV, AppLocker or an input filter for a broken exploit.** Change payload class and staging location before abandoning the bug.
- **Editing shared lab artifacts in place.** Other testers overwrite them; append, re-check, and keep your own copy.
- **Reaching for a kernel exploit first.** It is the highest-risk, lowest-reliability path; exhaust configuration and credentials first.
- **No fallback channel.** A crashed service or a killed shell ends the box; open a second shell or a persistence route first.
- **Skipping cleanup.** Leftover webshells, users, keys, and tunnels are a finding against you, and they invalidate the "restored" claim.
- **Poor notes.** No timestamps, no commands, no failed paths — the report becomes guesswork and the exam retrace costs more than the original work.

## OSCP-specific notes

OSCP is one application of this methodology under a hard clock. It rewards breadth, cheap wins, and clean notes; it punishes tunnel vision and unnecessary risk. Rules and scoring change — confirm the current details in the official exam guide before relying on any number here.

| Item | Typical shape |
| ---- | ------------- |
| Exam window | **24 hours** (or 48-hour version), proctored, VPN into an isolated range |
| Targets | **3 standalone machines (20 pts each)** plus a **3-machine Active Directory set (40 pts)** |
| Scoring | 100 points total; AD set is the largest block; **70 to pass**, plus up to 10 bonus points from the course exercises |
| Report | Separate 24-hour window after the exam ends |
| Tooling | Restricted: check the current guide. Metasploit/Meterpreter usage has historically been limited to one machine |

**Time management**

- Scan everything in the first 30 minutes, in parallel, and write the host skeleton while scans run.
- Take the **low-privilege flag first** on each standalone box; do not spend the whole budget on root.
- Attack the AD set as one contiguous block, early enough that a failure leaves time to return.
- Keep 60–90 minutes at the end for proof screenshots, note cleanup and report preparation.
- If a box resists past its timebox, leave a note and rotate; a fresh look later is cheaper than grinding.

**AD set strategy**

- Start with the credentials or foothold the brief provides; assumed breach is the normal opening.
- Enumerate unauthenticated paths anyway: null SMB/RPC, guest, shares, web bugs, kerbrute.
- Run BloodHound early and read the edges; the intended path is usually ACL, delegation or ADCS, not a CVE.
- Re-enumerate after every new user, group membership or ACL change.
- Sync the clock before Kerberos steps; expect the VPN to drop and reconnect.
- Plan the final chain (grant → dump → proof) as one sequence, because lab reverts can undo intermediate state.

**Proof files**

- `local.txt` in the user's home/Desktop and `proof.txt` in `root`/Administrator's Desktop; capture both when the box has them.
- One screenshot must show the file content, `whoami` (or `id`), `hostname`, and the IP configuration together.
- Save the raw command output next to the screenshot; the report needs reproducible steps, not just images.
- For the AD set, proof includes domain admin context (DCSync output or a DA shell), not only the last machine's flag.

**What not to do**

- Do not attack the exam infrastructure, other candidates, or anything outside the provided range.
- Do not brute force or spray without checking the policy; lockouts cost the box.
- Do not reboot, shut down, or run destructive exploits on shared exam hosts.
- Do not leave the report to the last hours of the 24-hour window; write findings as you go.
- Do not present an unverified exploit attempt as a confirmed finding.

The lab pages are the worked examples of these phases: [Linux machines](/notes/oscp-labs/linux/) for web-to-shell and local privesc patterns, [Windows](/notes/oscp-labs/windows/) for tokens, services and credential artifacts, [AD](/notes/oscp-labs/ad/) for assumed-breach chains and domain dominance.
