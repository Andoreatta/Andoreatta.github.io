+++
title = 'Linux Privilege Escalation Checklist'
date = 2026-10-30
type = 'notes'
weight = 70
toc = true
task = true
tags = ['linux', 'privilege-escalation', 'checklist']
+++

> Working document — tick as you go. Commands are abbreviated; full detail is in the matching section of the notes.
> **Stop at the first successful path.** Work top-down: configuration and credential wins are faster and safer than kernel exploits. Kernel exploits last.
> **CVE numbers are hints, not gospel** — verify the version against the current NVD before committing to a CVE-specific path. The *behavioural* checks below are valid regardless.

**Target context — fill before starting:**

| Field | Value |
|---|---|
| Hostname | |
| OS / kernel (`uname -r`) | |
| Architecture (`uname -m`) | |
| Current user / groups (`id`) | |
| Sudo version (`sudo -V`) | |
| util-linux version (`mount --version`) | |
| `ptrace_scope` | |
| Inside a container? | |
| Kubernetes / node? | |
| AD-joined / domain host? | |
| Package-manager access (`wheel`/`sudo` + npm/pip)? | |
| Notes | |

---

## Phase 0 — Orient (60 seconds)

- [ ] `id; groups; whoami; hostname; uname -a; cat /etc/os-release`
- [ ] `sudo -V | head -1` — record version against the sudo CVE table
- [ ] `mount --version` — record util-linux version (mount TOCTOU family)
- [ ] `sudo -l` — **read every line**: runas user, `NOPASSWD`, `SETENV`, `env_keep`
- [ ] `cat /proc/sys/kernel/yama/ptrace_scope` — `0`/`1` leaves FD-theft and ptrace paths open; `2` narrows them
- [ ] `ls -la /.dockerenv 2>/dev/null; cat /proc/1/cgroup | grep -E 'docker|lxc|kubepods'` — container?
- [ ] `ls /var/run/secrets/kubernetes.io/serviceaccount/ 2>/dev/null` — Kubernetes pod?
- [ ] `realm list 2>/dev/null` — AD-joined?
- [ ] `ss -tulpn` — note localhost-only services for Phase 7
- [ ] Record findings above, then proceed

---

## Phase 1 — Quick Wins (30 seconds each, high payoff)

- [ ] `sudo -l` shows `(ALL : ALL) ALL` → `sudo su -` **DONE**
- [ ] `sudo -l` shows any binary → check [GTFOBins](https://gtfobins.github.io/) → escalate via sudo
- [ ] `ls -la /etc/passwd /etc/shadow` — writable? → [Writable /etc/passwd](/notes/linux-privilege-escalation/enumerating-attack-vectors/#writable-etcpasswd--etcshadow)
- [ ] `ls -la /etc/ld.so.preload 2>/dev/null` — writable or creatable? → [ld.so.preload](/notes/linux-privilege-escalation/enumerating-attack-vectors/#ldsopreload--universal-linker-hijack)
- [ ] `getcap -r / 2>/dev/null` — any `cap_setuid`, `cap_dac_*`, `cap_sys_admin`, `cap_setfcap`? → [Capabilities](/notes/linux-privilege-escalation/enumerating-attack-vectors/#linux-capabilities)
- [ ] `find /etc/logrotate.d -writable 2>/dev/null` — writable config? → [Logrotate](/notes/linux-privilege-escalation/enumerating-attack-vectors/#logrotate)
- [ ] `find /etc/systemd/system -type f -writable 2>/dev/null` — writable unit? → [Systemd](/notes/linux-privilege-escalation/enumerating-attack-vectors/#systemd-unit-abuse)
- [ ] `grep -E '^\S+\s+\S+\s+(user|users)\s' /etc/fstab 2>/dev/null` — user-mountable entries (mount TOCTOU precondition)
- [ ] `ls -l /usr/bin/pkexec 2>/dev/null; pkexec --version 2>/dev/null` — PwnKit still alive on many hosts

---

## Phase 2 — Credentials (often the fastest root)

**Files and histories**

- [ ] `grep -riE 'pass|pwd|secret|token' ~/.bash_history /home/*/.bash_history 2>/dev/null`
- [ ] `cat ~/.ssh/id_rsa /home/*/.ssh/id_rsa 2>/dev/null` — private keys?
- [ ] `grep -riE 'password|api_key|secret' /var/www /opt /srv /etc 2>/dev/null | grep -v Binary`
- [ ] `find / -name '.env' -type f -exec cat {} \; 2>/dev/null`
- [ ] `find / -name '*.sql' -o -name '*.bak' -o -name '*.old' -o -name '*.db' 2>/dev/null | head -20`

**Live process state**

- [ ] `for p in /proc/[0-9]*; do tr '\0' '\n' < $p/environ 2>/dev/null | grep -iE 'pass|token|secret' && echo "  ^PID $p"; done`
- [ ] `for p in /proc/[0-9]*; do tr '\0' ' ' < $p/cmdline 2>/dev/null | grep -iE 'pass|token' && echo "  ^PID $p"; done`

**Logs — argv leaks that `ps` never shows**

- [ ] `grep -iE 'pass|token|secret' /var/log/auth.log /var/log/syslog 2>/dev/null`
- [ ] `grep 'type=EXECVE' /var/log/audit/audit.log 2>/dev/null | grep -iE 'pass|token|secret|key'` — requires `audit` group
- [ ] `journalctl --no-pager | grep -iE 'pass|token|secret'` — requires `systemd-journal` group
- [ ] `grep -i 'sudo' /var/log/auth.log 2>/dev/null | tail -20` — recent sudo use → FD-theft / token-reuse surface (Phase 6)

**Reuse**

- [ ] Any password found → `su - <user>` / `sudo -l` / `ssh <user>@localhost` / try on other users

---

## Phase 3 — Privileged Execution Paths

**SUID / SGID / capabilities**

- [ ] `find / -perm -4000 -type f 2>/dev/null` — list SUID, filter against GTFOBins
- [ ] `find / -perm -2000 -type f 2>/dev/null` — SGID
- [ ] `find / -perm -6000 -type f 2>/dev/null` — SUID + SGID
- [ ] `ldd /path/to/suid` on every non-GTFOBins SUID → library hijack? → [SUID Shared-Library](/notes/linux-privilege-escalation/enumerating-attack-vectors/#suid-shared-library-and-linker-abuse)
- [ ] `readelf -d /path/to/suid | grep -E 'RPATH|RUNPATH'` — writable path or `$ORIGIN`?
- [ ] `find / -perm -4000 -type f -exec sh -c 'ldd "$1" 2>&1 | grep -q "not a dynamic" && echo "$1"' _ {} \; 2>/dev/null` — static SUID (glibc dlopen family)
- [ ] `capsh --print` — current capability set, especially inside a container

**Sudo environment vectors**

- [ ] `SETENV` / `env_keep` on `LD_PRELOAD`, `LD_LIBRARY_PATH`, `PYTHONPATH`, `BASH_ENV`, `PATH`
- [ ] Sudo version in the `1.9.14`–`1.9.17` range **and** any sudo rule present → check for the `-R` / nsswitch LPE (CVE-2025-32463)

**Authentication stack**

- [ ] `grep -r 'pam_env\|pam_exec' /etc/pam.d/ 2>/dev/null`
- [ ] `ls -la ~/.pam_environment 2>/dev/null` — writable + trusted by PAM = root execution path
- [ ] `grep -n 'pam_env\|pam_systemd' /etc/pam.d/sshd 2>/dev/null` — check load order (pam_env before pam_systemd is the risky order)
- [ ] `env | grep CREDENTIALS_DIRECTORY`; `ls -la /run/credentials/ 2>/dev/null` — systemd credential exposure

---

## Phase 4 — Scheduled & Background Execution

- [ ] `cat /etc/crontab; ls -la /etc/cron.* /var/spool/cron/crontabs/ 2>/dev/null` — writable scripts?
- [ ] `cat /etc/anacrontab 2>/dev/null` — anacron runs the same `cron.daily` scripts; a writable script there is a root path
- [ ] `systemctl list-timers --all` — systemd timers
- [ ] `atq 2>/dev/null` — queued `at` jobs
- [ ] `./pspy64 -pf -i 1000` — watch process spawns for 1–2 minutes
- [ ] Note any root job → check `ExecStart` / script path / cron `PATH` → writable?
- [ ] `systemctl cat <service>; systemctl show <service>` — inspect root services for writable binaries, `EnvironmentFile=`, drop-ins
- [ ] `find /etc/systemd/system -type d -name '*.d' -writable 2>/dev/null` — writable drop-in directories

---

## Phase 5 — Filesystem Primitives

- [ ] `find / -path /proc -prune -o -type d -perm -o+w 2>/dev/null` — world-writable directories
- [ ] `find / -path /proc -prune -o -type f -perm -o+w 2>/dev/null` — world-writable files
- [ ] `find / -writable -type f 2>/dev/null | grep -E '\.sh$|\.service$|\.conf$|\.cron$'` — writable scripts/configs executed by root
- [ ] `find / -mmin -10 -type f 2>/dev/null` — recently modified (active cron tell)
- [ ] `cat /etc/exports 2>/dev/null` — `no_root_squash`? → NFS root primitive
- [ ] Writable `/etc/passwd`, `/etc/shadow`, `/etc/sudoers.d/` — see Phase 1

---

## Phase 6 — Session, Process, and File-Descriptor Attacks

**Sudo token reuse**

- [ ] `ptrace_scope` is `0` (from Phase 0) **and** `last` / `auth.log` shows recent sudo use → `sudo_inject`

**Terminal multiplexer hijacking**

- [ ] `find /tmp /run -name 'screen.*' -o -name 'tmux-*' 2>/dev/null` — accessible sockets?
- [ ] `ls -la /tmp/tmux-* 2>/dev/null` — attach to root's tmux/screen

**Privileged groups**

- [ ] `groups | grep -E 'screen|tmux|docker|lxd|disk|adm|shadow|systemd-journal|audit'`

**File-descriptor theft (privileged-process exit race)**

- [ ] `ls /usr/bin/{chage,ssh-keysign,pkexec,accounts-daemon,passwd} 2>/dev/null` — candidate SUID targets held open at exit
- [ ] `ls -la /proc/*/fd/ 2>/dev/null | grep -E 'root|shadow|sudoers|\.ssh'` — writable or readable FDs to root files
- [ ] `ptrace_scope` value from Phase 0 — `2` mitigates the clone-the-fd path; `0`/`1` keeps it open

**D-Bus and open FDs**

- [ ] `busctl --system list 2>/dev/null` — privileged system-bus services
- [ ] `ls -la /proc/*/fd/ 2>/dev/null | grep -E 'root|shadow|sudoers'` — writable FD to a root file

---

## Phase 7 — Network, Pivot, and Runtime Sockets

- [ ] `ss -tulpn` — localhost-only services → `ssh -R` / `socat` tunnel
- [ ] `cat /etc/resolv.conf` — internal DNS → AD pivot
- [ ] `ip route` — reachable networks
- [ ] `arp -a` — hosts the target talks to
- [ ] `iptables -L -n -v 2>/dev/null; nft list ruleset 2>/dev/null` — firewall ruleset
- [ ] Cross-reference listening ports with process owners — any root-owned service?
- [ ] **Container runtime sockets:** `ls -la /run/containerd/containerd.sock /run/crio/crio.sock /run/podman/podman.sock /var/run/docker.sock 2>/dev/null`
- [ ] `ss -xl | grep -E 'docker|containerd|crio|podman'`; `env | grep -E 'DOCKER_HOST|CONTAINERD_ADDRESS'` — TCP-exposed runtime APIs
- [ ] Network-management platform on host (UniFi / Zabbix / LibreNMS) → check its DB for device credentials

---

## Phase 8 — Container Escape (only if inside a container)

- [ ] `capsh --print` — `CAP_SYS_ADMIN`, `CAP_SYS_PTRACE`, `CAP_SYS_MODULE`, `CAP_DAC_READ_SEARCH`?
- [ ] `find / -maxdepth 4 \( -name docker.sock -o -name containerd.sock -o -name crio.sock \) 2>/dev/null` — reachable socket?
- [ ] `mount | grep -E ' / | /host '` — host bind mount?
- [ ] `cat /proc/self/mountinfo | grep -E ' / | /host '` — host root mounted?
- [ ] `ls -la /proc/sys/kernel/core_pattern` — writable?
- [ ] `runc --version` — vulnerable runc build? (masked-path, `/dev/console`, procfs-write redirect bugs)
- [ ] If host root mounted → `chroot /host` or drop a SUID binary through the mount

---

## Phase 9 — Kubernetes / Node (only if the shell is in a pod or on a node)

- [ ] `ls /var/run/secrets/kubernetes.io/serviceaccount/` — current ServiceAccount token; note its RBAC
- [ ] `cat /var/run/secrets/kubernetes.io/serviceaccount/token | cut -d. -f2 | base64 -d 2>/dev/null` — decode token claims
- [ ] `ss -tlnp | grep 10250` — kubelet API reachable?
- [ ] `ls -la /var/lib/kubelet/kubeconfig 2>/dev/null` — kubelet credentials (node root)
- [ ] `capsh --print | grep -E 'CAP_SYS_ADMIN|CAP_NET_ADMIN'` — pod capability surface for node-level bugs
- [ ] `cat /proc/self/mountinfo | grep -E 'kubelet|pods|containers'` — host paths leaked into the pod
- [ ] Page-cache corruption (Phase 11) inside a pod can reach **node root** because the page cache is kernel-wide

---

## Phase 10 — Supply Chain and Package Managers (if in `wheel` / `sudo`)

- [ ] `groups | grep -qE 'wheel|sudo' && echo "wheel/sudo: package postinstall can reach root paths"`
- [ ] `npm config get ignore-scripts 2>/dev/null` — `false` means a malicious package's `postinstall` runs in your context
- [ ] `pip config list 2>/dev/null | grep -iE 'require-virtualenv|user'` — pip execution context
- [ ] `rpm-ostree --version 2>/dev/null` — local installs on ostree systems do not always prompt for elevation
- [ ] `cat /etc/yum.repos.d/*.repo /etc/apt/sources.list.d/* 2>/dev/null | grep -E '^\[|^deb '` — writable or attacker-controlled repos

---

## Phase 11 — Kernel Exploit (last resort)

- [ ] `uname -r` → `searchsploit linux kernel <ver>` / `linux-exploit-suggester` / `lse.sh -l 2`
- [ ] `uname -m` — architecture; compile for it
- [ ] **Page-cache surface:** `cat /proc/crypto | grep -i aead`; `lsmod | grep -E 'xfrm|rxrpc'`
- [ ] **SUID page-cache targets:** any readable root-owned SUID binary is a candidate for page-cache overwrite — on-disk hash unchanged
- [ ] `ls -l /usr/bin/pkexec 2>/dev/null` — PwnKit still present on many hosts
- [ ] Keep a fallback shell open — kernel panics cost the machine
- [ ] Prefer deterministic page-cache / logic bugs over traditional heap races: higher success rate, no crash on failure, no on-disk artifact

---

## Post-Root — What "Root" Looks Like in 2026

Do not assume root is "a new SUID binary on disk." Modern post-exploitation and tooling is increasingly memory-resident.

- [ ] `ls -la /proc/*/exe 2>/dev/null | grep memfd` — memory-resident payloads
- [ ] `find /etc -name 'ld.so.preload' -newer /etc/hostname 2>/dev/null` — linker config changed post-boot?
- [ ] `ldconfig -p 2>/dev/null | head -30` — any cache entries pointing at user-writable directories?
- [ ] `ls -la /etc/ld.so.conf.d/` — third linker path beyond `LD_PRELOAD` and `ld.so.preload`
- [ ] Record the exact escalation path, the timestamp, and the command that triggered it

---

## Stop Conditions

- [ ] Root obtained → **stop enumerating, record the path, screenshot / copy flags**
- [ ] Two full passes with no lead → re-read `sudo -l`, `/etc/systemd/system`, `/etc/cron.*`, **process environments**, and **`/proc/*/fd`** — these are the most-missed
- [ ] If time-boxed and stuck → pivot to network enumeration (Phase 7); a lateral host may be easier
- [ ] If kernel exploit is the only path left → confirm architecture, keep a fallback shell, and choose a deterministic bug over a race
