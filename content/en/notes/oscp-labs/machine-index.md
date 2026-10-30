+++
title = 'OSCP Machine Index'
date = 2026-10-30
type = 'notes'
weight = 40
toc = true
tags = ['oscp', 'methodology', 'htb', 'machine-index']
+++

> One row per box for the whole OSCP-like list — **76 machines**: 39 Linux, 18 Windows, 16 AD and 3 non-AD. Use it to pick a box by technique, to revise a path in 30 seconds, and to tick off what you have actually rooted. Detail lives in [Linux](/notes/oscp-labs/linux/), [Windows](/notes/oscp-labs/windows/) and [Active Directory](/notes/oscp-labs/ad/); this page only routes you there.
>
> **Verification status (2026-10-28):** every CVE and path below was checked against NVD/MITRE, the vendor advisory, and at least one independent write-up. Two CVE misattributions from earlier drafts were corrected — [Keeper](#corrections) and [Enigma](#corrections). One "false lead" was confirmed and kept — [Dog](#corrections). Where a source still disagrees, the row is marked **(unverified)**.

## How to use this page

- **Revision:** read the row, then explain the path out loud without looking at the page. If you stall on the privesc cell, open the machine page.
- **Progress:** `[ ]` → `[x]` only when you rooted it unaided (no writeup, no hint). Reset a tick if you needed help.
- **Choosing by technique:** scan the *Key tool or CVE* and *Privesc / path* columns, not the names. The [Study tracks](#study-tracks) below give ready-made orders.
- **Gaps:** the [Coverage check](#coverage-check) shows which phase you have been avoiding — usually the one you keep skipping.

## Linux

| Machine | Foothold | Privesc / path | Key tool or CVE | Done |
| --- | --- | --- | --- | --- |
| [Enigma](/notes/oscp-labs/linux/) | NFS onboarding PDF | OliveTin mysqldump break-out | showmount · OpenSTAManager · **CVE-2026-29782** | [ ] |
| [Nibbles](/notes/oscp-labs/linux/) | NibbleBlog plugin upload | sudo writable monitor.sh | **CVE-2015-6967** · NibbleBlog | [ ] |
| [Solidstate](/notes/oscp-labs/linux/) | Apache James admin 4555 | root cron /opt/tmp.py | **CVE-2015-7611** · Apache James 2.3.2 · pspy32 | [ ] |
| [Poison](/notes/oscp-labs/linux/) | LFI log poisoning | VNC secret.zip → root | vncpasswd · proxychains | [ ] |
| [Editor](/notes/oscp-labs/linux/) | XWiki Groovy RCE | ndsudo PATH hijack | **CVE-2025-24893** · **CVE-2024-32019** | [ ] |
| [Sunday](/notes/oscp-labs/linux/) | finger enum → SSH 22022 | sudo wget | hashcat 7400 · finger-user-enum | [ ] |
| [Keeper](/notes/oscp-labs/linux/) | Request Tracker default creds | KeePass dump → PuTTY key | **CVE-2023-32784** · kpcli · RT root:password | [ ] |
| [Pilgrimage](/notes/oscp-labs/linux/) | .git → ImageMagick read | binwalk PFS traversal | **CVE-2022-44268** · **CVE-2022-4510** | [ ] |
| [Cozyhosting](/notes/oscp-labs/linux/) | Spring actuator session hijack | sudo ssh ProxyCommand | actuator/sessions · GTFOBins ssh | [ ] |
| [Codify](/notes/oscp-labs/linux/) | vm2 sandbox escape | glob bypass → pspy | vm2 3.9.16 · pspy | [ ] |
| [Tartarsauce](/notes/oscp-labs/linux/) | WordPress gwolle-gb RFI | sudo tar → backuperer race | wpscan · GTFOBins tar | [ ] |
| [Jarvis](/notes/oscp-labs/linux/) | UNION SQLi → phpMyAdmin | SUID systemctl unit | **CVE-2018-12613** · sqlmap | [ ] |
| [Tabby](/notes/oscp-labs/linux/) | Tomcat manager WAR deploy | lxd group mount | manager-script · lxd | [ ] |
| [Connected](/notes/oscp-labs/linux/) | FreePBX pre-auth SQLi | incron writable init.conf | **CVE-2025-57819** · incron | [ ] |
| [Mentor](/notes/oscp-labs/linux/) | SNMP community → admin JWT | snmpd.conf cleartext → sudo | snmpwalk · COPY PROGRAM | [ ] |
| [Devvortex](/notes/oscp-labs/linux/) | Joomla config leak | apport-cli pager | **CVE-2023-23752** · **CVE-2023-1326** | [ ] |
| [Irked](/notes/oscp-labs/linux/) | UnrealIRCd backdoor shell | SUID viewuser /tmp/listusers | UnrealIRCd 3.2.8.1 · steghide | [ ] |
| [Popcorn](/notes/oscp-labs/linux/) | upload Content-Type bypass | PAM MOTD passwd write | **CVE-2010-0832** · DirtyCow | [ ] |
| [Bashed](/notes/oscp-labs/linux/) | /dev/phpbash.php webshell | writable /scripts cron | phpbash · pspy | [ ] |
| [Broker](/notes/oscp-labs/linux/) | ActiveMQ OpenWire exploit | sudo nginx root config | **CVE-2023-46604** · nginx | [ ] |
| [Silentium](/notes/oscp-labs/linux/) | Flowise reset-token ATO | Gogs symlink → root keys | **CVE-2025-58434** (ATO) · **CVE-2025-59528** (RCE) · **CVE-2025-8110** | [ ] |
| [Networked](/notes/oscp-labs/linux/) | backup.tar source leak | cron filename injection | AddHandler · changename.sh | [ ] |
| [UpDown](/notes/oscp-labs/linux/) | dev header → .git source | sudo easy_install setup.py | phar:// · easy_install | [ ] |
| [Swagshop](/notes/oscp-labs/linux/) | Magento admin object injection | sudo vi wildcard | shoplift · Magento 1.9 | [ ] |
| [Nineveh](/notes/oscp-labs/linux/) | type-juggling login → LFI | port knock → chkrootkit | phpLiteAdmin · **CVE-2014-0476** | [ ] |
| [Pandora](/notes/oscp-labs/linux/) | SNMP args → internal SQLi | SUID backup PATH hijack | snmpbulkwalk · ltrace | [ ] |
| [OpenAdmin](/notes/oscp-labs/linux/) | OpenNetAdmin xajax injection | internal vhost → sudo nano | OpenNetAdmin 18.1.1 · sudo nano | [ ] |
| [Precious](/notes/oscp-labs/linux/) | PDFKit URL injection | sudo ruby YAML.load | **CVE-2022-25765** · exiftool | [ ] |
| [Busqueda](/notes/oscp-labs/linux/) | Searchor eval() injection | full-checkup CWD hijack | Searchor 2.4.0 · docker-inspect | [ ] |
| [Monitored](/notes/oscp-labs/linux/) | SNMP args → Nagios token | getprofile symlink zip | **CVE-2023-40931** · getprofile.sh | [ ] |
| [BoardLight](/notes/oscp-labs/linux/) | Dolibarr default creds | Enlightenment SUID escape | **CVE-2023-30253** · **CVE-2022-37706** | [ ] |
| [Magic](/notes/oscp-labs/linux/) | SQLi login → upload bypass | SUID sysinfo PATH | exif_imagetype · ltrace | [ ] |
| [Help](/notes/oscp-labs/linux/) | GraphQL credential leak | kernel 4.4.0-116 LPE | **CVE-2017-16995** · GraphQL | [ ] |
| [Editorial](/notes/oscp-labs/linux/) | SSRF to internal API | GitPython ext:: clone | SSRF · GitPython ext:: | [ ] |
| [Builder](/notes/oscp-labs/linux/) | Jenkins CLI file read | admin → root SSH key | **CVE-2024-23897** · jenkins-cli | [ ] |
| [Linkvortex](/notes/oscp-labs/linux/) | dev .git → Ghost CVE | sudo clean_symlink env | **CVE-2023-40028** · git-dumper | [ ] |
| [UnderPass](/notes/oscp-labs/linux/) | SNMP → daloRADIUS panel | sudo mosh-server | snmpwalk · mosh-client | [ ] |
| [Dog](/notes/oscp-labs/linux/) | Backdrop .git → module upload | sudo bee eval | git-dumper · bee | [ ] |
| [Cctv](/notes/oscp-labs/linux/) | ZoneMinder SQLi | tcpdump caps → motionEye | **CVE-2024-51482** · **CVE-2025-60787** | [ ] |

## Windows

| Machine | Foothold | Privesc / path | Key tool or CVE | Done |
| --- | --- | --- | --- | --- |
| [Markup](/notes/oscp-labs/windows/) | default creds → XXE | writable job.bat as SYSTEM | XXE · icacls | [ ] |
| [Jerry](/notes/oscp-labs/windows/) | Tomcat default creds | WAR deploys as SYSTEM | Tomcat 7.0.88 · msfvenom | [ ] |
| [Netmon](/notes/oscp-labs/windows/) | anonymous FTP = C: drive | PRTG notification injection | PRTG · psexec | [ ] |
| [Servmon](/notes/oscp-labs/windows/) | NVMS-1000 path traversal | NSClient++ 0.5.2.35 | NSClient++ · 8443 tunnel | [ ] |
| [Chatterbox](/notes/oscp-labs/windows/) | AChat UDP overflow | Alfred ACL → root.txt | AutoRunScript · icacls | [ ] |
| [Jeeves](/notes/oscp-labs/windows/) | Jenkins no-auth console | KeePass PTH → ADS | KeePass · psexec -hashes | [ ] |
| [Sniper](/notes/oscp-labs/windows/) | LFI → session poisoning | weaponized .chm | Out-CHM · AppLocker | [ ] |
| [Querier](/notes/oscp-labs/windows/) | xlsm macros → MSSQL creds | xp_dirtree → GPP cpassword | olevba · GPP | [ ] |
| [Giddy](/notes/oscp-labs/windows/) | stacked SQLi xp_dirtree | UniFi taskkill.exe hijack | xp_dirtree · Ebowla | [ ] |
| [Bounty](/notes/oscp-labs/windows/) | IIS upload null byte | SeImpersonate → LonelyPotato | web.config · LonelyPotato | [ ] |
| [Arctic](/notes/oscp-labs/windows/) | ColdFusion FCKeditor upload | MS10-059 kernel | MS10-059 · exploit-suggester | [ ] |
| [Remote](/notes/oscp-labs/windows/) | NFS Umbraco.sdf | XSLT RCE → TeamViewer AES | Umbraco · TeamViewer 7 | [ ] |
| [Buff](/notes/oscp-labs/windows/) | Gym Management upload | CloudMe overflow via Chisel | Chisel · CloudMe 1.11.2 | [ ] |
| [Love](/notes/oscp-labs/windows/) | TLS cert vhost → SSRF | AlwaysInstallElevated → SYSTEM | AlwaysInstallElevated · msiexec | [ ] |
| [Secnotes](/notes/oscp-labs/windows/) | XSRF password reset | SMB share → WSL history | CSRF · WSL rootfs | [ ] |
| [Access](/notes/oscp-labs/windows/) | FTP mdb + PST | cmdkey → runas /savecred | runas /savecred · DPAPI | [ ] |
| [Mailing](/notes/oscp-labs/windows/) | traversal → hMailServer.ini | CVE-2024-21413 → CVE-2023-2255 | **CVE-2024-21413** · **CVE-2023-2255** | [ ] |
| [Heist](/notes/oscp-labs/windows/) | guest portal Cisco config | Firefox dump → admin reuse | Cisco type 7 · procdump | [ ] |

## Active Directory

| Machine | Foothold | Privesc / path | Key tool or CVE | Done |
| --- | --- | --- | --- | --- |
| [Active](/notes/oscp-labs/ad/) | anonymous Replication share | GPP → Kerberoast Administrator | gpp-decrypt · GetUserSPNs | [ ] |
| [Forest](/notes/oscp-labs/ad/) | null RPC → AS-REP roast | WriteDacl domain → DCSync | GetNPUsers · secretsdump | [ ] |
| [Sauna](/notes/oscp-labs/ad/) | kerbrute → AS-REP fsmith | AutoLogon → GetChanges | kerbrute · secretsdump | [ ] |
| [Flight](/notes/oscp-labs/ad/) | UNC include → NetNTLMv2 | machine TGT → DCSync | ntlm_theft · Rubeus tgtdeleg | [ ] |
| [Return](/notes/oscp-labs/ad/) | printer panel LDAP bind | Server Operators binPath swap | Responder · Server Operators | [ ] |
| [Blackfield](/notes/oscp-labs/ad/) | profiles share → AS-REP | ForceChangePassword → SeBackup | rpcclient setuserinfo2 · diskshadow | [ ] |
| [Cicada](/notes/oscp-labs/ad/) | guest SMB → HR note | spray → reg save SAM | netexec --rid-brute · reg save | [ ] |
| [TheFrizz](/notes/oscp-labs/ad/) | Gibbon LMS file write | GPO abuse → SYSTEM | **CVE-2023-45878** · SharpGPOAbuse · hashcat 1420 | [ ] |
| [Administrator](/notes/oscp-labs/ad/) | assumed breach → BloodHound | GenericAll chain → DCSync | BloodHound · targetedKerberoast | [ ] |
| [Monteverde](/notes/oscp-labs/ad/) | querydispinfo → user spray | ADSync LocalDB → DA | ADSync · mcrypt.dll | [ ] |
| [Escape](/notes/oscp-labs/ad/) | SMB PDF creds → MSSQL | coerce → ESC1 | Certipy ESC1 · xp_dirtree | [ ] |
| [EscapeTwo](/notes/oscp-labs/ad/) | assumed breach → xlsx | WriteOwner → ESC4 → ESC1 | Certipy ESC4 · bloodyAD | [ ] |
| [Certified](/notes/oscp-labs/ad/) | assumed breach → WriteOwner | shadow creds → ESC9 | Certipy ESC9 · owneredit | [ ] |
| [Puppy](/notes/oscp-labs/ad/) | assumed breach → HR group | KeePassXC → DPAPI | KeePassXC · dpapi.py | [ ] |
| [Timelapse](/notes/oscp-labs/ad/) | null SMB zip → pfx | cert WinRM → LAPS | pfx2john · LAPS | [ ] |
| [Signed](/notes/oscp-labs/ad/) | assumed breach SQL login | silver ticket → OPENROWSET | ticketer.py · OPENROWSET | [ ] |

## Also on the list (not AD)

Linux boxes that sit in the AD column of the source sheet but have no domain, no Kerberos and no BloodHound. They belong with the web → Linux privesc cluster.

| Machine | Foothold | Privesc / path | Key tool or CVE | Done |
| --- | --- | --- | --- | --- |
| [Gobox](/notes/oscp-labs/ad/) | Go template SSTI | backdoored nginx module | SSTI · LocalStack | [ ] |
| [Bucket](/notes/oscp-labs/ad/) | LocalStack S3 upload | pd4ml attachment read | LocalStack · pd4ml | [ ] |
| [Facts](/notes/oscp-labs/ad/) | Camaleon CMS admin | sudo facter --custom-dir | **CVE-2024-46987** · facter | [ ] |

## Corrections

Three verification changes were made to earlier drafts. All three are reflected in the rows above.

### Enigma — CVE-2026-29782, not CVE-2025-69212

**Earlier attribution:** "one writeup reports a file-upload RCE credited as **CVE-2025-69212**, another describes an authenticated SQLi in the Aggiornamenti module plus PHP deserialization via PHPGGC **(unverified)**."

**Verified attribution:** the RCE chain on Enigma is **CVE-2026-29782** — an unauthenticated `oauth2.php` endpoint that loads a record from `zz_oauth2` using an attacker-controlled `state` parameter and calls `unserialize()` on `access_token` without class restriction. The public PoC explicitly describes it as *"auth-SQLi → PHP object injection → RCE"* for OpenSTAManager ≤ 2.10.1. **CVE-2025-69212** is a separate **OS Command Injection** in the P7M (signed XML) decoding function, affecting 2.9.8 and earlier. The `(unverified)` caveat is removed.

### Keeper — CVE-2023-32784, not CVE-2022-32784

The KeePass master-password recovery is **CVE-2023-32784** (KeePass 2.x before 2.54, cleartext master password recoverable from a memory dump). CVE-2022-32784 is a **Request Tracker REST 2.0 API information disclosure** — a different product and a different primitive. The foothold (Request Tracker default credentials `root:password`) is correct and well documented, but the CVE in the *Key tool or CVE* column belonged to the KeePass step and was off by one year.

### Dog — CVE-2024-41709 is a false lead, confirmed

CVE-2024-41709 is a **Backdrop CMS field-label sanitization** issue affecting versions before 1.27.3 and 1.28.x before 1.28.2, mitigated by the *"administer fields"* permission. The Dog path uses an **authenticated RCE via malicious archive upload** in the admin module installer, **not** CVE-2024-41709. The original note calling it a false lead is correct and is now recorded as verified rather than speculative.

> **Verification method:** each CVE was checked against the NVD/MITRE record, the vendor advisory, and at least one independent write-up. Paths without a CVE (Jerry, Netmon, Love) were checked against multiple public walkthroughs. The `[Machine](page)` links point to the detail pages in this repository; the CVE numbers are the external anchors.

## Study tracks

Six orders through the same 76 boxes. Each one assumes the previous is comfortable; skip ahead only if you can already explain the privesc step.

1. **Web → shell first** — Nibbles, Devvortex, Cozyhosting, Magic, Networked, Tabby, Busqueda, Pilgrimage. One app bug, one shell, no AD. Do these before anything that needs Kerberos.
2. **Linux privesc ladder** — Sunday, Bashed, Nibbles, Codify, Broker, Tabby, BoardLight, Cctv. sudo → writable script → cron → group → SUID → capabilities, in that order.
3. **Windows starter set** — Jerry, Netmon, Bounty, Querier, Giddy, Access. Web or file-share foothold, then an ACL, service or SeImpersonate step.
4. **AD starter set (unauthenticated)** — Active, Forest, Cicada, Monteverde, Escape, Timelapse. No starting creds: share, null RPC, guest or a document is the way in.
5. **Assumed breach → DA** — Administrator, Certified, EscapeTwo, Puppy, Signed. Start with a login; finish with BloodHound, shadow creds or a silver ticket.
6. **Harder / multi-stage** — Silentium, Editor, Linkvortex, Builder, TheFrizz, Blackfield. Two or three pivots before root/DA; expect revert timers and cleanup scripts.

## Coverage check

Counted by tagging every row above against the page it came from. A box appears under each phase it needs, so the column is not meant to sum to 76.

| Phase / technique | Boxes | Examples |
| --- | --- | --- |
| Credentials & enumeration | 36 | Enigma, Netmon, Monteverde |
| Web / service → shell | 57 | Devvortex, Bounty, Return |
| Linux privesc | 42 | Broker, Tabby, BoardLight |
| Windows privesc | 22 | Markup, Bounty, Buff |
| AD (ACL, Kerberos, ADCS) | 16 | Forest, Certified, Signed |
| Pivot / hidden service | 8 | Pandora, Buff, Cctv |

**Sanity check:** the Linux privesc count (42) equals the 39 Linux machines plus the 3 non-AD Linux machines — every Linux box in the list requires a Linux privesc step. The Windows privesc count (22) exceeds the 18 Windows machines because the AD boxes also require Windows-side escalation. The AD count (16) matches the AD table exactly. Before an exam run: at least one ticked box per row, and no phase left at zero.

---

*Last verified: 2026-10-28. If a CVE is retired, reassigned, or a write-up contradicts a row, update the row and add a note under [Corrections](#corrections) rather than silently editing it.*
