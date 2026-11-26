#!/usr/bin/env python3
"""
netscan.py - Home/small-office network vulnerability scanner (macOS / Linux)

Discovers devices on your LAN, scans common ports, and runs safe,
non-destructive checks for common misconfigurations and known-vulnerable
service versions. Writes a console summary plus HTML and JSON reports.

ONLY scan networks you own or are explicitly authorized to test.

Usage:
    python3 netscan.py                     # auto-detect your subnet
    python3 netscan.py 192.168.1.0/24      # specific subnet
    python3 netscan.py 192.168.1.10        # single host
    python3 netscan.py --ports full        # scan ports 1-65535 (slow)
    python3 netscan.py --nmap              # also run nmap -sV + vulners CVE lookup (brew install nmap)
    python3 netscan.py --dashboard         # open the dashboard of past scans without scanning

Results go to ~/netscan-reports/ and an interactive dashboard (dashboard.html)
opens in your browser after every scan, with history and changes between scans.

No third-party packages required (Python 3.8+).
"""

import argparse
import concurrent.futures as cf
import datetime as dt
import html
import ipaddress
import json
import os
import platform
import re
import shutil
import socket
import ssl
import struct
import subprocess
import sys
import time

VERSION = "1.0"

# --------------------------------------------------------------------------
# Configuration
# --------------------------------------------------------------------------

COMMON_PORTS = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns", 80: "http",
    81: "http", 88: "kerberos", 110: "pop3", 111: "rpcbind", 135: "msrpc",
    139: "netbios", 143: "imap", 389: "ldap", 443: "https", 445: "smb",
    465: "smtps", 515: "lpd", 548: "afp", 554: "rtsp", 587: "smtp",
    631: "ipp", 636: "ldaps", 873: "rsync", 993: "imaps", 995: "pop3s",
    1080: "socks", 1433: "mssql", 1521: "oracle", 1723: "pptp",
    1883: "mqtt", 2049: "nfs", 2375: "docker", 2376: "docker-tls",
    3000: "http", 3306: "mysql", 3389: "rdp", 5000: "http/upnp",
    5001: "https", 5060: "sip", 5222: "xmpp", 5353: "mdns", 5432: "postgres",
    5555: "adb", 5900: "vnc", 5901: "vnc", 6379: "redis", 6667: "irc",
    7000: "airplay", 7547: "tr-069", 8000: "http", 8008: "http",
    8009: "ajp", 8080: "http", 8081: "http", 8443: "https", 8888: "http",
    9000: "http", 9090: "http", 9100: "printer", 9200: "elasticsearch",
    10000: "webmin", 11211: "memcached", 27017: "mongodb", 32400: "plex",
    49152: "upnp", 62078: "iphone-sync",
}

DISCOVERY_PORTS = [80, 443, 22, 445, 139, 53, 8080, 62078, 5353, 7000, 554, 9100]

HTTP_PORTS = {80, 81, 3000, 5000, 8000, 8008, 8080, 8081, 8888, 9000, 9090, 10000, 32400, 49152}
TLS_PORTS = {443, 465, 636, 993, 995, 5001, 8443, 2376}

SEV_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}

USE_COLOR = sys.stdout.isatty()
COLORS = {"CRITICAL": "\033[1;97;41m", "HIGH": "\033[1;91m", "MEDIUM": "\033[1;93m",
          "LOW": "\033[94m", "INFO": "\033[90m", "OK": "\033[92m", "B": "\033[1m", "R": "\033[0m"}


def c(key, text):
    return f"{COLORS[key]}{text}{COLORS['R']}" if USE_COLOR else text


def log(msg):
    print(msg, flush=True)


# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------

def run(cmd, timeout=10):
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout).stdout
    except Exception:
        return ""


def raise_fd_limit():
    """macOS defaults to 256 open files, which throttles concurrent scanning."""
    try:
        import resource
        soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
        target = min(4096, hard if hard != resource.RLIM_INFINITY else 4096)
        if soft < target:
            resource.setrlimit(resource.RLIMIT_NOFILE, (target, hard))
        return resource.getrlimit(resource.RLIMIT_NOFILE)[0]
    except Exception:
        return 256


def detect_local_network():
    """Return (interface, local_ip, network, gateway)."""
    iface, gateway, local_ip, net = None, None, None, None
    if platform.system() == "Darwin":
        out = run(["route", "-n", "get", "default"])
        m = re.search(r"interface:\s*(\S+)", out)
        iface = m.group(1) if m else "en0"
        m = re.search(r"gateway:\s*(\S+)", out)
        gateway = m.group(1) if m else None
        ifc = run(["ifconfig", iface])
        m = re.search(r"inet (\d+\.\d+\.\d+\.\d+) netmask (0x[0-9a-f]+)", ifc)
        if m:
            local_ip = m.group(1)
            mask = str(ipaddress.IPv4Address(int(m.group(2), 16)))
            net = ipaddress.IPv4Network(f"{local_ip}/{mask}", strict=False)
    else:  # Linux
        out = run(["ip", "route", "show", "default"])
        m = re.search(r"default via (\S+) dev (\S+)", out)
        if m:
            gateway, iface = m.group(1), m.group(2)
            addr = run(["ip", "-4", "addr", "show", iface])
            m = re.search(r"inet (\d+\.\d+\.\d+\.\d+/\d+)", addr)
            if m:
                local_ip = m.group(1).split("/")[0]
                net = ipaddress.IPv4Network(m.group(1), strict=False)
    if not local_ip:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
            s.close()
        except Exception:
            local_ip = "127.0.0.1"
        net = ipaddress.IPv4Network(f"{local_ip}/24", strict=False)
    # Guard against huge networks (e.g. corporate /16)
    if net.prefixlen < 22:
        log(c("MEDIUM", f"[!] Network {net} is large; limiting scan to {local_ip}/24. "
                        "Pass a CIDR explicitly to override."))
        net = ipaddress.IPv4Network(f"{local_ip}/24", strict=False)
    return iface, local_ip, net, gateway


def parse_ports(spec):
    if spec == "common":
        return sorted(COMMON_PORTS)
    if spec == "full":
        return list(range(1, 65536))
    ports = set()
    for part in spec.split(","):
        part = part.strip()
        if "-" in part:
            a, b = part.split("-")
            ports.update(range(int(a), int(b) + 1))
        elif part:
            ports.add(int(part))
    return sorted(p for p in ports if 0 < p < 65536)


def tcp_probe(ip, port, timeout):
    """Return 'open', 'closed' (host alive, port refused) or None (no response)."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        r = s.connect_ex((ip, port))
        if r == 0:
            return "open"
        if r in (61, 111):  # ECONNREFUSED (macOS 61, Linux 111)
            return "closed"
        return None
    except Exception:
        return None
    finally:
        s.close()


def recv_all(sock, limit=4096, timeout=2.0):
    sock.settimeout(timeout)
    data = b""
    try:
        while len(data) < limit:
            chunk = sock.recv(limit - len(data))
            if not chunk:
                break
            data += chunk
    except Exception:
        pass
    return data


def talk(ip, port, send=None, timeout=3.0, read_first=False, limit=4096):
    """Open a TCP connection, optionally read a banner, optionally send data, return reply."""
    try:
        with socket.create_connection((ip, port), timeout=timeout) as s:
            data = b""
            if read_first:
                s.settimeout(timeout)
                try:
                    data = s.recv(limit)
                except Exception:
                    pass
            if send is not None:
                s.sendall(send)
                data += recv_all(s, limit, timeout)
            return data
    except Exception:
        return b""


def http_get(ip, port, path="/", use_tls=False, timeout=4.0):
    req = (f"GET {path} HTTP/1.1\r\nHost: {ip}\r\nUser-Agent: netscan/{VERSION}\r\n"
           "Accept: */*\r\nConnection: close\r\n\r\n").encode()
    try:
        raw = socket.create_connection((ip, port), timeout=timeout)
        if use_tls:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            raw = ctx.wrap_socket(raw, server_hostname=ip)
        with raw as s:
            s.sendall(req)
            data = recv_all(s, 65536, timeout)
    except Exception:
        return None
    if not data.startswith(b"HTTP/"):
        return None
    head, _, body = data.partition(b"\r\n\r\n")
    lines = head.decode(errors="replace").split("\r\n")
    status = lines[0]
    headers = {}
    for line in lines[1:]:
        if ":" in line:
            k, v = line.split(":", 1)
            headers[k.strip().lower()] = v.strip()
    return {"status": status, "headers": headers, "body": body.decode(errors="replace")}


def finding(sev, title, detail, fix):
    return {"severity": sev, "title": title, "detail": detail, "fix": fix}


def vtuple(s):
    return tuple(int(x) for x in re.findall(r"\d+", s)[:3])


# --------------------------------------------------------------------------
# Discovery
# --------------------------------------------------------------------------

def ping(ip):
    if platform.system() == "Darwin":
        cmd = ["ping", "-c", "1", "-W", "700", ip]  # -W is milliseconds on macOS
    else:
        cmd = ["ping", "-c", "1", "-W", "1", ip]
    try:
        return subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                              timeout=3).returncode == 0
    except Exception:
        return False


def host_alive(ip, timeout):
    if ping(ip):
        return True
    for p in DISCOVERY_PORTS:
        if tcp_probe(ip, p, timeout) is not None:
            return True
    return False


def read_arp_table():
    table = {}
    out = run(["arp", "-an"])
    for m in re.finditer(r"\((\d+\.\d+\.\d+\.\d+)\) at ([0-9a-f:]+)", out, re.I):
        mac = m.group(2).lower()
        if mac not in ("ff:ff:ff:ff:ff:ff",) and "incomplete" not in mac:
            mac = ":".join(x.zfill(2) for x in mac.split(":"))
            table[m.group(1)] = mac
    return table


def discover_hosts(net, workers, timeout):
    hosts = [str(h) for h in net.hosts()] if net.num_addresses > 1 else [str(net.network_address)]
    log(c("B", f"[*] Discovering live hosts in {net} ({len(hosts)} addresses)..."))
    alive = set()
    with cf.ThreadPoolExecutor(max_workers=min(workers, 128)) as ex:
        futs = {ex.submit(host_alive, ip, timeout): ip for ip in hosts}
        for f in cf.as_completed(futs):
            if f.result():
                alive.add(futs[f])
    # Devices that block ping and all probed ports still show up in ARP
    arp = read_arp_table()
    for ip in arp:
        try:
            if ipaddress.IPv4Address(ip) in net:
                alive.add(ip)
        except ValueError:
            pass
    return sorted(alive, key=lambda x: ipaddress.IPv4Address(x)), arp


def resolve_name(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return ""


def ssdp_discover(timeout=3.0):
    """Find UPnP devices (routers with UPnP can let malware open ports)."""
    msg = ("M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\n"
           "MX: 2\r\nST: ssdp:all\r\n\r\n").encode()
    found = {}
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
        s.settimeout(timeout)
        s.sendto(msg, ("239.255.255.250", 1900))
        end = time.time() + timeout
        while time.time() < end:
            try:
                data, addr = s.recvfrom(4096)
            except socket.timeout:
                break
            text = data.decode(errors="replace")
            info = found.setdefault(addr[0], {"server": "", "types": set()})
            for line in text.split("\r\n"):
                low = line.lower()
                if low.startswith("server:"):
                    info["server"] = line.split(":", 1)[1].strip()
                elif low.startswith("st:"):
                    info["types"].add(line.split(":", 1)[1].strip())
        s.close()
    except Exception:
        pass
    return found


# --------------------------------------------------------------------------
# Service checks (all read-only / non-destructive)
# --------------------------------------------------------------------------

def check_ssh(ip, port):
    out = []
    banner = talk(ip, port, read_first=True).decode(errors="replace").strip()
    if not banner:
        return out, ""
    if banner.startswith("SSH-1.") and not banner.startswith("SSH-1.99"):
        out.append(finding("HIGH", "SSH protocol version 1 supported",
                           f"Banner: {banner}", "Disable SSHv1; it is cryptographically broken."))
    m = re.search(r"OpenSSH[_-](\d+)\.(\d+)(?:p(\d+))?", banner)
    if m:
        ver = (int(m.group(1)), int(m.group(2)))
        if (8, 5) <= ver < (9, 8) or ver < (4, 4):
            out.append(finding("HIGH", "OpenSSH version in regreSSHion range (CVE-2024-6387)",
                               f"Banner: {banner}. Versions 8.5p1-9.7p1 (and <4.4p1) are affected "
                               "unless the vendor backported a fix (common on Debian/Ubuntu).",
                               "Update OpenSSH to 9.8p1 or later / apply vendor patches."))
        elif ver < (7, 4):
            out.append(finding("MEDIUM", "Outdated OpenSSH version",
                               f"Banner: {banner}. Old releases have multiple published CVEs.",
                               "Update the device firmware/OS so OpenSSH is current."))
    m = re.search(r"dropbear[_-](\d+)\.(\d+)", banner, re.I)
    if m and (int(m.group(1)), int(m.group(2))) < (2020, 79):
        out.append(finding("MEDIUM", "Outdated Dropbear SSH (common on routers/IoT)",
                           f"Banner: {banner}", "Update the device firmware."))
    out.append(finding("INFO", "SSH service exposed", f"Banner: {banner}",
                       "Ensure password login is disabled or strong passwords/keys are used."))
    return out, banner


def check_ftp(ip, port):
    out = []
    try:
        with socket.create_connection((ip, port), timeout=4) as s:
            banner = recv_all(s, 1024, 3).decode(errors="replace").strip()
            if "vsFTPd 2.3.4" in banner:
                out.append(finding("CRITICAL", "vsftpd 2.3.4 (backdoored release)",
                                   f"Banner: {banner}", "Replace immediately with a current FTP server."))
            if re.search(r"ProFTPD 1\.3\.[0-5]\b", banner):
                out.append(finding("HIGH", "Outdated ProFTPD (e.g. CVE-2015-3306 mod_copy)",
                                   f"Banner: {banner}", "Update ProFTPD."))
            s.sendall(b"USER anonymous\r\n")
            r1 = recv_all(s, 1024, 3).decode(errors="replace")
            anon = False
            if r1.startswith("230"):
                anon = True
            elif r1.startswith("331"):
                s.sendall(b"PASS netscan@example.com\r\n")
                r2 = recv_all(s, 1024, 3).decode(errors="replace")
                anon = r2.startswith("230")
            try:
                s.sendall(b"QUIT\r\n")
            except Exception:
                pass
    except Exception:
        return out, ""
    if anon:
        out.append(finding("HIGH", "Anonymous FTP login allowed",
                           "Anyone on the network can log in without a password.",
                           "Disable anonymous FTP access."))
    out.append(finding("MEDIUM", "FTP (unencrypted) in use",
                       f"Banner: {banner}. Credentials and files travel in cleartext.",
                       "Use SFTP/FTPS instead, or disable FTP."))
    return out, banner


def check_telnet(ip, port):
    banner = talk(ip, port, read_first=True, timeout=3).decode(errors="replace")
    banner = re.sub(r"[^\x20-\x7e]", "", banner).strip()
    return [finding("HIGH", "Telnet service open",
                    "Telnet sends logins in cleartext and is a favorite target of IoT botnets (Mirai). "
                    f"Banner: {banner[:120] or '(none)'}",
                    "Disable Telnet on this device; use SSH or the web UI instead.")], banner


def check_http(ip, port, use_tls=False):
    out = []
    r = http_get(ip, port, "/", use_tls)
    if not r:
        return out, ""
    h, body = r["headers"], r["body"]
    server = h.get("server", "")
    banner = f"{r['status']} | Server: {server}".strip()
    if server and re.search(r"\d", server):
        out.append(finding("LOW", "Web server discloses version",
                           f"Server: {server}", "Hide version banners where possible."))
    if "x-powered-by" in h:
        out.append(finding("LOW", "X-Powered-By header discloses technology",
                           f"X-Powered-By: {h['x-powered-by']}", "Remove the header."))
    m = re.search(r"Apache/(2\.4\.(49|50))\b", server)
    if m:
        out.append(finding("CRITICAL", f"Apache {m.group(1)} path traversal / RCE (CVE-2021-41773/42013)",
                           f"Server: {server}", "Upgrade Apache to 2.4.51 or later immediately."))
    m = re.search(r"Apache/(\d+\.\d+\.\d+)", server)
    if m and vtuple(m.group(1)) < (2, 4, 0):
        out.append(finding("MEDIUM", "End-of-life Apache version", f"Server: {server}", "Upgrade Apache."))
    m = re.search(r"nginx/(\d+\.\d+\.\d+)", server)
    if m and vtuple(m.group(1)) < (1, 20, 0):
        out.append(finding("MEDIUM", "Outdated nginx version", f"Server: {server}", "Upgrade nginx."))
    if "<title>Index of /" in body or "Directory listing for" in body:
        out.append(finding("MEDIUM", "Directory listing enabled",
                           "Files on this web server can be browsed by anyone.",
                           "Disable directory indexing."))
    if not use_tls and re.search(r'type=["\']?password', body, re.I):
        out.append(finding("MEDIUM", "Login page served over unencrypted HTTP",
                           "Passwords entered here travel in cleartext across your network.",
                           "Enable HTTPS on the device's admin interface if available."))
    if "www-authenticate" in h and not use_tls and h["www-authenticate"].lower().startswith("basic"):
        out.append(finding("MEDIUM", "HTTP Basic auth over cleartext",
                           f"Realm: {h['www-authenticate']}", "Use HTTPS for this interface."))
    if port in (8080, 8081, 8000, 9000) and "Jenkins" in (body + str(h)) and "Dashboard" in body:
        out.append(finding("HIGH", "Jenkins dashboard reachable without login",
                           "Unauthenticated Jenkins often allows code execution.",
                           "Enable Jenkins security / authentication."))
    if port == 10000 and "webmin" in body.lower():
        out.append(finding("MEDIUM", "Webmin admin panel exposed", banner,
                           "Restrict access and keep Webmin updated (many past RCE CVEs)."))
    tomcat_body = body
    if "tomcat" not in (body + server).lower():
        r404 = http_get(ip, port, "/netscan-" + os.urandom(4).hex(), use_tls)
        tomcat_body = r404["body"] if r404 else ""
    out += check_tomcat_http(ip, port, tomcat_body, server)
    if use_tls and "strict-transport-security" not in h:
        out.append(finding("INFO", "HTTPS without HSTS header", "", "Add Strict-Transport-Security if this is a web app."))
    return out, banner


def check_tls(ip, port):
    out = []
    # 1. Certificate validity (using system trust store)
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        with socket.create_connection((ip, port), timeout=4) as raw:
            with ctx.wrap_socket(raw, server_hostname=ip) as s:
                ver = s.version()
    except ssl.SSLCertVerificationError as e:
        msg = str(getattr(e, "verify_message", "") or e)
        if "expired" in msg:
            out.append(finding("MEDIUM", "TLS certificate expired", msg, "Renew/replace the certificate."))
        elif "self" in msg.lower():
            out.append(finding("LOW", "Self-signed TLS certificate",
                               "Common on routers/NAS, but makes man-in-the-middle attacks harder to notice.",
                               "Install a trusted certificate if the device supports it."))
        else:
            out.append(finding("LOW", "TLS certificate not trusted", msg, "Install a valid certificate."))
        ver = None
    except (ssl.SSLError, OSError):
        return out
    # 2. Legacy protocol support (TLS 1.0 / 1.1)
    for name, tv in (("TLS 1.0", getattr(ssl.TLSVersion, "TLSv1", None)),
                     ("TLS 1.1", getattr(ssl.TLSVersion, "TLSv1_1", None))):
        if tv is None:
            continue
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            ctx.minimum_version = tv
            ctx.maximum_version = tv
            try:
                ctx.set_ciphers("ALL:@SECLEVEL=0")
            except ssl.SSLError:
                pass
            with socket.create_connection((ip, port), timeout=4) as raw:
                with ctx.wrap_socket(raw, server_hostname=ip):
                    out.append(finding("MEDIUM", f"Deprecated {name} supported",
                                       f"Port {port} accepts {name}, which is deprecated (RFC 8996).",
                                       "Disable TLS 1.0/1.1; allow only TLS 1.2+."))
        except Exception:
            pass
    return out


def check_vnc(ip, port):
    out = []
    try:
        with socket.create_connection((ip, port), timeout=4) as s:
            s.settimeout(4)
            ver = s.recv(12)
            if not ver.startswith(b"RFB "):
                return out, ""
            banner = ver.decode(errors="replace").strip()
            if ver[4:11] == b"003.003":
                s.sendall(ver)
                sec = struct.unpack(">I", s.recv(4))[0]
                types = [sec]
            else:
                s.sendall(b"RFB 003.008\n")
                n = s.recv(1)[0]
                types = list(s.recv(n)) if n else []
    except Exception:
        return out, ""
    if 1 in types:
        out.append(finding("CRITICAL", "VNC allows connections with NO password",
                           f"{banner}; security types offered: {types}",
                           "Set a VNC password or disable screen sharing immediately."))
    else:
        out.append(finding("MEDIUM", "VNC / Screen Sharing exposed",
                           f"{banner}; security types: {types}",
                           "Disable if unused; VNC passwords are often limited to 8 chars."))
    return out, banner


def check_redis(ip, port):
    r = talk(ip, port, b"PING\r\n").decode(errors="replace")
    if r.startswith("+PONG"):
        return [finding("CRITICAL", "Redis accessible without authentication",
                        "Unauthenticated Redis can be abused to read data and often to execute code.",
                        "Set requirepass / ACLs and bind Redis to localhost.")], "redis"
    if "NOAUTH" in r:
        return [finding("LOW", "Redis exposed (auth required)", "", "Bind Redis to localhost if remote access isn't needed.")], "redis"
    return [], ""


def check_memcached(ip, port):
    r = talk(ip, port, b"stats\r\n").decode(errors="replace")
    if "STAT " in r:
        m = re.search(r"STAT version (\S+)", r)
        return [finding("HIGH", "Memcached accessible without authentication",
                        f"Version {m.group(1) if m else '?'}; data is readable and it can be used for DDoS amplification.",
                        "Bind memcached to localhost and disable UDP.")], "memcached"
    return [], ""


def check_elasticsearch(ip, port):
    r = http_get(ip, port, "/")
    if r and "cluster_name" in r["body"]:
        return [finding("HIGH", "Elasticsearch accessible without authentication",
                        "Index data can be read or deleted by anyone on the network.",
                        "Enable Elasticsearch security (xpack) and restrict network access.")], "elasticsearch"
    return [], ""


def check_docker(ip, port):
    r = http_get(ip, port, "/version")
    if r and "ApiVersion" in r["body"]:
        return [finding("CRITICAL", "Docker API exposed without TLS/auth",
                        "Anyone on the network can run containers = full root on the host.",
                        "Stop exposing the Docker daemon on TCP 2375.")], "docker"
    return [], ""


# --- Apache Tomcat / AJP (Ghostcat, CVE-2020-1938) -------------------------
# Detection only: sends an AJP "CPing" and an ordinary AJP GET for a page that
# doesn't exist, then reads the Tomcat version from the 404 error page. It does
# NOT send the javax.servlet.include.* attributes the Ghostcat exploit relies on.

TOMCAT_RE = re.compile(r"Apache Tomcat/(\d+\.\d+\.\d+(?:\.M\d+)?)")
GHOSTCAT_FIXED = {7: (7, 0, 100), 8: (8, 5, 51), 9: (9, 0, 31)}  # first fixed release per branch


def _ajp_str(s):
    if s is None:
        return b"\xff\xff"
    b = s.encode()
    return struct.pack(">H", len(b)) + b + b"\x00"


def ajp_cping(ip, port):
    """True if the port speaks AJP13 (CPing -> CPong)."""
    r = talk(ip, port, b"\x12\x34\x00\x01\x0a", timeout=3, limit=16)
    return r[:5] == b"AB\x00\x01\x09"


def ajp_get(ip, port, path):
    """Plain AJP13 GET request. Returns (status, raw_response_bytes)."""
    body = (b"\x02\x02" + _ajp_str("HTTP/1.1") + _ajp_str(path) + _ajp_str("127.0.0.1")
            + _ajp_str(None) + _ajp_str(ip) + struct.pack(">H", 80) + b"\x00"
            + struct.pack(">H", 2)
            + b"\xa0\x0b" + _ajp_str(ip)                       # Host
            + b"\xa0\x0e" + _ajp_str("netscan/" + VERSION)     # User-Agent
            + b"\xff")
    pkt = b"\x12\x34" + struct.pack(">H", len(body)) + body
    raw = talk(ip, port, pkt, timeout=4, limit=65536)
    status = None
    i = raw.find(b"AB")
    # first server packet: 'AB' len(2) prefix(1)=4 SEND_HEADERS status(2)
    if i >= 0 and len(raw) >= i + 7 and raw[i + 4] == 4:
        status = struct.unpack(">H", raw[i + 5:i + 7])[0]
    return status, raw


def tomcat_version_via_http(ip, http_ports):
    """Tomcat's default 404 page prints its version; check the host's web ports."""
    probe = "/netscan-" + os.urandom(4).hex()
    for p in http_ports:
        r = http_get(ip, p, probe, use_tls=p in TLS_PORTS)
        if r:
            m = TOMCAT_RE.search(r["body"] + " " + r["headers"].get("server", ""))
            if m:
                return m.group(1), f"{p}/tcp"
    return None, None


def ghostcat_verdict(ver):
    """Return True (vulnerable), False (patched) for a Tomcat version string."""
    v = vtuple(ver)
    major = v[0]
    if major <= 6:
        return True                      # Tomcat 6 and older: never fixed
    if major == 8 and v[1] == 0:
        return True                      # 8.0.x: end-of-life, never fixed
    if major in GHOSTCAT_FIXED:
        return v < GHOSTCAT_FIXED[major]
    return False                         # 10.x and newer shipped with the fix


def check_ajp(ip, port, open_ports):
    out = []
    if not ajp_cping(ip, port):
        return out, "", "unknown"
    status, raw = ajp_get(ip, port, "/netscan-" + os.urandom(4).hex())
    m = TOMCAT_RE.search(raw.decode("latin-1"))
    ver, src = (m.group(1), "AJP 404 page") if m else (None, None)
    if not ver:
        web = [p for p in open_ports if p in HTTP_PORTS or p in TLS_PORTS]
        ver, src = tomcat_version_via_http(ip, web)
        if ver:
            src = f"HTTP error page on {src}"
    banner = f"AJP13 (Apache Tomcat {ver})" if ver else "AJP13"
    fix = ("Update Tomcat to 9.0.31 / 8.5.51 / 7.0.100 or newer (on a NAS/appliance: update its firmware). "
           "If nothing uses AJP, comment out the AJP <Connector port=\"8009\"> in conf/server.xml. "
           "If you need it, set address=\"127.0.0.1\" and secretRequired=\"true\" with a long secret.")
    if ver and ghostcat_verdict(ver):
        out.append(finding("CRITICAL", f"Ghostcat (CVE-2020-1938): vulnerable Tomcat {ver} with AJP reachable",
                           f"AJP port {port} answers without a secret and Tomcat {ver} (from {src}) is in the "
                           "affected range. Anyone on the network can read web-app files such as config files "
                           "with passwords; with file upload it can lead to code execution. CVSS 9.8.", fix))
    elif status == 403:
        out.append(finding("LOW", "AJP connector reachable but requires a secret",
                           f"AJP port {port} rejected an unauthenticated request (403), which is how patched "
                           f"Tomcat behaves with secretRequired=true.{' Version: ' + ver if ver else ''}",
                           "Bind AJP to 127.0.0.1 if only a local web server uses it."))
    elif ver:
        out.append(finding("MEDIUM", f"AJP connector exposed (Tomcat {ver} is patched for Ghostcat)",
                           f"Tomcat {ver} (from {src}) includes the CVE-2020-1938 fix, but AJP is still "
                           "reachable from the network and accepted a request without a secret.",
                           "Bind AJP to 127.0.0.1 or set secretRequired=\"true\" with a secret, or disable it."))
    else:
        out.append(finding("HIGH", "AJP connector exposed, Tomcat version unknown (possible Ghostcat)",
                           f"AJP port {port} accepts unauthenticated requests but the Tomcat version is hidden, "
                           "so CVE-2020-1938 can't be ruled out. Run with --nmap or check the version on the device.",
                           fix))
    return out, banner, "ajp"


def check_tomcat_http(ip, port, r_body, server):
    """Flag an old Tomcat seen on a web port (independent of AJP)."""
    m = TOMCAT_RE.search(r_body + " " + server)
    if not m:
        return []
    if vtuple(m.group(1))[0] <= 8:
        return [finding("MEDIUM", f"End-of-life Apache Tomcat {m.group(1)}",
                        "Tomcat 8.5 and older no longer receive security fixes.",
                        "Upgrade to a supported Tomcat release (10.1.x or 11.x).")]
    return [finding("INFO", f"Apache Tomcat {m.group(1)} detected", "Default error page reveals the version.",
                    "Configure a custom error page / ErrorReportValve showServerInfo=\"false\".")]


def check_mongodb(ip, port):
    return [finding("MEDIUM", "MongoDB port exposed", "Verify authentication is enabled.",
                    "Enable auth and bind to localhost if remote access isn't needed.")], "mongodb"


def check_snmp(ip):
    """Send an SNMPv2c GET sysDescr.0 with community 'public'."""
    pkt = bytes.fromhex("302902010104067075626c6963a01c0204") + os.urandom(4) + \
        bytes.fromhex("020100020100300e300c06082b060102010101000500")
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(1.5)
        s.sendto(pkt, (ip, 161))
        data, _ = s.recvfrom(4096)
        s.close()
    except Exception:
        return []
    descr = "".join(chr(b) if 32 <= b < 127 else " " for b in data[40:])
    descr = re.sub(r"\s+", " ", descr).strip()[:150]
    return [finding("HIGH", "SNMP responds to default community string 'public'",
                    f"Device info leaks to anyone on the network. sysDescr: {descr}",
                    "Disable SNMP or change the community string / use SNMPv3.")]


SIMPLE_EXPOSURE = {
    139: ("MEDIUM", "NetBIOS/SMB file sharing exposed", "Check that shares require passwords. Run with --nmap to test for SMBv1."),
    445: ("MEDIUM", "SMB file sharing exposed", "Check shares require passwords and SMBv1 is disabled (WannaCry/EternalBlue)."),
    3389: ("MEDIUM", "Remote Desktop (RDP) exposed", "Enable Network Level Authentication and keep Windows patched."),
    5555: ("HIGH", "Android Debug Bridge (ADB) over network", "Anyone on the network may get a shell on this device. Disable wireless debugging."),
    7547: ("HIGH", "TR-069 (ISP remote management) reachable on LAN", "Historically exploited by botnets; update router firmware."),
    1883: ("MEDIUM", "MQTT broker exposed", "Ensure MQTT requires authentication (IoT devices often don't)."),
    3306: ("LOW", "MySQL exposed", "Bind to localhost if remote access isn't needed."),
    5432: ("LOW", "PostgreSQL exposed", "Bind to localhost if remote access isn't needed."),
    1433: ("LOW", "MSSQL exposed", "Restrict network access."),
    2049: ("MEDIUM", "NFS exposed", "Check exports are not world-readable."),
    873: ("MEDIUM", "rsync daemon exposed", "Check modules require authentication."),
    1723: ("MEDIUM", "PPTP VPN enabled", "PPTP encryption is broken; switch to WireGuard/IPsec/OpenVPN."),
    9100: ("LOW", "Raw printer port (JetDirect) open", "Anyone can send print jobs; restrict if possible."),
    111: ("LOW", "RPC portmapper exposed", "Disable if not needed."),
    23: None, 21: None,  # handled by dedicated checks
}


def scan_host(ip, ports, timeout, workers):
    open_ports = []
    with cf.ThreadPoolExecutor(max_workers=workers) as ex:
        futs = {ex.submit(tcp_probe, ip, p, timeout): p for p in ports}
        for f in cf.as_completed(futs):
            if f.result() == "open":
                open_ports.append(futs[f])
    return sorted(open_ports)


def assess_host(ip, open_ports):
    findings, services = [], {}
    for port in open_ports:
        name = COMMON_PORTS.get(port, "unknown")
        banner, fs = "", []
        try:
            if port == 22 or name == "ssh":
                fs, banner = check_ssh(ip, port)
            elif port == 21:
                fs, banner = check_ftp(ip, port)
            elif port == 23:
                fs, banner = check_telnet(ip, port)
            elif port in (5900, 5901):
                fs, banner = check_vnc(ip, port)
            elif port == 6379:
                fs, banner = check_redis(ip, port)
            elif port == 11211:
                fs, banner = check_memcached(ip, port)
            elif port == 9200:
                fs, banner = check_elasticsearch(ip, port)
            elif port == 2375:
                fs, banner = check_docker(ip, port)
            elif port == 27017:
                fs, banner = check_mongodb(ip, port)
            elif port == 8009:
                fs, banner, name = check_ajp(ip, port, open_ports)
            elif port in TLS_PORTS:
                fs = check_tls(ip, port)
                hf, banner = check_http(ip, port, use_tls=True)
                fs += hf
            elif port in HTTP_PORTS:
                fs, banner = check_http(ip, port)
            else:
                # Try to identify unknown services: banner, then HTTP
                b = talk(ip, port, read_first=True, timeout=2).decode(errors="replace").strip()
                if b.startswith("SSH-"):
                    fs, banner = check_ssh(ip, port)
                else:
                    banner = re.sub(r"[^\x20-\x7e]", " ", b)[:120]
                    if not banner:
                        hf, hb = check_http(ip, port)
                        if hb:
                            fs, banner, name = hf, hb, "http"
            simple = SIMPLE_EXPOSURE.get(port)
            if simple:
                sev, title, fix = simple
                fs.append(finding(sev, title, f"Port {port}/tcp open", fix))
        except Exception as e:
            banner = f"(check error: {e})"
        for f in fs:
            f["port"] = port
        findings.extend(fs)
        services[port] = {"service": name, "banner": banner}
    for f in check_snmp(ip):
        f["port"] = "161/udp"
        findings.append(f)
    findings.sort(key=lambda f: SEV_ORDER[f["severity"]])
    return services, findings


def run_nmap(ip, open_ports):
    if not shutil.which("nmap") or not open_ports:
        return ""
    cmd = ["nmap", "-Pn", "-sV", "--script", "vulners,smb-protocols,ssl-enum-ciphers",
           "-p", ",".join(map(str, open_ports)), ip]
    return run(cmd, timeout=600)


# --------------------------------------------------------------------------
# Local macOS checks
# --------------------------------------------------------------------------

def local_mac_checks():
    out = []
    if platform.system() != "Darwin":
        return out
    fw = "/usr/libexec/ApplicationFirewall/socketfilterfw"
    state = run([fw, "--getglobalstate"])
    if "disabled" in state.lower() or "State = 0" in state:
        out.append(finding("MEDIUM", "macOS firewall is OFF on this Mac",
                           state.strip(), "System Settings > Network > Firewall > turn on."))
    elif state:
        out.append(finding("INFO", "macOS firewall is on", state.strip(), ""))
    stealth = run([fw, "--getstealthmode"])
    if stealth and ("off" in stealth.lower() or "disabled" in stealth.lower()):
        out.append(finding("LOW", "Firewall stealth mode is off",
                           stealth.strip(), "Firewall > Options > Enable stealth mode."))
    sip = run(["csrutil", "status"])
    if "disabled" in sip.lower():
        out.append(finding("HIGH", "System Integrity Protection is disabled", sip.strip(),
                           "Re-enable SIP from Recovery: csrutil enable."))
    gk = run(["spctl", "--status"])
    if "disabled" in gk.lower():
        out.append(finding("MEDIUM", "Gatekeeper is disabled", gk.strip(), "sudo spctl --master-enable"))
    fv = run(["fdesetup", "status"])
    if "Off" in fv:
        out.append(finding("MEDIUM", "FileVault disk encryption is off", fv.strip(),
                           "System Settings > Privacy & Security > FileVault."))
    return out


# --------------------------------------------------------------------------
# Reporting
# --------------------------------------------------------------------------

def print_host(h):
    title = f"{h['ip']}"
    if h["hostname"]:
        title += f"  ({h['hostname']})"
    if h["mac"]:
        title += f"  [{h['mac']}]"
    if h.get("role"):
        title += f"  <{h['role']}>"
    log("\n" + c("B", "━" * 78))
    log(c("B", title))
    if h["services"]:
        for port, s in sorted(h["services"].items(), key=lambda x: int(x[0])):
            log(f"   {str(port) + '/tcp':<10} {s['service']:<14} {s['banner'][:50]}")
    else:
        log("   no open ports found in scanned range")
    for f in h["findings"]:
        if f["severity"] == "INFO":
            continue
        tag = "[" + f["severity"].center(8) + "]"
        log(f"   {c(f['severity'], tag)} {f['title']} (port {f['port']})")


def load_history(out_dir, limit=30):
    """Load previous scan JSON files (oldest first) for the dashboard."""
    reports = []
    try:
        names = sorted(n for n in os.listdir(out_dir) if re.match(r"netscan-\d{8}-\d{6}\.json$", n))
    except OSError:
        return reports
    for n in names[-limit:]:
        try:
            with open(os.path.join(out_dir, n)) as fh:
                r = json.load(fh)
            r["meta"]["id"] = n[8:-5]
            reports.append(r)
        except Exception:
            pass
    return reports


def write_dashboard(out_dir, history):
    data = json.dumps(history, default=str).replace("</", "<\\/")
    page = DASHBOARD_TEMPLATE.replace("__DATA__", data).replace("__VERSION__", VERSION)
    path = os.path.join(out_dir, "dashboard.html")
    with open(path, "w") as fh:
        fh.write(page)
    return path


def open_in_browser(path):
    try:
        if platform.system() == "Darwin":
            subprocess.Popen(["open", path])
        else:
            import webbrowser
            webbrowser.open("file://" + os.path.abspath(path))
    except Exception:
        pass


DASHBOARD_TEMPLATE = r"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>netscan dashboard</title>
<style>
:root{--bg:#0d1117;--panel:#161b22;--panel2:#1c2230;--line:#2a3140;--text:#e6edf3;--muted:#8b949e;
--CRITICAL:#ff4d6d;--HIGH:#ff8a3d;--MEDIUM:#f2c94c;--LOW:#58a6ff;--INFO:#6e7681;--OK:#3fb950}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--text);font:14px/1.45 -apple-system,BlinkMacSystemFont,"SF Pro Text",system-ui,sans-serif}
header{display:flex;align-items:center;gap:16px;padding:18px 28px;border-bottom:1px solid var(--line);background:var(--panel);position:sticky;top:0;z-index:5}
header h1{font-size:17px;margin:0;font-weight:650;letter-spacing:.2px}
header h1 span{color:var(--muted);font-weight:400}
header .meta{color:var(--muted);font-size:12.5px;flex:1}
select,input{background:var(--panel2);color:var(--text);border:1px solid var(--line);border-radius:7px;padding:7px 10px;font:inherit}
main{padding:22px 28px;max-width:1400px;margin:0 auto}
.grid{display:grid;gap:14px}
.kpis{grid-template-columns:repeat(auto-fit,minmax(140px,1fr));margin-bottom:14px}
.kpi{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:14px 16px;position:relative;overflow:hidden}
.kpi .v{font-size:28px;font-weight:700;font-variant-numeric:tabular-nums}
.kpi .l{color:var(--muted);font-size:12px;text-transform:uppercase;letter-spacing:.6px}
.kpi .d{font-size:12px;margin-top:2px}
.kpi.sev::before{content:"";position:absolute;left:0;top:0;bottom:0;width:4px;background:var(--c)}
.row2{grid-template-columns:1.1fr 1fr 1fr;margin-bottom:14px}
@media(max-width:1000px){.row2{grid-template-columns:1fr}}
.panel{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:16px 18px}
.panel h2{font-size:13px;margin:0 0 12px;color:var(--muted);text-transform:uppercase;letter-spacing:.7px;font-weight:600;display:flex;align-items:center;gap:8px}
.panel h2 .sp{flex:1}
.score{display:flex;align-items:center;gap:18px}
.score .big{font-size:46px;font-weight:750;font-variant-numeric:tabular-nums}
.score .grade{font-size:13px;padding:3px 10px;border-radius:20px;font-weight:700}
.bar{display:flex;height:12px;border-radius:6px;overflow:hidden;background:var(--panel2);margin:12px 0 8px}
.legend{display:flex;flex-wrap:wrap;gap:12px;font-size:12px;color:var(--muted)}
.legend i{display:inline-block;width:9px;height:9px;border-radius:2px;margin-right:5px;vertical-align:middle}
.top li{display:flex;gap:10px;align-items:center;padding:6px 0;border-bottom:1px solid var(--line)}
.top li:last-child{border:0}
.top ul{list-style:none;margin:0;padding:0}
.top .t{flex:1;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.top .n{color:var(--muted);font-variant-numeric:tabular-nums}
.pill{display:inline-block;font-size:10.5px;font-weight:700;padding:2px 8px;border-radius:20px;color:#0d1117;background:var(--c);letter-spacing:.3px;white-space:nowrap}
.chip{cursor:pointer;user-select:none;border:1px solid var(--line);background:var(--panel2);color:var(--muted);padding:5px 11px;border-radius:20px;font-size:12px;font-weight:600}
.chip.on{color:#0d1117;background:var(--c);border-color:var(--c)}
table{width:100%;border-collapse:collapse}
th{text-align:left;font-size:11.5px;color:var(--muted);text-transform:uppercase;letter-spacing:.5px;font-weight:600;padding:8px 10px;border-bottom:1px solid var(--line);cursor:pointer;white-space:nowrap}
td{padding:9px 10px;border-bottom:1px solid var(--line);vertical-align:top}
tr.host{cursor:pointer}
tr.host:hover td{background:var(--panel2)}
tr.detail td{background:#11161e;padding:14px 18px}
.mono{font-family:ui-monospace,"SF Mono",Menlo,monospace;font-size:12.5px}
.muted{color:var(--muted)}
.counts span{display:inline-block;min-width:22px;text-align:center;font-size:11.5px;font-weight:700;border-radius:5px;padding:1px 5px;margin-right:3px;background:var(--panel2);color:var(--muted)}
.counts span.x{color:#0d1117;background:var(--c)}
.dgrid{display:grid;grid-template-columns:1fr 1.6fr;gap:18px}
@media(max-width:900px){.dgrid{grid-template-columns:1fr}}
.f{padding:8px 0;border-bottom:1px dashed var(--line)}
.f:last-child{border:0}
.f .fix{color:var(--OK);font-size:12.5px;margin-top:3px}
.f .det{color:var(--muted);font-size:12.5px;margin-top:2px;word-break:break-word}
.tools{display:flex;gap:8px;flex-wrap:wrap;align-items:center;margin-bottom:10px}
.tools input{flex:1;min-width:200px}
.empty{color:var(--muted);text-align:center;padding:30px}
.tag{font-size:11px;color:var(--muted);border:1px solid var(--line);border-radius:5px;padding:1px 6px;margin-left:6px}
.new{color:var(--CRITICAL)} .fixed{color:var(--OK)}
svg text{fill:var(--muted);font-size:10px}
details pre{background:#0a0d12;padding:12px;border-radius:8px;overflow:auto;font-size:12px;max-height:400px}
footer{color:var(--muted);font-size:12px;padding:10px 28px 30px;max-width:1400px;margin:0 auto}
</style></head><body>
<header>
  <h1>netscan <span>dashboard</span></h1>
  <div class="meta" id="meta"></div>
  <label class="muted" style="font-size:12px">Scan&nbsp;<select id="scanSel"></select></label>
</header>
<main>
  <div class="grid kpis" id="kpis"></div>
  <div class="grid row2">
    <div class="panel"><h2>Risk score</h2><div id="score"></div></div>
    <div class="panel"><h2>Trend <span class="sp"></span><span class="muted" style="text-transform:none;letter-spacing:0" id="trendNote"></span></h2><div id="trend"></div></div>
    <div class="panel top"><h2>Most common issues</h2><div id="top"></div></div>
  </div>
  <div class="panel" style="margin-bottom:14px" id="changesPanel"><h2>Changes since previous scan</h2><div id="changes"></div></div>
  <div class="panel" style="margin-bottom:14px" id="localPanel"><h2>This Mac</h2><div id="local"></div></div>
  <div class="panel" style="margin-bottom:14px">
    <h2>Devices <span class="sp"></span><span class="muted" style="text-transform:none;letter-spacing:0">click a row for details</span></h2>
    <table id="hosts"><thead><tr>
      <th data-k="ip">IP</th><th data-k="name">Device</th><th data-k="mac">MAC</th>
      <th data-k="ports">Open ports</th><th data-k="risk">Findings</th><th data-k="worst">Worst</th></tr></thead><tbody></tbody></table>
  </div>
  <div class="panel">
    <h2>All findings</h2>
    <div class="tools" id="chips"><input id="q" placeholder="Search findings, hosts, ports…"></div>
    <table id="findings"><thead><tr><th>Severity</th><th>Host</th><th>Port</th><th>Finding</th><th>Fix</th></tr></thead><tbody></tbody></table>
  </div>
</main>
<footer>Generated by netscan v__VERSION__. Version-based findings are <i>potential</i> issues: vendors sometimes backport fixes without changing version strings. Only scan networks you own or are authorized to test.</footer>
<script>
const HISTORY = __DATA__;
const SEVS = ["CRITICAL","HIGH","MEDIUM","LOW","INFO"];
const W = {CRITICAL:10,HIGH:5,MEDIUM:2,LOW:0.5,INFO:0};
const $ = s => document.querySelector(s);
const esc = s => String(s ?? "").replace(/[&<>"']/g, m => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[m]));
const pill = s => `<span class="pill" style="--c:var(--${s})">${s}</span>`;
const allF = r => r.hosts.flatMap(h => h.findings.map(f => ({...f, ip:h.ip, host:h}))).concat((r.local||[]).map(f => ({...f, ip:"this Mac", port:"-"})));
const risk = r => Math.round(allF(r).reduce((a,f) => a + W[f.severity], 0));
const counts = fs => { const c = {}; SEVS.forEach(s => c[s]=0); fs.forEach(f => c[f.severity]++); return c; };
const hostName = h => h.hostname || h.role || "";
const key = f => `${f.ip}|${f.port}|${f.title}`;
let cur = HISTORY.length - 1, sevFilter = new Set(["CRITICAL","HIGH","MEDIUM","LOW"]), sortK = "risk", sortDir = -1, openRows = new Set();

function grade(score, c) {
  if (c.CRITICAL) return ["Critical", "CRITICAL"];
  if (c.HIGH) return ["At risk", "HIGH"];
  if (score > 10) return ["Needs attention", "MEDIUM"];
  if (score > 0) return ["Fair", "LOW"];
  return ["Good", "OK"];
}

function render() {
  if (!HISTORY.length) { document.body.innerHTML = '<p class="empty">No scans yet. Run: python3 netscan.py</p>'; return; }
  const r = HISTORY[cur], prev = cur > 0 ? HISTORY[cur-1] : null, m = r.meta;
  const fs = allF(r), c = counts(fs), pc = prev ? counts(allF(prev)) : null;
  $("#meta").innerHTML = `${esc(m.network)} · ${esc(m.started)} · ${m.duration}s · gateway ${esc(m.gateway||"?")} · ${m.ports_scanned} ports/host`;

  const openPorts = r.hosts.reduce((a,h) => a + h.open_ports.length, 0);
  const delta = (now, was) => was == null ? "" : now === was ? `<div class="d muted">no change</div>` :
      `<div class="d ${now > was ? "new" : "fixed"}">${now > was ? "▲" : "▼"} ${Math.abs(now-was)} vs last</div>`;
  const pOpen = prev ? prev.hosts.reduce((a,h) => a + h.open_ports.length, 0) : null;
  $("#kpis").innerHTML =
    `<div class="kpi"><div class="l">Devices</div><div class="v">${r.hosts.length}</div>${delta(r.hosts.length, prev && prev.hosts.length)}</div>` +
    `<div class="kpi"><div class="l">Open ports</div><div class="v">${openPorts}</div>${delta(openPorts, pOpen)}</div>` +
    SEVS.slice(0,4).map(s => `<div class="kpi sev" style="--c:var(--${s})"><div class="l">${s}</div><div class="v" style="color:${c[s] ? `var(--${s})` : "inherit"}">${c[s]}</div>${delta(c[s], pc && pc[s])}</div>`).join("");

  const score = risk(r), [g, gc] = grade(score, c), tot = SEVS.slice(0,4).reduce((a,s) => a + c[s], 0) || 1;
  $("#score").innerHTML = `<div class="score"><div class="big" style="color:var(--${gc})">${score}</div>
    <div><span class="grade" style="background:var(--${gc});color:#0d1117">${g}</span>
    <div class="muted" style="font-size:12px;margin-top:6px">Weighted: critical ×10, high ×5, medium ×2, low ×0.5. Lower is better.</div></div></div>
    <div class="bar">${SEVS.slice(0,4).map(s => c[s] ? `<div title="${s}: ${c[s]}" style="width:${c[s]/tot*100}%;background:var(--${s})"></div>` : "").join("")}</div>
    <div class="legend">${SEVS.slice(0,4).map(s => `<span><i style="background:var(--${s})"></i>${s.toLowerCase()} ${c[s]}</span>`).join("")}</div>`;

  renderTrend();

  const groups = {};
  fs.filter(f => f.severity !== "INFO").forEach(f => { const g = groups[f.title] ||= {n:0, sev:f.severity}; g.n++; });
  const top = Object.entries(groups).sort((a,b) => W[b[1].sev]-W[a[1].sev] || b[1].n-a[1].n).slice(0,7);
  $("#top").innerHTML = top.length ? `<ul>${top.map(([t,g]) => `<li>${pill(g.sev)}<span class="t" title="${esc(t)}">${esc(t)}</span><span class="n">×${g.n}</span></li>`).join("")}</ul>` : `<div class="empty">No issues found 🎉</div>`;

  if (prev) {
    const now = new Map(fs.filter(f => f.severity !== "INFO").map(f => [key(f), f]));
    const was = new Map(allF(prev).filter(f => f.severity !== "INFO").map(f => [key(f), f]));
    const added = [...now].filter(([k]) => !was.has(k)).map(([,f]) => f);
    const gone = [...was].filter(([k]) => !now.has(k)).map(([,f]) => f);
    const nowIps = new Set(r.hosts.map(h => h.ip)), wasIps = new Set(prev.hosts.map(h => h.ip));
    const newDev = r.hosts.filter(h => !wasIps.has(h.ip)), goneDev = prev.hosts.filter(h => !nowIps.has(h.ip));
    const line = (f, cls, sym) => `<div class="f"><span class="${cls}">${sym}</span> ${pill(f.severity)} <b>${esc(f.title)}</b> <span class="muted mono">${esc(f.ip)}:${esc(f.port)}</span></div>`;
    const items = added.map(f => line(f,"new","＋ new")).concat(gone.map(f => line(f,"fixed","✓ resolved")))
      .concat(newDev.map(h => `<div class="f"><span class="new">＋ new device</span> <span class="mono">${esc(h.ip)}</span> <span class="muted">${esc(hostName(h))} ${esc(h.mac)}</span></div>`))
      .concat(goneDev.map(h => `<div class="f"><span class="muted">− device gone</span> <span class="mono">${esc(h.ip)}</span> <span class="muted">${esc(hostName(h))}</span></div>`));
    $("#changesPanel").style.display = "";
    $("#changes").innerHTML = items.length ? items.join("") : `<div class="muted">No changes since ${esc(prev.meta.started)}.</div>`;
  } else $("#changesPanel").style.display = "none";

  const local = r.local || [];
  $("#localPanel").style.display = local.length ? "" : "none";
  $("#local").innerHTML = local.map(f => `<div class="f">${pill(f.severity)} <b>${esc(f.title)}</b><div class="det">${esc(f.detail)}</div>${f.fix ? `<div class="fix">→ ${esc(f.fix)}</div>` : ""}</div>`).join("");

  renderHosts(); renderFindings();
}

function renderTrend() {
  const el = $("#trend");
  if (HISTORY.length < 2) { el.innerHTML = `<div class="empty">Run more scans to see a trend.</div>`; $("#trendNote").textContent = ""; return; }
  const pts = HISTORY.map(risk), w = 380, h = 130, p = 22, max = Math.max(...pts, 1);
  const x = i => p + i * (w - 2*p) / (pts.length - 1), y = v => h - p - v / max * (h - 2*p);
  const path = pts.map((v,i) => `${i ? "L" : "M"}${x(i)},${y(v)}`).join("");
  $("#trendNote").textContent = `${HISTORY.length} scans`;
  el.innerHTML = `<svg viewBox="0 0 ${w} ${h}" width="100%">
    <line x1="${p}" y1="${h-p}" x2="${w-p}" y2="${h-p}" stroke="var(--line)"/>
    <path d="${path} L${x(pts.length-1)},${h-p} L${x(0)},${h-p}Z" fill="var(--LOW)" opacity=".12"/>
    <path d="${path}" fill="none" stroke="var(--LOW)" stroke-width="2"/>
    ${pts.map((v,i) => `<circle cx="${x(i)}" cy="${y(v)}" r="${i===cur?5:3}" fill="${i===cur?"var(--text)":"var(--LOW)"}" style="cursor:pointer" onclick="pick(${i})"><title>${esc(HISTORY[i].meta.started)}: risk ${v}</title></circle>`).join("")}
    <text x="${p}" y="${h-6}">${esc(HISTORY[0].meta.started.slice(5))}</text>
    <text x="${w-p}" y="${h-6}" text-anchor="end">${esc(HISTORY.at(-1).meta.started.slice(5))}</text>
    <text x="${p}" y="12">risk ${max}</text></svg>`;
}

function worst(h) { return h.findings.length ? SEVS.indexOf(h.findings.reduce((a,f) => SEVS.indexOf(f.severity) < SEVS.indexOf(a.severity) ? f : a).severity) : 9; }

function renderHosts() {
  const r = HISTORY[cur];
  const val = h => ({ip: h.ip.split(".").map(n => n.padStart(3,"0")).join("."), name: hostName(h), mac: h.mac,
    ports: h.open_ports.length, risk: h.findings.reduce((a,f) => a + W[f.severity], 0), worst: -worst(h)})[sortK];
  const hosts = [...r.hosts].sort((a,b) => { const A = val(a), B = val(b); return (A > B ? 1 : A < B ? -1 : 0) * sortDir; });
  $("#hosts tbody").innerHTML = hosts.map(h => {
    const c = counts(h.findings), wi = worst(h), ws = SEVS[wi];
    const row = `<tr class="host" data-ip="${esc(h.ip)}"><td class="mono">${esc(h.ip)}</td>
      <td>${esc(h.hostname || "—")}${h.role ? `<span class="tag">${esc(h.role)}</span>` : ""}</td>
      <td class="mono muted">${esc(h.mac || "—")}</td>
      <td class="mono">${h.open_ports.length ? esc(h.open_ports.join(", ")) : '<span class="muted">none</span>'}</td>
      <td class="counts">${SEVS.slice(0,4).map(s => `<span class="${c[s] ? "x" : ""}" style="--c:var(--${s})" title="${s}">${c[s]}</span>`).join("")}</td>
      <td>${ws && ws !== "INFO" ? pill(ws) : '<span class="pill" style="--c:var(--OK)">OK</span>'}</td></tr>`;
    if (!openRows.has(h.ip)) return row;
    const svc = Object.entries(h.services).sort((a,b) => a[0]-b[0]).map(([p,s]) =>
      `<tr><td class="mono">${p}/tcp</td><td>${esc(s.service)}</td><td class="mono muted">${esc(s.banner)}</td></tr>`).join("");
    const fnd = h.findings.map(f => `<div class="f">${pill(f.severity)} <b>${esc(f.title)}</b> <span class="muted mono">port ${esc(f.port)}</span>
      ${f.detail ? `<div class="det">${esc(f.detail)}</div>` : ""}${f.fix ? `<div class="fix">→ ${esc(f.fix)}</div>` : ""}</div>`).join("");
    return row + `<tr class="detail"><td colspan="6"><div class="dgrid">
      <div><h2 style="font-size:12px;color:var(--muted);margin:0 0 6px">SERVICES</h2><table>${svc || '<tr><td class="muted">No open ports</td></tr>'}</table></div>
      <div><h2 style="font-size:12px;color:var(--muted);margin:0 0 6px">FINDINGS</h2>${fnd || '<div class="muted">No issues found</div>'}</div></div>
      ${h.nmap ? `<details style="margin-top:12px"><summary class="muted">nmap output</summary><pre>${esc(h.nmap)}</pre></details>` : ""}</td></tr>`;
  }).join("") || `<tr><td colspan="6" class="empty">No devices found</td></tr>`;
  document.querySelectorAll("#hosts th").forEach(th => th.textContent = th.textContent.replace(/ [▲▼]$/, "") + (th.dataset.k === sortK ? (sortDir > 0 ? " ▲" : " ▼") : ""));
}

function renderFindings() {
  const q = $("#q").value.toLowerCase();
  const fs = allF(HISTORY[cur]).filter(f => sevFilter.has(f.severity))
    .filter(f => !q || [f.title, f.detail, f.fix, f.ip, f.port, f.host && f.host.hostname].join(" ").toLowerCase().includes(q))
    .sort((a,b) => SEVS.indexOf(a.severity) - SEVS.indexOf(b.severity));
  $("#findings tbody").innerHTML = fs.map(f => `<tr><td>${pill(f.severity)}</td>
    <td class="mono">${esc(f.ip)}${f.host && f.host.hostname ? `<div class="muted" style="font-family:inherit;font-size:12px">${esc(f.host.hostname)}</div>` : ""}</td>
    <td class="mono">${esc(f.port)}</td><td><b>${esc(f.title)}</b>${f.detail ? `<div class="det muted" style="font-size:12.5px">${esc(f.detail)}</div>` : ""}</td>
    <td style="color:var(--OK);font-size:13px">${esc(f.fix)}</td></tr>`).join("") || `<tr><td colspan="5" class="empty">No findings match</td></tr>`;
  const all = counts(allF(HISTORY[cur]));
  document.querySelectorAll(".chip").forEach(ch => { ch.classList.toggle("on", sevFilter.has(ch.dataset.s)); ch.textContent = `${ch.dataset.s} ${all[ch.dataset.s]}`; });
}

function pick(i) { cur = i; $("#scanSel").value = i; openRows.clear(); render(); }

// wiring
$("#scanSel").innerHTML = HISTORY.map((r,i) => `<option value="${i}">${esc(r.meta.started)} — ${esc(r.meta.network)}</option>`).reverse().join("");
$("#scanSel").value = cur;
$("#scanSel").onchange = e => pick(+e.target.value);
$("#chips").insertAdjacentHTML("beforeend", SEVS.map(s => `<span class="chip" data-s="${s}" style="--c:var(--${s})"></span>`).join(""));
document.querySelectorAll(".chip").forEach(ch => ch.onclick = () => { sevFilter.has(ch.dataset.s) ? sevFilter.delete(ch.dataset.s) : sevFilter.add(ch.dataset.s); renderFindings(); });
$("#q").oninput = renderFindings;
$("#hosts tbody").onclick = e => { const tr = e.target.closest("tr.host"); if (!tr) return; const ip = tr.dataset.ip; openRows.has(ip) ? openRows.delete(ip) : openRows.add(ip); renderHosts(); };
document.querySelectorAll("#hosts th").forEach(th => th.onclick = () => { const k = th.dataset.k; sortDir = sortK === k ? -sortDir : (k === "ip" || k === "name" || k === "mac" ? 1 : -1); sortK = k; renderHosts(); });
render();
</script></body></html>"""


# --------------------------------------------------------------------------
# Main
# --------------------------------------------------------------------------

def main():
    global USE_COLOR
    ap = argparse.ArgumentParser(description="Scan your local network for common vulnerabilities.")
    ap.add_argument("target", nargs="?", help="CIDR (192.168.1.0/24) or single IP. Default: auto-detect.")
    ap.add_argument("--ports", default="common", help="'common' (default), 'full', or list like 22,80,8000-8100")
    ap.add_argument("--timeout", type=float, default=0.6, help="TCP connect timeout in seconds (default 0.6)")
    ap.add_argument("--workers", type=int, default=200, help="Concurrent connections (default 200)")
    ap.add_argument("--nmap", action="store_true", help="Also run nmap -sV with vulners CVE lookup (needs nmap)")
    ap.add_argument("--no-local", action="store_true", help="Skip local Mac security checks")
    ap.add_argument("--out", default=os.path.expanduser("~/netscan-reports"),
                    help="Directory for reports and dashboard (default: ~/netscan-reports)")
    ap.add_argument("--dashboard", action="store_true", help="Just open the dashboard of past scans; don't scan")
    ap.add_argument("--no-open", action="store_true", help="Don't open the dashboard in a browser when done")
    ap.add_argument("--no-color", action="store_true")
    a = ap.parse_args()
    if a.no_color:
        USE_COLOR = False

    if a.dashboard:
        history = load_history(a.out)
        if not history:
            log(f"No scans found in {a.out}. Run a scan first: python3 netscan.py")
            return
        path = write_dashboard(a.out, history)
        log(c("OK", f"[+] Dashboard ({len(history)} scans): {path}"))
        open_in_browser(path)
        return

    log(c("B", f"netscan v{VERSION} — only scan networks you own or are authorized to test.\n"))
    fd = raise_fd_limit()
    workers = max(16, min(a.workers, fd - 64))

    iface, local_ip, net, gateway = detect_local_network()
    if a.target:
        net = ipaddress.IPv4Network(a.target, strict=False)
    ports = parse_ports(a.ports)
    log(f"[*] Interface {iface or '?'} · this Mac {local_ip} · gateway {gateway or '?'} · target {net}")
    log(f"[*] {len(ports)} ports per host · timeout {a.timeout}s · {workers} workers")
    if a.nmap and not shutil.which("nmap"):
        log(c("MEDIUM", "[!] --nmap requested but nmap isn't installed (brew install nmap). Continuing without it."))

    start = time.time()
    if net.num_addresses == 1:
        live, arp = [str(net.network_address)], read_arp_table()
    else:
        live, arp = discover_hosts(net, workers, a.timeout)
    log(c("OK", f"[+] {len(live)} live hosts found"))

    log(c("B", "[*] Looking for UPnP devices (SSDP)..."))
    upnp = ssdp_discover()

    hosts = []
    for i, ip in enumerate(live, 1):
        log(f"[*] ({i}/{len(live)}) Scanning {ip} ...")
        open_ports = scan_host(ip, ports, a.timeout, workers)
        services, findings = assess_host(ip, open_ports)
        if ip in upnp:
            u = upnp[ip]
            sev = "MEDIUM" if ip == gateway or any("InternetGatewayDevice" in t for t in u["types"]) else "LOW"
            title = "UPnP enabled on router (IGD)" if sev == "MEDIUM" else "UPnP/SSDP service responding"
            fix = ("Disable UPnP in router settings unless needed; malware can use it to open ports to the internet."
                   if sev == "MEDIUM" else "Disable UPnP on this device if unused.")
            findings.append(dict(finding(sev, title, f"Server: {u['server']}", fix), port="1900/udp"))
            findings.sort(key=lambda f: SEV_ORDER[f["severity"]])
        host = {"ip": ip, "hostname": resolve_name(ip), "mac": arp.get(ip, ""),
                "role": "gateway" if ip == gateway else ("this Mac" if ip == local_ip else ""),
                "open_ports": open_ports, "services": services, "findings": findings}
        if a.nmap:
            host["nmap"] = run_nmap(ip, open_ports)
        hosts.append(host)
        print_host(host)

    local = [] if a.no_local else local_mac_checks()
    for f in local:
        f["port"] = "-"

    duration = round(time.time() - start, 1)
    summary = {}
    for f in [f for h in hosts for f in h["findings"]] + local:
        summary[f["severity"]] = summary.get(f["severity"], 0) + 1

    if local:
        log("\n" + c("B", "━" * 78) + "\n" + c("B", "This Mac"))
        for f in local:
            log(f"   {c(f['severity'], '[' + f['severity'].center(8) + ']')} {f['title']}")

    log("\n" + c("B", "═" * 78))
    log(c("B", f"Summary: {len(hosts)} hosts scanned in {duration}s"))
    log("   " + "  ".join(c(s, f"{s}: {summary.get(s, 0)}") for s in SEV_ORDER))

    stamp = dt.datetime.now().strftime("%Y%m%d-%H%M%S")
    os.makedirs(a.out, exist_ok=True)
    report = {"meta": {"version": VERSION, "network": str(net), "local_ip": local_ip,
                       "gateway": gateway, "interface": iface,
                       "started": dt.datetime.now().strftime("%Y-%m-%d %H:%M"),
                       "duration": duration, "host_count": len(hosts), "ports_scanned": len(ports)},
              "summary": summary, "local": local, "hosts": hosts}
    jpath = os.path.join(a.out, f"netscan-{stamp}.json")
    with open(jpath, "w") as fh:
        json.dump(report, fh, indent=2, default=str)
    history = load_history(a.out)
    dpath = write_dashboard(a.out, history)
    log(c("OK", f"\n[+] Scan saved:  {jpath}"))
    log(c("OK", f"[+] Dashboard:   {dpath}  ({len(history)} scans in history)"))
    log("    Reopen any time with:  python3 netscan.py --dashboard")
    if not a.no_open:
        open_in_browser(dpath)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nAborted.")
        sys.exit(130)
