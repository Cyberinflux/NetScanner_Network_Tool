# netscan

A zero-dependency network vulnerability scanner for home and small-office networks. Point it at your LAN and it finds every device, checks common ports, flags risky services and known-vulnerable versions, and opens an interactive dashboard that tracks changes between scans.

Built and tested for **macOS (Apple Silicon and Intel)**. Also runs on Linux.

![netscan dashboard](docs/dashboard.png)

> ⚠️ **Only scan networks you own or have explicit permission to test.** Unauthorized scanning may be illegal where you live and may violate your ISP's or employer's terms.

---

## Features

- **Zero dependencies:** a single Python file using only the standard library (Python 3.8+).
- **Automatic network detection:** finds your active interface, subnet and gateway on its own.
- **Thorough device discovery:** ICMP ping, TCP probes, the ARP table and SSDP/UPnP, so devices that ignore ping still show up.
- **Fast port scanning:** about 67 commonly abused ports by default, or a custom range, or all 65,535.
- **Safe, read-only checks:** it never changes settings or attempts exploitation (see [What it checks](#what-it-checks)).
- **Version-based CVE detection** for OpenSSH, Apache, Tomcat, vsftpd, ProFTPD and Dropbear.
- **Local Mac hardening checks:** firewall, stealth mode, FileVault, Gatekeeper and System Integrity Protection (SIP).
- **Interactive dashboard:**
  - Risk score and trend across scans
  - What changed since the last scan (new devices, new issues, resolved issues)
  - Sortable device table with drill-down
  - Searchable findings with a fix for each one
- **Optional nmap integration** for service fingerprinting, a lookup of known vulnerabilities (CVEs) through the `vulners` script, SMBv1 detection and TLS cipher grading.
- **JSON output** for scripting, SIEM ingestion, or diffing.

---

## Quick start

```bash
git clone https://github.com/<cyberinflux>/netscan.git
cd netscan
python3 netscan.py
```

That's it. When the scan finishes, the dashboard opens in your browser.

> On a fresh Mac, the first `python3` run may prompt you to install the Xcode Command Line Tools. Accept it.

---

## Usage

```bash
python3 netscan.py                         # auto-detect and scan your local subnet
python3 netscan.py 192.168.1.0/24          # scan a specific subnet
python3 netscan.py 192.168.1.1             # scan a single host (e.g. your router)
python3 netscan.py 192.168.1.1 --ports full    # all 65,535 ports on one host
python3 netscan.py --ports 22,80,8000-8100     # custom port list
python3 netscan.py --nmap                  # add nmap service/CVE detection
python3 netscan.py --dashboard             # reopen the dashboard without scanning
```

### Options

| Option | Default | Description |
|---|---|---|
| `target` | auto | CIDR range or single IP. Networks larger than /22 are trimmed to your /24 unless given explicitly. |
| `--ports` | `common` | `common` (~67 ports), `full` (1–65535), or a list such as `22,80,8000-8100`. |
| `--timeout` | `0.6` | TCP connect timeout in seconds. Raise it on slow Wi-Fi. |
| `--workers` | `200` | Concurrent connections. The open-file limit is raised automatically on macOS. |
| `--nmap` | off | Also run `nmap -sV` with the `vulners`, `smb-protocols` and `ssl-enum-ciphers` scripts. |
| `--no-local` | off | Skip the local Mac security checks. |
| `--out` | `~/netscan-reports` | Where scan JSON files and `dashboard.html` are written. |
| `--dashboard` | off | Rebuild and open the dashboard from previous scans, then exit. |
| `--no-open` | off | Don't open the browser after a scan (useful for scheduled runs). |
| `--no-color` | off | Disable colored terminal output. |

### Optional: nmap

```bash
brew install nmap
python3 netscan.py --nmap
```

nmap output for each host appears in the dashboard's device drill-down. The `vulners` script looks up CVEs online through vulners.com.

---

## What it checks

All checks are non-destructive. The scanner reads banners and responses; it does not brute-force passwords or run exploits.

### Network services

| Service | Port(s) | Check | Severity if found |
|---|---|---|---|
| **Tomcat AJP (Ghostcat)** | 8009 | Reads the Tomcat version and tests CVE-2020-1938 range | Critical / High / Medium / Low |
| **Docker API** | 2375 | Unauthenticated API access | Critical |
| **Redis** | 6379 | No authentication (`PING` → `PONG`) | Critical |
| **VNC / Screen Sharing** | 5900–5901 | "None" security type offered (no password) | Critical / Medium |
| **Apache httpd** | web ports | 2.4.49 / 2.4.50 path traversal (CVE-2021-41773/42013) | Critical |
| **vsftpd** | 21 | 2.3.4 backdoored release | Critical |
| **OpenSSH** | 22 | regreSSHion range (CVE-2024-6387), SSHv1, very old versions | High / Medium |
| **Telnet** | 23 | Service open (cleartext logins, Mirai botnet target) | High |
| **FTP** | 21 | Anonymous login allowed, cleartext protocol, old ProFTPD | High / Medium |
| **SNMP** | 161/udp | Responds to the default `public` community string | High |
| **Memcached** | 11211 | Unauthenticated stats access | High |
| **Elasticsearch** | 9200 | Unauthenticated cluster access | High |
| **ADB** | 5555 | Android Debug Bridge exposed on the network | High |
| **TR-069** | 7547 | ISP remote-management port reachable | High |
| **UPnP** | 1900/udp | Router Internet Gateway Device (IGD) enabled | Medium |
| **SMB / NetBIOS** | 139, 445 | File sharing exposed | Medium |
| **RDP** | 3389 | Remote Desktop exposed | Medium |
| **TLS** | 443, 8443, 993… | TLS 1.0/1.1 accepted, expired, self-signed or untrusted certificate | Medium / Low |
| **HTTP** | 80, 8080… | Login form over plain HTTP, Basic auth in cleartext, directory listing, version disclosure, outdated nginx/Tomcat, open Jenkins | Medium / Low |
| **Other** | various | MongoDB, MQTT, NFS, rsync, PPTP, MySQL/Postgres/MSSQL, JetDirect, RPC | Medium / Low |

### Ghostcat (CVE-2020-1938) detection

When port 8009 is open, netscan:

1. Sends an AJP13 **CPing** to confirm the port really speaks AJP.
2. Sends an ordinary AJP `GET` for a random, nonexistent path and reads the Tomcat version from the 404 page. If the version is hidden there, it checks the host's HTTP ports.
3. Compares the version against the first fixed releases: **7.0.100, 8.5.51 and 9.0.31**. Tomcat 6.x and 8.0.x were never patched.

The scanner never sends the `javax.servlet.include.*` request attributes that the exploit relies on, so it identifies the risk without exploiting it.

| Result | Severity |
|---|---|
| Vulnerable version, AJP reachable without a secret | **Critical** |
| AJP reachable, version hidden | **High** |
| Patched version, AJP reachable without a secret | **Medium** |
| AJP rejects the request with 403 (secret required) | **Low** |

### Local Mac checks

| Check | Severity if failing |
|---|---|
| System Integrity Protection disabled | High |
| Application Firewall off | Medium |
| FileVault off | Medium |
| Gatekeeper disabled | Medium |
| Firewall stealth mode off | Low |

---

## The dashboard

Each scan saves `netscan-YYYYMMDD-HHMMSS.json` to `~/netscan-reports/` and regenerates `dashboard.html` from the last 30 scans. The dashboard is a single self-contained HTML file with no external requests, so it works offline and your network map never leaves your machine.

- **KPIs:** device count, open ports, and issue counts by severity, each showing its change since the previous scan.
- **Risk score:** weighted total (critical ×10, high ×5, medium ×2, low ×0.5) and a rating from *Good* to *Critical*.
- **Trend chart:** risk over time. Click a point to load that scan.
- **Changes since previous scan:** new and resolved issues, and devices that joined or left. A new device is often the first sign of trouble.
- **Devices:** sortable. Click a row for services, banners, findings and nmap output.
- **All findings:** filter by severity and search by host, port or keyword.

---

## Scheduled scans (optional)

Run a nightly scan and check the dashboard whenever you like.

**cron:**
```bash
crontab -e
# every day at 2:15am
15 2 * * * /usr/bin/python3 /path/to/netscan.py --no-open --no-color >> ~/netscan-reports/cron.log 2>&1
```

**launchd** is more reliable on a laptop that sleeps: create `~/Library/LaunchAgents/com.netscan.nightly.plist` with a `StartCalendarInterval`, then run `launchctl load` on it.

---

## Output format

The JSON reports are easy to script against:

```json
{
  "meta":    { "network": "192.168.1.0/24", "gateway": "192.168.1.1", "started": "2026-11-25 19:00", ... },
  "summary": { "CRITICAL": 0, "HIGH": 3, "MEDIUM": 4, "LOW": 1 },
  "local":   [ { "severity": "MEDIUM", "title": "macOS firewall is OFF on this Mac", ... } ],
  "hosts": [
    {
      "ip": "192.168.1.20", "hostname": "nas.lan", "mac": "00:11:32:aa:bb:cc",
      "open_ports": [22, 445, 8009],
      "services": { "22": { "service": "ssh", "banner": "SSH-2.0-OpenSSH_8.9" } },
      "findings": [ { "severity": "HIGH", "title": "...", "detail": "...", "fix": "...", "port": 22 } ]
    }
  ]
}
```

Example: list every critical finding across all scans:

```bash
jq -r '.hosts[] | .ip as $ip | .findings[] | select(.severity=="CRITICAL") | "\($ip) \(.title)"' ~/netscan-reports/netscan-*.json
```

---

## Limitations

- **Version checks are heuristics.** Linux distributions (Debian, Ubuntu, RHEL) often backport security fixes without changing the version string, so treat version-based findings as "verify this", not proof.
- **TCP connect scan only.** UDP coverage is limited to SNMP and SSDP. Use `--nmap` for deeper fingerprinting.
- **Internal view only.** It shows what is reachable from inside your LAN. To see what's exposed to the internet, scan your public IP from an outside network.
- **No credentialed checks:** no logins, no password guessing, and no patch-level inspection inside devices.
- Very large networks (bigger than /22) are capped by default to keep scans quick.

---

## Troubleshooting

| Problem | Fix |
|---|---|
| Few or no devices found | Raise `--timeout 1.5`. Make sure you're on the same Wi-Fi/VLAN, and check that guest-network "client isolation" isn't on. |
| `Too many open files` | Lower `--workers 100`. |
| macOS asks to allow incoming connections | Allow, or ignore it; it's triggered by the SSDP discovery reply. |
| Dashboard didn't open | `open ~/netscan-reports/dashboard.html` or `python3 netscan.py --dashboard`. |
| nmap results missing | Run `brew install nmap`, and check that `nmap` is on your `PATH`. |

---

## Contributing

Issues and pull requests are welcome. Good first contributions:

- New service checks: add a `check_<service>(ip, port)` function returning `(findings, banner)` and wire it into `assess_host()`.
- More version → CVE mappings.
- MAC vendor (OUI) lookup.

Please keep checks **non-destructive** and **dependency-free**.

---

## Disclaimer

This tool is provided for defensive security assessment of networks you own or are authorized to test. The authors are not responsible for misuse or for any damage caused by this software. Findings are informational and not a substitute for a professional security assessment.

## License

MIT. See [LICENSE](LICENSE).
