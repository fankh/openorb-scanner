# OpenOrb — Open-Source Network Vulnerability Scanner

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/Built%20with-Rust-orange.svg)](https://www.rust-lang.org/)
[![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20macOS%20%7C%20Windows-lightgrey.svg)]()
[![Release](https://img.shields.io/github/v/release/fankh/openorb-scanner)](https://github.com/fankh/openorb-scanner/releases/latest)

**OpenOrb** is an open-source, high-performance network vulnerability scanner written in Rust. It combines port scanning, service/banner detection, and CVE matching in a single tool — an open-source alternative to Nmap + Nessus for vulnerability assessment.

**Key highlights:**
- Scan up to **1–5 million packets per second** using AF_PACKET + MMAP zero-copy (Linux)
- Detect services via **banner grabbing** (SSH, HTTP, FTP, SMB, MySQL, PostgreSQL, Redis, MongoDB, and more)
- Match discovered services to **CVEs from NVD** with CPE-based version comparison and CVSS/EPSS risk scoring
- Run **active vulnerability tests** (Heartbleed, anonymous FTP, Redis/MongoDB no-auth, weak SSL ciphers)
- **REST API** for integration with dashboards, SIEM, and CI/CD pipelines
- **Endpoint agent** for software inventory collection across Linux, macOS, and Windows

---

## Why OpenOrb?

| Feature | OpenOrb | Nmap | Masscan | Nessus |
|---------|---------|------|---------|--------|
| Port scanning | TCP Connect, SYN, AF_PACKET | TCP, SYN, UDP | SYN only | Agent-based |
| Max throughput | 1–5M pps | ~100K pps | 10M+ pps | N/A |
| Banner grabbing | Built-in | NSE scripts | No | Built-in |
| CVE matching | NVD + CPE + EPSS | No | No | Proprietary DB |
| Active vuln tests | YAML-based probes | NSE scripts | No | Plugins |
| REST API | Built-in (Axum) | XML output | No | Proprietary |
| Open source | MIT | GPL | AGPL | Commercial |
| Single binary | 9 MB | ~25 MB + scripts | 0.1 MB | ~1 GB |
| Language | Rust | C/Lua | C | Closed |

---

## Quick Start

### Download

Pre-compiled binaries (Linux x86_64):

> **[Download latest release](https://github.com/fankh/openorb-scanner/releases/latest)**
>
> - `openorb` (9 MB) — main scanner
> - `openorb-agent` (4 MB) — endpoint agent

```bash
# Download and run
wget https://github.com/fankh/openorb-scanner/releases/latest/download/openorb
chmod +x openorb
./openorb scan 192.168.1.1 --top-ports 100
```

### Build from Source

```bash
# Requires Rust 1.70+
git clone https://github.com/fankh/openorb-scanner.git
cd openorb-scanner
cargo build --release

# Binaries at target/release/openorb and target/release/openorb-agent
```

### Scan Modes

OpenOrb supports 3 scan modes via `--mode`:

| Mode | Command | Description | Speed |
|------|---------|-------------|-------|
| **port** | `--mode port` | Open port discovery only | Fastest (~0.1s) |
| **service** | `--mode service` | Ports + application name & version | ~8s (banner grab) |
| **full** | `--mode full` | Ports + service + CVE matching | ~8s + CVE lookup (default) |

```bash
# Port discovery only (fastest)
openorb scan 192.168.1.1 --top-ports 100 --mode port

# Port + service/version detection
openorb scan 192.168.1.1 --top-ports 100 --mode service

# Full scan with CVE matching (default)
openorb scan 192.168.1.1 --top-ports 100 --mode full

# Full port scan with JSON output
openorb scan 10.0.0.0/24 --all-ports --json -o results.json

# Fast scan with AF_PACKET (Linux, requires root)
sudo openorb scan 10.0.0.1 --all-ports --method afpacket --rate 100000
```

**Example — Port only mode:**
```
$ openorb scan 127.0.0.1 --top-ports 25 --mode port

Scanning target: 127.0.0.1
Ports: 25 ports
Mode: Port Discovery Only
Method: TCP Connect (~6 packets/port)

Discovery Complete
  Hosts found: 1
  Open ports: 4
  Duration: 0s

Discovered Hosts:
----------------------------------------------------------------------

127.0.0.1 (localhost)
  80/tcp  open
  443/tcp  open
  5432/tcp  open
  8080/tcp  open
```

**Example — Service mode:**
```
$ openorb scan 127.0.0.1 --top-ports 25 --mode service

Scanning target: 127.0.0.1
Ports: 25 ports
Mode: Port + Service Detection
Method: TCP Connect (~6 packets/port)

Discovery Complete
  Hosts found: 1
  Open ports: 4
  Duration: 8s

Discovered Hosts:
----------------------------------------------------------------------

127.0.0.1 (localhost)
  80/tcp  http            nginx/1.26.3 (Ubuntu)
  443/tcp  http            nginx
  5432/tcp  postgresql
  8080/tcp  http
```

---

## Scan Methods

| Method | Speed | Privileges | Use Case |
|--------|-------|------------|----------|
| **TCP Connect** | ~500 ports/s | None | Default, works everywhere |
| **SYN Scan** | ~1K pps | Root | Stealthier, half-open scan |
| **AF_PACKET** | 1–5M pps | Root (Linux) | Large network sweeps, masscan-level speed |
| **Auto** | Best available | Auto-detect | Picks fastest method available |

```bash
openorb scan TARGET --method connect    # No root needed
openorb scan TARGET --method syn        # Raw socket SYN scan
openorb scan TARGET --method afpacket   # Zero-copy ring buffer (Linux)
openorb scan TARGET --method auto       # Auto-detect best method (default)
```

---

## Features

### Port Scanning & Service Detection

OpenOrb discovers open ports and identifies running services through banner grabbing. It parses version strings into structured data for accurate CVE matching.

```
$ openorb scan 127.0.0.1 --top-ports 25 --method connect

Scanning target: 127.0.0.1
Ports: 25 ports
Method: TCP Connect (~6 packets/port)

Discovery Complete
  Hosts found: 1
  Open ports: 4
  Duration: 8s

Discovered Hosts:
----------------------------------------------------------------------

127.0.0.1 (localhost)
  80/tcp  http            nginx/1.26.3 (Ubuntu)
  443/tcp  http            nginx
  5432/tcp  postgresql
  8080/tcp  http

Checking vulnerabilities...
No vulnerabilities found
```

### JSON Output

Structured JSON output for integration with other tools and pipelines:

```bash
openorb scan 127.0.0.1 --top-ports 25 --method connect --json
```

```json
{
  "hosts": [
    {
      "hostname": "localhost",
      "ip": "127.0.0.1",
      "open_ports": [80, 443, 5432, 8080],
      "services": [
        {
          "port": 80,
          "service": "http",
          "product": "nginx",
          "version": "1.26.3 (Ubuntu)",
          "confidence": 0.85,
          "method": "banner-grab",
          "banner": "HTTP/1.1 200 OK\r\nServer: nginx/1.26.3 (Ubuntu)...",
          "metadata": {
            "headers": {
              "server": "nginx/1.26.3 (Ubuntu)",
              "content-type": "text/html",
              "x-frame-options": "DENY",
              "strict-transport-security": "max-age=31536000; includeSubDomains"
            },
            "status_code": 200
          },
          "parsed_version": {
            "raw": "1.26.3 (Ubuntu)",
            "core": "1.26.3",
            "major": 1,
            "minor": 26,
            "patch": 3,
            "distro": "Ubuntu"
          }
        }
      ]
    }
  ],
  "scan_method": "connect",
  "total_hosts": 1,
  "total_open_ports": 4,
  "duration_seconds": 8
}
```

### CVE Database & Vulnerability Matching

Sync the NVD (National Vulnerability Database) and match discovered services against known CVEs using CPE (Common Platform Enumeration) version comparison:

```bash
# Sync last 30 days of CVEs from NVD
openorb sync --days 30

# Sync all sources (NVD + CISA KEV + EPSS scores)
openorb sync --all

# Search CVE database
openorb search nginx --version 1.26.3
openorb search apache --severity high
```

### 3-Step Pipeline for Large Scans

For large-scale network assessments, OpenOrb supports a 3-step pipeline with SQLite persistence between steps. This allows you to scan thousands of hosts, then enrich results incrementally:

```bash
# Step 1: Fast port discovery
openorb discover 10.0.0.0/24 --top-ports 100 --method afpacket
# → Scan ID: 01fa9dc0-...

# Step 2: Banner grab discovered ports
openorb grab 01fa9dc0-...

# Step 3: Match CVEs
openorb match 01fa9dc0-...

# View scan history
openorb scans
openorb status 01fa9dc0-...
```

**Pipeline output example:**

```
$ openorb discover 127.0.0.1 --top-ports 25 --method connect

[Step 1] Port Discovery
  Target: 127.0.0.1
  Ports: 25 ports
  Method: Connect
  Scan ID: 01fa9dc0-4f2a-4fab-9941-06dab7ade7cc

Discovery Complete!
  Hosts: 1
  Open ports: 4

Next step:
  openorb grab 01fa9dc0-4f2a-4fab-9941-06dab7ade7cc
```

```
$ openorb grab 01fa9dc0-4f2a-4fab-9941-06dab7ade7cc

[Step 2] Banner Grabbing
  Scan ID: 01fa9dc0-4f2a-4fab-9941-06dab7ade7cc
  Assets: 4 ports to grab
  Timeout: 3000ms
  127.0.0.1:80   http 1.26.3 (Ubuntu)
  127.0.0.1:443  http nginx
  127.0.0.1:5432 postgresql -
  127.0.0.1:8080 http -

Banner Grab Complete!
  Services identified: 4

Next step:
  openorb match 01fa9dc0-4f2a-4fab-9941-06dab7ade7cc
```

### Active Vulnerability Testing

Run behavioral tests against services to verify specific vulnerabilities — safe by default, no exploitation:

```
$ openorb test 127.0.0.1 --list

Available Active Tests:
----------------------------------------------------------------------
ID                   SERVICE           RISK CVEs
----------------------------------------------------------------------
ssh-weak-algos       ssh             Safe -
mysql-nopassword     mysql           Low  -
heartbleed           ssl             Safe CVE-2014-0160
ssl-weak-ciphers     ssl             Safe -
ftp-anon             ftp             Safe -
redis-noauth         redis           Safe -
mongodb-noauth       mongodb         Safe -
http-trace           http            Safe -

Total: 8 tests
```

```bash
# Run all safe tests
openorb test 192.168.1.1 --all --max-risk safe

# Test for Heartbleed (CVE-2014-0160)
openorb test 192.168.1.1 --cve CVE-2014-0160

# Test specific vulnerability
openorb test 192.168.1.1 --id redis-noauth
```

### REST API Server

Built-in API server (Axum) for integrating OpenOrb with dashboards, SIEM systems, and CI/CD pipelines:

```bash
openorb server --port 8080 --host 0.0.0.0
```

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/health` | Health check |
| POST | `/api/v1/scans` | Create scan |
| GET | `/api/v1/scans` | List scans |
| GET | `/api/v1/scans/:id` | Get scan details |
| POST | `/api/v1/agents/register` | Register endpoint agent |
| POST | `/api/v1/agents/:id/inventory` | Submit software inventory |
| GET | `/api/v1/agents` | List registered agents |
| GET | `/api/v1/cve/search?product=nginx` | Search CVE database |
| GET | `/api/v1/dashboard/summary` | Dashboard statistics |

### Endpoint Agent

Cross-platform agent that collects software inventory from endpoints and reports to the OpenOrb server for centralized vulnerability management:

```bash
# Run once and exit
openorb-agent --server https://server:8080 --api-key KEY --once

# Run as daemon (scan every hour)
openorb-agent --server https://server:8080 --api-key KEY --interval 3600
```

| Platform | Package Sources |
|----------|----------------|
| **Linux** | dpkg, rpm, snap, flatpak, pip, npm |
| **macOS** | system_profiler, homebrew, pip, npm |
| **Windows** | Registry (Uninstall keys), PowerShell Get-Service |

---

## Risk Scoring

OpenOrb calculates prioritized risk scores combining multiple threat intelligence signals:

```
Risk = CVSS × Confidence × EPSS × Asset Criticality × Multipliers
```

| Factor | Description |
|--------|-------------|
| **CVSS** | Base vulnerability severity (0–10) from NVD |
| **Confidence** | Match quality: exact (0.95), range (0.70), product-only (0.40) |
| **EPSS** | Exploit Prediction Scoring System — probability of exploitation (0–1) |
| **KEV** | 1.5x multiplier for CISA Known Exploited Vulnerabilities |
| **Exploit** | 1.3x multiplier when public exploits exist |
| **Criticality** | Asset importance: critical (2.0), high (1.5), medium (1.0), low (0.5) |

---

## Architecture

```
openorb (9 MB single binary)
├── discovery/        Port scanning + service detection
│   ├── scanner.rs       TCP connect scan (async, tokio semaphore)
│   ├── syn_scanner.rs   SYN scan (pnet raw sockets, rate-limited)
│   ├── afpacket.rs      AF_PACKET + MMAP zero-copy ring buffer (1-5M pps)
│   ├── service.rs       Banner grabbing (HTTP, SSH, FTP, SMB, MySQL, Redis, MongoDB)
│   └── models.rs        Host, ServiceInfo, ParsedVersion
├── vulndb/           CVE database + matching engine
│   ├── database.rs      SQLite, NVD/EPSS/KEV sync, version-range matching
│   ├── scanner.rs       Service-to-CVE matching with confidence scoring
│   ├── cpe.rs           CPE 2.3 parsing + semantic version comparison
│   ├── active_tests.rs  YAML-based vulnerability probes
│   └── models.rs        Vulnerability, VulnMatch, Severity
├── api/              REST API (Axum framework)
├── agent/            Endpoint software inventory collector
└── plugins/          Protocol detection plugins (Modbus ICS/SCADA)

openorb-agent (4 MB)
└── Standalone endpoint agent (register, collect, report)
```

---

## CLI Reference

```
$ openorb --help
OpenOrb - Network Vulnerability Scanner

Usage: openorb [OPTIONS] <COMMAND>

Commands:
  scan      Scan target for open ports and vulnerabilities
  sync      Sync CVE database from NVD or external source
  search    Search CVE database
  server    Start API server
  discover  Step 1: Fast port discovery (no banner grab)
  grab      Step 2: Banner grab for discovered ports
  match     Step 3: Match CVEs for discovered services
  scans     List recent scans
  status    Show scan status and results
  test      Run active vulnerability tests

Options:
  -d, --debug    Enable debug logging
  -h, --help     Print help
  -V, --version  Print version
```

### Scan Options

```
openorb scan <TARGET> [OPTIONS]

  -p, --ports <PORTS>          Ports to scan (e.g., 22,80,443 or 1-1000)
      --top-ports <N>          Scan top N common ports
      --all-ports              Scan all 65535 ports
      --mode <MODE>            port | service | full [default: full]
      --no-vuln                Skip vulnerability check
  -o, --output <FILE>          Output file (JSON)
      --timeout <MS>           Port scan timeout in ms [default: 1000]
  -m, --method <METHOD>        connect | syn | afpacket | auto [default: auto]
      --rate <PPS>             Packets per second limit [default: 1000]
      --json                   Output as JSON
```

---

## Use Cases

- **Penetration testing** — Discover attack surface and known CVEs before engagement
- **Vulnerability assessment** — Continuous scanning with NVD sync and EPSS prioritization
- **Asset discovery** — Map network services and software versions across infrastructure
- **Compliance auditing** — Verify patch levels against CISA KEV and NVD databases
- **CI/CD security gates** — REST API integration for automated vulnerability checks
- **ICS/SCADA security** — Modbus protocol detection plugin for industrial networks

## License

[MIT](LICENSE) — Copyright 2025 Seekers Lab
