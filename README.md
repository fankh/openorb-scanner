# OpenOrb

A high-performance network vulnerability scanner written in Rust.

## Features

- **Network Scanning** - TCP connect, SYN, and AF_PACKET zero-copy scanning (1-5M pps)
- **Banner Grabbing** - Service detection for SSH, HTTP, FTP, SMB, MySQL, PostgreSQL, Redis, MongoDB, and more
- **CVE Matching** - NVD database sync with CPE-based version matching and risk scoring
- **Active Testing** - YAML-based vulnerability probes (Heartbleed, FTP anonymous, Redis noauth, etc.)
- **3-Step Pipeline** - Discover ports, grab banners, match CVEs with persistent scan history
- **REST API** - Axum-based API server for scan management and CVE search
- **Endpoint Agent** - Cross-platform software inventory collection (dpkg, rpm, pip, npm, Windows Registry)
- **Plugin System** - Extensible protocol detection (Modbus ICS/SCADA included)

## Installation

```bash
# Clone and build
git clone https://github.com/fankh/openorb-scanner.git
cd openorb-scanner
cargo build --release

# Binaries are at:
#   target/release/openorb        (9 MB - main scanner)
#   target/release/openorb-agent  (4 MB - endpoint agent)
```

## Scan Methods

| Method | Throughput | Privileges | Command |
|--------|-----------|------------|---------|
| TCP Connect | ~500 ports/s | None | `--method connect` |
| SYN Scan | ~1K pps | Root | `--method syn` |
| AF_PACKET | 1-5M pps | Root (Linux) | `--method afpacket` or `--method fast` |
| Auto | Best available | Auto-detect | `--method auto` (default) |

---

## Usage Manual

### Command Overview

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
  help      Print this message or the help of the given subcommand(s)

Options:
  -d, --debug    Enable debug logging
  -h, --help     Print help
  -V, --version  Print version
```

### 1. Quick Scan (All-in-One)

Scans ports, grabs banners, detects services, and checks CVEs in a single command.

```bash
openorb scan <TARGET> [OPTIONS]
```

**Options:**
```
  -p, --ports <PORTS>          Ports to scan (e.g., 22,80,443 or 1-1000)
      --top-ports <TOP_PORTS>  Scan top N common ports
      --all-ports              Scan all 65535 ports
      --no-vuln                Skip vulnerability check
  -o, --output <OUTPUT>        Output file (JSON)
      --timeout <TIMEOUT>      Port scan timeout in ms [default: 1000]
  -m, --method <METHOD>        Scan method: connect, syn, afpacket, auto [default: auto]
      --rate <RATE>            Packets per second rate limit [default: 1000]
      --json                   Output as JSON
```

**Example:**
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

**JSON Output:**
```
$ openorb scan 127.0.0.1 --top-ports 25 --method connect --json

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
        },
        {
          "port": 443,
          "service": "http",
          "product": "nginx",
          "confidence": 0.85
        },
        {
          "port": 5432,
          "service": "postgresql",
          "confidence": 0.9
        },
        {
          "port": 8080,
          "service": "http",
          "confidence": 0.5
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

### 2. Pipeline Mode (3-Step Scan)

For large scans, use the 3-step pipeline to separate port discovery, banner grabbing, and CVE matching. Results are persisted in SQLite between steps.

#### Step 1: Discover Ports

Fast port discovery without banner grabbing.

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

#### Step 2: Banner Grab

Grab banners and detect services for previously discovered ports.

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

#### Step 3: CVE Matching

Match detected services against the CVE database.

```
$ openorb match 01fa9dc0-4f2a-4fab-9941-06dab7ade7cc

[Step 3] CVE Matching
  Scan ID: 01fa9dc0-4f2a-4fab-9941-06dab7ade7cc
  Min severity: LOW
  Services: 4 to check

No vulnerabilities found!
```

### 3. Scan History

#### List Recent Scans

```
$ openorb scans

Recent Scans:
------------------------------------------------------------------------------------------
SCAN ID                              TARGET         STEP  PORTS  SVCS  VULNS  STATUS
------------------------------------------------------------------------------------------
01fa9dc0-4f2a-4fab-9941-06dab7ade7cc 127.0.0.1         3      4     4      0  completed
```

#### Show Scan Details

```
$ openorb status 01fa9dc0-4f2a-4fab-9941-06dab7ade7cc

Scan Status:
  Scan ID: 01fa9dc0-4f2a-4fab-9941-06dab7ade7cc
  Target: 127.0.0.1
  Step: 3/3
  Status: completed
  Started: 2026-03-13 06:45:34
  Completed: 2026-03-13 06:45:56

Results:
  Open ports: 4
  Services: 4
  Vulnerabilities: 0
```

### 4. Active Vulnerability Testing

Run behavioral tests against target services to verify vulnerabilities.

#### List Available Tests

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

#### Run All Tests

```
$ openorb test 127.0.0.1 --all --max-risk low

Active Vulnerability Testing
  Target: 127.0.0.1
  Ports: [80, 443, 22, 21, 25, 6379, 27017, 3306]
  Max risk: Low
  Mode: All tests

Results:
----------------------------------------------------------------------
Safe         http-trace           127.0.0.1:80 (0ms)
Error        ssh-weak-algos       127.0.0.1:22 (0ms)
             Test error: Connection failed: Connection refused (os error 111)
Error        ftp-anon             127.0.0.1:21 (0ms)
             Test error: Connection failed: Connection refused (os error 111)
Error        redis-noauth         127.0.0.1:6379 (0ms)
             Test error: Connection failed: Connection refused (os error 111)
Error        mongodb-noauth       127.0.0.1:27017 (0ms)
             Test error: Connection failed: Connection refused (os error 111)
Error        mysql-nopassword     127.0.0.1:3306 (0ms)
             Test error: Connection failed: Connection refused (os error 111)
----------------------------------------------------------------------
Summary: 8 tests | 0 vulnerable | 1 safe | 7 errors | 0 skipped
```

#### Run Specific Test

```bash
# Test for Heartbleed
openorb test 192.168.1.1 --cve CVE-2014-0160

# Test specific ID
openorb test 192.168.1.1 --id ftp-anon

# Specify ports
openorb test 192.168.1.1 -p 443 --id heartbleed
```

### 5. CVE Database Management

#### Sync from NVD

```bash
# Sync last 30 days of CVEs
openorb sync --days 30

# Sync all sources (NVD + CISA KEV + EPSS scores)
openorb sync --all

# Sync CISA Known Exploited Vulnerabilities only
openorb sync --kev

# Sync EPSS scores only
openorb sync --epss
```

#### Search CVEs

```
$ openorb search nginx

CVE Search Results
  Product: nginx
  Found: 0 vulnerabilities
```

```bash
# Search with version filter
openorb search nginx --version 1.26.3

# Filter by severity
openorb search apache --severity high
```

### 6. REST API Server

```bash
# Start API server
openorb server --port 8080 --host 0.0.0.0

# With custom database path
openorb server --port 8080 --db /path/to/cve_database.db
```

**API Endpoints:**

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/health` | Health check |
| POST | `/api/v1/scans` | Create scan |
| GET | `/api/v1/scans` | List scans |
| GET | `/api/v1/scans/:id` | Get scan details |
| POST | `/api/v1/agents/register` | Register agent |
| POST | `/api/v1/agents/:id/inventory` | Submit inventory |
| GET | `/api/v1/agents` | List agents |
| GET | `/api/v1/cve/search?product=nginx` | Search CVEs |
| GET | `/api/v1/dashboard/summary` | Dashboard stats |

### 7. Endpoint Agent

Collects software inventory from endpoints and reports to a central server.

```bash
# Run once and exit
openorb-agent --server https://server:8080 --api-key KEY --once

# Run as daemon (scan every hour)
openorb-agent --server https://server:8080 --api-key KEY --interval 3600

# Debug mode
openorb-agent --server https://server:8080 --api-key KEY --debug
```

**Agent Help:**
```
$ openorb-agent --help

OpenOrb Endpoint Agent

Usage: openorb-agent [OPTIONS] --server <SERVER> --api-key <API_KEY>

Options:
  -s, --server <SERVER>      Server URL
  -a, --api-key <API_KEY>    API key
  -i, --interval <INTERVAL>  Scan interval in seconds [default: 3600]
      --once                 Run once (don't daemon)
  -d, --debug                Debug logging
  -h, --help                 Print help
```

**Supported Package Managers:**

| Platform | Sources |
|----------|---------|
| Linux | dpkg, rpm, snap, flatpak, pip, npm |
| macOS | system_profiler, homebrew, pip, npm |
| Windows | Registry (Uninstall keys), PowerShell Get-Service |

---

## Risk Scoring

OpenOrb calculates risk scores using:

```
Risk = CVSS * Confidence * EPSS * Asset Criticality * Multipliers
```

| Factor | Description |
|--------|-------------|
| **CVSS** | Base vulnerability severity (0-10) |
| **Confidence** | Match quality: exact (0.95), range (0.70), product-only (0.40) |
| **EPSS** | Exploit Prediction Scoring System probability (0-1) |
| **KEV** | 1.5x multiplier for CISA Known Exploited Vulnerabilities |
| **Exploit** | 1.3x multiplier when public exploits exist |
| **Criticality** | Asset criticality: critical (2.0), high (1.5), medium (1.0), low (0.5) |

## Architecture

```
openorb (9 MB)
├── discovery/        Port scanning + service detection
│   ├── scanner.rs       TCP connect (async, semaphore concurrency)
│   ├── syn_scanner.rs   SYN scan (pnet raw sockets)
│   ├── afpacket.rs      AF_PACKET + MMAP zero-copy (Linux, 1-5M pps)
│   ├── service.rs       Banner grabbing + SMB negotiation
│   └── models.rs        Host, ServiceInfo, ParsedVersion
├── vulndb/           CVE database + matching
│   ├── database.rs      SQLite store, NVD/EPSS/KEV sync, risk scoring
│   ├── scanner.rs       Service-to-CVE matching
│   ├── cpe.rs           CPE 2.3 parsing + version comparison
│   ├── active_tests.rs  YAML-based vulnerability probes
│   └── models.rs        Vulnerability, VulnMatch, Severity
├── api/              REST API (Axum)
├── agent/            Endpoint software inventory
└── plugins/          Protocol detection (Modbus ICS/SCADA)

openorb-agent (4 MB)
└── Endpoint agent binary (register, collect, report)
```

## License

MIT
