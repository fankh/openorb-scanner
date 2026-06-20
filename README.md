# OpenOrb — Open-Source Network Port & Service Scanner

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/Built%20with-Rust-orange.svg)](https://www.rust-lang.org/)
[![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20macOS%20%7C%20Windows-lightgrey.svg)]()
[![Release](https://img.shields.io/github/v/release/fankh/openorb-scanner)](https://github.com/fankh/openorb-scanner/releases/latest)

**OpenOrb** is an open-source, high-performance network scanner written in Rust. It combines fast port scanning with service/banner detection in a single tool — an open-source alternative to Nmap for network discovery.

**Key highlights:**
- Scan up to **1–5 million packets per second** using AF_PACKET + MMAP zero-copy (Linux)
- Detect services via **banner grabbing** (SSH, HTTP, FTP, SMB, MySQL, PostgreSQL, Redis, MongoDB, and more)
- Parse version strings into **structured data** (core version, distro, backport detection)
- **REST API** for integration with dashboards and CI/CD pipelines

---

## Why OpenOrb?

| Feature | OpenOrb | Nmap | Masscan |
|---------|---------|------|---------|
| Port scanning | TCP Connect, SYN, AF_PACKET | TCP, SYN, UDP | SYN only |
| Max throughput | 1–5M pps | ~100K pps | 10M+ pps |
| Banner grabbing | Built-in | NSE scripts | No |
| REST API | Built-in (Axum) | XML output | No |
| Open source | MIT | GPL | AGPL |
| Single binary | 9 MB | ~25 MB + scripts | 0.1 MB |
| Language | Rust | C/Lua | C |

---

## Quick Start

### Download

Pre-compiled binaries (Linux x86_64):

> **[Download latest release](https://github.com/fankh/openorb-scanner/releases/latest)**
>
> - `openorb` — network scanner

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

# Binary at target/release/openorb
```

### Scan Modes

OpenOrb supports 2 scan modes via `--mode`:

| Mode | Command | Description | Speed |
|------|---------|-------------|-------|
| **port** | `--mode port` | Open port discovery only | Fastest (~0.1s) |
| **service** | `--mode service` | Ports + application name & version (default) | ~8s (banner grab) |

```bash
# Port discovery only (fastest)
openorb scan 192.168.1.1 --top-ports 100 --mode port

# Port + service/version detection (default)
openorb scan 192.168.1.1 --top-ports 100 --mode service

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

OpenOrb discovers open ports and identifies running services through banner grabbing. It parses version strings into structured data, including OS/distro detection.

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
```

### JSON Output

Structured JSON output for integration with other tools and pipelines:

```bash
openorb scan 127.0.0.1 --top-ports 25 --method connect --json
```

```json
{
  "target": "127.0.0.1",
  "scan_mode": "service",
  "scan_method": "connect",
  "total_hosts": 1,
  "total_open_ports": 4,
  "hosts": [
    {
      "ip": "127.0.0.1",
      "hostname": "localhost",
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
              "content-type": "text/html"
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
  ]
}
```

### 2-Step Pipeline for Large Scans

For large-scale network sweeps, OpenOrb supports a 2-step pipeline with SQLite persistence between steps. This lets you scan thousands of hosts, then enrich results incrementally:

```bash
# Step 1: Fast port discovery
openorb discover 10.0.0.0/24 --top-ports 100 --method afpacket
# → Scan ID: 01fa9dc0-...

# Step 2: Banner grab discovered ports
openorb grab 01fa9dc0-...

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
```

### REST API Server

Built-in API server (Axum) for integrating OpenOrb with dashboards and CI/CD pipelines:

```bash
openorb server --port 8080 --host 0.0.0.0
```

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/health` | Health check |
| POST | `/api/v1/scans` | Create scan |
| GET | `/api/v1/scans` | List scans |
| GET | `/api/v1/scans/:id` | Get scan details |
| GET | `/api/v1/dashboard/summary` | Dashboard statistics |

---

## Architecture

```
openorb (single binary)
├── discovery/        Port scanning + service detection
│   ├── scanner.rs       TCP connect scan (async, tokio semaphore)
│   ├── syn_scanner.rs   SYN scan (pnet raw sockets, rate-limited)
│   ├── afpacket.rs      AF_PACKET + MMAP zero-copy ring buffer (1-5M pps)
│   ├── service.rs       Banner grabbing (HTTP, SSH, FTP, SMB, MySQL, PostgreSQL, Redis, MongoDB)
│   └── models.rs        Host, ServiceInfo, ParsedVersion
├── storage/          SQLite persistence (scans, ports, services)
├── api/              REST API (Axum framework)
└── plugins/          Experimental protocol-plugin scaffolding (Modbus; library-only, not yet exposed via CLI)
```

---

## CLI Reference

```
$ openorb --help
OpenOrb - Network Port & Service Scanner

Usage: openorb [OPTIONS] <COMMAND>

Commands:
  scan      Scan target for open ports (and optionally services)
  server    Start API server
  discover  Step 1: Fast port discovery (no banner grab)
  grab      Step 2: Banner grab for discovered ports
  scans     List recent scans
  status    Show scan status and results

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
      --mode <MODE>            port | service [default: service]
  -o, --output <FILE>          Output file (JSON)
      --timeout <MS>           Port scan timeout in ms [default: 1000]
  -m, --method <METHOD>        connect | syn | afpacket | auto [default: auto]
      --rate <PPS>             Packets per second limit [default: 1000]
      --json                   Output as JSON
```

---

## Use Cases

- **Asset discovery** — Map network services and software versions across infrastructure
- **Attack surface mapping** — Discover open ports and running services before an engagement
- **Network inventory** — Continuous port/service scanning with REST API integration
- **CI/CD security gates** — REST API integration for automated exposure checks

## License

[MIT](LICENSE) — Copyright 2025 Seekers Lab
