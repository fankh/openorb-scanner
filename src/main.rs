//! OpenOrb - Network Port & Service Scanner
//!
//! A high-performance network scanner written in Rust.

use anyhow::Result;
use clap::{Parser, Subcommand};
use tracing::Level;
use tracing_subscriber::FmtSubscriber;

use openorb::discovery::{NetworkDiscovery, PortScanner, ScanMethod, SynScanner};
use openorb::storage::{ParsedVersionData, ScanStore};

#[derive(Parser)]
#[command(name = "openorb")]
#[command(author, version, about = "OpenOrb - Network Port & Service Scanner", long_about = None)]
struct Cli {
    /// Enable debug logging
    #[arg(short, long)]
    debug: bool,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Scan target for open ports (and optionally services)
    Scan {
        /// Target IP, hostname, or CIDR network
        target: String,

        /// Ports to scan (e.g., 22,80,443 or 1-1000)
        #[arg(short, long)]
        ports: Option<String>,

        /// Scan top N common ports
        #[arg(long)]
        top_ports: Option<usize>,

        /// Scan all 65535 ports
        #[arg(long)]
        all_ports: bool,

        /// Scan mode: port or service (default: service)
        /// - port: Open port discovery only (fastest)
        /// - service: Port scan + banner grab (application name & version)
        #[arg(long, default_value = "service")]
        mode: String,

        /// Output file (JSON)
        #[arg(short, long)]
        output: Option<String>,

        /// Port scan timeout in milliseconds
        #[arg(long, default_value = "1000")]
        timeout: u64,

        /// Scan method: connect, syn, afpacket, or auto (default: auto)
        /// - connect: TCP connect scan (no root required, ~6 packets/port)
        /// - syn: SYN scan (requires root/admin, ~2 packets/port)
        /// - afpacket: AF_PACKET zero-copy scan (Linux, requires root)
        /// - auto: pick the fastest method available
        #[arg(short, long, default_value = "auto")]
        method: String,

        /// Packets per second rate limit (for SYN/AF_PACKET scan)
        #[arg(long, default_value = "1000")]
        rate: u32,

        /// Output as JSON (service detection with full metadata)
        #[arg(long)]
        json: bool,
    },

    /// Start API server
    Server {
        /// Bind host
        #[arg(long, default_value = "0.0.0.0")]
        host: String,

        /// Bind port
        #[arg(long, default_value = "8000")]
        port: u16,
    },

    /// Step 1: Fast port discovery (no banner grab)
    Discover {
        /// Target IP, hostname, or CIDR network
        target: String,

        /// Ports to scan (e.g., 22,80,443 or 1-1000)
        #[arg(short, long)]
        ports: Option<String>,

        /// Scan top N common ports
        #[arg(long, default_value = "100")]
        top_ports: usize,

        /// Scan method: connect, syn, afpacket, auto
        #[arg(short, long, default_value = "auto")]
        method: String,

        /// Database file path
        #[arg(long, default_value = "openorb.db")]
        db: String,
    },

    /// Step 2: Banner grab for discovered ports
    Grab {
        /// Scan ID from discover step
        scan_id: String,

        /// Banner grab timeout in milliseconds
        #[arg(long, default_value = "3000")]
        timeout: u64,

        /// Database file path
        #[arg(long, default_value = "openorb.db")]
        db: String,
    },

    /// List recent scans
    Scans {
        /// Number of scans to list
        #[arg(long, default_value = "10")]
        limit: usize,

        /// Database file path
        #[arg(long, default_value = "openorb.db")]
        db: String,
    },

    /// Show scan status and results
    Status {
        /// Scan ID
        scan_id: String,

        /// Database file path
        #[arg(long, default_value = "openorb.db")]
        db: String,

        /// Show detailed results
        #[arg(long)]
        detail: bool,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    // Setup logging
    let level = if cli.debug { Level::DEBUG } else { Level::INFO };
    let subscriber = FmtSubscriber::builder()
        .with_max_level(level)
        .with_target(false)
        .finish();
    tracing::subscriber::set_global_default(subscriber)?;

    match cli.command {
        Commands::Scan {
            target,
            ports,
            top_ports,
            all_ports,
            mode,
            output,
            timeout,
            method,
            rate,
            json,
        } => {
            run_scan(target, ports, top_ports, all_ports, &mode, output, timeout, &method, rate, json).await?;
        }

        Commands::Server { host, port } => {
            openorb::api::run_server(&host, port).await?;
        }

        Commands::Discover {
            target,
            ports,
            top_ports,
            method,
            db,
        } => {
            run_discover(&target, ports, top_ports, &method, &db).await?;
        }

        Commands::Grab { scan_id, timeout, db } => {
            run_grab(&scan_id, timeout, &db).await?;
        }

        Commands::Scans { limit, db } => {
            run_list_scans(limit, &db)?;
        }

        Commands::Status { scan_id, db, detail } => {
            run_status(&scan_id, &db, detail)?;
        }
    }

    Ok(())
}

async fn run_scan(
    target: String,
    ports: Option<String>,
    top_ports: Option<usize>,
    all_ports: bool,
    mode: &str,
    output: Option<String>,
    timeout: u64,
    method: &str,
    rate: u32,
    json_output: bool,
) -> Result<()> {
    // Parse scan mode
    let detect_services = mode != "port";

    // Parse scan method
    let scan_method: ScanMethod = method.parse().unwrap_or(ScanMethod::Auto);

    // Parse ports
    let port_list: Option<Vec<u16>> = if let Some(ref p) = ports {
        Some(parse_ports(p)?)
    } else if let Some(n) = top_ports {
        Some(PortScanner::TOP_PORTS.iter().take(n).copied().collect())
    } else if all_ports {
        Some((1..=65535).collect())
    } else {
        None
    };

    // Display scan info (only if not JSON output)
    if !json_output {
        println!("\n\x1b[1;34mScanning target:\x1b[0m {}", target);
        if let Some(ref p) = port_list {
            println!("\x1b[2mPorts: {} ports\x1b[0m", p.len());
        }

        // Show scan mode
        let mode_display = match mode {
            "port" => "\x1b[33mPort Discovery Only\x1b[0m",
            _ => "\x1b[36mPort + Service Detection\x1b[0m",
        };
        println!("\x1b[2mMode: {}\x1b[0m", mode_display);

        // Show scan method
        let method_display = match scan_method {
            ScanMethod::AfPacket => {
                if SynScanner::check_privileges() {
                    "\x1b[35mAF_PACKET + MMAP (zero-copy, masscan-level)\x1b[0m"
                } else {
                    println!("\x1b[33mWarning: AF_PACKET requires root/admin privileges\x1b[0m");
                    "\x1b[33mAF_PACKET (will fallback to connect)\x1b[0m"
                }
            }
            ScanMethod::Syn => {
                if SynScanner::check_privileges() {
                    "\x1b[32mSYN (stealth, ~2 packets/port)\x1b[0m"
                } else {
                    println!("\x1b[33mWarning: SYN scan requires root/admin privileges\x1b[0m");
                    "\x1b[33mSYN (will fallback to connect)\x1b[0m"
                }
            }
            ScanMethod::Connect => "\x1b[36mTCP Connect (~6 packets/port)\x1b[0m",
            ScanMethod::Auto => {
                if SynScanner::check_privileges() {
                    "\x1b[35mAuto → AF_PACKET/SYN (has privileges)\x1b[0m"
                } else {
                    "\x1b[36mAuto → Connect (no privileges)\x1b[0m"
                }
            }
        };
        println!("\x1b[2mMethod: {}\x1b[0m", method_display);
        if scan_method == ScanMethod::Syn || scan_method == ScanMethod::AfPacket {
            println!("\x1b[2mRate: {} packets/sec\x1b[0m", rate);
        }
    }

    // Run discovery
    let discovery = NetworkDiscovery::with_config(timeout, 3000, 500)
        .with_scan_method(scan_method);
    let result = discovery.discover(&target, port_list, detect_services).await?;

    // JSON output mode - output full result and exit
    if json_output {
        let json_report = if mode == "port" {
            // Port-only mode: minimal output
            serde_json::json!({
                "target": target,
                "scan_start": result.scan_start,
                "scan_end": result.scan_end,
                "scan_mode": "port",
                "scan_method": method,
                "total_hosts": result.total_hosts,
                "total_open_ports": result.total_open_ports,
                "hosts": result.hosts.iter().map(|host| {
                    serde_json::json!({
                        "ip": host.ip.to_string(),
                        "hostname": host.hostname,
                        "open_ports": host.open_ports,
                    })
                }).collect::<Vec<_>>()
            })
        } else {
            // Service mode: include service details
            serde_json::json!({
                "target": target,
                "scan_start": result.scan_start,
                "scan_end": result.scan_end,
                "scan_mode": mode,
                "scan_method": method,
                "total_hosts": result.total_hosts,
                "total_open_ports": result.total_open_ports,
                "hosts": result.hosts.iter().map(|host| {
                    serde_json::json!({
                        "ip": host.ip.to_string(),
                        "hostname": host.hostname,
                        "open_ports": host.open_ports,
                        "services": host.services.iter().map(|(port, svc)| {
                            serde_json::json!({
                                "port": port,
                                "service": svc.service,
                                "version": svc.version,
                                "product": svc.product,
                                "os": svc.os,
                                "banner": svc.banner,
                                "confidence": svc.confidence,
                                "method": svc.method,
                                "metadata": svc.metadata,
                                "parsed_version": svc.parsed_version,
                            })
                        }).collect::<Vec<_>>()
                    })
                }).collect::<Vec<_>>()
            })
        };

        println!("{}", serde_json::to_string_pretty(&json_report)?);
        return Ok(());
    }

    // Text output mode
    println!("\n\x1b[1;32mDiscovery Complete\x1b[0m");
    println!("  Hosts found: {}", result.total_hosts);
    println!("  Open ports: {}", result.total_open_ports);
    if let Some(duration) = result.duration() {
        println!("  Duration: {}s", duration.num_seconds());
    }

    // Display hosts
    if !result.hosts.is_empty() {
        println!("\n\x1b[1mDiscovered Hosts:\x1b[0m");
        println!("{:-<70}", "");

        for host in &result.hosts {
            println!(
                "\n\x1b[36m{}\x1b[0m ({})",
                host.ip,
                host.hostname.as_deref().unwrap_or("unknown")
            );

            if detect_services {
                // Service mode: show service name + version
                for (port, svc) in &host.services {
                    let version = svc.version.as_deref().unwrap_or("");
                    println!(
                        "  \x1b[32m{}/tcp\x1b[0m  {:15} {}",
                        port, svc.service, version
                    );
                }
            } else {
                // Port-only mode: show just port numbers
                for port in &host.open_ports {
                    println!("  \x1b[32m{}/tcp\x1b[0m  open", port);
                }
            }
        }
    }

    // Save output
    if let Some(output_path) = output {
        let report = serde_json::json!({
            "target": target,
            "scan_start": result.scan_start,
            "scan_end": result.scan_end,
            "hosts": result.hosts,
        });

        std::fs::write(&output_path, serde_json::to_string_pretty(&report)?)?;
        println!("\n\x1b[32mResults saved to {}\x1b[0m", output_path);
    }

    Ok(())
}

// ============================================================================
// Step 1: Discover - Fast port scanning
// ============================================================================

async fn run_discover(
    target: &str,
    ports: Option<String>,
    top_ports: usize,
    method: &str,
    db_path: &str,
) -> Result<()> {
    println!("\n\x1b[1;34m[Step 1] Port Discovery\x1b[0m");
    println!("  Target: {}", target);

    let scan_method: ScanMethod = method.parse().unwrap_or(ScanMethod::Auto);

    // Parse ports
    let port_list: Vec<u16> = if let Some(ref p) = ports {
        parse_ports(p)?
    } else {
        PortScanner::TOP_PORTS.iter().take(top_ports).copied().collect()
    };

    println!("  Ports: {} ports", port_list.len());

    // Show scan method
    let method_display = match scan_method {
        ScanMethod::AfPacket => {
            if SynScanner::check_privileges() {
                "\x1b[35mAF_PACKET (zero-copy)\x1b[0m"
            } else {
                "\x1b[36mConnect (no root)\x1b[0m"
            }
        }
        ScanMethod::Syn => {
            if SynScanner::check_privileges() {
                "\x1b[32mSYN (fast)\x1b[0m"
            } else {
                "\x1b[36mConnect (no root)\x1b[0m"
            }
        }
        ScanMethod::Connect => "\x1b[36mConnect\x1b[0m",
        ScanMethod::Auto => {
            if SynScanner::check_privileges() {
                "\x1b[35mAuto → AF_PACKET/SYN\x1b[0m"
            } else {
                "\x1b[36mAuto → Connect\x1b[0m"
            }
        }
    };
    println!("  Method: {}", method_display);

    // Create scan record
    let store = ScanStore::new(db_path)?;
    let scan_id = store.create_scan(target)?;
    println!("  Scan ID: \x1b[33m{}\x1b[0m", scan_id);

    // Run discovery (without banner grab)
    let discovery = NetworkDiscovery::with_config(1000, 3000, 500)
        .with_scan_method(scan_method);
    let result = discovery.discover(target, Some(port_list), false).await?;

    // Save results
    let mut total_ports = 0;
    for host in &result.hosts {
        store.save_open_ports(
            &scan_id,
            &host.ip.to_string(),
            host.hostname.as_deref(),
            &host.open_ports,
        )?;
        total_ports += host.open_ports.len();
    }

    println!("\n\x1b[32mDiscovery Complete!\x1b[0m");
    println!("  Hosts: {}", result.total_hosts);
    println!("  Open ports: {}", total_ports);
    println!("\n\x1b[1mNext step:\x1b[0m");
    println!("  openorb grab {}", scan_id);

    Ok(())
}

// ============================================================================
// Step 2: Grab - Banner grabbing
// ============================================================================

async fn run_grab(scan_id: &str, timeout: u64, db_path: &str) -> Result<()> {
    println!("\n\x1b[1;34m[Step 2] Banner Grabbing\x1b[0m");
    println!("  Scan ID: {}", scan_id);

    let store = ScanStore::new(db_path)?;

    // Get assets from step 1
    let assets = store.get_scan_assets(scan_id)?;
    if assets.is_empty() {
        anyhow::bail!("No assets found for scan ID: {}", scan_id);
    }

    println!("  Assets: {} ports to grab", assets.len());
    println!("  Timeout: {}ms", timeout);

    // Banner grab each asset
    let detector = openorb::discovery::ServiceDetector::with_timeout(timeout);
    let mut grabbed = 0;

    for (ip, _hostname, port) in &assets {
        let ip_addr: std::net::IpAddr = ip.parse()?;
        match detector.detect(ip_addr, *port).await {
            Ok(info) => {
                // Convert ParsedVersion to ParsedVersionData for database storage
                let parsed_data = info.parsed_version.as_ref().map(|pv| ParsedVersionData {
                    core: pv.core.clone(),
                    major: pv.major,
                    minor: pv.minor,
                    patch: pv.patch,
                    distro: pv.distro.clone(),
                    distro_version: pv.distro_version.clone(),
                    has_backport: pv.has_backport,
                });

                store.save_service_info_parsed(
                    scan_id,
                    ip,
                    *port,
                    &info.service,
                    info.product.as_deref(),
                    info.version.as_deref(),
                    info.banner.as_deref(),
                    parsed_data.as_ref(),
                )?;

                // Display version info with distro if detected
                let version_display = if let Some(ref pv) = info.parsed_version {
                    if let Some(ref distro) = pv.distro {
                        format!("{} ({})", pv.core, distro)
                    } else {
                        pv.core.clone()
                    }
                } else {
                    info.version.clone().unwrap_or_else(|| "-".to_string())
                };

                println!(
                    "  \x1b[32m{}:{}\x1b[0m {} {}",
                    ip, port, info.service, version_display
                );
                grabbed += 1;
            }
            Err(e) => {
                println!("  \x1b[31m{}:{}\x1b[0m error: {}", ip, port, e);
            }
        }
    }

    println!("\n\x1b[32mBanner Grab Complete!\x1b[0m");
    println!("  Services identified: {}", grabbed);

    Ok(())
}

// ============================================================================
// List scans
// ============================================================================

fn run_list_scans(limit: usize, db_path: &str) -> Result<()> {
    let store = ScanStore::new(db_path)?;
    let scans = store.list_scans(limit)?;

    println!("\n\x1b[1mRecent Scans:\x1b[0m");
    println!("{:-<82}", "");
    println!(
        "{:<36} {:<20} {:>5} {:>6} {:>6} {:>8}",
        "SCAN ID", "TARGET", "STEP", "PORTS", "SVCS", "STATUS"
    );
    println!("{:-<82}", "");

    for scan in scans {
        let status_color = match scan.status.as_str() {
            "completed" => "\x1b[32m",
            "running" => "\x1b[33m",
            _ => "\x1b[31m",
        };
        println!(
            "{:<36} {:<20} {:>5} {:>6} {:>6} {}{}",
            scan.scan_id,
            &scan.target[..scan.target.len().min(20)],
            scan.step,
            scan.total_ports,
            scan.total_services,
            status_color,
            scan.status,
        );
        print!("\x1b[0m");
    }

    Ok(())
}

// ============================================================================
// Show scan status
// ============================================================================

fn run_status(scan_id: &str, db_path: &str, detail: bool) -> Result<()> {
    let store = ScanStore::new(db_path)?;
    let status = store.get_scan_status(scan_id)?;

    println!("\n\x1b[1mScan Status:\x1b[0m");
    println!("  Scan ID: {}", status.scan_id);
    println!("  Target: {}", status.target);
    println!("  Step: {}/2", status.step);
    println!("  Status: {}", status.status);
    println!("  Started: {}", status.started_at);
    if let Some(completed) = &status.completed_at {
        println!("  Completed: {}", completed);
    }
    println!("\n\x1b[1mResults:\x1b[0m");
    println!("  Open ports: {}", status.total_ports);
    println!("  Services: {}", status.total_services);

    if detail {
        // Show services
        let services = store.get_scan_services(scan_id)?;
        if !services.is_empty() {
            println!("\n\x1b[1mDiscovered Services:\x1b[0m");
            println!("{:-<70}", "");
            for svc in &services {
                let product = svc.product.as_deref().unwrap_or("-");
                let version = svc.version.as_deref().unwrap_or("-");
                println!(
                    "  {}:{} - {} {} {}",
                    svc.ip,
                    svc.port,
                    svc.service.as_deref().unwrap_or("unknown"),
                    product,
                    version
                );
            }
        }
    }

    // Next step hint
    if status.step == 1 {
        println!("\n\x1b[1mNext:\x1b[0m openorb grab {}", scan_id);
    }

    Ok(())
}

fn parse_ports(port_str: &str) -> Result<Vec<u16>> {
    let mut ports = Vec::new();

    for part in port_str.split(',') {
        if part.contains('-') {
            let range: Vec<&str> = part.split('-').collect();
            if range.len() == 2 {
                let start: u16 = range[0].trim().parse()?;
                let end: u16 = range[1].trim().parse()?;
                ports.extend(start..=end);
            }
        } else {
            ports.push(part.trim().parse()?);
        }
    }

    ports.sort();
    ports.dedup();
    Ok(ports)
}
