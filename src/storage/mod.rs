//! Scan Storage Module
//!
//! SQLite persistence for the 3-step scan pipeline (discover -> grab).
//! Stores scans, discovered open ports (assets), and service/banner
//! information. Contains no CVE/vulnerability data.

use anyhow::Result;
use rusqlite::{params, Connection};
use serde::{Deserialize, Serialize};
use std::path::Path;
use tracing::{debug, info};

/// Parsed version data for database storage
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParsedVersionData {
    /// Core upstream version (e.g., "8.9p1")
    pub core: String,
    /// Major version number
    pub major: Option<u32>,
    /// Minor version number
    pub minor: Option<u32>,
    /// Patch version number
    pub patch: Option<u32>,
    /// OS/Distro name (e.g., "Ubuntu", "Debian", "RHEL")
    pub distro: Option<String>,
    /// Distro-specific version/patch level
    pub distro_version: Option<String>,
    /// Whether this version likely has backported patches
    pub has_backport: bool,
}

/// Service record from database
#[derive(Debug, Clone, Serialize)]
pub struct ServiceRecord {
    pub id: i64,
    pub ip: String,
    pub port: u16,
    pub service: Option<String>,
    pub product: Option<String>,
    pub version: Option<String>,
    pub banner: Option<String>,
    pub cpe: Option<String>,
}

/// Scan status / summary record
#[derive(Debug, Clone, Serialize)]
pub struct ScanStatus {
    pub scan_id: String,
    pub target: String,
    pub step: i32,
    pub status: String,
    pub started_at: String,
    pub completed_at: Option<String>,
    pub total_hosts: i32,
    pub total_ports: i32,
    pub total_services: i32,
}

/// Scan pipeline storage manager
pub struct ScanStore {
    conn: Connection,
}

impl ScanStore {
    /// Create or open the scan database
    pub fn new<P: AsRef<Path>>(db_path: P) -> Result<Self> {
        let conn = Connection::open(db_path)?;
        let store = Self { conn };
        store.init_schema()?;
        Ok(store)
    }

    /// Create an in-memory scan database
    pub fn in_memory() -> Result<Self> {
        let conn = Connection::open_in_memory()?;
        let store = Self { conn };
        store.init_schema()?;
        Ok(store)
    }

    fn init_schema(&self) -> Result<()> {
        self.conn.execute_batch(
            r#"
            -- Scan history
            CREATE TABLE IF NOT EXISTS scans (
                scan_id TEXT PRIMARY KEY,
                target TEXT NOT NULL,
                step INTEGER DEFAULT 1,
                status TEXT DEFAULT 'running',
                started_at TEXT DEFAULT CURRENT_TIMESTAMP,
                completed_at TEXT,
                total_hosts INTEGER DEFAULT 0,
                total_ports INTEGER DEFAULT 0,
                total_services INTEGER DEFAULT 0
            );

            -- Discovered assets (Step 1: Port Scan)
            CREATE TABLE IF NOT EXISTS assets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip TEXT NOT NULL,
                hostname TEXT,
                port INTEGER NOT NULL,
                protocol TEXT DEFAULT 'tcp',
                state TEXT DEFAULT 'open',
                scan_id TEXT,
                discovered_at TEXT DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(ip, port, protocol, scan_id)
            );

            CREATE INDEX IF NOT EXISTS idx_assets_ip ON assets(ip);
            CREATE INDEX IF NOT EXISTS idx_assets_scan ON assets(scan_id);

            -- Service information (Step 2: Banner Grab)
            CREATE TABLE IF NOT EXISTS services (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                asset_id INTEGER NOT NULL,
                service TEXT,
                product TEXT,
                version TEXT,
                version_core TEXT,
                version_major INTEGER,
                version_minor INTEGER,
                version_patch INTEGER,
                distro TEXT,
                distro_version TEXT,
                has_backport INTEGER DEFAULT 0,
                banner TEXT,
                cpe TEXT,
                grabbed_at TEXT DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (asset_id) REFERENCES assets(id) ON DELETE CASCADE
            );

            CREATE INDEX IF NOT EXISTS idx_services_asset ON services(asset_id);
            CREATE INDEX IF NOT EXISTS idx_services_product ON services(product);
            "#,
        )?;
        Ok(())
    }

    /// Create a new scan record, returning its generated scan ID
    pub fn create_scan(&self, target: &str) -> Result<String> {
        let scan_id = uuid::Uuid::new_v4().to_string();
        self.conn.execute(
            "INSERT INTO scans (scan_id, target, step, status) VALUES (?, ?, 1, 'running')",
            params![scan_id, target],
        )?;
        info!("Created scan: {}", scan_id);
        Ok(scan_id)
    }

    /// Step 1: Save discovered open ports
    pub fn save_open_ports(
        &self,
        scan_id: &str,
        ip: &str,
        hostname: Option<&str>,
        ports: &[u16],
    ) -> Result<usize> {
        let mut count = 0;
        for port in ports {
            self.conn.execute(
                r#"
                INSERT OR REPLACE INTO assets (ip, hostname, port, state, scan_id, discovered_at)
                VALUES (?, ?, ?, 'open', ?, datetime('now'))
                "#,
                params![ip, hostname, *port as i64, scan_id],
            )?;
            count += 1;
        }

        // Update scan stats
        self.conn.execute(
            "UPDATE scans SET total_ports = total_ports + ?, step = 1 WHERE scan_id = ?",
            params![count as i64, scan_id],
        )?;

        debug!("Saved {} open ports for {}", count, ip);
        Ok(count)
    }

    /// Step 2: Save service/banner information
    pub fn save_service_info(
        &self,
        scan_id: &str,
        ip: &str,
        port: u16,
        service: &str,
        product: Option<&str>,
        version: Option<&str>,
        banner: Option<&str>,
    ) -> Result<i64> {
        self.save_service_info_parsed(scan_id, ip, port, service, product, version, banner, None)
    }

    /// Step 2: Save service/banner information with parsed version
    pub fn save_service_info_parsed(
        &self,
        scan_id: &str,
        ip: &str,
        port: u16,
        service: &str,
        product: Option<&str>,
        version: Option<&str>,
        banner: Option<&str>,
        parsed_version: Option<&ParsedVersionData>,
    ) -> Result<i64> {
        // Find the asset
        let asset_id: i64 = self.conn.query_row(
            "SELECT id FROM assets WHERE ip = ? AND port = ? AND scan_id = ?",
            params![ip, port as i64, scan_id],
            |row| row.get(0),
        )?;

        // Extract parsed version data
        let (version_core, version_major, version_minor, version_patch, distro, distro_version, has_backport) =
            if let Some(pv) = parsed_version {
                (
                    Some(pv.core.as_str()),
                    pv.major.map(|v| v as i64),
                    pv.minor.map(|v| v as i64),
                    pv.patch.map(|v| v as i64),
                    pv.distro.as_deref(),
                    pv.distro_version.as_deref(),
                    if pv.has_backport { 1i64 } else { 0i64 },
                )
            } else {
                (None, None, None, None, None, None, 0i64)
            };

        // Generate a CPE identifier using the core version (without distro suffix)
        let cpe = if let (Some(prod), Some(ver)) = (product, version_core.or(version)) {
            Some(format!(
                "cpe:2.3:a:*:{}:{}:*:*:*:*:*:*:*",
                prod.to_lowercase().replace(' ', "_"),
                ver.split_whitespace().next().unwrap_or(ver)
            ))
        } else {
            None
        };

        // Insert or update service
        self.conn.execute(
            r#"
            INSERT OR REPLACE INTO services
            (asset_id, service, product, version, version_core, version_major, version_minor,
             version_patch, distro, distro_version, has_backport, banner, cpe, grabbed_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))
            "#,
            params![
                asset_id, service, product, version, version_core,
                version_major, version_minor, version_patch,
                distro, distro_version, has_backport,
                banner, cpe
            ],
        )?;

        let service_id = self.conn.last_insert_rowid();

        // Update scan stats
        self.conn.execute(
            "UPDATE scans SET total_services = total_services + 1, step = 2 WHERE scan_id = ?",
            params![scan_id],
        )?;

        debug!(
            "Saved service {} for {}:{} (core version: {:?}, distro: {:?})",
            service, ip, port, version_core, distro
        );
        Ok(service_id)
    }

    /// Get assets for a scan (for Step 2 processing)
    pub fn get_scan_assets(&self, scan_id: &str) -> Result<Vec<(String, Option<String>, u16)>> {
        let mut stmt = self.conn.prepare(
            "SELECT ip, hostname, port FROM assets WHERE scan_id = ? ORDER BY ip, port",
        )?;

        let assets: Vec<(String, Option<String>, u16)> = stmt
            .query_map([scan_id], |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get::<_, i64>(2)? as u16,
                ))
            })?
            .filter_map(|r| r.ok())
            .collect();

        Ok(assets)
    }

    /// Get services for a scan
    pub fn get_scan_services(&self, scan_id: &str) -> Result<Vec<ServiceRecord>> {
        let mut stmt = self.conn.prepare(
            r#"
            SELECT s.id, a.ip, a.port, s.service, s.product, s.version, s.banner, s.cpe
            FROM services s
            JOIN assets a ON s.asset_id = a.id
            WHERE a.scan_id = ?
            ORDER BY a.ip, a.port
            "#,
        )?;

        let services: Vec<ServiceRecord> = stmt
            .query_map([scan_id], |row| {
                Ok(ServiceRecord {
                    id: row.get(0)?,
                    ip: row.get(1)?,
                    port: row.get::<_, i64>(2)? as u16,
                    service: row.get(3)?,
                    product: row.get(4)?,
                    version: row.get(5)?,
                    banner: row.get(6)?,
                    cpe: row.get(7)?,
                })
            })?
            .filter_map(|r| r.ok())
            .collect();

        Ok(services)
    }

    /// Get scan status
    pub fn get_scan_status(&self, scan_id: &str) -> Result<ScanStatus> {
        self.conn.query_row(
            r#"
            SELECT scan_id, target, step, status, started_at, completed_at,
                   total_hosts, total_ports, total_services
            FROM scans WHERE scan_id = ?
            "#,
            [scan_id],
            |row| {
                Ok(ScanStatus {
                    scan_id: row.get(0)?,
                    target: row.get(1)?,
                    step: row.get(2)?,
                    status: row.get(3)?,
                    started_at: row.get(4)?,
                    completed_at: row.get(5)?,
                    total_hosts: row.get(6)?,
                    total_ports: row.get(7)?,
                    total_services: row.get(8)?,
                })
            },
        )
        .map_err(|e| anyhow::anyhow!("Scan not found: {}", e))
    }

    /// List recent scans
    pub fn list_scans(&self, limit: usize) -> Result<Vec<ScanStatus>> {
        let mut stmt = self.conn.prepare(
            r#"
            SELECT scan_id, target, step, status, started_at, completed_at,
                   total_hosts, total_ports, total_services
            FROM scans
            ORDER BY started_at DESC
            LIMIT ?
            "#,
        )?;

        let scans: Vec<ScanStatus> = stmt
            .query_map([limit as i64], |row| {
                Ok(ScanStatus {
                    scan_id: row.get(0)?,
                    target: row.get(1)?,
                    step: row.get(2)?,
                    status: row.get(3)?,
                    started_at: row.get(4)?,
                    completed_at: row.get(5)?,
                    total_hosts: row.get(6)?,
                    total_ports: row.get(7)?,
                    total_services: row.get(8)?,
                })
            })?
            .filter_map(|r| r.ok())
            .collect();

        Ok(scans)
    }
}
