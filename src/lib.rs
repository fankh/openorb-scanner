//! OpenOrb - Network Port & Service Scanner
//!
//! A high-performance network scanner written in Rust.
//!
//! ## Features
//!
//! - **Network Scanning**: Fast port discovery with SYN/Connect/AF_PACKET methods
//! - **Service Detection**: Banner grabbing and version parsing
//! - **REST API**: Axum-based API server
//!
//! ## Quick Start
//!
//! ```bash
//! # Scan a target for open ports
//! openorb scan 192.168.1.0/24 --mode port
//!
//! # Scan with service/version detection
//! openorb scan 192.168.1.1 --mode service
//! ```

pub mod discovery;
pub mod storage;
pub mod api;
pub mod plugins;

pub use discovery::{Host, ScanResult, NetworkDiscovery, PortScanner, ServiceDetector, ServiceInfo, ParsedVersion, SynScanner, ScanMethod};
pub use storage::{ScanStore, ServiceRecord, ScanStatus, ParsedVersionData};
