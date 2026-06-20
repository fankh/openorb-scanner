//! REST API Server
//!
//! FastAPI-like REST API using Axum.

use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::info;
use uuid::Uuid;
use chrono::{DateTime, Utc};

use crate::discovery::NetworkDiscovery;

/// Application state
pub struct AppState {
    pub scans: RwLock<HashMap<String, ScanStatus>>,
}

// ============== Request/Response Models ==============

#[derive(Debug, Deserialize)]
pub struct ScanRequest {
    pub target: String,
    pub ports: Option<Vec<u16>>,
    pub detect_services: Option<bool>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ScanStatus {
    pub scan_id: String,
    pub status: String,
    pub target: String,
    pub progress: u8,
    pub created_at: DateTime<Utc>,
    pub completed_at: Option<DateTime<Utc>>,
    pub total_hosts: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub results: Option<ScanResults>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ScanResults {
    pub hosts: Vec<serde_json::Value>,
}

// ============== API Handlers ==============

async fn health() -> impl IntoResponse {
    Json(serde_json::json!({
        "status": "healthy",
        "timestamp": Utc::now().to_rfc3339()
    }))
}

async fn create_scan(
    State(state): State<Arc<AppState>>,
    Json(request): Json<ScanRequest>,
) -> impl IntoResponse {
    let scan_id = Uuid::new_v4().to_string();

    let scan_status = ScanStatus {
        scan_id: scan_id.clone(),
        status: "pending".to_string(),
        target: request.target.clone(),
        progress: 0,
        created_at: Utc::now(),
        completed_at: None,
        total_hosts: 0,
        results: None,
    };

    state.scans.write().await.insert(scan_id.clone(), scan_status.clone());

    // Spawn background scan task
    let state_clone = state.clone();
    let scan_id_clone = scan_id.clone();
    tokio::spawn(async move {
        run_scan(state_clone, scan_id_clone, request).await;
    });

    (StatusCode::CREATED, Json(scan_status))
}

async fn run_scan(state: Arc<AppState>, scan_id: String, request: ScanRequest) {
    // Update status to running
    {
        let mut scans = state.scans.write().await;
        if let Some(scan) = scans.get_mut(&scan_id) {
            scan.status = "running".to_string();
        }
    }

    let discovery = NetworkDiscovery::new();
    let detect_services = request.detect_services.unwrap_or(true);

    match discovery.discover(&request.target, request.ports, detect_services).await {
        Ok(result) => {
            let host_results: Vec<_> = result.hosts.iter().map(|h| {
                serde_json::json!({
                    "ip": h.ip.to_string(),
                    "hostname": h.hostname,
                    "open_ports": h.open_ports,
                    "services": h.services,
                })
            }).collect();

            let mut scans = state.scans.write().await;
            if let Some(scan) = scans.get_mut(&scan_id) {
                scan.status = "completed".to_string();
                scan.progress = 100;
                scan.completed_at = Some(Utc::now());
                scan.total_hosts = result.total_hosts;
                scan.results = Some(ScanResults {
                    hosts: host_results,
                });
            }
        }
        Err(e) => {
            let mut scans = state.scans.write().await;
            if let Some(scan) = scans.get_mut(&scan_id) {
                scan.status = "failed".to_string();
            }
            tracing::error!("Scan failed: {}", e);
        }
    }
}

async fn get_scan(
    State(state): State<Arc<AppState>>,
    Path(scan_id): Path<String>,
) -> impl IntoResponse {
    let scans = state.scans.read().await;
    match scans.get(&scan_id) {
        Some(scan) => (StatusCode::OK, Json(serde_json::to_value(scan).unwrap())),
        None => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error": "Scan not found"})),
        ),
    }
}

async fn list_scans(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let scans = state.scans.read().await;
    let list: Vec<_> = scans.values().cloned().collect();
    Json(list)
}

async fn dashboard_summary(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let scans = state.scans.read().await;
    let running_scans = scans.values().filter(|s| s.status == "running").count();

    Json(serde_json::json!({
        "scans": {
            "total": scans.len(),
            "running": running_scans,
        }
    }))
}

/// Create the API router
pub fn create_router(state: Arc<AppState>) -> Router {
    Router::new()
        // Health
        .route("/health", get(health))
        // Scans
        .route("/api/v1/scans", post(create_scan).get(list_scans))
        .route("/api/v1/scans/:scan_id", get(get_scan))
        // Dashboard
        .route("/api/v1/dashboard/summary", get(dashboard_summary))
        .with_state(state)
}

/// Start the API server
pub async fn run_server(host: &str, port: u16) -> anyhow::Result<()> {
    let state = Arc::new(AppState {
        scans: RwLock::new(HashMap::new()),
    });

    let app = create_router(state);

    let addr = format!("{}:{}", host, port);
    info!("Starting API server on {}", addr);

    let listener = tokio::net::TcpListener::bind(&addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}
