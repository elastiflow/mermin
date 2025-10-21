mod error;

use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};

use axum::{
    Router,
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Json},
    routing::get,
};
pub use error::HealthError;
use serde_json::json;
use tokio::net::TcpListener;
use tower_http::trace::TraceLayer;
use tracing::info;

use crate::runtime::conf::ApiConf;

#[derive(Clone)]
pub struct HealthState {
    pub ebpf_loaded: Arc<AtomicBool>,
    pub k8s_caches_synced: Arc<AtomicBool>,
    pub ready_to_process: Arc<AtomicBool>,
    pub startup_complete: Arc<AtomicBool>,
}

impl Default for HealthState {
    fn default() -> Self {
        Self {
            ebpf_loaded: Arc::new(AtomicBool::new(false)),
            k8s_caches_synced: Arc::new(AtomicBool::new(false)),
            ready_to_process: Arc::new(AtomicBool::new(false)),
            startup_complete: Arc::new(AtomicBool::new(false)),
        }
    }
}

pub async fn liveness_handler(State(state): State<HealthState>) -> impl IntoResponse {
    let ebpf_loaded = state.ebpf_loaded.load(Ordering::Relaxed);
    let status_code = if ebpf_loaded {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };

    let body = Json(json!({
        "status": if ebpf_loaded { "ok" } else { "unavailable" },
        "checks": {
            "ebpf_loaded": ebpf_loaded
        }
    }));

    (status_code, body)
}

pub async fn readiness_handler(State(state): State<HealthState>) -> impl IntoResponse {
    let ebpf_loaded = state.ebpf_loaded.load(Ordering::Relaxed);
    let k8s_caches_synced = state.k8s_caches_synced.load(Ordering::Relaxed);
    let ready_to_process = state.ready_to_process.load(Ordering::Relaxed);

    let is_ready = ebpf_loaded && k8s_caches_synced && ready_to_process;

    let status_code = if is_ready {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };

    let body = Json(json!({
        "status": if is_ready { "ok" } else { "unavailable" },
        "checks": {
            "ebpf_loaded": ebpf_loaded,
            "k8s_caches_synced": k8s_caches_synced,
            "ready_to_process": ready_to_process
        }
    }));

    (status_code, body)
}

pub async fn startup_handler(State(state): State<HealthState>) -> impl IntoResponse {
    let startup_complete = state.startup_complete.load(Ordering::Relaxed);
    let status_code = if startup_complete {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };

    let body = Json(json!({
        "status": if startup_complete { "ok" } else { "unavailable" },
        "checks": {
            "startup_complete": startup_complete
        }
    }));

    (status_code, body)
}

pub fn create_health_router(state: HealthState) -> Router {
    Router::new()
        .route("/livez", get(liveness_handler))
        .route("/readyz", get(readiness_handler))
        .route("/startup", get(startup_handler))
        .layer(TraceLayer::new_for_http())
        .with_state(state)
}

pub async fn start_api_server(state: HealthState, config: &ApiConf) -> Result<(), HealthError> {
    let app = create_health_router(state);

    let bind_address = format!("{}:{}", config.listen_address, config.port);
    let listener = TcpListener::bind(&bind_address)
        .await
        .map_err(|e| HealthError::bind_address(&bind_address, e))?;

    info!(
        event.name = "api.started",
        net.listen.address = %bind_address,
        "api server has started"
    );
    axum::serve(listener, app)
        .await
        .map_err(HealthError::ServeError)?;
    Ok(())
}
