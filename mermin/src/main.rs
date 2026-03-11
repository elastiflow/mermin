mod error;
mod filter;
mod health;
mod iface;
mod ip;
mod k8s;
mod listening_ports;
mod metrics;
mod otlp;
mod packet;
mod runtime;
mod span;

use std::{
    collections::HashMap,
    sync::{Arc, atomic::Ordering},
    time::Duration,
};

use arc_swap::ArcSwap;
use aya::{
    Btf, EbpfLoader,
    programs::{FExit, Lsm, SchedClassifier, TcAttachType},
    util::KernelVersion,
};
use clap::Parser;
use error::{MerminError, Result};
use mermin_common::MapUnit;
#[cfg(unix)]
use tokio::signal::unix::{SignalKind, signal as unix_signal};
use tokio::sync::{mpsc, oneshot};
use tracing::{debug, error, info, warn};

use crate::{
    health::{HealthState, start_api_server},
    iface::{
        controller::IfaceController,
        threads::{
            spawn_controller_event_handler, spawn_controller_thread, spawn_netlink_thread,
            wait_for_controller_initialized, wait_for_controller_ready,
        },
        types::ControllerCommand,
    },
    k8s::{attributor::Attributor, decorator::Decorator},
    metrics::{
        cleanup::MetricCleanupTracker,
        ebpf::{EbpfMapName, init_ringbuf_metrics},
        k8s::K8sDecoratorStatus,
        processing::ProcessingStage,
        server::start_metrics_server,
        userspace::{ChannelName, ChannelSendStatus},
    },
    otlp::{
        provider::{init_bootstrap_logger, init_internal_tracing, init_provider},
        resource::detect_resource,
        trace::{NoOpExporterAdapter, TraceExporterAdapter, TraceableExporter, TraceableRecord},
    },
    runtime::{
        capabilities,
        cli::Cli,
        component::{error::ShutdownResult, handle::Handle, manager::ComponentManager},
        conf::Conf,
        pipeline::{EbpfRecoveryError, EbpfResources, Pipeline},
        reload::{ConfigWatcher, ReloadTrigger},
        shutdown::ShutdownConfig,
    },
    span::producer::FlowSpanProducer,
};

async fn shutdown_exporter_gracefully(
    exporter: Arc<dyn TraceableExporter>,
    timeout_duration: Duration,
) -> Result<()> {
    let shutdown_future = tokio::task::spawn_blocking(move || {
        exporter
            .as_any()
            .downcast_ref::<TraceExporterAdapter>()
            .map(|adapter| adapter.shutdown())
            .unwrap_or(Ok(()))
    });

    let join_handle_result = tokio::time::timeout(timeout_duration, shutdown_future)
        .await
        .map_err(|_| MerminError::internal("otel provider shutdown timed out"))?;

    let shutdown_result = join_handle_result
        .map_err(|join_err| MerminError::internal(format!("shutdown task panicked: {join_err}")))?;

    shutdown_result
        .map_err(|e| MerminError::internal(format!("otel provider failed to shut down: {e}")))?;

    Ok(())
}

fn main() {
    let cli = Cli::parse();

    if let Some(subcommand) = &cli.subcommand {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("failed to create mermin runtime");
        let result = rt.block_on(runtime::commands::execute(subcommand));
        match result {
            Ok(()) => std::process::exit(0),
            Err(e) => {
                display_error(&e);
                std::process::exit(1);
            }
        }
    }

    let mut builder = tokio::runtime::Builder::new_multi_thread();
    builder.thread_name("mermin-main").enable_all();
    if let Some(n) = cli.worker_threads {
        builder.worker_threads(n.max(1));
    }
    let rt = builder.build().expect("failed to create mermin runtime");

    if let Err(e) = rt.block_on(run(cli)) {
        display_error(&e);
        std::process::exit(1);
    }

    // opentelemetry-sdk 0.31 registers a global SdkTracerProvider whose
    // BatchSpanProcessor runs a background thread. That thread keeps the tokio
    // runtime alive after run() returns, causing the process to hang. Calling
    // process::exit(0) here is safe: all components have already been gracefully
    // shut down inside run(), so no data is lost.
    std::process::exit(0);
}

/// eBPF map schema version - MUST be incremented when FlowKey or FlowStats struct layout changes
/// Versioning prevents incompatible map formats from being reused across upgrades
/// Schema version is used in map pin path: /sys/fs/bpf/mermin_v{VERSION}/
///
/// IMPORTANT: Increment this when ANY of the following change:
/// - FlowKey struct layout (in mermin-ebpf/src/*.rs)
/// - FlowStats struct layout (in mermin-ebpf/src/*.rs)
/// - Map max_entries values
/// - Map key/value types
///
/// History:
/// - v1: Initial schema version (current)
///
/// CI check in place: .github/workflows/ci.yaml (schema_version_check job)
const EBPF_MAP_SCHEMA_VERSION: u8 = 1;

/// Timeout for individual export operations (in seconds).
/// If an export takes longer than this, it's considered timed out and the span may be lost.
const EXPORT_TIMEOUT_SECS: u64 = 10;

const LISTENING_PORTS_CAPACITY: u64 = 1024;

async fn run(cli: Cli) -> Result<()> {
    let reload_handles = init_bootstrap_logger(&cli);
    let conf = Conf::new(cli)?;

    let worker_threads = tokio::runtime::Handle::current().metrics().num_workers();
    info!(
        event.name = "runtime.threads",
        worker_threads, "runtime worker threads: {worker_threads}",
    );

    // Initialize Prometheus metrics registry early, before any subsystems that might record metrics
    // This also initializes the global debug_enabled flag
    let bucket_config = metrics::registry::HistogramBucketConfig::from(&conf.internal.metrics);
    if let Err(e) =
        metrics::registry::init_registry(conf.internal.metrics.debug_metrics_enabled, bucket_config)
    {
        error!(
            event.name = "metrics.registry_init_failed",
            error.message = %e,
            "failed to initialize metrics registry"
        );
    } else {
        info!(
            event.name = "metrics.registry_initialized",
            debug_metrics_enabled = conf.internal.metrics.debug_metrics_enabled,
            "prometheus metrics registry initialized"
        );
    }

    if conf.internal.metrics.debug_metrics_enabled {
        warn!(
            event.name = "metrics.debug_metrics_enabled",
            stale_metric_ttl = ?conf.internal.metrics.stale_metric_ttl,
            "DEBUG METRICS ENABLED: High-cardinality metrics with per-resource labels are active. \
             Memory usage will increase significantly. DO NOT USE IN PRODUCTION unless necessary for debugging."
        );
    }

    let cleanup_tracker = if conf.internal.metrics.debug_metrics_enabled {
        Some(MetricCleanupTracker::new(
            conf.internal.metrics.stale_metric_ttl,
            conf.internal.metrics.debug_metrics_enabled,
        ))
    } else {
        None
    };

    let mut components = ComponentManager::new();

    if let Some(tracker) = cleanup_tracker.clone() {
        let shutdown_rx = components.subscribe();
        let join = tokio::spawn(async move {
            tracker.run_cleanup_loop(shutdown_rx).await;
        });
        components.register(Handle::async_task("metrics-cleanup", join));
    }

    if conf.internal.metrics.enabled {
        let metrics_conf = conf.internal.metrics.clone();
        let mut shutdown_rx = components.subscribe();
        let (ready_tx, ready_rx) = oneshot::channel::<std::result::Result<(), MerminError>>();

        // Start metrics server on a dedicated runtime thread to prevent starvation
        // This ensures /metrics endpoint always responds even when main runtime is under heavy load
        let metrics_handle = std::thread::spawn(move || {
            let rt = match tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .thread_name("mermin-metrics")
                .build()
            {
                Ok(rt) => {
                    let _ = ready_tx.send(Ok(()));
                    rt
                }
                Err(e) => {
                    let _ = ready_tx.send(Err(MerminError::internal(format!("{e}"))));
                    return;
                }
            };

            rt.block_on(async move {
                tokio::select! {
                    result = start_metrics_server(metrics_conf) => {
                        if let Err(e) = result {
                            error!(
                                event.name = "metrics.server_error",
                                error.message = %e,
                                "metrics server encountered a fatal error"
                            );
                        }
                    },
                    _ = shutdown_rx.recv() => {
                        info!(event.name = "metrics.shutdown_signal_received", "metrics server received shutdown signal");
                    }
                }
                info!(event.name = "metrics.server_exited", "metrics server has shut down");
            });
        });

        // Wait for the thread to confirm its runtime started successfully
        match ready_rx.await {
            Ok(Ok(())) => {
                components.register(Handle::thread("metrics-server", metrics_handle));
                info!(event.name = "metrics.started", "metrics server started");
            }
            Ok(Err(e)) => {
                error!(
                    event.name = "metrics.runtime_failed",
                    error.message = %e,
                    "failed to create metrics server runtime; continuing without metrics"
                );
                // Thread returns immediately after sending on ready_tx; join to clean up.
                let _ = metrics_handle.join();
            }
            Err(_) => {
                error!(
                    event.name = "metrics.runtime_failed",
                    "metrics server thread exited before reporting readiness; continuing without metrics"
                );
                // Thread may have panicked before sending; join to clean up (returns quickly).
                let _ = metrics_handle.join();
            }
        }
    }

    let health_state = HealthState::default();

    if conf.internal.server.enabled {
        let health_state_clone = health_state.clone();
        let server_conf = conf.internal.server.clone();
        let mut shutdown_rx = components.subscribe();

        // Start API server on a dedicated runtime thread to prevent starvation
        // This ensures health checks always respond even when main runtime is under heavy load
        let api_handle = std::thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .thread_name("mermin-api")
                .build()
                .expect("failed to create api server runtime");

            rt.block_on(async move {
                tokio::select! {
                    result = start_api_server(health_state_clone, &server_conf) => {
                        if let Err(e) = result {
                            error!(
                                event.name = "api.internal_error",
                                error.message = %e,
                                "api server encountered a fatal error"
                            );
                        }
                    },
                    _ = shutdown_rx.recv() => {
                        info!(event.name = "api.shutdown_signal_received", "api server received shutdown signal");
                    }
                }
                debug!(event.name = "api.server_exited", "api server has shut down");
            });
        });
        components.register(Handle::thread("api-server", api_handle));
        info!(
            event.name = "api.started",
            "api server started, health checks will report not ready until initialization completes"
        );
    }

    // If a provider is already installed, install_default() returns Err, which we can safely ignore.
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

    capabilities::check_required_capabilities()?;

    let exporter: Arc<dyn TraceableExporter> = {
        let resource = detect_resource().await;

        init_internal_tracing(
            reload_handles,
            conf.log_level,
            conf.internal.traces.span_fmt,
            conf.log_color,
            conf.internal.traces.stdout.clone(),
            conf.internal.traces.otlp.clone(),
            resource.clone(),
        )
        .await?;

        conf.display_conf();

        if conf.export.traces.stdout.is_some() || conf.export.traces.otlp.is_some() {
            let app_tracer_provider = init_provider(
                conf.export.traces.stdout.clone(),
                conf.export.traces.otlp.clone(),
                resource,
            )
            .await?;
            info!(
                event.name = "task.started",
                task.name = "exporter",
                "initialized configured trace exporters"
            );
            Arc::new(TraceExporterAdapter::new(app_tracer_provider))
        } else {
            warn!(
                event.name = "exporter.misconfigured",
                exporter.type = "no-op",
                "no exporters configured, using no-op exporter"
            );
            Arc::new(NoOpExporterAdapter::default())
        }
    };

    // Bump the memlock rlimit. This is needed for older kernels that don't use the
    // new memcg based accounting, see https://lwn.net/Articles/837122/
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    // SAFETY: setrlimit with RLIMIT_MEMLOCK is safe to call with a valid rlimit struct.
    // We're passing a stack-allocated rlimit with valid values (RLIM_INFINITY).
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        warn!(
            event.name = "system.rlimit_failed",
            system.rlimit.type = "memlock",
            error.code = ret,
            "failed to remove limit on locked memory"
        );
    }

    // Load eBPF programs and extract maps once — these persist across pipeline restarts.
    let ebpf_resources = load_ebpf_resources(&conf)?;

    // Install shutdown signal handler. The oneshot sender is moved into a spawned task;
    // when a signal arrives the task sends the signal variant and the main loop exits.
    let (shutdown_tx, mut shutdown_rx) = oneshot::channel();
    tokio::spawn(async move {
        match wait_for_shutdown_signal().await {
            Ok(sig) => {
                let _ = shutdown_tx.send(sig);
            }
            Err(e) => {
                error!(
                    event.name = "shutdown.signal_handler_failed",
                    error.message = %e,
                    "failed to install shutdown signal handlers; shutdown via signal will not work"
                );
                // Dropping shutdown_tx causes shutdown_rx to return Err, which the
                // main loop maps to MerminError::internal and exits.
            }
        }
    });

    // Install SIGHUP no-op handler when auto_reload is disabled so a mistyped
    // `kill -HUP` doesn't kill the process with the OS default disposition.
    #[cfg(unix)]
    if !conf.auto_reload {
        tokio::spawn(async {
            let Ok(mut sighup) = unix_signal(SignalKind::hangup()) else {
                return;
            };
            loop {
                if sighup.recv().await.is_none() {
                    break;
                }
                warn!(
                    event.name = "reload.sighup_ignored",
                    "received SIGHUP but auto_reload is disabled; ignoring"
                );
            }
        });
    }

    // `conf` is intentionally the original startup config (CLI + env baked in).
    // `reload()` uses it as the base and layers the current file on top, so
    // subsequent reloads produce "original CLI/env + latest file".
    let original_conf = conf.clone();
    let mut current_conf = conf;

    let mut config_watcher = if current_conf.auto_reload {
        Some(
            ConfigWatcher::new(current_conf.config_path.as_deref()).map_err(|e| {
                MerminError::internal(format!("failed to create config watcher: {e}"))
            })?,
        )
    } else {
        None
    };

    // The outer loop runs once on normal startup, and again after each successful reload.
    let mut ebpf_resources = ebpf_resources;
    loop {
        let pipeline = start_pipeline(
            &current_conf,
            ebpf_resources,
            health_state.clone(),
            cleanup_tracker.clone(),
            Arc::clone(&exporter),
        )
        .await?;

        info!("waiting for shutdown signal");

        let shutdown_config = ShutdownConfig {
            timeout: current_conf.shutdown_timeout,
            preserve_flows: true,
            flow_preservation_timeout: Duration::from_secs(10),
        };

        enum LoopOutcome {
            Shutdown(ShutdownSignal),
            Reload(Box<Conf>),
        }

        let outcome = if let Some(ref mut watcher) = config_watcher {
            loop {
                tokio::select! {
                    result = &mut shutdown_rx => {
                        let sig = result.map_err(|_| {
                            MerminError::internal("shutdown listener channel closed unexpectedly")
                        })?;
                        break LoopOutcome::Shutdown(sig);
                    }
                    trigger = watcher.next() => {
                        let Some(trigger) = trigger else {
                            warn!(
                                event.name = "application.reload_channel_closed",
                                "reload channel closed unexpectedly, shutting down"
                            );
                            // Treat as shutdown — no valid signal available; use a synthetic one.
                            break LoopOutcome::Shutdown(ShutdownSignal::SigTerm);
                        };
                        match &trigger {
                            ReloadTrigger::Sighup => {
                                info!(
                                    event.name = "application.config_reload_triggered",
                                    trigger = "sighup",
                                    "config reload triggered"
                                );
                            }
                            ReloadTrigger::FileChanged(path) => {
                                info!(
                                    event.name = "application.config_reload_triggered",
                                    trigger = "file_changed",
                                    path = %path.display(),
                                    "config reload triggered"
                                );
                            }
                        }
                        match original_conf.reload() {
                            Ok(new_conf) => {
                                info!(
                                    event.name = "application.config_reloaded",
                                    "configuration reloaded successfully"
                                );
                                break LoopOutcome::Reload(Box::new(new_conf));
                            }
                            Err(e) => {
                                warn!(
                                    event.name = "application.config_reload_failed",
                                    error.message = %e,
                                    "failed to reload configuration, keeping current config"
                                );
                                // Keep running with current pipeline; wait for next trigger.
                            }
                        }
                    }
                }
            }
        } else {
            tokio::select! {
                result = &mut shutdown_rx => {
                    let sig = result.map_err(|_| {
                        MerminError::internal("shutdown listener channel closed unexpectedly")
                    })?;
                    LoopOutcome::Shutdown(sig)
                }
            }
        };

        match outcome {
            LoopOutcome::Shutdown(sig) => {
                info!(
                    event.name = "application.shutdown_signal_received",
                    signal.kind = %sig,
                    "received shutdown signal, starting graceful cleanup"
                );
                let (shutdown_result, _) = pipeline.preserve_and_shutdown(shutdown_config).await;
                log_shutdown_result(shutdown_result);
                break;
            }
            LoopOutcome::Reload(new_conf) => {
                info!(
                    event.name = "application.pipeline_restarting",
                    "restarting pipeline with new configuration"
                );
                let (shutdown_result, recovered) =
                    pipeline.preserve_and_shutdown(shutdown_config).await;
                log_shutdown_result(shutdown_result);
                ebpf_resources = recovered
                    .map_err(|e: EbpfRecoveryError| MerminError::internal(e.to_string()))?;
                current_conf = *new_conf;
            }
        }
    }

    Ok(())
}

/// Load the eBPF binary, attach programs, and extract all maps.
///
/// Called once at process start. The resulting [`EbpfResources`] is passed into
/// [`start_pipeline`] and returned by [`Pipeline::preserve_and_shutdown`] so it
/// can be reused across hot-reload restarts.
fn load_ebpf_resources(conf: &Conf) -> Result<EbpfResources> {
    // Load eBPF program with versioned map pinning for state persistence.
    // Maps will be pinned to /sys/fs/bpf/mermin_v{version}/<map_name>.
    // On restart, existing pinned maps will be automatically reused (state continuity).
    // Schema version in path allows breaking changes without manual cleanup.
    let map_pin_path = format!("/sys/fs/bpf/mermin_v{EBPF_MAP_SCHEMA_VERSION}");
    if let Err(e) = std::fs::create_dir_all(&map_pin_path) {
        warn!(
            "failed to create eBPF map pin path '{map_pin_path}': {e} - ensure /sys/fs/bpf is mounted and writable - map pinning is required for state persistence across restarts",
        );
    }
    let mut ebpf = EbpfLoader::new()
        .map_pin_path(&map_pin_path)
        .set_max_entries("FLOW_STATS", conf.pipeline.flow_capture.flow_stats_capacity)
        .set_max_entries(
            "FLOW_EVENTS",
            conf.pipeline.flow_capture.flow_events_capacity_bytes(),
        )
        .load(aya::include_bytes_aligned!(concat!(
            env!("OUT_DIR"),
            "/mermin"
        )))?;
    let programs = [TcAttachType::Ingress, TcAttachType::Egress];
    programs.iter().try_for_each(|attach_type| -> Result<()> {
        let program: &mut SchedClassifier = ebpf
            .program_mut(match attach_type {
                TcAttachType::Ingress => "mermin_flow_ingress",
                TcAttachType::Egress => "mermin_flow_egress",
                _ => unreachable!("only ingress and egress are used"),
            })
            .ok_or_else(|| {
                MerminError::internal(format!(
                    "ebpf program for {attach_type:?} not found in loaded object",
                ))
            })?
            .try_into()?;
        program.load()?;
        Ok(())
    })?;
    info!(
        event.name = "ebpf.programs_loaded",
        "tc programs loaded into kernel"
    );

    let btf = Btf::from_sys_fs().map_err(|e| {
        MerminError::internal(format!(
            "failed to load btf from /sys/kernel/btf/vmlinux: {e} - lsm/fentry programs require btf support"
        ))
    })?;

    if let Some(prog) = ebpf.program_mut("tcp_v4_connect_exit") {
        let fexit_prog: &mut FExit = prog.try_into().map_err(|e| {
            MerminError::internal(format!(
                "failed to convert tcp_v4_connect_exit to fexit: {e}"
            ))
        })?;
        fexit_prog.load("tcp_v4_connect", &btf).map_err(|e| {
            MerminError::internal(format!(
                "failed to load tcp_v4_connect_exit fexit program: {e}"
            ))
        })?;
        fexit_prog.attach().map_err(|e| {
            MerminError::internal(format!(
                "failed to attach tcp_v4_connect_exit fexit program: {e}"
            ))
        })?;
        info!(
            event.name = "ebpf.fexit_attached",
            program.name = "tcp_v4_connect_exit",
            "fexit program attached for outbound tcp process tracking"
        );
    } else {
        error!(
            event.name = "ebpf.fexit_not_found",
            program.name = "tcp_v4_connect_exit",
            "tcp_v4_connect_exit fexit program not found, skipping"
        );
    }

    if let Some(prog) = ebpf.program_mut("socket_accept") {
        let lsm_prog: &mut Lsm = prog.try_into().map_err(|e| {
            MerminError::internal(format!("failed to convert socket_accept to Lsm: {e}"))
        })?;
        lsm_prog.load("socket_accept", &btf).map_err(|e| {
            MerminError::internal(format!("failed to load socket_accept lsm program: {e}"))
        })?;
        lsm_prog.attach().map_err(|e| {
            MerminError::internal(format!("failed to attach socket_accept lsm program: {e}"))
        })?;
        info!(
            event.name = "ebpf.lsm_attached",
            program.name = "socket_accept",
            "lsm program attached for inbound tcp process tracking"
        );
    } else {
        error!(
            event.name = "ebpf.lsm_not_found",
            program.name = "socket_accept",
            "socket_accept lsm program not found, skipping"
        );
    }

    let kernel_version = KernelVersion::current().unwrap_or(KernelVersion::new(0, 0, 0));
    let use_tcx = kernel_version >= KernelVersion::new(6, 6, 0);
    let bpf_fs_writable = if !use_tcx {
        false
    } else {
        let test_pin_path = format!("/sys/fs/bpf/mermin_test_map_{}", std::process::id());

        match ebpf.maps().next() {
            Some((_, map)) => match map.pin(&test_pin_path) {
                Ok(_) => match std::fs::remove_file(&test_pin_path) {
                    Ok(_) => {
                        info!(
                            event.name = "ebpf.bpf_fs_writable",
                            "/sys/fs/bpf is writable, tcx link pinning enabled"
                        );
                        true
                    }
                    Err(e) => {
                        warn!(
                            event.name = "ebpf.bpf_test_cleanup_failed",
                            path = %test_pin_path,
                            error = %e,
                            "failed to cleanup test pin, but /sys/fs/bpf is confirmed writable"
                        );
                        true
                    }
                },
                Err(e) => {
                    info!(
                        event.name = "ebpf.bpf_fs_not_writable",
                        error = %e,
                        "/sys/fs/bpf is not writable, tcx link pinning disabled"
                    );
                    false
                }
            },
            None => {
                error!(
                    event.name = "ebpf.unexpected_error",
                    "no ebpf maps found in loaded program, cannot test /sys/fs/bpf writability - this is unexpected and indicates a problem with the ebpf program."
                );
                false
            }
        }
    };
    if use_tcx {
        crate::metrics::registry::BPF_FS_WRITABLE.set(if bpf_fs_writable { 1 } else { 0 });

        info!(
            event.name = "ebpf.bpf_fs_check_complete",
            bpf_fs_writable = bpf_fs_writable,
            "checked /sys/fs/bpf writability for tcx link pinning"
        );
    }

    let log_events_ringbuf = aya::maps::RingBuf::try_from(
        ebpf.take_map("LOG_EVENTS")
            .ok_or_else(|| MerminError::internal("LOG_EVENTS not found in eBPF object"))?,
    )
    .map_err(|e| MerminError::internal(format!("failed to convert LOG_EVENTS ring buffer: {e}")))?;
    let flow_stats_map = Arc::new(tokio::sync::Mutex::new(
        aya::maps::HashMap::try_from(
            ebpf.take_map("FLOW_STATS")
                .ok_or_else(|| MerminError::internal("FLOW_STATS not found in eBPF object"))?,
        )
        .map_err(|e| MerminError::internal(format!("failed to convert FLOW_STATS: {e}")))?,
    ));
    let flow_events_ringbuf = aya::maps::RingBuf::try_from(
        ebpf.take_map("FLOW_EVENTS")
            .ok_or_else(|| MerminError::internal("FLOW_EVENTS not found in eBPF object"))?,
    )
    .map_err(|e| {
        MerminError::internal(format!("failed to convert FLOW_EVENTS ring buffer: {e}"))
    })?;

    // Initialize ring buffer metrics before producer takes ownership (need fd access for mmap).
    if !init_ringbuf_metrics(&flow_events_ringbuf) {
        warn!(
            event.name = "ringbuf_metrics.init_failed",
            "failed to initialize ring buffer metrics - FLOW_EVENTS size will not be reported"
        );
    }

    let listening_ports_map = Arc::new(tokio::sync::Mutex::new(
        aya::maps::HashMap::try_from(
            ebpf.take_map("LISTENING_PORTS")
                .ok_or_else(|| MerminError::internal("LISTENING_PORTS not found in eBPF object"))?,
        )
        .map_err(|e| MerminError::internal(format!("failed to convert LISTENING_PORTS: {e}")))?,
    ));

    metrics::registry::EBPF_MAP_CAPACITY
        .with_label_values(&[EbpfMapName::FlowStats.as_str(), MapUnit::Entries.as_str()])
        .set(conf.pipeline.flow_capture.flow_stats_capacity as i64);
    metrics::registry::EBPF_MAP_CAPACITY
        .with_label_values(&[EbpfMapName::FlowEvents.as_str(), MapUnit::Bytes.as_str()])
        .set(conf.pipeline.flow_capture.flow_events_capacity_bytes() as i64);
    metrics::registry::EBPF_MAP_CAPACITY
        .with_label_values(&[
            EbpfMapName::ListeningPorts.as_str(),
            MapUnit::Entries.as_str(),
        ])
        .set(LISTENING_PORTS_CAPACITY as i64);

    info!(
        event.name = "ebpf.maps_ready",
        schema_version = EBPF_MAP_SCHEMA_VERSION,
        "ebpf maps ready for flow producer"
    );

    let iface_map = Arc::new(ArcSwap::new(Arc::new(HashMap::with_capacity(
        runtime::memory::initial_capacity::INTERFACE_MAP,
    ))));
    let host_netns = Arc::new(std::fs::File::open("/proc/1/ns/net").map_err(|e| {
        MerminError::internal(format!(
            "failed to open host network namespace: {e} - requires hostPID: true in pod spec"
        ))
    })?);

    Ok(EbpfResources {
        ebpf,
        flow_events_ringbuf,
        log_events_ringbuf,
        flow_stats_map,
        listening_ports_map,
        iface_map,
        host_netns,
    })
}

/// Wire all pipeline components and return a [`Pipeline`] ready to run.
///
/// All eBPF-touching resources are moved out of `ebpf_resources`. They are
/// returned when the pipeline shuts down via [`Pipeline::preserve_and_shutdown`].
async fn start_pipeline(
    conf: &Conf,
    ebpf_resources: EbpfResources,
    health_state: HealthState,
    cleanup_tracker: Option<MetricCleanupTracker>,
    exporter: Arc<dyn TraceableExporter>,
) -> Result<Pipeline> {
    let EbpfResources {
        ebpf,
        flow_events_ringbuf,
        log_events_ringbuf,
        flow_stats_map,
        listening_ports_map,
        iface_map,
        host_netns,
    } = ebpf_resources;

    let mut pipeline_components = ComponentManager::new();

    // Spawn eBPF log consumer with return channel for ring buffer recovery.
    let (log_events_return_tx, log_events_return) = oneshot::channel();
    let log_shutdown_rx = pipeline_components.subscribe();
    let log_join = tokio::spawn(async move {
        runtime::ebpf_log::run_log_consumer(
            log_events_ringbuf,
            log_shutdown_rx,
            log_events_return_tx,
        )
        .await;
    });
    pipeline_components.register(Handle::async_task("ebpf-log-consumer", log_join));

    let patterns = if conf.discovery.instrument.interfaces.is_empty() {
        info!(
            event.name = "config.interfaces_empty",
            "no interfaces configured, using default patterns"
        );
        runtime::conf::InstrumentOptions::default().interfaces
    } else {
        conf.discovery.instrument.interfaces.clone()
    };

    let kernel_version = KernelVersion::current().unwrap_or(KernelVersion::new(0, 0, 0));
    let use_tcx = kernel_version >= KernelVersion::new(6, 6, 0);
    let bpf_fs_writable = crate::metrics::registry::BPF_FS_WRITABLE.get() == 1;

    let (cmd_tx, cmd_rx) = crossbeam::channel::bounded(64);
    let (netlink_tx, netlink_rx) = crossbeam::channel::bounded(256);
    let (event_tx, event_rx) = crossbeam::channel::bounded(128);
    let controller = IfaceController::new(
        patterns,
        Arc::clone(&iface_map),
        ebpf,
        use_tcx,
        bpf_fs_writable,
        conf.discovery.instrument.tc_priority,
        conf.discovery.instrument.tcx_order.clone(),
        Some(event_tx.clone()),
        cleanup_tracker.clone(),
    )?;
    let (netlink_handle, netlink_shutdown_fd) =
        spawn_netlink_thread(Arc::clone(&host_netns), netlink_tx).map_err(|e| {
            MerminError::internal(format!("failed to spawn netlink monitoring thread: {e}"))
        })?;

    let (ebpf_return_tx, ebpf_return) = oneshot::channel();
    let controller_handle = spawn_controller_thread(
        Arc::clone(&host_netns),
        controller,
        cmd_rx,
        netlink_rx,
        Some(event_tx.clone()),
        ebpf_return_tx,
    )
    .map_err(|e| MerminError::internal(format!("failed to spawn controller thread: {e}")))?;

    wait_for_controller_ready(&event_rx, &cmd_tx)?;

    cmd_tx
        .send(ControllerCommand::Initialize)
        .map_err(|e| MerminError::internal(format!("failed to send initialize command: {e}")))?;

    wait_for_controller_initialized(&event_rx, &cmd_tx)?;
    health_state.ebpf_loaded.store(true, Ordering::Relaxed);

    let event_handler_handle = spawn_controller_event_handler(event_rx)
        .map_err(|e| MerminError::internal(format!("failed to spawn event handler: {e}")))?;
    pipeline_components.register(Handle::thread("iface-event-handler", event_handler_handle));

    info!(
        event.name = "ebpf.ready",
        "ebpf programs attached and ready to process network traffic"
    );

    conf.pipeline.validate_memory_usage();

    let flow_span_capacity = conf.pipeline.flow_producer.flow_span_queue_capacity;
    let decorated_span_capacity = conf.pipeline.k8s_decorator.decorated_span_queue_capacity;

    let (flow_span_tx, mut flow_span_rx) = mpsc::channel(flow_span_capacity);
    metrics::registry::CHANNEL_CAPACITY
        .with_label_values(&[ChannelName::ProducerOutput.as_str()])
        .set(flow_span_capacity as i64);
    metrics::registry::CHANNEL_ENTRIES
        .with_label_values(&[ChannelName::ProducerOutput.as_str()])
        .set(0);
    let (k8s_decorated_flow_span_tx, mut k8s_decorated_flow_span_rx) =
        mpsc::channel(decorated_span_capacity);
    metrics::registry::CHANNEL_ENTRIES
        .with_label_values(&[ChannelName::DecoratorOutput.as_str()])
        .set(0);
    metrics::registry::CHANNEL_CAPACITY
        .with_label_values(&[ChannelName::DecoratorOutput.as_str()])
        .set(decorated_span_capacity as i64);

    let listening_port_scanner =
        listening_ports::ListeningPortScanner::new(Arc::clone(&listening_ports_map));
    let scanned_ports = listening_port_scanner
        .scan_and_populate()
        .await
        .map_err(|e| MerminError::internal(format!("failed to scan listening ports: {e}")))?;

    // Set LISTENING_PORTS map metrics after initial scan.
    // Note: This only reflects the startup state; eBPF kprobes maintain the map
    // in real-time after this, but those changes are not reflected in these metrics.
    if metrics::registry::debug_enabled() {
        metrics::registry::EBPF_MAP_SIZE
            .with_label_values(&[
                EbpfMapName::ListeningPorts.as_str(),
                MapUnit::Entries.as_str(),
            ])
            .set(scanned_ports as i64);
    }

    info!(
        event.name = "listening_ports.scan_complete",
        total_ports = scanned_ports,
        "populated ebpf map with existing listening ports"
    );

    let flow_span_producer = FlowSpanProducer::new(
        conf.clone().span,
        conf.pipeline.flow_producer.worker_queue_capacity,
        conf.pipeline.flow_producer.workers,
        Arc::clone(&iface_map),
        Arc::clone(&flow_stats_map),
        flow_events_ringbuf,
        flow_span_tx,
        Arc::clone(&listening_ports_map),
        conf,
    )?;
    let flow_span_components = flow_span_producer.components();

    let owner_relations_opts = conf
        .discovery
        .informer
        .as_ref()
        .and_then(|informer| informer.k8s.as_ref())
        .and_then(|k8s_conf| k8s_conf.owner_relations.clone());
    let selector_relations_opts = conf
        .discovery
        .informer
        .as_ref()
        .and_then(|informer| informer.k8s.as_ref())
        .and_then(|k8s_conf| k8s_conf.selector_relations.clone());

    info!(
        event.name = "k8s.client_initializing",
        "initializing kubernetes client"
    );
    let k8s_attributor = match Attributor::new(
        health_state.clone(),
        owner_relations_opts,
        selector_relations_opts,
        conf,
        cleanup_tracker.clone(),
    )
    .await
    {
        Ok(attributor) => {
            info!(
                event.name = "k8s.client.init.success",
                "kubernetes client initialized successfully and all caches are synced"
            );
            Some(attributor)
        }
        Err(e) => {
            error!(
                event.name = "k8s.client.init.failed",
                error.message = %e,
                "failed to initialize kubernetes client; metadata lookup will be unavailable"
            );
            health_state
                .k8s_caches_synced
                .store(false, Ordering::Relaxed);
            None
        }
    };

    // The decorator does fast in-memory K8s cache lookups (hash map reads) and
    // forwards each span to the exporter channel. The exporter calls
    // exporter.export() which enqueues the span for async OTLP batch flush over
    // HTTP/gRPC. Both are cooperative async tasks that park at every .await point
    // and run on the main runtime via tokio::spawn. The bounded channels between
    // stages provide backpressure. No separate runtime or OS thread is needed.
    let source_extract_rules = conf.k8s_extract_metadata("source");
    let dest_extract_rules = conf.k8s_extract_metadata("destination");

    let mut decorator_shutdown_rx = pipeline_components.subscribe();
    let decorator_join = tokio::spawn(async move {
        info!(
            event.name = "task.started",
            task.name = "k8s.decorator",
            task.description = "decorating flow attributes with kubernetes metadata",
            "k8s decorator started"
        );

        // Matching on the attributor early is a performance optimization to avoid having to
        // check to see if the attributor is None per flow_span_rx receive.
        match k8s_attributor.as_ref() {
            Some(attributor) => {
                let decorator =
                    Decorator::new(attributor, source_extract_rules, dest_extract_rules);
                loop {
                    tokio::select! {
                        _ = decorator_shutdown_rx.recv() => {
                            break;
                        },
                        maybe_span = flow_span_rx.recv() => {
                            let Some(flow_span) = maybe_span else { break };

                            let channel_size = flow_span_rx.len();
                            metrics::registry::CHANNEL_ENTRIES
                                .with_label_values(&[ChannelName::ProducerOutput.as_str()])
                                .set(channel_size as i64);

                            let _timer = metrics::registry::processing_duration_seconds()
                                .with_label_values(&[ProcessingStage::K8sDecoratorOut.as_str()])
                                .start_timer();
                            let (span, err) = decorator.decorate_or_fallback(flow_span).await;

                            match err {
                                Some(e) => {
                                    metrics::k8s::inc_k8s_decorator_flow_spans(K8sDecoratorStatus::Error);
                                    debug!(
                                        event.name = "k8s.decorator.failed",
                                        flow.community_id = %span.attributes.flow_community_id,
                                        error.message = %e,
                                        "failed to decorate flow attributes with kubernetes metadata, sending undecorated span"
                                    );
                                }
                                None => {
                                    metrics::k8s::inc_k8s_decorator_flow_spans(K8sDecoratorStatus::Ok);
                                }
                            }

                            match k8s_decorated_flow_span_tx.send(span).await {
                                Ok(_) => {
                                    metrics::registry::CHANNEL_SENDS_TOTAL
                                        .with_label_values(&[ChannelName::DecoratorOutput.as_str(), ChannelSendStatus::Success.as_str()])
                                        .inc();
                                }
                                Err(e) => {
                                    metrics::registry::CHANNEL_SENDS_TOTAL
                                        .with_label_values(&[ChannelName::DecoratorOutput.as_str(), ChannelSendStatus::Error.as_str()])
                                        .inc();
                                    error!(
                                        event.name = "channel.send_failed",
                                        channel.name = "k8s_decorated_flow_span",
                                        error.message = %e,
                                        "failed to send flow span to export channel"
                                    );
                                }
                            }
                        }
                    }
                }
            }
            None => {
                warn!(
                    event.name = "k8s.decorator.unavailable",
                    reason = "kubernetes_client_unavailable",
                    "kubernetes decorator unavailable, all spans will be sent undecorated"
                );

                loop {
                    tokio::select! {
                        _ = decorator_shutdown_rx.recv() => {
                            break;
                        },
                        maybe_span = flow_span_rx.recv() => {
                            let Some(flow_span) = maybe_span else { break };
                            let channel_size = flow_span_rx.len();
                            metrics::registry::CHANNEL_ENTRIES
                                .with_label_values(&[ChannelName::ProducerOutput.as_str()])
                                .set(channel_size as i64);
                            match k8s_decorated_flow_span_tx.send(flow_span).await {
                                Ok(_) => {
                                    metrics::registry::CHANNEL_SENDS_TOTAL
                                        .with_label_values(&[ChannelName::DecoratorOutput.as_str(), ChannelSendStatus::Success.as_str()])
                                        .inc();
                                    metrics::k8s::inc_k8s_decorator_flow_spans(K8sDecoratorStatus::Undecorated);
                                }
                                Err(e) => {
                                    metrics::registry::CHANNEL_SENDS_TOTAL
                                        .with_label_values(&[ChannelName::DecoratorOutput.as_str(), ChannelSendStatus::Error.as_str()])
                                        .inc();
                                    metrics::k8s::inc_k8s_decorator_flow_spans(K8sDecoratorStatus::Dropped);
                                    error!(
                                        event.name = "channel.send_failed",
                                        channel.name = "k8s_decorated_flow_span",
                                        error.message = %e,
                                        "failed to send flow span to export channel"
                                    );
                                }
                            }
                        }
                    }
                }
            }
        }
        drop(k8s_decorated_flow_span_tx);
        flow_span_rx.close();
        info!(
            event.name = "task.exited",
            task.name = "k8s.decorator",
            "k8s decorator task exited"
        );
    });

    health_state
        .k8s_caches_synced
        .store(true, Ordering::Relaxed);

    // Spawn flow span producer with return channel for ring buffer recovery.
    let (flow_events_return_tx, flow_events_return) = oneshot::channel();
    let producer_shutdown_rx = pipeline_components.subscribe();
    let producer_join = tokio::spawn(async move {
        info!(
            event.name = "task.started",
            task.name = "span.producer",
            "flow span producer task started"
        );
        flow_span_producer
            .run(producer_shutdown_rx, flow_events_return_tx)
            .await;
        info!(
            event.name = "task.exited",
            task.name = "span.producer",
            "flow span producer task exited"
        );
    });
    // Defer registration until after the exporter is also spawned so we can
    // register them in the correct order (exporter first, producer second).
    // Reverse shutdown then joins producer first (stops new spans), closes the
    // channel, and the exporter drains cleanly before being joined.
    health_state.ready_to_process.store(true, Ordering::Relaxed);

    let exporter_join = tokio::spawn(async move {
        while let Some(flow_span) = k8s_decorated_flow_span_rx.recv().await {
            let queue_size = k8s_decorated_flow_span_rx.len();
            metrics::registry::CHANNEL_ENTRIES
                .with_label_values(&[ChannelName::DecoratorOutput.as_str()])
                .set(queue_size as i64);
            let traceable: TraceableRecord = Arc::new(flow_span);
            let export_start = std::time::Instant::now();
            let export_result = tokio::time::timeout(
                Duration::from_secs(EXPORT_TIMEOUT_SECS),
                exporter.export(traceable),
            )
            .await;
            let export_duration = export_start.elapsed();
            metrics::registry::processing_duration_seconds()
                .with_label_values(&[ProcessingStage::ExportOut.as_str()])
                .observe(export_duration.as_secs_f64());

            if export_result.is_err() {
                metrics::registry::EXPORT_TIMEOUTS_TOTAL.inc();
                warn!(
                    event.name = "flow.export_timeout",
                    "export call timed out, span may be lost"
                );
            }
        }

        match shutdown_exporter_gracefully(Arc::clone(&exporter), Duration::from_secs(5)).await {
            Ok(()) => {}
            Err(e) => {
                let event_name = match &e {
                    MerminError::Otlp(_) => "exporter.otlp_shutdown_error",
                    MerminError::Internal(msg) if msg.contains("timed out") => {
                        "exporter.otlp_shutdown_timeout"
                    }
                    MerminError::Internal(msg) if msg.contains("panicked") => {
                        "exporter.otlp_shutdown_panic"
                    }
                    _ => "exporter.otlp_shutdown_error",
                };
                warn!(event.name = event_name, error.message = %e, "opentelemetry provider shutdown failed");
            }
        }

        info!(
            event.name = "task.exited",
            task.name = "exporter",
            "exporter task exited"
        );
    });

    // Shutdown join order (reverse of registration): span-producer → k8s-decorator → exporter
    //   1. span-producer stops, closing the flow_span channel
    //   2. k8s-decorator sees its input channel close (or reacts to the shutdown
    //      signal directly), exits, and drops k8s_decorated_flow_span_tx
    //   3. exporter sees its input channel close, calls OTLP flush, and exits
    pipeline_components.register(Handle::async_task("exporter", exporter_join));
    pipeline_components.register(Handle::async_task("k8s-decorator", decorator_join));
    pipeline_components.register(Handle::async_task("span-producer", producer_join));

    // Register controller and netlink last so they are joined first (reverse order),
    // stopping the data source before the processing pipeline drains.
    pipeline_components.register(Handle::thread("controller", controller_handle));
    pipeline_components.register(Handle::thread_with_shutdown(
        "netlink",
        netlink_handle,
        netlink_shutdown_fd,
    ));

    info!(
        event.name = "application.startup_finished",
        "application startup sequence finished"
    );
    health_state.startup_complete.store(true, Ordering::Relaxed);

    let is_ready = health_state.ebpf_loaded.load(Ordering::Relaxed)
        && health_state.k8s_caches_synced.load(Ordering::Relaxed)
        && health_state.ready_to_process.load(Ordering::Relaxed);

    if is_ready {
        info!(
            event.name = "application.healthy",
            "all systems are ready, application is healthy"
        );
    } else {
        warn!(
            event.name = "application.unhealthy",
            "application is running but is not healthy"
        );
    }

    Ok(Pipeline {
        manager: pipeline_components,
        flow_span_components,
        cmd_tx,
        flow_events_return,
        log_events_return,
        ebpf_return,
        flow_stats_map,
        listening_ports_map,
        iface_map,
        host_netns,
    })
}

fn log_shutdown_result(result: ShutdownResult) {
    match result {
        ShutdownResult::Graceful {
            duration,
            components_completed,
        } => {
            info!(
                event.name = "application.cleanup_complete",
                duration_ms = duration.as_millis(),
                components_completed = components_completed,
                "graceful cleanup completed successfully"
            );
        }
        ShutdownResult::ForcedTermination {
            duration,
            components_completed,
            components_failed,
            ref failed_names,
        } => {
            warn!(
                event.name = "application.cleanup_complete_with_failures",
                duration_ms = duration.as_millis(),
                components_completed = components_completed,
                components_failed = components_failed,
                failed = ?failed_names,
                "cleanup completed but some components failed or timed out"
            );
        }
    }
}

#[derive(Debug, Clone, Copy)]
enum ShutdownSignal {
    CtrlC,
    SigTerm,
}

impl std::fmt::Display for ShutdownSignal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ShutdownSignal::CtrlC => write!(f, "CTRL_C"),
            ShutdownSignal::SigTerm => write!(f, "SIGTERM"),
        }
    }
}

async fn wait_for_shutdown_signal() -> Result<ShutdownSignal> {
    #[cfg(unix)]
    {
        let mut sigint = unix_signal(SignalKind::interrupt())
            .map_err(|e| MerminError::internal(format!("failed to install SIGINT handler: {e}")))?;
        let mut sigterm = unix_signal(SignalKind::terminate()).map_err(|e| {
            MerminError::internal(format!("failed to install SIGTERM handler: {e}"))
        })?;
        tokio::select! {
            _ = sigint.recv() => Ok(ShutdownSignal::CtrlC),
            _ = sigterm.recv() => Ok(ShutdownSignal::SigTerm),
        }
    }
    #[cfg(not(unix))]
    {
        signal::ctrl_c().await?;
        Ok(ShutdownSignal::CtrlC)
    }
}

/// Display user-friendly error messages with helpful hints
fn display_error(error: &MerminError) {
    eprintln!("\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");

    match error {
        MerminError::Conf(conf_err) => {
            eprintln!("Configuration Error");
            eprintln!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");
            eprintln!("{conf_err}\n");

            let err_msg = conf_err.to_string();
            if err_msg.contains("no config file provided") {
                eprintln!("Solution:");
                eprintln!("   1. Create the config file at the specified path, or");
                eprintln!("   2. Run without --config flag to use defaults, or");
                eprintln!("   3. Unset MERMIN_CONFIG_PATH environment variable\n");
                eprintln!("Example configs:");
                eprintln!("   - charts/mermin/config/examples/");
            } else if err_msg.contains("invalid file extension") {
                eprintln!("Solution:");
                eprintln!("   Use a config file with .hcl extension");
            } else if err_msg.contains("is not a valid file") {
                eprintln!("Solution:");
                eprintln!("   Provide a file path, not a directory");
            } else if err_msg.contains("configuration error") {
                eprintln!("Tip:");
                eprintln!("   Check your config file syntax and values");
            }
        }

        MerminError::EbpfLoad(e) => {
            eprintln!("eBPF Loading Error");
            eprintln!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");
            eprintln!("Failed to load eBPF program: {e}\n");
            eprintln!("Common causes:");
            eprintln!("   - Insufficient privileges (needs root/CAP_BPF)");
            eprintln!("   - Kernel doesn't support eBPF");
            eprintln!("   - Incompatible kernel version\n");
            eprintln!("Solution:");
            eprintln!("   Run with elevated privileges: sudo mermin");
            eprintln!("   Or in Docker with --privileged flag");
        }

        MerminError::EbpfProgram(e) => {
            eprintln!("eBPF Program Error");
            eprintln!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");
            eprintln!("{e}\n");
            eprintln!("Common causes:");
            eprintln!("   - Interface doesn't exist");
            eprintln!("   - Interface is down");
            eprintln!("   - Insufficient privileges\n");
            eprintln!("Solution:");
            eprintln!("   - Check interface names: ip link show");
            eprintln!("   - Verify interfaces in config match host interfaces");
            eprintln!("   - Run with elevated privileges");
        }

        MerminError::Otlp(e) => {
            eprintln!("OpenTelemetry Error");
            eprintln!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");
            eprintln!("{e}\n");
            eprintln!("Common causes:");
            eprintln!("   - OTLP endpoint is unreachable");
            eprintln!("   - Invalid endpoint configuration");
            eprintln!("   - Network connectivity issues\n");
            eprintln!("Solution:");
            eprintln!("   - Verify export.traces.otlp.endpoint in config");
            eprintln!("   - Check if the OTLP collector is running");
            eprintln!("   - Use export.traces.stdout for local debugging");
        }

        MerminError::Health(e) => {
            eprintln!("Health/HTTP Server Error");
            eprintln!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");
            eprintln!("{e}\n");
            eprintln!("Common causes:");
            eprintln!("   - Port already in use");
            eprintln!("   - Invalid listen address\n");
            eprintln!("Solution:");
            eprintln!("   - Check internal.server.port and internal.metrics.port in config");
            eprintln!("   - Set internal.server.enabled=false to disable HTTP server");
        }

        MerminError::Signal(e) => {
            eprintln!("Signal Handling Error");
            eprintln!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");
            eprintln!("{e}\n");
        }

        _ => {
            eprintln!("Error");
            eprintln!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");
            eprintln!("{error}\n");
        }
    }

    eprintln!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");
    eprintln!("For more information, run with: --log-level debug");
    eprintln!("Documentation: https://github.com/elastiflow/mermin\n");
}
