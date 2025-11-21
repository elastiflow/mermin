mod error;
mod filter;
mod health;
mod iface;
mod ip;
mod k8s;
mod metrics;
mod otlp;
mod packet;
mod runtime;
mod span;

use std::{
    sync::{Arc, atomic::Ordering},
    time::Duration,
};

use aya::{
    EbpfLoader,
    programs::{SchedClassifier, TcAttachType},
    util::KernelVersion,
};
use dashmap::DashMap;
use error::{MerminError, Result};
use tokio::{
    signal,
    sync::{broadcast, mpsc},
};
use tracing::{debug, error, info, trace, warn};

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
    metrics::server::start_metrics_server,
    otlp::{
        provider::{init_internal_tracing, init_provider},
        trace::{NoOpExporterAdapter, TraceExporterAdapter, TraceableExporter, TraceableRecord},
    },
    runtime::{
        capabilities, context::Context, shutdown::ShutdownManager, task_manager::TaskManager,
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
        .map_err(|_| MerminError::internal("OpenTelemetry provider shutdown timed out"))?;

    let shutdown_result = join_handle_result
        .map_err(|join_err| MerminError::internal(format!("shutdown task panicked: {join_err}")))?;

    shutdown_result.map_err(|e| {
        MerminError::internal(format!("OpenTelemetry provider failed to shut down: {e}"))
    })?;

    Ok(())
}

#[tokio::main]
async fn main() {
    if let Err(e) = run().await {
        display_error(&e);
        std::process::exit(1);
    }
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
/// CI check in place: .github/workflows/ci.yml (schema_version_check job)
const EBPF_MAP_SCHEMA_VERSION: u8 = 1;

async fn run() -> Result<()> {
    // TODO: runtime should be aware of all threads and tasks spawned by the eBPF program so that they can be gracefully shutdown and restarted.
    // TODO: listen for SIGUP `kill -HUP $(pidof mermin)` to reload the eBPF program and all configuration
    // TODO: listen for SIGTERM `kill -TERM $(pidof mermin)` to gracefully shutdown the eBPF program and all configuration.
    // TODO: do not reload global configuration found in CLI

    let runtime = Context::new()?;
    let Context { conf, .. } = runtime;

    // Initialize Prometheus metrics registry early, before any subsystems that might record metrics
    if let Err(e) = metrics::registry::init_registry() {
        error!(
            event.name = "metrics.registry_init_failed",
            error.message = %e,
            "failed to initialize metrics registry"
        );
    } else {
        info!(
            event.name = "metrics.registry_initialized",
            "prometheus metrics registry initialized"
        );
    }

    let (shutdown_tx, _) = broadcast::channel::<()>(1);
    let mut task_manager = TaskManager::new();
    let mut os_thread_handles = Vec::new();

    if conf.metrics.enabled {
        let metrics_conf = conf.metrics.clone();
        let mut shutdown_rx = shutdown_tx.subscribe();

        // Start metrics server on a dedicated runtime thread to prevent starvation
        // This ensures /metrics endpoint always responds even when main runtime is under heavy load
        let metrics_handle = std::thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .thread_name("mermin-metrics")
                .build()
                .expect("failed to create metrics server runtime");

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
        os_thread_handles.push(("metrics-server".to_string(), metrics_handle));
        info!(event.name = "metrics.started", "metrics server started");
    }

    let health_state = HealthState::default();

    if conf.api.enabled {
        let health_state_clone = health_state.clone();
        let api_conf = conf.api.clone();
        let mut shutdown_rx = shutdown_tx.subscribe();

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
                    result = start_api_server(health_state_clone, &api_conf) => {
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
        os_thread_handles.push(("api-server".to_string(), api_handle));
        info!(
            event.name = "api.started",
            "api server started, health checks will report not ready until initialization completes"
        );
    }

    // If a provider is already installed, install_default() returns Err, which we can safely ignore.
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

    capabilities::check_required_capabilities()?;

    let exporter: Arc<dyn TraceableExporter> = {
        init_internal_tracing(
            conf.log_level,
            conf.internal.traces.span_fmt,
            conf.log_color,
            conf.internal.traces.stdout.clone(),
            conf.internal.traces.otlp.clone(),
        )
        .await?;

        if conf.export.traces.stdout.is_some() || conf.export.traces.otlp.is_some() {
            let app_tracer_provider = init_provider(
                conf.export.traces.stdout.clone(),
                conf.export.traces.otlp.clone(),
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

    // This will include your eBPF object file as raw bytes at compile-time and load it at
    // runtime. This approach is recommended for most real-world use cases. If you would
    // like to specify the eBPF program at runtime rather than at compile-time, you can
    // reach for `Bpf::load_file` instead.

    // Load eBPF program with versioned map pinning for state persistence
    // Maps will be pinned to /sys/fs/bpf/mermin_v{version}/<map_name>
    // On restart, existing pinned maps will be automatically reused (state continuity)
    // Schema version in path allows breaking changes without manual cleanup
    let map_pin_path = format!("/sys/fs/bpf/mermin_v{EBPF_MAP_SCHEMA_VERSION}");
    if let Err(e) = std::fs::create_dir_all(&map_pin_path) {
        warn!(
            "failed to create eBPF map pin path '{map_pin_path}': {e} - ensure /sys/fs/bpf is mounted and writable - map pinning is required for state persistence across restarts",
        );
    }
    let mut ebpf =
        EbpfLoader::new()
            .map_pin_path(&map_pin_path)
            .load(aya::include_bytes_aligned!(concat!(
                env!("OUT_DIR"),
                "/mermin"
            )))?;

    debug!(
        event.name = "ebpf.loaded",
        map.pin_path = %map_pin_path,
        map.schema_version = EBPF_MAP_SCHEMA_VERSION,
        "eBPF program loaded, maps will persist with versioned pinning"
    );
    if let Err(e) = aya_log::EbpfLogger::init(&mut ebpf) {
        // This can happen if you remove all log statements from your eBPF program.
        warn!(
            event.name = "ebpf.logger_init_failed",
            error.message = %e,
            "failed to initialize eBPF logger"
        );
    }

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
                    "no ebpf maps found in loaded program, cannot test /sys/fs/bpf writability - this is unexpected and indicates a problem with the eBPF program."
                );
                false
            }
        }
    };
    if use_tcx {
        info!(
            event.name = "ebpf.bpf_fs_check_complete",
            bpf_fs_writable = bpf_fs_writable,
            "checked /sys/fs/bpf writability for TCX link pinning"
        );
    }

    // Extract eBPF maps - they're already pinned/reused automatically by EbpfLoader
    // Maps are pinned to /sys/fs/bpf/mermin_v{version}/<map_name> and reused across restarts
    let flow_stats_map = Arc::new(tokio::sync::Mutex::new(
        aya::maps::HashMap::try_from(
            ebpf.take_map("FLOW_STATS_MAP")
                .ok_or_else(|| MerminError::internal("FLOW_STATS_MAP not found in eBPF object"))?,
        )
        .map_err(|e| MerminError::internal(format!("failed to convert FLOW_STATS_MAP: {e}")))?,
    ));
    let flow_events_ringbuf = aya::maps::RingBuf::try_from(
        ebpf.take_map("FLOW_EVENTS")
            .ok_or_else(|| MerminError::internal("FLOW_EVENTS not found in eBPF object"))?,
    )
    .map_err(|e| {
        MerminError::internal(format!("failed to convert FLOW_EVENTS ring buffer: {e}"))
    })?;

    info!(
        event.name = "ebpf.maps_ready",
        schema_version = EBPF_MAP_SCHEMA_VERSION,
        "eBPF maps ready for flow producer"
    );

    let attach_method = if use_tcx { "TCX" } else { "netlink" };
    debug!(
        event.name = "ebpf.attach_method_determined",
        ebpf.attach.method = attach_method,
        ebpf.attach.priority = conf.discovery.instrument.tc_priority,
        ebpf.attach.tcx_order = %conf.discovery.instrument.tcx_order,
        system.kernel.version = %kernel_version,
        "determined TC attachment method and priority"
    );
    info!(
        event.name = "ebpf.ready_for_controller",
        "eBPF programs ready to move to controller thread"
    );

    let patterns = if conf.discovery.instrument.interfaces.is_empty() {
        info!(
            event.name = "config.interfaces_empty",
            "no interfaces configured, using default patterns"
        );
        runtime::conf::InstrumentOptions::default().interfaces
    } else {
        conf.discovery.instrument.interfaces.clone()
    };
    let iface_map = Arc::new(DashMap::new());
    let host_netns = Arc::new(std::fs::File::open("/proc/1/ns/net").map_err(|e| {
        MerminError::internal(format!(
            "failed to open host network namespace: {e} - requires hostPID: true in pod spec"
        ))
    })?);
    let (cmd_tx, cmd_rx) = crossbeam::channel::unbounded();
    let (netlink_tx, netlink_rx) = crossbeam::channel::unbounded();
    let (event_tx, event_rx) = crossbeam::channel::unbounded();
    let controller = IfaceController::new(
        patterns,
        Arc::clone(&iface_map),
        ebpf,
        use_tcx,
        bpf_fs_writable,
        conf.discovery.instrument.tc_priority,
        conf.discovery.instrument.tcx_order.clone(),
        Some(event_tx.clone()),
    )?;
    let (netlink_handle, netlink_shutdown_fd) =
        spawn_netlink_thread(Arc::clone(&host_netns), netlink_tx).map_err(|e| {
            MerminError::internal(format!("failed to spawn netlink monitoring thread: {e}"))
        })?;
    let controller_handle = spawn_controller_thread(
        Arc::clone(&host_netns),
        controller,
        cmd_rx,
        netlink_rx,
        Some(event_tx.clone()),
    )
    .map_err(|e| MerminError::internal(format!("failed to spawn controller thread: {e}")))?;

    wait_for_controller_ready(&event_rx, &cmd_tx)?;

    info!(
        event.name = "interface_controller.sending_initialize",
        "sending initialize command to controller thread"
    );
    cmd_tx
        .send(ControllerCommand::Initialize)
        .map_err(|e| MerminError::internal(format!("failed to send initialize command: {e}")))?;

    let _interface_count = wait_for_controller_initialized(&event_rx, &cmd_tx)?;
    health_state.ebpf_loaded.store(true, Ordering::Relaxed);

    let event_handler_handle = spawn_controller_event_handler(event_rx)
        .map_err(|e| MerminError::internal(format!("failed to spawn event handler: {e}")))?;
    os_thread_handles.push(("iface-event-handler".to_string(), event_handler_handle));

    info!(
        event.name = "ebpf.ready",
        "ebpf programs attached and ready to process network traffic"
    );

    let flow_span_capacity = (conf.pipeline.ring_buffer_capacity as f32
        * conf.pipeline.flow_span_channel_multiplier) as usize;
    let decorated_span_capacity = (conf.pipeline.ring_buffer_capacity as f32
        * conf.pipeline.decorated_span_channel_multiplier)
        as usize;

    let (flow_span_tx, mut flow_span_rx) = mpsc::channel(flow_span_capacity);
    metrics::userspace::set_channel_capacity("exporter", flow_span_capacity);
    let (k8s_decorated_flow_span_tx, mut k8s_decorated_flow_span_rx) =
        mpsc::channel(decorated_span_capacity);

    let flow_span_producer = FlowSpanProducer::new(
        conf.clone().span,
        conf.pipeline.ring_buffer_capacity,
        conf.pipeline.worker_count,
        Arc::clone(&iface_map),
        flow_stats_map,
        flow_events_ringbuf,
        flow_span_tx,
        &conf,
    )?;

    info!(
        event.name = "task.started",
        task.name = "k8s.decorator",
        task.description = "decorating flow attributes with kubernetes metadata",
        "userspace task started"
    );
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
        &conf,
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

    // K8s decorator runs on dedicated thread pool to prevent K8s API lookups from blocking main runtime
    let decorator_threads = conf.pipeline.k8s_decorator_threads;
    let mut decorator_shutdown_rx = shutdown_tx.subscribe();
    let decorator_handle = std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(decorator_threads)
            .thread_name("mermin-k8s-decorator")
            .enable_all()
            .build()
            .expect("failed to create k8s decorator runtime");

        rt.block_on(async move {
            info!(
                event.name = "task.started",
                task.name = "k8s.decorator",
                task.description = "decorating flow attributes with kubernetes metadata",
                decorator.threads = decorator_threads,
                "k8s decorator started on dedicated thread pool"
            );

            // Matching on the attributor early is a performance optimization to avoid having to check to see if the attributor is None per flow_span_rx receive.
            match k8s_attributor.as_ref().map(Decorator::new) {
                Some(decorator) => loop {
                    tokio::select! {
                        _ = decorator_shutdown_rx.recv() => {
                            info!(
                                event.name = "k8s.decorator.shutdown_signal_received",
                                "k8s decorator received shutdown signal"
                            );
                            break;
                        },
                        maybe_span = flow_span_rx.recv() => {
                            let Some(flow_span) = maybe_span else { break };

                            metrics::userspace::set_channel_size("decorator_input", flow_span_rx.len());

                            let timer = metrics::registry::PROCESSING_LATENCY
                                .with_label_values(&["k8s_decoration"])
                                .start_timer();
                            let (span, err) = decorator.decorate_or_fallback(flow_span).await;
                            timer.observe_duration();

                            match err {
                                Some(e) => debug!(
                                    event.name = "k8s.decorator.failed",
                                    flow.community_id = %span.attributes.flow_community_id,
                                    error.message = %e,
                                    "failed to decorate flow attributes with kubernetes metadata, sending undecorated span"
                                ),
                                None => trace!(
                                    event.name = "k8s.decorator.decorated",
                                    flow.community_id = %span.attributes.flow_community_id,
                                    "successfully decorated flow attributes with kubernetes metadata"
                                ),
                            }

                            if let Err(e) = k8s_decorated_flow_span_tx.send(span).await {
                                metrics::registry::FLOW_SPANS_DROPPED_EXPORT_FAILURE.inc();
                                error!(
                                    event.name = "channel.send_failed",
                                    channel.name = "k8s_decorated_flow_span",
                                    error.message = %e,
                                    "failed to send flow span to export channel"
                                );
                            }
                        }
                    }
                },
                None => {
                    warn!(
                        event.name = "k8s.decorator.unavailable",
                        reason = "kubernetes_client_unavailable",
                        "kubernetes decorator unavailable, all spans will be sent undecorated"
                    );

                    while let Some(flow_span) = flow_span_rx.recv().await {
                        trace!(event.name = "decorator.sending_to_exporter", flow.community_id = %flow_span.attributes.flow_community_id);

                        if let Err(e) = k8s_decorated_flow_span_tx.send(flow_span).await {
                            metrics::registry::FLOW_SPANS_DROPPED_EXPORT_FAILURE.inc();
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
            drop(k8s_decorated_flow_span_tx);
            flow_span_rx.close();
            info!(
                event.name = "task.exited",
                task.name = "k8s.decorator",
                "k8s decorator task exited"
            );
        });
    });
    let decorator_join_handle = decorator_handle;

    health_state
        .k8s_caches_synced
        .store(true, Ordering::Relaxed);

    let producer_shutdown_rx = shutdown_tx.subscribe();
    task_manager.spawn("span-producer", async move {
        flow_span_producer.run(producer_shutdown_rx).await;
        info!(
            event.name = "task.exited",
            task.name = "span.producer",
            "flow span producer task exited"
        );
    });
    health_state.ready_to_process.store(true, Ordering::Relaxed);

    task_manager.spawn("exporter", async move {
        while let Some(flow_span) = k8s_decorated_flow_span_rx.recv().await {
            let flow_span_clone = flow_span.clone();
            let traceable: TraceableRecord = Arc::new(flow_span);
            trace!(event.name = "flow.exporting", "exporting flow span");

            let community_id = flow_span_clone.attributes.flow_community_id;

            trace!(event.name = "exporter.received_from_decorator", flow.community_id = %community_id);

            if tokio::time::timeout(Duration::from_secs(10), exporter.export(traceable)).await.is_err() {
                warn!(event.name = "flow.export_timeout", "export call timed out, span may be lost");
            } else {
                trace!(event.name = "exporter.export_successful", flow.community_id = %community_id);
            }
        }

        trace!(
            event.name = "task.exited",
            task.name = "exporter",
            "exporter task exited because its channel was closed, flushing remaining spans via provider shutdown."
        );

        if let Err(e) = shutdown_exporter_gracefully(exporter, Duration::from_secs(5)).await {
            warn!(
                event.name = "exporter.otlp_shutdown_failed",
                error.message = %e,
                "OpenTelemetry provider failed to shut down cleanly during exit."
            );
        } else {
            debug!(
                event.name = "exporter.otlp_shutdown_success",
                "OpenTelemetry provider shut down cleanly."
            );
        }

        info!(
            event.name = "task.exited",
            task.name = "exporter",
            "exporter task exited"
        );
    });

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

    info!("waiting for ctrl+c");

    signal::ctrl_c().await?;

    info!(
        event.name = "application.shutdown_initiated",
        "received shutdown signal, starting graceful cleanup"
    );

    let shutdown_manager = ShutdownManager {
        shutdown_tx,
        cmd_tx,
        netlink_shutdown_fd,
        task_manager,
        decorator_join_handle,
        os_thread_handles,
        controller_handle,
        netlink_handle,
    };

    shutdown_manager.shutdown().await;

    info!(
        event.name = "application.cleanup_complete",
        "graceful cleanup completed"
    );

    info!("exiting");

    Ok(())
}

/// Display user-friendly error messages with helpful hints
fn display_error(error: &MerminError) {
    eprintln!("\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");

    match error {
        MerminError::Context(ctx_err) => {
            eprintln!("❌ Configuration Error");
            eprintln!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");
            eprintln!("{ctx_err}\n");

            let err_msg = ctx_err.to_string();
            if err_msg.contains("no config file provided") {
                eprintln!("💡 Solution:");
                eprintln!("   1. Create the config file at the specified path, or");
                eprintln!("   2. Run without --config flag to use defaults, or");
                eprintln!("   3. Unset MERMIN_CONFIG_PATH environment variable\n");
                eprintln!("📖 Example configs:");
                eprintln!("   - charts/mermin/config/examples/");
            } else if err_msg.contains("invalid file extension") {
                eprintln!("💡 Solution:");
                eprintln!("   Use a config file with .hcl extension");
            } else if err_msg.contains("is not a valid file") {
                eprintln!("💡 Solution:");
                eprintln!("   Provide a file path, not a directory");
            } else if err_msg.contains("configuration error") {
                eprintln!("💡 Tip:");
                eprintln!("   Check your config file syntax and values");
            }
        }

        MerminError::EbpfLoad(e) => {
            eprintln!("❌ eBPF Loading Error");
            eprintln!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");
            eprintln!("Failed to load eBPF program: {e}\n");
            eprintln!("💡 Common causes:");
            eprintln!("   - Insufficient privileges (needs root/CAP_BPF)");
            eprintln!("   - Kernel doesn't support eBPF");
            eprintln!("   - Incompatible kernel version");
            eprintln!("\n💡 Solution:");
            eprintln!("   Run with elevated privileges: sudo mermin");
            eprintln!("   Or in Docker with --privileged flag");
        }

        MerminError::EbpfProgram(e) => {
            eprintln!("❌ eBPF Program Error");
            eprintln!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");
            eprintln!("{e}\n");
            eprintln!("💡 Common causes:");
            eprintln!("   - Interface doesn't exist");
            eprintln!("   - Interface is down");
            eprintln!("   - Insufficient privileges");
            eprintln!("\n💡 Solution:");
            eprintln!("   - Check interface names: ip link show");
            eprintln!("   - Verify interfaces in config match host interfaces");
            eprintln!("   - Run with elevated privileges");
        }

        MerminError::Otlp(e) => {
            eprintln!("❌ OpenTelemetry Error");
            eprintln!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");
            eprintln!("{e}\n");
            eprintln!("💡 Common causes:");
            eprintln!("   - OTLP endpoint is unreachable");
            eprintln!("   - Invalid endpoint configuration");
            eprintln!("   - Network connectivity issues");
            eprintln!("\n💡 Solution:");
            eprintln!("   - Verify export.traces.otlp.endpoint in config");
            eprintln!("   - Check if the OTLP collector is running");
            eprintln!("   - Use export.traces.stdout for local debugging");
        }

        MerminError::Health(e) => {
            eprintln!("❌ Health/API Server Error");
            eprintln!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");
            eprintln!("{e}\n");
            eprintln!("💡 Common causes:");
            eprintln!("   - Port already in use");
            eprintln!("   - Invalid listen address");
            eprintln!("\n💡 Solution:");
            eprintln!("   - Check api.port and metrics.port in config");
            eprintln!("   - Set api.enabled=false to disable API server");
        }

        MerminError::Signal(e) => {
            eprintln!("❌ Signal Handling Error");
            eprintln!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");
            eprintln!("{e}\n");
        }

        _ => {
            eprintln!("❌ Error");
            eprintln!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");
            eprintln!("{error}\n");
        }
    }

    eprintln!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");
    eprintln!("For more information, run with: --log-level debug");
    eprintln!("Documentation: https://github.com/elastiflow/mermin\n");
}
