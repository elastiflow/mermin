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
    os::fd::AsRawFd,
    sync::{Arc, atomic::Ordering},
};

use aya::{
    programs::{SchedClassifier, TcAttachType},
    util::KernelVersion,
};
use dashmap::DashMap;
use error::{MerminError, Result};
use tokio::{signal, sync::mpsc};
use tracing::{debug, error, info, trace, warn};

use crate::{
    health::{HealthState, start_api_server},
    iface::{
        controller::IfaceController,
        threads::{spawn_controller_thread, spawn_netlink_thread},
        types::{ControllerCommand, ControllerEvent},
    },
    k8s::{attributor::Attributor, decorator::Decorator},
    metrics::server::start_metrics_server,
    otlp::{
        provider::{init_internal_tracing, init_provider},
        trace::{NoOpExporterAdapter, TraceExporterAdapter, TraceableExporter, TraceableRecord},
    },
    runtime::{capabilities, context::Context},
    span::producer::FlowSpanProducer,
};

const CONTROLLER_INIT_TIMEOUT_SECS: u64 = 60;

#[tokio::main]
async fn main() {
    if let Err(e) = run().await {
        display_error(&e);
        std::process::exit(1);
    }
}

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

    if conf.metrics.enabled {
        let metrics_conf = conf.metrics.clone();

        tokio::spawn(async move {
            if let Err(e) = start_metrics_server(metrics_conf).await {
                error!(
                    event.name = "metrics.server_error",
                    error.message = %e,
                    "metrics server encountered a fatal error"
                );
            }
        });
    }

    let health_state = HealthState::default();

    // Start API server immediately so Kubernetes can start health checks
    // Health checks will return "not ready" based on health_state flags until initialization completes
    if conf.api.enabled {
        let health_state_clone = health_state.clone();
        let api_conf = conf.api.clone();

        tokio::spawn(async move {
            if let Err(e) = start_api_server(health_state_clone, &api_conf).await {
                error!(
                    event.name = "api.internal_error",
                    error.message = %e,
                    "api server encountered a fatal error"
                );
            }
        });

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
    let mut ebpf = aya::Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/mermin"
    )))?;
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

    // Extract eBPF maps BEFORE moving Ebpf object to controller thread
    // Maps will be owned by FlowSpanProducer (main thread), programs by controller (host namespace thread)
    let flow_stats_map = ebpf
        .take_map("FLOW_STATS_MAP")
        .ok_or_else(|| MerminError::internal("FLOW_STATS_MAP not found in eBPF object"))?;
    let flow_events_map = ebpf
        .take_map("FLOW_EVENTS")
        .ok_or_else(|| MerminError::internal("FLOW_EVENTS not found in eBPF object"))?;

    let flow_stats_map = Arc::new(tokio::sync::Mutex::new(
        aya::maps::HashMap::try_from(flow_stats_map)
            .map_err(|e| MerminError::internal(format!("failed to convert FLOW_STATS_MAP: {e}")))?,
    ));
    let flow_events_ringbuf = aya::maps::RingBuf::try_from(flow_events_map).map_err(|e| {
        MerminError::internal(format!("failed to convert FLOW_EVENTS ring buffer: {e}"))
    })?;

    info!(
        event.name = "ebpf.maps_extracted",
        "eBPF maps extracted successfully for flow producer"
    );

    let kernel_version = KernelVersion::current().unwrap_or(KernelVersion::new(0, 0, 0));
    let use_tcx = kernel_version >= KernelVersion::new(6, 6, 0);
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
    let host_netns = std::fs::File::open("/proc/1/ns/net").map_err(|e| {
        MerminError::internal(format!(
            "failed to open host network namespace: {e} - requires hostPID: true in pod spec"
        ))
    })?;
    let host_netns_fd = host_netns.as_raw_fd();
    let netlink_fd = unsafe { libc::dup(host_netns_fd) };
    if netlink_fd < 0 {
        return Err(MerminError::internal(
            "failed to duplicate netns fd for netlink thread",
        ));
    }
    let controller_fd = unsafe { libc::dup(host_netns_fd) };
    if controller_fd < 0 {
        return Err(MerminError::internal(
            "failed to duplicate netns fd for controller thread",
        ));
    }
    let (cmd_tx, cmd_rx) = crossbeam::channel::unbounded();
    let (netlink_tx, netlink_rx) = crossbeam::channel::unbounded();
    let (event_tx, event_rx) = crossbeam::channel::unbounded();
    let controller = IfaceController::new(
        patterns,
        Arc::clone(&iface_map),
        ebpf,
        use_tcx,
        conf.discovery.instrument.tc_priority,
        conf.discovery.instrument.tcx_order.clone(),
        Some(event_tx.clone()),
    )?;
    let _netlink_handle = spawn_netlink_thread(netlink_fd, netlink_tx).map_err(|e| {
        MerminError::internal(format!("failed to spawn netlink monitoring thread: {e}"))
    })?;
    let _controller_handle = spawn_controller_thread(
        controller_fd,
        controller,
        cmd_rx,
        netlink_rx,
        Some(event_tx),
    )
    .map_err(|e| MerminError::internal(format!("failed to spawn controller thread: {e}")))?;

    info!(
        event.name = "interface_controller.initializing",
        "sending initialize command to controller thread"
    );

    cmd_tx
        .send(ControllerCommand::Initialize)
        .map_err(|e| MerminError::internal(format!("failed to send initialize command: {e}")))?;

    match event_rx.recv_timeout(std::time::Duration::from_secs(CONTROLLER_INIT_TIMEOUT_SECS)) {
        Ok(ControllerEvent::Initialized { interface_count }) => {
            info!(
                event.name = "interface_controller.initialized",
                interface_count = interface_count,
                "controller initialized successfully"
            );
            health_state.ebpf_loaded.store(true, Ordering::Relaxed);
        }
        Ok(other) => {
            return Err(MerminError::internal(format!(
                "unexpected controller event during initialization: {other:?}",
            )));
        }
        Err(e) => {
            warn!(
                event.name = "interface_controller.init_timeout",
                "initialization timed out, sending shutdown to controller thread"
            );
            let _ = cmd_tx.send(ControllerCommand::Shutdown);
            return Err(MerminError::internal(format!(
                "controller initialization timeout after {CONTROLLER_INIT_TIMEOUT_SECS}s: {e}"
            )));
        }
    }

    // Spawn background task to handle controller events for observability
    tokio::spawn(async move {
        while let Ok(event) = event_rx.recv() {
            match event {
                ControllerEvent::InterfaceAttached { iface } => {
                    info!(
                        event.name = "interface_controller.interface_attached",
                        network.interface.name = %iface,
                        "interface attached successfully"
                    );
                }
                ControllerEvent::InterfaceDetached { iface } => {
                    info!(
                        event.name = "interface_controller.interface_detached",
                        network.interface.name = %iface,
                        "interface detached successfully"
                    );
                }
                ControllerEvent::AttachmentFailed { iface, error } => {
                    warn!(
                        event.name = "interface_controller.attachment_failed",
                        network.interface.name = %iface,
                        error.message = %error,
                        "interface attachment failed"
                    );
                }
                ControllerEvent::Initialized { interface_count } => {
                    // Initialization is waited for synchronously before this task spawns,
                    // but log it if we somehow receive it here
                    debug!(
                        event.name = "interface_controller.unexpected_initialization",
                        interface_count = interface_count,
                        "received initialization event in background handler"
                    );
                }
                ControllerEvent::ShutdownComplete => {
                    info!(
                        event.name = "interface_controller.shutdown_complete",
                        "controller thread shutdown successfully"
                    );
                    // Exit the event loop since controller is shutting down
                    break;
                }
            }
        }
        debug!(
            event.name = "interface_controller.event_handler_stopped",
            "controller event handler stopped"
        );
    });

    info!(
        event.name = "ebpf.ready",
        "ebpf programs attached and ready to process network traffic"
    );

    let (flow_span_tx, mut flow_span_rx) = mpsc::channel(conf.packet_channel_capacity);
    let (k8s_decorated_flow_span_tx, mut k8s_decorated_flow_span_rx) =
        mpsc::channel(conf.packet_channel_capacity);

    let flow_span_producer = FlowSpanProducer::new(
        conf.clone().span,
        conf.packet_channel_capacity,
        conf.packet_worker_count,
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
    tokio::spawn(async move {
        info!(
            event.name = "task.started",
            task.name = "k8s.decorator",
            task.description = "decorating flow attributes with kubernetes metadata",
            "userspace task started"
        );
        // Matching on the attributor early is a performance optimization to avoid having to check to see if the attributor is None per flow_span_rx receive.
        match k8s_attributor.as_ref().map(Decorator::new) {
            Some(decorator) => {
                while let Some(flow_span) = flow_span_rx.recv().await {
                    let (span, err) = decorator.decorate_or_fallback(flow_span).await;

                    if let Some(e) = &err {
                        debug!(
                            event.name = "k8s.decorator.failed",
                            flow.community_id = %span.attributes.flow_community_id,
                            error.message = %e,
                            "failed to decorate flow attributes with kubernetes metadata, sending undecorated span"
                        );
                    } else {
                        trace!(
                            event.name = "k8s.decorator.decorated",
                            flow.community_id = %span.attributes.flow_community_id,
                            "successfully decorated flow attributes with kubernetes metadata"
                        );
                    }

                    if let Err(e) = k8s_decorated_flow_span_tx.send(span).await {
                        error!(
                            event.name = "channel.send_failed",
                            channel.name = "k8s_decorated_flow_span",
                            error.message = %e,
                            "failed to send flow span to export channel"
                        );
                    }
                }
            }
            None => {
                warn!(
                    event.name = "k8s.decorator.unavailable",
                    reason = "kubernetes_client_unavailable",
                    "kubernetes decorator unavailable, all spans will be sent undecorated"
                );

                while let Some(flow_span) = flow_span_rx.recv().await {
                    if let Err(e) = k8s_decorated_flow_span_tx.send(flow_span).await {
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

        info!(
            event.name = "task.exited",
            task.name = "k8s.decorator",
            "attributes decoration task exited"
        );
    });

    tokio::spawn(async move {
        flow_span_producer.run().await;
        info!(
            event.name = "task.exited",
            task.name = "span.producer",
            "flow span producer task exited"
        );
    });
    health_state.ready_to_process.store(true, Ordering::Relaxed);

    tokio::spawn(async move {
        while let Some(k8s_decorated_flow_span) = k8s_decorated_flow_span_rx.recv().await {
            let traceable: TraceableRecord = Arc::new(k8s_decorated_flow_span);
            trace!(event.name = "flow.exporting", "exporting flow span");
            exporter.export(traceable).await;
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

    // Send shutdown command to controller thread
    info!(
        event.name = "interface_controller.shutdown_requested",
        "sending shutdown command to controller thread"
    );

    if let Err(e) = cmd_tx.send(ControllerCommand::Shutdown) {
        warn!(
            event.name = "interface_controller.shutdown_send_failed",
            error = %e,
            "failed to send shutdown command, controller thread may have already exited"
        );
    }

    // Note: ShutdownComplete event is handled by the background event handler task
    // which will log the completion and exit when it receives the event

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
