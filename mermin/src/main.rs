mod error;
mod health;
mod ip;
mod k8s;
mod otlp;
mod runtime;
mod source;
mod span;

use std::{
    collections::HashMap,
    sync::{Arc, atomic::Ordering},
};

use aya::{
    maps::{Array, RingBuf},
    programs::{SchedClassifier, TcAttachType, tc},
};
use error::{MerminError, Result};
use pnet::datalink;
use tokio::{signal, sync::mpsc};
use tracing::{debug, error, info, trace, warn};

use crate::{
    health::{HealthState, start_api_server},
    k8s::{decorator::Decorator, parser::decorate_flow_span},
    otlp::{
        provider::{init_internal_tracing, init_provider},
        trace::{NoOpExporterAdapter, TraceExporterAdapter, TraceableExporter, TraceableRecord},
    },
    runtime::context::Context,
    source::{filter::PacketFilter, ringbuf::RingBufReader},
    span::producer::FlowSpanProducer,
};

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

        MerminError::EbpfMap(msg) => {
            eprintln!("❌ eBPF Map Error");
            eprintln!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");
            eprintln!("{msg}\n");
            eprintln!("💡 This is likely a compilation or loading issue.");
            eprintln!("   Try rebuilding the project.");
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
    // TODO: API will come once we have an API server
    // TODO: listen for SIGTERM `kill -TERM $(pidof mermin)` to gracefully shutdown the eBPF program and all configuration.
    // TODO: do not reload global configuration found in CLI

    let runtime = Context::new()?;
    let Context { conf, .. } = runtime;

    // If a provider is already installed, install_default() returns Err, which we can safely ignore.
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

    let exporter: Arc<dyn TraceableExporter> = {
        init_internal_tracing(
            conf.log_level,
            conf.internal.traces.span_fmt,
            conf.internal.traces.stdout,
            conf.internal.traces.otlp.clone(),
        )
        .await?;

        if conf.export.traces.stdout.is_some() || conf.export.traces.otlp.is_some() {
            let app_tracer_provider =
                init_provider(conf.export.traces.stdout, conf.export.traces.otlp.clone()).await?;
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

    // Configure parser options for tunnel port detection
    let mut parser_options_map: Array<_, u16> = ebpf
        .take_map("PARSER_OPTIONS")
        .ok_or_else(|| MerminError::ebpf_map("PARSER_OPTIONS map not present in the object"))?
        .try_into()?;

    // Set tunnel ports in the map (indices: 0=geneve, 1=vxlan, 2=wireguard)
    parser_options_map.set(0, conf.parser.geneve_port, 0)?;
    parser_options_map.set(1, conf.parser.vxlan_port, 0)?;
    parser_options_map.set(2, conf.parser.wireguard_port, 0)?;

    info!(
        event.name = "ebpf.config_applied",
        ebpf.config.type = "tunnel_ports",
        parser.geneve_port = conf.parser.geneve_port,
        parser.vxlan_port = conf.parser.vxlan_port,
        parser.wireguard_port = conf.parser.wireguard_port,
        "configured ebpf tunnel ports"
    );

    let health_state = HealthState::default();

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
    }

    // Load and attach both ingress and egress programs
    let programs = [TcAttachType::Ingress, TcAttachType::Egress];
    programs.iter().try_for_each(|attach_type| -> Result<()> {
        let program: &mut SchedClassifier = ebpf
            .program_mut(attach_type.program_name())
            .ok_or_else(|| {
                MerminError::internal(format!(
                    "eBPF program '{}' not found in loaded object",
                    attach_type.program_name()
                ))
            })?
            .try_into()?;
        program.load()?;

        conf.resolved_interfaces
            .iter()
            .try_for_each(|iface| -> Result<()> {
                // error adding clsact to the interface if it is already added is harmless
                // the full cleanup can be done with 'sudo tc qdisc del dev eth0 clsact'.
                let _ = tc::qdisc_add_clsact(iface);

                program.attach(iface, *attach_type)?;
                debug!(
                    event.name = "ebpf.program_attached",
                    ebpf.program.direction = attach_type.direction_name(),
                    network.interface.name = %iface,
                    "ebpf program attached to interface"
                );
                Ok(())
            })
    })?;

    let map = ebpf
        .take_map("PACKETS_META")
        .ok_or_else(|| MerminError::ebpf_map("PACKETS_META map not present in the object"))?;
    let ring_buf = RingBuf::try_from(map)?;

    debug!(
        event.name = "source.ringbuf.initialized",
        "ring buffer initialized, waiting for packets"
    );
    info!(
        event.name = "ebpf.ready",
        "ebpf program loaded and ready to process network traffic"
    );
    health_state.ebpf_loaded.store(true, Ordering::Relaxed);

    let iface_map: HashMap<u32, String> = {
        let mut map = HashMap::new();
        for iface in datalink::interfaces() {
            if conf.resolved_interfaces.contains(&iface.name) {
                map.insert(iface.index, iface.name.clone());
            }
        }
        map
    };
    info!(
        event.name = "system.config_loaded",
        system.config.type = "interface_map",
        system.config.interface_count = iface_map.len(),
        "built interface map from configuration"
    );

    let (packet_meta_tx, packet_meta_rx) = mpsc::channel(conf.packet_channel_capacity);
    let (flow_span_tx, mut flow_span_rx) = mpsc::channel(conf.packet_channel_capacity);
    let (k8s_decorated_flow_span_tx, mut k8s_decorated_flow_span_rx) =
        mpsc::channel(conf.packet_channel_capacity);

    let flow_span_producer = FlowSpanProducer::new(
        conf.clone().span,
        conf.packet_channel_capacity,
        conf.packet_worker_count,
        iface_map.clone(),
        packet_meta_rx,
        flow_span_tx,
    )?;

    info!(
        event.name = "k8s.client_initializing",
        "initializing kubernetes client"
    );

    // Extract owner_relations and selector_relations configuration from discovery.informer.k8s if present
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

    let k8s_decorator = match Decorator::new(
        health_state.clone(),
        owner_relations_opts,
        selector_relations_opts,
    )
    .await
    {
        Ok(decorator) => {
            info!(
                event.name = "k8s.client.init.success",
                "kubernetes client initialized successfully and all caches are synced"
            );
            Some(Arc::new(decorator))
        }
        Err(e) => {
            error!(
                event.name = "k8s.client_init_failed",
                error.message = %e,
                "failed to initialize kubernetes client; metadata lookup will be unavailable"
            );
            health_state
                .k8s_caches_synced
                .store(false, Ordering::Relaxed);
            None
        }
    };

    let k8s_decorator_clone = k8s_decorator.clone();
    tokio::spawn(async move {
        info!(
            event.name = "task.started",
            task.name = "k8s.decorator",
            task.description = "decorating flow attributes with kubernetes metadata",
            "userspace task started"
        );
        while let Some(flow_span) = flow_span_rx.recv().await {
            // Attempt K8s decoration for enhanced logging/debugging first
            if let Some(decorator) = &k8s_decorator_clone {
                match decorate_flow_span(&flow_span, decorator).await {
                    Ok(decorated_flow_span) => {
                        debug!(
                            event.name = "k8s.decorator.decorated",
                            flow.community_id = %decorated_flow_span.attributes.flow_community_id,
                            "successfully decorated flow attributes with kubernetes metadata"
                        );
                        if let Err(e) = k8s_decorated_flow_span_tx.send(decorated_flow_span).await {
                            error!(
                                event.name = "channel.send_failed",
                                channel.name = "k8s_decorated_flow_span",
                                error.message = %e,
                                "failed to send decorated flow attributes to kubernetes decoration channel"
                            );
                        }
                    }
                    Err(e) => {
                        debug!(
                            event.name = "k8s.decorator.failed",
                            flow.community_id = %flow_span.attributes.flow_community_id,
                            error.message = %e,
                            "failed to decorate flow attributes with kubernetes metadata"
                        );
                    }
                }
            } else {
                debug!(
                    event.name = "k8s.decorator.skipped",
                    flow.community_id = %flow_span.attributes.flow_community_id,
                    reason = "kubernetes_client_unavailable",
                    "skipping kubernetes decoration for flow attributes"
                );
            }
        }
        debug!(
            event.name = "task.exited",
            task.name = "k8s.decorator",
            "attributes decoration task exited"
        );
    });

    tokio::spawn(async move {
        flow_span_producer.run().await;
        debug!(
            event.name = "task.exited",
            task.name = "span.producer",
            "flow span producer task exited"
        );
    });
    health_state.ready_to_process.store(true, Ordering::Relaxed);

    let packet_filter = Arc::new(PacketFilter::new(&conf, iface_map.clone()));

    let ring_buf_reader = RingBufReader::new(ring_buf, packet_filter, packet_meta_tx);
    tokio::spawn(async move {
        ring_buf_reader.run().await;
        debug!(
            event.name = "task.exited",
            task.name = "source.ringbuf",
            "ring buffer reader task exited"
        );
    });

    tokio::spawn(async move {
        while let Some(k8s_decorated_flow_span) = k8s_decorated_flow_span_rx.recv().await {
            let traceable: TraceableRecord = Arc::new(k8s_decorated_flow_span);
            trace!(event.name = "flow.exporting", "exporting flow span");
            exporter.export(traceable).await;
        }
        debug!(
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
    info!("exiting");

    Ok(())
}

/// Extension trait for TcAttachType to provide direction name
trait TcAttachTypeExt {
    fn direction_name(&self) -> &'static str;
    fn program_name(&self) -> &'static str;
}

impl TcAttachTypeExt for TcAttachType {
    fn direction_name(&self) -> &'static str {
        match self {
            TcAttachType::Ingress => "ingress",
            TcAttachType::Egress => "egress",
            TcAttachType::Custom(_) => "custom",
        }
    }

    fn program_name(&self) -> &'static str {
        match self {
            TcAttachType::Ingress => "mermin_ingress",
            TcAttachType::Egress => "mermin_egress",
            TcAttachType::Custom(_) => "mermin_custom",
        }
    }
}
