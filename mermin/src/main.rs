mod community_id;
mod flow;
mod health;
mod k8s;
mod otlp;
mod runtime;

use std::{
    collections::HashMap,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    sync::{Arc, atomic::Ordering},
};

use anyhow::{Result, anyhow};
use aya::{
    maps::RingBuf,
    programs::{SchedClassifier, TcAttachType, tc},
};
use mermin_common::{IpAddrType, PacketMeta};
use pnet::datalink;
use tokio::{signal, sync::mpsc};
use tracing::{debug, error, info, warn};

use crate::{
    community_id::CommunityIdGenerator,
    flow::{FlowAttributesExporter, FlowAttributesProducer},
    health::{HealthState, start_api_server},
    k8s::resource_parser::attribute_flow_attrs,
    otlp::{
        opts::{ExporterOptions, OtlpExporterOptions, StdoutExporterOptions, resolve_exporters},
        trace::lib::{TraceExporterAdapter, init_tracer_provider},
    },
    runtime::conf::Conf,
};

#[tokio::main]
async fn main() -> Result<()> {
    // TODO: runtime should be aware of all threads and tasks spawned by the eBPF program so that they can be gracefully shutdown and restarted.
    // TODO: listen for SIGUP `kill -HUP $(pidof mermin)` to reload the eBPF program and all configuration
    // TODO: API will come once we have an API server
    // TODO: listen for SIGTERM `kill -TERM $(pidof mermin)` to gracefully shutdown the eBPF program and all configuration.
    // TODO: do not reload global configuration found in CLI
    let runtime = runtime::Runtime::new()?;
    let runtime::Runtime { config, .. } = runtime;

    let mut fmt_builder = tracing_subscriber::fmt().with_max_level(config.log_level);
    match config.log_level {
        tracing::Level::DEBUG => fmt_builder = fmt_builder.with_file(true).with_line_number(true),
        tracing::Level::TRACE => {
            fmt_builder = fmt_builder
                .with_thread_ids(true)
                .with_thread_names(true)
                .with_file(true)
                .with_line_number(true)
        }
        _ => {
            // default format:
            // Format {
            //     format: Full,
            //     timer: SystemTime,
            //     ansi: None, // conditionally set based on environment, handled by tracing-subscriber
            //     display_timestamp: true,
            //     display_target: true,
            //     display_level: true,
            //     display_thread_id: false,
            //     display_thread_name: false,
            //     display_filename: false,
            //     display_line_number: false,
            // }
        }
    }
    fmt_builder.init();

    let agent_opts = config
        .agent
        .as_ref()
        .ok_or_else(|| anyhow!("no agent options configured"))?;
    let exporter_opts = if let Some(opts) = config.exporter.as_ref() {
        opts
    } else {
        warn!("no exporter options configured, continuing without exporters");
        &ExporterOptions::default()
    };

    let (otlp_exporters, stdout_exporters) =
        resolve_exporters(agent_opts.traces.main.exporters.clone(), exporter_opts)
            .map_err(|e| anyhow!("failed to resolve exporters: {e}"))?;

    let exporter = if !otlp_exporters.is_empty() || !stdout_exporters.is_empty() {
        info!(
            "initializing exporter (otlp: {}, stdout: {})",
            otlp_exporters.len(),
            stdout_exporters.len()
        );
        match create_otlp_exporter(
            otlp_exporters.first(),
            stdout_exporters.first(),
            config.log_level,
        )
        .await
        {
            Ok(exporter) => Some(exporter),
            Err(e) => {
                error!("failed to initialize exporter: {e}");
                warn!("continuing without exporter");
                None
            }
        }
    } else {
        warn!("no exporters configured");
        None
    };

    let community_id_generator = CommunityIdGenerator::new(0);

    // Bump the memlock rlimit. This is needed for older kernels that don't use the
    // new memcg based accounting, see https://lwn.net/Articles/837122/
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        warn!("remove limit on locked memory failed, ret is: {ret}");
    }

    let Conf { interface, api, .. } = config;

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
        warn!("failed to initialize ebpf logger: {e}");
    }

    let health_state = HealthState::default();

    if api.enabled {
        let health_state_clone = health_state.clone();

        tokio::spawn(async move {
            if let Err(e) = start_api_server(health_state_clone, &api).await {
                log::error!("API server error: {e}");
            }
        });
    }

    // Load and attach both ingress and egress programs
    let programs = [TcAttachType::Ingress, TcAttachType::Egress];
    programs.iter().try_for_each(|attach_type| -> Result<()> {
        let program: &mut SchedClassifier = ebpf
            .program_mut(attach_type.program_name())
            .unwrap()
            .try_into()?;
        program.load()?;

        interface.iter().try_for_each(|iface| -> Result<()> {
            // error adding clsact to the interface if it is already added is harmless
            // the full cleanup can be done with 'sudo tc qdisc del dev eth0 clsact'.
            let _ = tc::qdisc_add_clsact(iface);

            program.attach(iface, *attach_type)?;
            debug!(
                "mermin {} program attached to {iface}",
                attach_type.direction_name()
            );
            Ok(())
        })
    })?;

    let map = ebpf
        .take_map("PACKETS_META")
        .ok_or_else(|| anyhow!("PACKETS_META map not present in the object"))?;
    let mut ring_buf = RingBuf::try_from(map)?;

    info!("waiting for packets - ring buffer initialized");
    info!("press ctrl+c to exit");

    health_state.ebpf_loaded.store(true, Ordering::Relaxed);

    info!("building interface index map");
    let iface_map: Arc<HashMap<u32, String>> = {
        let mut map = HashMap::new();
        for iface in datalink::interfaces() {
            if interface.contains(&iface.name) {
                map.insert(iface.index, iface.name.clone());
            }
        }
        Arc::new(map)
    };

    let (packet_meta_tx, packet_meta_rx) = mpsc::channel(config.packet_channel_capacity);
    let (flow_attrs_tx, mut flow_attrs_rx) = mpsc::channel(config.packet_channel_capacity);
    let (k8s_attributed_flow_attrs_tx, mut k8s_attributed_flow_attrs_rx) =
        mpsc::channel(config.packet_channel_capacity);

    let flow_attrs_producer = FlowAttributesProducer::new(
        config.span,
        config.packet_channel_capacity,
        config.packet_worker_count,
        packet_meta_rx,
        flow_attrs_tx,
    );

    info!("initializing k8s client");
    let k8s_attributor = match k8s::Attributor::new().await {
        Ok(attributor) => {
            // TODO: we should implement an event based notifier
            // that sends a signal when the kubeclient is ready with its stores instead of waiting for a fixed interval.
            info!("k8s client initialized successfully");
            health_state.k8s_connected.store(true, Ordering::Relaxed);
            debug!("waiting 10 seconds for the k8s reflector to populate stores");
            tokio::time::sleep(std::time::Duration::from_secs(10)).await;
            debug!("reflectors should be populated");
            Some(Arc::new(attributor))
        }
        Err(e) => {
            error!(
                "failed to initialize k8s client - k8s metadata lookup will not be available: {e}"
            );
            health_state.k8s_connected.store(false, Ordering::Relaxed);
            None
        }
    };

    let k8s_attributor_clone = k8s_attributor.clone();
    tokio::spawn(async move {
        while let Some(flow_attrs) = flow_attrs_rx.recv().await {
            // Attempt K8s attribution for enhanced logging/debugging first
            if let Some(attributor) = &k8s_attributor_clone {
                match attribute_flow_attrs(&flow_attrs, attributor).await {
                    Ok(attributed_flow_attrs) => {
                        debug!("k8s attributed flow attributes: {attributed_flow_attrs:?}");
                        if let Err(e) = k8s_attributed_flow_attrs_tx
                            .send(attributed_flow_attrs)
                            .await
                        {
                            error!(
                                "failed to send attributed flow attributes to k8s attribution channel: {e}"
                            );
                        }
                    }
                    Err(e) => {
                        debug!("failed to attribute flow attributes with k8s metadata: {e}");
                    }
                }
            } else {
                debug!(
                    "skipping k8s attribution for flow attributes with community id {}: k8s client not available",
                    flow_attrs.community_id
                );
            }
        }
        debug!("flow attributes attribution task exiting");
    });

    tokio::spawn(async move {
        flow_attrs_producer.run().await;
        debug!("flow attributes producer task exiting");
    });
    health_state.ready_to_process.store(true, Ordering::Relaxed);

    let task_iface_map = Arc::clone(&iface_map);
    tokio::spawn(async move {
        info!("userspace task started: reading from ring buffer for packet metadata");
        loop {
            match ring_buf.next() {
                Some(bytes) => {
                    let packet_meta: PacketMeta =
                        unsafe { core::ptr::read_unaligned(bytes.as_ptr() as *const PacketMeta) };

                    let iface_name = task_iface_map
                        .get(&packet_meta.ifindex)
                        .map(String::as_str)
                        .unwrap_or("unknown_if");

                    // Extract port numbers for community ID generation
                    let src_port = packet_meta.src_port();
                    let dst_port = packet_meta.dst_port();

                    let community_id = match packet_meta.ip_addr_type {
                        IpAddrType::Ipv4 => community_id_generator.generate(
                            IpAddr::V4(Ipv4Addr::from(packet_meta.src_ipv4_addr)),
                            IpAddr::V4(Ipv4Addr::from(packet_meta.dst_ipv4_addr)),
                            src_port,
                            dst_port,
                            packet_meta.proto,
                        ),
                        IpAddrType::Ipv6 => community_id_generator.generate(
                            IpAddr::V6(Ipv6Addr::from(packet_meta.src_ipv6_addr)),
                            IpAddr::V6(Ipv6Addr::from(packet_meta.dst_ipv6_addr)),
                            src_port,
                            dst_port,
                            packet_meta.proto,
                        ),
                    };

                    // Log packet details if debug logging is enabled
                    log_packet_info(&packet_meta, &community_id, iface_name);

                    if let Err(e) = packet_meta_tx.send(packet_meta).await {
                        warn!("failed to send packet to k8s attribution channel: {e}");
                    }
                }
                None => {
                    // Short sleep to prevent busy-looping.
                    tokio::time::sleep(std::time::Duration::from_millis(10)).await;
                }
            }
        }
    });

    let all_systems_ready = health_state.ebpf_loaded.load(Ordering::Relaxed)
        && health_state.k8s_connected.load(Ordering::Relaxed)
        && health_state.ready_to_process.load(Ordering::Relaxed);

    health_state
        .startup_complete
        .store(all_systems_ready, Ordering::Relaxed);

    if all_systems_ready {
        info!("startup complete - all systems ready");
    } else {
        warn!(
            "startup completed but some systems are not ready - check readiness endpoint for details"
        );
    }

    tokio::spawn(async move {
        while let Some(k8s_attributed_flow_attrs) = k8s_attributed_flow_attrs_rx.recv().await {
            if let Some(ref exporter) = exporter {
                debug!("exporting flow spans");
                exporter.export(k8s_attributed_flow_attrs).await;
            } else {
                debug!("skipping export - no exporters available");
            }
        }
        debug!("exporting task exiting");
        if let Some(ref exporter) = exporter
            && let Err(e) = exporter.shutdown().await
        {
            error!("error during exporters shutdown: {e}");
        }
    });

    println!("waiting for ctrl+c");
    signal::ctrl_c().await?;
    println!("exiting");

    Ok(())
}

// TODO: eng-205 should refactor this because we're overloading the otlp exporter with stdout exporters here and that's not a good idea.
// TODO: eng-205 should allow for multiple otlp exporters
async fn create_otlp_exporter(
    otlp_exporters: Option<&OtlpExporterOptions>,
    stdout_exporters: Option<&StdoutExporterOptions>,
    log_level: tracing::Level,
) -> Result<Arc<dyn FlowAttributesExporter>, anyhow::Error> {
    info!("using otlp exporter adapter");

    let provider = init_tracer_provider(otlp_exporters, stdout_exporters, log_level).await?;

    let exporter = TraceExporterAdapter::new(provider);
    Ok(Arc::new(exporter))
}

/// Helper function to format IP address based on type
fn format_ip(addr_type: IpAddrType, ipv4_addr: [u8; 4], ipv6_addr: [u8; 16]) -> String {
    match addr_type {
        IpAddrType::Ipv4 => Ipv4Addr::from(ipv4_addr).to_string(),
        IpAddrType::Ipv6 => Ipv6Addr::from(ipv6_addr).to_string(),
    }
}

/// Log packet information in a structured way
fn log_packet_info(packet_meta: &PacketMeta, community_id: &str, iface_name: &str) {
    let src_port = packet_meta.src_port();
    let dst_port = packet_meta.dst_port();

    // Check if this is tunneled traffic
    let is_tunneled =
        packet_meta.tunnel_src_ipv4_addr != [0; 4] || packet_meta.tunnel_src_ipv6_addr != [0; 16];

    if is_tunneled {
        let tunnel_src_ip = format_ip(
            packet_meta.tunnel_ip_addr_type,
            packet_meta.tunnel_src_ipv4_addr,
            packet_meta.tunnel_src_ipv6_addr,
        );
        let tunnel_dst_ip = format_ip(
            packet_meta.tunnel_ip_addr_type,
            packet_meta.tunnel_dst_ipv4_addr,
            packet_meta.tunnel_dst_ipv6_addr,
        );
        let inner_src_ip = format_ip(
            packet_meta.ip_addr_type,
            packet_meta.src_ipv4_addr,
            packet_meta.src_ipv6_addr,
        );
        let inner_dst_ip = format_ip(
            packet_meta.ip_addr_type,
            packet_meta.dst_ipv4_addr,
            packet_meta.dst_ipv6_addr,
        );
        let tunnel_src_port = packet_meta.tunnel_src_port();
        let tunnel_dst_port = packet_meta.tunnel_dst_port();

        debug!(
            "[{iface_name}] Tunneled {} packet: {} | Tunnel: {}:{} -> {}:{} ({}) | Inner: {}:{} -> {}:{} | bytes: {}",
            packet_meta.proto,
            community_id,
            tunnel_src_ip,
            tunnel_src_port,
            tunnel_dst_ip,
            tunnel_dst_port,
            packet_meta.tunnel_proto,
            inner_src_ip,
            src_port,
            inner_dst_ip,
            dst_port,
            packet_meta.l3_octet_count,
        );
    } else {
        let src_ip = format_ip(
            packet_meta.ip_addr_type,
            packet_meta.src_ipv4_addr,
            packet_meta.src_ipv6_addr,
        );
        let dst_ip = format_ip(
            packet_meta.ip_addr_type,
            packet_meta.dst_ipv4_addr,
            packet_meta.dst_ipv6_addr,
        );

        debug!(
            "[{iface_name}] {} packet: {} | {}:{} -> {}:{} | bytes: {}",
            packet_meta.proto,
            community_id,
            src_ip,
            src_port,
            dst_ip,
            dst_port,
            packet_meta.l3_octet_count,
        );
    }
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
