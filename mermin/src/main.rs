mod community_id;
mod health;
mod k8s;
mod otlp;
mod runtime;
mod span;

use std::{
    collections::HashMap,
    os::unix::io::AsRawFd,
    sync::{Arc, atomic::Ordering},
};

use anyhow::{Result, anyhow};
use aya::{
    maps::RingBuf,
    programs::{SchedClassifier, TcAttachType, tc},
};
use mermin_common::PacketMeta;
use pnet::datalink;
use tokio::{io::unix::AsyncFd, signal, sync::mpsc};
use tracing::{debug, error, info, warn};

use crate::{
    health::{HealthState, start_api_server},
    k8s::resource_parser::attribute_flow_span,
    otlp::{
        opts::ExporterOptions,
        provider::{init_internal_tracing, init_provider},
        trace::{NoOpExporterAdapter, TraceExporterAdapter, TraceableExporter, TraceableRecord},
    },
    span::producer::FlowSpanProducer,
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

    let exporter_refs = config
        .agent
        .as_ref()
        .map(|a| a.traces.main.exporters.clone())
        .unwrap_or_default();

    let traces_exporters = config.traces.exporters.clone();
    let exporter: Arc<dyn TraceableExporter> = match &config.exporter {
        Some(exporter_options) => {
            init_internal_tracing(
                exporter_options,
                traces_exporters.clone(),
                config.log_level,
                config.traces.span_level,
            )
            .await?;
            let app_tracer_provider = init_provider(exporter_options, exporter_refs).await;
            info!("initialized configured exporters");
            Arc::new(TraceExporterAdapter::new(app_tracer_provider))
        }
        None => {
            init_internal_tracing(
                &ExporterOptions::default(),
                traces_exporters,
                config.log_level,
                config.traces.span_level,
            )
            .await?;
            info!("initialized default exporters");
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
        warn!("remove limit on locked memory failed, ret is: {ret}");
    }

    let api = config.api.clone();
    let interface = config.resolve_interfaces();

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
    let iface_map: HashMap<u32, String> = {
        let mut map = HashMap::new();
        for iface in datalink::interfaces() {
            if interface.contains(&iface.name) {
                map.insert(iface.index, iface.name.clone());
            }
        }
        map
    };

    let (packet_meta_tx, packet_meta_rx) = mpsc::channel(config.packet_channel_capacity);
    let (flow_span_tx, mut flow_span_rx) = mpsc::channel(config.packet_channel_capacity);
    let (k8s_attributed_flow_span_tx, mut k8s_attributed_flow_span_rx) =
        mpsc::channel(config.packet_channel_capacity);

    let flow_span_producer = FlowSpanProducer::new(
        config.span,
        config.packet_channel_capacity,
        config.packet_worker_count,
        iface_map.clone(),
        packet_meta_rx,
        flow_span_tx,
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
        while let Some(flow_span) = flow_span_rx.recv().await {
            // Attempt K8s attribution for enhanced logging/debugging first
            if let Some(attributor) = &k8s_attributor_clone {
                match attribute_flow_span(&flow_span, attributor).await {
                    Ok(attributed_flow_span) => {
                        debug!("k8s attributed flow attributes: {attributed_flow_span:?}");
                        if let Err(e) = k8s_attributed_flow_span_tx.send(attributed_flow_span).await
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
                    flow_span.attributes.flow_community_id
                );
            }
        }
        debug!("flow attributes attribution task exiting");
    });

    tokio::spawn(async move {
        flow_span_producer.run().await;
        debug!("flow attributes producer task exiting");
    });
    health_state.ready_to_process.store(true, Ordering::Relaxed);

    tokio::spawn(async move {
        info!("userspace task started: reading from ring buffer for packet metadata");

        // Wrap the ring buffer's fd in AsyncFd for event-driven polling
        let async_fd = match AsyncFd::new(ring_buf.as_raw_fd()) {
            Ok(fd) => fd,
            Err(e) => {
                error!("failed to create AsyncFd for ring buffer: {e}");
                return;
            }
        };

        loop {
            // Wait for the ring buffer to be readable (event-driven, no busy-loop)
            let mut guard = match async_fd.readable().await {
                Ok(guard) => guard,
                Err(e) => {
                    error!("error waiting for ring buffer readability: {e}");
                    break;
                }
            };

            // Consume all available data in a batch
            while let Some(bytes) = ring_buf.next() {
                let packet_meta: PacketMeta =
                    unsafe { core::ptr::read_unaligned(bytes.as_ptr() as *const PacketMeta) };

                if let Err(e) = packet_meta_tx.send(packet_meta).await {
                    warn!("failed to send packet to k8s attribution channel: {e}");
                }
            }

            guard.clear_ready();
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
        while let Some(k8s_attributed_flow_span) = k8s_attributed_flow_span_rx.recv().await {
            let traceable: TraceableRecord = Arc::new(k8s_attributed_flow_span);
            debug!("exporting flow spans");
            exporter.export(traceable).await;
        }
        debug!("exporting task exiting");
    });

    println!("waiting for ctrl+c");
    signal::ctrl_c().await?;
    println!("exiting");

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
