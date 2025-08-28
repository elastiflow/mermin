mod community_id;
mod flow_manager;
mod flow;
mod k8s;
mod runtime;

use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    sync::Arc,
};

use anyhow::anyhow;
use aya::{
    maps::RingBuf,
    programs::{SchedClassifier, TcAttachType, tc},
};
use log::{debug, info, warn};
use mermin_common::{IpAddrType, PacketMeta};
use tokio::signal;

use crate::{
    community_id::CommunityIdGenerator,
    runtime::{conf::Config, pipeline::Pipeline},
};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // TODO: create `runtime` module to handle reloading of eBPF program and all configuration
    // TODO: runtime should be aware of all threads and tasks spawned by the eBPF program so that they can be gracefully shutdown and restarted.
    // TODO: listen for SIGUP `kill -HUP $(pidof mermin)` to reload the eBPF program and all configuration
    // TODO: API will come once we have an API server
    // TODO: listen for SIGTERM `kill -TERM $(pidof mermin)` to gracefully shutdown the eBPF program and all configuration.
    // TODO: do not reload global configuration found in CLI
    // TODO: expose these as metrics:
    // - active_flows
    // - packets processed
    // - flows created
    // - flows released
    // - enrichment queue size
    // - processing latency (optional)
    let runtime = runtime::Runtime::new()?;
    let runtime::Runtime { config, .. } = runtime;
    let community_id_generator = CommunityIdGenerator::new(0);

    // TODO: switch to using tracing for logging and allow users to configure the log level via conf
    env_logger::Builder::from_default_env()
        .target(env_logger::Target::Stdout)
        .init();

    // Bump the memlock rlimit. This is needed for older kernels that don't use the
    // new memcg based accounting, see https://lwn.net/Articles/837122/
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        debug!("remove limit on locked memory failed, ret is: {ret}");
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
        warn!("failed to initialize eBPF logger: {e}");
    }

    let Config { interface, .. } = config;
    let iface = &interface[0];
    // error adding clsact to the interface if it is already added is harmless
    // the full cleanup can be done with 'sudo tc qdisc del dev eth0 clsact'.
    let _ = tc::qdisc_add_clsact(iface);
    let program: &mut SchedClassifier = ebpf.program_mut("mermin").unwrap().try_into()?;
    program.load()?;
    program.attach(iface, TcAttachType::Egress)?;

    info!("eBPF program attached. Waiting for events... Press Ctrl-C to exit.");

    // Initialize the Kubernetes client
    info!("Initializing Kubernetes client...");
    let kube_client = match k8s::Attributor::new().await {
        Ok(client) => {
            // TODO: we should implement an event based notifier
            // that sends a signal when the kubeclient is ready with its stores instead of waiting for a fixed interval.
            info!("Kubernetes client initialized successfully");
            info!("Waiting for reflectors to populate stores...");
            tokio::time::sleep(std::time::Duration::from_secs(10)).await;
            info!("Reflectors should have populated stores by now");
            Some(Arc::new(client))
        }
        Err(e) => {
            warn!("Failed to initialize Kubernetes client: {e}");
            warn!("Pod metadata lookup will not be available");
            None
        }
    };

    let map = ebpf
        .take_map("PACKETS")
        .ok_or_else(|| anyhow!("PACKETS map not present in the object"))?;
    let mut ring_buf = RingBuf::try_from(map)?;

    // Run the application with the channel-based pipeline
    info!("Starting channel-based flow processing pipeline");
    run_with_pipeline(config, community_id_generator, kube_client, ring_buf).await?;

    println!("Waiting for Ctrl-C...");
    signal::ctrl_c().await?;
    println!("Exiting...");

    Ok(())
}

/// Run the application with the channel-based pipeline
async fn run_with_pipeline(
    config: Config,
    community_id_generator: CommunityIdGenerator,
    kube_client: Option<Arc<k8s::Attributor>>,
    mut ring_buf: RingBuf,
) -> anyhow::Result<()> {
    let community_id_gen = Arc::new(community_id_generator);

    // Create the flow processing pipeline
    let mut pipeline = Pipeline::new(
        config.clone(),
        community_id_gen.clone(),
        kube_client.clone(),
    );

    info!("Flow processing pipeline initialized");

    // Packet reading task - dedicated to reading from eBPF ring buffer
    let pipeline_sender = pipeline.sender();
    let community_id_gen_clone = community_id_gen.clone();
    tokio::spawn(async move {
        info!("Packet reader task started");
        let mut packet_count = 0u64;

        loop {
            match ring_buf.next() {
                Some(bytes) => {
                    let event: PacketMeta =
                        unsafe { core::ptr::read_unaligned(bytes.as_ptr() as *const PacketMeta) };

                    // Generate Community ID
                    let community_id = match event.ip_addr_type {
                        IpAddrType::Ipv4 => community_id_gen_clone.generate(
                            IpAddr::V4(Ipv4Addr::from(event.src_ipv4_addr)),
                            IpAddr::V4(Ipv4Addr::from(event.dst_ipv4_addr)),
                            u16::from_be_bytes(event.src_port),
                            u16::from_be_bytes(event.dst_port),
                            event.proto,
                        ),
                        IpAddrType::Ipv6 => community_id_gen_clone.generate(
                            IpAddr::V6(Ipv6Addr::from(event.src_ipv6_addr)),
                            IpAddr::V6(Ipv6Addr::from(event.dst_ipv6_addr)),
                            u16::from_be_bytes(event.src_port),
                            u16::from_be_bytes(event.dst_port),
                            event.proto,
                        ),
                    };

                    // Send to pipeline (with backpressure handling)
                    if let Err(e) = pipeline_sender.send_packet(event, community_id).await {
                        if config.pipeline.enable_backpressure {
                            warn!("Failed to send packet to pipeline: {}", e);
                        } else {
                            debug!("Dropped packet due to full pipeline: {}", e);
                        }
                    }

                    packet_count += 1;
                    if packet_count % 1000 == 0 {
                        info!("Processed {} packets", packet_count);
                    }
                }
                None => {
                    // Short sleep to prevent busy-looping
                    tokio::time::sleep(std::time::Duration::from_millis(1)).await;
                }
            }
        }
    });

    // Flow statistics task - periodically log statistics
    let pipeline_for_stats = pipeline.clone();
    let stats_interval = config.pipeline.stats_interval;
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(stats_interval);

        loop {
            interval.tick().await;

            match pipeline_for_stats.get_stats().await {
                Ok(stats) => {
                    info!(
                        "Flow Pipeline Stats: {} active flows, {} total created, {} total released, {} packets processed",
                        stats.active_flows,
                        stats.total_flows_created,
                        stats.total_flows_released,
                        stats.total_packets_processed
                    );
                }
                Err(e) => {
                    warn!("Failed to get pipeline stats: {}", e);
                }
            }
        }
    });

    // Process enriched flow events
    tokio::spawn(async move {
        info!("Enriched event processor started");

        while let Some(enriched_event) = pipeline.recv_enriched_event().await {
            // Process the enriched flow event
            if enriched_event.is_new_flow {
                info!(
                    "New flow created: {}",
                    enriched_event.flow_record.community_id
                );
            }

            // Log flow details (can be extended to send to OpenTelemetry, etc.)
            match enriched_event.packet.ip_addr_type {
                IpAddrType::Ipv4 => {
                    debug!(
                        "Flow Update - Community ID: {}, Packets: {}, Bytes: {}, Bidirectional: {}",
                        enriched_event.flow_record.community_id,
                        enriched_event.flow_record.total_packets,
                        enriched_event.flow_record.total_bytes,
                        enriched_event.flow_record.is_bidirectional()
                    );
                }
                IpAddrType::Ipv6 => {
                    debug!(
                        "Flow Update - Community ID: {}, Packets: {}, Bytes: {}, Bidirectional: {}",
                        enriched_event.flow_record.community_id,
                        enriched_event.flow_record.total_packets,
                        enriched_event.flow_record.total_bytes,
                        enriched_event.flow_record.is_bidirectional()
                    );
                }
            }
        }
    });

    Ok(())
}
