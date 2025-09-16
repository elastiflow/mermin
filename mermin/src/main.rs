mod community_id;
mod flow;
mod health;
mod k8s;
mod runtime;

use std::{
    collections::HashMap,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    sync::{Arc, atomic::Ordering},
};

use anyhow::anyhow;
use aya::{
    maps::RingBuf,
    programs::{SchedClassifier, TcAttachType, tc},
};
use log::{debug, info, warn};
use mermin_common::{IpAddrType, PacketMeta};
use pnet::datalink;
use tokio::signal;

use crate::{
    community_id::CommunityIdGenerator,
    health::{HealthState, start_health_server},
    k8s::resource_parser::parse_packet,
    runtime::conf::Conf,
};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // TODO: create `runtime` module to handle reloading of eBPF program and all configuration
    // TODO: runtime should be aware of all threads and tasks spawned by the eBPF program so that they can be gracefully shutdown and restarted.
    // TODO: listen for SIGUP `kill -HUP $(pidof mermin)` to reload the eBPF program and all configuration
    // TODO: API will come once we have an API server
    // TODO: listen for SIGTERM `kill -TERM $(pidof mermin)` to gracefully shutdown the eBPF program and all configuration.
    // TODO: do not reload global configuration found in CLI
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

    let Conf {
        interface,
        health_port,
        ..
    } = config;

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

    let health_state = HealthState::default();
    let health_state_clone = health_state.clone();

    tokio::spawn(async move {
        if let Err(e) = start_health_server(health_state_clone, health_port).await {
            log::error!("Health server error: {e}");
        }
    });

    let program: &mut SchedClassifier = ebpf.program_mut("mermin").unwrap().try_into()?;
    program.load()?;

    for iface in &interface {
        // error adding clsact to the interface if it is already added is harmless
        // the full cleanup can be done with 'sudo tc qdisc del dev eth0 clsact'.
        let _ = tc::qdisc_add_clsact(iface);
        program.attach(iface, TcAttachType::Egress)?;
        info!("eBPF program attached to {iface}");
    }

    info!("eBPF program attached to all interfaces. Waiting for events... Press Ctrl-C to exit.");

    health_state.ebpf_loaded.store(true, Ordering::Relaxed);

    info!("Building interface index map...");
    let iface_map: Arc<HashMap<u32, String>> = {
        let mut map = HashMap::new();
        for iface in datalink::interfaces() {
            if interface.contains(&iface.name) {
                map.insert(iface.index, iface.name.clone());
            }
        }
        Arc::new(map)
    };

    let map = ebpf
        .take_map("PACKETS")
        .ok_or_else(|| anyhow!("PACKETS map not present in the object"))?;
    let mut ring_buf = RingBuf::try_from(map)?;

    #[cfg(not(feature = "flow"))]
    {
        let (tx, mut rx) = tokio::sync::mpsc::channel::<(PacketMeta, String, String)>(1024);

        // Initialize the Kubernetes client
        info!("Initializing Kubernetes client...");
        let kube_client = match k8s::Attributor::new().await {
            Ok(client) => {
                // TODO: we should implement an event based notifier
                // that sends a signal when the kubeclient is ready with its stores instead of waiting for a fixed interval.
                info!("Kubernetes client initialized successfully");
                health_state.k8s_connected.store(true, Ordering::Relaxed);
                info!("Waiting for reflectors to populate stores...");
                tokio::time::sleep(std::time::Duration::from_secs(10)).await;
                info!("Reflectors should have populated stores by now");
                Some(Arc::new(client))
            }
            Err(e) => {
                warn!("Failed to initialize Kubernetes client: {e}");
                warn!("Pod metadata lookup will not be available");
                health_state.k8s_connected.store(false, Ordering::Relaxed);
                None
            }
        };

        let kube_client_clone = kube_client.clone();

        tokio::spawn(async move {
            while let Some((event, community_id, iface_name)) = rx.recv().await {
                info!("Received packet to parse for Community ID {community_id}");
                if let Some(client) = &kube_client_clone {
                    let enriched_packet = parse_packet(&event, client, community_id).await;
                    info!("[{iface_name}] Enriched packet: {enriched_packet:?}");
                } else {
                    info!(
                        "Skipping packet enrichment for Community ID {community_id}: Kubernetes client not available"
                    );
                }
            }
        });

        let task_iface_map = Arc::clone(&iface_map);
        tokio::spawn(async move {
            info!("Userspace task started. Polling the ring buffer...");
            loop {
                match ring_buf.next() {
                    Some(bytes) => {
                        let event: PacketMeta = unsafe {
                            core::ptr::read_unaligned(bytes.as_ptr() as *const PacketMeta)
                        };

                        let iface_name = task_iface_map
                            .get(&event.ifindex)
                            .map(String::as_str)
                            .unwrap_or("unknown_if");

                        // Helper function to format IP address based on type
                        let format_ip = |addr_type: IpAddrType,
                                         ipv4_addr: [u8; 4],
                                         ipv6_addr: [u8; 16]|
                         -> String {
                            match addr_type {
                                IpAddrType::Ipv4 => Ipv4Addr::from(ipv4_addr).to_string(),
                                IpAddrType::Ipv6 => Ipv6Addr::from(ipv6_addr).to_string(),
                            }
                        };

                        // Extract port numbers
                        let src_port = u16::from_be_bytes(event.src_port);
                        let dst_port = u16::from_be_bytes(event.dst_port);

                        let community_id = match event.ip_addr_type {
                            IpAddrType::Ipv4 => community_id_generator.generate(
                                IpAddr::V4(Ipv4Addr::from(event.src_ipv4_addr)),
                                IpAddr::V4(Ipv4Addr::from(event.dst_ipv4_addr)),
                                src_port,
                                dst_port,
                                event.proto,
                            ),
                            IpAddrType::Ipv6 => community_id_generator.generate(
                                IpAddr::V6(Ipv6Addr::from(event.src_ipv6_addr)),
                                IpAddr::V6(Ipv6Addr::from(event.dst_ipv6_addr)),
                                src_port,
                                dst_port,
                                event.proto,
                            ),
                        };

                        // Check if this is tunneled traffic
                        let is_tunneled = event.tunnel_src_ipv4_addr != [0; 4]
                            || event.tunnel_src_ipv6_addr != [0; 16];

                        if is_tunneled {
                            let tunnel_src_ip = format_ip(
                                event.tunnel_ip_addr_type,
                                event.tunnel_src_ipv4_addr,
                                event.tunnel_src_ipv6_addr,
                            );
                            let tunnel_dst_ip = format_ip(
                                event.tunnel_ip_addr_type,
                                event.tunnel_dst_ipv4_addr,
                                event.tunnel_dst_ipv6_addr,
                            );
                            let inner_src_ip = format_ip(
                                event.ip_addr_type,
                                event.src_ipv4_addr,
                                event.src_ipv6_addr,
                            );
                            let inner_dst_ip = format_ip(
                                event.ip_addr_type,
                                event.dst_ipv4_addr,
                                event.dst_ipv6_addr,
                            );
                            let tunnel_src_port = u16::from_be_bytes(event.tunnel_src_port);
                            let tunnel_dst_port = u16::from_be_bytes(event.tunnel_dst_port);

                            info!(
                                "Tunneled {} packet: {} | Tunnel: {}:{} -> {}:{} ({}) | Inner: {}:{} -> {}:{} | bytes: {}",
                                event.proto,
                                community_id,
                                tunnel_src_ip,
                                tunnel_src_port,
                                tunnel_dst_ip,
                                tunnel_dst_port,
                                event.tunnel_proto,
                                inner_src_ip,
                                src_port,
                                inner_dst_ip,
                                dst_port,
                                event.l3_octet_count,
                            );
                        } else {
                            let src_ip = format_ip(
                                event.ip_addr_type,
                                event.src_ipv4_addr,
                                event.src_ipv6_addr,
                            );
                            let dst_ip = format_ip(
                                event.ip_addr_type,
                                event.dst_ipv4_addr,
                                event.dst_ipv6_addr,
                            );

                            info!(
                                "{} packet: {} | {}:{} -> {}:{} | bytes: {}",
                                event.proto,
                                community_id,
                                src_ip,
                                src_port,
                                dst_ip,
                                dst_port,
                                event.l3_octet_count,
                            );
                        }

                        if let Err(e) = tx
                            .send((event, community_id, String::from(iface_name)))
                            .await
                        {
                            warn!("Failed to send packet to enrichment channel: {e}");
                        }
                    }
                    None => {
                        // Short sleep to prevent busy-looping.
                        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
                    }
                }
            }
        });

        health_state.ready_to_process.store(true, Ordering::Relaxed);
    }

    #[cfg(feature = "flow")]
    {
        use tokio::sync::mpsc;

        use crate::flow::FlowProducer;

        let (_packet_event_tx, packet_event_rx) = mpsc::channel(config.packet_channel_capacity);
        let (flow_event_tx, _flow_event_rx) = mpsc::channel(config.packet_channel_capacity);
        let flow_producer = FlowProducer::new(
            config.flow,
            config.packet_channel_capacity,
            config.packet_worker_count,
            packet_event_rx,
            flow_event_tx,
        );
        tokio::spawn(async move {
            flow_producer.run().await;
        });

        let task_iface_map = Arc::clone(&iface_map);
        tokio::spawn(async move {
            info!("Userspace task started. Polling the ring buffer...");
            loop {
                match ring_buf.next() {
                    Some(bytes) => {
                        let event: PacketMeta = unsafe {
                            core::ptr::read_unaligned(bytes.as_ptr() as *const PacketMeta)
                        };

                        let iface_name = task_iface_map
                            .get(&event.ifindex)
                            .map(String::as_str)
                            .unwrap_or("unknown_if");

                        // Helper function to format IP address based on type
                        let format_ip = |addr_type: IpAddrType,
                                         ipv4_addr: [u8; 4],
                                         ipv6_addr: [u8; 16]|
                         -> String {
                            match addr_type {
                                IpAddrType::Ipv4 => Ipv4Addr::from(ipv4_addr).to_string(),
                                IpAddrType::Ipv6 => Ipv6Addr::from(ipv6_addr).to_string(),
                            }
                        };

                        // Extract port numbers
                        let src_port = u16::from_be_bytes(event.src_port);
                        let dst_port = u16::from_be_bytes(event.dst_port);

                        let community_id = match event.ip_addr_type {
                            IpAddrType::Ipv4 => community_id_generator.generate(
                                IpAddr::V4(Ipv4Addr::from(event.src_ipv4_addr)),
                                IpAddr::V4(Ipv4Addr::from(event.dst_ipv4_addr)),
                                src_port,
                                dst_port,
                                event.proto,
                            ),
                            IpAddrType::Ipv6 => community_id_generator.generate(
                                IpAddr::V6(Ipv6Addr::from(event.src_ipv6_addr)),
                                IpAddr::V6(Ipv6Addr::from(event.dst_ipv6_addr)),
                                src_port,
                                dst_port,
                                event.proto,
                            ),
                        };

                        info!(
                            "Received packet to parse for Community ID {community_id} on interface {iface_name}"
                        );

                        // Check if this is tunneled traffic
                        let is_tunneled = event.tunnel_src_ipv4_addr != [0; 4]
                            || event.tunnel_src_ipv6_addr != [0; 16];

                        if is_tunneled {
                            let tunnel_src_ip = format_ip(
                                event.tunnel_ip_addr_type,
                                event.tunnel_src_ipv4_addr,
                                event.tunnel_src_ipv6_addr,
                            );
                            let tunnel_dst_ip = format_ip(
                                event.tunnel_ip_addr_type,
                                event.tunnel_dst_ipv4_addr,
                                event.tunnel_dst_ipv6_addr,
                            );
                            let inner_src_ip = format_ip(
                                event.ip_addr_type,
                                event.src_ipv4_addr,
                                event.src_ipv6_addr,
                            );
                            let inner_dst_ip = format_ip(
                                event.ip_addr_type,
                                event.dst_ipv4_addr,
                                event.dst_ipv6_addr,
                            );
                            let tunnel_src_port = u16::from_be_bytes(event.tunnel_src_port);
                            let tunnel_dst_port = u16::from_be_bytes(event.tunnel_dst_port);

                            info!(
                                "Tunneled {} packet: {} | Tunnel: {}:{} -> {}:{} ({}) | Inner: {}:{} -> {}:{} | bytes: {}",
                                event.proto,
                                community_id,
                                tunnel_src_ip,
                                tunnel_src_port,
                                tunnel_dst_ip,
                                tunnel_dst_port,
                                event.tunnel_proto,
                                inner_src_ip,
                                src_port,
                                inner_dst_ip,
                                dst_port,
                                event.l3_octet_count,
                            );
                        } else {
                            let src_ip = format_ip(
                                event.ip_addr_type,
                                event.src_ipv4_addr,
                                event.src_ipv6_addr,
                            );
                            let dst_ip = format_ip(
                                event.ip_addr_type,
                                event.dst_ipv4_addr,
                                event.dst_ipv6_addr,
                            );

                            info!(
                                "{} packet: {} | {}:{} -> {}:{} | bytes: {}",
                                event.proto,
                                community_id,
                                src_ip,
                                src_port,
                                dst_ip,
                                dst_port,
                                event.l3_octet_count,
                            );
                        }
                    }
                    None => {
                        // Short sleep to prevent busy-looping.
                        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
                    }
                }
            }
        });

        // Mark system as ready to process packets
        health_state.ready_to_process.store(true, Ordering::Relaxed);
    }

    let all_systems_ready = health_state.ebpf_loaded.load(Ordering::Relaxed)
        && health_state.k8s_connected.load(Ordering::Relaxed)
        && health_state.ready_to_process.load(Ordering::Relaxed);

    health_state
        .startup_complete
        .store(all_systems_ready, Ordering::Relaxed);

    if all_systems_ready {
        info!("Startup complete - all systems ready");
    } else {
        warn!(
            "Startup completed but some systems are not ready - check readiness endpoint for details"
        );
    }

    println!("Waiting for Ctrl-C...");
    signal::ctrl_c().await?;
    println!("Exiting...");

    Ok(())
}

#[allow(dead_code)]
struct FlowRecord {
    /// Total number of packets observed for this flow since its start.
    pub packet_total_count: u64,
    /// Total number of bytes (octets) observed for this flow since its start.
    pub octet_total_count: u64,
    /// Number of packets observed in the last measurement interval.
    pub packet_delta_count: u64,
    /// Number of bytes (octets) observed in the last measurement interval.
    pub octet_delta_count: u64,

    // Fields with 4-byte alignment
    /// Timestamp (seconds since epoch) when the flow was first observed.
    pub flow_start_seconds: u32,
    /// Timestamp (seconds since epoch) when the flow was last observed or ended.
    pub flow_end_seconds: u32,
    /// Reason code indicating why the flow record was generated or ended.
    /// (e.g., 1 = Active Timeout, 2 = End of Flow detected, etc. - specific values depend on the system).
    pub flow_end_reason: u8,
    // Implicit padding (2 bytes) is added here by the compiler to ensure
    // the total struct size (88 bytes) is a multiple of the maximum alignment (8 bytes).
}
