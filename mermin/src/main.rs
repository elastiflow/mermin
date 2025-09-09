mod community_id;
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
    community_id::CommunityIdGenerator, k8s::resource_parser::parse_packet, runtime::conf::Config,
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

    let (tx, mut rx) = tokio::sync::mpsc::channel::<(PacketMeta, String)>(1024);

    let kube_client_clone = kube_client.clone();

    tokio::spawn(async move {
        while let Some((event, community_id)) = rx.recv().await {
            info!("Received packet to parse for Community ID {community_id}");
            if let Some(client) = &kube_client_clone {
                let enriched_packet = parse_packet(&event, client, community_id).await;
                info!("Enriched packet: {enriched_packet:?}");
            } else {
                info!(
                    "Skipping packet enrichment for Community ID {community_id}: Kubernetes client not available"
                );
            }
        }
    });

    tokio::spawn(async move {
        info!("Userspace task started. Polling the ring buffer...");
        loop {
            match ring_buf.next() {
                Some(bytes) => {
                    let event: PacketMeta =
                        unsafe { core::ptr::read_unaligned(bytes.as_ptr() as *const PacketMeta) };
                    let community_id = match event.ip_addr_type {
                        IpAddrType::Ipv4 => community_id_generator.generate(
                            IpAddr::V4(Ipv4Addr::from(event.src_ipv4_addr)),
                            IpAddr::V4(Ipv4Addr::from(event.dst_ipv4_addr)),
                            u16::from_be_bytes(event.src_port),
                            u16::from_be_bytes(event.dst_port),
                            event.proto,
                        ),
                        IpAddrType::Ipv6 => community_id_generator.generate(
                            IpAddr::V6(Ipv6Addr::from(event.src_ipv6_addr)),
                            IpAddr::V6(Ipv6Addr::from(event.dst_ipv6_addr)),
                            u16::from_be_bytes(event.src_port),
                            u16::from_be_bytes(event.dst_port),
                            event.proto,
                        ),
                    };

                    // Check if this is tunneled traffic (tunnel headers present)
                    let is_tunneled = event.tunnel_src_ipv4_addr != [0; 4]
                        || event.tunnel_src_ipv6_addr != [0; 16];

                    if is_tunneled {
                        // Log tunneled traffic with both tunnel and inner headers
                        match (event.tunnel_ip_addr_type, event.ip_addr_type) {
                            (IpAddrType::Ipv4, IpAddrType::Ipv4) => {
                                info!(
                                    "Received {} packet (TUNNELED): Community ID: {}, Outer: {}:{} -> {}:{} ({}), Inner: {}:{} -> {}:{} ({}), L3 Octet Count: {}",
                                    event.proto,
                                    community_id,
                                    Ipv4Addr::from(event.tunnel_src_ipv4_addr),
                                    event.tunnel_src_port(),
                                    Ipv4Addr::from(event.tunnel_dst_ipv4_addr),
                                    event.tunnel_dst_port(),
                                    event.tunnel_proto,
                                    Ipv4Addr::from(event.src_ipv4_addr),
                                    event.src_port(),
                                    Ipv4Addr::from(event.dst_ipv4_addr),
                                    event.dst_port(),
                                    event.proto,
                                    event.l3_octet_count,
                                );
                            }
                            (IpAddrType::Ipv4, IpAddrType::Ipv6) => {
                                info!(
                                    "Received {} packet (TUNNELED): Community ID: {}, Outer: {}:{} -> {}:{} ({}), Inner: {}:{} -> {}:{} ({}), L3 Octet Count: {}",
                                    event.proto,
                                    community_id,
                                    Ipv4Addr::from(event.tunnel_src_ipv4_addr),
                                    event.tunnel_src_port(),
                                    Ipv4Addr::from(event.tunnel_dst_ipv4_addr),
                                    event.tunnel_dst_port(),
                                    event.tunnel_proto,
                                    Ipv6Addr::from(event.src_ipv6_addr),
                                    event.src_port(),
                                    Ipv6Addr::from(event.dst_ipv6_addr),
                                    event.dst_port(),
                                    event.proto,
                                    event.l3_octet_count,
                                );
                            }
                            (IpAddrType::Ipv6, IpAddrType::Ipv4) => {
                                info!(
                                    "Received {} packet (TUNNELED): Community ID: {}, Outer: {}:{} -> {}:{} ({}), Inner: {}:{} -> {}:{} ({}), L3 Octet Count: {}",
                                    event.proto,
                                    community_id,
                                    Ipv6Addr::from(event.tunnel_src_ipv6_addr),
                                    event.tunnel_src_port(),
                                    Ipv6Addr::from(event.tunnel_dst_ipv6_addr),
                                    event.tunnel_dst_port(),
                                    event.tunnel_proto,
                                    Ipv4Addr::from(event.src_ipv4_addr),
                                    event.src_port(),
                                    Ipv4Addr::from(event.dst_ipv4_addr),
                                    event.dst_port(),
                                    event.proto,
                                    event.l3_octet_count,
                                );
                            }
                            (IpAddrType::Ipv6, IpAddrType::Ipv6) => {
                                info!(
                                    "Received {} packet (TUNNELED): Community ID: {}, Outer: {}:{} -> {}:{} ({}), Inner: {}:{} -> {}:{} ({}), L3 Octet Count: {}",
                                    event.proto,
                                    community_id,
                                    Ipv6Addr::from(event.tunnel_src_ipv6_addr),
                                    event.tunnel_src_port(),
                                    Ipv6Addr::from(event.tunnel_dst_ipv6_addr),
                                    event.tunnel_dst_port(),
                                    event.tunnel_proto,
                                    Ipv6Addr::from(event.src_ipv6_addr),
                                    event.src_port(),
                                    Ipv6Addr::from(event.dst_ipv6_addr),
                                    event.dst_port(),
                                    event.proto,
                                    event.l3_octet_count,
                                );
                            }
                        }
                    } else {
                        // Log non-tunneled traffic as before
                        match event.ip_addr_type {
                            IpAddrType::Ipv4 => {
                                info!(
                                    "Received {} packet: Community ID: {}, Src IPv4: {}, Dst IPv4: {}, L3 Octet Count: {}, Src Port: {}, Dst Port: {}",
                                    event.proto,
                                    community_id,
                                    Ipv4Addr::from(event.src_ipv4_addr),
                                    Ipv4Addr::from(event.dst_ipv4_addr),
                                    event.l3_octet_count,
                                    event.src_port(),
                                    event.dst_port(),
                                );
                            }
                            IpAddrType::Ipv6 => {
                                info!(
                                    "Received {} packet: Community ID: {}, Src IPv6: {}, Dst IPv6: {}, L3 Octet Count: {}, Src Port: {}, Dst Port: {}",
                                    event.proto,
                                    community_id,
                                    Ipv6Addr::from(event.src_ipv6_addr),
                                    Ipv6Addr::from(event.dst_ipv6_addr),
                                    event.l3_octet_count,
                                    event.src_port(),
                                    event.dst_port(),
                                );
                            }
                        }
                    }

                    if let Err(e) = tx.send((event, community_id)).await {
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
