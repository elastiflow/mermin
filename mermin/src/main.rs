mod runtime;

use std::{
    net::{Ipv4Addr, Ipv6Addr},
    sync::Arc,
};

use anyhow::anyhow;
use aya::{
    maps::RingBuf,
    programs::{SchedClassifier, TcAttachType, tc},
};
use k8s::resource_parser;
use log::{debug, info, warn};
use mermin_common::PacketMeta;
use tokio::signal;

mod k8s;

use crate::runtime::conf::Config;

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

    let kube_client_clone = kube_client.clone();
    tokio::spawn(async move {
        info!("Userspace task started. Polling the ring buffer...");
        loop {
            match ring_buf.next() {
                Some(bytes) => {
                    let event: PacketMeta =
                        unsafe { core::ptr::read_unaligned(bytes.as_ptr() as *const PacketMeta) };
                    let protocol_name = match event.proto {
                        1 => "ICMP",
                        6 => "TCP",
                        17 => "UDP",
                        58 => "ICMPv6",
                        _ => "Other",
                    };

                    // Log differently for ICMP vs port-based protocols
                    match event.proto {
                        1 | 58 => {
                            info!(
                                "Received {} event: Src IPV6: {}, Dst IPV6: {}, Src IPV4: {}, Dst IPV4: {}, L3 Octect Count: {}",
                                protocol_name,
                                Ipv6Addr::from(event.src_ipv6_addr),
                                Ipv6Addr::from(event.dst_ipv6_addr),
                                Ipv4Addr::from(event.src_ipv4_addr),
                                Ipv4Addr::from(event.dst_ipv4_addr),
                                event.l3_octet_count,
                            );
                        }
                        _ => {
                            info!(
                                "Received {} event: Src IPV6: {}, Dst IPV6: {}, Src IPV4: {}, Dst IPV4: {}, L3 Octect Count: {}, Src Port: {}, Dst Port: {}",
                                protocol_name,
                                Ipv6Addr::from(event.src_ipv6_addr),
                                Ipv6Addr::from(event.dst_ipv6_addr),
                                Ipv4Addr::from(event.src_ipv4_addr),
                                Ipv4Addr::from(event.dst_ipv4_addr),
                                event.l3_octet_count,
                                u16::from_be_bytes(event.src_port),
                                u16::from_be_bytes(event.dst_port),
                            );
                        }
                    }
                    parse_packet(event, kube_client_clone.clone()).await;
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

/// Parse all available data from the packet metadata and Kubernetes resources
async fn parse_packet(event: PacketMeta, kube_client_clone: Option<Arc<k8s::Attributor>>) {
    info!("Parsing packet data...");

    // Parse packet metadata
    let (connection_info, packet_size_info) = resource_parser::parse_packet_meta(&event);

    info!("{connection_info}");
    info!("{packet_size_info}");

    println!("{connection_info}");
    println!("{packet_size_info}");

    if let Some(client) = &kube_client_clone {
        info!("Kubernetes client is available, attempting to parse pod info");

        // Get the source IPv4 address
        let src_ipv4 = Ipv4Addr::from(event.src_ipv4_addr);

        // Use the resource parsers to extract and display information
        let parsers = resource_parser::ResourceParserFactory::all_parsers();
        for parser in parsers {
            parser.parse_and_print(client, src_ipv4).await;
        }

        info!("Completed parsing all Kubernetes resources");
    } else {
        warn!("Kubernetes client is not available, skipping pod info parsing");
        println!("Kubernetes data lookup not available");
    }
}
