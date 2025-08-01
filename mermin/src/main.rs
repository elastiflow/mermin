use aya::{
    maps::RingBuf,
    programs::{SchedClassifier, TcAttachType, tc},
};
use clap::Parser;
#[rustfmt::skip]
use log::{debug, info, warn};
use mermin_common::{IpAddrType, PacketMeta};
use std::time::Duration;
use tokio::signal;

#[derive(Debug, Parser)]
struct Opt {
    #[clap(short, long, default_value = "eth0")]
    iface: String,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let opt = Opt::parse();

    env_logger::init();

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
    let Opt { iface } = opt;
    // error adding clsact to the interface if it is already added is harmless
    // the full cleanup can be done with 'sudo tc qdisc del dev eth0 clsact'.
    let _ = tc::qdisc_add_clsact(&iface);
    let program: &mut SchedClassifier = ebpf.program_mut("mermin").unwrap().try_into()?;
    program.load()?;
    program.attach(&iface, TcAttachType::Egress)?;

    info!("eBPF program attached. Waiting for events... Press Ctrl-C to exit.");

    let map_ref_mut = ebpf.map_mut("PACKETS").unwrap();
    let mut ring_buf = RingBuf::try_from(map_ref_mut)?;

    // Start consuming events
    tokio::spawn(async move {
        while let Some(bytes) = ring_buf.next().await {
            let event: PacketMeta =
                unsafe { core::ptr::read_unaligned(bytes.as_ptr() as *const PacketMeta) };
            println!("Received event: {:?}", event);
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
