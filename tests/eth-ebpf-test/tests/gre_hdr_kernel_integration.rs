//! End‑to‑end tests that load the real eBPF program, inject packets over a
//! veth pair, and confirm that the Gre header was parsed in‑kernel.

use std::{
    net::{SocketAddr, UdpSocket},
    process::Command,
    sync::Once,
    time::Duration,
};

use anyhow::{Context, Result};
use aya::{
    maps::HashMap as UserHashMap,
    programs::{SchedClassifier, TcAttachType},
    Ebpf,
};
use aya_log::EbpfLogger;
use log::{error, info};
use socket2::{Domain, Socket, Type};
use tokio::time::sleep;

const BPF_ELF: &str = concat!(
env!("CARGO_MANIFEST_DIR"),
"/../target/bpfel-unknown-none/release/eth-ebpf-test"
);

const GRE_MAP_NAME: &str = "GREHDR_RESULT";
const RETRY_INTERVAL: Duration = Duration::from_millis(100);
const MAX_RETRIES: u32 = 20;

const SHORT_HEADER_MARKER: u32 = 2;

const IP0_V4: &str = "10.42.0.1";
const IP1_V4: &str = "10.42.0.2";
const IP0_V6: &str = "fc00:42::1";
const IP1_V6: &str = "fc00:42::2";

static LOG_INIT: Once = Once::new();

fn setup_logging() {
    LOG_INIT.call_once(|| {
        env_logger::builder()
            .filter_level(log::LevelFilter::Info)
            .init();
    });
}

fn run(cmd: &mut Command) -> Result<()> {
    info!("Running command: {:?}", cmd);
    let status = cmd.status().with_context(|| format!("failed: {:?}", cmd))?;
    if !status.success() {
        error!("Command failed with status {}: {:?}", status, cmd);
        anyhow::bail!("command {:?} failed: {status}", cmd);
    }
    Ok(())
}

fn destroy_veth() {
    info!("Destroying veth pair...");
    let _ = Command::new("tc")
        .args(["qdisc", "del", "dev", "veth0", "clsact"])
        .status();
    let _ = Command::new("tc")
        .args(["qdisc", "del", "dev", "veth1", "clsact"])
        .status();
    let _ = Command::new("ip").args(["link", "del", "veth0"]).status();
    std::thread::sleep(Duration::from_millis(50));
    info!("Veth pair destroyed.");
}

async fn create_veth() -> Result<()> {
    info!("Creating veth pair...");
    destroy_veth();

    run(Command::new("ip").args([
        "link", "add", "veth0", "type", "veth", "peer", "name", "veth1",
    ]))?;
    run(Command::new("ip").args(["addr", "add", &format!("{IP0_V4}/24"), "dev", "veth0"]))?;
    run(Command::new("ip").args(["addr", "add", &format!("{IP1_V4}/24"), "dev", "veth1"]))?;
    run(Command::new("ip").args([
        "-6",
        "addr",
        "add",
        &format!("{IP0_V6}/64"),
        "dev",
        "veth0",
        "nodad",
    ]))?;
    run(Command::new("ip").args([
        "-6",
        "addr",
        "add",
        &format!("{IP1_V6}/64"),
        "dev",
        "veth1",
        "nodad",
    ]))?;

    run(Command::new("ip").args(["link", "set", "veth0", "up"]))?;
    run(Command::new("ip").args(["link", "set", "veth1", "up"]))?;

    run(Command::new("tc").args(["qdisc", "add", "dev", "veth0", "clsact"]))?;
    run(Command::new("tc").args(["qdisc", "add", "dev", "veth1", "clsact"]))?;

    info!("Priming neighbour caches…");
    run(Command::new("ping").args(["-c", "1", "-W", "1", "-I", IP1_V4, IP0_V4]))?;
    run(Command::new("ping").args(["-c", "1", "-W", "1", "-I", IP0_V4, IP1_V4]))?;
    run(Command::new("ping6").args(["-c", "1", "-W", "1", "-I", IP1_V6, IP0_V6]))?;
    run(Command::new("ping6").args(["-c", "1", "-W", "1", "-I", IP0_V6, IP1_V6]))?;

    sleep(Duration::from_millis(200)).await;
    info!("Veth setup complete.");
    Ok(())
}

fn load_and_attach() -> Result<Ebpf> {
    info!("Loading eBPF program from: {}", BPF_ELF);
    let mut bpf = Ebpf::load_file(BPF_ELF).context("load BPF object")?;

    let prog: &mut SchedClassifier = bpf
        .program_mut("gre_hdr_test")
        .context("program not found")?
        .try_into()?;

    prog.load()?;
    prog.attach("veth0", TcAttachType::Ingress)?;
    info!("eBPF program loaded and attached successfully.");
    Ok(bpf)
}

/// Creates a socket bound to a specific interface (`veth1`).
fn create_socket_for_sender(addr: SocketAddr) -> Result<UdpSocket> {
    let socket = Socket::new(
        if addr.is_ipv4() {
            Domain::IPV4
        } else {
            Domain::IPV6
        },
        Type::DGRAM,
        None,
    )?;
    socket.bind_device(Some(b"veth1\0"))?;
    socket.bind(&addr.into())?;
    Ok(socket.into())
}

async fn get_gre_map_result(bpf: &mut Ebpf) -> Result<(u32, u32, u32, u32, u32, u32)> {
    // Return flags, version, protocol, checksum, key, sequence from kernel space map
    let mut map = UserHashMap::try_from(bpf.map_mut(GRE_MAP_NAME).context("gre map not present")?)?;
    for _ in 0..MAX_RETRIES {
        // Check for a value at key 0. We assume key 0 is always populated
        // when the map contains a result.
        if let Ok(val) = map.get(&0, 0) {
            // A non-zero value indicates the map is ready to be read.
            if val != 0 {
                let flgs = map.get(&0, 0).unwrap_or(0);
                let ver = map.get(&1, 0).unwrap_or(0);
                let proto = map.get(&2, 0).unwrap_or(0);
                let cks = map.get(&3, 0).unwrap_or(0);
                let key = map.get(&4, 0).unwrap_or(0);
                let seq = map.get(&5, 0).unwrap_or(0);

                // Clean up the map for the next test run.
                let _ = map.remove(&0);
                let _ = map.remove(&1);
                let _ = map.remove(&2);
                let _ = map.remove(&3);
                let _ = map.remove(&4);
                let _ = map.remove(&5);

                return Ok((flgs, ver, proto, cks, key, seq));
            }
        }
        sleep(RETRY_INTERVAL).await;
    }
    Ok((0, 0, 0, 0, 0, 0))
}

#[tokio::test]
async fn gre_expected_values_all_flags_on() -> Result<()> {
    setup_logging();
    info!("--- gre_expected_values ---");
    create_veth().await?;
    let mut bpf = load_and_attach()?;
    let _log = EbpfLogger::init(&mut bpf).context("eBPF logger")?;

    // Payload should be 4 total bytes
    let mut payload = Vec::<u8>::new();
    //  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    //  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    //  |C| |K|S| Reserved0       | Ver |         Protocol Type         |
    //  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    //  |      Checksum (optional)      |       Reserved1 (Optional)    |
    //  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    //  |                         Key (optional)                        |
    //  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    //  |                 Sequence Number (Optional)                    |
    //  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

    let flags_and_version: u16 = 0x8001;
    payload.extend_from_slice(&flags_and_version.to_be_bytes());

    // --- Word 1 (Bytes 2-3): Protocol Type ---
    // The protocol type for IPv6 is `0x86DD`.
    let protocol_type: u16 = 0x86DD;
    payload.extend_from_slice(&protocol_type.to_be_bytes());

    // --- Word 2 (Bytes 4-5): Checksum ---
    // Since the C flag is set, the Checksum and Reserved1 fields are present.
    // The checksum is requested to be all 1s.
    let checksum: u16 = 0xFFFF;
    payload.extend_from_slice(&checksum.to_be_bytes());

    // --- Word 3 (Bytes 6-7): Reserved1 ---
    // This field is present along with the checksum. It's set to zero.
    let reserved1: u16 = 0x0000;
    payload.extend_from_slice(&reserved1.to_be_bytes());

    let sender_addr: SocketAddr = format!("[{IP1_V6}]:23456").parse()?;
    let sock = create_socket_for_sender(sender_addr)?;

    info!(
        "Sending {}-byte gre header to [{IP0_V6}]:443",
        payload.len()
    );
    sock.send_to(&payload, format!("[{IP0_V6}]:443"))?;
    sleep(Duration::from_millis(200)).await;

    let (flags, version, proto, checksum, key, sequence)= get_gre_map_result(&mut bpf).await?;

    info!("flags:     Decimal: {} \tHex: {:#04x}", flags, flags);
    info!("version:   Decimal: {} \tHex: {:#04x}", version, version);
    info!("proto:     Decimal: {} \tHex: {:#06x}", proto, proto);
    info!("checksum:  Decimal: {} \tHex: {:#010x}", checksum, checksum);
    info!("key:       Decimal: {} \tHex: {:#010x}", key, key);
    info!("sequence:  Decimal: {} \tHex: {:#010x}", sequence, sequence);

    assert_eq!(flags, 0x80, "flags");
    assert_eq!(version, 0x1, "version");
    assert_eq!(proto, 0x86DD, "protocol type");
    assert_eq!(checksum, 0xFFFF0000, "checksum");
    assert_eq!(key, 0x0, "key");
    assert_eq!(sequence, 0x0, "sequence");

    destroy_veth();
    Ok(())
}
