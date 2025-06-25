//! End‑to‑end tests that load the real eBPF program, inject packets over a
//! veth pair, and confirm that the QUIC header was parsed in‑kernel.

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
use network_types::quic::{QuicHdr, QUIC_MAX_CID_LEN};
use socket2::{Domain, Socket, Type};
use tokio::time::sleep;

const BPF_ELF: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../target/bpfel-unknown-none/release/eth-ebpf-test"
);
const MAP_NAME: &str = "QUICHDR_RESULT";
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
        .program_mut("quic_hdr_test")
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

async fn get_map_result(bpf: &mut Ebpf) -> Result<(u32, u32, u32)> {
    let mut map = UserHashMap::try_from(bpf.map_mut(MAP_NAME).context("map not present")?)?;
    for _ in 0..MAX_RETRIES {
        if let Ok(ver) = map.get(&0, 0) {
            if ver != 0 {
                let dcil = map.get(&1, 0).unwrap_or(0);
                let scil = map.get(&2, 0).unwrap_or(0);
                let _ = map.remove(&0);
                let _ = map.remove(&1);
                let _ = map.remove(&2);
                return Ok((ver, dcil, scil));
            }
        }
        sleep(RETRY_INTERVAL).await;
    }
    Ok((0, 0, 0))
}

#[tokio::test]
async fn long_header_ipv6_sets_expected_values() -> Result<()> {
    setup_logging();
    info!("--- long_header_ipv6_sets_expected_values ---");
    create_veth().await?;
    let mut bpf = load_and_attach()?;
    let _log = EbpfLogger::init(&mut bpf).context("eBPF logger")?;
    let dcid = [0xAA, 0xBB, 0xCC, 0xDD, 0xDD, 0xDD, 0xDD, 0xDD, 0xDD, 0xDD, 0xDD, 0xDD, 0xDD, 0xDD, 0xDD, 0xDD];
    let scid = [0x11, 0x22, 0x33, 0x44];
    let mut payload = Vec::<u8>::new();
    // A valid QUIC Initial packet header without padding, similar to a live packet.
    payload.push(0b1100_0000); // Long Header: Initial Packet, Packet Number Length: 1 byte
    payload.extend_from_slice(&1u32.to_be_bytes()); // Version: 1
    payload.push(dcid.len() as u8); // DCID Len
    payload.extend_from_slice(&dcid); // DCID
    payload.push(scid.len() as u8); // SCID Len
    payload.extend_from_slice(&scid); // SCID
    payload.push(0); // Token Length (variable-length integer, 0)

    // Length of the rest of the packet (Packet Number + Payload + Auth Tag).
    // Let's assume a 1-byte packet number and a 1-byte payload (a minimal CRYPTO frame starts with 0x06).
    // The AEAD auth tag for Initial packets is 16 bytes.
    // Total length = 1 (PN) + 1 (Payload) + 16 (Tag) = 18.
    payload.push(18);
    payload.push(1); // Packet Number
    payload.push(0x06); // Dummy payload: A CRYPTO frame starts with the byte 0x06.

    // Note: A real client Initial packet would be padded to at least 1200 bytes.
    info!("{:?}", payload);
    //assert_eq!(payload.len(), QuicHdr::LEN);
    let sender_addr: SocketAddr = format!("[{IP1_V6}]:12345").parse()?;
    let sock = create_socket_for_sender(sender_addr)?;
    info!(
        "Sending {}-byte long-header to [{IP0_V6}]:443",
        payload.len()
    );
    sock.send_to(&payload, format!("[{IP0_V6}]:443"))?;
    sleep(Duration::from_millis(200)).await;
    let (ver, dcil, scil) = get_map_result(&mut bpf).await?;
    info!("Map result: v={} dcil={} scil={}", ver, dcil, scil);
    assert_eq!(ver, 1, "version");
    assert_eq!(dcil as usize, dcid.len(), "DCID length");
    assert_eq!(scil as usize, scid.len(), "SCID length");
    destroy_veth();
    Ok(())
}

#[tokio::test]
async fn short_header_ipv6_sets_expected_values() -> Result<()> {
    setup_logging();
    info!("--- short_header_ipv6_sets_expected_values ---");
    create_veth().await?;
    let mut bpf = load_and_attach()?;
    let _log = EbpfLogger::init(&mut bpf).context("eBPF logger")?;
    const DCID: [u8; 8] = [0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02, 0x03, 0x04];
    let mut payload = vec![0x44];
    payload.extend_from_slice(&DCID);
    //assert_eq!(payload.len(), QuicHdr::LEN);
    let sender_addr: SocketAddr = format!("[{IP1_V6}]:23456").parse()?;
    let sock = create_socket_for_sender(sender_addr)?;
    info!(
        "Sending {}-byte short-header to [{IP0_V6}]:443",
        payload.len()
    );
    sock.send_to(&payload, format!("[{IP0_V6}]:443"))?;
    sleep(Duration::from_millis(200)).await;
    let (marker, dcil, scil) = get_map_result(&mut bpf).await?;
    info!("Map result: m={} dcil={} scil={}", marker, dcil, scil);
    assert_eq!(marker, SHORT_HEADER_MARKER, "marker for short header");
    assert_eq!(dcil as usize, DCID.len(), "DCID length");
    assert_eq!(scil, 0, "SCID length");
    destroy_veth();
    Ok(())
}