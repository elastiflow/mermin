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
use socket2::{Domain, Socket, Type};
use tokio::time::sleep;

mod common;
use common::*;

const MAP_NAME: &str = "QUICHDR_RESULT";
const PROGRAM_NAME: &str = "quic_hdr_test";
pub const SHORT_HEADER_MARKER: u32 = 2;

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
    let mut bpf = load_and_attach_bpf(PROGRAM_NAME)?;
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
    let token = [0xde, 0xad, 0xbe, 0xef];
    payload.push(token.len() as u8); // Token Length (variable-length integer)
    payload.extend_from_slice(&token); // Token

    // The length of the packet number and the payload.
    // Packet number is 1 byte, payload is 1 byte, so length is 2.
    payload.push(2); // Length
    payload.push(1); // Packet Number
    payload.push(0x06); // Dummy payload: A CRYPTO frame starts with the byte 0x06.
    info!("{:?}", payload);
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
    let mut bpf = load_and_attach_bpf(PROGRAM_NAME)?;
    let _log = EbpfLogger::init(&mut bpf).context("eBPF logger")?;
    const DCID: [u8; 8] = [0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02, 0x03, 0x04];
    let mut payload = vec![0x44];
    payload.extend_from_slice(&DCID);
    payload.push(0x01); // Add a 1-byte packet number
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