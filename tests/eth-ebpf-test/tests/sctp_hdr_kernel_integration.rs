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

mod common;
use common::*;


const MAP_NAME: &str = "SCTPHDR_RESULT";
const PROGRAM_NAME: &str = "sctp_hdr_test";

/// Reads GRE header parsing results from the eBPF map.
/// It waits for the map to be populated and then clears it.
///
/// Returns (flags, version, protocol, checksum, key, sequence)
async fn get_sctp_map_result(bpf: &mut Ebpf) -> Result<(u32, u32, u32, u32)> {
    // Return flags, version, protocol, checksum, key, sequence from kernel space map
    let mut map = UserHashMap::try_from(bpf.map_mut(MAP_NAME).context("sctp map not present")?)?;
    for _ in 0..MAX_RETRIES {
        // Check for a value at key 0. We assume key 0 is always populated
        // when the map contains a result.
        if let Ok(src) = map.get(&0, 0) {
            // A non-zero value indicates the map is ready to be read.
            if src != 0 {
                let dst = map.get(&1, 0).unwrap_or(0);
                let ver_tag = map.get(&2, 0).unwrap_or(0);
                let cks = map.get(&3, 0).unwrap_or(0);

                // Clean up the map for the next test run.
                let _ = map.remove(&0);
                let _ = map.remove(&1);
                let _ = map.remove(&2);
                let _ = map.remove(&3);

                return Ok((src, dst, ver_tag, cks));
            }
        }
        sleep(RETRY_INTERVAL).await;
    }
    Ok((0, 0, 0, 0))
}

#[tokio::test]
async fn sctp_sets_expected_values() -> Result<()> {
    setup_logging();
    info!("--- sctp_sets_expected_values ---");
    create_veth().await?;
    let mut bpf = load_and_attach_bpf(PROGRAM_NAME)?;
    let _log = EbpfLogger::init(&mut bpf).context("eBPF logger")?;

    // SCTP Common Header (12 bytes)
    let mut payload = Vec::new();
    payload.extend_from_slice(&[0x12, 0x34]);     // Source Port (4660)
    payload.extend_from_slice(&[0x45, 0x67]);     // Destination Port (17767)
    payload.extend_from_slice(&[0x00, 0x00, 0x00, 0x01]); // Verification Tag
    payload.extend_from_slice(&[0x62, 0xE7, 0xF6, 0x17]); // Checksum

    let sender_addr: SocketAddr = format!("[{IP1_V6}]:23456").parse()?;
    let sock = create_socket_for_sender(sender_addr)?;

    info!(
    "Sending {}-byte SCTP common header to [{IP0_V6}]:443",
    payload.len()
);
    sock.send_to(&payload, format!("[{IP0_V6}]:443"))?;
    sleep(Duration::from_millis(200)).await;

    let (src_port, dst_port, ver_tag, checksum) = get_sctp_map_result(&mut bpf).await?;
    info!("Map result: source_port={} destination_port={} verification_tag={} checksum={}",
    src_port, dst_port, ver_tag, checksum);
    assert_eq!(src_port, 0x1234, "SCTP source port");
    assert_eq!(dst_port, 0x4567, "SCTP destination port");
    assert_eq!(ver_tag.to_be_bytes(), [0x00, 0x00, 0x00, 0x01], "SCTP verification tag");
    assert_eq!(checksum.to_be_bytes(), [0x62, 0xE7, 0xF6, 0x17], "SCTP checksum");

    destroy_veth();
    Ok(())
}
