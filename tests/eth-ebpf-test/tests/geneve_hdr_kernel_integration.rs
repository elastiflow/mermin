//! End‑to‑end tests that load the real eBPF program, inject packets over a
//! veth pair, and confirm that the GENEVE header was parsed in‑kernel.

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

const MAP_NAME: &str = "GENEVEHDR_RESULT";
const PROGRAM_NAME: &str = "geneve_hdr_test";

async fn get_map_result(bpf: &mut Ebpf) -> Result<(u32, u32, u32, u32, u32, u32)> {
    let mut map = UserHashMap::try_from(bpf.map_mut(MAP_NAME).context("map not present")?)?;
    for _ in 0..MAX_RETRIES {
        if let Ok(ver) = map.get(&0, 0) {
            if ver != 0 {
                let opt_len = map.get(&1, 0).unwrap_or(0);
                let o_flag = map.get(&2, 0).unwrap_or(0);
                let c_flag = map.get(&3, 0).unwrap_or(0);
                let protocol_type = map.get(&4, 0).unwrap_or(0);
                let vni = map.get(&5, 0).unwrap_or(0);

                // Clean up the map for the next test run.
                let _ = map.remove(&0);
                let _ = map.remove(&1);
                let _ = map.remove(&2);
                let _ = map.remove(&3);
                let _ = map.remove(&4);
                let _ = map.remove(&5);

                return Ok((ver, opt_len, o_flag, c_flag, protocol_type, vni));
            }
        }
        sleep(RETRY_INTERVAL).await;
    }
    Ok((0, 0, 0, 0, 0, 0))
}

#[tokio::test]
async fn geneve_sets_expected_values() -> Result<()> {
    setup_logging();
    info!("--- geneve_sets_expected_values ---");
    create_veth().await?;
    let mut bpf = load_and_attach_bpf(PROGRAM_NAME)?;
    let _log = EbpfLogger::init(&mut bpf).context("eBPF logger")?;
    
    // Geneve Header (8 bytes)
    let mut payload = Vec::new();
    payload.push(0x42);                    // Version (2 bits) + Option Length (6 bits)
    payload.push(0x40);                    // Control bits + Reserved
    payload.extend_from_slice(&[0x65, 0x58]); // Protocol Type (0x6558 for IPv4)
    payload.extend_from_slice(&[0x12, 0x34, 0x56]); // VNI (24 bits)
    payload.push(0); // Reserved (8 bits)

    let sender_addr: SocketAddr = format!("[{IP1_V6}]:23456").parse()?;
    let sock = create_socket_for_sender(sender_addr)?;

    info!(
        "Sending {}-byte Geneve header to [{IP0_V6}]:443",
        payload.len()
    );
    sock.send_to(&payload, format!("[{IP0_V6}]:443"))?;
    sleep(Duration::from_millis(200)).await;

    let (version, opt_len, o_flag, c_flag, protocol_type, vni) = get_map_result(&mut bpf).await?;
    info!(
        "Map result: version={} opt_len={} o_flag={} c_flag={} protocol_type={} vni={}",
        version, opt_len, o_flag, c_flag, protocol_type, vni
    );
    assert_eq!(version, 1, "Geneve version");
    assert_eq!(opt_len, 2, "Option length");
    assert_eq!(o_flag, 0, "O flag");
    assert_eq!(c_flag, 1, "C flag");
    assert_eq!(protocol_type, 0x6558, "Protocol type");
    assert_eq!(vni.to_be_bytes(), [0, 0x12, 0x34, 0x56], "VNI");

    destroy_veth();
    Ok(())
}