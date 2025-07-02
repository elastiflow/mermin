//! End‑to‑end tests that load the real eBPF program, inject packets over a
//! veth pair, and confirm that the OSPF header was parsed in‑kernel.

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

const MAP_NAME: &str = "OSPFHDR_RESULT";
const PROGRAM_NAME: &str = "ospf_hdr_test";

async fn get_map_result(bpf: &mut Ebpf) -> Result<(u32, u32, u32, u32, u32, u32, u32, u32)> {
    let mut map = UserHashMap::try_from(bpf.map_mut(MAP_NAME).context("map not present")?)?;
    for _ in 0..MAX_RETRIES {
        if let Ok(ver) = map.get(&0, 0) {
            if ver != 0 {
                let packet_type = map.get(&1, 0).unwrap_or(0);
                let length = map.get(&2, 0).unwrap_or(0);
                let router_id = map.get(&3, 0).unwrap_or(0);
                let area_id = map.get(&4, 0).unwrap_or(0);
                let checksum = map.get(&5, 0).unwrap_or(0);
                let custom1 = map.get(&6, 0).unwrap_or(0);
                let custom2 = map.get(&7, 0).unwrap_or(0);

                // Clean up the map for the next test run.
                let _ = map.remove(&0);
                let _ = map.remove(&1);
                let _ = map.remove(&2);
                let _ = map.remove(&3);
                let _ = map.remove(&4);
                let _ = map.remove(&5);
                let _ = map.remove(&6);
                let _ = map.remove(&7);
                
                return Ok((ver, packet_type, length, router_id, area_id, checksum, custom1, custom2));
            }
        }
        sleep(RETRY_INTERVAL).await;
    }
    Ok((0, 0, 0, 0, 0, 0, 0, 0))
}

#[tokio::test]
async fn ospfv2_sets_expected_values() -> Result<()> {
    setup_logging();
    info!("--- ospfv2_sets_expected_values ---");
    create_veth().await?;
    let mut bpf = load_and_attach_bpf(PROGRAM_NAME)?;
    let _log = EbpfLogger::init(&mut bpf).context("eBPF logger")?;

    // OSPF Header (24 bytes)
    let mut payload = Vec::new();
    payload.push(2);                    // Version 2
    payload.push(1);                    // Hello packet type
    payload.extend_from_slice(&[0, 44]); // Packet length (BE)
    payload.extend_from_slice(&[192, 168, 1, 1]); // Router ID
    payload.extend_from_slice(&[0, 0, 0, 0]);     // Area ID
    payload.extend_from_slice(&[0, 0]);           // Checksum
    payload.extend_from_slice(&[0, 0]);           // AuType
    payload.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 0]); // Authentication

    let sender_addr: SocketAddr = format!("[{IP1_V6}]:23456").parse()?;
    let sock = create_socket_for_sender(sender_addr)?;

    info!(
        "Sending {}-byte ospfv2 header to [{IP0_V6}]:443",
        payload.len()
    );
    sock.send_to(&payload, format!("[{IP0_V6}]:443"))?;
    sleep(Duration::from_millis(200)).await;

    let (version, packet_type, length, router_id, area_id, checksum, au_type, auth) = get_map_result(&mut bpf).await?;
    info!("Map result: version={} type={} length={} router={} area={} checksum={} auth type={} auth={}", version, packet_type, length, router_id, area_id, checksum, au_type, auth);
    assert_eq!(version, 2, "OSPF version");
    assert_eq!(packet_type, 1, "OSPF packet type");
    assert_eq!(length, 44, "OSPF packet length");
    assert_eq!(router_id.to_be_bytes(), [192, 168, 1, 1], "Router ID");
    assert_eq!(area_id.to_be_bytes(), [0, 0, 0, 0], "Area ID");
    assert_eq!(checksum, 0, "OSPF checksum");
    assert_eq!(au_type, 0, "OSPF authentication type");
    assert_eq!(auth, 0, "OSPF authentication");

    destroy_veth();
    Ok(())
}

#[tokio::test]
async fn ospfv3_sets_expected_values() -> Result<()> {
    setup_logging();
    info!("--- ospfv3_sets_expected_values ---");
    create_veth().await?;
    let mut bpf = load_and_attach_bpf(PROGRAM_NAME)?;
    let _log = EbpfLogger::init(&mut bpf).context("eBPF logger")?;

    // OSPF Header (16 bytes)
    let mut payload = Vec::new();
    payload.push(3);                    // Version 3
    payload.push(1);                    // Hello packet type
    payload.extend_from_slice(&[0, 24]); // Packet length (BE)
    payload.extend_from_slice(&[1, 1, 1, 1]); // Router ID
    payload.extend_from_slice(&[0, 0, 0, 1]);     // Area ID
    payload.extend_from_slice(&[0xFB, 0x86]);           // Checksum
    payload.extend_from_slice(&[0]);           // Instance ID
    payload.extend_from_slice(&[0]); // Reserved

    let sender_addr: SocketAddr = format!("[{IP1_V6}]:23456").parse()?;
    let sock = create_socket_for_sender(sender_addr)?;

    info!(
        "Sending {}-byte ospfV3 header to [{IP0_V6}]:443",
        payload.len()
    );
    sock.send_to(&payload, format!("[{IP0_V6}]:443"))?;
    sleep(Duration::from_millis(200)).await;

    let (version, packet_type, length, router_id, area_id, checksum, instance, res) = get_map_result(&mut bpf).await?;
    info!("Map result: version={} type={} length={} router={} area={} checksum={} instance={} res={}", version, packet_type, length, router_id, area_id, checksum, instance, res);
    assert_eq!(version, 3, "OSPF version");
    assert_eq!(packet_type, 1, "OSPF packet type");
    assert_eq!(length, 24, "OSPF packet length");
    assert_eq!(router_id.to_be_bytes(), [1, 1, 1, 1], "Router ID");
    assert_eq!(area_id.to_be_bytes(), [0, 0, 0, 1], "Area ID");
    assert_eq!(checksum, 0xFB86, "OSPF checksum");
    assert_eq!(instance, 0, "OSPF instance ID");
    assert_eq!(res, 0, "OSPF reserved");

    destroy_veth();
    Ok(())
}