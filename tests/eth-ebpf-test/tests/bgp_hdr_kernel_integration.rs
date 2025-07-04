//! End‑to‑end tests that load the real eBPF program, inject packets over a
//! veth pair, and confirm that the BGP header was parsed in‑kernel.

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

const MAP_NAME: &str = "BGPHDR_RESULT";
const PROGRAM_NAME: &str = "bgp_hdr_test";

async fn get_map_result(bpf: &mut Ebpf) -> Result<(u32, u32, u32, u32, u32, u32, u32, u32)> {
    let mut map = UserHashMap::try_from(bpf.map_mut(MAP_NAME).context("map not present")?)?;
    for _ in 0..MAX_RETRIES {
        if let Ok(msg_type) = map.get(&2, 0) {
            if msg_type != 0 {
                let marker = map.get(&0, 0).unwrap_or(0);
                let length = map.get(&1, 0).unwrap_or(0);
                let custom1 = map.get(&3, 0).unwrap_or(0);
                let custom2 = map.get(&4, 0).unwrap_or(0);
                let custom3 = map.get(&5, 0).unwrap_or(0);
                let custom4 = map.get(&6, 0).unwrap_or(0);
                let custom5 = map.get(&7, 0).unwrap_or(0);

                // Clean up the map for the next test run.
                let _ = map.remove(&0);
                let _ = map.remove(&1);
                let _ = map.remove(&2);
                let _ = map.remove(&3);
                let _ = map.remove(&4);
                let _ = map.remove(&5);
                let _ = map.remove(&6);
                let _ = map.remove(&7);

                return Ok((marker, length, msg_type, custom1, custom2, custom3, custom4, custom5));
            }
        }
        sleep(RETRY_INTERVAL).await;
    }
    Ok((0, 0, 0, 0, 0, 0, 0, 0))
}

#[tokio::test]
async fn bgp_sets_open_expected_values() -> Result<()> {
    setup_logging();
    info!("--- bgp_sets_expected_values ---");
    create_veth().await?;
    let mut bpf = load_and_attach_bpf(PROGRAM_NAME)?;
    let _log = EbpfLogger::init(&mut bpf).context("eBPF logger")?;

    // BGP Header (19 bytes)
    let mut payload = Vec::new();
    // Marker (16 bytes of 0xFF)
    payload.extend_from_slice(&[0xFF; 16]);
    payload.extend_from_slice(&[0, 0x2D]); // Length (45 bytes)
    payload.push(1); // Type (OPEN)
    payload.push(4); // Version
    payload.extend_from_slice(&[0xFE, 0x4C]); // My AS (65,100)
    payload.extend_from_slice(&[0x00, 0xB4]); // Hold time (180)
    payload.extend_from_slice(&[0x0A, 0x00, 0x00, 0x01]); // BGP Identifier
    payload.push(16); // Opt Parameter Length

    let sender_addr: SocketAddr = format!("[{IP1_V6}]:23456").parse()?;
    let sock = create_socket_for_sender(sender_addr)?;

    info!(
        "Sending {}-byte BGP header to [{IP0_V6}]:443",
        payload.len()
    );
    sock.send_to(&payload, format!("[{IP0_V6}]:443"))?;
    sleep(Duration::from_millis(200)).await;

    let (marker, length, msg_type, version, my_as, hold_time, bgp_id, opt_param_len) = get_map_result(&mut bpf).await?;
    info!("Map result: marker={} length={} type={} version={} my_as={} hold_time={} bgp_id={} opt_param_len={}", marker, length, msg_type, version, my_as, hold_time, bgp_id, opt_param_len);
    assert_eq!(marker, 0xFF, "First byte of marker");
    assert_eq!(length, 45, "Message length");
    assert_eq!(msg_type, 1, "Message type (OPEN)");
    assert_eq!(version, 4, "Version");
    assert_eq!(my_as, 65100, "My AS");
    assert_eq!(hold_time, 180, "Hold time");
    assert_eq!(bgp_id.to_be_bytes(), [0x0A, 0x00, 0x00, 0x01], "BGP Identifier");
    assert_eq!(opt_param_len, 16, "Optional Parameter Length");

    destroy_veth();
    Ok(())
}

#[tokio::test]
async fn bgp_sets_update_expected_values() -> Result<()> {
    setup_logging();
    info!("--- bgp_sets_update_expected_values ---");
    create_veth().await?;
    let mut bpf = load_and_attach_bpf(PROGRAM_NAME)?;
    let _log = EbpfLogger::init(&mut bpf).context("eBPF logger")?;

    // BGP Header with UPDATE message
    let mut payload = Vec::new();
    // Marker (16 bytes of 0xFF)
    payload.extend_from_slice(&[0xFF; 16]);
    payload.extend_from_slice(&[0, 0x1C]); // Length (28 bytes)
    payload.push(2); // Type (UPDATE)

    // Withdrawn Routes Length (2 bytes)
    payload.extend_from_slice(&[0x00, 0x00]);

    // Total Path Attribute Length (2 bytes)
    payload.extend_from_slice(&[0x00, 0x18]);

    // Path Attributes
    payload.extend_from_slice(&[0x40, 0x01, 0x01, 0x02]); // First Path
    payload.extend_from_slice(&[0x40, 0x02, 0x0a, 0x02, 0x01, 0x00, 0x1E, 0x01, 0x02, 0x00, 0x0A, 0x00, 0x14]); // Second Path
    payload.extend_from_slice(&[0x40, 0x03, 0x04, 0x0a, 0x00, 0x00, 0x09]); // Third Path

    // Network Layer Reachability Information (NLRI)
    payload.push(0x15); // Length in bits (21)
    payload.extend_from_slice(&[0xAC, 0x10, 0x00]); // 172.16.0.0

    let sender_addr: SocketAddr = format!("[{IP1_V6}]:23456").parse()?;
    let sock = create_socket_for_sender(sender_addr)?;

    info!(
        "Sending {}-byte BGP UPDATE message to [{IP0_V6}]:443",
        payload.len()
    );
    sock.send_to(&payload, format!("[{IP0_V6}]:443"))?;
    sleep(Duration::from_millis(200)).await;

    let (marker, length, msg_type, withdrawn_len, path_attr_len, _, _, _) = get_map_result(&mut bpf).await?;
    info!("Map result: marker={} length={} type={} withdrawn_len={} path_attr_len={}", 
      marker, length, msg_type, withdrawn_len, path_attr_len);
    assert_eq!(marker, 0xFF, "First byte of marker");
    assert_eq!(length, 28, "Message length");
    assert_eq!(msg_type, 2, "Message type (UPDATE)");
    assert_eq!(withdrawn_len, 0, "Withdrawn routes length");
    assert_eq!(path_attr_len, 24, "Path attributes length");

    destroy_veth();
    Ok(())
}

#[tokio::test]
async fn bgp_sets_notification_expected_values() -> Result<()> {
    setup_logging();
    info!("--- bgp_sets_notification_expected_values ---");
    create_veth().await?;
    let mut bpf = load_and_attach_bpf(PROGRAM_NAME)?;
    let _log = EbpfLogger::init(&mut bpf).context("eBPF logger")?;

    // BGP Header with NOTIFICATION message
    let mut payload = Vec::new();
    // Marker (16 bytes of 0xFF)
    payload.extend_from_slice(&[0xFF; 16]);
    payload.extend_from_slice(&[0, 0x15]); // Length (21 bytes)
    payload.push(3); // Type (NOTIFICATION)
    payload.push(2); // Error Code (UPDATE Message Error)
    payload.push(4); // Error Subcode (Invalid NEXT_HOP Attribute)

    let sender_addr: SocketAddr = format!("[{IP1_V6}]:23456").parse()?;
    let sock = create_socket_for_sender(sender_addr)?;

    info!(
        "Sending {}-byte BGP NOTIFICATION message to [{IP0_V6}]:443",
        payload.len()
    );
    sock.send_to(&payload, format!("[{IP0_V6}]:443"))?;
    sleep(Duration::from_millis(200)).await;

    let (marker, length, msg_type, error_code, error_subcode, _, _, _) = get_map_result(&mut bpf).await?;
    info!("Map result: marker={} length={} type={} error_code={} error_subcode={}", marker, length, msg_type, error_code, error_subcode);
    assert_eq!(marker, 0xFF, "First byte of marker");
    assert_eq!(length, 21, "Message length");
    assert_eq!(msg_type, 3, "Message type (NOTIFICATION)");
    assert_eq!(error_code, 2, "Error code");
    assert_eq!(error_subcode, 4, "Error subcode");

    destroy_veth();
    Ok(())
}

#[tokio::test]
async fn bgp_sets_keep_alive_expected_values() -> Result<()> {
    setup_logging();
    info!("--- bgp_sets_keep_alive_expected_values ---");
    create_veth().await?;
    let mut bpf = load_and_attach_bpf(PROGRAM_NAME)?;
    let _log = EbpfLogger::init(&mut bpf).context("eBPF logger")?;

    // BGP Header (19 bytes)
    let mut payload = Vec::new();
    // Marker (16 bytes of 0xFF)
    payload.extend_from_slice(&[0xFF; 16]);
    payload.extend_from_slice(&[0, 19]); // Length (19 bytes)
    payload.push(4); // Type (KEEPALIVE)

    let sender_addr: SocketAddr = format!("[{IP1_V6}]:23456").parse()?;
    let sock = create_socket_for_sender(sender_addr)?;

    info!(
        "Sending {}-byte BGP header to [{IP0_V6}]:443",
        payload.len()
    );
    sock.send_to(&payload, format!("[{IP0_V6}]:443"))?;
    sleep(Duration::from_millis(200)).await;

    let (marker, length, msg_type, _, _, _, _, _) = get_map_result(&mut bpf).await?;
    info!("Map result: marker={} length={} type={}", marker, length, msg_type);
    assert_eq!(marker, 0xFF, "First byte of marker");
    assert_eq!(length, 19, "Message length");
    assert_eq!(msg_type, 4, "Message type (KEEPALIVE)");

    destroy_veth();
    Ok(())
}

#[tokio::test]
async fn bgp_sets_route_refresh_expected_values() -> Result<()> {
    setup_logging();
    info!("--- bgp_sets_route_refresh_expected_values ---");
    create_veth().await?;
    let mut bpf = load_and_attach_bpf(PROGRAM_NAME)?;
    let _log = EbpfLogger::init(&mut bpf).context("eBPF logger")?;

    // BGP Header with ROUTE-REFRESH message
    let mut payload = Vec::new();
    // Marker (16 bytes of 0xFF)
    payload.extend_from_slice(&[0xFF; 16]);
    payload.extend_from_slice(&[0, 0x17]); // Length (23 bytes)
    payload.push(5); // Type (ROUTE-REFRESH)
    payload.extend_from_slice(&[0, 1]); // AFI (IPv4)
    payload.push(0); // Reserved
    payload.push(1); // SAFI (Unicast)

    let sender_addr: SocketAddr = format!("[{IP1_V6}]:23456").parse()?;
    let sock = create_socket_for_sender(sender_addr)?;

    info!(
        "Sending {}-byte BGP ROUTE-REFRESH message to [{IP0_V6}]:443",
        payload.len()
    );
    sock.send_to(&payload, format!("[{IP0_V6}]:443"))?;
    sleep(Duration::from_millis(200)).await;

    let (marker, length, msg_type, afi, safi, _, _, _) = get_map_result(&mut bpf).await?;
    info!("Map result: marker={} length={} type={} afi={} safi={}", marker, length, msg_type, afi, safi);
    assert_eq!(marker, 0xFF, "First byte of marker");
    assert_eq!(length, 23, "Message length");
    assert_eq!(msg_type, 5, "Message type (ROUTE REFRESH)");
    assert_eq!(afi, 1, "Address Family Identifier");
    assert_eq!(safi, 1, "Subsequent Address Family Identifier");

    destroy_veth();
    Ok(())
}