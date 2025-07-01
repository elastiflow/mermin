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


const GRE_MAP_NAME: &str = "GREHDR_RESULT";
const PROGRAM_NAME: &str = "gre_hdr_test";

/// Reads GRE header parsing results from the eBPF map.
/// It waits for the map to be populated and then clears it.
///
/// Returns (flags, version, protocol, checksum, key, sequence)
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
    let mut bpf = load_and_attach_bpf(PROGRAM_NAME)?;
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
