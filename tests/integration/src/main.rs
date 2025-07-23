use std::net::UdpSocket;
use aya::{
    include_bytes_aligned,
    maps::{AsyncPerfEventArray, HashMap},
    programs::KProbe,
    Pod,
};
use log::info;
// Import the fixture and data structures
use integration_common::{
    PacketType,
    REQUEST_DATA_SIZE,
    ParsedHeader,
    ParsedRequest,
};
use network_types::{
    eth::{EthHdr, EtherType},
    ip::{IpProto, Ipv4Hdr},
    tcp::TcpHdr,
};
use crate::utils::setup_test;

mod utils;

fn main() {
    // This main is required for linking during tests, even if unused.
}

#[tokio::test]
async fn test_parses_eth_header() -> Result<(), anyhow::Error> {
    info!("--- Running Test for Ethernet Header ---");
    // Use the test harness for boilerplate setup.
    let mut harness = setup_test().await?;

    let client = UdpSocket::bind("127.0.0.1:0")?;
    let server_addr = "127.0.0.1:8080"; // The exact port doesn't matter.
    client.connect(server_addr)?;

    let mut request_data = [0u8; REQUEST_DATA_SIZE];

    // Byte 0: The type discriminator for the eBPF program's `match` statement.
    request_data[0] = PacketType::Eth as u8;
    // Bytes 1-6: Destination MAC (ff:ff:ff:ff:ff:ff)
    request_data[1..7].copy_from_slice(&[0xff, 0xff, 0xff, 0xff, 0xff, 0xff]);
    // Bytes 7-12: Source MAC (00:11:22:33:44:55)
    request_data[7..13].copy_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
    // Bytes 13-14: EtherType (0x0800, big-endian for IPv4)
    request_data[13..15].copy_from_slice(&[0x08, 0x00]);
    client.send(&request_data)?;

    let expected_header = EthHdr {
        dst_addr: [0xff, 0xff, 0xff, 0xff, 0xff, 0xff],
        src_addr: [0x00, 0x11, 0x22, 0x33, 0x44, 0x55],
        ether_type: EtherType::Ipv4.into(),
    };

    let received = harness.receive_event().await?;

    assert_eq!(received.ty, PacketType::Eth);
    let parsed_header = unsafe { received.data.eth.0 }; // Unwrap the newtype here

    let parsed_dst_addr = parsed_header.dst_addr;
    let expected_dst_addr = expected_header.dst_addr;
    assert_eq!(parsed_dst_addr, expected_dst_addr, "Destination MAC mismatch");

    let parsed_src_addr = parsed_header.src_addr;
    let expected_src_addr = expected_header.src_addr;
    assert_eq!(parsed_src_addr, expected_src_addr, "Source MAC mismatch");

    let parsed_ether_type = parsed_header.ether_type;
    let expected_ether_type = expected_header.ether_type;
    assert_eq!(parsed_ether_type, expected_ether_type, "EtherType mismatch");

    info!("✅ Test for Ethernet Header from Raw Bytes Passed!");
    Ok(())
}
