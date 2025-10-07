use integration_common::{EthernetTestData, PacketType, ParsedHeader};
use network_types::eth::{ETH_LEN, EtherType};

/// Helper for constructing Ethernet header test packets
///
/// Note: This matches the new parsing methodology where we only extract:
/// - First 6 bytes (destination MAC in the frame, stored as mac_addr)
/// - Bytes 12-13 (EtherType)
///
/// The source MAC (bytes 6-11) is NOT extracted by the parser.
pub fn create_eth_test_packet() -> ([u8; ETH_LEN + 1], EthernetTestData) {
    let mut request_data = [0u8; ETH_LEN + 1];

    // Byte 0: The type discriminator for the eBPF program's `match` statement
    request_data[0] = PacketType::Eth as u8;

    // Bytes 1-6: Destination MAC (ff:ff:ff:ff:ff:ff) - THIS IS EXTRACTED
    request_data[1..7].copy_from_slice(&[0xff, 0xff, 0xff, 0xff, 0xff, 0xff]);

    // Bytes 7-12: Source MAC (00:11:22:33:44:55) - NOT extracted by parser
    request_data[7..13].copy_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);

    // Bytes 13-14: EtherType (0x0800, big-endian for IPv4) - THIS IS EXTRACTED
    request_data[13..15].copy_from_slice(&[0x08, 0x00]);

    // Expected data contains only what the parser actually extracts
    let expected_data = EthernetTestData {
        mac_addr: [0xff, 0xff, 0xff, 0xff, 0xff, 0xff], // Destination MAC
        ether_type: EtherType::Ipv4,
    };

    (request_data, expected_data)
}

/// Helper for verifying Ethernet header test results
///
/// Only verifies fields that are actually extracted by the parser:
/// - mac_addr (first 6 bytes of ethernet frame)
/// - ether_type (bytes 12-13)
pub fn verify_eth_header(received: ParsedHeader, expected: EthernetTestData) {
    assert_eq!(received.type_, PacketType::Eth, "Packet type mismatch");

    let parsed = unsafe { received.data.eth };

    assert_eq!(
        parsed.mac_addr, expected.mac_addr,
        "MAC address mismatch: expected {:02x?}, got {:02x?}",
        expected.mac_addr, parsed.mac_addr
    );

    assert_eq!(
        parsed.ether_type, expected.ether_type,
        "EtherType mismatch: expected {:?}, got {:?}",
        expected.ether_type, parsed.ether_type
    );
}
