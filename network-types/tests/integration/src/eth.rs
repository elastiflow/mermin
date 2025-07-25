use integration_common::{PacketType, ParsedHeader};
use network_types::eth::{EthHdr, EtherType};

// Helper for constructing Ethernet header test packets
pub fn create_eth_test_packet() -> ([u8; EthHdr::LEN + 1], EthHdr) {
    let mut request_data = [0u8; EthHdr::LEN + 1];

    // Byte 0: The type discriminator for the eBPF program's `match` statement.
    request_data[0] = PacketType::Eth as u8;
    // Bytes 1-6: Destination MAC (ff:ff:ff:ff:ff:ff)
    request_data[1..7].copy_from_slice(&[0xff, 0xff, 0xff, 0xff, 0xff, 0xff]);
    // Bytes 7-12: Source MAC (00:11:22:33:44:55)
    request_data[7..13].copy_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
    // Bytes 13-14: EtherType (0x0800, big-endian for IPv4)
    request_data[13..15].copy_from_slice(&[0x08, 0x00]);

    let expected_header = EthHdr {
        dst_addr: [0xff, 0xff, 0xff, 0xff, 0xff, 0xff],
        src_addr: [0x00, 0x11, 0x22, 0x33, 0x44, 0x55],
        ether_type: EtherType::Ipv4.into(),
    };

    (request_data, expected_header)
}

// Helper for verifying Ethernet header test results
pub fn verify_eth_header(received: ParsedHeader, expected: EthHdr) {
    assert_eq!(received.type_, PacketType::Eth);
    let parsed_header = unsafe { received.data.eth };

    let parsed_dst_addr = parsed_header.dst_addr;
    let expected_dst_addr = expected.dst_addr;
    assert_eq!(
        parsed_dst_addr, expected_dst_addr,
        "Destination MAC mismatch"
    );

    let parsed_src_addr = parsed_header.src_addr;
    let expected_src_addr = expected.src_addr;
    assert_eq!(parsed_src_addr, expected_src_addr, "Source MAC mismatch");

    let parsed_ether_type = parsed_header.ether_type;
    let expected_ether_type = expected.ether_type;
    assert_eq!(parsed_ether_type, expected_ether_type, "EtherType mismatch");
}

// Similar helpers would be implemented for IPv6, TCP, and UDP headers
