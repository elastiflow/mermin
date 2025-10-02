use integration_common::{PacketType, ParsedHeader, UdpTestData};
use network_types::udp::UDP_LEN;

/// Helper for constructing UDP header test packets
/// 
/// Matches the new parsing methodology where we only extract:
/// - Bytes 0-1: Source port
/// - Bytes 2-3: Destination port
pub fn create_udp_test_packet() -> ([u8; UDP_LEN + 1], UdpTestData) {
    let mut request_data = [0u8; UDP_LEN + 1];

    // Byte 0: The type discriminator for the eBPF program's `match` statement
    request_data[0] = PacketType::Udp as u8;
    
    // Bytes 1-2: Source Port - EXTRACTED
    request_data[1..3].copy_from_slice(&[0x30, 0x39]);
    
    // Bytes 3-4: Destination Port - EXTRACTED
    request_data[3..5].copy_from_slice(&[0x00, 0x50]);
    
    // Bytes 5-8: Length and Checksum - NOT extracted
    request_data[5..9].copy_from_slice(&[
        0, 0, // Header Length
        0, 0, // Checksum
    ]);

    let expected_data = UdpTestData {
        src_port: [0x30, 0x39],
        dst_port: [0x00, 0x50],
    };

    (request_data, expected_data)
}

/// Helper for verifying UDP header test results
/// 
/// Only verifies fields that are actually extracted by the parser
pub fn verify_udp_header(received: ParsedHeader, expected: UdpTestData) {
    assert_eq!(received.type_, PacketType::Udp, "Packet type mismatch");
    
    let parsed = unsafe { received.data.udp };

    assert_eq!(
        parsed.src_port, expected.src_port,
        "Source port mismatch: expected {:02x?}, got {:02x?}",
        expected.src_port, parsed.src_port
    );

    assert_eq!(
        parsed.dst_port, expected.dst_port,
        "Destination port mismatch: expected {:02x?}, got {:02x?}",
        expected.dst_port, parsed.dst_port
    );
}
