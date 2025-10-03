use integration_common::{PacketType, ParsedHeader, UdpTestData};

// Helper for constructing UDP header test packets
// Only constructs the fields that are actually extracted by mermin-ebpf
pub fn create_udp_test_packet() -> ([u8; 9], UdpTestData) {
    let mut request_data = [0u8; 9];

    // Byte 0: The type discriminator for the eBPF program's `match` statement.
    request_data[0] = PacketType::Udp as u8;

    // Bytes 1-8: UDP header (8 bytes total)
    request_data[1..9].copy_from_slice(&[
        // Bytes 1-2: Source Port (src_port field - extracted at offset 0 from data)
        0x30, 0x39, // Port 12345
        // Bytes 3-4: Destination Port (dst_port field - extracted at offset 2 from data)
        0x00, 0x50, // Port 80
        // Bytes 5-6: Length (not extracted)
        0x00, 0x08, // 8 bytes (header only)
        // Bytes 7-8: Checksum (not extracted)
        0x00, 0x00,
    ]);

    let expected_header = UdpTestData {
        src_port: [0x30, 0x39],
        dst_port: [0x00, 0x50],
    };

    (request_data, expected_header)
}

// Helper for verifying UDP header test results
pub fn verify_udp_header(received: ParsedHeader, expected: UdpTestData) {
    assert_eq!(received.type_, PacketType::Udp);
    let parsed_header = unsafe { received.data.udp };

    assert_eq!(
        parsed_header.src_port,
        expected.src_port,
        "Source Port mismatch: got [{:#x}, {:#x}], expected [{:#x}, {:#x}]",
        parsed_header.src_port[0],
        parsed_header.src_port[1],
        expected.src_port[0],
        expected.src_port[1]
    );

    assert_eq!(
        parsed_header.dst_port,
        expected.dst_port,
        "Destination Port mismatch: got [{:#x}, {:#x}], expected [{:#x}, {:#x}]",
        parsed_header.dst_port[0],
        parsed_header.dst_port[1],
        expected.dst_port[0],
        expected.dst_port[1]
    );
}
