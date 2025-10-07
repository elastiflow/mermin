use integration_common::{PacketType, ParsedHeader, TcpTestData};

// Helper for constructing TCP header test packets
// Only constructs the fields that are actually extracted by mermin-ebpf
pub fn create_tcp_test_packet() -> ([u8; 21], TcpTestData) {
    let mut request_data = [0u8; 21];

    // Byte 0: The type discriminator for the eBPF program's `match` statement.
    request_data[0] = PacketType::Tcp as u8;

    // Bytes 1-20: TCP header (20 bytes total)
    request_data[1..21].copy_from_slice(&[
        // Bytes 0-1 of TCP header: Source Port (extracted at offset 0)
        0x30, 0x39, // Port 12345
        // Bytes 2-3 of TCP header: Destination Port (extracted at offset 2)
        0x00, 0x50, // Port 80
        // Bytes 4-7 of TCP header: Sequence Number (not extracted)
        0x00, 0x00, 0x00, 0x01,
        // Bytes 8-11 of TCP header: Acknowledgement Number (not extracted)
        0x00, 0x00, 0x00, 0x00,
        // Byte 12 of TCP header: Data Offset (4 bits) + Reserved (4 bits)
        0x50, // Data offset = 5 (20 bytes header), reserved = 0
        // Byte 13 of TCP header: Flags (extracted at offset 13)  ← THIS IS THE KEY
        0x02, // SYN flag
        // Bytes 14-15 of TCP header: Window Size (not extracted)
        0x20, 0x00, // Bytes 16-17 of TCP header: Checksum (not extracted)
        0x00, 0x00, // Bytes 18-19 of TCP header: Urgent Pointer (not extracted)
        0x00, 0x00,
    ]);

    let expected_header = TcpTestData {
        src_port: [0x30, 0x39],
        dst_port: [0x00, 0x50],
        tcp_flags: 0x02, // SYN flag
    };

    (request_data, expected_header)
}

// Helper for verifying TCP header test results
pub fn verify_tcp_header(received: ParsedHeader, expected: TcpTestData) {
    assert_eq!(received.type_, PacketType::Tcp);
    let parsed_header = unsafe { received.data.tcp };

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

    assert_eq!(
        parsed_header.tcp_flags, expected.tcp_flags,
        "TCP Flags mismatch: got {:#x}, expected {:#x}",
        parsed_header.tcp_flags, expected.tcp_flags
    );
}
