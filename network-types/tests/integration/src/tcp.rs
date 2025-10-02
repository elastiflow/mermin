use integration_common::{PacketType, ParsedHeader, TcpTestData};
use network_types::tcp::TCP_LEN;

/// Helper for constructing TCP header test packets
/// 
/// Matches the new parsing methodology where we only extract:
/// - Bytes 0-1: Source port
/// - Bytes 2-3: Destination port
/// - Byte 13: TCP flags
pub fn create_tcp_test_packet() -> ([u8; TCP_LEN + 1], TcpTestData) {
    let mut request_data = [0u8; TCP_LEN + 1];

    // Byte 0: The type discriminator for the eBPF program's `match` statement
    request_data[0] = PacketType::Tcp as u8;
    
    // Bytes 1-2: Source Port - EXTRACTED
    request_data[1..3].copy_from_slice(&[0x30, 0x39]);
    
    // Bytes 3-4: Destination Port - EXTRACTED
    request_data[3..5].copy_from_slice(&[0x00, 0x50]);
    
    // Bytes 5-13: Sequence number, ack number, data offset/reserved - NOT extracted
    request_data[5..14].copy_from_slice(&[
        0, 0, 0, 0, // Sequence Number
        0, 0, 0, 0, // Acknowledgement Number
        0x50, // Data offset (5 << 4) and reserved bits
    ]);
    
    // Byte 14: TCP Flags - EXTRACTED (SYN flag set as an example)
    request_data[14] = 0x02; // SYN flag
    
    // Bytes 15-20: Window, checksum, urgent pointer - NOT extracted
    request_data[15..21].copy_from_slice(&[
        0, 0, // Window size
        0, 0, // Checksum
        0, 0, // Urgent Pointer
    ]);

    let expected_data = TcpTestData {
        src_port: [0x30, 0x39],
        dst_port: [0x00, 0x50],
        tcp_flags: 0x02, // SYN flag
    };

    (request_data, expected_data)
}

/// Helper for verifying TCP header test results
/// 
/// Only verifies fields that are actually extracted by the parser
pub fn verify_tcp_header(received: ParsedHeader, expected: TcpTestData) {
    assert_eq!(received.type_, PacketType::Tcp, "Packet type mismatch");
    
    let parsed = unsafe { received.data.tcp };

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

    assert_eq!(
        parsed.tcp_flags, expected.tcp_flags,
        "TCP flags mismatch: expected {:#04x}, got {:#04x}",
        expected.tcp_flags, parsed.tcp_flags
    );
}
