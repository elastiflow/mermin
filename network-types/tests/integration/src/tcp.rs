use integration_common::{PacketType, ParsedHeader};
use network_types::tcp::{TcpHdr};

// Helper for constructing Tcp header test packets
pub fn create_tcp_test_packet() -> ([u8; TcpHdr::LEN + 1], TcpHdr) {
    let mut request_data = [0u8; TcpHdr::LEN + 1];

    // Byte 0: The type discriminator for the eBPF program's `match` statement.
    request_data[0] = PacketType::Tcp as u8;
    // Bytes 1-2: Source Port
    request_data[1..3].copy_from_slice(&[0x30, 0x39]);
    // Bytes 3-4: Destination Port
    request_data[3..5].copy_from_slice(&[0x00, 0x50]);
    // Bytes 5-21: Remaning values
    request_data[5..21].copy_from_slice(&[
        0, 0, 0, 0, // Sequence Number
        0, 0, 0, 0, // Acknowledgement Number
        0, 0, // Data offset, reserved bits and flags
        0, 0, // Window size
        0, 0, // Checksum
        0, 0 // Urgent Pointer
    ]);

    let expected_header = TcpHdr {
        src: [0x30, 0x39],
        dst: [0x00, 0x50],
        seq: [0, 0, 0, 0],
        ack_seq: [0, 0, 0, 0],
        off_res_flags: [0, 0],
        window: [0, 0],
        check: [0, 0],
        urg_ptr: [0, 0],
    };

    (request_data, expected_header)
}

// Helper for verifying Tcp header test results
pub fn verify_tcp_header(received: ParsedHeader, expected: TcpHdr) {
    assert_eq!(received.type_, PacketType::Tcp);
    let parsed_header = unsafe { received.data.tcp };

    let parsed_dst_port = parsed_header.dst;
    let expected_dst_port = expected.dst;
    assert_eq!(
        parsed_dst_port, expected_dst_port,
        "Destination Port mismatch"
    );

    let parsed_src_port = parsed_header.src;
    let expected_src_port = expected.src;
    assert_eq!(parsed_src_port, expected_src_port, "Source Port mismatch");
}
