use integration_common::{PacketType, ParsedHeader};
use network_types::udp::{UdpHdr};

// Helper for constructing Udp header test packets
pub fn create_udp_test_packet() -> ([u8; UdpHdr::LEN + 1], UdpHdr) {
    let mut request_data = [0u8; UdpHdr::LEN + 1];

    // Byte 0: The type discriminator for the eBPF program's `match` statement.
    request_data[0] = PacketType::Udp as u8;
    // Bytes 1-2: Source Port
    request_data[1..3].copy_from_slice(&[0x30, 0x39]);
    // Bytes 3-4: Destination Port
    request_data[3..5].copy_from_slice(&[0x00, 0x50]);
    // Bytes 5-9: Remaining values
    request_data[5..9].copy_from_slice(&[
        0, 0, // Header Length
        0, 0 // Checksum
    ]);

    let expected_header = UdpHdr {
        src: [0x30, 0x39],
        dst: [0x00, 0x50],
        len: [0, 0],
        check: [0, 0],
    };

    (request_data, expected_header)
}

// Helper for verifying Udp header test results
pub fn verify_udp_header(received: ParsedHeader, expected: UdpHdr) {
    assert_eq!(received.type_, PacketType::Udp);
    let parsed_header = unsafe { received.data.udp };

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
