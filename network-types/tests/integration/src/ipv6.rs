use integration_common::{PacketType, ParsedHeader};
use network_types::ip::{IpProto, Ipv6Hdr};

// Helper for constructing Ipv6 header test packets
pub fn create_ipv6_test_packet() -> ([u8; Ipv6Hdr::LEN + 1], Ipv6Hdr) {
    let mut request_data = [0u8; Ipv6Hdr::LEN + 1];

    // Byte 0: The type discriminator for the eBPF program's `match` statement.
    request_data[0] = PacketType::Ipv6 as u8;
    request_data[1..9].copy_from_slice(&[
        0, 0, 0, 0, // Version, Traffic Class, Flow Label
        0, 0, // Payload Length
        IpProto::Tcp as u8, // Next Header
        0, // Hop Limit
    ]);
    // Bytes 9-24: Source Address
    request_data[9..25].copy_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01]);
    // Bytes 25-40: Destination Address
    request_data[25..41].copy_from_slice(&[0xc0, 0xa8, 0x01, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);

    let expected_header = Ipv6Hdr {
        vcf: [0; 4],
        payload_len: [0; 2],
        next_hdr: IpProto::Tcp,
        hop_limit: 0,
        src_addr: [0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01],
        dst_addr: [0xc0, 0xa8, 0x01, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
    };

    (request_data, expected_header)
}

// Helper for verifying Ipv4 header test results
pub fn verify_ipv6_header(received: ParsedHeader, expected: Ipv6Hdr) {
    assert_eq!(received.type_, PacketType::Ipv6);
    let parsed_header = unsafe { received.data.ipv6 };

    let parsed_dst_addr = parsed_header.dst_addr;
    let expected_dst_addr = expected.dst_addr;
    assert_eq!(
        parsed_dst_addr, expected_dst_addr,
        "Destination Addr mismatch"
    );

    let parsed_src_addr = parsed_header.src_addr;
    let expected_src_addr = expected.src_addr;
    assert_eq!(parsed_src_addr, expected_src_addr, "Source Addr mismatch");

    let parsed_next_hdr = parsed_header.next_hdr;
    let expected_next_hdr = expected.next_hdr;
    assert_eq!(parsed_next_hdr, expected_next_hdr, "Next Header mismatch");
}
