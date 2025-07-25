use integration_common::{PacketType, ParsedHeader};
use network_types::ip::{IpProto, Ipv4Hdr};

// Helper for constructing Ipv4 header test packets
pub fn create_ipv4_test_packet() -> ([u8; Ipv4Hdr::LEN + 1], Ipv4Hdr) {
    let mut request_data = [0u8; Ipv4Hdr::LEN + 1];

    // Byte 0: The type discriminator for the eBPF program's `match` statement.
    request_data[0] = PacketType::Ipv4 as u8;
    request_data[1..10].copy_from_slice(&[
        0, // Version and Header Length
        0, // Type of Service
        0, 0, // Total Length
        0, 0, // Identification
        0, 0, // Fragment Offset
        0, // Time to Live
    ]);
    // Byte 10: Protocol
    request_data[10] = IpProto::Tcp as u8;
    // Bytes 11-12: Header Checksum
    request_data[11..13].copy_from_slice(&[0, 0]);
    // Bytes 13-16: Source Address
    request_data[13..17].copy_from_slice(&[192, 168, 1, 1]);
    // Bytes 17-20: Destination Address
    request_data[17..21].copy_from_slice(&[192, 168, 1, 2]);

    let expected_header = Ipv4Hdr {
        vihl: 0,
        tos: 0,
        tot_len: [0; 2],
        id: [0; 2],
        frags: [0; 2],
        ttl: 0,
        proto: IpProto::Tcp,
        check: [0; 2],
        src_addr: [192, 168, 1, 1],
        dst_addr: [192, 168, 1, 2],
    };

    (request_data, expected_header)
}

// Helper for verifying Ipv4 header test results
pub fn verify_ipv4_header(received: ParsedHeader, expected: Ipv4Hdr) {
    assert_eq!(received.type_, PacketType::Ipv4);
    let parsed_header = unsafe { received.data.ipv4 };

    let parsed_dst_addr = parsed_header.dst_addr;
    let expected_dst_addr = expected.dst_addr;
    assert_eq!(
        parsed_dst_addr, expected_dst_addr,
        "Destination Addr mismatch"
    );

    let parsed_src_addr = parsed_header.src_addr;
    let expected_src_addr = expected.src_addr;
    assert_eq!(parsed_src_addr, expected_src_addr, "Source Addr mismatch");

    let parsed_proto = parsed_header.proto;
    let expected_proto = expected.proto;
    assert_eq!(parsed_proto, expected_proto, "Proto mismatch");
}
