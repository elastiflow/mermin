use integration_common::{Ipv4TestData, PacketType, ParsedHeader};
use network_types::ip::IpProto;

// Helper for constructing Ipv4 header test packets
// Only constructs the fields that are actually extracted by mermin-ebpf
pub fn create_ipv4_test_packet() -> ([u8; 21], Ipv4TestData) {
    let mut request_data = [0u8; 21];

    // Byte 0: The type discriminator for the eBPF program's `match` statement.
    request_data[0] = PacketType::Ipv4 as u8;

    // Byte 1: Version and Header Length (not extracted, but needed for valid packet)
    request_data[1] = 0x45; // Version 4, IHL 5 (20 bytes)

    // Byte 2: DSCP/ECN (dscp_ecn field - extracted at offset 1 from data)
    request_data[2] = 0x10; // DSCP=4, ECN=0

    // Bytes 3-8: Total Length, Identification, Fragment Offset (not extracted)
    request_data[3..9].copy_from_slice(&[0, 0, 0, 0, 0, 0]);

    // Byte 9: Time to Live (ttl field - extracted at offset 8 from data)
    request_data[9] = 64;

    // Byte 10: Protocol (proto field - extracted at offset 9 from data)
    request_data[10] = IpProto::Tcp as u8;

    // Bytes 11-12: Header Checksum (not extracted)
    request_data[11..13].copy_from_slice(&[0, 0]);

    // Bytes 13-16: Source Address (src_addr field - extracted at offset 12 from data)
    request_data[13..17].copy_from_slice(&[192, 168, 1, 1]);

    // Bytes 17-20: Destination Address (dst_addr field - extracted at offset 16 from data)
    request_data[17..21].copy_from_slice(&[10, 0, 0, 1]);

    let expected_header = Ipv4TestData {
        dscp_ecn: 0x10,
        ttl: 64,
        proto: IpProto::Tcp as u8,
        src_addr: [192, 168, 1, 1],
        dst_addr: [10, 0, 0, 1],
    };

    (request_data, expected_header)
}

// Helper for verifying Ipv4 header test results
pub fn verify_ipv4_header(received: ParsedHeader, expected: Ipv4TestData) {
    assert_eq!(received.type_, PacketType::Ipv4);
    let parsed_header = unsafe { received.data.ipv4 };

    assert_eq!(
        parsed_header.dscp_ecn, expected.dscp_ecn,
        "DSCP/ECN mismatch: got {:#x}, expected {:#x}",
        parsed_header.dscp_ecn, expected.dscp_ecn
    );

    assert_eq!(
        parsed_header.ttl, expected.ttl,
        "TTL mismatch: got {}, expected {}",
        parsed_header.ttl, expected.ttl
    );

    assert_eq!(
        parsed_header.proto, expected.proto,
        "Proto mismatch: got {}, expected {}",
        parsed_header.proto, expected.proto
    );

    assert_eq!(
        parsed_header.src_addr,
        expected.src_addr,
        "Source Addr mismatch: got {}.{}.{}.{}, expected {}.{}.{}.{}",
        parsed_header.src_addr[0],
        parsed_header.src_addr[1],
        parsed_header.src_addr[2],
        parsed_header.src_addr[3],
        expected.src_addr[0],
        expected.src_addr[1],
        expected.src_addr[2],
        expected.src_addr[3]
    );

    assert_eq!(
        parsed_header.dst_addr,
        expected.dst_addr,
        "Destination Addr mismatch: got {}.{}.{}.{}, expected {}.{}.{}.{}",
        parsed_header.dst_addr[0],
        parsed_header.dst_addr[1],
        parsed_header.dst_addr[2],
        parsed_header.dst_addr[3],
        expected.dst_addr[0],
        expected.dst_addr[1],
        expected.dst_addr[2],
        expected.dst_addr[3]
    );
}
