use integration_common::{Ipv6TestData, PacketType, ParsedHeader};
use network_types::ip::IpProto;

// Helper for constructing Ipv6 header test packets
// Only constructs the fields that are actually extracted by mermin-ebpf
pub fn create_ipv6_test_packet() -> ([u8; 41], Ipv6TestData) {
    let mut request_data = [0u8; 41];

    // Byte 0: The type discriminator for the eBPF program's `match` statement.
    request_data[0] = PacketType::Ipv6 as u8;

    // Bytes 1-4: VCF (Version, Traffic Class, Flow Label) - extracted at offset 0 from data
    // Version 6 (bits 0-3), Traffic Class 0x20 (bits 4-11), Flow Label 0x12345 (bits 12-31)
    request_data[1..5].copy_from_slice(&[0x60, 0x21, 0x23, 0x45]);

    // Bytes 5-6: Payload Length (not extracted)
    request_data[5..7].copy_from_slice(&[0, 0]);

    // Byte 7: Next Header/Protocol (proto field - extracted at offset 6 from data)
    request_data[7] = IpProto::Tcp as u8;

    // Byte 8: Hop Limit (hop_limit field - extracted at offset 7 from data)
    request_data[8] = 64;

    // Bytes 9-24: Source Address (src_addr field - extracted at offset 8 from data)
    request_data[9..25].copy_from_slice(&[
        0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x01,
    ]);

    // Bytes 25-40: Destination Address (dst_addr field - extracted at offset 24 from data)
    request_data[25..41].copy_from_slice(&[
        0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x02,
    ]);

    let expected_header = Ipv6TestData {
        vcf: [0x60, 0x21, 0x23, 0x45],
        proto: IpProto::Tcp as u8,
        hop_limit: 64,
        src_addr: [
            0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x01,
        ],
        dst_addr: [
            0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x02,
        ],
    };

    (request_data, expected_header)
}

// Helper for verifying IPv6 header test results
pub fn verify_ipv6_header(received: ParsedHeader, expected: Ipv6TestData) {
    assert_eq!(received.type_, PacketType::Ipv6);
    let parsed_header = unsafe { received.data.ipv6 };

    assert_eq!(
        parsed_header.vcf,
        expected.vcf,
        "VCF mismatch: got [{:#x}, {:#x}, {:#x}, {:#x}], expected [{:#x}, {:#x}, {:#x}, {:#x}]",
        parsed_header.vcf[0],
        parsed_header.vcf[1],
        parsed_header.vcf[2],
        parsed_header.vcf[3],
        expected.vcf[0],
        expected.vcf[1],
        expected.vcf[2],
        expected.vcf[3]
    );

    assert_eq!(
        parsed_header.proto, expected.proto,
        "Proto mismatch: got {}, expected {}",
        parsed_header.proto, expected.proto
    );

    assert_eq!(
        parsed_header.hop_limit, expected.hop_limit,
        "Hop Limit mismatch: got {}, expected {}",
        parsed_header.hop_limit, expected.hop_limit
    );

    assert_eq!(
        parsed_header.src_addr, expected.src_addr,
        "Source Addr mismatch: got {:x?}, expected {:x?}",
        parsed_header.src_addr, expected.src_addr
    );

    assert_eq!(
        parsed_header.dst_addr, expected.dst_addr,
        "Destination Addr mismatch: got {:x?}, expected {:x?}",
        parsed_header.dst_addr, expected.dst_addr
    );
}
