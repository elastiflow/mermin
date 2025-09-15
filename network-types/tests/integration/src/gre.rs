use integration_common::{PacketType, ParsedHeader};
use network_types::{eth::EtherType, gre::GreHdr};

// Helper for constructing GRE header test packets
pub fn create_gre_test_packet() -> ([u8; GreHdr::LEN + 1], GreHdr) {
    let mut request_data = [0u8; GreHdr::LEN + 1];

    // Byte 0: The type discriminator for the eBPF program's `match` statement.
    request_data[0] = PacketType::Gre as u8;

    // Byte 1: C flag (1 bit), Reserved (12 bits), Version (3 bits)
    // Setting C flag to 1, Reserved to 0, Version to 0 (0b10000000)
    request_data[1] = 0b10000000;

    // Byte 2: Reserved (13 bits)
    request_data[2] = 0;

    // Bytes 3-4: Protocol Type (16 bits)
    // Setting to 0x0800 (IPv4)
    request_data[3..5].copy_from_slice(&[0x08, 0x00]);

    let expected_header = GreHdr {
        flgs_res0_ver: [0x80, 0x00],
        proto: EtherType::Ipv4 as u16,
    };
    (request_data, expected_header)
}

// Helper for verifying Gre header test results
pub fn verify_gre_header(received: ParsedHeader, expected: GreHdr) {
    assert_eq!(received.type_, PacketType::Gre);
    let parsed_header = unsafe { received.data.gre };

    let parsed_flgs_res0_ver = parsed_header.flgs_res0_ver;
    let expected_flgs_res0_ver = expected.flgs_res0_ver;
    let parsed_proto = parsed_header.proto;
    let expected_proto = expected.proto;

    // Verify header fields
    assert_eq!(
        parsed_flgs_res0_ver, expected_flgs_res0_ver,
        "Flags/Reserved0/Version mismatch"
    );
    assert_eq!(parsed_proto, expected_proto, "Protocol mismatch");
}
