use integration_common::{PacketType, ParsedHeader};
use network_types::geneve::GeneveHdr;

// Helper for constructing Geneve header test packets
pub fn create_geneve_test_packet() -> ([u8; GeneveHdr::LEN + 1], GeneveHdr) {
    let mut request_data = [0u8; GeneveHdr::LEN + 1];

    // Byte 0: The type discriminator for the eBPF program's `match` statement.
    request_data[0] = PacketType::Geneve as u8;

    // Byte 1: Version (2 bits) and Option Length (6 bits)
    // Setting version to 0 and option length to 2 (0b00000010)
    request_data[1] = 0b00000010;

    // Byte 2: OAM flag (1 bit), Critical flag (1 bit), Reserved (6 bits)
    // Setting OAM flag to 1, Critical flag to 0 (0b10000000)
    request_data[2] = 0b10000000;

    // Bytes 3-4: Protocol Type (16 bits)
    // Setting to 0x0800 (IPv4)
    request_data[3..5].copy_from_slice(&[0x08, 0x00]);

    // Bytes 5-7: Virtual Network Identifier (VNI) (24 bits)
    // Setting to 0x123456
    request_data[5..8].copy_from_slice(&[0x12, 0x34, 0x56]);

    // Byte 8: Reserved (8 bits)
    request_data[8] = 0;

    let expected_header = GeneveHdr {
        ver_opt_len: 0b00000010,
        o_c_rsvd: 0b10000000,
        protocol_type: [0x08, 0x00],
        vni: [0x12, 0x34, 0x56],
        reserved2: 0,
    };

    (request_data, expected_header)
}

// Helper for verifying Geneve header test results
pub fn verify_geneve_header(received: ParsedHeader, expected: GeneveHdr) {
    assert_eq!(received.type_, PacketType::Geneve);
    let parsed_header = unsafe { received.data.geneve };

    // Verify version and option length
    assert_eq!(
        parsed_header.ver_opt_len, expected.ver_opt_len,
        "Version and Option Length mismatch"
    );
    assert_eq!(parsed_header.ver(), expected.ver(), "Version mismatch");
    assert_eq!(
        parsed_header.opt_len(),
        expected.opt_len(),
        "Option Length mismatch"
    );

    // Verify OAM and Critical flags
    assert_eq!(
        parsed_header.o_c_rsvd, expected.o_c_rsvd,
        "OAM and Critical flags mismatch"
    );
    assert_eq!(
        parsed_header.o_flag(),
        expected.o_flag(),
        "OAM flag mismatch"
    );
    assert_eq!(
        parsed_header.c_flag(),
        expected.c_flag(),
        "Critical flag mismatch"
    );

    // Verify Protocol Type
    assert_eq!(
        parsed_header.protocol_type, expected.protocol_type,
        "Protocol Type mismatch"
    );
    assert_eq!(
        parsed_header.protocol_type(),
        expected.protocol_type(),
        "Protocol Type value mismatch"
    );

    // Verify VNI
    assert_eq!(parsed_header.vni, expected.vni, "VNI mismatch");
    assert_eq!(parsed_header.vni(), expected.vni(), "VNI value mismatch");

    // Verify Reserved field
    assert_eq!(
        parsed_header.reserved2, expected.reserved2,
        "Reserved field mismatch"
    );
}
