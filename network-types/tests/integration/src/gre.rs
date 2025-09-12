use integration_common::{PacketType, ParsedHeader};
use network_types::{
    eth::EtherType,
    gre::{GreFixedHdr, GreHdr},
};

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

    // All other fields are reserved (zeros)
    request_data[5] = 0;
    request_data[6] = 0;
    request_data[7] = 0;
    request_data[8] = 0;

    let expected_header = GreHdr {
        fixed: GreFixedHdr {
            flgs_res0_ver: [0x80, 0x00],
            proto: EtherType::Ipv4 as u16,
        },
        opt1: [0; 4],
        opt2: [0; 4],
        opt3: [0; 4],
    };
    (request_data, expected_header)
}

// Helper for verifying Gre header test results
pub fn verify_gre_header(received: ParsedHeader, expected: GreHdr) {
    assert_eq!(received.type_, PacketType::Gre);
    let parsed_header = unsafe { received.data.gre };

    let parsed_flgs_res0_ver = parsed_header.fixed.flgs_res0_ver;
    let expected_flgs_res0_ver = expected.fixed.flgs_res0_ver;
    let parsed_proto = parsed_header.fixed.proto;
    let expected_proto = expected.fixed.proto;
    let parsed_opt1 = parsed_header.opt1;
    let expected_opt1 = expected.opt1;
    let parsed_opt2 = parsed_header.opt2;
    let expected_opt2 = expected.opt2;
    let parsed_opt3 = parsed_header.opt3;
    let expected_opt3 = expected.opt3;

    // Verify fixed header
    assert_eq!(
        parsed_flgs_res0_ver, expected_flgs_res0_ver,
        "Flags/Reserved0/Version mismatch"
    );
    assert_eq!(parsed_proto, expected_proto, "Protocol mismatch");

    // Verify optional fields
    assert_eq!(parsed_opt1, expected_opt1, "Optional field 1 mismatch");
    assert_eq!(parsed_opt2, expected_opt2, "Optional field 2 mismatch");
    assert_eq!(parsed_opt3, expected_opt3, "Optional field 3 mismatch");
}
