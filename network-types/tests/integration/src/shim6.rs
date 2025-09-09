use integration_common::{PacketType, ParsedHeader};
use network_types::{ip::IpProto, shim6::Shim6Hdr};

// Creates a basic Shim6 header test packet with no variable extension (hdr_ext_len = 0)
pub fn create_shim6_test_packet() -> (Vec<u8>, Shim6Hdr) {
    let packet_size = 1 + Shim6Hdr::LEN; // discriminator + base header (8 bytes)
    let mut packet_data = vec![0u8; packet_size];

    // Byte 0: Packet type discriminator
    packet_data[0] = PacketType::Shim6 as u8;

    // Fill fixed Shim6 header starting at byte 1
    // Next Header: typically No Next Header for control messages
    packet_data[1] = IpProto::Ipv6NoNxt as u8;
    // Hdr Ext Len: 0 => total 8 bytes
    packet_data[2] = 0;
    // P bit (0) | Type (example 0x2A = 42)
    packet_data[3] = 0x2A; // P=0, Type=42
    // Type-specific (0x12) | S bit (0)
    packet_data[4] = 0x24; // 0b0100_100 => actually we want bits<<1 with S=0; choose 0x24
    // Checksum 0x1234
    packet_data[5] = 0x12;
    packet_data[6] = 0x34;
    // Type-specific data first 2 bytes
    packet_data[7] = 0x56;
    packet_data[8] = 0x78;

    let expected = Shim6Hdr {
        next_hdr: IpProto::Ipv6NoNxt,
        hdr_ext_len: 0,
        p_and_type: 0x2A,
        type_specific_and_s: 0x24,
        checksum: [0x12, 0x34],
        type_specific_data: [0x56, 0x78],
    };

    // Sanity: computed lens
    assert_eq!(expected.total_hdr_len(), 8);
    assert_eq!(expected.variable_len(), 0);

    (packet_data, expected)
}

// Creates a Shim6 header test packet with variable extension bytes (hdr_ext_len > 0)
pub fn create_shim6_with_extension_test_packet() -> (Vec<u8>, Shim6Hdr) {
    // Choose hdr_ext_len = 2 => total header 24 bytes, so 16 bytes variable after base 8
    let hdr_ext_len = 2u8;
    let total_len = (hdr_ext_len as usize + 1) * 8;
    let packet_size = 1 + total_len; // discriminator + full header
    let mut packet_data = vec![0u8; packet_size];

    packet_data[0] = PacketType::Shim6 as u8;

    // Fixed fields
    packet_data[1] = IpProto::Tcp as u8; // Next Header points to TCP just for variety
    packet_data[2] = hdr_ext_len; // Hdr Ext Len
    packet_data[3] = 0x05; // Type=5, P=0
    packet_data[4] = (0x7F << 1) | 0; // Type-specific bits = 0x7F, S=0
    packet_data[5] = 0xAB; // checksum
    packet_data[6] = 0xCD;
    packet_data[7] = 0x00; // type-specific first 2 bytes in base part
    packet_data[8] = 0x01;

    // Fill variable bytes with a pattern
    for i in 0..(total_len - Shim6Hdr::LEN) {
        packet_data[9 + i] = (i as u8) ^ 0xAA;
    }

    let expected = Shim6Hdr {
        next_hdr: IpProto::Tcp,
        hdr_ext_len,
        p_and_type: 0x05,
        type_specific_and_s: (0x7F << 1) as u8,
        checksum: [0xAB, 0xCD],
        type_specific_data: [0x00, 0x01],
    };

    // Sanity
    assert_eq!(expected.total_hdr_len(), total_len);

    (packet_data, expected)
}

// Verifier for Shim6 header parsed from eBPF
pub fn verify_shim6_header(received: ParsedHeader, expected: Shim6Hdr) {
    assert_eq!(received.type_, PacketType::Shim6);
    let parsed_header: Shim6Hdr = unsafe { received.data.shim6 };

    assert_eq!(
        parsed_header.next_hdr as u8, expected.next_hdr as u8,
        "Next Header mismatch"
    );
    assert_eq!(
        parsed_header.hdr_ext_len, expected.hdr_ext_len,
        "Hdr Ext Len mismatch"
    );
    assert_eq!(
        parsed_header.p_and_type, expected.p_and_type,
        "p_and_type mismatch"
    );
    assert_eq!(
        parsed_header.type_specific_and_s, expected.type_specific_and_s,
        "type_specific_and_s mismatch"
    );
    assert_eq!(
        parsed_header.checksum, expected.checksum,
        "Checksum mismatch"
    );
    assert_eq!(
        parsed_header.type_specific_data, expected.type_specific_data,
        "Type-specific data mismatch"
    );

    let total_hdr_len_bytes = (parsed_header.hdr_ext_len as usize + 1) * 8;
    match parsed_header.hdr_ext_len {
        0 => assert_eq!(
            total_hdr_len_bytes, 8,
            "Expected 8-byte header for hdr_ext_len=0"
        ),
        2 => assert_eq!(
            total_hdr_len_bytes, 24,
            "Expected 24-byte header for hdr_ext_len=2"
        ),
        other => panic!("Unexpected hdr_ext_len for Shim6 test: {}", other),
    }
}
