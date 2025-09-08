use integration_common::{PacketType, ParsedHeader};
use network_types::{
    ip::IpProto,
    route::{CrhHeader, GenericRoute, RoutingHeaderType},
};

/// Creates a test packet for CRH-16 with 3 SIDs (16-bit each = 6 bytes total)
pub fn create_crh16_test_packet() -> (Vec<u8>, CrhHeader) {
    // Structure: Include variable area per hdr_ext_len=1 (8 bytes after the first 8), but parsing will skip it

    let packet_size = 1 + CrhHeader::LEN + 12; // 1 byte discriminator + 4 byte header + 12 bytes SIDs and padding
    let mut packet_data = vec![0u8; packet_size];

    // Byte 0: Packet type discriminator for eBPF program
    packet_data[0] = PacketType::Crh16 as u8;

    // GenericRoute (4 bytes) - starting at byte 1
    packet_data[1] = IpProto::Tcp as u8; // Next Header
    packet_data[2] = 1; // Hdr Ext Len = 1 (8 bytes after first 8 octets)
    packet_data[3] = RoutingHeaderType::Crh16.as_u8(); // Routing Type (5)
    packet_data[4] = 2; // Segments Left (index of current active segment, 0-based)

    // SID List: 3 16-bit SIDs (6 bytes) + 2 bytes padding to fill hdr_ext_len region
    packet_data[5] = 0x12;
    packet_data[6] = 0x34;
    packet_data[7] = 0x56;
    packet_data[8] = 0x78;
    packet_data[9] = 0x9A;
    packet_data[10] = 0xBC;
    // 2 bytes padding to complete 8-byte variable section
    packet_data[11] = 0x00;
    packet_data[12] = 0x00;

    // Additional 4 bytes padding to reach 8-byte boundary for whole header (total 16 bytes)
    packet_data.extend_from_slice(&[0; 4]);

    // Create the expected parsed structure
    let generic_route = GenericRoute {
        next_hdr: IpProto::Tcp,
        hdr_ext_len: 1,
        type_: RoutingHeaderType::Crh16.as_u8(),
        sgmt_left: 2,
    };

    let header = CrhHeader {
        gen_route: generic_route,
    };

    let expected = header;

    (packet_data, expected)
}

/// Creates a test packet for CRH-32 with 2 SIDs (32-bit each = 8 bytes total)
pub fn create_crh32_test_packet() -> (Vec<u8>, CrhHeader) {
    // Structure: Include variable area per hdr_ext_len=1 (8 bytes after the first 8), but parsing will skip it

    let packet_size = 1 + CrhHeader::LEN + 12; // 1 byte discriminator + 4 byte header + 12 bytes SIDs and padding
    let mut packet_data = vec![0u8; packet_size];

    // Byte 0: Packet type discriminator for eBPF program
    packet_data[0] = PacketType::Crh32 as u8;

    // GenericRoute (4 bytes) - starting at byte 1
    packet_data[1] = IpProto::Ipv6 as u8; // Next Header
    packet_data[2] = 1; // Hdr Ext Len = 1 (8 bytes after first 8 octets)
    packet_data[3] = RoutingHeaderType::Crh32.as_u8(); // Routing Type (6)
    packet_data[4] = 1; // Segments Left (index of current active segment, 0-based)

    // SID List: 2 32-bit SIDs (8 bytes)
    packet_data[5] = 0x12;
    packet_data[6] = 0x34;
    packet_data[7] = 0x56;
    packet_data[8] = 0x78;
    packet_data[9] = 0x9A;
    packet_data[10] = 0xBC;
    packet_data[11] = 0xDE;
    packet_data[12] = 0xF0;

    // Additional 4 bytes padding to reach 16 bytes total header (8 static + 8 variable)
    packet_data.extend_from_slice(&[0; 4]);

    // Create the expected parsed structure
    let generic_route = GenericRoute {
        next_hdr: IpProto::Ipv6,
        hdr_ext_len: 1,
        type_: RoutingHeaderType::Crh32.as_u8(),
        sgmt_left: 1,
    };

    let header = CrhHeader {
        gen_route: generic_route,
    };

    let expected = header;

    (packet_data, expected)
}

/// Verifies the parsed CRH-16 Header and its SID data
pub fn verify_crh16_header(received: ParsedHeader, expected: CrhHeader) {
    assert_eq!(received.type_, PacketType::Crh16);
    let parsed_header: CrhHeader = unsafe { received.data.crh16 };
    let expected_header: CrhHeader = expected;

    // Verify GenericRoute fields
    assert_eq!(
        parsed_header.gen_route.next_hdr, expected_header.gen_route.next_hdr,
        "Next Header mismatch"
    );
    assert_eq!(
        parsed_header.gen_route.hdr_ext_len, expected_header.gen_route.hdr_ext_len,
        "Header Extension Length mismatch"
    );
    assert_eq!(
        parsed_header.gen_route.type_, expected_header.gen_route.type_,
        "Routing Type mismatch"
    );
    assert_eq!(
        parsed_header.gen_route.sgmt_left, expected_header.gen_route.sgmt_left,
        "Segments Left mismatch"
    );

    // Verify total header length equals 16 (8 static + 8 variable for hdr_ext_len=1)
    let total_hdr_len_bytes = 8 + (parsed_header.gen_route.hdr_ext_len as usize) * 8;
    assert_eq!(
        parsed_header.gen_route.hdr_ext_len, 1,
        "Expected hdr_ext_len=1 for CRH-16 test"
    );
    assert_eq!(
        total_hdr_len_bytes, 16,
        "Expected 16-byte CRH-16 header by total_hdr_len"
    );

    // Verify routing type is CRH-16
    assert_eq!(
        parsed_header.type_(),
        RoutingHeaderType::Crh16,
        "Expected CRH-16 routing type"
    );
}

/// Verifies the parsed CRH-32 Header and its SID data
pub fn verify_crh32_header(received: ParsedHeader, expected: CrhHeader) {
    assert_eq!(received.type_, PacketType::Crh32);
    let parsed_header: CrhHeader = unsafe { received.data.crh32 };
    let expected_header: CrhHeader = expected;

    // Verify GenericRoute fields
    assert_eq!(
        parsed_header.gen_route.next_hdr, expected_header.gen_route.next_hdr,
        "Next Header mismatch"
    );
    assert_eq!(
        parsed_header.gen_route.hdr_ext_len, expected_header.gen_route.hdr_ext_len,
        "Header Extension Length mismatch"
    );
    assert_eq!(
        parsed_header.gen_route.type_, expected_header.gen_route.type_,
        "Routing Type mismatch"
    );
    assert_eq!(
        parsed_header.gen_route.sgmt_left, expected_header.gen_route.sgmt_left,
        "Segments Left mismatch"
    );

    // Verify total header length equals 16 (8 static + 8 variable for hdr_ext_len=1)
    let total_hdr_len_bytes = 8 + (parsed_header.gen_route.hdr_ext_len as usize) * 8;
    assert_eq!(
        parsed_header.gen_route.hdr_ext_len, 1,
        "Expected hdr_ext_len=1 for CRH-32 test"
    );
    assert_eq!(
        total_hdr_len_bytes, 16,
        "Expected 16-byte CRH-32 header by total_hdr_len"
    );

    // Verify routing type is CRH-32
    assert_eq!(
        parsed_header.type_(),
        RoutingHeaderType::Crh32,
        "Expected CRH-32 routing type"
    );
}
