use integration_common::{CrhParsed, MAX_CRH_SID_STORAGE, PacketType, ParsedHeader};
use network_types::{
    ip::IpProto,
    route::{CrhHeader, GenericRoute, RoutingHeaderType},
};

/// Creates a test packet for CRH-16 with 3 SIDs (16-bit each = 6 bytes total)
pub fn create_crh16_test_packet() -> (Vec<u8>, CrhParsed) {
    // Structure:
    // - GenericRoute (4 bytes): Next Header, Hdr Ext Len, Routing Type (5), Segments Left
    // - SID List: 3 SIDs * 2 bytes = 6 bytes
    // Total header: 4 + 6 = 10 bytes
    // Need to round up to next 8-byte boundary = 16 bytes
    // Hdr Ext Len = (16 - 8) / 8 = 1

    let packet_size = 1 + CrhHeader::LEN + 12; // 1 byte discriminator + 4 byte header + 12 bytes SIDs and padding
    let mut packet_data = vec![0u8; packet_size];

    // Byte 0: Packet type discriminator for eBPF program
    packet_data[0] = PacketType::Crh16 as u8;

    // GenericRoute (4 bytes) - starting at byte 1
    packet_data[1] = IpProto::Tcp as u8; // Next Header
    packet_data[2] = 1; // Hdr Ext Len (1 * 8 = 8 bytes additional data, but we only use 6)
    packet_data[3] = RoutingHeaderType::Crh16.as_u8(); // Routing Type (5)
    packet_data[4] = 2; // Segments Left (index of current active segment, 0-based)

    // SID List: 3 16-bit SIDs - starting at byte 5
    // SID[0] = 0x1234
    packet_data[5] = 0x12;
    packet_data[6] = 0x34;
    // SID[1] = 0x5678
    packet_data[7] = 0x56;
    packet_data[8] = 0x78;
    // SID[2] = 0x9ABC
    packet_data[9] = 0x9A;
    packet_data[10] = 0xBC;

    // 6 bytes of padding to get to 8 byte boundary
    packet_data.extend_from_slice(&[0; 6]);

    // Create the expected parsed structure
    let generic_route = GenericRoute {
        next_hdr: IpProto::Tcp,
        hdr_ext_len: 1,
        type_: RoutingHeaderType::Crh16.as_u8(),
        sgmt_left: 2,
    };

    let header = CrhHeader { generic_route };

    let mut sids = [0u8; MAX_CRH_SID_STORAGE];
    // Copy the three SIDs (6 bytes total)
    sids[0..6].copy_from_slice(&packet_data[5..11]);

    let expected = CrhParsed {
        header,
        sids,
        sids_len: 12, // 3 SIDs * 2 bytes each + 6 bytes padding
    };

    (packet_data, expected)
}

/// Creates a test packet for CRH-32 with 2 SIDs (32-bit each = 8 bytes total)
pub fn create_crh32_test_packet() -> (Vec<u8>, CrhParsed) {
    // Structure:
    // - GenericRoute (4 bytes): Next Header, Hdr Ext Len, Routing Type (6), Segments Left
    // - SID List: 2 SIDs * 4 bytes = 8 bytes
    // Total header: 4 + 8 = 12 bytes
    // Need to round up to next 8-byte boundary = 16 bytes
    // Hdr Ext Len = (16 - 8) / 8 = 1

    let packet_size = 1 + CrhHeader::LEN + 12; // 1 byte discriminator + 4 byte header + 12 bytes SIDs and padding
    let mut packet_data = vec![0u8; packet_size];

    // Byte 0: Packet type discriminator for eBPF program
    packet_data[0] = PacketType::Crh32 as u8;

    // GenericRoute (4 bytes) - starting at byte 1
    packet_data[1] = IpProto::Ipv6 as u8; // Next Header
    packet_data[2] = 1; // Hdr Ext Len (1 * 8 = 8 bytes additional data)
    packet_data[3] = RoutingHeaderType::Crh32.as_u8(); // Routing Type (6)
    packet_data[4] = 1; // Segments Left (index of current active segment, 0-based)

    // SID List: 2 32-bit SIDs - starting at byte 5
    // SID[0] = 0x12345678
    packet_data[5] = 0x12;
    packet_data[6] = 0x34;
    packet_data[7] = 0x56;
    packet_data[8] = 0x78;
    // SID[1] = 0x9ABCDEF0
    packet_data[9] = 0x9A;
    packet_data[10] = 0xBC;
    packet_data[11] = 0xDE;
    packet_data[12] = 0xF0;

    // 4 bytes of padding to get to 8 byte boundary
    packet_data.extend_from_slice(&[0; 4]);

    // Create the expected parsed structure
    let generic_route = GenericRoute {
        next_hdr: IpProto::Ipv6,
        hdr_ext_len: 1,
        type_: RoutingHeaderType::Crh32.as_u8(),
        sgmt_left: 1,
    };

    let header = CrhHeader { generic_route };

    let mut sids = [0u8; MAX_CRH_SID_STORAGE];
    // Copy the two SIDs (8 bytes total)
    sids[0..8].copy_from_slice(&packet_data[5..13]);

    let expected = CrhParsed {
        header,
        sids,
        sids_len: 12, // 2 SIDs * 4 bytes each + 4 bytes padding
    };

    (packet_data, expected)
}

/// Verifies the parsed CRH-16 Header and its SID data
pub fn verify_crh16_header(received: ParsedHeader, expected: CrhParsed) {
    assert_eq!(received.type_, PacketType::Crh16);
    let parsed_data = unsafe { received.data.crh16 };
    let parsed_header = parsed_data.header;
    let expected_header = expected.header;

    // Verify GenericRoute fields
    assert_eq!(
        parsed_header.generic_route.next_hdr, expected_header.generic_route.next_hdr,
        "Next Header mismatch"
    );
    assert_eq!(
        parsed_header.generic_route.hdr_ext_len, expected_header.generic_route.hdr_ext_len,
        "Header Extension Length mismatch"
    );
    assert_eq!(
        parsed_header.generic_route.type_, expected_header.generic_route.type_,
        "Routing Type mismatch"
    );
    assert_eq!(
        parsed_header.generic_route.sgmt_left, expected_header.generic_route.sgmt_left,
        "Segments Left mismatch"
    );

    // Verify SID data
    assert_eq!(
        parsed_data.sids_len, expected.sids_len,
        "SIDs length mismatch"
    );
    assert_eq!(
        &parsed_data.sids[..parsed_data.sids_len as usize],
        &expected.sids[..expected.sids_len as usize],
        "SIDs data mismatch"
    );

    // Verify routing type is CRH-16
    assert_eq!(
        parsed_header.type_(),
        RoutingHeaderType::Crh16,
        "Expected CRH-16 routing type"
    );
}

/// Verifies the parsed CRH-32 Header and its SID data
pub fn verify_crh32_header(received: ParsedHeader, expected: CrhParsed) {
    assert_eq!(received.type_, PacketType::Crh32);
    let parsed_data = unsafe { received.data.crh32 };
    let parsed_header = parsed_data.header;
    let expected_header = expected.header;

    // Verify GenericRoute fields
    assert_eq!(
        parsed_header.generic_route.next_hdr, expected_header.generic_route.next_hdr,
        "Next Header mismatch"
    );
    assert_eq!(
        parsed_header.generic_route.hdr_ext_len, expected_header.generic_route.hdr_ext_len,
        "Header Extension Length mismatch"
    );
    assert_eq!(
        parsed_header.generic_route.type_, expected_header.generic_route.type_,
        "Routing Type mismatch"
    );
    assert_eq!(
        parsed_header.generic_route.sgmt_left, expected_header.generic_route.sgmt_left,
        "Segments Left mismatch"
    );

    // Verify SID data
    assert_eq!(
        parsed_data.sids_len, expected.sids_len,
        "SIDs length mismatch"
    );
    assert_eq!(
        &parsed_data.sids[..parsed_data.sids_len as usize],
        &expected.sids[..expected.sids_len as usize],
        "SIDs data mismatch"
    );

    // Verify routing type is CRH-32
    assert_eq!(
        parsed_header.type_(),
        RoutingHeaderType::Crh32,
        "Expected CRH-32 routing type"
    );
}
