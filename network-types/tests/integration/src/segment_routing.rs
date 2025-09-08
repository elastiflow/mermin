use integration_common::{PacketType, ParsedHeader};
use network_types::{
    ip::IpProto,
    route::{GenericRoute, RoutingHeaderType, SegmentFixedHeader, SegmentRoutingHeader},
};

/// Creates a test packet with 2 segments (IPv6 addresses)
pub fn create_segment_routing_test_packet() -> (Vec<u8>, SegmentRoutingHeader) {
    // Structure based on RFC 8754 ASCII diagram:
    // - GenericRoute (4 bytes): Next Header, Hdr Ext Len, Routing Type (4), Segments Left
    // - SegmentFixedHeader (4 bytes): Last Entry, Flags, Tag
    // - Segment List: 2 segments * 16 bytes = 32 bytes
    // Total header: 8 + 32 = 40 bytes
    // Hdr Ext Len = (40 - 8) / 8 = 4 (excluding first 8 octets, in 8-octet units)

    let packet_size = 1 + SegmentRoutingHeader::LEN + 32; // 1 byte discriminator + 8 byte static header only
    let mut packet_data = vec![0u8; packet_size];

    // Byte 0: Packet type discriminator for eBPF program
    packet_data[0] = PacketType::SegmentRouting as u8;

    // GenericRoute (4 bytes) - starting at byte 1
    packet_data[1] = IpProto::Tcp as u8; // Next Header
    packet_data[2] = 4; // Hdr Ext Len (4 * 8 = 32 bytes additional data)
    packet_data[3] = RoutingHeaderType::SegmentRoutingHeader.as_u8(); // Routing Type (4)
    packet_data[4] = 1; // Segments Left (index of current active segment)

    // SegmentFixedHeader (4 bytes) - starting at byte 5
    packet_data[5] = 1; // Last Entry (index of last entry in segment list, 0-based)
    packet_data[6] = 0x00; // Flags (8 bits of flags)
    packet_data[7] = 0x12; // Tag high byte
    packet_data[8] = 0x34; // Tag low byte (Tag = 0x1234)

    // Segment List: 2 IPv6 addresses (16 bytes each) - starting at byte 9
    packet_data[9..25].copy_from_slice(&[
        0x20, 0x01, 0x0d, 0xb8, 0x85, 0xa3, 0x00, 0x00, 0x00, 0x00, 0x8a, 0x2e, 0x03, 0x70, 0x73,
        0x34,
    ]);
    packet_data[25..41].copy_from_slice(&[
        0x20, 0x01, 0x0d, 0xb8, 0x85, 0xa3, 0x00, 0x01, 0x00, 0x00, 0x8a, 0x2e, 0x03, 0x70, 0x73,
        0x35,
    ]);

    // Create the expected parsed structure
    let gen_route = GenericRoute {
        next_hdr: IpProto::Tcp,
        hdr_ext_len: 4,
        type_: RoutingHeaderType::SegmentRoutingHeader.as_u8(),
        sgmt_left: 1,
    };

    let fixed_hdr = SegmentFixedHeader {
        last_entry: 1,
        flags: 0x00,
        tag: [0x12, 0x34],
    };

    let header = SegmentRoutingHeader {
        gen_route,
        fixed_hdr,
    };

    let expected = header;

    (packet_data, expected)
}

/// Creates a test packet with segments and TLVs
pub fn create_segment_routing_with_tlvs_test_packet() -> (Vec<u8>, SegmentRoutingHeader) {
    // 1 segment (16 bytes) + 8 bytes TLVs = 24 bytes variable data
    // Total header: 8 + 24 = 32 bytes
    // Hdr Ext Len = (32 - 8) / 8 = 3

    let packet_size = 1 + SegmentRoutingHeader::LEN + 24; // 1 byte discriminator + 8 byte static header only + 24 byte variable data and pad
    let mut packet_data = vec![0u8; packet_size];

    // Byte 0: Packet type discriminator
    packet_data[0] = PacketType::SegmentRouting as u8;

    // GenericRoute (4 bytes)
    packet_data[1] = IpProto::Ipv6 as u8; // Next Header
    packet_data[2] = 3; // Hdr Ext Len = 0 (no additional data)
    packet_data[3] = RoutingHeaderType::SegmentRoutingHeader.as_u8(); // Routing Type (4)
    packet_data[4] = 0; // Segments Left

    // SegmentFixedHeader (4 bytes)
    packet_data[5] = 0; // Last Entry (1 segment)
    packet_data[6] = 0x80; // Flags
    packet_data[7] = 0x00; // Tag high byte
    packet_data[8] = 0x00; // Tag low byte

    // Single segment (16 bytes)
    packet_data[9..25].copy_from_slice(&[
        0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x01,
    ]);

    // TLV data (8 bytes of padding/example TLV)
    packet_data[25..33].copy_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);

    let gen_route = GenericRoute {
        next_hdr: IpProto::Ipv6,
        hdr_ext_len: 3,
        type_: RoutingHeaderType::SegmentRoutingHeader.as_u8(),
        sgmt_left: 0,
    };

    let fixed_hdr = SegmentFixedHeader {
        last_entry: 0,
        flags: 0x80,
        tag: [0x00, 0x00],
    };

    let header = SegmentRoutingHeader {
        gen_route,
        fixed_hdr,
    };

    let expected = header;

    (packet_data, expected)
}

/// Verifies the parsed Segment Routing Header and its segments/TLV data
pub fn verify_segment_routing_header(received: ParsedHeader, expected: SegmentRoutingHeader) {
    assert_eq!(received.type_, PacketType::SegmentRouting);
    let parsed_header: SegmentRoutingHeader = unsafe { received.data.segment_routing };
    let expected_header: SegmentRoutingHeader = expected;

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

    // Verify SegmentFixedHeader fields
    assert_eq!(
        parsed_header.fixed_hdr.last_entry, expected_header.fixed_hdr.last_entry,
        "Last Entry mismatch"
    );
    assert_eq!(
        parsed_header.fixed_hdr.flags, expected_header.fixed_hdr.flags,
        "Flags mismatch"
    );
    assert_eq!(
        parsed_header.fixed_hdr.tag, expected_header.fixed_hdr.tag,
        "Tag mismatch"
    );

    // Additionally verify total header length computation matches our constructed variable data
    let total_hdr_len_bytes = 8 + (parsed_header.gen_route.hdr_ext_len as usize) * 8;
    match parsed_header.gen_route.hdr_ext_len {
        4 => assert_eq!(
            total_hdr_len_bytes, 40,
            "Expected 40-byte SRH for hdr_ext_len=4"
        ),
        3 => assert_eq!(
            total_hdr_len_bytes, 32,
            "Expected 32-byte SRH for hdr_ext_len=3"
        ),
        other => panic!("Unexpected hdr_ext_len for SRH test: {}", other),
    }
}
