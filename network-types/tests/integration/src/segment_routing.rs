use integration_common::{
    MAX_SRH_SEGMENTS_STORAGE, PacketType, ParsedHeader, SegmentRoutingParsed,
};
use network_types::{
    ip::IpProto,
    route::{GenericRoute, RoutingHeaderType, SegmentFixedHeader, SegmentRoutingHeader},
};

/// Creates a test packet with 2 segments (IPv6 addresses)
pub fn create_segment_routing_test_packet() -> (Vec<u8>, SegmentRoutingParsed) {
    // Structure based on RFC 8754 ASCII diagram:
    // - GenericRoute (4 bytes): Next Header, Hdr Ext Len, Routing Type (4), Segments Left
    // - SegmentFixedHeader (4 bytes): Last Entry, Flags, Tag
    // - Segment List: 2 segments * 16 bytes = 32 bytes
    // Total header: 8 + 32 = 40 bytes
    // Hdr Ext Len = (40 - 8) / 8 = 4 (excluding first 8 octets, in 8-octet units)

    let packet_size = 1 + SegmentRoutingHeader::LEN + 32; // 1 byte discriminator + 8 byte header + 32 bytes segments
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
    // First segment (Segment List[0])
    packet_data[9..25].copy_from_slice(&[
        0x20, 0x01, 0x0d, 0xb8, 0x85, 0xa3, 0x00, 0x00, 0x00, 0x00, 0x8a, 0x2e, 0x03, 0x70, 0x73,
        0x34,
    ]);

    // Second segment (Segment List[1])
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

    let mut segments_and_tlvs = [0u8; MAX_SRH_SEGMENTS_STORAGE];
    // Copy the two segments (32 bytes total)
    segments_and_tlvs[0..32].copy_from_slice(&packet_data[9..41]);

    let expected = SegmentRoutingParsed {
        header,
        segments_and_tlvs,
        segments_and_tlvs_len: 32, // 2 segments * 16 bytes each
    };

    (packet_data, expected)
}

/// Creates a test packet with segments and TLVs
pub fn create_segment_routing_with_tlvs_test_packet() -> (Vec<u8>, SegmentRoutingParsed) {
    // 1 segment (16 bytes) + 8 bytes TLVs = 24 bytes variable data
    // Total header: 8 + 24 = 32 bytes
    // Hdr Ext Len = (32 - 8) / 8 = 3

    let packet_size = 1 + SegmentRoutingHeader::LEN + 24; // 1 byte discriminator + 8 byte header + 24 bytes data
    let mut packet_data = vec![0u8; packet_size];

    // Byte 0: Packet type discriminator
    packet_data[0] = PacketType::SegmentRouting as u8;

    // GenericRoute (4 bytes)
    packet_data[1] = IpProto::Ipv6 as u8; // Next Header
    packet_data[2] = 3; // Hdr Ext Len
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

    let mut segments_and_tlvs = [0u8; MAX_SRH_SEGMENTS_STORAGE];
    segments_and_tlvs[0..24].copy_from_slice(&packet_data[9..33]);

    let expected = SegmentRoutingParsed {
        header,
        segments_and_tlvs,
        segments_and_tlvs_len: 24,
    };

    (packet_data, expected)
}

/// Verifies the parsed Segment Routing Header and its segments/TLV data
pub fn verify_segment_routing_header(received: ParsedHeader, expected: SegmentRoutingParsed) {
    assert_eq!(received.type_, PacketType::SegmentRouting);
    let parsed_data = unsafe { received.data.segment_routing };
    let parsed_header = parsed_data.header;
    let expected_header = expected.header;

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

    // Verify segments and TLVs data
    assert_eq!(
        parsed_data.segments_and_tlvs_len, expected.segments_and_tlvs_len,
        "Segments and TLVs length mismatch"
    );
    assert_eq!(
        &parsed_data.segments_and_tlvs[..parsed_data.segments_and_tlvs_len as usize],
        &expected.segments_and_tlvs[..expected.segments_and_tlvs_len as usize],
        "Segments and TLVs data mismatch"
    );
}
