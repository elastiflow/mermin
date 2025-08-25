use integration_common::{PacketType, ParsedHeader};
use network_types::{
    ip::IpProto,
    route::{GenericRoute, RoutingHeaderType, Type2FixedHeader, Type2RoutingHeader},
};

// Helper for constructing Type2 Routing Header test packets
pub fn create_type2_test_packet() -> ([u8; Type2RoutingHeader::LEN + 1], Type2RoutingHeader) {
    let mut request_data = [0u8; Type2RoutingHeader::LEN + 1];

    // Byte 0: The type discriminator for the eBPF program's `match` statement.
    request_data[0] = PacketType::Type2 as u8;

    // GenericRoute (4 bytes)
    // Byte 1: Next Header (TCP = 6)
    request_data[1] = IpProto::Tcp as u8;
    // Byte 2: Hdr Ext Len (2 for Type2 - means 24 bytes total)
    request_data[2] = 2;
    // Byte 3: Routing Type (Type2 = 2)
    request_data[3] = RoutingHeaderType::Type2.as_u8();
    // Byte 4: Segments Left (always 1 for Type2)
    request_data[4] = 1;

    // Type2FixedHeader (20 bytes)
    // Bytes 5-8: Reserved (4 bytes)
    request_data[5..9].copy_from_slice(&[0x00, 0x00, 0x00, 0x00]);
    // Bytes 9-24: Home Address (16 bytes)
    request_data[9..25].copy_from_slice(&[
        0x20, 0x01, 0x0d, 0xb8, 0x85, 0xa3, 0x00, 0x00, 0x00, 0x00, 0x8a, 0x2e, 0x03, 0x70, 0x73,
        0x34,
    ]);

    let gen_route = GenericRoute {
        next_hdr: IpProto::Tcp,
        hdr_ext_len: 2,
        type_: RoutingHeaderType::Type2.as_u8(),
        sgmt_left: 1,
    };

    let fixed_hdr = Type2FixedHeader {
        reserved: [0x00, 0x00, 0x00, 0x00],
        home_address: [
            0x20, 0x01, 0x0d, 0xb8, 0x85, 0xa3, 0x00, 0x00, 0x00, 0x00, 0x8a, 0x2e, 0x03, 0x70,
            0x73, 0x34,
        ],
    };

    let expected_header = Type2RoutingHeader::new(gen_route, fixed_hdr);

    (request_data, expected_header)
}

// Helper for verifying Type2 Routing Header test results
pub fn verify_type2_header(received: ParsedHeader, expected: Type2RoutingHeader) {
    assert_eq!(received.type_, PacketType::Type2);
    let parsed_header = unsafe { received.data.type2 };

    assert_eq!(
        parsed_header.gen_route.next_hdr, expected.gen_route.next_hdr,
        "Next Header mismatch"
    );
    assert_eq!(
        parsed_header.gen_route.hdr_ext_len, expected.gen_route.hdr_ext_len,
        "Header Extension Length mismatch"
    );
    assert_eq!(
        parsed_header.gen_route.type_, expected.gen_route.type_,
        "Routing Type mismatch"
    );
    assert_eq!(
        parsed_header.gen_route.sgmt_left, expected.gen_route.sgmt_left,
        "Segments Left mismatch"
    );
    assert_eq!(
        parsed_header.fixed_hdr.reserved, expected.fixed_hdr.reserved,
        "Reserved field mismatch"
    );
    assert_eq!(
        parsed_header.fixed_hdr.home_address, expected.fixed_hdr.home_address,
        "Home Address mismatch"
    );
}