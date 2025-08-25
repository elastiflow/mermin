use integration_common::{PacketType, ParsedHeader};
use network_types::{
    ip::IpProto,
    route::{GenericRoute, RoutingHeaderType, RplSourceFixedHeader, RplSourceRouteHeader},
};

// Helper for constructing RPL Source Route Header test packets
pub fn create_rpl_source_route_test_packet()
    -> ([u8; RplSourceRouteHeader::LEN + 1], RplSourceRouteHeader) {
    let mut request_data = [0u8; RplSourceRouteHeader::LEN + 1];

    // Byte 0: The type discriminator for the eBPF program's `match` statement.
    request_data[0] = PacketType::RplSourceRoute as u8;

    // GenericRoute (4 bytes)
    // Byte 1: Next Header (TCP = 6)
    request_data[1] = IpProto::Tcp as u8;
    // Byte 2: Hdr Ext Len (1 for minimal RPL header - means 16 bytes total)
    request_data[2] = 1;
    // Byte 3: Routing Type (RplSourceRoute = 3)
    request_data[3] = RoutingHeaderType::RplSourceRoute.as_u8();
    // Byte 4: Segments Left
    request_data[4] = 2;

    // RplSourceFixedHeader (4 bytes)
    // Byte 5: CmprI (4 bits) | CmprE (4 bits) - using 8 for both (compress 8 bytes)
    request_data[5] = (8 << 4) | 8; // CmprI=8, CmprE=8
    // Byte 6: Pad (4 bits) | Reserved (4 bits) - using 0 for pad
    request_data[6] = 0x00;
    // Bytes 7-8: Reserved (remaining 16 bits)
    request_data[7] = 0x00;
    request_data[8] = 0x00;

    // Addresses (8 bytes for this test - 2 addresses of 4 bytes each due to compression)
    // First address (4 bytes due to CmprI=8)
    request_data[9..13].copy_from_slice(&[0x00, 0x01, 0x02, 0x03]);
    // Second address (4 bytes due to CmprE=8)
    request_data[13..17].copy_from_slice(&[0x00, 0x04, 0x05, 0x06]);

    let gen_route = GenericRoute {
        next_hdr: IpProto::Tcp,
        hdr_ext_len: 1,
        type_: RoutingHeaderType::RplSourceRoute.as_u8(),
        sgmt_left: 2,
    };

    let fixed_hdr = RplSourceFixedHeader {
        cmpr: (8 << 4) | 8, // CmprI=8, CmprE=8
        pad_reserved: [0x00, 0x00, 0x00],
    };

    let mut expected_header = RplSourceRouteHeader::new(gen_route, fixed_hdr);
    // Set the first 8 bytes of addresses for our test
    expected_header.addresses[0..8]
        .copy_from_slice(&[0x00, 0x01, 0x02, 0x03, 0x00, 0x04, 0x05, 0x06]);

    (request_data, expected_header)
}

// Helper for verifying RPL Source Route Header test results
pub fn verify_rpl_source_route_header(received: ParsedHeader, expected: RplSourceRouteHeader) {
    assert_eq!(received.type_, PacketType::RplSourceRoute);
    let parsed_header = unsafe { received.data.rpl };

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
        parsed_header.fixed_hdr.cmpr, expected.fixed_hdr.cmpr,
        "Compression field mismatch"
    );
    assert_eq!(
        parsed_header.fixed_hdr.pad_reserved, expected.fixed_hdr.pad_reserved,
        "Pad/Reserved field mismatch"
    );
    // Compare the first 8 bytes of addresses (our test data)
    assert_eq!(
        &parsed_header.addresses[0..8],
        &expected.addresses[0..8],
        "Addresses mismatch"
    );
}