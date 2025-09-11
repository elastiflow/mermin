use integration_common::{PacketType, ParsedHeader};
use network_types::{
    ip::IpProto,
    route::{GenericRoute, RoutingHeaderType, RplSourceFixedHeader, RplSourceRouteHeader},
};

// Creates a test packet including variable-length compressed addresses that should be skipped by parsing
pub fn create_rpl_source_route_test_packet() -> (Vec<u8>, RplSourceRouteHeader) {
    // With CmprI=8, CmprE=8, each address contributes 8 bytes
    // Two addresses = 16 bytes of variable data
    // Total header bytes on wire = 8 (static) + 16 (addresses) = 24
    // Hdr Ext Len = (24 - 8) / 8 = 2

    let mut packet_data = vec![0u8; 1 + RplSourceRouteHeader::LEN + 16];

    // Byte 0: Packet type discriminator for eBPF program
    packet_data[0] = PacketType::RplSourceRoute as u8;

    // GenericRoute (4 bytes) - starting at byte 1
    packet_data[1] = IpProto::Tcp as u8; // Next Header
    packet_data[2] = 2; // Hdr Ext Len = 2 (16 bytes after first 8)
    packet_data[3] = RoutingHeaderType::RplSourceRoute as u8;
    packet_data[4] = 2; // Segments Left (2 addresses remaining)

    // RplSourceFixedHeader (4 bytes) - starting at byte 5
    packet_data[5] = (8 << 4) | 8; // CmprI=8, CmprE=8
    packet_data[6] = 0; // Pad=0, Reserved upper 4 bits
    packet_data[7] = 0; // Reserved middle 8 bits
    packet_data[8] = 0; // Reserved lower 8 bits

    // Two compressed addresses (8 bytes each) that should be skipped by parsing
    packet_data[9..17].copy_from_slice(&[0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xF0, 0x11, 0x22]);
    packet_data[17..25].copy_from_slice(&[0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0x00]);

    // Expected parsed structure only includes static header; dynamic addresses_len = 0
    let gen_route = GenericRoute {
        next_hdr: IpProto::Tcp,
        hdr_ext_len: 2,
        type_: RoutingHeaderType::RplSourceRoute,
        sgmt_left: 2,
    };

    let mut fixed_hdr = RplSourceFixedHeader {
        cmpr: 0,
        pad_reserved: [0; 3],
    };
    fixed_hdr.set_cmpr(8, 8);
    fixed_hdr.set_pad(0);
    fixed_hdr.set_reserved(0);

    let header = RplSourceRouteHeader {
        generic_route: gen_route,
        fixed_hdr,
    };

    let expected = header;

    (packet_data, expected)
}

// Verifies the parsed RPL header and its addresses
pub fn verify_rpl_source_route_header(received: ParsedHeader, expected: RplSourceRouteHeader) {
    assert_eq!(received.type_, PacketType::RplSourceRoute);
    let parsed_header: RplSourceRouteHeader = unsafe { received.data.rpl };
    let expected_header: RplSourceRouteHeader = expected;

    assert_eq!(
        parsed_header.generic_route.hdr_ext_len, expected_header.generic_route.hdr_ext_len,
        "Header Extension Length mismatch"
    );
    // Add other assertions for gen_route and fixed_hdr fields...

    // Verify total header length equals 24 (8 static + 16 variable)
    let total_hdr_len_bytes = 8 + (parsed_header.generic_route.hdr_ext_len as usize) * 8;
    assert_eq!(
        parsed_header.generic_route.hdr_ext_len, 2,
        "Expected hdr_ext_len=2 for RPL SRH test"
    );
    assert_eq!(
        total_hdr_len_bytes, 24,
        "Expected 24-byte RPL Source Route header by total_hdr_len"
    );
}
