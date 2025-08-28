use integration_common::{MAX_RPL_ADDR_STORAGE, PacketType, ParsedHeader, RplSourceRouteParsed};
use network_types::{
    ip::IpProto,
    route::{GenericRoute, RoutingHeaderType, RplSourceFixedHeader, RplSourceRouteHeader},
};

// Creates a test packet with two compressed addresses
pub fn create_rpl_source_route_test_packet() -> (Vec<u8>, RplSourceRouteParsed) {
    // With CmprI=8, CmprE=8, each address is 16-8=8 bytes (eliding 8 prefix octets)
    // Two addresses = 2 * 8 = 16 bytes of address data
    // Total header: GenericRoute (4) + RplSourceFixedHeader (4) + addresses (16) = 24 bytes
    // Hdr Ext Len = (24 - 8) / 8 = 2 (excluding first 8 octets, in 8-octet units)

    let packet_size = 1 + RplSourceRouteHeader::LEN + 16; // 1 byte discriminator + 8 byte header + 16 bytes addresses
    let mut packet_data = vec![0u8; packet_size];

    // Byte 0: Packet type discriminator for eBPF program
    packet_data[0] = PacketType::RplSourceRoute as u8;

    // GenericRoute (4 bytes) - starting at byte 1
    packet_data[1] = IpProto::Tcp as u8; // Next Header
    packet_data[2] = 2; // Hdr Ext Len (2 * 8 = 16 bytes additional data)
    packet_data[3] = RoutingHeaderType::RplSourceRoute.as_u8(); // Routing Type (3)
    packet_data[4] = 2; // Segments Left (2 addresses remaining)

    // RplSourceFixedHeader (4 bytes) - starting at byte 5
    packet_data[5] = (8 << 4) | 8; // CmprI=8, CmprE=8 (both compress 8 octets)
    packet_data[6] = 0; // Pad=0, Reserved upper 4 bits
    packet_data[7] = 0; // Reserved middle 8 bits
    packet_data[8] = 0; // Reserved lower 8 bits

    // Two compressed addresses (8 bytes each) - starting at byte 9
    // First address (compressed): remove first 8 bytes (2001:db8:85a3:0000), keep last 8
    packet_data[9..17].copy_from_slice(&[0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07]);

    // Second address (compressed): remove first 8 bytes (2001:db8:85a3:0000), keep last 8
    packet_data[17..25].copy_from_slice(&[0x08, 0x09, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15]);

    // Create the expected parsed structure
    let gen_route = GenericRoute {
        next_hdr: IpProto::Tcp,
        hdr_ext_len: 2,
        type_: RoutingHeaderType::RplSourceRoute.as_u8(),
        sgmt_left: 2,
    };

    let mut fixed_hdr = RplSourceFixedHeader {
        cmpr: 0,
        pad_reserved: [0; 3],
    };
    fixed_hdr.set_cmpr(8, 8); // CmprI=8, CmprE=8
    fixed_hdr.set_pad(0); // Pad=0
    fixed_hdr.set_reserved(0); // Reserved=0

    let header = RplSourceRouteHeader::new(gen_route, fixed_hdr);

    let mut addresses = [0u8; MAX_RPL_ADDR_STORAGE];
    // Copy the two compressed addresses (16 bytes total)
    addresses[0..16].copy_from_slice(&packet_data[9..25]);

    let expected = RplSourceRouteParsed {
        header,
        addresses,
        addresses_len: 16, // 2 addresses * 8 bytes each
    };

    (packet_data, expected)
}

// Verifies the parsed RPL header and its addresses
pub fn verify_rpl_source_route_header(received: ParsedHeader, expected: RplSourceRouteParsed) {
    assert_eq!(received.type_, PacketType::RplSourceRoute);
    let parsed_data = unsafe { received.data.rpl };
    let parsed_header = parsed_data.header;
    let expected_header = expected.header;

    assert_eq!(
        parsed_header.gen_route.hdr_ext_len, expected_header.gen_route.hdr_ext_len,
        "Header Extension Length mismatch"
    );
    // Add other assertions for gen_route and fixed_hdr fields...

    assert_eq!(
        parsed_data.addresses_len, expected.addresses_len,
        "Addresses length mismatch"
    );
    assert_eq!(
        &parsed_data.addresses[..parsed_data.addresses_len as usize],
        &expected.addresses[..expected.addresses_len as usize],
        "Addresses mismatch"
    );
}
