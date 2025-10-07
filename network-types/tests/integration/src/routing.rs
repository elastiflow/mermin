use integration_common::{GenericRouteTestData, PacketType, ParsedHeader};
use network_types::{ip::IpProto, route::GENERIC_ROUTE_LEN};

// Helper for constructing Generic Route header test packets
// Only constructs the fields that are actually extracted by mermin-ebpf
pub fn create_generic_route_test_packet() -> ([u8; GENERIC_ROUTE_LEN + 1], GenericRouteTestData) {
    let mut request_data = [0u8; GENERIC_ROUTE_LEN + 1];

    // Byte 0: The type discriminator for the eBPF program's `match` statement.
    request_data[0] = PacketType::GenericRoute as u8;

    // Bytes 1-4: Generic Route header (4 bytes)
    request_data[1..5].copy_from_slice(&[
        // Byte 1: Next Header (next_hdr field - extracted at offset 0 from data)
        IpProto::Tcp as u8,
        // Byte 2: Header Extension Length (hdr_ext_len field - extracted at offset 1 from data)
        1, // (1+1)*8 = 16 bytes total
        // Byte 3: Routing Type (not extracted)
        0, // Type 0 (Source Route)
        // Byte 4: Segments Left (not extracted)
        2, // 2 segments left
    ]);

    let expected_header = GenericRouteTestData {
        next_hdr: IpProto::Tcp as u8,
        hdr_ext_len: 1,
    };

    (request_data, expected_header)
}

// Helper for verifying Generic Route header test results
pub fn verify_generic_route_header(received: ParsedHeader, expected: GenericRouteTestData) {
    assert_eq!(received.type_, PacketType::GenericRoute);
    let parsed_header = unsafe { received.data.generic_route };

    assert_eq!(
        parsed_header.next_hdr, expected.next_hdr,
        "Next Header mismatch: got {}, expected {}",
        parsed_header.next_hdr, expected.next_hdr
    );

    assert_eq!(
        parsed_header.hdr_ext_len, expected.hdr_ext_len,
        "Header Extension Length mismatch: got {}, expected {}",
        parsed_header.hdr_ext_len, expected.hdr_ext_len
    );
}
