use integration_common::{PacketType, ParsedHeader};
use network_types::{fragment::Fragment, ip::IpProto};

// Helper for constructing Fragment Header test packets
pub fn create_fragment_test_packet() -> ([u8; Fragment::LEN + 1], Fragment) {
    let mut request_data = [0u8; Fragment::LEN + 1];

    // Discriminator for eBPF match statement
    request_data[0] = PacketType::Fragment as u8;

    // Build expected header using setters to ensure correct bit packing
    let mut expected_header = Fragment {
        next_hdr: IpProto::Tcp,
        reserved: 0,
        frag_offset: 0,
        fo_res_m: 0,
        id: [0; 4],
    };

    expected_header.set_next_hdr(IpProto::Tcp);
    expected_header.set_reserved(0);
    // Choose an arbitrary 13-bit fragment offset
    expected_header.set_fragment_offset(0x1234 & 0x1FFF);
    // Set reserved2 to 0 and M flag to true
    expected_header.set_reserved2(0);
    expected_header.set_m_flag(true);
    // Set identification field
    expected_header.set_identification(0x11_22_33_44);

    // Serialize fields into the request buffer following the struct layout
    request_data[1] = expected_header.next_hdr as u8; // Next Header
    request_data[2] = expected_header.reserved; // Reserved
    request_data[3] = expected_header.frag_offset; // Fragment Offset (low 8 bits portion per layout)
    request_data[4] = expected_header.fo_res_m; // Upper offset bits + reserved2 + M flag
    request_data[5..9].copy_from_slice(&expected_header.id); // Identification

    (request_data, expected_header)
}

// Helper for verifying Fragment Header test results
pub fn verify_fragment_header(received: ParsedHeader, expected: Fragment) {
    assert_eq!(received.type_, PacketType::Fragment);
    let parsed = unsafe { received.data.fragment };

    // Compare via accessors to validate bit-packed fields
    assert_eq!(
        parsed.next_hdr(),
        expected.next_hdr(),
        "Next Header mismatch"
    );
    assert_eq!(parsed.reserved(), expected.reserved(), "Reserved mismatch");
    assert_eq!(
        parsed.fragment_offset(),
        expected.fragment_offset(),
        "Fragment Offset mismatch"
    );
    assert_eq!(
        parsed.reserved2(),
        expected.reserved2(),
        "Reserved2 mismatch"
    );
    assert_eq!(parsed.m_flag(), expected.m_flag(), "M flag mismatch");
    assert_eq!(
        parsed.identification(),
        expected.identification(),
        "Identification mismatch"
    );
}
