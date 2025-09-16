use integration_common::{PacketType, ParsedHeader};
use network_types::{ip::IpProto, mobility::MobilityHdr};

// Helper for constructing Mobility Header test packets
pub fn create_mobility_test_packet() -> ([u8; MobilityHdr::LEN + 1], MobilityHdr) {
    let mut request_data = [0u8; MobilityHdr::LEN + 1];

    // Discriminator for eBPF match statement
    request_data[0] = PacketType::Mobility as u8;

    // Build expected header
    let mut expected = MobilityHdr {
        next_hdr: IpProto::Tcp,
        hdr_ext_len: 0, // minimal fixed 8 bytes (no additional 8-octet blocks)
        mh_type: 5,     // arbitrary MH type
        reserved: 0,
        checksum: [0x12, 0x34],
        reserved_data: [0, 0],
    };

    // Use setters as available
    expected.next_hdr = IpProto::Tcp;
    expected.hdr_ext_len = 0;
    expected.mh_type = 5;
    expected.reserved = 0;
    expected.set_checksum(0x1234);
    expected.set_reserved_data(0);

    // Serialize into buffer according to repr(C, packed) layout
    request_data[1] = expected.next_hdr as u8;
    request_data[2] = expected.hdr_ext_len;
    request_data[3] = expected.mh_type;
    request_data[4] = expected.reserved;
    request_data[5] = expected.checksum[0];
    request_data[6] = expected.checksum[1];
    request_data[7] = expected.reserved_data[0];
    request_data[8] = expected.reserved_data[1];

    (request_data, expected)
}

// Helper for verifying Mobility Header test results
pub fn verify_mobility_header(received: ParsedHeader, expected: MobilityHdr) {
    assert_eq!(received.type_, PacketType::Mobility);
    let parsed = unsafe { received.data.mobility };

    assert_eq!(parsed.next_hdr, expected.next_hdr, "Next Header mismatch");
    assert_eq!(
        parsed.hdr_ext_len, expected.hdr_ext_len,
        "Hdr Ext Len mismatch"
    );
    assert_eq!(parsed.mh_type, expected.mh_type, "MH Type mismatch");
    assert_eq!(parsed.reserved, expected.reserved, "Reserved mismatch");
    assert_eq!(parsed.checksum(), expected.checksum(), "Checksum mismatch");
    assert_eq!(
        parsed.reserved_data(),
        expected.reserved_data(),
        "Reserved data mismatch"
    );
    // Also sanity check total length for hdr_ext_len = 0
    assert_eq!(parsed.total_hdr_len(), 8, "Total header length mismatch");
}
