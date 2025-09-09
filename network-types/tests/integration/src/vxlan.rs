use integration_common::{PacketType, ParsedHeader};
use network_types::vxlan::VxlanHdr;

// Helper for constructing Vxlan header test packets
pub fn create_vxlan_test_packet() -> ([u8; VxlanHdr::LEN + 1], VxlanHdr) {
    let mut request_data = [0u8; VxlanHdr::LEN + 1];

    // Byte 0: The type discriminator for the eBPF program's `match` statement.
    request_data[0] = PacketType::Vxlan as u8;

    // Flags (8 bits). Setting I flag (bit 3) to 1 for VNI presence
    request_data[1] = 0x08;

    // Reserved field (24 bits)
    request_data[2] = 0;
    request_data[3] = 0;
    request_data[4] = 0;

    // VNI (24 bits) - Setting to 0x123456
    request_data[5] = 0x12;
    request_data[6] = 0x34;
    request_data[7] = 0x56;

    // Reserved field (8 bits)
    request_data[8] = 0;

    let expected_header = VxlanHdr {
        flags: 0x08,
        _reserved1: [0, 0, 0],
        vni: [0x12, 0x34, 0x56],
        _reserved2: 0,
    };

    (request_data, expected_header)
}

// Helper for verifying Vxlan header test results
pub fn verify_vxlan_header(received: ParsedHeader, expected: VxlanHdr) {
    assert_eq!(received.type_, PacketType::Vxlan);
    let parsed_header = unsafe { received.data.vxlan };

    // Verify flags
    assert_eq!(parsed_header.flags, expected.flags, "Flags mismatch");

    // Verify reserved fields
    assert_eq!(
        parsed_header._reserved1, expected._reserved1,
        "Reserved1 field mismatch"
    );

    // Verify VNI
    assert_eq!(parsed_header.vni, expected.vni, "VNI mismatch");

    // Verify Reserved2 field
    assert_eq!(
        parsed_header._reserved2, expected._reserved2,
        "Reserved2 field mismatch"
    );
}
