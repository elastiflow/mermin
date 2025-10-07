use integration_common::{PacketType, ParsedHeader, VxlanTestData};
use network_types::vxlan::{VXLAN_I_FLAG_MASK, VXLAN_LEN};

// Helper for constructing VXLAN header test packets
// Only constructs the fields that are actually extracted by mermin-ebpf
pub fn create_vxlan_test_packet() -> ([u8; VXLAN_LEN + 1], VxlanTestData) {
    let mut request_data = [0u8; VXLAN_LEN + 1];

    // Byte 0: The type discriminator for the eBPF program's `match` statement.
    request_data[0] = PacketType::Vxlan as u8;

    // Bytes 1-8: VXLAN header (8 bytes)
    request_data[1..9].copy_from_slice(&[
        // Byte 1: Flags (flags field - extracted at offset 0 from data)
        0b00001000, // I flag set (bit 3), other bits reserved
        // Bytes 2-4: Reserved (not extracted)
        0x00, 0x00, 0x00,
        // Bytes 5-7: VNI (vni field - extracted at offset 4 from data, only if I flag set)
        0x12, 0x34, 0x56, // VNI: 0x123456
        // Byte 8: Reserved (not extracted)
        0x00,
    ]);

    let expected_header = VxlanTestData {
        flags: 0b00001000, // I flag set
        vni: [0x12, 0x34, 0x56],
    };

    (request_data, expected_header)
}

// Helper for verifying VXLAN header test results
pub fn verify_vxlan_header(received: ParsedHeader, expected: VxlanTestData) {
    assert_eq!(received.type_, PacketType::Vxlan);
    let parsed_header = unsafe { received.data.vxlan };

    assert_eq!(
        parsed_header.flags, expected.flags,
        "Flags mismatch: got {:#x}, expected {:#x}",
        parsed_header.flags, expected.flags
    );

    assert_eq!(
        parsed_header.vni,
        expected.vni,
        "VNI mismatch: got [{:#x}, {:#x}, {:#x}], expected [{:#x}, {:#x}, {:#x}]",
        parsed_header.vni[0],
        parsed_header.vni[1],
        parsed_header.vni[2],
        expected.vni[0],
        expected.vni[1],
        expected.vni[2]
    );

    // Verify that I flag is set (as expected in our test data)
    assert!(
        (parsed_header.flags & VXLAN_I_FLAG_MASK) != 0,
        "I flag should be set in test data"
    );
}
