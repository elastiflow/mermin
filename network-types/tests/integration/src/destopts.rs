use integration_common::{PacketType, ParsedHeader};
use network_types::{destopts::DestOptsHdr, ip::IpProto};

// Helper for constructing Destination Options Header test packets
pub fn create_destopts_test_packet() -> ([u8; DestOptsHdr::LEN + 1], DestOptsHdr) {
    let mut request_data = [0u8; DestOptsHdr::LEN + 1];

    // Discriminator for eBPF match statement
    request_data[0] = PacketType::DestOpts as u8;

    // Build expected header
    let mut expected = DestOptsHdr {
        next_hdr: IpProto::Tcp,
        hdr_ext_len: 0, // minimal header size (only 8 bytes total)
        opt_data: [0u8; 6],
    };

    expected.set_next_hdr(IpProto::Tcp);
    expected.set_hdr_ext_len(0);
    // Fill some option padding bytes (for deterministic comparison)
    expected
        .opt_data
        .copy_from_slice(&[0x01, 0x02, 0x03, 0x04, 0x05, 0x06]);

    // Serialize into buffer, following repr(C, packed) layout
    request_data[1] = expected.next_hdr as u8; // Next Header
    request_data[2] = expected.hdr_ext_len; // Hdr Ext Len
    request_data[3..9].copy_from_slice(&expected.opt_data); // 6 bytes of option/pad

    (request_data, expected)
}

// Helper for verifying Destination Options Header test results
pub fn verify_destopts_header(received: ParsedHeader, expected: DestOptsHdr) {
    assert_eq!(received.type_, PacketType::DestOpts);
    let parsed = unsafe { received.data.destopts };

    assert_eq!(
        parsed.next_hdr(),
        expected.next_hdr(),
        "Next Header mismatch"
    );
    assert_eq!(
        parsed.hdr_ext_len(),
        expected.hdr_ext_len(),
        "Hdr Ext Len mismatch"
    );
    assert_eq!(parsed.opt_data, expected.opt_data, "Option data mismatch");

    // Also validate total length calculation for hdr_ext_len = 0
    assert_eq!(parsed.total_hdr_len(), 8, "Total header length mismatch");
}
