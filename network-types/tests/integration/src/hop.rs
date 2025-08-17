use integration_common::{PacketType, ParsedHeader};
use network_types::{hop::HopOptHdr, ip::IpProto};

// Helper for constructing Hop-by-Hop Options Header test packets
pub fn create_hop_test_packet() -> ([u8; HopOptHdr::LEN + 1], HopOptHdr) {
    let mut request_data = [0u8; HopOptHdr::LEN + 1];

    // Byte 0: The type discriminator for the eBPF program's `match` statement.
    request_data[0] = PacketType::Hop as u8;
    // Byte 1: Next Header (TCP = 6)
    request_data[1] = IpProto::Tcp as u8;
    // Byte 2: Header Extension Length (0 means 8 bytes total, which is the minimum)
    request_data[2] = 0;
    // Bytes 3-8: Option data (6 bytes)
    request_data[3..9].copy_from_slice(&[0x01, 0x02, 0x03, 0x04, 0x05, 0x06]);

    let expected_header = HopOptHdr {
        next_hdr: IpProto::Tcp,
        hdr_ext_len: 0,
        opt_data: [0x01, 0x02, 0x03, 0x04, 0x05, 0x06],
    };

    (request_data, expected_header)
}

// Helper for verifying Hop-by-Hop Options Header test results
pub fn verify_hop_header(received: ParsedHeader, expected: HopOptHdr) {
    assert_eq!(received.type_, PacketType::Hop);
    let parsed_header = unsafe { received.data.hop };

    assert_eq!(
        parsed_header.next_hdr, expected.next_hdr,
        "Next Header mismatch"
    );
    assert_eq!(
        parsed_header.hdr_ext_len, expected.hdr_ext_len,
        "Header Extension Length mismatch"
    );
    assert_eq!(
        parsed_header.opt_data, expected.opt_data,
        "Option data mismatch"
    );
}
