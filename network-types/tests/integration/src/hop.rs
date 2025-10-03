use integration_common::{HopOptTestData, PacketType, ParsedHeader};
use network_types::{hop::HOP_OPT_LEN, ip::IpProto};

// Helper for constructing Hop-by-Hop Options header test packets
// Only constructs the fields that are actually extracted by mermin-ebpf
pub fn create_hop_test_packet() -> ([u8; HOP_OPT_LEN + 1], HopOptTestData) {
    let mut request_data = [0u8; HOP_OPT_LEN + 1];

    // Byte 0: The type discriminator for the eBPF program's `match` statement.
    request_data[0] = PacketType::Hop as u8;

    // Bytes 1-8: Hop-by-Hop Options header (8 bytes minimum)
    request_data[1..9].copy_from_slice(&[
        // Byte 1: Next Header (next_hdr field - extracted at offset 0 from data)
        IpProto::Tcp as u8,
        // Byte 2: Header Extension Length (not extracted)
        0, // (0+1)*8 = 8 bytes total
        // Bytes 3-8: Options data (not extracted)
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
    ]);

    let expected_header = HopOptTestData {
        next_hdr: IpProto::Tcp as u8,
    };

    (request_data, expected_header)
}

// Helper for verifying Hop-by-Hop Options header test results
pub fn verify_hop_header(received: ParsedHeader, expected: HopOptTestData) {
    assert_eq!(received.type_, PacketType::Hop);
    let parsed_header = unsafe { received.data.hop };

    assert_eq!(
        parsed_header.next_hdr, expected.next_hdr,
        "Next Header mismatch: got {}, expected {}",
        parsed_header.next_hdr, expected.next_hdr
    );
}
