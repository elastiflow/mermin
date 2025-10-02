use integration_common::{NextHdrOnlyTestData, PacketType, ParsedHeader};
use network_types::{destopts::DEST_OPTS_LEN, ip::IpProto};

/// Helper for constructing Destination Options header test packets
/// 
/// Matches the new parsing methodology where we only extract:
/// - Byte 0: Next Header (IpProto)
pub fn create_destopts_test_packet() -> ([u8; DEST_OPTS_LEN + 1], NextHdrOnlyTestData) {
    let mut request_data = [0u8; DEST_OPTS_LEN + 1];

    // Byte 0: The type discriminator for the eBPF program's `match` statement
    request_data[0] = PacketType::DestOpts as u8;
    
    // Byte 1: Next Header (IpProto::Tcp) - THIS IS EXTRACTED
    request_data[1] = IpProto::Tcp as u8;
    
    // Byte 2: Header Extension Length - NOT extracted
    request_data[2] = 0;

    let expected_data = NextHdrOnlyTestData {
        next_hdr: IpProto::Tcp as u8,
    };

    (request_data, expected_data)
}

/// Helper for verifying Destination Options header test results
pub fn verify_destopts_header(received: ParsedHeader, expected: NextHdrOnlyTestData) {
    assert_eq!(received.type_, PacketType::DestOpts, "Packet type mismatch");
    
    let parsed = unsafe { received.data.next_hdr_only };

    assert_eq!(
        parsed.next_hdr, expected.next_hdr,
        "Next header mismatch: expected {}, got {}",
        expected.next_hdr, parsed.next_hdr
    );
}
