use integration_common::{NextHdrOnlyTestData, PacketType, ParsedHeader};
use network_types::{ip::IpProto, mobility::MOBILITY_LEN};

/// Helper for constructing Mobility header test packets
/// 
/// Matches the new parsing methodology where we only extract:
/// - Byte 0: Next Header (IpProto)
pub fn create_mobility_test_packet() -> ([u8; MOBILITY_LEN + 1], NextHdrOnlyTestData) {
    let mut request_data = [0u8; MOBILITY_LEN + 1];

    // Byte 0: The type discriminator for the eBPF program's `match` statement
    request_data[0] = PacketType::Mobility as u8;
    
    // Byte 1: Next Header (IpProto::Tcp) - THIS IS EXTRACTED
    request_data[1] = IpProto::Tcp as u8;
    
    // Bytes 2-7: Remaining fields - NOT extracted
    request_data[2] = 0;  // Header Length
    request_data[3] = 0;  // MH Type
    request_data[4] = 0;  // Reserved
    request_data[5..8].copy_from_slice(&[0, 0, 0]);  // Checksum

    let expected_data = NextHdrOnlyTestData {
        next_hdr: IpProto::Tcp as u8,
    };

    (request_data, expected_data)
}

/// Helper for verifying Mobility header test results
pub fn verify_mobility_header(received: ParsedHeader, expected: NextHdrOnlyTestData) {
    assert_eq!(received.type_, PacketType::Mobility, "Packet type mismatch");
    
    let parsed = unsafe { received.data.next_hdr_only };

    assert_eq!(
        parsed.next_hdr, expected.next_hdr,
        "Next header mismatch: expected {}, got {}",
        expected.next_hdr, parsed.next_hdr
    );
}
