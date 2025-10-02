use integration_common::{NextHdrOnlyTestData, PacketType, ParsedHeader};
use network_types::{fragment::FRAGMENT_LEN, ip::IpProto};

/// Helper for constructing Fragment header test packets
/// 
/// Matches the new parsing methodology where we only extract:
/// - Byte 0: Next Header (IpProto)
pub fn create_fragment_test_packet() -> ([u8; FRAGMENT_LEN + 1], NextHdrOnlyTestData) {
    let mut request_data = [0u8; FRAGMENT_LEN + 1];

    // Byte 0: The type discriminator for the eBPF program's `match` statement
    request_data[0] = PacketType::Fragment as u8;
    
    // Byte 1: Next Header (IpProto::Tcp) - THIS IS EXTRACTED
    request_data[1] = IpProto::Tcp as u8;
    
    // Bytes 2-8: Remaining fields - NOT extracted
    request_data[2] = 0;  // Reserved
    request_data[3..5].copy_from_slice(&[0x12, 0x34]);  // Fragment Offset & Flags
    request_data[5..9].copy_from_slice(&[0x56, 0x78, 0x9A, 0xBC]);  // Identification

    let expected_data = NextHdrOnlyTestData {
        next_hdr: IpProto::Tcp as u8,
    };

    (request_data, expected_data)
}

/// Helper for verifying Fragment header test results
pub fn verify_fragment_header(received: ParsedHeader, expected: NextHdrOnlyTestData) {
    assert_eq!(received.type_, PacketType::Fragment, "Packet type mismatch");
    
    let parsed = unsafe { received.data.next_hdr_only };

    assert_eq!(
        parsed.next_hdr, expected.next_hdr,
        "Next header mismatch: expected {}, got {}",
        expected.next_hdr, parsed.next_hdr
    );
}
