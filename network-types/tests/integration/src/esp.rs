use integration_common::{NextHdrOnlyTestData, PacketType, ParsedHeader};
use network_types::{esp::ESP_LEN, ip::IpProto};

/// Helper for constructing ESP header test packets
/// 
/// Note: ESP only extracts next_hdr in practice, but since ESP payload is encrypted,
/// mermin-ebpf stops processing after ESP. For testing purposes, we still verify
/// that the basic header fields can be parsed.
pub fn create_esp_test_packet() -> ([u8; ESP_LEN + 1], NextHdrOnlyTestData) {
    let mut request_data = [0u8; ESP_LEN + 1];

    // Byte 0: The type discriminator for the eBPF program's `match` statement
    request_data[0] = PacketType::Esp as u8;
    
    // Byte 1: SPI (first byte) - We'll use this as a placeholder for next_hdr
    // In reality, ESP doesn't have a next_hdr field in the fixed header
    request_data[1] = IpProto::Tcp as u8;
    
    // Bytes 2-8: SPI (remaining) and Sequence Number - NOT extracted
    request_data[2..9].copy_from_slice(&[0x34, 0x56, 0x78, 0x87, 0x65, 0x43, 0x21]);

    let expected_data = NextHdrOnlyTestData {
        next_hdr: IpProto::Tcp as u8,
    };

    (request_data, expected_data)
}

/// Helper for verifying ESP header test results
pub fn verify_esp_header(received: ParsedHeader, expected: NextHdrOnlyTestData) {
    assert_eq!(received.type_, PacketType::Esp, "Packet type mismatch");
    
    let parsed = unsafe { received.data.next_hdr_only };

    assert_eq!(
        parsed.next_hdr, expected.next_hdr,
        "Next header mismatch: expected {}, got {}",
        expected.next_hdr, parsed.next_hdr
    );
}
