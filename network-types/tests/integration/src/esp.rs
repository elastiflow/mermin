use integration_common::{EspTestData, PacketType, ParsedHeader};
use network_types::esp::ESP_LEN;

// Helper for constructing ESP header test packets
// Only constructs the fields that are actually extracted by mermin-ebpf
pub fn create_esp_test_packet() -> ([u8; ESP_LEN + 1], EspTestData) {
    let mut request_data = [0u8; ESP_LEN + 1];

    // Byte 0: The type discriminator for the eBPF program's `match` statement.
    request_data[0] = PacketType::Esp as u8;

    // Bytes 1-8: ESP header (8 bytes total)
    request_data[1..9].copy_from_slice(&[
        // Bytes 1-4: Security Parameters Index (spi field - extracted at offset 0 from data)
        0x12, 0x34, 0x56, 0x78, // Bytes 5-8: Sequence Number (not extracted)
        0x00, 0x00, 0x00, 0x01,
    ]);

    let expected_header = EspTestData {
        spi: [0x12, 0x34, 0x56, 0x78],
    };

    (request_data, expected_header)
}

// Helper for verifying ESP header test results
pub fn verify_esp_header(received: ParsedHeader, expected: EspTestData) {
    assert_eq!(received.type_, PacketType::Esp);
    let parsed_header = unsafe { received.data.esp };

    assert_eq!(
        parsed_header.spi,
        expected.spi,
        "SPI mismatch: got [{:#x}, {:#x}, {:#x}, {:#x}], expected [{:#x}, {:#x}, {:#x}, {:#x}]",
        parsed_header.spi[0],
        parsed_header.spi[1],
        parsed_header.spi[2],
        parsed_header.spi[3],
        expected.spi[0],
        expected.spi[1],
        expected.spi[2],
        expected.spi[3]
    );
}
