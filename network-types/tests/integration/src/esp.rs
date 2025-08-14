use integration_common::{PacketType, ParsedHeader};
use network_types::esp::Esp;

// Helper for constructing ESP test packets
pub fn create_esp_test_packet() -> ([u8; Esp::LEN + 1], Esp) {
    let mut request_data = [0u8; Esp::LEN + 1];

    // Byte 0: The type discriminator for the eBPF program's `match` statement.
    request_data[0] = PacketType::Esp as u8;
    // Bytes 1-4: SPI (Security Parameters Index)
    request_data[1..5].copy_from_slice(&[0x12, 0x34, 0x56, 0x78]);
    // Bytes 5-8: Sequence Number
    request_data[5..9].copy_from_slice(&[0x87, 0x65, 0x43, 0x21]);

    let expected_header = Esp {
        spi: [0x12, 0x34, 0x56, 0x78],
        seq_num: [0x87, 0x65, 0x43, 0x21],
    };

    (request_data, expected_header)
}

// Helper for verifying ESP test results
pub fn verify_esp_header(received: ParsedHeader, expected: Esp) {
    assert_eq!(received.type_, PacketType::Esp);
    let parsed_header = unsafe { received.data.esp };

    assert_eq!(parsed_header.spi, expected.spi, "SPI mismatch");
    assert_eq!(
        parsed_header.seq_num, expected.seq_num,
        "Sequence Number mismatch"
    );
}
