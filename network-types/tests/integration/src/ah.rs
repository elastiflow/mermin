use integration_common::{AhTestData, PacketType, ParsedHeader};
use network_types::ip::IpProto;

// Helper for constructing AH header test packets
// Only constructs the fields that are actually extracted by mermin-ebpf
pub fn create_ah_test_packet() -> ([u8; 13], AhTestData) {
    let mut request_data = [0u8; 13];

    // Byte 0: The type discriminator for the eBPF program's `match` statement.
    request_data[0] = PacketType::Ah as u8;

    // Bytes 1-12: AH header (12 bytes total minimum)
    request_data[1..13].copy_from_slice(&[
        // Byte 1: Next Header (next_hdr field - extracted at offset 0 from data)
        IpProto::Tcp as u8,
        // Byte 2: Payload Length (not extracted)
        2, // (2+2)*4 = 16 bytes total, 12 bytes fixed + 4 bytes ICV
        // Bytes 3-4: Reserved (not extracted)
        0x00,
        0x00,
        // Bytes 5-8: Security Parameters Index (spi field - extracted at offset 4 from data)
        0x12,
        0x34,
        0x56,
        0x78,
        // Bytes 9-12: Sequence Number (not extracted)
        0x00,
        0x00,
        0x00,
        0x01,
    ]);

    let expected_header = AhTestData {
        next_hdr: IpProto::Tcp as u8,
        spi: [0x12, 0x34, 0x56, 0x78],
    };

    (request_data, expected_header)
}

// Helper for verifying AH header test results
pub fn verify_ah_header(received: ParsedHeader, expected: AhTestData) {
    assert_eq!(received.type_, PacketType::Ah);
    let parsed_header = unsafe { received.data.ah };

    assert_eq!(
        parsed_header.next_hdr, expected.next_hdr,
        "Next Header mismatch: got {}, expected {}",
        parsed_header.next_hdr, expected.next_hdr
    );

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
