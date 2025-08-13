use integration_common::{PacketType, ParsedHeader};
use network_types::{ah::AuthHdr, ip::IpProto};

// Helper for constructing Authentication Header test packets
pub fn create_ah_test_packet() -> ([u8; AuthHdr::LEN + 1], AuthHdr) {
    let mut request_data = [0u8; AuthHdr::LEN + 1];

    // Byte 0: The type discriminator for the eBPF program's `match` statement.
    request_data[0] = PacketType::Ah as u8;
    // Bytes 1: Next Header (TCP = 6)
    request_data[1] = IpProto::Tcp as u8;
    // Byte 2: Payload Length (2 in 4-octet units, which means 16 bytes total)
    request_data[2] = 2;
    // Bytes 3-4: Reserved (should be 0)
    request_data[3] = 0;
    request_data[4] = 0;
    // Bytes 5-8: SPI (Security Parameters Index)
    request_data[5..9].copy_from_slice(&[0x12, 0x34, 0x56, 0x78]);
    // Bytes 9-12: Sequence Number
    request_data[9..13].copy_from_slice(&[0x87, 0x65, 0x43, 0x21]);

    let expected_header = AuthHdr {
        next_hdr: IpProto::Tcp,
        payload_len: 2,
        reserved: [0, 0],
        spi: [0x12, 0x34, 0x56, 0x78],
        seq_num: [0x87, 0x65, 0x43, 0x21],
    };

    (request_data, expected_header)
}

// Helper for verifying Authentication Header test results
pub fn verify_ah_header(received: ParsedHeader, expected: AuthHdr) {
    assert_eq!(received.type_, PacketType::Ah);
    let parsed_header = unsafe { received.data.ah };

    assert_eq!(
        parsed_header.next_hdr, expected.next_hdr,
        "Next Header mismatch"
    );
    assert_eq!(
        parsed_header.payload_len, expected.payload_len,
        "Payload Length mismatch"
    );
    assert_eq!(
        parsed_header.reserved, expected.reserved,
        "Reserved field mismatch"
    );
    assert_eq!(parsed_header.spi, expected.spi, "SPI mismatch");
    assert_eq!(
        parsed_header.seq_num, expected.seq_num,
        "Sequence Number mismatch"
    );
}
