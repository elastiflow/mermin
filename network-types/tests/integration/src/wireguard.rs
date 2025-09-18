use integration_common::{PacketType, ParsedHeader, WireGuardMinimalHeader};
use network_types::wireguard::WireGuardType;

/// Creates a test packet for WireGuard Initiation (minimal header)
pub fn create_wireguard_initiation_test_packet() -> (Vec<u8>, WireGuardMinimalHeader) {
    let packet_size = 1 + WireGuardMinimalHeader::LEN; // 1 byte discriminator + header
    let mut packet_data = vec![0u8; packet_size];

    // Byte 0: Packet type discriminator for eBPF program
    packet_data[0] = PacketType::WireGuard as u8;

    // WireGuard Minimal Header (12 bytes) - starting at byte 1
    packet_data[1] = WireGuardType::HandshakeInitiation as u8; // Type
    packet_data[2..5].copy_from_slice(&[0x00, 0x00, 0x00]); // Reserved (3 bytes)

    // Sender Index (4 bytes) - big endian
    packet_data[5..9].copy_from_slice(&[0x12, 0x34, 0x56, 0x78]);

    // Receiver Index (4 bytes) - zero for initiation
    packet_data[9..13].copy_from_slice(&[0x00, 0x00, 0x00, 0x00]);

    // Create the expected parsed structure
    let expected = WireGuardMinimalHeader {
        type_: WireGuardType::HandshakeInitiation,
        reserved: [0x00, 0x00, 0x00],
        sender_ind: [0x12, 0x34, 0x56, 0x78],
        receiver_ind: [0x00, 0x00, 0x00, 0x00],
    };

    (packet_data, expected)
}

/// Creates a test packet for WireGuard Response (minimal header)
pub fn create_wireguard_response_test_packet() -> (Vec<u8>, WireGuardMinimalHeader) {
    let packet_size = 1 + WireGuardMinimalHeader::LEN; // 1 byte discriminator + header
    let mut packet_data = vec![0u8; packet_size];

    // Byte 0: Packet type discriminator for eBPF program
    packet_data[0] = PacketType::WireGuard as u8;

    // WireGuard Minimal Header (12 bytes) - starting at byte 1
    packet_data[1] = WireGuardType::HandshakeResponse as u8; // Type
    packet_data[2..5].copy_from_slice(&[0x00, 0x00, 0x00]); // Reserved (3 bytes)

    // Sender Index (4 bytes) - big endian
    packet_data[5..9].copy_from_slice(&[0x87, 0x65, 0x43, 0x21]);

    // Receiver Index (4 bytes) - big endian
    packet_data[9..13].copy_from_slice(&[0x11, 0x22, 0x33, 0x44]);

    // Create the expected parsed structure
    let expected = WireGuardMinimalHeader {
        type_: WireGuardType::HandshakeResponse,
        reserved: [0x00, 0x00, 0x00],
        sender_ind: [0x87, 0x65, 0x43, 0x21],
        receiver_ind: [0x11, 0x22, 0x33, 0x44],
    };

    (packet_data, expected)
}

/// Creates a test packet for WireGuard Cookie Reply (minimal header)
pub fn create_wireguard_cookie_reply_test_packet() -> (Vec<u8>, WireGuardMinimalHeader) {
    let packet_size = 1 + WireGuardMinimalHeader::LEN; // 1 byte discriminator + header
    let mut packet_data = vec![0u8; packet_size];

    // Byte 0: Packet type discriminator for eBPF program
    packet_data[0] = PacketType::WireGuard as u8;

    // WireGuard Minimal Header (12 bytes) - starting at byte 1
    packet_data[1] = WireGuardType::CookieReply as u8; // Type
    packet_data[2..5].copy_from_slice(&[0x00, 0x00, 0x00]); // Reserved (3 bytes)

    // Sender Index (4 bytes) - zero for cookie reply
    packet_data[5..9].copy_from_slice(&[0x00, 0x00, 0x00, 0x00]);

    // Receiver Index (4 bytes) - big endian
    packet_data[9..13].copy_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]);

    // Create the expected parsed structure
    let expected = WireGuardMinimalHeader {
        type_: WireGuardType::CookieReply,
        reserved: [0x00, 0x00, 0x00],
        sender_ind: [0x00, 0x00, 0x00, 0x00],
        receiver_ind: [0xDE, 0xAD, 0xBE, 0xEF],
    };

    (packet_data, expected)
}

/// Creates a test packet for WireGuard Transport Data (minimal header)
pub fn create_wireguard_transport_data_test_packet() -> (Vec<u8>, WireGuardMinimalHeader) {
    let packet_size = 1 + WireGuardMinimalHeader::LEN; // 1 byte discriminator + header
    let mut packet_data = vec![0u8; packet_size];

    // Byte 0: Packet type discriminator for eBPF program
    packet_data[0] = PacketType::WireGuard as u8;

    // WireGuard Minimal Header (12 bytes) - starting at byte 1
    packet_data[1] = WireGuardType::TransportData as u8; // Type
    packet_data[2..5].copy_from_slice(&[0x00, 0x00, 0x00]); // Reserved (3 bytes)

    // Sender Index (4 bytes) - zero for transport data
    packet_data[5..9].copy_from_slice(&[0x00, 0x00, 0x00, 0x00]);

    // Receiver Index (4 bytes) - big endian
    packet_data[9..13].copy_from_slice(&[0xCA, 0xFE, 0xBA, 0xBE]);

    // Create the expected parsed structure
    let expected = WireGuardMinimalHeader {
        type_: WireGuardType::TransportData,
        reserved: [0x00, 0x00, 0x00],
        sender_ind: [0x00, 0x00, 0x00, 0x00],
        receiver_ind: [0xCA, 0xFE, 0xBA, 0xBE],
    };

    (packet_data, expected)
}

/// Verifies the parsed WireGuard Minimal Header
/// This single verification function works for all WireGuard packet types
pub fn verify_wireguard_header(received: ParsedHeader, expected: WireGuardMinimalHeader) {
    assert_eq!(received.type_, PacketType::WireGuard);
    let parsed_header: WireGuardMinimalHeader = unsafe { received.data.wireguard };
    let expected_header: WireGuardMinimalHeader = expected;

    // Verify all fields match
    assert_eq!(parsed_header.type_, expected_header.type_, "Type mismatch");
    assert_eq!(
        parsed_header.reserved, expected_header.reserved,
        "Reserved field mismatch"
    );
    assert_eq!(
        parsed_header.sender_ind, expected_header.sender_ind,
        "Sender Index mismatch"
    );
    assert_eq!(
        parsed_header.receiver_ind, expected_header.receiver_ind,
        "Receiver Index mismatch"
    );

    // Verify getter methods work correctly
    assert_eq!(parsed_header.sender_ind(), expected_header.sender_ind());
    assert_eq!(parsed_header.receiver_ind(), expected_header.receiver_ind());
}
