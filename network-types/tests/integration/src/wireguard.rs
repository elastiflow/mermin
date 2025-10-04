use integration_common::{
    PacketType, ParsedHeader, WireGuardCookieReplyTestData, WireGuardInitTestData,
    WireGuardResponseTestData, WireGuardTransportDataTestData,
};
use network_types::wireguard::WireGuardType;

/// Creates a test packet for WireGuard Initiation
pub fn create_wireguard_initiation_test_packet() -> (Vec<u8>, WireGuardInitTestData) {
    let packet_size = 1 + 8; // 1 byte discriminator + 8 bytes (1 type + 3 reserved + 4 sender_ind)
    let mut packet_data = vec![0u8; packet_size];

    // Byte 0: Packet type discriminator for eBPF program
    packet_data[0] = PacketType::WireGuardInit as u8;

    // WireGuard Init Header - starting at byte 1
    packet_data[1] = WireGuardType::HandshakeInitiation as u8; // Type
    // Bytes 2-4: Reserved (not used by parser)

    // Sender Index (4 bytes) - little endian (offset +4)
    packet_data[5..9].copy_from_slice(&[0x78, 0x56, 0x34, 0x12]);

    // Create the expected parsed structure
    let expected = WireGuardInitTestData {
        type_: WireGuardType::HandshakeInitiation,
        sender_ind: [0x78, 0x56, 0x34, 0x12],
    };

    (packet_data, expected)
}

/// Creates a test packet for WireGuard Response
pub fn create_wireguard_response_test_packet() -> (Vec<u8>, WireGuardResponseTestData) {
    let packet_size = 1 + 12; // 1 byte discriminator + 12 bytes (1 type + 3 reserved + 4 sender_ind + 4 receiver_ind)
    let mut packet_data = vec![0u8; packet_size];

    // Byte 0: Packet type discriminator for eBPF program
    packet_data[0] = PacketType::WireGuardResponse as u8;

    // WireGuard Response Header - starting at byte 1
    packet_data[1] = WireGuardType::HandshakeResponse as u8; // Type
    // Bytes 2-4: Reserved (not used by parser)

    // Sender Index (4 bytes) - little endian (offset +4)
    packet_data[5..9].copy_from_slice(&[0x21, 0x43, 0x65, 0x87]);

    // Receiver Index (4 bytes) - little endian (offset +8)
    packet_data[9..13].copy_from_slice(&[0x44, 0x33, 0x22, 0x11]);

    // Create the expected parsed structure
    let expected = WireGuardResponseTestData {
        type_: WireGuardType::HandshakeResponse,
        sender_ind: [0x21, 0x43, 0x65, 0x87],
        receiver_ind: [0x44, 0x33, 0x22, 0x11],
    };

    (packet_data, expected)
}

/// Creates a test packet for WireGuard Cookie Reply
pub fn create_wireguard_cookie_reply_test_packet() -> (Vec<u8>, WireGuardCookieReplyTestData) {
    let packet_size = 1 + 8; // 1 byte discriminator + 8 bytes (1 type + 3 reserved + 4 receiver_ind)
    let mut packet_data = vec![0u8; packet_size];

    // Byte 0: Packet type discriminator for eBPF program
    packet_data[0] = PacketType::WireGuardCookieReply as u8;

    // WireGuard Cookie Reply Header - starting at byte 1
    packet_data[1] = WireGuardType::CookieReply as u8; // Type
    // Bytes 2-4: Reserved (not used by parser)

    // Receiver Index (4 bytes) - little endian (offset +4)
    packet_data[5..9].copy_from_slice(&[0xEF, 0xBE, 0xAD, 0xDE]);

    // Create the expected parsed structure
    let expected = WireGuardCookieReplyTestData {
        type_: WireGuardType::CookieReply,
        receiver_ind: [0xEF, 0xBE, 0xAD, 0xDE],
    };

    (packet_data, expected)
}

/// Creates a test packet for WireGuard Transport Data
pub fn create_wireguard_transport_data_test_packet() -> (Vec<u8>, WireGuardTransportDataTestData) {
    let packet_size = 1 + 8; // 1 byte discriminator + 8 bytes (1 type + 3 reserved + 4 receiver_ind)
    let mut packet_data = vec![0u8; packet_size];

    // Byte 0: Packet type discriminator for eBPF program
    packet_data[0] = PacketType::WireGuardTransportData as u8;

    // WireGuard Transport Data Header - starting at byte 1
    packet_data[1] = WireGuardType::TransportData as u8; // Type
    // Bytes 2-4: Reserved (not used by parser)

    // Receiver Index (4 bytes) - little endian (offset +4)
    packet_data[5..9].copy_from_slice(&[0xBE, 0xBA, 0xFE, 0xCA]);

    // Create the expected parsed structure
    let expected = WireGuardTransportDataTestData {
        type_: WireGuardType::TransportData,
        receiver_ind: [0xBE, 0xBA, 0xFE, 0xCA],
    };

    (packet_data, expected)
}

/// Verifies the parsed WireGuard Init Header
pub fn verify_wireguard_init_header(received: ParsedHeader, expected: WireGuardInitTestData) {
    assert_eq!(received.type_, PacketType::WireGuardInit);
    let parsed_header: WireGuardInitTestData = unsafe { received.data.wireguard_init };
    let expected_header: WireGuardInitTestData = expected;

    // Verify all fields match
    assert_eq!(parsed_header.type_, expected_header.type_, "Type mismatch");
    assert_eq!(
        parsed_header.sender_ind, expected_header.sender_ind,
        "Sender Index mismatch"
    );

    // Verify getter methods work correctly
    assert_eq!(parsed_header.sender_ind(), expected_header.sender_ind());
}

/// Verifies the parsed WireGuard Response Header
pub fn verify_wireguard_response_header(
    received: ParsedHeader,
    expected: WireGuardResponseTestData,
) {
    assert_eq!(received.type_, PacketType::WireGuardResponse);
    let parsed_header: WireGuardResponseTestData = unsafe { received.data.wireguard_response };
    let expected_header: WireGuardResponseTestData = expected;

    // Verify all fields match
    assert_eq!(parsed_header.type_, expected_header.type_, "Type mismatch");
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

/// Verifies the parsed WireGuard Cookie Reply Header
pub fn verify_wireguard_cookie_reply_header(
    received: ParsedHeader,
    expected: WireGuardCookieReplyTestData,
) {
    assert_eq!(received.type_, PacketType::WireGuardCookieReply);
    let parsed_header: WireGuardCookieReplyTestData =
        unsafe { received.data.wireguard_cookie_reply };
    let expected_header: WireGuardCookieReplyTestData = expected;

    // Verify all fields match
    assert_eq!(parsed_header.type_, expected_header.type_, "Type mismatch");
    assert_eq!(
        parsed_header.receiver_ind, expected_header.receiver_ind,
        "Receiver Index mismatch"
    );

    // Verify getter methods work correctly
    assert_eq!(parsed_header.receiver_ind(), expected_header.receiver_ind());
}

/// Verifies the parsed WireGuard Transport Data Header
pub fn verify_wireguard_transport_data_header(
    received: ParsedHeader,
    expected: WireGuardTransportDataTestData,
) {
    assert_eq!(received.type_, PacketType::WireGuardTransportData);
    let parsed_header: WireGuardTransportDataTestData =
        unsafe { received.data.wireguard_transport_data };
    let expected_header: WireGuardTransportDataTestData = expected;

    // Verify all fields match
    assert_eq!(parsed_header.type_, expected_header.type_, "Type mismatch");
    assert_eq!(
        parsed_header.receiver_ind, expected_header.receiver_ind,
        "Receiver Index mismatch"
    );

    // Verify getter methods work correctly
    assert_eq!(parsed_header.receiver_ind(), expected_header.receiver_ind());
}
