use integration_common::{PacketType, ParsedHeader};
use network_types::{hip::HipHdr, ip::IpProto};

// Creates a basic HIP header test packet with no parameters (hdr_len set for base header only)
pub fn create_hip_test_packet() -> (Vec<u8>, HipHdr) {
    // HipHdr::LEN is 40 bytes base header
    // hdr_len counts 8-octet units excluding first 8 bytes, so for 40 total: (40-8)/8 = 4
    let hdr_len = 4u8;
    let total_len = (hdr_len as usize + 1) * 8; // 40

    let packet_size = 1 + total_len; // discriminator + HIP header
    let mut packet_data = vec![0u8; packet_size];

    packet_data[0] = PacketType::Hip as u8;

    // Fixed fields
    packet_data[1] = IpProto::Ipv6NoNxt as u8; // Next Header
    packet_data[2] = hdr_len; // Header Length

    // packet_type_field: top bit fixed 0, lower 7 bits packet type (choose 2 for R1, arbitrary)
    packet_data[3] = 0x02;

    // version_field: Version in high nibble (2), low 3 bits reserved 0, LSB fixed bit 1
    // Set lower 4 bits to 0b0001 so the final bit is 1
    packet_data[4] = (2u8 << 4) | 0x01;

    // checksum 0xBEEF
    packet_data[5] = 0xBE;
    packet_data[6] = 0xEF;

    // controls 0x1234
    packet_data[7] = 0x12;
    packet_data[8] = 0x34;

    // sender HIT (16 bytes) and receiver HIT (16 bytes)
    let sender = 0x0123_4567_89AB_CDEF_FEDC_BA98_7654_3210u128.to_be_bytes();
    let receiver = 0x1122_3344_5566_7788_8877_6655_4433_2211u128.to_be_bytes();
    packet_data[9..25].copy_from_slice(&sender);
    packet_data[25..41].copy_from_slice(&receiver);

    let expected = HipHdr {
        next_hdr: IpProto::Ipv6NoNxt,
        hdr_len,
        packet_type_field: 0x02,
        version_field: (2u8 << 4) | 0x01,
        checksum: [0xBE, 0xEF],
        controls: [0x12, 0x34],
        sender_hit: sender,
        receiver_hit: receiver,
    };

    (packet_data, expected)
}

// Creates a HIP header test packet with parameters (hdr_len increased)
pub fn create_hip_with_params_test_packet() -> (Vec<u8>, HipHdr) {
    // add one 8-octet parameter: total 48 bytes => hdr_len = (48-8)/8 = 5
    let hdr_len = 5u8;
    let total_len = (hdr_len as usize + 1) * 8; // 48

    let packet_size = 1 + total_len;
    let mut packet_data = vec![0u8; packet_size];

    packet_data[0] = PacketType::Hip as u8;

    packet_data[1] = IpProto::Udp as u8; // Next Header variety
    packet_data[2] = hdr_len;
    packet_data[3] = 0x04; // packet type 4 (R2)
    packet_data[4] = (2u8 << 4) | 0x01; // version 2, fixed bit set
    packet_data[5] = 0x12; // checksum 0x1234
    packet_data[6] = 0x34;
    packet_data[7] = 0xAB; // controls 0xABCD
    packet_data[8] = 0xCD;

    // Construct 16-byte HITs explicitly to avoid oversized integer literals
    let sender: [u8; 16] = [
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE,
        0xFF,
    ];
    let receiver: [u8; 16] = [
        0xFF, 0xEE, 0xDD, 0xCC, 0xBB, 0xAA, 0x99, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11,
        0x00,
    ];
    packet_data[9..25].copy_from_slice(&sender);
    packet_data[25..41].copy_from_slice(&receiver);

    // one 8-byte parameter payload after fixed 40 bytes
    for i in 0..8 {
        packet_data[41 + i] = (i as u8) ^ 0x5A;
    }

    let expected = HipHdr {
        next_hdr: IpProto::Udp,
        hdr_len,
        packet_type_field: 0x04,
        version_field: (2u8 << 4) | 0x01,
        checksum: [0x12, 0x34],
        controls: [0xAB, 0xCD],
        sender_hit: sender,
        receiver_hit: receiver,
    };

    (packet_data, expected)
}

pub fn verify_hip_header(received: ParsedHeader, expected: HipHdr) {
    assert_eq!(received.type_, PacketType::Hip);
    let parsed: HipHdr = unsafe { received.data.hip };

    assert_eq!(
        parsed.next_hdr as u8, expected.next_hdr as u8,
        "Next Header mismatch"
    );
    assert_eq!(parsed.hdr_len, expected.hdr_len, "Header Length mismatch");
    assert_eq!(
        parsed.packet_type_field, expected.packet_type_field,
        "Packet Type field mismatch"
    );
    assert_eq!(
        parsed.version_field, expected.version_field,
        "Version field mismatch"
    );
    assert_eq!(parsed.checksum, expected.checksum, "Checksum mismatch");
    assert_eq!(parsed.controls, expected.controls, "Controls mismatch");
    assert_eq!(
        parsed.sender_hit, expected.sender_hit,
        "Sender HIT mismatch"
    );
    assert_eq!(
        parsed.receiver_hit, expected.receiver_hit,
        "Receiver HIT mismatch"
    );

    let total_hdr_len_bytes = (parsed.hdr_len as usize + 1) * 8;
    match parsed.hdr_len {
        4 => assert_eq!(
            total_hdr_len_bytes, 40,
            "Expected 40-byte HIP header for hdr_len=4"
        ),
        5 => assert_eq!(
            total_hdr_len_bytes, 48,
            "Expected 48-byte HIP header for hdr_len=5"
        ),
        other => panic!("Unexpected hdr_len for HIP test: {}", other),
    }
}
