use integration_common::{HipTestData, PacketType, ParsedHeader};
use network_types::{hip::HIP_LEN, ip::IpProto};

// Helper for constructing HIP header test packets
// Only constructs the fields that are actually extracted by mermin-ebpf
pub fn create_hip_test_packet() -> ([u8; HIP_LEN + 1], HipTestData) {
    let mut request_data = [0u8; HIP_LEN + 1];

    // Byte 0: The type discriminator for the eBPF program's `match` statement.
    request_data[0] = PacketType::Hip as u8;

    // Bytes 1-41: HIP header (40 bytes)
    request_data[1..41].copy_from_slice(&[
        // Byte 1: Next Header (next_hdr field - extracted at offset 0 from data)
        IpProto::Tcp as u8, // TCP (6)
        // Byte 2: Header Length (hdr_ext_len field - extracted at offset 1 from data)
        5, // Header length = 5 (total header length = (5+1)*8 = 48 bytes)
        // Bytes 3-4: Packet Type and Version (not extracted)
        0x00,
        0x00,
        // Bytes 5-6: Checksum (not extracted)
        0x12,
        0x34,
        // Bytes 7-8: Controls (not extracted)
        0x56,
        0x78,
        // Bytes 9-24: Sender's HIT (not extracted)
        0x01,
        0x23,
        0x45,
        0x67,
        0x89,
        0xAB,
        0xCD,
        0xEF,
        0xFE,
        0xDC,
        0xBA,
        0x98,
        0x76,
        0x54,
        0x32,
        0x10,
        // Bytes 25-40: Receiver's HIT (not extracted)
        0x11,
        0x22,
        0x33,
        0x44,
        0x55,
        0x66,
        0x77,
        0x88,
        0x88,
        0x77,
        0x66,
        0x55,
        0x44,
        0x33,
        0x22,
        0x11,
    ]);

    let expected_header = HipTestData {
        next_hdr: IpProto::Tcp as u8,
        hdr_ext_len: 5,
    };

    (request_data, expected_header)
}

// Helper for verifying HIP header test results
pub fn verify_hip_header(received: ParsedHeader, expected: HipTestData) {
    assert_eq!(received.type_, PacketType::Hip);
    let parsed_header = unsafe { received.data.hip };

    assert_eq!(
        parsed_header.next_hdr, expected.next_hdr,
        "Next Header mismatch: got {:#x}, expected {:#x}",
        parsed_header.next_hdr, expected.next_hdr
    );

    assert_eq!(
        parsed_header.hdr_ext_len, expected.hdr_ext_len,
        "Header Extension Length mismatch: got {}, expected {}",
        parsed_header.hdr_ext_len, expected.hdr_ext_len
    );
}
