use integration_common::{DestOptsTestData, PacketType, ParsedHeader};
use network_types::{destopts::DEST_OPTS_LEN, ip::IpProto};

// Helper for constructing Destination Options header test packets
// Only constructs the fields that are actually extracted by mermin-ebpf
pub fn create_destopts_test_packet() -> ([u8; DEST_OPTS_LEN + 1], DestOptsTestData) {
    let mut request_data = [0u8; DEST_OPTS_LEN + 1];

    // Byte 0: The type discriminator for the eBPF program's `match` statement.
    request_data[0] = PacketType::DestOpts as u8;

    // Bytes 1-2: Destination Options header (2 bytes minimum)
    request_data[1..3].copy_from_slice(&[
        // Byte 1: Next Header (next_hdr field - extracted at offset 0 from data)
        IpProto::Tcp as u8,
        // Byte 2: Header Extension Length (not extracted)
        0, // (0+1)*8 = 8 bytes total
    ]);

    let expected_header = DestOptsTestData {
        next_hdr: IpProto::Tcp as u8,
    };

    (request_data, expected_header)
}

// Helper for verifying Destination Options header test results
pub fn verify_destopts_header(received: ParsedHeader, expected: DestOptsTestData) {
    assert_eq!(received.type_, PacketType::DestOpts);
    let parsed_header = unsafe { received.data.destopts };

    assert_eq!(
        parsed_header.next_hdr, expected.next_hdr,
        "Next Header mismatch: got {}, expected {}",
        parsed_header.next_hdr, expected.next_hdr
    );
}
