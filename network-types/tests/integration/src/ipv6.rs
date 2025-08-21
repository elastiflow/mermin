use integration_common::{PacketType, ParsedHeader};
use network_types::ip::{IpProto, Ipv6Hdr, Ipv6ExtHdr, Ipv6FragHdr};

// Helper for constructing Ipv6 header test packets
pub fn create_ipv6_test_packet() -> ([u8; Ipv6Hdr::LEN + 1], Ipv6Hdr) {
    let mut request_data = [0u8; Ipv6Hdr::LEN + 1];

    // Byte 0: The type discriminator for the eBPF program's `match` statement.
    request_data[0] = PacketType::Ipv6 as u8;
    // Bytes 1-4: Version, Traffic Class, Flow Label
    request_data[1..5].copy_from_slice(&[0, 0, 0, 0]);
    // Bytes 5-6: Payload Length
    request_data[5..7].copy_from_slice(&[0, 0]);
    // Byte 7: Next Header
    request_data[7] = IpProto::Tcp as u8;
    // Byte 8: Hop Limit
    request_data[8] = 0;
    // Bytes 9-24: Source Address
    request_data[9..25].copy_from_slice(&[
        0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x01,
    ]);
    // Bytes 25-40: Destination Address
    request_data[25..41].copy_from_slice(&[
        0xc0, 0xa8, 0x01, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00,
    ]);

    let expected_header = Ipv6Hdr {
        vcf: [0; 4],
        payload_len: [0; 2],
        next_hdr: IpProto::Tcp,
        hop_limit: 0,
        src_addr: [
            0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x01,
        ],
        dst_addr: [
            0xc0, 0xa8, 0x01, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00,
        ],
    };

    (request_data, expected_header)
}

// Helper for verifying Ipv4 header test results
pub fn verify_ipv6_header(received: ParsedHeader, expected: Ipv6Hdr) {
    assert_eq!(received.type_, PacketType::Ipv6);
    let parsed_header = unsafe { received.data.ipv6 };

    let parsed_dst_addr = parsed_header.dst_addr;
    let expected_dst_addr = expected.dst_addr;
    assert_eq!(
        parsed_dst_addr, expected_dst_addr,
        "Destination Addr mismatch"
    );

    let parsed_src_addr = parsed_header.src_addr;
    let expected_src_addr = expected.src_addr;
    assert_eq!(parsed_src_addr, expected_src_addr, "Source Addr mismatch");

    let parsed_next_hdr = parsed_header.next_hdr;
    let expected_next_hdr = expected.next_hdr;
    assert_eq!(parsed_next_hdr, expected_next_hdr, "Next Header mismatch");
}

/// Creates a test packet with IPv6 header followed by a Hop-by-Hop extension header and TCP
pub fn create_ipv6_with_hop_by_hop_test_packet() -> Vec<u8> {
    let mut packet = Vec::new();
    
    // Packet type discriminator
    packet.push(PacketType::Ipv6 as u8);
    
    // IPv6 Header (40 bytes)
    let mut ipv6_hdr = Ipv6Hdr {
        vcf: [0x60, 0x00, 0x00, 0x00], // Version 6, Traffic Class 0, Flow Label 0
        payload_len: [0x00, 0x10], // 16 bytes payload (8 bytes hop-by-hop + 8 bytes fake TCP)
        next_hdr: IpProto::HopOpt, // Next header is Hop-by-Hop Options
        hop_limit: 64,
        src_addr: [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01],
        dst_addr: [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x02],
    };
    
    // Convert IPv6 header to bytes and append
    let ipv6_bytes = unsafe { 
        core::slice::from_raw_parts(
            &ipv6_hdr as *const _ as *const u8, 
            core::mem::size_of::<Ipv6Hdr>()
        ) 
    };
    packet.extend_from_slice(ipv6_bytes);
    
    // Hop-by-Hop Options Header (8 bytes minimum)
    let hop_by_hop = Ipv6ExtHdr {
        next_hdr: IpProto::Tcp, // Next header is TCP
        hdr_ext_len: 0, // 0 means 8 bytes total (8 * (0 + 1))
    };
    
    // Convert Hop-by-Hop header to bytes and append
    let hop_bytes = unsafe {
        core::slice::from_raw_parts(
            &hop_by_hop as *const _ as *const u8,
            core::mem::size_of::<Ipv6ExtHdr>()
        )
    };
    packet.extend_from_slice(hop_bytes);
    
    // Add 6 bytes of padding to make it 8 bytes total (as per hdr_ext_len = 0)
    packet.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
    
    // Add minimal fake TCP header (8 bytes)
    packet.extend_from_slice(&[0x00, 0x50, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00]); // Ports 80, 128
    
    packet
}

/// Creates a test packet with IPv6 header followed by a Fragment extension header and UDP
pub fn create_ipv6_with_fragment_test_packet() -> Vec<u8> {
    let mut packet = Vec::new();
    
    // Packet type discriminator
    packet.push(PacketType::Ipv6 as u8);
    
    // IPv6 Header (40 bytes)
    let ipv6_hdr = Ipv6Hdr {
        vcf: [0x60, 0x00, 0x00, 0x00], // Version 6, Traffic Class 0, Flow Label 0
        payload_len: [0x00, 0x10], // 16 bytes payload (8 bytes fragment + 8 bytes fake UDP)
        next_hdr: IpProto::Ipv6Frag, // Next header is Fragment
        hop_limit: 64,
        src_addr: [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x03],
        dst_addr: [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x04],
    };
    
    // Convert IPv6 header to bytes and append
    let ipv6_bytes = unsafe { 
        core::slice::from_raw_parts(
            &ipv6_hdr as *const _ as *const u8, 
            core::mem::size_of::<Ipv6Hdr>()
        ) 
    };
    packet.extend_from_slice(ipv6_bytes);
    
    // Fragment Header (8 bytes)
    let frag_hdr = Ipv6FragHdr {
        next_hdr: IpProto::Udp, // Next header is UDP
        reserved: 0,
        frag_off_and_flags: [0x00, 0x00], // Fragment offset 0, no more fragments
        identification: [0x12, 0x34, 0x56, 0x78], // Identification
    };
    
    // Convert Fragment header to bytes and append
    let frag_bytes = unsafe {
        core::slice::from_raw_parts(
            &frag_hdr as *const _ as *const u8,
            core::mem::size_of::<Ipv6FragHdr>()
        )
    };
    packet.extend_from_slice(frag_bytes);
    
    // Add minimal fake UDP header (8 bytes)
    packet.extend_from_slice(&[0x00, 0x50, 0x00, 0x35, 0x00, 0x08, 0x00, 0x00]); // Ports 80, 53, length 8, checksum 0
    
    packet
}

/// Creates a test packet with IPv6 header followed by multiple extension headers (Hop-by-Hop -> Routing -> TCP)
pub fn create_ipv6_with_multiple_extension_headers_test_packet() -> Vec<u8> {
    let mut packet = Vec::new();
    
    // Packet type discriminator
    packet.push(PacketType::Ipv6 as u8);
    
    // IPv6 Header (40 bytes)
    let ipv6_hdr = Ipv6Hdr {
        vcf: [0x60, 0x00, 0x00, 0x00], // Version 6, Traffic Class 0, Flow Label 0
        payload_len: [0x00, 0x18], // 24 bytes payload (8 + 8 + 8 bytes)
        next_hdr: IpProto::HopOpt, // Next header is Hop-by-Hop Options
        hop_limit: 64,
        src_addr: [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x05],
        dst_addr: [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x06],
    };
    
    // Convert IPv6 header to bytes and append
    let ipv6_bytes = unsafe { 
        core::slice::from_raw_parts(
            &ipv6_hdr as *const _ as *const u8, 
            core::mem::size_of::<Ipv6Hdr>()
        ) 
    };
    packet.extend_from_slice(ipv6_bytes);
    
    // First Extension Header: Hop-by-Hop Options (8 bytes)
    let hop_by_hop = Ipv6ExtHdr {
        next_hdr: IpProto::Ipv6Route, // Next header is Routing
        hdr_ext_len: 0, // 8 bytes total
    };
    let hop_bytes = unsafe {
        core::slice::from_raw_parts(
            &hop_by_hop as *const _ as *const u8,
            core::mem::size_of::<Ipv6ExtHdr>()
        )
    };
    packet.extend_from_slice(hop_bytes);
    packet.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x00, 0x00]); // Padding
    
    // Second Extension Header: Routing (8 bytes)
    let routing = Ipv6ExtHdr {
        next_hdr: IpProto::Tcp, // Next header is TCP (final L4 protocol)
        hdr_ext_len: 0, // 8 bytes total
    };
    let routing_bytes = unsafe {
        core::slice::from_raw_parts(
            &routing as *const _ as *const u8,
            core::mem::size_of::<Ipv6ExtHdr>()
        )
    };
    packet.extend_from_slice(routing_bytes);
    packet.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x00, 0x00]); // Padding
    
    // Add minimal fake TCP header (8 bytes)
    packet.extend_from_slice(&[0x00, 0x50, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00]); // Ports 80, 128
    
    packet
}
