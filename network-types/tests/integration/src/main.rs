mod ah;
mod crh;
mod esp;
mod eth;
mod geneve;
mod hop;
mod ipv4;
mod ipv6;
mod rpl_source_route;
mod segment_routing;
mod tcp;
mod type2;
mod udp;
mod utils;

// Import the helper functions and macros
use crate::{
    ah::{create_ah_test_packet, verify_ah_header},
    crh::{
        create_crh16_test_packet, create_crh32_test_packet, verify_crh16_header,
        verify_crh32_header,
    },
    esp::{create_esp_test_packet, verify_esp_header},
    eth::{create_eth_test_packet, verify_eth_header},
    geneve::{create_geneve_test_packet, verify_geneve_header},
    hop::{create_hop_test_packet, verify_hop_header},
    ipv4::{create_ipv4_test_packet, verify_ipv4_header},
    ipv6::{create_ipv6_test_packet, verify_ipv6_header},
    rpl_source_route::{create_rpl_source_route_test_packet, verify_rpl_source_route_header},
    segment_routing::{
        create_segment_routing_test_packet, create_segment_routing_with_tlvs_test_packet,
        verify_segment_routing_header,
    },
    tcp::{create_tcp_test_packet, verify_tcp_header},
    type2::{create_type2_test_packet, verify_type2_header},
    udp::{create_udp_test_packet, verify_udp_header},
};

fn main() {
    // This main is required for linking during tests, even if unused.
}

// Use the macro to define tests for each header type
define_header_test!(
    test_parses_eth_header,
    EthHdr,
    PacketType::Eth,
    create_eth_test_packet,
    verify_eth_header
);

define_header_test!(
    test_parses_ipv4_header,
    Ipv4Hdr,
    PacketType::Ipv4,
    create_ipv4_test_packet,
    verify_ipv4_header
);

define_header_test!(
    test_parses_ipv6_header,
    Ipv6Hdr,
    PacketType::Ipv6,
    create_ipv6_test_packet,
    verify_ipv6_header
);

define_header_test!(
    test_parses_tcp_header,
    TcpHdr,
    PacketType::Tcp,
    create_tcp_test_packet,
    verify_tcp_header
);

define_header_test!(
    test_parses_udp_header,
    UdpHdr,
    PacketType::Udp,
    create_udp_test_packet,
    verify_udp_header
);

define_header_test!(
    test_parses_ah_header,
    AuthHdr,
    PacketType::Ah,
    create_ah_test_packet,
    verify_ah_header
);

define_header_test!(
    test_parses_esp_header,
    Esp,
    PacketType::Esp,
    create_esp_test_packet,
    verify_esp_header
);

define_header_test!(
    test_parses_hop_header,
    HopOptHdr,
    PacketType::Hop,
    create_hop_test_packet,
    verify_hop_header
);

define_header_test!(
    test_parses_geneve_header,
    GeneveHdr,
    PacketType::Geneve,
    create_geneve_test_packet,
    verify_geneve_header
);

define_header_test!(
    test_parses_rpl_source_route_header,
    RplSourceRouteParsed,
    PacketType::RplSourceRoute,
    create_rpl_source_route_test_packet,
    verify_rpl_source_route_header
);

define_header_test!(
    test_parses_type2_header,
    Type2RoutingHeader,
    PacketType::Type2,
    create_type2_test_packet,
    verify_type2_header
);

define_header_test!(
    test_parses_segment_routing_header,
    SegmentRoutingParsed,
    PacketType::SegmentRouting,
    create_segment_routing_test_packet,
    verify_segment_routing_header
);

define_header_test!(
    test_parses_segment_routing_with_tlvs_header,
    SegmentRoutingParsed,
    PacketType::SegmentRouting,
    create_segment_routing_with_tlvs_test_packet,
    verify_segment_routing_header
);

define_header_test!(
    test_parses_crh16_header,
    CrhParsed,
    PacketType::Crh16,
    create_crh16_test_packet,
    verify_crh16_header
);

define_header_test!(
    test_parses_crh32_header,
    CrhParsed,
    PacketType::Crh32,
    create_crh32_test_packet,
    verify_crh32_header
);
