// Refactored modules
// mod ah;
// mod destopts;
// mod esp;
mod eth;
// mod fragment;
// mod hop;
// mod mobility;
// mod shim6;
// mod tcp;
// mod udp;
mod utils;

// TODO: Uncomment as we refactor each type
// mod crh;
// mod geneve;
// mod gre;
// mod hip;
// mod ipv4;
// mod ipv6;
// mod rpl_source_route;
// mod segment_routing;
// mod type2;
// mod vxlan;
// mod wireguard;

// Import the helper functions and macros - only for refactored types
use crate::{
    // ah::{create_ah_test_packet, verify_ah_header},
    // destopts::{create_destopts_test_packet, verify_destopts_header},
    // esp::{create_esp_test_packet, verify_esp_header},
    eth::{create_eth_test_packet, verify_eth_header},
    // fragment::{create_fragment_test_packet, verify_fragment_header},
    // hop::{create_hop_test_packet, verify_hop_header},
    // mobility::{create_mobility_test_packet, verify_mobility_header},
    // shim6::{create_shim6_test_packet, create_shim6_with_extension_test_packet, verify_shim6_header},
    // tcp::{create_tcp_test_packet, verify_tcp_header},
    // udp::{create_udp_test_packet, verify_udp_header},
    // TODO: Uncomment as we refactor each type
    // crh::{create_crh16_test_packet, create_crh32_test_packet, verify_crh16_header, verify_crh32_header},
    // geneve::{create_geneve_test_packet, verify_geneve_header},
    // gre::{create_gre_test_packet, verify_gre_header},
    // hip::{create_hip_test_packet, create_hip_with_params_test_packet, verify_hip_header},
    // ipv4::{create_ipv4_test_packet, verify_ipv4_header},
    // ipv6::{create_ipv6_test_packet, verify_ipv6_header},
    // rpl_source_route::{create_rpl_source_route_test_packet, verify_rpl_source_route_header},
    // segment_routing::{create_segment_routing_test_packet, create_segment_routing_with_tlvs_test_packet, verify_segment_routing_header},
    // type2::{create_type2_test_packet, verify_type2_header},
    // vxlan::{create_vxlan_test_packet, verify_vxlan_header},
    // wireguard::{create_wireguard_cookie_reply_test_packet, create_wireguard_initiation_test_packet, create_wireguard_response_test_packet, create_wireguard_transport_data_test_packet, verify_wireguard_header},
};

fn main() {
    // This main is required for linking during tests, even if unused.
}

// Use the macro to define tests for each header type
// Refactored to match new parsing methodology - only tests extracted fields

define_header_test!(
    test_parses_eth_header,
    EthernetTestData,
    PacketType::Eth,
    create_eth_test_packet,
    verify_eth_header
);

// define_header_test!(
//     test_parses_ipv4_header,
//     Ipv4Hdr,
//     PacketType::Ipv4,
//     create_ipv4_test_packet,
//     verify_ipv4_header
// );

// define_header_test!(
//     test_parses_ipv6_header,
//     Ipv6Hdr,
//     PacketType::Ipv6,
//     create_ipv6_test_packet,
//     verify_ipv6_header
// );

// define_header_test!(
//     test_parses_tcp_header,
//     TcpTestData,
//     PacketType::Tcp,
//     create_tcp_test_packet,
//     verify_tcp_header
// );

// define_header_test!(
//     test_parses_udp_header,
//     UdpTestData,
//     PacketType::Udp,
//     create_udp_test_packet,
//     verify_udp_header
// );

// define_header_test!(
//     test_parses_ah_header,
//     NextHdrOnlyTestData,
//     PacketType::Ah,
//     create_ah_test_packet,
//     verify_ah_header
// );

// define_header_test!(
//     test_parses_esp_header,
//     NextHdrOnlyTestData,
//     PacketType::Esp,
//     create_esp_test_packet,
//     verify_esp_header
// );

// define_header_test!(
//     test_parses_hop_header,
//     NextHdrOnlyTestData,
//     PacketType::Hop,
//     create_hop_test_packet,
//     verify_hop_header
// );

// define_header_test!(
//     test_parses_fragment_header,
//     NextHdrOnlyTestData,
//     PacketType::Fragment,
//     create_fragment_test_packet,
//     verify_fragment_header
// );

// define_header_test!(
//     test_parses_destopts_header,
//     NextHdrOnlyTestData,
//     PacketType::DestOpts,
//     create_destopts_test_packet,
//     verify_destopts_header
// );

// define_header_test!(
//     test_parses_mobility_header,
//     NextHdrOnlyTestData,
//     PacketType::Mobility,
//     create_mobility_test_packet,
//     verify_mobility_header
// );

// define_header_test!(
//     test_parses_shim6_header,
//     NextHdrOnlyTestData,
//     PacketType::Shim6,
//     create_shim6_test_packet,
//     verify_shim6_header
// );

// define_header_test!(
//     test_parses_shim6_with_extension_header,
//     NextHdrOnlyTestData,
//     PacketType::Shim6,
//     create_shim6_with_extension_test_packet,
//     verify_shim6_header
// );

// define_header_test!(
//     test_parses_geneve_header,
//     GeneveHdr,
//     PacketType::Geneve,
//     create_geneve_test_packet,
//     verify_geneve_header
// );

// define_header_test!(
//     test_parses_rpl_source_route_header,
//     RplSourceRouteHeader,
//     PacketType::RplSourceRoute,
//     create_rpl_source_route_test_packet,
//     verify_rpl_source_route_header
// );

// define_header_test!(
//     test_parses_type2_header,
//     Type2RoutingHeader,
//     PacketType::Type2,
//     create_type2_test_packet,
//     verify_type2_header
// );

// define_header_test!(
//     test_parses_segment_routing_header,
//     SegmentRoutingHeader,
//     PacketType::SegmentRouting,
//     create_segment_routing_test_packet,
//     verify_segment_routing_header
// );

// define_header_test!(
//     test_parses_segment_routing_with_tlvs_header,
//     SegmentRoutingHeader,
//     PacketType::SegmentRouting,
//     create_segment_routing_with_tlvs_test_packet,
//     verify_segment_routing_header
// );

// define_header_test!(
//     test_parses_crh16_header,
//     CrhHeader,
//     PacketType::Crh16,
//     create_crh16_test_packet,
//     verify_crh16_header
// );

// define_header_test!(
//     test_parses_crh32_header,
//     CrhHeader,
//     PacketType::Crh32,
//     create_crh32_test_packet,
//     verify_crh32_header
// );

// define_header_test!(
//     test_parses_fragment_header,
//     Fragment,
//     PacketType::Fragment,
//     create_fragment_test_packet,
//     verify_fragment_header
// );

// define_header_test!(
//     test_parses_destopts_header,
//     DestOptsHdr,
//     PacketType::DestOpts,
//     create_destopts_test_packet,
//     verify_destopts_header
// );

// define_header_test!(
//     test_parses_mobility_header,
//     MobilityHdr,
//     PacketType::Mobility,
//     create_mobility_test_packet,
//     verify_mobility_header
// );

// define_header_test!(
//     test_parses_vxlan_header,
//     VxlanHdr,
//     PacketType::Vxlan,
//     create_vxlan_test_packet,
//     verify_vxlan_header
// );

// define_header_test!(
//     test_parses_shim6_header,
//     Shim6Hdr,
//     PacketType::Shim6,
//     create_shim6_test_packet,
//     verify_shim6_header
// );

// define_header_test!(
//     test_parses_shim6_with_extension_header,
//     Shim6Hdr,
//     PacketType::Shim6,
//     create_shim6_with_extension_test_packet,
//     verify_shim6_header
// );

// define_header_test!(
//     test_parses_hip_header,
//     HipHdr,
//     PacketType::Hip,
//     create_hip_test_packet,
//     verify_hip_header
// );

// define_header_test!(
//     test_parses_hip_with_params_header,
//     HipHdr,
//     PacketType::Hip,
//     create_hip_with_params_test_packet,
//     verify_hip_header
// );

// define_header_test!(
//     test_parses_gre_header,
//     GreHdr,
//     PacketType::Gre,
//     create_gre_test_packet,
//     verify_gre_header
// );

// define_header_test!(
//     test_parses_wireguard_initiation_header,
//     WireGuardMinimalHeader,
//     PacketType::WireGuard,
//     create_wireguard_initiation_test_packet,
//     verify_wireguard_header
// );

// define_header_test!(
//     test_parses_wireguard_response_header,
//     WireGuardMinimalHeader,
//     PacketType::WireGuard,
//     create_wireguard_response_test_packet,
//     verify_wireguard_header
// );

// define_header_test!(
//     test_parses_wireguard_cookie_reply_header,
//     WireGuardMinimalHeader,
//     PacketType::WireGuard,
//     create_wireguard_cookie_reply_test_packet,
//     verify_wireguard_header
// );

// define_header_test!(
//     test_parses_wireguard_transport_data_header,
//     WireGuardMinimalHeader,
//     PacketType::WireGuard,
//     create_wireguard_transport_data_test_packet,
//     verify_wireguard_header
// );
