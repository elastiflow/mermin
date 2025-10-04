// Refactored modules
mod ah;
mod destopts;
mod esp;
mod eth;
mod fragment;
mod geneve;
mod gre;
mod hip;
mod hop;
mod mobility;
mod routing;
mod shim6;
mod tcp;
mod udp;
mod utils;
mod vxlan;

// TODO: Uncomment as we refactor each type
// mod crh;
// mod geneve;
// mod gre;
// mod hip;
mod ipv4;
mod ipv6;
// mod rpl_source_route;
// mod segment_routing;
// mod type2;
// mod vxlan;
mod wireguard;

// Import the helper functions and macros - only for refactored types
use crate::{
    ah::{create_ah_test_packet, verify_ah_header},
    destopts::{create_destopts_test_packet, verify_destopts_header},
    esp::{create_esp_test_packet, verify_esp_header},
    eth::{create_eth_test_packet, verify_eth_header},
    fragment::{create_fragment_test_packet, verify_fragment_header},
    geneve::{create_geneve_test_packet, verify_geneve_header},
    gre::{create_gre_test_packet, verify_gre_header},
    hip::{create_hip_test_packet, verify_hip_header},
    hop::{create_hop_test_packet, verify_hop_header},
    ipv4::{create_ipv4_test_packet, verify_ipv4_header},
    ipv6::{create_ipv6_test_packet, verify_ipv6_header},
    mobility::{create_mobility_test_packet, verify_mobility_header},
    routing::{create_generic_route_test_packet, verify_generic_route_header},
    shim6::{create_shim6_test_packet, verify_shim6_header},
    tcp::{create_tcp_test_packet, verify_tcp_header},
    udp::{create_udp_test_packet, verify_udp_header},
    vxlan::{create_vxlan_test_packet, verify_vxlan_header},
    wireguard::{
        create_wireguard_cookie_reply_test_packet, create_wireguard_initiation_test_packet,
        create_wireguard_response_test_packet, create_wireguard_transport_data_test_packet,
        verify_wireguard_cookie_reply_header, verify_wireguard_init_header,
        verify_wireguard_response_header, verify_wireguard_transport_data_header,
    },
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

define_header_test!(
    test_parses_ipv4_header,
    Ipv4TestData,
    PacketType::Ipv4,
    create_ipv4_test_packet,
    verify_ipv4_header
);

define_header_test!(
    test_parses_ipv6_header,
    Ipv6TestData,
    PacketType::Ipv6,
    create_ipv6_test_packet,
    verify_ipv6_header
);

define_header_test!(
    test_parses_tcp_header,
    TcpTestData,
    PacketType::Tcp,
    create_tcp_test_packet,
    verify_tcp_header
);

define_header_test!(
    test_parses_udp_header,
    UdpTestData,
    PacketType::Udp,
    create_udp_test_packet,
    verify_udp_header
);

define_header_test!(
    test_parses_ah_header,
    AhTestData,
    PacketType::Ah,
    create_ah_test_packet,
    verify_ah_header
);

define_header_test!(
    test_parses_esp_header,
    EspTestData,
    PacketType::Esp,
    create_esp_test_packet,
    verify_esp_header
);

define_header_test!(
    test_parses_hop_header,
    HopOptTestData,
    PacketType::Hop,
    create_hop_test_packet,
    verify_hop_header
);

define_header_test!(
    test_parses_fragment_header,
    FragmentTestData,
    PacketType::Fragment,
    create_fragment_test_packet,
    verify_fragment_header
);

define_header_test!(
    test_parses_destopts_header,
    DestOptsTestData,
    PacketType::DestOpts,
    create_destopts_test_packet,
    verify_destopts_header
);

define_header_test!(
    test_parses_mobility_header,
    MobilityTestData,
    PacketType::Mobility,
    create_mobility_test_packet,
    verify_mobility_header
);

define_header_test!(
    test_parses_shim6_header,
    Shim6TestData,
    PacketType::Shim6,
    create_shim6_test_packet,
    verify_shim6_header
);

define_header_test!(
    test_parses_geneve_header,
    GeneveTestData,
    PacketType::Geneve,
    create_geneve_test_packet,
    verify_geneve_header
);

define_header_test!(
    test_parses_generic_route_header,
    GenericRouteTestData,
    PacketType::GenericRoute,
    create_generic_route_test_packet,
    verify_generic_route_header
);

define_header_test!(
    test_parses_vxlan_header,
    VxlanTestData,
    PacketType::Vxlan,
    create_vxlan_test_packet,
    verify_vxlan_header
);

define_header_test!(
    test_parses_hip_header,
    HipTestData,
    PacketType::Hip,
    create_hip_test_packet,
    verify_hip_header
);

define_header_test!(
    test_parses_gre_header,
    GreTestData,
    PacketType::Gre,
    create_gre_test_packet,
    verify_gre_header
);

define_header_test!(
    test_parses_wireguard_init_header,
    WireGuardInitTestData,
    PacketType::WireGuardInit,
    create_wireguard_initiation_test_packet,
    verify_wireguard_init_header
);

define_header_test!(
    test_parses_wireguard_response_header,
    WireGuardResponseTestData,
    PacketType::WireGuardResponse,
    create_wireguard_response_test_packet,
    verify_wireguard_response_header
);

define_header_test!(
    test_parses_wireguard_cookie_reply_header,
    WireGuardCookieReplyTestData,
    PacketType::WireGuardCookieReply,
    create_wireguard_cookie_reply_test_packet,
    verify_wireguard_cookie_reply_header
);

define_header_test!(
    test_parses_wireguard_transport_data_header,
    WireGuardTransportDataTestData,
    PacketType::WireGuardTransportData,
    create_wireguard_transport_data_test_packet,
    verify_wireguard_transport_data_header
);
