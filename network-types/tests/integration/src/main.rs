mod eth;
mod ipv4;
mod utils;
mod ipv6;
mod tcp;
mod udp;

// Import the helper functions and macros
use crate::{
    eth::{create_eth_test_packet, verify_eth_header},
    ipv4::{create_ipv4_test_packet, verify_ipv4_header},
    ipv6::{create_ipv6_test_packet, verify_ipv6_header},
    tcp::{create_tcp_test_packet, verify_tcp_header},
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