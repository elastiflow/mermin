mod eth;
mod ipv4;
mod utils;

// Import the helper functions and macros
use crate::{
    eth::{create_eth_test_packet, verify_eth_header},
    ipv4::{create_ipv4_test_packet, verify_ipv4_header},
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
