mod eth;
mod utils;

// Import the helper functions and macros
use crate::eth::{
    create_eth_test_packet,
    verify_eth_header,
    // Additional helper functions would be imported here
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
