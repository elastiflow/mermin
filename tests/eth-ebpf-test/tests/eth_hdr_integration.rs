//! Checks that our Rust representation of `struct ethhdr` is sane.

use std::mem::{align_of, size_of};

use network_types::eth::EthHdr;

#[test]
fn eth_hdr_static_constants() {
    assert_eq!(size_of::<EthHdr>(), 14, "EthHdr size should be 14 bytes");
    assert_eq!(align_of::<EthHdr>(), 1, "EthHdr alignment should be 1 byte");
}
