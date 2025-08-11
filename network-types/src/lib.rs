#![no_std]

pub mod eth;
pub mod ip;
pub mod tcp;
pub mod udp;
#[cfg(any(test, target_arch = "bpf"))]
pub mod parser;
