#![no_std]

pub mod eth;
pub mod ip;
#[cfg(any(test, target_arch = "bpf"))]
pub mod parser;
pub mod tcp;
pub mod udp;
