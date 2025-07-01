#![no_std]
#![no_main]

use aya_ebpf::{
    macros::{classifier},
    maps::HashMap,
    programs::TcContext,
};

mod common;
mod quic;
mod gre;
mod ospf;


/// IPv6 Fragment‑header – RFC 8200 §4.5 (8 bytes)
#[repr(C, packed)]
#[derive(Copy, Clone)]
struct Ipv6FragHdr {
    pub next_hdr: u8,
    pub _reserved: u8,
    pub frag_off: [u8; 2],
    pub ident: [u8; 4],
}


/// TC‑ingress entry‑point for QUIC.
#[classifier]
pub fn quic_hdr_test(ctx: TcContext) -> i32 {
    // Explicitly annotate the type of `map` as `&mut HashMap<u32, u32>`
    let map: &mut HashMap<u32, u32> = unsafe { &mut *(&raw mut quic::QUICHDR_RESULT as *mut _) };

    // Initialize map entry if not present (for test setup)
    if unsafe { map.get(&0).is_none() } {
        unsafe { quic::store_result(map, 0, 0, 0) };
    }

    match quic::try_quic_hdr_test(ctx, map) {
        Ok(ret) | Err(ret) => ret,
    }
}


/// TC-ingress entry-point for GRE
#[classifier]
pub fn gre_hdr_test(ctx: TcContext) -> i32 {
    // Explicitly annotate the type of `map` as `&mut HashMap<u32, u32>`
    let map: &mut HashMap<u32, u32> = unsafe { &mut *(&raw mut gre::GREHDR_RESULT as *mut _) };

    // Initialize map entry if not present (for test setup)
    if unsafe { map.get(&0).is_none() } {
        unsafe { gre::store_result(map, 0, 0, 0, 0, 0, 0) };
    }
    
    match gre::try_gre_hdr_test(ctx, map) {
        Ok(ret) | Err(ret) => ret,
    }
}


/// TC-ingress entry-point for OSPF
#[classifier]
pub fn ospf_hdr_test(ctx: TcContext) -> i32 {
    // Explicitly annotate the type of `map` as `&mut HashMap<u32, u32>`
    let map: &mut HashMap<u32, u32> = unsafe { &mut *(&raw mut ospf::OSPFHDR_RESULT as *mut _) };

    // Initialize map entry if not present (for test setup)
    if unsafe { map.get(&0).is_none() } {
        unsafe { ospf::store_result(map, 0, 0, 0, 0, 0, 0, 0, 0) };
    }

    match ospf::try_ospf_hdr_test(ctx, map) {
        Ok(ret) | Err(ret) => ret,
    }
}
