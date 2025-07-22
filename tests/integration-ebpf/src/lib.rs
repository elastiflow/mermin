#![no_std]
#![no_main]

use aya_ebpf::{
    helpers::bpf_get_current_pid_tgid,
    macros::{kprobe, map},
    maps::{HashMap, PerfEventArray},
    programs::ProbeContext,
};

use integration_common::{HeaderUnion, PacketType, ParsedHeader, REQUEST_DATA_SIZE};
use network_types::{
    eth::{EthHdr, EtherType},
};

/// Raw bytes received from the user-space test-runner, keyed by PID.
#[map(name = "IN_DATA")]          // ⊕ give the map an ELF name
static mut IN_DATA: HashMap<u32, [u8; REQUEST_DATA_SIZE]> =
    HashMap::<u32, [u8; REQUEST_DATA_SIZE]>::with_max_entries(1024, 0);

/// Parsed header we send back to user space.
#[map(name = "OUT_DATA")]         // ⊕ likewise
static mut OUT_DATA: PerfEventArray<ParsedHeader> = PerfEventArray::new(0);

// This program is the eBPF part of our integration test.
#[kprobe]
pub fn integration_test(ctx: ProbeContext) -> u32 {
    match try_integration_test(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_integration_test(ctx: ProbeContext) -> Result<u32, u32> {
    let pid = bpf_get_current_pid_tgid() as u32;
    let raw_data = match unsafe { (*(&raw const IN_DATA)).get(&pid) } {
        Some(data) => data,
        None => return Ok(0),
    };

    let packet_type = raw_data[0];
    let payload_bytes = &raw_data[1..];

    // Match on the packet type to execute the correct parsing logic.
    match packet_type {
        t if t == PacketType::Eth as u8 => {
            if payload_bytes.len() < EthHdr::LEN {
                return Err(1);
            }
            let dst_addr: [u8; 6] = payload_bytes[0..6].try_into().map_err(|_| 1u32)?;
            let src_addr: [u8; 6] = payload_bytes[6..12].try_into().map_err(|_| 1u32)?;
            let eth_type_bytes: [u8; 2] = payload_bytes[12..14].try_into().map_err(|_| 1u32)?;
            let eth_type_u16 = u16::from_be_bytes(eth_type_bytes);
            let eth_type_enum = EtherType::try_from(eth_type_u16).map_err(|_| 1u32)?;

            let header = EthHdr::new(dst_addr, src_addr, eth_type_enum);

            let response = ParsedHeader {
                ty: PacketType::Eth,
                data: HeaderUnion { eth: header },
            };
            unsafe { (*(&raw const OUT_DATA)).output(&ctx, &response, 0) };
        }
        _ => {
            // Unknown packet type, do nothing.
        }
    }

    // Clean up the map after processing.
    let _ = unsafe { (*(&raw const IN_DATA)).remove(&pid) };

    Ok(0)
}

#[cfg(target_arch = "bpf")]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}