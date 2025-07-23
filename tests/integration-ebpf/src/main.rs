#![no_std]
#![no_main]

use aya_ebpf::{
    helpers::bpf_get_current_pid_tgid,
    macros::{kprobe, map},
    maps::{HashMap, PerfEventArray},
    programs::ProbeContext,
};
use aya_log_ebpf::{log, Level};

use integration_common::{
    EthHdr as PodEthHdr, HeaderUnion, PacketType, ParsedHeader, REQUEST_DATA_SIZE,
};
use network_types::eth::{EthHdr, EtherType};

#[map(name = "IN_DATA")]
static mut IN_DATA: HashMap<u32, [u8; REQUEST_DATA_SIZE]> =
    HashMap::<u32, [u8; REQUEST_DATA_SIZE]>::with_max_entries(1024, 0);

#[map(name = "OUT_DATA")]
static mut OUT_DATA: PerfEventArray<ParsedHeader> = PerfEventArray::new(0);

#[kprobe]
pub fn integration_test(ctx: ProbeContext) -> u32 {
    match try_integration_test(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_integration_test(ctx: ProbeContext) -> Result<u32, u32> {
    // Correctly get the Process ID (TGID) by shifting the 64-bit result.
    let tgid = (bpf_get_current_pid_tgid() >> 32) as u32;

    // Use the correct TGID to look up the data. `get` returns a reference to the
    // value in the map, wrapped in an Option.
    let raw_data = match unsafe { (*(&raw mut IN_DATA)).get(&tgid) } {
        Some(data) => data,
        None => {
            // This is expected for other processes on the system calling getpid.
            return Ok(0);
        }
    };

    log!(&ctx, Level::Info, "Data found for tgid {}, processing...", tgid);

    // Since raw_data is a reference, we can directly access its elements.
    let packet_type = raw_data[0];
    let payload_bytes = &raw_data[1..];

    match packet_type {
        t if t == PacketType::Eth as u8 => {
            if payload_bytes.len() < core::mem::size_of::<EthHdr>() {
                return Err(1);
            }

            let header: EthHdr = unsafe {
                core::ptr::read_unaligned(payload_bytes.as_ptr() as *const EthHdr)
            };

            let response = ParsedHeader {
                ty: PacketType::Eth,
                data: HeaderUnion {
                    eth: PodEthHdr(header),
                },
            };

            unsafe { (*(&raw const OUT_DATA)).output(&ctx, &response, 0) };
            log!(&ctx, Level::Info, "Successfully processed Eth packet for tgid {}", tgid);
        }
        _ => {
            log!(&ctx, Level::Warn, "Unknown packet type: {}", packet_type);
        }
    }

    // After processing, clean up the map to prevent processing stale data.
    // We ignore the result of remove, as there's not much we can do if it fails.
    unsafe {
        let _ = (*(&raw mut IN_DATA)).remove(&tgid);
    }

    Ok(0)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}