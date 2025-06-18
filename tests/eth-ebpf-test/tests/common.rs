//! Test‑only helper: backs a packet with a virtually‑addressed buffer that is
//! **guaranteed** to live below 0x1_0000_0000 so that the 32‑bit
//! `__sk_buff.data` and `data_end` fields can hold the address.

#![allow(dead_code)]

use core::{cmp, ptr};

use aya_ebpf::{bindings::__sk_buff, programs::TcContext};

pub struct PacketBuf {
    ptr: *mut u8,
    len: usize,
}

impl PacketBuf {
    /// Allocate `len.max(page_size)` bytes below and copy `data` into it.
    pub fn new(data: &[u8]) -> Self {
        unsafe {
            let page_size = libc::sysconf(libc::_SC_PAGESIZE) as usize;
            let len = cmp::max(page_size, data.len());
            let hint = 0x1000_0000 as *mut libc::c_void;
            let addr = libc::mmap(
                hint,
                len,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | 0x100000, // MAP_FIXED_NOREPLACE
                -1,
                0,
            );
            if addr == libc::MAP_FAILED {
                panic!("mmap failed when creating PacketBuf");
            }
            ptr::copy_nonoverlapping(data.as_ptr(), addr as *mut u8, data.len());
            Self {
                ptr: addr as *mut u8,
                len,
            }
        }
    }

    /// Fill the given `__sk_buff` and yield a real `TcContext`.
    pub fn as_ctx(&self, skb: &mut __sk_buff) -> TcContext {
        skb.data = self.ptr as u32;
        skb.data_end = (self.ptr as usize + self.len) as u32;
        skb.len = self.len as u32;
        // Safety: the lifetimes line up – we pin `self` for the duration of `ctx`.
        TcContext::new(skb)
    }
}

impl Drop for PacketBuf {
    fn drop(&mut self) {
        unsafe {
            libc::munmap(self.ptr.cast(), self.len);
        }
    }
}
