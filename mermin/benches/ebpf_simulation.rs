use std::hint::black_box;

use criterion::{Criterion, criterion_group, criterion_main};
use mermin_common::{IpAddrType, PacketMeta};
use network_types::ip::IpProto;

/// Simulates the eBPF stack constraints and memory access patterns
/// This benchmark focuses on the specific performance characteristics
/// of the two approaches in an eBPF-like environment
struct MockRingBuf {
    buffer: Vec<u8>,
    write_pos: usize,
    capacity: usize,
}

impl MockRingBuf {
    fn new(capacity_bytes: usize) -> Self {
        Self {
            buffer: vec![0u8; capacity_bytes],
            write_pos: 0,
            capacity: capacity_bytes,
        }
    }

    /// Reset the ring buffer for consistent benchmarking
    fn reset(&mut self) {
        self.write_pos = 0;
    }

    /// Simulates RingBuf::output() - copies data directly to ring buffer
    /// Returns Result<(), i64> like the real implementation
    fn output<T: Copy>(&mut self, data: &T, _flags: u64) -> Result<(), i64> {
        let size = std::mem::size_of::<T>();

        // Check if we have enough space (simulates ring buffer full condition)
        if self.write_pos + size > self.capacity {
            return Err(-1); // Ring buffer full
        }

        // Simulate the memory copy operation that bpf_ringbuf_output does
        let data_bytes = unsafe { std::slice::from_raw_parts(data as *const T as *const u8, size) };

        // Copy data to ring buffer (this is the expensive operation)
        self.buffer[self.write_pos..self.write_pos + size].copy_from_slice(data_bytes);
        self.write_pos += size;

        Ok(())
    }

    /// Simulates ring buffer query for available space
    fn available_space(&self) -> usize {
        self.capacity - self.write_pos
    }
}

/// Mock eBPF context that simulates the constraints
struct MockEbpFContext {
    scratch_meta: [PacketMeta; 1],
    ring_buffer: MockRingBuf,
}

impl MockEbpFContext {
    fn new() -> Self {
        Self {
            scratch_meta: [PacketMeta::default(); 1],
            ring_buffer: MockRingBuf::new(1024), // 1KB ring buffer
        }
    }

    /// Reset the context for consistent benchmarking
    fn reset(&mut self) {
        self.ring_buffer.reset();
    }

    /// Simulates the current PerCpuArray approach
    fn populate_and_write_to_ring_buffer(
        &mut self,
        meta_data: &TestPacketData,
    ) -> Result<PacketMeta, i64> {
        // Simulate the unsafe pointer access pattern from the real code
        let meta = &mut self.scratch_meta[0];

        // Individual field assignments (matches the real eBPF code)
        meta.ifindex = meta_data.ifindex;
        meta.src_ipv6_addr = meta_data.src_ipv6_addr;
        meta.dst_ipv6_addr = meta_data.dst_ipv6_addr;
        meta.tunnel_src_ipv6_addr = meta_data.tunnel_src_ipv6_addr;
        meta.tunnel_dst_ipv6_addr = meta_data.tunnel_dst_ipv6_addr;
        meta.src_ipv4_addr = meta_data.src_ipv4_addr;
        meta.dst_ipv4_addr = meta_data.dst_ipv4_addr;
        meta.l3_octet_count = meta_data.l3_octet_count;
        meta.tunnel_src_ipv4_addr = meta_data.tunnel_src_ipv4_addr;
        meta.tunnel_dst_ipv4_addr = meta_data.tunnel_dst_ipv4_addr;
        meta.src_port = meta_data.src_port;
        meta.dst_port = meta_data.dst_port;
        meta.tunnel_src_port = meta_data.tunnel_src_port;
        meta.tunnel_dst_port = meta_data.tunnel_dst_port;
        meta.ip_addr_type = meta_data.ip_addr_type;
        meta.proto = meta_data.proto;
        meta.tunnel_ip_addr_type = meta_data.tunnel_ip_addr_type;
        meta.tunnel_proto = meta_data.tunnel_proto;
        meta.wireguard = meta_data.wireguard;

        // Simulate the real ring buffer write using output() - this copies the data
        self.ring_buffer.output(meta, 0)?;
        Ok(self.scratch_meta[0])
    }

    /// Simulates just the PerCpuArray population (without ring buffer write)
    fn populate_percpu_array_only(&mut self, meta_data: &TestPacketData) -> PacketMeta {
        // Simulate the unsafe pointer access pattern from the real code
        let meta = &mut self.scratch_meta[0];

        // Individual field assignments (matches the real eBPF code)
        meta.ifindex = meta_data.ifindex;
        meta.src_ipv6_addr = meta_data.src_ipv6_addr;
        meta.dst_ipv6_addr = meta_data.dst_ipv6_addr;
        meta.tunnel_src_ipv6_addr = meta_data.tunnel_src_ipv6_addr;
        meta.tunnel_dst_ipv6_addr = meta_data.tunnel_dst_ipv6_addr;
        meta.src_ipv4_addr = meta_data.src_ipv4_addr;
        meta.dst_ipv4_addr = meta_data.dst_ipv4_addr;
        meta.l3_octet_count = meta_data.l3_octet_count;
        meta.tunnel_src_ipv4_addr = meta_data.tunnel_src_ipv4_addr;
        meta.tunnel_dst_ipv4_addr = meta_data.tunnel_dst_ipv4_addr;
        meta.src_port = meta_data.src_port;
        meta.dst_port = meta_data.dst_port;
        meta.tunnel_src_port = meta_data.tunnel_src_port;
        meta.tunnel_dst_port = meta_data.tunnel_dst_port;
        meta.ip_addr_type = meta_data.ip_addr_type;
        meta.proto = meta_data.proto;
        meta.tunnel_ip_addr_type = meta_data.tunnel_ip_addr_type;
        meta.tunnel_proto = meta_data.tunnel_proto;
        meta.wireguard = meta_data.wireguard;

        // Return a copy of the populated data
        self.scratch_meta[0]
    }

    /// Simulates the direct return approach - creates and writes to ring buffer in one operation
    fn create_and_write_meta(&mut self, meta_data: &TestPacketData) -> Result<PacketMeta, i64> {
        // Create the PacketMeta directly (no intermediate copy)
        let meta = PacketMeta {
            ifindex: meta_data.ifindex,
            src_ipv6_addr: meta_data.src_ipv6_addr,
            dst_ipv6_addr: meta_data.dst_ipv6_addr,
            tunnel_src_ipv6_addr: meta_data.tunnel_src_ipv6_addr,
            tunnel_dst_ipv6_addr: meta_data.tunnel_dst_ipv6_addr,
            src_ipv4_addr: meta_data.src_ipv4_addr,
            dst_ipv4_addr: meta_data.dst_ipv4_addr,
            l3_octet_count: meta_data.l3_octet_count,
            tunnel_src_ipv4_addr: meta_data.tunnel_src_ipv4_addr,
            tunnel_dst_ipv4_addr: meta_data.tunnel_dst_ipv4_addr,
            src_port: meta_data.src_port,
            dst_port: meta_data.dst_port,
            tunnel_src_port: meta_data.tunnel_src_port,
            tunnel_dst_port: meta_data.tunnel_dst_port,
            ip_addr_type: meta_data.ip_addr_type,
            proto: meta_data.proto,
            tunnel_ip_addr_type: meta_data.tunnel_ip_addr_type,
            tunnel_proto: meta_data.tunnel_proto,
            wireguard: meta_data.wireguard,
        };

        // Write directly to ring buffer (single copy operation)
        self.ring_buffer.output(&meta, 0)?;
        Ok(meta)
    }

    /// Simulates the direct return approach (for comparison without ring buffer)
    fn create_and_return_meta(&self, meta_data: &TestPacketData) -> PacketMeta {
        PacketMeta {
            ifindex: meta_data.ifindex,
            src_ipv6_addr: meta_data.src_ipv6_addr,
            dst_ipv6_addr: meta_data.dst_ipv6_addr,
            tunnel_src_ipv6_addr: meta_data.tunnel_src_ipv6_addr,
            tunnel_dst_ipv6_addr: meta_data.tunnel_dst_ipv6_addr,
            src_ipv4_addr: meta_data.src_ipv4_addr,
            dst_ipv4_addr: meta_data.dst_ipv4_addr,
            l3_octet_count: meta_data.l3_octet_count,
            tunnel_src_ipv4_addr: meta_data.tunnel_src_ipv4_addr,
            tunnel_dst_ipv4_addr: meta_data.tunnel_dst_ipv4_addr,
            src_port: meta_data.src_port,
            dst_port: meta_data.dst_port,
            tunnel_src_port: meta_data.tunnel_src_port,
            tunnel_dst_port: meta_data.tunnel_dst_port,
            ip_addr_type: meta_data.ip_addr_type,
            proto: meta_data.proto,
            tunnel_ip_addr_type: meta_data.tunnel_ip_addr_type,
            tunnel_proto: meta_data.tunnel_proto,
            wireguard: meta_data.wireguard,
        }
    }

    /// Simulates writing PacketMeta to ring buffer (same operation for both approaches)
    fn write_to_ring_buffer(&mut self, meta: &PacketMeta) -> Result<(), i64> {
        // Use the same output() method as the real implementation
        self.ring_buffer.output(meta, 0)
    }

    /// Write directly from scratch memory to ring buffer (avoids copy)
    fn write_from_scratch_to_ring_buffer(&mut self) -> Result<(), i64> {
        // Write directly from scratch memory without copying
        self.ring_buffer.output(&self.scratch_meta[0], 0)
    }
}

/// Test data structure to avoid parameter explosion
#[derive(Clone, Copy)]
struct TestPacketData {
    ifindex: u32,
    src_ipv6_addr: [u8; 16],
    dst_ipv6_addr: [u8; 16],
    tunnel_src_ipv6_addr: [u8; 16],
    tunnel_dst_ipv6_addr: [u8; 16],
    src_ipv4_addr: [u8; 4],
    dst_ipv4_addr: [u8; 4],
    l3_octet_count: u32,
    tunnel_src_ipv4_addr: [u8; 4],
    tunnel_dst_ipv4_addr: [u8; 4],
    src_port: [u8; 2],
    dst_port: [u8; 2],
    tunnel_src_port: [u8; 2],
    tunnel_dst_port: [u8; 2],
    ip_addr_type: IpAddrType,
    proto: IpProto,
    tunnel_ip_addr_type: IpAddrType,
    tunnel_proto: IpProto,
    wireguard: bool,
}

impl TestPacketData {
    fn new() -> Self {
        Self {
            ifindex: 42,
            src_ipv6_addr: [
                0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01,
            ],
            dst_ipv6_addr: [0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01],
            tunnel_src_ipv6_addr: [
                0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x02,
            ],
            tunnel_dst_ipv6_addr: [0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x02],
            src_ipv4_addr: [0xc0, 0xa8, 0x01, 0x01],
            dst_ipv4_addr: [0xc0, 0xa8, 0x01, 0x02],
            l3_octet_count: 1500,
            tunnel_src_ipv4_addr: [0xc0, 0xa8, 0x02, 0x01],
            tunnel_dst_ipv4_addr: [0xc0, 0xa8, 0x02, 0x02],
            src_port: 12345u16.to_be_bytes(),
            dst_port: 80u16.to_be_bytes(),
            tunnel_src_port: 12346u16.to_be_bytes(),
            tunnel_dst_port: 81u16.to_be_bytes(),
            ip_addr_type: IpAddrType::Ipv4,
            proto: IpProto::Tcp,
            tunnel_ip_addr_type: IpAddrType::Ipv6,
            tunnel_proto: IpProto::Udp,
            wireguard: false,
        }
    }
}

fn criterion_benchmark(c: &mut Criterion) {
    let test_data = TestPacketData::new();

    // Benchmark 1: Current PerCpuArray approach (includes ring buffer write)
    c.bench_function("current_percpu_approach", |b| {
        b.iter(|| {
            let mut ctx = MockEbpFContext::new();
            let result = ctx.populate_and_write_to_ring_buffer(black_box(&test_data));
            black_box(result)
        })
    });

    // Benchmark 2: Direct return approach
    c.bench_function("direct_return_with_ring_buffer", |b| {
        b.iter(|| {
            let mut ctx = MockEbpFContext::new();
            let result = ctx.create_and_write_meta(black_box(&test_data));
            black_box(result)
        })
    });

    // Benchmark 3: Core approach comparison - PerCpuArray vs Direct Return (NO ring buffer)
    let mut core_group = c.benchmark_group("core_approaches_no_ring_buffer");

    // 1. PerCpuArray population approach
    core_group.bench_function("percpu_array_population", |b| {
        b.iter(|| {
            let mut ctx = MockEbpFContext::new();
            let meta = ctx.populate_percpu_array_only(black_box(&test_data));
            black_box(meta)
        })
    });

    // 2. Direct PacketMeta creation and return approach
    core_group.bench_function("direct_packet_meta_creation", |b| {
        b.iter(|| {
            let ctx = MockEbpFContext::new();
            let meta = ctx.create_and_return_meta(black_box(&test_data));
            black_box(meta)
        })
    });

    core_group.finish();

    // Benchmark 4: Ring buffer write overhead measurement - comparing PerCpuArray vs PacketMeta object
    let mut ring_group = c.benchmark_group("ring_buffer_overhead");

    // 1. Measure writing from PerCpuArray (scratch memory) to ring buffer
    ring_group.bench_function("percpu_array_to_ring_buffer", |b| {
        b.iter(|| {
            let mut ctx = MockEbpFContext::new();
            // Populate the PerCpuArray with test data
            let meta = ctx.populate_percpu_array_only(black_box(&test_data));
            black_box(meta); // Ensure population is not optimized away
            // Write directly from scratch memory to ring buffer (no copy)
            let result = ctx.write_from_scratch_to_ring_buffer();
            black_box(result)
        })
    });

    // 2. Measure writing from PacketMeta object to ring buffer
    ring_group.bench_function("packetmeta_object_to_ring_buffer", |b| {
        b.iter(|| {
            let mut ctx = MockEbpFContext::new();
            // Create PacketMeta object directly
            let meta = ctx.create_and_return_meta(black_box(&test_data));
            black_box(meta); // Ensure creation is not optimized away
            // Write PacketMeta object to ring buffer
            let result = ctx.write_to_ring_buffer(&meta);
            black_box(result)
        })
    });

    ring_group.finish();
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
