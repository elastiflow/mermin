use std::{
    collections::HashMap,
    time::{Duration, Instant},
};

use mermin_common::{IpAddrType, PacketMeta};
use network_types::ip::IpProto;

/// Represents aggregated data for a network flow identified by a Community ID.
///
/// This structure accumulates metrics and metadata from multiple packets
/// that belong to the same flow. It's designed to minimize allocations
/// and enable efficient updates.
#[derive(Debug, Clone)]
pub struct FlowRecord {
    /// The Community ID that identifies this flow
    pub community_id: String,

    /// Flow identification fields (from the first packet)
    pub ip_addr_type: IpAddrType,
    pub src_ipv4_addr: [u8; 4],
    pub dst_ipv4_addr: [u8; 4],
    pub src_ipv6_addr: [u8; 16],
    pub dst_ipv6_addr: [u8; 16],
    pub src_port: [u8; 2],
    pub dst_port: [u8; 2],
    pub proto: IpProto,

    /// Flow metrics (aggregated across all packets)
    pub total_packets: u64,
    pub total_bytes: u64,
    // /// Total number of packets observed for this flow since its start.
    // pub packet_total_count: u64,
    // /// Total number of bytes (octets) observed for this flow since its start.
    // pub octet_total_count: u64,
    // /// Number of packets observed in the last measurement interval.
    // pub packet_delta_count: u64,
    // /// Number of bytes (octets) observed in the last measurement interval.
    // pub octet_delta_count: u64,
    /// Timing information
    pub first_seen: Instant,
    pub last_seen: Instant,

    /// TCP-specific flags (if applicable)
    pub tcp_flags: u8,

    /// Direction tracking (for bidirectional flows)
    pub forward_packets: u64,
    pub forward_bytes: u64,
    pub reverse_packets: u64,
    pub reverse_bytes: u64,
    // /// Timestamp (seconds since epoch) when the flow was first observed.
    // pub flow_start_seconds: u32,
    // /// Timestamp (seconds since epoch) when the flow was last observed or ended.
    // pub flow_end_seconds: u32,
    // /// Reason code indicating why the flow record was generated or ended.
    // /// (e.g., 1 = Active Timeout, 2 = End of Flow detected, etc. - specific values depend on the system).
    // pub flow_end_reason: u8,
}

impl FlowRecord {
    /// Create a new flow record from the first packet
    pub fn new(community_id: String, packet: &PacketMeta) -> Self {
        let now = Instant::now();

        Self {
            community_id,
            ip_addr_type: packet.ip_addr_type,
            src_ipv4_addr: packet.src_ipv4_addr,
            dst_ipv4_addr: packet.dst_ipv4_addr,
            src_ipv6_addr: packet.src_ipv6_addr,
            dst_ipv6_addr: packet.dst_ipv6_addr,
            src_port: packet.src_port,
            dst_port: packet.dst_port,
            proto: packet.proto,
            total_packets: 1,
            total_bytes: packet.l3_octet_count as u64,
            first_seen: now,
            last_seen: now,
            tcp_flags: 0,       // TODO: Will be updated if TCP
            forward_packets: 1, // TODO: Cannot be assumed the first packet is in the forward direction
            forward_bytes: packet.l3_octet_count as u64,
            reverse_packets: 0,
            reverse_bytes: 0,
        }
    }

    /// Update the flow record with information from a new packet
    ///
    /// This method efficiently updates the flow metrics without additional allocations.
    /// It determines packet direction by comparing source/destination with the original flow.
    pub fn update_with_packet(&mut self, packet: &PacketMeta) {
        self.total_packets += 1;
        self.total_bytes += packet.l3_octet_count as u64;
        self.last_seen = Instant::now();

        // Determine packet direction by comparing with original flow direction
        let is_forward = self.is_forward_direction(packet);

        if is_forward {
            self.forward_packets += 1;
            self.forward_bytes += packet.l3_octet_count as u64;
        } else {
            self.reverse_packets += 1;
            self.reverse_bytes += packet.l3_octet_count as u64;
        }
    }

    /// Determine if a packet is in the forward direction of the flow
    fn is_forward_direction(&self, packet: &PacketMeta) -> bool {
        match self.ip_addr_type {
            IpAddrType::Ipv4 => {
                packet.src_ipv4_addr == self.src_ipv4_addr
                    && packet.dst_ipv4_addr == self.dst_ipv4_addr
                    && packet.src_port == self.src_port
                    && packet.dst_port == self.dst_port
            }
            IpAddrType::Ipv6 => {
                packet.src_ipv6_addr == self.src_ipv6_addr
                    && packet.dst_ipv6_addr == self.dst_ipv6_addr
                    && packet.src_port == self.src_port
                    && packet.dst_port == self.dst_port
            }
        }
    }

    /// Get the age of this flow (time since first packet)
    pub fn age(&self) -> Duration {
        self.first_seen.elapsed()
    }

    /// Get the time since the last packet in this flow
    pub fn idle_time(&self) -> Duration {
        self.last_seen.elapsed()
    }

    /// Check if this flow is bidirectional (has packets in both directions)
    pub fn is_bidirectional(&self) -> bool {
        self.forward_packets > 0 && self.reverse_packets > 0
    }
}

/// A high-performance store for flow records indexed by Community ID.
///
/// This store is designed to minimize allocations and provide efficient
/// operations for adding, updating, and releasing flow entries.
#[derive(Debug)]
pub struct FlowStore {
    /// The main storage map: Community ID -> Flow Record
    flows: HashMap<String, FlowRecord>,

    /// Statistics
    total_flows_created: u64,
    total_flows_released: u64,
    total_packets_processed: u64,
}

impl FlowStore {
    /// Create a new empty flow store
    pub fn new() -> Self {
        Self {
            flows: HashMap::new(),
            total_flows_created: 0,
            total_flows_released: 0,
            total_packets_processed: 0,
        }
    }

    /// Create a new flow store with pre-allocated capacity
    ///
    /// This can help reduce allocations when the expected number of
    /// concurrent flows is known.
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            flows: HashMap::with_capacity(capacity),
            total_flows_created: 0,
            total_flows_released: 0,
            total_packets_processed: 0,
        }
    }

    /// Add a new packet to the store, either creating a new flow or updating an existing one
    ///
    /// This is the main entry point for processing packets. It will:
    /// - Create a new flow record if this is the first packet for a Community ID
    /// - Update an existing flow record if one already exists
    ///
    /// Returns true if a new flow was created, false if an existing flow was updated.
    pub fn add_packet(&mut self, community_id: String, packet: &PacketMeta) -> bool {
        self.total_packets_processed += 1;

        if let Some(existing_flow) = self.flows.get_mut(&community_id) {
            // Update existing flow
            existing_flow.update_with_packet(packet);
            false
        } else {
            // Create new flow
            let flow_record = FlowRecord::new(community_id.clone(), packet);
            self.flows.insert(community_id, flow_record);
            self.total_flows_created += 1;
            true
        }
    }

    /// Get a reference to a flow record by Community ID
    pub fn get_flow(&self, community_id: &str) -> Option<&FlowRecord> {
        self.flows.get(community_id)
    }

    /// Get a mutable reference to a flow record by Community ID
    pub fn get_flow_mut(&mut self, community_id: &str) -> Option<&mut FlowRecord> {
        self.flows.get_mut(community_id)
    }

    /// Release (remove) a flow from the store by Community ID
    ///
    /// Returns the released flow record if it existed, None otherwise.
    pub fn release_flow(&mut self, community_id: &str) -> Option<FlowRecord> {
        if let Some(flow) = self.flows.remove(community_id) {
            self.total_flows_released += 1;
            Some(flow)
        } else {
            None
        }
    }

    /// Release flows that match a given predicate
    ///
    /// This is useful for implementing flow expiration policies.
    /// Returns a vector of the released flow records.
    pub fn release_flows_matching<F>(&mut self, mut predicate: F) -> Vec<FlowRecord>
    where
        F: FnMut(&FlowRecord) -> bool,
    {
        let mut to_remove = Vec::new();
        let mut released_flows = Vec::new();

        // Find flows that match the predicate
        for (community_id, flow) in &self.flows {
            if predicate(flow) {
                to_remove.push(community_id.clone());
            }
        }

        // Remove and collect the matching flows
        for community_id in to_remove {
            if let Some(flow) = self.flows.remove(&community_id) {
                self.total_flows_released += 1;
                released_flows.push(flow);
            }
        }

        released_flows
    }

    /// Release flows older than the specified duration
    pub fn release_flows_older_than(&mut self, max_age: Duration) -> Vec<FlowRecord> {
        self.release_flows_matching(|flow| flow.age() > max_age)
    }

    /// Release flows that have been idle longer than the specified duration
    pub fn release_idle_flows(&mut self, max_idle: Duration) -> Vec<FlowRecord> {
        self.release_flows_matching(|flow| flow.idle_time() > max_idle)
    }

    /// Get the number of currently active flows
    pub fn active_flow_count(&self) -> usize {
        self.flows.len()
    }

    /// Get an iterator over all active flows
    pub fn flows(&self) -> impl Iterator<Item = &FlowRecord> {
        self.flows.values()
    }

    /// Clear all flows from the store
    ///
    /// This is mainly useful for testing or when implementing configuration reloads.
    pub fn clear(&mut self) {
        self.total_flows_released += self.flows.len() as u64;
        self.flows.clear();
    }
}

impl Default for FlowStore {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use std::{net::Ipv4Addr, thread, time::Duration};

    use super::*;

    fn create_test_packet(
        src_ip: [u8; 4],
        dst_ip: [u8; 4],
        src_port: u16,
        dst_port: u16,
        bytes: u32,
    ) -> PacketMeta {
        PacketMeta {
            ip_addr_type: IpAddrType::Ipv4,
            src_ipv4_addr: src_ip,
            dst_ipv4_addr: dst_ip,
            src_ipv6_addr: [0; 16],
            dst_ipv6_addr: [0; 16],
            src_port: src_port.to_be_bytes(),
            dst_port: dst_port.to_be_bytes(),
            l3_octet_count: bytes,
            proto: IpProto::Tcp,
        }
    }

    #[test]
    fn test_flow_record_creation() {
        let packet = create_test_packet([10, 0, 0, 1], [10, 0, 0, 2], 8080, 80, 1500);
        let flow = FlowRecord::new("test_id".to_string(), &packet);

        assert_eq!(flow.community_id, "test_id");
        assert_eq!(flow.total_packets, 1);
        assert_eq!(flow.total_bytes, 1500);
        assert_eq!(flow.forward_packets, 1);
        assert_eq!(flow.forward_bytes, 1500);
        assert_eq!(flow.reverse_packets, 0);
        assert_eq!(flow.reverse_bytes, 0);
        assert!(!flow.is_bidirectional());
    }

    #[test]
    fn test_flow_record_update() {
        let packet1 = create_test_packet([10, 0, 0, 1], [10, 0, 0, 2], 8080, 80, 1500);
        let mut flow = FlowRecord::new("test_id".to_string(), &packet1);

        // Add forward packet
        let packet2 = create_test_packet([10, 0, 0, 1], [10, 0, 0, 2], 8080, 80, 800);
        flow.update_with_packet(&packet2);

        assert_eq!(flow.total_packets, 2);
        assert_eq!(flow.total_bytes, 2300);
        assert_eq!(flow.forward_packets, 2);
        assert_eq!(flow.forward_bytes, 2300);

        // Add reverse packet
        let packet3 = create_test_packet([10, 0, 0, 2], [10, 0, 0, 1], 80, 8080, 500);
        flow.update_with_packet(&packet3);

        assert_eq!(flow.total_packets, 3);
        assert_eq!(flow.total_bytes, 2800);
        assert_eq!(flow.forward_packets, 2);
        assert_eq!(flow.forward_bytes, 2300);
        assert_eq!(flow.reverse_packets, 1);
        assert_eq!(flow.reverse_bytes, 500);
        assert!(flow.is_bidirectional());
    }

    #[test]
    fn test_flow_store_basic_operations() {
        let mut store = FlowStore::new();

        let packet = create_test_packet([10, 0, 0, 1], [10, 0, 0, 2], 8080, 80, 1500);

        // Add first packet - should create new flow
        let created = store.add_packet("flow1".to_string(), &packet);
        assert!(created);
        assert_eq!(store.active_flow_count(), 1);

        // Add second packet with same Community ID - should update existing flow
        let created = store.add_packet("flow1".to_string(), &packet);
        assert!(!created);
        assert_eq!(store.active_flow_count(), 1);

        // Check flow was updated
        let flow = store.get_flow("flow1").unwrap();
        assert_eq!(flow.total_packets, 2);
        assert_eq!(flow.total_bytes, 3000);
    }

    #[test]
    fn test_flow_store_release() {
        let mut store = FlowStore::new();

        let packet = create_test_packet([10, 0, 0, 1], [10, 0, 0, 2], 8080, 80, 1500);
        store.add_packet("flow1".to_string(), &packet);
        store.add_packet("flow2".to_string(), &packet);

        assert_eq!(store.active_flow_count(), 2);

        // Release one flow
        let released = store.release_flow("flow1");
        assert!(released.is_some());
        assert_eq!(store.active_flow_count(), 1);

        // Try to release non-existent flow
        let released = store.release_flow("nonexistent");
        assert!(released.is_none());
        assert_eq!(store.active_flow_count(), 1);
    }

    #[test]
    fn test_flow_expiration() {
        let mut store = FlowStore::new();

        let packet = create_test_packet([10, 0, 0, 1], [10, 0, 0, 2], 8080, 80, 1500);
        store.add_packet("flow1".to_string(), &packet);

        // Wait a bit and add another flow
        thread::sleep(Duration::from_millis(10));
        store.add_packet("flow2".to_string(), &packet);

        // Release flows older than 5ms (should release flow1)
        let released = store.release_flows_older_than(Duration::from_millis(5));
        assert_eq!(released.len(), 1);
        assert_eq!(released[0].community_id, "flow1");
        assert_eq!(store.active_flow_count(), 1);
    }
}
