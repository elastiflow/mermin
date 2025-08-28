use std::time::Duration;

use network_types::ip::IpProto;

use crate::{
    flow::{FlowRecord, FlowStore},
    runtime::conf::flow::FlowConf,
};

/// A high-level flow manager that provides flow lifecycle management
/// according to the flow generation configuration.
pub struct FlowManager {
    store: FlowStore,
    config: FlowConf,
}

impl FlowManager {
    /// Create a new flow manager with the given configuration
    pub fn new(config: FlowConf) -> Self {
        Self {
            store: FlowStore::new(),
            config,
        }
    }

    /// Get a reference to the underlying flow store
    pub fn store(&self) -> &FlowStore {
        &self.store
    }

    /// Get a mutable reference to the underlying flow store
    pub fn store_mut(&mut self) -> &mut FlowStore {
        &mut self.store
    }

    /// Release flows based on the flow generation configuration
    ///
    /// This method implements the flow release logic according to the
    /// configuration parameters. It handles different protocols and
    /// their specific timeout requirements.
    pub fn release_expired_flows(&mut self) -> Vec<FlowRecord> {
        let mut released_flows = Vec::new();

        // Release flows that have exceeded maximum active lifetime
        let max_active_flows = self
            .store
            .release_flows_older_than(self.config.max_active_life);
        released_flows.extend(max_active_flows);

        // Release flows based on protocol-specific idle timeouts
        let idle_flows = self.store.release_flows_matching(|flow| {
            let idle_timeout = self.get_idle_timeout_for_flow(flow);
            flow.idle_time() > idle_timeout
        });
        released_flows.extend(idle_flows);

        released_flows
    }

    /// Get the appropriate idle timeout for a flow based on its protocol
    /// and any TCP-specific flags
    fn get_idle_timeout_for_flow(&self, flow: &FlowRecord) -> Duration {
        match flow.proto {
            IpProto::Tcp => {
                // Check for TCP termination flags
                if flow.tcp_flags & 0x01 != 0 {
                    // FIN flag is set
                    self.config.tcp_fin
                } else if flow.tcp_flags & 0x04 != 0 {
                    // RST flag is set
                    self.config.tcp_rst
                } else {
                    // Normal TCP flow
                    self.config.tcp
                }
            }
            IpProto::Udp => self.config.udp,
            IpProto::Icmp | IpProto::Ipv6Icmp => self.config.icmp,
            _ => self.config.flow_generic,
        }
    }

    /// Force release a specific flow by Community ID
    ///
    /// This is useful for implementing manual flow termination
    /// or when specific events require immediate flow cleanup.
    pub fn release_flow(&mut self, community_id: &str) -> Option<FlowRecord> {
        self.store.release_flow(community_id)
    }

    /// Release all flows (useful for configuration reloads or shutdown)
    pub fn release_all_flows(&mut self) -> Vec<FlowRecord> {
        let flows: Vec<FlowRecord> = self.store.flows().cloned().collect();
        self.store.clear();
        flows
    }

    /// Get flows that are ready for release according to current configuration
    ///
    /// This method doesn't actually release the flows, it just identifies them.
    /// Useful for preview or logging purposes.
    pub fn get_flows_ready_for_release(&self) -> Vec<&FlowRecord> {
        self.store
            .flows()
            .filter(|flow| {
                // Check if flow exceeds max active life
                if flow.age() > self.config.max_active_life {
                    return true;
                }

                // Check if flow exceeds protocol-specific idle timeout
                let idle_timeout = self.get_idle_timeout_for_flow(flow);
                flow.idle_time() > idle_timeout
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use mermin_common::{IpAddrType, PacketMeta};

    use super::*;
    use crate::runtime::conf::flow::Flow as FlowConf;

    fn create_test_config() -> FlowConf {
        FlowConf {
            expiry_interval: Duration::from_secs(10),
            max_active_life: Duration::from_secs(60),
            flow_generic: Duration::from_secs(30),
            icmp: Duration::from_secs(10),
            tcp: Duration::from_secs(20),
            tcp_fin: Duration::from_secs(5),
            tcp_rst: Duration::from_secs(5),
            udp: Duration::from_secs(20),
        }
    }

    fn create_test_packet(proto: IpProto) -> PacketMeta {
        PacketMeta {
            ip_addr_type: IpAddrType::Ipv4,
            src_ipv4_addr: [10, 0, 0, 1],
            dst_ipv4_addr: [10, 0, 0, 2],
            src_ipv6_addr: [0; 16],
            dst_ipv6_addr: [0; 16],
            src_port: 8080u16.to_be_bytes(),
            dst_port: 80u16.to_be_bytes(),
            l3_octet_count: 1500,
            proto,
        }
    }

    #[test]
    fn test_flow_manager_creation() {
        let config = create_test_config();
        let manager = FlowManager::new(config);

        assert_eq!(manager.store().active_flow_count(), 0);
    }

    #[test]
    fn test_protocol_specific_timeouts() {
        let config = create_test_config();
        let manager = FlowManager::new(config);

        // Create test flows
        let tcp_packet = create_test_packet(IpProto::Tcp);
        let udp_packet = create_test_packet(IpProto::Udp);
        let icmp_packet = create_test_packet(IpProto::Icmp);

        let tcp_flow = super::super::flow::FlowRecord::new("tcp_flow".to_string(), &tcp_packet);
        let udp_flow = super::super::flow::FlowRecord::new("udp_flow".to_string(), &udp_packet);
        let icmp_flow = super::super::flow::FlowRecord::new("icmp_flow".to_string(), &icmp_packet);

        // Test timeout calculations
        assert_eq!(
            manager.get_idle_timeout_for_flow(&tcp_flow),
            Duration::from_secs(20)
        );
        assert_eq!(
            manager.get_idle_timeout_for_flow(&udp_flow),
            Duration::from_secs(20)
        );
        assert_eq!(
            manager.get_idle_timeout_for_flow(&icmp_flow),
            Duration::from_secs(10)
        );
    }
}
