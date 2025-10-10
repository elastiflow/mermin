use std::{collections::HashSet, net::IpAddr};

use ip_network::IpNetwork;
use ip_network_table::IpNetworkTable;
use log::warn;

use crate::runtime::conf::FlowSpanFilter;

struct FilterRules {
    exclude_cidrs: IpNetworkTable<()>,
    include_cidrs: IpNetworkTable<()>,
    exclude_ports: HashSet<u16>,
    include_ports: HashSet<u16>,
}

impl FilterRules {
    fn new(raw_filter: FlowSpanFilter) -> Self {
        let parse_cidrs = |cidrs: Vec<String>| -> Vec<IpNetwork> {
            cidrs
                .into_iter()
                .filter_map(|s| match s.parse() {
                    Ok(net) => Some(net),
                    Err(e) => {
                        warn!("invalid cidr string '{s}' in configuration, skipping: {e}");
                        None
                    }
                })
                .collect()
        };

        let exclude_cidrs_vec = parse_cidrs(raw_filter.exclude_cidrs);
        let include_cidrs_vec = parse_cidrs(raw_filter.include_cidrs);

        let mut exclude_table = IpNetworkTable::new();
        for network in exclude_cidrs_vec {
            exclude_table.insert(network, ());
        }

        let mut include_table = IpNetworkTable::new();
        for network in include_cidrs_vec {
            include_table.insert(network, ());
        }

        Self {
            exclude_cidrs: exclude_table,
            include_cidrs: include_table,
            exclude_ports: raw_filter.exclude_ports.into_iter().collect(),
            include_ports: raw_filter.include_ports.into_iter().collect(),
        }
    }

    /// Applies the filtering logic:
    /// 1. If an item matches an exclusion rule, it is immediately removed and isn't considered
    ///    by the inclusion rules.
    /// 2. If an inclusion list is empty, everything is considered a match.
    /// 3. If an exclusion list is empty, nothing is considered a match.
    fn is_allowed(&self, ip: IpAddr, port: u16) -> bool {
        if self.exclude_ports.contains(&port) {
            return false;
        }
        if self.exclude_cidrs.longest_match(ip).is_some() {
            return false;
        }

        if !self.include_ports.is_empty() && !self.include_ports.contains(&port) {
            return false;
        }
        if !self.include_cidrs.is_empty() && self.include_cidrs.longest_match(ip).is_none() {
            return false;
        }

        true
    }
}

/// A pre-compiled filter for network spans.
/// It parses CIDR strings into a more efficient representation for matching.
pub struct PacketFilter {
    source: FilterRules,
    destination: FilterRules,
}

impl PacketFilter {
    /// Creates a new `PacketFilter` from the resolved configuration filters.
    pub fn new(source_filter: FlowSpanFilter, destination_filter: FlowSpanFilter) -> Self {
        Self {
            source: FilterRules::new(source_filter),
            destination: FilterRules::new(destination_filter),
        }
    }

    /// Determines if a span should be produced based on the filtering rules.
    /// Returns `true` if the packet should be kept, `false` if it should be dropped.
    pub fn should_process(
        &self,
        src_ip: IpAddr,
        src_port: u16,
        dst_ip: IpAddr,
        dst_port: u16,
    ) -> bool {
        self.source.is_allowed(src_ip, src_port) && self.destination.is_allowed(dst_ip, dst_port)
    }
}
