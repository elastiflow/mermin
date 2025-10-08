use std::net::IpAddr;

use ipnetwork::IpNetwork;
use log::warn;

use crate::runtime::conf::FlowSpanFilter;

/// A pre-compiled filter for network spans.
/// It parses CIDR strings into a more efficient representation for matching.
#[derive(Debug, Clone)]
pub struct PacketFilter {
    source: CompiledFilter,
    destination: CompiledFilter,
}

#[derive(Debug, Clone)]
struct CompiledFilter {
    exclude_cidrs: Vec<IpNetwork>,
    include_cidrs: Vec<IpNetwork>,
    exclude_ports: Vec<u16>,
    include_ports: Vec<u16>,
}

impl PacketFilter {
    /// Creates a new `PacketFilter` from the resolved configuration filters.
    pub fn new(source_filter: FlowSpanFilter, destination_filter: FlowSpanFilter) -> Self {
        Self {
            source: CompiledFilter::new(source_filter),
            destination: CompiledFilter::new(destination_filter),
        }
    }

    /// Determines if a span should be produced based on the filtering rules.
    /// Returns `true` if the packet should be kept, `false` if it should be dropped.
    pub fn should_produce_span(
        &self,
        src_ip: IpAddr,
        src_port: u16,
        dst_ip: IpAddr,
        dst_port: u16,
    ) -> bool {
        self.source.is_allowed(src_ip, src_port) && self.destination.is_allowed(dst_ip, dst_port)
    }
}

impl CompiledFilter {
    fn new(raw_filter: FlowSpanFilter) -> Self {
        let parse_cidrs = |cidrs: Vec<String>| -> Vec<IpNetwork> {
            cidrs
                .into_iter()
                .filter_map(|s| match s.parse() {
                    Ok(net) => Some(net),
                    Err(e) => {
                        warn!("invalid CIDR string '{s}' in configuration, skipping: {e}");
                        None
                    }
                })
                .collect()
        };

        Self {
            exclude_cidrs: parse_cidrs(raw_filter.exclude_cidrs),
            include_cidrs: parse_cidrs(raw_filter.include_cidrs),
            exclude_ports: raw_filter.exclude_ports,
            include_ports: raw_filter.include_ports,
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
        if self.exclude_cidrs.iter().any(|net| net.contains(ip)) {
            return false;
        }

        if !self.include_ports.is_empty() && !self.include_ports.contains(&port) {
            return false;
        }
        if !self.include_cidrs.is_empty() && !self.include_cidrs.iter().any(|net| net.contains(ip))
        {
            return false;
        }

        true
    }
}
