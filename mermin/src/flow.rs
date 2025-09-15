use std::{net::IpAddr, sync::Arc, time::Duration};

use dashmap::DashMap;
use fxhash::FxBuildHasher;
use mermin_common::PacketMeta;
use network_types::ip::IpProto;
use tokio::sync::mpsc;

use crate::{
    community_id::CommunityIdGenerator,
    k8s::{EnrichedInfo, resource_parser::NetworkPolicy},
    runtime::conf::flow::FlowConf,
};

#[allow(dead_code)]
type FlowMap = Arc<DashMap<String, FlowRecord, FxBuildHasher>>;

#[derive(Debug, Default)]
#[allow(dead_code)]
pub struct EnrichedFlowData {
    pub id: String,
    pub src: Option<EnrichedInfo>,
    pub dst: Option<EnrichedInfo>,
    pub network_policies: Option<Vec<NetworkPolicy>>,
}

/// Flow direction for policy evaluation
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum FlowDirection {
    Ingress,
    Egress,
}

#[allow(dead_code)]
pub struct FlowRecord {
    pub id: String,
    pub ifindex: u32,
    pub src_addr: IpAddr,
    pub dst_addr: IpAddr,
    pub src_port: u16,
    pub dst_port: u16,
    pub proto: IpProto,
    pub tunnel_src_addr: IpAddr,
    pub tunnel_dst_addr: IpAddr,
    pub tunnel_src_port: u16,
    pub tunnel_dst_port: u16,
    pub tunnel_proto: IpProto,
    pub bytes: u32,
    pub packets: u32,
}

#[allow(dead_code)]
pub struct FlowProducer {
    flow_conf: FlowConf,
    packet_channel_capacity: usize,
    packet_worker_count: usize,
    flow_map: FlowMap,
    community_id_generator: CommunityIdGenerator,
    packet_event_rx: mpsc::Receiver<PacketMeta>,
    flow_event_tx: mpsc::Sender<FlowRecord>,
}

impl FlowProducer {
    #[allow(dead_code)]
    pub fn new(
        flow_conf: FlowConf,
        packet_channel_capacity: usize,
        packet_worker_count: usize,
        packet_event_rx: mpsc::Receiver<PacketMeta>,
        flow_event_tx: mpsc::Sender<FlowRecord>,
    ) -> Self {
        let flow_map_capacity = packet_channel_capacity * 8;
        let flow_map = Arc::new(DashMap::with_capacity_and_hasher(
            flow_map_capacity,
            FxBuildHasher::default(),
        ));
        let community_id_generator = CommunityIdGenerator::new(0);

        Self {
            flow_conf,
            packet_channel_capacity,
            packet_worker_count,
            community_id_generator,
            flow_map,
            packet_event_rx,
            flow_event_tx,
        }
    }

    #[allow(dead_code)]
    pub async fn run(mut self) {
        // Create channels for each worker
        let mut worker_channels = Vec::new();
        let worker_capacity = self.packet_channel_capacity.max(self.packet_worker_count)
            / self.packet_worker_count.max(1);

        for _ in 0..self.packet_worker_count.max(1) {
            let (worker_tx, worker_rx) = mpsc::channel(worker_capacity);
            worker_channels.push(worker_tx);

            let packet_worker = PacketWorker::new(
                self.flow_conf.clone(),
                Arc::clone(&self.flow_map),
                self.community_id_generator.clone(),
                worker_rx,
                self.flow_event_tx.clone(),
            );
            tokio::spawn(async move {
                packet_worker.run().await;
            });
        }

        // Distribute packets with backpressure-aware fallback
        let mut worker_index = 0;
        let worker_count = self.packet_worker_count.max(1);

        while let Some(packet) = self.packet_event_rx.recv().await {
            let mut sent = false;
            // Try current worker first, then try others if it's full
            for attempt in 0..worker_count {
                let current_worker = (worker_index + attempt) % worker_count;
                let worker_tx = &worker_channels[current_worker];

                match worker_tx.try_send(packet) {
                    Ok(_) => {
                        worker_index = (current_worker + 1) % worker_count;
                        sent = true;
                        break;
                    }
                    Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => {
                        // This worker is full, try next one
                        continue;
                    }
                    Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => {
                        // Worker is gone, try next one
                        continue;
                    }
                }
            }

            if !sent {
                // All workers are full - fallback to blocking send to preferred worker
                let worker_tx = &worker_channels[worker_index];
                // TODO: remove this once we have a better way to handle this
                #[allow(clippy::redundant_pattern_matching)]
                if let Err(_) = worker_tx.send(packet).await {
                    // Worker channel is closed, handle gracefully
                    continue;
                }
                worker_index = (worker_index + 1) % worker_count;
            }
        }
    }
}

#[allow(dead_code)]
pub struct PacketWorker {
    max_batch_size: usize,
    max_batch_interval: Duration,
    max_record_interval: Duration,
    generic_timeout: Duration,
    icmp_timeout: Duration,
    tcp_timeout: Duration,
    tcp_fin_timeout: Duration,
    tcp_rst_timeout: Duration,
    udp_timeout: Duration,

    flow_map: FlowMap,
    community_id_generator: CommunityIdGenerator,
    pub packet_event_rx: mpsc::Receiver<PacketMeta>,
    pub flow_event_tx: mpsc::Sender<FlowRecord>,
}

impl PacketWorker {
    #[allow(dead_code)]
    pub fn new(
        flow_conf: FlowConf,
        flow_map: FlowMap,
        community_id_generator: CommunityIdGenerator,
        packet_event_rx: mpsc::Receiver<PacketMeta>,
        flow_event_tx: mpsc::Sender<FlowRecord>,
    ) -> Self {
        Self {
            max_batch_size: flow_conf.max_batch_size,
            max_batch_interval: flow_conf.max_batch_interval,
            max_record_interval: flow_conf.max_record_interval,
            generic_timeout: flow_conf.generic_timeout,
            icmp_timeout: flow_conf.icmp_timeout,
            tcp_timeout: flow_conf.tcp_timeout,
            tcp_fin_timeout: flow_conf.tcp_fin_timeout,
            tcp_rst_timeout: flow_conf.tcp_rst_timeout,
            udp_timeout: flow_conf.udp_timeout,
            packet_event_rx,
            flow_event_tx,
            flow_map,
            community_id_generator,
        }
    }

    #[allow(dead_code)]
    fn extract_ip_addresses(
        ip_addr_type: mermin_common::IpAddrType,
        src_ipv4_addr: [u8; 4],
        dst_ipv4_addr: [u8; 4],
        src_ipv6_addr: [u8; 16],
        dst_ipv6_addr: [u8; 16],
    ) -> (IpAddr, IpAddr) {
        match ip_addr_type {
            mermin_common::IpAddrType::Ipv4 => {
                let src = IpAddr::V4(std::net::Ipv4Addr::from(src_ipv4_addr));
                let dst = IpAddr::V4(std::net::Ipv4Addr::from(dst_ipv4_addr));
                (src, dst)
            }
            mermin_common::IpAddrType::Ipv6 => {
                let src = IpAddr::V6(std::net::Ipv6Addr::from(src_ipv6_addr));
                let dst = IpAddr::V6(std::net::Ipv6Addr::from(dst_ipv6_addr));
                (src, dst)
            }
        }
    }

    #[allow(dead_code)]
    pub async fn run(mut self) {
        while let Some(packet) = self.packet_event_rx.recv().await {
            let (src_addr, dst_addr) = Self::extract_ip_addresses(
                packet.ip_addr_type,
                packet.src_ipv4_addr,
                packet.dst_ipv4_addr,
                packet.src_ipv6_addr,
                packet.dst_ipv6_addr,
            );
            let (tunnel_src_addr, tunnel_dst_addr) = Self::extract_ip_addresses(
                packet.tunnel_ip_addr_type,
                packet.tunnel_src_ipv4_addr,
                packet.tunnel_dst_ipv4_addr,
                packet.tunnel_src_ipv6_addr,
                packet.tunnel_dst_ipv6_addr,
            );

            let src_port = packet.src_port();
            let dst_port = packet.dst_port();

            let community_id = self.community_id_generator.generate(
                src_addr,
                dst_addr,
                src_port,
                dst_port,
                packet.proto,
            );

            let flow_record = FlowRecord {
                id: community_id.clone(),
                ifindex: packet.ifindex,
                src_addr,
                dst_addr,
                src_port,
                dst_port,
                proto: packet.proto,
                tunnel_src_addr,
                tunnel_dst_addr,
                tunnel_src_port: packet.tunnel_src_port(),
                tunnel_dst_port: packet.tunnel_dst_port(),
                tunnel_proto: packet.tunnel_proto,
                bytes: packet.l3_octet_count,
                packets: 1,
            };

            self.flow_map.insert(community_id, flow_record);
        }
    }
}
