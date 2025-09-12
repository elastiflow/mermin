use std::{net::IpAddr, time::Duration};

use mermin_common::PacketMeta;
use network_types::ip::IpProto;
use tokio::sync::mpsc;

use crate::{
    k8s::{EnrichedInfo, resource_parser::NetworkPolicy},
    runtime::conf::flow::FlowConf,
};

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

pub struct FlowProducer {
    flow_conf: FlowConf,
    packet_channel_capacity: usize,
    packet_worker_count: usize,
    packet_event_rx: mpsc::Receiver<PacketMeta>,
    flow_event_tx: mpsc::Sender<FlowRecord>,
}

impl FlowProducer {
    pub fn new(
        flow_conf: FlowConf,
        packet_channel_capacity: usize,
        packet_worker_count: usize,
        packet_event_rx: mpsc::Receiver<PacketMeta>,
        flow_event_tx: mpsc::Sender<FlowRecord>,
    ) -> Self {
        Self {
            flow_conf,
            packet_channel_capacity,
            packet_worker_count,
            packet_event_rx,
            flow_event_tx,
        }
    }

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

                match worker_tx.try_send(packet.clone()) {
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
                if let Err(_) = worker_tx.send(packet).await {
                    // Worker channel is closed, handle gracefully
                    continue;
                }
                worker_index = (worker_index + 1) % worker_count;
            }
        }
    }
}

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

    pub packet_event_rx: mpsc::Receiver<PacketMeta>,
    pub flow_event_tx: mpsc::Sender<FlowRecord>,
}

impl PacketWorker {
    pub fn new(
        flow_conf: FlowConf,
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
        }
    }

    pub async fn run(mut self) {
        while let Some(packet) = self.packet_event_rx.recv().await {
            // TODO: Process packet into flow records
            // let flow_record = FlowRecord::new(packet);
            // self.flow_event_tx.send(flow_record).await.unwrap();
        }
    }
}
