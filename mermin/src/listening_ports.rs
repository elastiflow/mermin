//! Listening port scanner for client/server direction inference.
//!
//! This module scans `/proc/net/{tcp,tcp6,udp,udp6}` at startup to populate
//! the eBPF LISTENING_PORTS map with existing listeners. After startup,
//! eBPF kprobes maintain the map in real-time.

use std::{
    fs::File,
    io::{BufRead, BufReader},
    sync::Arc,
};

use aya::maps::HashMap as EbpfHashMap;
use mermin_common::ListeningPortKey;
use network_types::ip::IpProto;
use tokio::sync::Mutex;
use tracing::{debug, trace, warn};

use crate::metrics::ebpf::{EbpfMapName, EbpfMapOperation, EbpfMapStatus, inc_map_operation};

/// TCP connection states from /proc/net/tcp
/// We only care about TCP_LISTEN (0x0A)
const TCP_LISTEN: u8 = 0x0A;

/// Scanner for listening ports at startup
pub struct ListeningPortScanner {
    listening_ports_map: Arc<Mutex<EbpfHashMap<aya::maps::MapData, ListeningPortKey, u8>>>,
}

impl ListeningPortScanner {
    pub fn new(
        listening_ports_map: Arc<Mutex<EbpfHashMap<aya::maps::MapData, ListeningPortKey, u8>>>,
    ) -> Self {
        Self {
            listening_ports_map,
        }
    }

    /// Scan /proc/net/* and populate the eBPF map with existing listeners.
    ///
    /// This is called once at startup after eBPF programs are attached.
    ///
    /// When running in a container with `hostPID: true`, uses `/proc/1/net/*` to see
    /// the host's listening ports rather than the container's own namespace.
    ///
    /// # Errors
    ///
    /// Returns [`std::io::Error`] if:
    /// - `/proc/net/tcp`, `/proc/net/tcp6`, `/proc/net/udp`, or `/proc/net/udp6`
    ///   cannot be read (excluding `NotFound` errors, which are silently ignored
    ///   for systems without IPv6 support)
    /// - Line parsing encounters I/O errors while reading the file
    pub async fn scan_and_populate(&self) -> Result<usize, std::io::Error> {
        let mut total_ports = 0;

        // Determine correct /proc path based on deployment mode:
        // - Container with hostPID: true -> use /proc/1/net/* (host namespace)
        // - Bare metal or hostNetwork: true -> use /proc/net/* (same namespace)
        let proc_net_base = if std::path::Path::new("/proc/1/ns/net").exists() {
            "/proc/1/net"
        } else {
            "/proc/net"
        };

        debug!(
            event.name = "listening_ports.scan_mode",
            proc_path = proc_net_base,
            "scanning for listening ports"
        );

        // Scan TCP (IPv4)
        total_ports += self
            .scan_proc_net(
                &format!("{proc_net_base}/tcp"),
                IpProto::Tcp,
                "listening_ports.tcp_scan_complete",
                Self::parse_tcp_line,
            )
            .await?;

        // Scan TCP (IPv6)
        total_ports += self
            .scan_proc_net(
                &format!("{proc_net_base}/tcp6"),
                IpProto::Tcp,
                "listening_ports.tcp_scan_complete",
                Self::parse_tcp_line,
            )
            .await?;

        // Scan UDP (IPv4) - all bound UDP ports are considered "listening"
        total_ports += self
            .scan_proc_net(
                &format!("{proc_net_base}/udp"),
                IpProto::Udp,
                "listening_ports.udp_scan_complete",
                Self::parse_udp_line,
            )
            .await?;

        // Scan UDP (IPv6)
        total_ports += self
            .scan_proc_net(
                &format!("{proc_net_base}/udp6"),
                IpProto::Udp,
                "listening_ports.udp_scan_complete",
                Self::parse_udp_line,
            )
            .await?;

        debug!(
            event.name = "listening_ports.scan_complete",
            total_ports = total_ports,
            "populated eBPF map with existing listening ports"
        );

        Ok(total_ports)
    }

    /// Generic scanner for /proc/net files
    ///
    /// Parses the file and collects ports before acquiring the eBPF map lock,
    /// minimizing lock hold time.
    ///
    /// # Errors
    ///
    /// Returns [`std::io::Error`] if:
    /// - The file at `path` cannot be opened (excluding `NotFound` which returns `Ok(0)`)
    /// - Line reading encounters I/O errors
    async fn scan_proc_net<F>(
        &self,
        path: &str,
        protocol: IpProto,
        event_name: &str,
        parser: F,
    ) -> Result<usize, std::io::Error>
    where
        F: Fn(&str) -> Option<u16>,
    {
        let file = match File::open(path) {
            Ok(f) => f,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                // File doesn't exist (e.g., IPv6 not enabled)
                debug!(
                    event.name = "listening_ports.file_not_found",
                    path = path,
                    "skipping scan, file not found"
                );
                return Ok(0);
            }
            Err(e) => return Err(e),
        };

        let reader = BufReader::new(file);
        let mut ports_to_insert = Vec::new();

        for (idx, line) in reader.lines().enumerate() {
            // Skip header line
            if idx == 0 {
                continue;
            }

            let line = line?;
            if let Some(port) = parser(&line) {
                ports_to_insert.push(port);
            }
        }

        let mut count = 0;
        let mut map = self.listening_ports_map.lock().await;

        for port in ports_to_insert {
            let key = ListeningPortKey { port, protocol };

            // Insert into eBPF map (duplicates are harmless, just updates value)
            match map.insert(key, 1u8, 0) {
                Ok(_) => {
                    inc_map_operation(
                        EbpfMapName::ListeningPorts,
                        EbpfMapOperation::Write,
                        EbpfMapStatus::Ok,
                    );
                    count += 1;
                }
                Err(e) => {
                    inc_map_operation(
                        EbpfMapName::ListeningPorts,
                        EbpfMapOperation::Write,
                        EbpfMapStatus::Error,
                    );
                    warn!(
                        event.name = "listening_ports.insert_failed",
                        path = path,
                        port = port,
                        error = %e,
                        "failed to insert listening port into eBPF map"
                    );
                }
            }
        }

        trace!(
            event.name = event_name,
            path = path,
            count = count,
            "scanned listening ports"
        );

        Ok(count)
    }

    /// Parse a line from /proc/net/tcp or /proc/net/tcp6
    ///
    /// Returns the port number if the line represents a socket in LISTEN state.
    ///
    /// Format: `sl local_address rem_address st tx_queue rx_queue tr tm->when retrnsmt uid timeout inode`
    ///
    /// Example: `"  0: 0100007F:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 12345 1 0000000000000000 100 0 0 10 0"`
    ///
    /// We extract local_address port (1F90 = 8080) when st (state) = 0A (LISTEN)
    fn parse_tcp_line(line: &str) -> Option<u16> {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 4 {
            return None;
        }

        // parts[1] = local_address (e.g., "0100007F:1F90")
        // parts[3] = st (state, e.g., "0A" for LISTEN)

        // Parse state
        let state = u8::from_str_radix(parts[3], 16).ok()?;
        if state != TCP_LISTEN {
            return None;
        }

        // Parse port from local_address
        let local_addr = parts[1];
        let port_hex = local_addr.split(':').nth(1)?;
        let port = u16::from_str_radix(port_hex, 16).ok()?;

        Some(port)
    }

    /// Parse a line from /proc/net/udp or /proc/net/udp6
    ///
    /// Returns the port number for any bound UDP socket (excluding port 0).
    /// For UDP, any bound socket is considered "listening" since UDP is connectionless.
    ///
    /// Format similar to TCP: `sl local_address rem_address st ...`
    fn parse_udp_line(line: &str) -> Option<u16> {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 2 {
            return None;
        }

        // parts[1] = local_address (e.g., "00000000:0035" for port 53)
        let local_addr = parts[1];
        let port_hex = local_addr.split(':').nth(1)?;
        let port = u16::from_str_radix(port_hex, 16).ok()?;

        // Ignore port 0 (wildcard/unbound)
        if port == 0 {
            return None;
        }

        Some(port)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_tcp_line_listen() {
        // Real line from /proc/net/tcp (nginx listening on port 80 = 0x0050)
        let line = "   1: 00000000:0050 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 12345 1 0000000000000000 100 0 0 10 0";
        assert_eq!(ListeningPortScanner::parse_tcp_line(line), Some(80));
    }

    #[test]
    fn test_parse_tcp_line_established() {
        // Established connection (state 01), should return None
        let line = "   2: 0100007F:1F90 0100007F:D8F0 01 00000000:00000000 00:00000000 00000000  1000        0 23456 1 0000000000000000 20 4 30 10 -1";
        assert_eq!(ListeningPortScanner::parse_tcp_line(line), None);
    }

    #[test]
    fn test_parse_tcp_line_https() {
        // HTTPS listening on port 443 = 0x01BB
        let line = "   3: 00000000:01BB 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 34567 1 0000000000000000 100 0 0 10 0";
        assert_eq!(ListeningPortScanner::parse_tcp_line(line), Some(443));
    }

    #[test]
    fn test_parse_udp_line_dns() {
        // DNS server on port 53 = 0x0035
        let line = "   1: 00000000:0035 00000000:0000 07 00000000:00000000 00:00000000 00000000     0        0 45678 2 0000000000000000 0";
        assert_eq!(ListeningPortScanner::parse_udp_line(line), Some(53));
    }

    #[test]
    fn test_parse_udp_line_wildcard() {
        // Port 0 (wildcard), should return None
        let line = "   2: 00000000:0000 00000000:0000 07 00000000:00000000 00:00000000 00000000     0        0 56789 2 0000000000000000 0";
        assert_eq!(ListeningPortScanner::parse_udp_line(line), None);
    }

    #[test]
    fn test_parse_tcp_line_malformed() {
        let line = "invalid line";
        assert_eq!(ListeningPortScanner::parse_tcp_line(line), None);
    }
}
