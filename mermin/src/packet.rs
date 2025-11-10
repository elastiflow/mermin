//! Deep packet parsing module for extracting innermost 5-tuples from tunneled traffic.
//!
//! This module provides functionality to parse raw packet bytes (captured from eBPF)
//! and extract:
//! - Innermost 5-tuple for correct Community ID calculation
//! - Tunnel metadata (VNI, type, outer headers)
//! - L2/L3 metadata (MACs, DSCP, TTL, etc.)
//!
//! **Key Optimization**: eBPF already parsed outer headers into FlowStats, so we only
//! parse the UNPARSED portion (tunnels) and skip redundant parsing for plain traffic.
//!
//! Supports:
//! - VXLAN (UDP port 4789)
//! - Geneve (UDP port 6081)
//! - GRE (IP protocol 47) - TODO
//! - Plain (non-tunneled) packets (fast path - no parsing!)

pub mod parser;
pub mod types;
