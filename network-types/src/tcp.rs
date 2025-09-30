//! TCP header, which is present after the IP header.
//!    0                   1                   2                   3
//!    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//!   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//!   |          Source Port          |       Destination Port        |
//!   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//!   |                        Sequence Number                        |
//!   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//!   |                    Acknowledgment Number                      |
//!   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//!   |  Data |     |N|C|E|U|A|P|R|S|F|                               |
//!   | Offset| Rsrv|S|R|C|R|C|S|S|Y|I|            Window             |
//!   |       |     | |W|E|G|K|H|T|N|N|                               |
//!   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//!   |           Checksum            |         Urgent Pointer        |
//!   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//!   |                            Options                            |
//!   /                              ...                              /
//!   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//!   |                            Padding                            |
//!   /                              ...                              /
//!   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//!   |                             data                              |
//!   /                              ...                              /
//!   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//!
//! This struct represents the Transmission Control Protocol (TCP) header as defined in RFC 793.
//! The TCP header is 20 bytes long (without options) and contains various fields for connection
//! management, flow control, and reliability.
//! All fields are stored in network byte order (big-endian).

/// The length of the TCP header base structure.
pub const TCP_LEN: usize = 20;

/// Source port field (16 bits).
pub type SrcPort = [u8; 2];
/// Destination port field (16 bits).
pub type DstPort = [u8; 2];
/// Sequence number field (32 bits).
pub type SeqNum = [u8; 4];
/// Acknowledgment sequence number field (32 bits).
pub type AckSeq = [u8; 4];
/// Combined field: Data offset (4 bits), Reserved (3 bits), Flags (9 bits).
pub type OffResFlags = [u8; 2];
/// Window size field (16 bits).
pub type Window = [u8; 2];
/// Checksum field (16 bits).
pub type Checksum = [u8; 2];
/// Urgent pointer field (16 bits).
pub type UrgPtr = [u8; 2];

/// TCP flag masks
pub const TCP_FLAG_FIN: u8 = 0x01;
pub const TCP_FLAG_SYN: u8 = 0x02;
pub const TCP_FLAG_RST: u8 = 0x04;
pub const TCP_FLAG_PSH: u8 = 0x08;
pub const TCP_FLAG_ACK: u8 = 0x10;
pub const TCP_FLAG_URG: u8 = 0x20;
pub const TCP_FLAG_ECE: u8 = 0x40;
pub const TCP_FLAG_CWR: u8 = 0x80;

/// Returns the source port from network byte order.
#[inline]
pub fn src_port(src: SrcPort) -> u16 {
    u16::from_be_bytes(src)
}

/// Returns the destination port from network byte order.
#[inline]
pub fn dst_port(dst: DstPort) -> u16 {
    u16::from_be_bytes(dst)
}

/// Returns the sequence number from network byte order.
#[inline]
pub fn seq_num(seq: SeqNum) -> u32 {
    u32::from_be_bytes(seq)
}

/// Returns the acknowledgment sequence number from network byte order.
#[inline]
pub fn ack_seq(ack_seq: AckSeq) -> u32 {
    u32::from_be_bytes(ack_seq)
}

/// Returns the window size from network byte order.
#[inline]
pub fn window(window: Window) -> u16 {
    u16::from_be_bytes(window)
}

/// Returns the checksum from network byte order.
#[inline]
pub fn checksum(check: Checksum) -> u16 {
    u16::from_be_bytes(check)
}

/// Returns the urgent pointer from network byte order.
#[inline]
pub fn urg_ptr(urg_ptr: UrgPtr) -> u16 {
    u16::from_be_bytes(urg_ptr)
}

/// Returns the data offset value (header length in 32-bit words).
#[inline]
pub fn data_offset(off_res_flags: OffResFlags) -> u8 {
    (off_res_flags[0] >> 4) & 0x0F
}

/// Returns the header length in bytes.
#[inline]
pub fn hdr_len(off_res_flags: OffResFlags) -> usize {
    (data_offset(off_res_flags) as usize) * 4
}

/// Returns the TCP flags.
#[inline]
pub fn tcp_flags(off_res_flags: OffResFlags) -> u8 {
    off_res_flags[1]
}

/// Returns true if the FIN flag is set.
#[inline]
pub fn fin_flag(off_res_flags: OffResFlags) -> bool {
    (off_res_flags[1] & TCP_FLAG_FIN) != 0
}

/// Returns true if the SYN flag is set.
#[inline]
pub fn syn_flag(off_res_flags: OffResFlags) -> bool {
    (off_res_flags[1] & TCP_FLAG_SYN) != 0
}

/// Returns true if the RST flag is set.
#[inline]
pub fn rst_flag(off_res_flags: OffResFlags) -> bool {
    (off_res_flags[1] & TCP_FLAG_RST) != 0
}

/// Returns true if the PSH flag is set.
#[inline]
pub fn psh_flag(off_res_flags: OffResFlags) -> bool {
    (off_res_flags[1] & TCP_FLAG_PSH) != 0
}

/// Returns true if the ACK flag is set.
#[inline]
pub fn ack_flag(off_res_flags: OffResFlags) -> bool {
    (off_res_flags[1] & TCP_FLAG_ACK) != 0
}

/// Returns true if the URG flag is set.
#[inline]
pub fn urg_flag(off_res_flags: OffResFlags) -> bool {
    (off_res_flags[1] & TCP_FLAG_URG) != 0
}

/// Returns true if the ECE flag is set.
#[inline]
pub fn ece_flag(off_res_flags: OffResFlags) -> bool {
    (off_res_flags[1] & TCP_FLAG_ECE) != 0
}

/// Returns true if the CWR flag is set.
#[inline]
pub fn cwr_flag(off_res_flags: OffResFlags) -> bool {
    (off_res_flags[1] & TCP_FLAG_CWR) != 0
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_tcp_len_constant() {
        assert_eq!(TCP_LEN, 20);
    }

    #[test]
    fn test_flag_masks() {
        assert_eq!(TCP_FLAG_FIN, 0x01);
        assert_eq!(TCP_FLAG_SYN, 0x02);
        assert_eq!(TCP_FLAG_RST, 0x04);
        assert_eq!(TCP_FLAG_PSH, 0x08);
        assert_eq!(TCP_FLAG_ACK, 0x10);
        assert_eq!(TCP_FLAG_URG, 0x20);
        assert_eq!(TCP_FLAG_ECE, 0x40);
        assert_eq!(TCP_FLAG_CWR, 0x80);
    }

    #[test]
    fn test_src_port() {
        assert_eq!(src_port([0x12, 0x34]), 0x1234);
        assert_eq!(src_port([0x00, 0x50]), 80);
        assert_eq!(src_port([0x00, 0x00]), 0);
        assert_eq!(src_port([0xFF, 0xFF]), u16::MAX);
    }

    #[test]
    fn test_dst_port() {
        assert_eq!(dst_port([0x56, 0x78]), 0x5678);
        assert_eq!(dst_port([0x1F, 0x90]), 8080);
        assert_eq!(dst_port([0x00, 0x00]), 0);
        assert_eq!(dst_port([0xFF, 0xFF]), u16::MAX);
    }

    #[test]
    fn test_seq_num() {
        assert_eq!(seq_num([0x12, 0x34, 0x56, 0x78]), 0x12345678);
        assert_eq!(seq_num([0x49, 0x96, 0x02, 0xD2]), 1234567890);
        assert_eq!(seq_num([0x00, 0x00, 0x00, 0x00]), 0);
        assert_eq!(seq_num([0xFF, 0xFF, 0xFF, 0xFF]), u32::MAX);
    }

    #[test]
    fn test_ack_seq() {
        assert_eq!(ack_seq([0x87, 0x65, 0x43, 0x21]), 0x87654321);
        assert_eq!(ack_seq([0x8B, 0xD0, 0x38, 0x35]), 2345678901);
        assert_eq!(ack_seq([0x00, 0x00, 0x00, 0x00]), 0);
        assert_eq!(ack_seq([0xFF, 0xFF, 0xFF, 0xFF]), u32::MAX);
    }

    #[test]
    fn test_window() {
        assert_eq!(window([0x20, 0x00]), 0x2000);
        assert_eq!(window([0x16, 0xD0]), 5840);
        assert_eq!(window([0x00, 0x00]), 0);
        assert_eq!(window([0xFF, 0xFF]), u16::MAX);
    }

    #[test]
    fn test_checksum() {
        assert_eq!(checksum([0x12, 0x34]), 0x1234);
        assert_eq!(checksum([0xAB, 0xCD]), 0xABCD);
        assert_eq!(checksum([0x00, 0x00]), 0);
        assert_eq!(checksum([0xFF, 0xFF]), u16::MAX);
    }

    #[test]
    fn test_urg_ptr() {
        assert_eq!(urg_ptr([0x00, 0x00]), 0);
        assert_eq!(urg_ptr([0x03, 0xE8]), 1000);
        assert_eq!(urg_ptr([0xFF, 0xFF]), u16::MAX);
    }

    #[test]
    fn test_data_offset() {
        // Data offset 5 (minimum valid - 20 bytes header)
        assert_eq!(data_offset([0x50, 0x00]), 5);
        // Data offset 6 (24 bytes header)
        assert_eq!(data_offset([0x60, 0x00]), 6);
        // Data offset 15 (maximum - 60 bytes header)
        assert_eq!(data_offset([0xF0, 0x00]), 15);
        // Data offset with flags set
        assert_eq!(data_offset([0x50, 0xFF]), 5);
    }

    #[test]
    fn test_hdr_len() {
        // Minimum header length (5 * 4 = 20 bytes)
        assert_eq!(hdr_len([0x50, 0x00]), 20);
        // Header with options (6 * 4 = 24 bytes)
        assert_eq!(hdr_len([0x60, 0x00]), 24);
        // Maximum header length (15 * 4 = 60 bytes)
        assert_eq!(hdr_len([0xF0, 0x00]), 60);
    }

    #[test]
    fn test_tcp_flags() {
        assert_eq!(tcp_flags([0x50, 0x00]), 0x00);
        assert_eq!(tcp_flags([0x50, 0x12]), 0x12); // SYN+ACK
        assert_eq!(tcp_flags([0x50, 0xFF]), 0xFF); // All flags
    }

    #[test]
    fn test_fin_flag() {
        assert_eq!(fin_flag([0x50, 0x01]), true);
        assert_eq!(fin_flag([0x50, 0x00]), false);
        assert_eq!(fin_flag([0x50, 0xFE]), false);
    }

    #[test]
    fn test_syn_flag() {
        assert_eq!(syn_flag([0x50, 0x02]), true);
        assert_eq!(syn_flag([0x50, 0x00]), false);
        assert_eq!(syn_flag([0x50, 0xFD]), false);
    }

    #[test]
    fn test_rst_flag() {
        assert_eq!(rst_flag([0x50, 0x04]), true);
        assert_eq!(rst_flag([0x50, 0x00]), false);
        assert_eq!(rst_flag([0x50, 0xFB]), false);
    }

    #[test]
    fn test_psh_flag() {
        assert_eq!(psh_flag([0x50, 0x08]), true);
        assert_eq!(psh_flag([0x50, 0x00]), false);
        assert_eq!(psh_flag([0x50, 0xF7]), false);
    }

    #[test]
    fn test_ack_flag() {
        assert_eq!(ack_flag([0x50, 0x10]), true);
        assert_eq!(ack_flag([0x50, 0x00]), false);
        assert_eq!(ack_flag([0x50, 0xEF]), false);
    }

    #[test]
    fn test_urg_flag() {
        assert_eq!(urg_flag([0x50, 0x20]), true);
        assert_eq!(urg_flag([0x50, 0x00]), false);
        assert_eq!(urg_flag([0x50, 0xDF]), false);
    }

    #[test]
    fn test_ece_flag() {
        assert_eq!(ece_flag([0x50, 0x40]), true);
        assert_eq!(ece_flag([0x50, 0x00]), false);
        assert_eq!(ece_flag([0x50, 0xBF]), false);
    }

    #[test]
    fn test_cwr_flag() {
        assert_eq!(cwr_flag([0x50, 0x80]), true);
        assert_eq!(cwr_flag([0x50, 0x00]), false);
        assert_eq!(cwr_flag([0x50, 0x7F]), false);
    }

    #[test]
    fn test_multiple_flags() {
        // SYN+ACK
        let off_res_flags: OffResFlags = [0x50, 0x12];
        assert_eq!(syn_flag(off_res_flags), true);
        assert_eq!(ack_flag(off_res_flags), true);
        assert_eq!(fin_flag(off_res_flags), false);

        // All flags set
        let off_res_flags: OffResFlags = [0x50, 0xFF];
        assert_eq!(fin_flag(off_res_flags), true);
        assert_eq!(syn_flag(off_res_flags), true);
        assert_eq!(rst_flag(off_res_flags), true);
        assert_eq!(psh_flag(off_res_flags), true);
        assert_eq!(ack_flag(off_res_flags), true);
        assert_eq!(urg_flag(off_res_flags), true);
        assert_eq!(ece_flag(off_res_flags), true);
        assert_eq!(cwr_flag(off_res_flags), true);
    }

    #[test]
    fn test_type_aliases() {
        // Test SrcPort type alias
        let src: SrcPort = [0x12, 0x34];
        assert_eq!(src, [0x12, 0x34]);

        // Test DstPort type alias
        let dst: DstPort = [0x56, 0x78];
        assert_eq!(dst, [0x56, 0x78]);

        // Test SeqNum type alias
        let seq: SeqNum = [0x12, 0x34, 0x56, 0x78];
        assert_eq!(seq, [0x12, 0x34, 0x56, 0x78]);

        // Test AckSeq type alias
        let ack: AckSeq = [0x87, 0x65, 0x43, 0x21];
        assert_eq!(ack, [0x87, 0x65, 0x43, 0x21]);

        // Test OffResFlags type alias
        let off_res_flags: OffResFlags = [0x50, 0x18];
        assert_eq!(off_res_flags, [0x50, 0x18]);

        // Test Window type alias
        let win: Window = [0x20, 0x00];
        assert_eq!(win, [0x20, 0x00]);

        // Test Checksum type alias
        let check: Checksum = [0x12, 0x34];
        assert_eq!(check, [0x12, 0x34]);

        // Test UrgPtr type alias
        let urg: UrgPtr = [0x00, 0x00];
        assert_eq!(urg, [0x00, 0x00]);
    }
}
