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
//!
use core::mem;

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
pub fn header_len(off_res_flags: OffResFlags) -> usize {
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

#[repr(C, packed)]
#[derive(Debug, Copy, Clone)]
pub struct TcpHdr {
    /// Source port in network byte order (big-endian)
    pub src: [u8; 2],
    /// Destination port in network byte order (big-endian)
    pub dst: [u8; 2],
    /// Sequence number in network byte order (big-endian)
    pub seq: [u8; 4],
    /// Acknowledgment number in network byte order (big-endian)
    pub ack_seq: [u8; 4],
    /// Data offset, reserved bits, and flags in network byte order (big-endian)
    pub off_res_flags: [u8; 2],
    /// Window size in network byte order (big-endian)
    pub window: [u8; 2],
    /// Checksum in network byte order (big-endian)
    pub check: [u8; 2],
    /// Urgent pointer in network byte order (big-endian)
    pub urg_ptr: [u8; 2],
}

impl TcpHdr {
    /// The size of the TCP header in bytes (8 bytes).
    pub const LEN: usize = mem::size_of::<TcpHdr>();

    /// Returns the source port number.
    ///
    /// This method converts the source port from network byte order (big-endian)
    /// to host byte order.
    ///
    /// # Returns
    /// The source port as a u16 value.
    #[inline]
    pub fn src_port(&self) -> u16 {
        u16::from_be_bytes(self.src)
    }

    /// Sets the source port number.
    ///
    /// This method converts the source port from host byte order
    /// to network byte order (big-endian).
    ///
    /// # Parameters
    /// * `source` - The source port number to set.
    #[inline]
    pub fn set_src_port(&mut self, source: u16) {
        self.src = source.to_be_bytes();
    }

    /// Returns the destination port number.
    ///
    /// This method converts the destination port from network byte order (big-endian)
    /// to host byte order.
    ///
    /// # Returns
    /// The destination port as a u16 value.
    #[inline]
    pub fn dst_port(&self) -> u16 {
        u16::from_be_bytes(self.dst)
    }

    /// Sets the destination port number.
    ///
    /// This method converts the destination port from host byte order
    /// to network byte order (big-endian).
    ///
    /// # Parameters
    /// * `dest` - The destination port number to set.
    #[inline]
    pub fn set_dst_port(&mut self, dest: u16) {
        self.dst = dest.to_be_bytes();
    }

    /// Returns the sequence number.
    ///
    /// This method converts the sequence number from network byte order (big-endian)
    /// to host byte order.
    ///
    /// # Returns
    /// The sequence number as a u32 value.
    #[inline]
    pub fn seq(&self) -> u32 {
        u32::from_be_bytes(self.seq)
    }

    /// Sets the sequence number.
    ///
    /// This method converts the sequence number from host byte order
    /// to network byte order (big-endian).
    ///
    /// # Parameters
    /// * `seq` - The sequence number to set.
    #[inline]
    pub fn set_seq(&mut self, seq: u32) {
        self.seq = seq.to_be_bytes();
    }

    /// Returns the acknowledgment sequence number.
    ///
    /// This method converts the acknowledgment sequence number from network byte order (big-endian)
    /// to host byte order.
    ///
    /// # Returns
    /// The acknowledgment sequence number as a u32 value.
    #[inline]
    pub fn ack_seq(&self) -> u32 {
        u32::from_be_bytes(self.ack_seq)
    }

    /// Sets the acknowledgment sequence number.
    ///
    /// This method converts the acknowledgment sequence number from host byte order
    /// to network byte order (big-endian).
    ///
    /// # Parameters
    /// * `ack_seq` - The acknowledgment sequence number to set.
    #[inline]
    pub fn set_ack_seq(&mut self, ack_seq: u32) {
        self.ack_seq = ack_seq.to_be_bytes();
    }

    /// Returns the window size.
    ///
    /// This method converts the window size from network byte order (big-endian)
    /// to host byte order.
    ///
    /// # Returns
    /// The window size as a u16 value.
    #[inline]
    pub fn window(&self) -> u16 {
        u16::from_be_bytes(self.window)
    }

    /// Sets the window size.
    ///
    /// This method converts the window size from host byte order
    /// to network byte order (big-endian).
    ///
    /// # Parameters
    /// * `window` - The window size to set.
    #[inline]
    pub fn set_window(&mut self, window: u16) {
        self.window = window.to_be_bytes();
    }

    /// Returns the checksum.
    ///
    /// This method converts the checksum from network byte order (big-endian)
    /// to host byte order.
    ///
    /// # Returns
    /// The checksum as a u16 value.
    #[inline]
    pub fn checksum(&self) -> u16 {
        u16::from_be_bytes(self.check)
    }

    /// Sets the checksum.
    ///
    /// This method converts the checksum from host byte order
    /// to network byte order (big-endian).
    ///
    /// # Parameters
    /// * `check` - The checksum to set.
    #[inline]
    pub fn set_checksum(&mut self, check: u16) {
        self.check = check.to_be_bytes();
    }

    /// Returns the urgent pointer.
    ///
    /// This method converts the urgent pointer from network byte order (big-endian)
    /// to host byte order.
    ///
    /// # Returns
    /// The urgent pointer as a u16 value.
    #[inline]
    pub fn urg_ptr(&self) -> u16 {
        u16::from_be_bytes(self.urg_ptr)
    }

    /// Sets the urgent pointer.
    ///
    /// This method converts the urgent pointer from host byte order
    /// to network byte order (big-endian).
    ///
    /// # Parameters
    /// * `urg_ptr` - The urgent pointer to set.
    #[inline]
    pub fn set_urg_ptr(&mut self, urg_ptr: u16) {
        self.urg_ptr = urg_ptr.to_be_bytes();
    }

    /// Returns the data offset value (header length in 32-bit words).
    ///
    /// This method extracts the data offset field from the off_res_flags field.
    /// The data offset is the high 4 bits of the first byte.
    ///
    /// # Returns
    /// The data offset value (header length in 32-bit words).
    #[inline]
    pub fn data_offset(&self) -> u8 {
        (self.off_res_flags[0] >> 4) & 0x0F
    }

    /// Sets the data offset value (header length in 32-bit words).
    ///
    /// This method sets the data offset field in the off_res_flags field.
    /// The data offset is the high 4 bits of the first byte.
    ///
    /// # Parameters
    /// * `doff` - The data offset value to set (header length in 32-bit words).
    #[inline]
    pub fn set_data_offset(&mut self, doff: u8) {
        self.off_res_flags[0] = (self.off_res_flags[0] & 0x0F) | ((doff & 0x0F) << 4);
    }

    /// Returns the header length in bytes.
    ///
    /// This method calculates the header length in bytes from the data offset field.
    /// The data offset field specifies the header length in 32-bit words.
    ///
    /// # Returns
    /// The header length in bytes.
    #[inline]
    pub fn header_len(&self) -> usize {
        (self.data_offset() as usize) * 4
    }

    /// Returns the TCP flags.
    ///
    /// This method returns the TCP flags from the second byte of the off_res_flags field.
    ///
    /// # Returns
    /// The TCP flags as a u8 value.
    #[inline]
    pub fn tcp_flags(&self) -> u8 {
        self.off_res_flags[1]
    }

    /// Private helper method to get a flag bit from the second byte of `off_res_flags`.
    #[inline]
    fn get_flag(&self, mask: u8) -> bool {
        (self.off_res_flags[1] & mask) != 0
    }

    /// Private helper method to set or clear a flag bit in the second byte of `off_res_flags`.
    #[inline]
    fn set_flag(&mut self, mask: u8, value: bool) {
        if value {
            self.off_res_flags[1] |= mask;
        } else {
            self.off_res_flags[1] &= !mask;
        }
    }

    /// Returns true if the FIN flag is set.
    ///
    /// # Returns
    /// `true` if the FIN flag is set, `false` otherwise.
    #[inline]
    pub fn fin(&self) -> bool {
        // Assuming Self::TCP_FLAG_FIN if constants are associated with TcpHdr struct
        // For this standalone snippet, we use the module-level const.
        self.get_flag(TCP_FLAG_FIN)
    }

    /// Sets the FIN flag.
    ///
    /// # Parameters
    /// * `fin` - `true` to set the FIN flag, `false` to clear it.
    #[inline]
    pub fn set_fin(&mut self, fin: bool) {
        self.set_flag(TCP_FLAG_FIN, fin)
    }

    /// Returns true if the SYN flag is set.
    ///
    /// # Returns
    /// `true` if the SYN flag is set, `false` otherwise.
    #[inline]
    pub fn syn(&self) -> bool {
        self.get_flag(TCP_FLAG_SYN)
    }

    /// Sets the SYN flag.
    ///
    /// # Parameters
    /// * `syn` - `true` to set the SYN flag, `false` to clear it.
    #[inline]
    pub fn set_syn(&mut self, syn: bool) {
        self.set_flag(TCP_FLAG_SYN, syn)
    }

    /// Returns true if the RST flag is set.
    ///
    /// # Returns
    /// `true` if the RST flag is set, `false` otherwise.
    #[inline]
    pub fn rst(&self) -> bool {
        self.get_flag(TCP_FLAG_RST)
    }

    /// Sets the RST flag.
    ///
    /// # Parameters
    /// * `rst` - `true` to set the RST flag, `false` to clear it.
    #[inline]
    pub fn set_rst(&mut self, rst: bool) {
        self.set_flag(TCP_FLAG_RST, rst)
    }

    /// Returns true if the PSH flag is set.
    ///
    /// # Returns
    /// `true` if the PSH flag is set, `false` otherwise.
    #[inline]
    pub fn psh(&self) -> bool {
        self.get_flag(TCP_FLAG_PSH)
    }

    /// Sets the PSH flag.
    ///
    /// # Parameters
    /// * `psh` - `true` to set the PSH flag, `false` to clear it.
    #[inline]
    pub fn set_psh(&mut self, psh: bool) {
        self.set_flag(TCP_FLAG_PSH, psh)
    }

    /// Returns true if the ACK flag is set.
    ///
    /// # Returns
    /// `true` if the ACK flag is set, `false` otherwise.
    #[inline]
    pub fn ack(&self) -> bool {
        self.get_flag(TCP_FLAG_ACK)
    }

    /// Sets the ACK flag.
    ///
    /// # Parameters
    /// * `ack` - `true` to set the ACK flag, `false` to clear it.
    #[inline]
    pub fn set_ack(&mut self, ack: bool) {
        self.set_flag(TCP_FLAG_ACK, ack)
    }

    /// Returns true if the URG flag is set.
    ///
    /// # Returns
    /// `true` if the URG flag is set, `false` otherwise.
    #[inline]
    pub fn urg(&self) -> bool {
        self.get_flag(TCP_FLAG_URG)
    }

    /// Sets the URG flag.
    ///
    /// # Parameters
    /// * `urg` - `true` to set the URG flag, `false` to clear it.
    #[inline]
    pub fn set_urg(&mut self, urg: bool) {
        self.set_flag(TCP_FLAG_URG, urg)
    }

    /// Returns true if the ECE flag is set.
    ///
    /// # Returns
    /// `true` if the ECE flag is set, `false` otherwise.
    #[inline]
    pub fn ece(&self) -> bool {
        self.get_flag(TCP_FLAG_ECE)
    }

    /// Sets the ECE flag.
    ///
    /// # Parameters
    /// * `ece` - `true` to set the ECE flag, `false` to clear it.
    #[inline]
    pub fn set_ece(&mut self, ece: bool) {
        self.set_flag(TCP_FLAG_ECE, ece)
    }

    /// Returns true if the CWR flag is set.
    ///
    /// # Returns
    /// `true` if the CWR flag is set, `false` otherwise.
    #[inline]
    pub fn cwr(&self) -> bool {
        self.get_flag(TCP_FLAG_CWR)
    }

    /// Sets the CWR flag.
    ///
    /// # Parameters
    /// * `cwr` - `true` to set the CWR flag, `false` to clear it.
    #[inline]
    pub fn set_cwr(&mut self, cwr: bool) {
        self.set_flag(TCP_FLAG_CWR, cwr)
    }
}

#[cfg(test)]
mod test {
    use core::mem;

    use super::TcpHdr;

    #[test]
    fn test_tcp_hdr_size() {
        // TcpHdr should be exactly 20 bytes
        assert_eq!(TcpHdr::LEN, 20);
        assert_eq!(TcpHdr::LEN, mem::size_of::<TcpHdr>());
    }

    #[test]
    fn test_source_port() {
        let mut tcp_hdr = TcpHdr {
            src: [0, 0],
            dst: [0, 0],
            seq: [0, 0, 0, 0],
            ack_seq: [0, 0, 0, 0],
            off_res_flags: [0, 0],
            window: [0, 0],
            check: [0, 0],
            urg_ptr: [0, 0],
        };

        // Test with a standard value
        let test_port: u16 = 12345;
        tcp_hdr.set_src_port(test_port);
        assert_eq!(tcp_hdr.src_port(), test_port);

        // Verify byte order in raw storage (big-endian/network byte order)
        assert_eq!(tcp_hdr.src, [0x30, 0x39]); // 12345 in big-endian

        // Test with zero
        tcp_hdr.set_src_port(0);
        assert_eq!(tcp_hdr.src_port(), 0);
        assert_eq!(tcp_hdr.src, [0, 0]);

        // Test with max value
        tcp_hdr.set_src_port(u16::MAX);
        assert_eq!(tcp_hdr.src_port(), u16::MAX);
        assert_eq!(tcp_hdr.src, [0xFF, 0xFF]);
    }

    #[test]
    fn test_dest_port() {
        let mut tcp_hdr = TcpHdr {
            src: [0, 0],
            dst: [0, 0],
            seq: [0, 0, 0, 0],
            ack_seq: [0, 0, 0, 0],
            off_res_flags: [0, 0],
            window: [0, 0],
            check: [0, 0],
            urg_ptr: [0, 0],
        };

        // Test with a standard value
        let test_port: u16 = 80;
        tcp_hdr.set_dst_port(test_port);
        assert_eq!(tcp_hdr.dst_port(), test_port);

        // Verify byte order in raw storage (big-endian/network byte order)
        assert_eq!(tcp_hdr.dst, [0x00, 0x50]); // 80 in big-endian

        // Test with zero
        tcp_hdr.set_dst_port(0);
        assert_eq!(tcp_hdr.dst_port(), 0);
        assert_eq!(tcp_hdr.dst, [0, 0]);

        // Test with max value
        tcp_hdr.set_dst_port(u16::MAX);
        assert_eq!(tcp_hdr.dst_port(), u16::MAX);
        assert_eq!(tcp_hdr.dst, [0xFF, 0xFF]);
    }

    #[test]
    fn test_sequence_number() {
        let mut tcp_hdr = TcpHdr {
            src: [0, 0],
            dst: [0, 0],
            seq: [0, 0, 0, 0],
            ack_seq: [0, 0, 0, 0],
            off_res_flags: [0, 0],
            window: [0, 0],
            check: [0, 0],
            urg_ptr: [0, 0],
        };

        // Test with a standard value
        let test_seq: u32 = 1234567890;
        tcp_hdr.set_seq(test_seq);
        assert_eq!(tcp_hdr.seq(), test_seq);

        // Verify byte order in raw storage (big-endian/network byte order)
        assert_eq!(tcp_hdr.seq, [0x49, 0x96, 0x02, 0xD2]); // 1234567890 in big-endian

        // Test with zero
        tcp_hdr.set_seq(0);
        assert_eq!(tcp_hdr.seq(), 0);
        assert_eq!(tcp_hdr.seq, [0, 0, 0, 0]);

        // Test with max value
        tcp_hdr.set_seq(u32::MAX);
        assert_eq!(tcp_hdr.seq(), u32::MAX);
        assert_eq!(tcp_hdr.seq, [0xFF, 0xFF, 0xFF, 0xFF]);
    }

    #[test]
    fn test_acknowledgment_number() {
        let mut tcp_hdr = TcpHdr {
            src: [0, 0],
            dst: [0, 0],
            seq: [0, 0, 0, 0],
            ack_seq: [0, 0, 0, 0],
            off_res_flags: [0, 0],
            window: [0, 0],
            check: [0, 0],
            urg_ptr: [0, 0],
        };

        // Test with a standard value
        let test_ack_seq: u32 = 2345678901;
        tcp_hdr.set_ack_seq(test_ack_seq);
        assert_eq!(tcp_hdr.ack_seq(), test_ack_seq);

        // Verify byte order in raw storage (big-endian/network byte order)
        assert_eq!(tcp_hdr.ack_seq, [0x8B, 0xD0, 0x38, 0x35]); // 2345678901 in big-endian

        // Test with zero
        tcp_hdr.set_ack_seq(0);
        assert_eq!(tcp_hdr.ack_seq(), 0);
        assert_eq!(tcp_hdr.ack_seq, [0, 0, 0, 0]);

        // Test with max value
        tcp_hdr.set_ack_seq(u32::MAX);
        assert_eq!(tcp_hdr.ack_seq(), u32::MAX);
        assert_eq!(tcp_hdr.ack_seq, [0xFF, 0xFF, 0xFF, 0xFF]);
    }

    #[test]
    fn test_data_offset() {
        let mut tcp_hdr = TcpHdr {
            src: [0, 0],
            dst: [0, 0],
            seq: [0, 0, 0, 0],
            ack_seq: [0, 0, 0, 0],
            off_res_flags: [0, 0],
            window: [0, 0],
            check: [0, 0],
            urg_ptr: [0, 0],
        };

        // Test with minimum valid value (5 = 20 bytes header)
        tcp_hdr.set_data_offset(5);
        assert_eq!(tcp_hdr.data_offset(), 5);
        assert_eq!(tcp_hdr.header_len(), 20);
        assert_eq!(tcp_hdr.off_res_flags[0] & 0xF0, 0x50);

        // Test with maximum value (15 = 60 bytes header)
        tcp_hdr.set_data_offset(15);
        assert_eq!(tcp_hdr.data_offset(), 15);
        assert_eq!(tcp_hdr.header_len(), 60);
        assert_eq!(tcp_hdr.off_res_flags[0] & 0xF0, 0xF0);

        // Test that only the top 4 bits are affected
        tcp_hdr.off_res_flags[0] = 0xFF;
        tcp_hdr.set_data_offset(5);
        assert_eq!(tcp_hdr.off_res_flags[0], 0x5F);
    }

    #[test]
    fn test_flags() {
        let mut tcp_hdr = TcpHdr {
            src: [0, 0],
            dst: [0, 0],
            seq: [0, 0, 0, 0],
            ack_seq: [0, 0, 0, 0],
            off_res_flags: [0, 0],
            window: [0, 0],
            check: [0, 0],
            urg_ptr: [0, 0],
        };

        // Test FIN flag
        assert!(!tcp_hdr.fin());
        tcp_hdr.set_fin(true);
        assert!(tcp_hdr.fin());
        assert_eq!(tcp_hdr.off_res_flags[1] & 0x01, 0x01);
        tcp_hdr.set_fin(false);
        assert!(!tcp_hdr.fin());

        // Test SYN flag
        assert!(!tcp_hdr.syn());
        tcp_hdr.set_syn(true);
        assert!(tcp_hdr.syn());
        assert_eq!(tcp_hdr.off_res_flags[1] & 0x02, 0x02);
        tcp_hdr.set_syn(false);
        assert!(!tcp_hdr.syn());

        // Test RST flag
        assert!(!tcp_hdr.rst());
        tcp_hdr.set_rst(true);
        assert!(tcp_hdr.rst());
        assert_eq!(tcp_hdr.off_res_flags[1] & 0x04, 0x04);
        tcp_hdr.set_rst(false);
        assert!(!tcp_hdr.rst());

        // Test PSH flag
        assert!(!tcp_hdr.psh());
        tcp_hdr.set_psh(true);
        assert!(tcp_hdr.psh());
        assert_eq!(tcp_hdr.off_res_flags[1] & 0x08, 0x08);
        tcp_hdr.set_psh(false);
        assert!(!tcp_hdr.psh());

        // Test ACK flag
        assert!(!tcp_hdr.ack());
        tcp_hdr.set_ack(true);
        assert!(tcp_hdr.ack());
        assert_eq!(tcp_hdr.off_res_flags[1] & 0x10, 0x10);
        tcp_hdr.set_ack(false);
        assert!(!tcp_hdr.ack());

        // Test URG flag
        assert!(!tcp_hdr.urg());
        tcp_hdr.set_urg(true);
        assert!(tcp_hdr.urg());
        assert_eq!(tcp_hdr.off_res_flags[1] & 0x20, 0x20);
        tcp_hdr.set_urg(false);
        assert!(!tcp_hdr.urg());

        // Test ECE flag
        assert!(!tcp_hdr.ece());
        tcp_hdr.set_ece(true);
        assert!(tcp_hdr.ece());
        assert_eq!(tcp_hdr.off_res_flags[1] & 0x40, 0x40);
        tcp_hdr.set_ece(false);
        assert!(!tcp_hdr.ece());

        // Test CWR flag
        assert!(!tcp_hdr.cwr());
        tcp_hdr.set_cwr(true);
        assert!(tcp_hdr.cwr());
        assert_eq!(tcp_hdr.off_res_flags[1] & 0x80, 0x80);
        tcp_hdr.set_cwr(false);
        assert!(!tcp_hdr.cwr());

        // Test setting multiple flags
        tcp_hdr.set_syn(true);
        tcp_hdr.set_ack(true);
        assert!(tcp_hdr.syn());
        assert!(tcp_hdr.ack());
        assert_eq!(tcp_hdr.off_res_flags[1], 0x12);
    }

    #[test]
    fn test_window() {
        let mut tcp_hdr = TcpHdr {
            src: [0, 0],
            dst: [0, 0],
            seq: [0, 0, 0, 0],
            ack_seq: [0, 0, 0, 0],
            off_res_flags: [0, 0],
            window: [0, 0],
            check: [0, 0],
            urg_ptr: [0, 0],
        };

        // Test with a standard value
        let test_window: u16 = 5840;
        tcp_hdr.set_window(test_window);
        assert_eq!(tcp_hdr.window(), test_window);

        // Verify byte order in raw storage (big-endian/network byte order)
        assert_eq!(tcp_hdr.window, [0x16, 0xD0]); // 5840 in big-endian

        // Test with zero
        tcp_hdr.set_window(0);
        assert_eq!(tcp_hdr.window(), 0);
        assert_eq!(tcp_hdr.window, [0, 0]);

        // Test with max value
        tcp_hdr.set_window(u16::MAX);
        assert_eq!(tcp_hdr.window(), u16::MAX);
        assert_eq!(tcp_hdr.window, [0xFF, 0xFF]);
    }

    #[test]
    fn test_checksum() {
        let mut tcp_hdr = TcpHdr {
            src: [0, 0],
            dst: [0, 0],
            seq: [0, 0, 0, 0],
            ack_seq: [0, 0, 0, 0],
            off_res_flags: [0, 0],
            window: [0, 0],
            check: [0, 0],
            urg_ptr: [0, 0],
        };

        // Test with a standard value
        let test_checksum: u16 = 0x1234;
        tcp_hdr.set_checksum(test_checksum);
        assert_eq!(tcp_hdr.checksum(), test_checksum);

        // Verify byte order in raw storage (big-endian/network byte order)
        assert_eq!(tcp_hdr.check, [0x12, 0x34]);

        // Test with zero
        tcp_hdr.set_checksum(0);
        assert_eq!(tcp_hdr.checksum(), 0);
        assert_eq!(tcp_hdr.check, [0, 0]);

        // Test with max value
        tcp_hdr.set_checksum(u16::MAX);
        assert_eq!(tcp_hdr.checksum(), u16::MAX);
        assert_eq!(tcp_hdr.check, [0xFF, 0xFF]);
    }

    #[test]
    fn test_urgent_pointer() {
        let mut tcp_hdr = TcpHdr {
            src: [0, 0],
            dst: [0, 0],
            seq: [0, 0, 0, 0],
            ack_seq: [0, 0, 0, 0],
            off_res_flags: [0, 0],
            window: [0, 0],
            check: [0, 0],
            urg_ptr: [0, 0],
        };

        // Test with a standard value
        let test_urg_ptr: u16 = 1000;
        tcp_hdr.set_urg_ptr(test_urg_ptr);
        assert_eq!(tcp_hdr.urg_ptr(), test_urg_ptr);

        // Verify byte order in raw storage (big-endian/network byte order)
        assert_eq!(tcp_hdr.urg_ptr, [0x03, 0xE8]); // 1000 in big-endian

        // Test with zero
        tcp_hdr.set_urg_ptr(0);
        assert_eq!(tcp_hdr.urg_ptr(), 0);
        assert_eq!(tcp_hdr.urg_ptr, [0, 0]);

        // Test with max value
        tcp_hdr.set_urg_ptr(u16::MAX);
        assert_eq!(tcp_hdr.urg_ptr(), u16::MAX);
        assert_eq!(tcp_hdr.urg_ptr, [0xFF, 0xFF]);
    }

    #[test]
    fn test_tcp_len_constant() {
        assert_eq!(TCP_LEN, 20);
    }

    #[test]
    fn test_public_type_aliases() {
        // Test SrcPort type alias
        let src_port: SrcPort = [0x12, 0x34];
        assert_eq!(src_port, [0x12, 0x34]);

        // Test DstPort type alias
        let dst_port: DstPort = [0x56, 0x78];
        assert_eq!(dst_port, [0x56, 0x78]);

        // Test SeqNum type alias
        let seq_num: SeqNum = [0x12, 0x34, 0x56, 0x78];
        assert_eq!(seq_num, [0x12, 0x34, 0x56, 0x78]);

        // Test AckSeq type alias
        let ack_seq: AckSeq = [0x87, 0x65, 0x43, 0x21];
        assert_eq!(ack_seq, [0x87, 0x65, 0x43, 0x21]);

        // Test OffResFlags type alias
        let off_res_flags: OffResFlags = [0x50, 0x18]; // Data offset 5, ACK+PSH flags
        assert_eq!(off_res_flags, [0x50, 0x18]);

        // Test Window type alias
        let window: Window = [0x20, 0x00];
        assert_eq!(window, [0x20, 0x00]);

        // Test Checksum type alias
        let checksum: Checksum = [0x12, 0x34];
        assert_eq!(checksum, [0x12, 0x34]);

        // Test UrgPtr type alias
        let urg_ptr: UrgPtr = [0x00, 0x00];
        assert_eq!(urg_ptr, [0x00, 0x00]);
    }

    #[test]
    fn test_public_field_helper_functions() {
        // Test src_port function
        let src_port: SrcPort = [0x12, 0x34];
        assert_eq!(src_port(src_port), 0x1234);

        // Test dst_port function
        let dst_port: DstPort = [0x56, 0x78];
        assert_eq!(dst_port(dst_port), 0x5678);

        // Test seq_num function
        let seq_num: SeqNum = [0x12, 0x34, 0x56, 0x78];
        assert_eq!(seq_num(seq_num), 0x12345678);

        // Test ack_seq function
        let ack_seq: AckSeq = [0x87, 0x65, 0x43, 0x21];
        assert_eq!(ack_seq(ack_seq), 0x87654321);

        // Test window function
        let window: Window = [0x20, 0x00];
        assert_eq!(window(window), 0x2000);

        // Test checksum function
        let checksum: Checksum = [0x12, 0x34];
        assert_eq!(checksum(checksum), 0x1234);

        // Test urg_ptr function
        let urg_ptr: UrgPtr = [0x00, 0x00];
        assert_eq!(urg_ptr(urg_ptr), 0x0000);
    }

    #[test]
    fn test_public_off_res_flags_helper_functions() {
        // Test data_offset function
        let off_res_flags: OffResFlags = [0x50, 0x00]; // Data offset 5
        assert_eq!(data_offset(off_res_flags), 5);

        // Test header_len function
        let off_res_flags: OffResFlags = [0x50, 0x00]; // Data offset 5
        assert_eq!(header_len(off_res_flags), 20);

        // Test tcp_flags function
        let off_res_flags: OffResFlags = [0x50, 0x18]; // ACK+PSH flags
        assert_eq!(tcp_flags(off_res_flags), 0x18);
    }

    #[test]
    fn test_public_flag_helper_functions() {
        // Test FIN flag
        let off_res_flags: OffResFlags = [0x50, 0x01]; // FIN flag set
        assert_eq!(fin_flag(off_res_flags), true);

        let off_res_flags: OffResFlags = [0x50, 0x00]; // No flags set
        assert_eq!(fin_flag(off_res_flags), false);

        // Test SYN flag
        let off_res_flags: OffResFlags = [0x50, 0x02]; // SYN flag set
        assert_eq!(syn_flag(off_res_flags), true);

        let off_res_flags: OffResFlags = [0x50, 0x00]; // No flags set
        assert_eq!(syn_flag(off_res_flags), false);

        // Test RST flag
        let off_res_flags: OffResFlags = [0x50, 0x04]; // RST flag set
        assert_eq!(rst_flag(off_res_flags), true);

        let off_res_flags: OffResFlags = [0x50, 0x00]; // No flags set
        assert_eq!(rst_flag(off_res_flags), false);

        // Test PSH flag
        let off_res_flags: OffResFlags = [0x50, 0x08]; // PSH flag set
        assert_eq!(psh_flag(off_res_flags), true);

        let off_res_flags: OffResFlags = [0x50, 0x00]; // No flags set
        assert_eq!(psh_flag(off_res_flags), false);

        // Test ACK flag
        let off_res_flags: OffResFlags = [0x50, 0x10]; // ACK flag set
        assert_eq!(ack_flag(off_res_flags), true);

        let off_res_flags: OffResFlags = [0x50, 0x00]; // No flags set
        assert_eq!(ack_flag(off_res_flags), false);

        // Test URG flag
        let off_res_flags: OffResFlags = [0x50, 0x20]; // URG flag set
        assert_eq!(urg_flag(off_res_flags), true);

        let off_res_flags: OffResFlags = [0x50, 0x00]; // No flags set
        assert_eq!(urg_flag(off_res_flags), false);

        // Test ECE flag
        let off_res_flags: OffResFlags = [0x50, 0x40]; // ECE flag set
        assert_eq!(ece_flag(off_res_flags), true);

        let off_res_flags: OffResFlags = [0x50, 0x00]; // No flags set
        assert_eq!(ece_flag(off_res_flags), false);

        // Test CWR flag
        let off_res_flags: OffResFlags = [0x50, 0x80]; // CWR flag set
        assert_eq!(cwr_flag(off_res_flags), true);

        let off_res_flags: OffResFlags = [0x50, 0x00]; // No flags set
        assert_eq!(cwr_flag(off_res_flags), false);

        // Test multiple flags
        let off_res_flags: OffResFlags = [0x50, 0xFF]; // All flags set
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
    fn test_flag_masks_are_public() {
        // Test that flag masks are accessible
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
    fn test_public_functions_consistency_with_struct_methods() {
        // Test that public functions match struct methods
        let tcp_hdr = TcpHdr {
            src: [0x12, 0x34],
            dst: [0x56, 0x78],
            seq: [0x12, 0x34, 0x56, 0x78],
            ack_seq: [0x87, 0x65, 0x43, 0x21],
            off_res_flags: [0x50, 0x18], // Data offset 5, ACK+PSH flags
            window: [0x20, 0x00],
            check: [0x12, 0x34],
            urg_ptr: [0x00, 0x00],
        };

        // Test field consistency
        assert_eq!(src_port(tcp_hdr.src), tcp_hdr.src_port());
        assert_eq!(dst_port(tcp_hdr.dst), tcp_hdr.dst_port());
        assert_eq!(seq_num(tcp_hdr.seq), tcp_hdr.seq());
        assert_eq!(ack_seq(tcp_hdr.ack_seq), tcp_hdr.ack_seq());
        assert_eq!(window(tcp_hdr.window), tcp_hdr.window());
        assert_eq!(checksum(tcp_hdr.check), tcp_hdr.checksum());
        assert_eq!(urg_ptr(tcp_hdr.urg_ptr), tcp_hdr.urg_ptr());

        // Test off_res_flags consistency
        assert_eq!(data_offset(tcp_hdr.off_res_flags), tcp_hdr.data_offset());
        assert_eq!(header_len(tcp_hdr.off_res_flags), tcp_hdr.header_len());
        assert_eq!(tcp_flags(tcp_hdr.off_res_flags), tcp_hdr.tcp_flags());

        // Test flag consistency
        assert_eq!(fin_flag(tcp_hdr.off_res_flags), tcp_hdr.fin());
        assert_eq!(syn_flag(tcp_hdr.off_res_flags), tcp_hdr.syn());
        assert_eq!(rst_flag(tcp_hdr.off_res_flags), tcp_hdr.rst());
        assert_eq!(psh_flag(tcp_hdr.off_res_flags), tcp_hdr.psh());
        assert_eq!(ack_flag(tcp_hdr.off_res_flags), tcp_hdr.ack());
        assert_eq!(urg_flag(tcp_hdr.off_res_flags), tcp_hdr.urg());
        assert_eq!(ece_flag(tcp_hdr.off_res_flags), tcp_hdr.ece());
        assert_eq!(cwr_flag(tcp_hdr.off_res_flags), tcp_hdr.cwr());
    }
}
