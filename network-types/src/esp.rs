use core::mem;
/// # Encapsulating Security Payload (ESP)
///
/// 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ ----
/// |               Security Parameters Index (SPI)                 | ^Int.
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ |Cov-
/// |                      Sequence Number                          | |ered
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ | ----
/// |                    Payload Data* (variable)                   | |   ^
/// ~                                                               ~ |   |
/// |                                                               | |Conf.
/// ~               +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ |Cov-
/// |               |     Padding (0-255 bytes)                     | |ered*
/// +-+-+-+-+-+-+-+-+               +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ |   |
/// |                               |  Pad Length   | Next Header   | v   v
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ ------
/// |         Integrity Check Value-ICV   (variable)                |
/// ~                                                               ~
/// |                                                               |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ## Fields
///
/// * **Security Parameters Index (SPI) (32 bits)**: An arbitrary value used to uniquely identify the **security association** of the receiving party.
/// * **Sequence Number (32 bits)**: A monotonically increasing counter for protecting against **replay attacks**.
#[repr(C, packed)]
#[derive(Debug, Copy, Clone)]
pub struct Esp {
    pub spi: [u8; 4],
    pub seq_num: [u8; 4],
}

impl Esp {
    /// The total size in bytes of the ESP header
    pub const LEN: usize = mem::size_of::<Esp>();

    /// Gets the Security Parameters Index (SPI) value.
    #[inline]
    pub fn spi(&self) -> u32 {
        u32::from_be_bytes(self.spi)
    }

    /// Sets the Security Parameters Index (SPI) value.
    #[inline]
    pub fn set_spi(&mut self, spi: u32) {
        self.spi = spi.to_be_bytes();
    }

    /// Gets the Sequence Number value.
    #[inline]
    pub fn seq_num(&self) -> u32 {
        u32::from_be_bytes(self.seq_num)
    }

    /// Sets the Sequence Number value.
    #[inline]
    pub fn set_seq_num(&mut self, seq_num: u32) {
        self.seq_num = seq_num.to_be_bytes();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_esp_len_constant() {
        assert_eq!(Esp::LEN, 8); // spi (4 bytes) + seq_num (4 bytes)
        assert_eq!(Esp::LEN, mem::size_of::<Esp>());
    }

    #[test]
    fn test_esp_getters_setters() {
        let mut header = Esp {
            spi: [0; 4],
            seq_num: [0; 4],
        };

        // Test SPI
        header.set_spi(0x12345678);
        assert_eq!(header.spi(), 0x12345678);
        assert_eq!(header.spi, [0x12, 0x34, 0x56, 0x78]);

        // Test Sequence Number
        header.set_seq_num(0x87654321);
        assert_eq!(header.seq_num(), 0x87654321);
        assert_eq!(header.seq_num, [0x87, 0x65, 0x43, 0x21]);
    }
}
