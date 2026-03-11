//! Encapsulating Security Payload (ESP)
//!
//! 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ ----
//! |               Security Parameters Index (SPI)                 | ^Int.
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ |Cov-
//! |                      Sequence Number                          | |ered
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ | ----
//! |                    Payload Data* (variable)                   | |   ^
//! ~                                                               ~ |   |
//! |                                                               | |Conf.
//! ~               +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ |Cov-
//! |               |     Padding (0-255 bytes)                     | |ered*
//! +-+-+-+-+-+-+-+-+               +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ |   |
//! |                               |  Pad Length   | Next Header   | v   v
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ ------
//! |         Integrity Check Value-ICV   (variable)                |
//! ~                                                               ~
//! |                                                               |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

/// The length of the ESP header in bytes.
pub const ESP_LEN: usize = 8;

/// Security Parameters Index (SPI) (32 bits): An arbitrary value used to uniquely identify the **security association** of the receiving party.
pub type Spi = [u8; 4];
/// Sequence Number (32 bits): A monotonically increasing counter for protecting against **replay attacks**.
pub type SeqNum = [u8; 4];

/// Gets the Security Parameters Index (SPI) value.
#[inline]
pub fn spi(spi: Spi) -> u32 {
    u32::from_be_bytes(spi)
}

/// Gets the Sequence Number value.
#[inline]
pub fn seq_num(seq_num: SeqNum) -> u32 {
    u32::from_be_bytes(seq_num)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_esp_len_constant() {
        assert_eq!(ESP_LEN, 8); // spi (4 bytes) + seq_num (4 bytes)
    }

    #[test]
    fn test_esp_spi_and_seq_num_functions() {
        // Test SPI
        let spi_bytes: Spi = [0x12, 0x34, 0x56, 0x78];
        assert_eq!(spi(spi_bytes), 0x12345678);

        // Test Sequence Number
        let seq_num_bytes: SeqNum = [0x87, 0x65, 0x43, 0x21];
        assert_eq!(seq_num(seq_num_bytes), 0x87654321);
    }
}
