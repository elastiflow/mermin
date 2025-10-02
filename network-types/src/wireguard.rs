//! ## Message Type 1: Handshake Initiation
//!
//!  0                   1                   2                   3
//!  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//! |+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+|
//! |     Type=1    |                  Reserved=0                   |
//! |+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+|
//! |                        Sender Index (le32)                    |
//! |+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+|
//! |                                                               |
//! |                      Unencrypted Ephemeral                    |
//! |                          (32 bytes)                           |
//! |                                                               |
//! |                                                               |
//! |+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+|
//! |                                                               |
//! |                        Encrypted Static                       |
//! |                          (48 bytes)                           |
//! |                                                               |
//! |                                                               |
//! |+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+|
//! |                                                               |
//! |                      Encrypted Timestamp                      |
//! |                          (28 bytes)                           |
//! |+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+|
//! |                                                               |
//! |                             MAC 1                             |
//! |                          (16 bytes)                           |
//! |+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+|
//! |                                                               |
//! |                             MAC 2                             |
//! |                          (16 bytes)                           |
//! |+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+|
//!
//!
//! Fields
//!
//! - **Type (8 bits)**: Identifies the message type. Set to `1` for Handshake Initiation.
//! - **Reserved (24 bits)**: Must be all zeroes.
//! - **Sender Index (32 bits)**: A session identifier chosen by the initiator. The
//!   responder will use this index in its reply to identify the session.
//! - **Unencrypted Ephemeral (32 bytes)**: The initiator's ephemeral (single-use)
//!   Curve25519 public key.
//! - **Encrypted Static (48 bytes)**: The initiator's static (long-term) public key,
//!   encrypted with the responder's public key. Includes a 16-byte AEAD
//!   authentication tag.
//! - **Encrypted Timestamp (28 bytes)**: A high-resolution TAI64N timestamp,
//!   encrypted to prevent replay attacks. Includes a 16-byte AEAD authentication tag.
//! - **MAC 1 & MAC 2 (16 bytes each)**: Message Authentication Codes (BLAKE2s) to
//!   protect the header against tampering and provide some DoS resistance.
//!
//!
//! ## Message Type 2: Handshake Response
//!
//! The reply sent by the responder to complete the handshake. After this
//! message is successfully processed by the initiator, the tunnel is active
//! and ready for data transport.
//!
//!
//!  0                   1                   2                   3
//!  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//! |+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+|
//! |     Type=2    |                  Reserved=0                   |
//! |+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+|
//! |                        Sender Index (le32)                    |
//! |+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+|
//! |                       Receiver Index (le32)                   |
//! |+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+|
//! |                                                               |
//! |                      Unencrypted Ephemeral                    |
//! |                          (32 bytes)                           |
//! |                                                               |
//! |+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+|
//! |                                                               |
//! |                       Encrypted Nothing                       |
//! |                          (16 bytes)                           |
//! |+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+|
//! |                                                               |
//! |                             MAC 1                             |
//! |                          (16 bytes)                           |
//! |+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+|
//! |                                                               |
//! |                             MAC 2                             |
//! |                          (16 bytes)                           |
//! |+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+|
//!
//!
//! Fields
//!
//! - **Type (8 bits)**: Identifies the message type. Set to `2` for Handshake Response.
//! - **Reserved (24 bits)**: Must be all zeroes.
//! - **Sender Index (32 bits)**: A session identifier chosen by the responder.
//! - **Receiver Index (32 bits)**: The `Sender Index` from the initiation message,
//!   echoed back by the responder to the initiator.
//! - **Unencrypted Ephemeral (32 bytes)**: The responder's ephemeral Curve25519
//!   public key.
//! - **Encrypted Nothing (16 bytes)**: An empty payload that is encrypted and
//!   authenticated using the new session key. Its successful decryption confirms
//!   the key exchange. This field consists only of the 16-byte AEAD authentication tag.
//! - **MAC 1 & MAC 2 (16 bytes each)**: Message Authentication Codes.
//!
//! ## Message Type 3: Cookie Reply
//!
//! A message sent by a responder that is currently under load. It instructs the
//! initiator to retry its handshake with the included cookie, which proves
//! ownership of the source IP address and mitigates DoS attacks.
//!
//!  0                   1                   2                   3
//!  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//! |+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+|
//! |     Type=3    |                  Reserved=0                   |
//! |+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+|
//! |                      Receiver Index (le32)                    |
//! |+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+|
//! |                                                               |
//! |                                                               |
//! |                                                               |
//! |                           Nonce                               |
//! |                          (24 bytes)                           |
//! |                                                               |
//! |                                                               |
//! |                                                               |
//! |                                                               |
//! |+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+|
//! |                                                               |
//! |                                                               |
//! |                      Encrypted Cookie                         |
//! |                         (16 bytes)                            |
//! |                                                               |
//! |+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+|
//!
//! Fields
//!
//! - **Type (8 bits)**: Identifies the message type. Set to `3` for a Cookie Reply.
//! - **Reserved (24 bits)**: Must be all zeroes.
//! - **Receiver Index (32 bits)**: The `Sender Index` from the handshake initiation
//!   message that this reply is in response to, echoed back to the initiator.
//! - **Nonce (24 bytes)**: A random, single-use number provided by the responder.
//! - **Encrypted Cookie (16 bytes)**: A MAC of the initiator's source IP and port,
//!   encrypted with the nonce. The initiator must include this cookie in its
//!   next handshake initiation attempt.
//!
//! ## Message Type 4: Transport Data
//!
//! The most common packet, used to send actual data through an established
//! tunnel. Its header is extremely minimal for high performance.
//!
//!
//!  0                   1                   2                   3
//!  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//! |+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+|
//! |     Type=4    |                  Reserved=0                   |
//! |+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+|
//! |                       Receiver Index (le32)                   |
//! |+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+|
//! |                                                               |
//! |                         Counter (le64)                        |
//! |                                                               |
//! |+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+|
//! |                                                               |
//! .                                                               .
//! .                     Encrypted Packet Data                     .
//! .                                                               .
//! |                                                               |
//! |+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+|
//!
//!
//! Fields
//!
//! - **Type (8 bits)**: Identifies the message type. Set to `4` for Transport Data.
//! - **Reserved (24 bits)**: Must be all zeroes.
//! - **Receiver Index (32 bits)**: The session identifier that tells the receiver
//!   which key to use for decryption. This corresponds to a `Sender Index`
//!   exchanged during the handshake.
//! - **Counter (64 bits)**: A per-packet nonce that is encrypted along with the data.
//!   It protects against replay attacks and must be unique and ever-increasing
//!   for a given key.
//! - **Encrypted Packet Data (variable length)**: The original IP packet, encrypted
//!   with ChaCha20Poly1305. This payload includes a 16-byte authentication tag
//!   at the end, which is generated by the AEAD cipher.

/// Represents the message type field in a WireGuard packet header.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
#[repr(u8)]
pub enum WireGuardType {
    HandshakeInitiation = 1,
    HandshakeResponse = 2,
    CookieReply = 3,
    TransportData = 4,
    Unknown = 0, // Unknown should be 0
}

impl From<u8> for WireGuardType {
    /// Infallible conversion from a byte to a WireGuardType.
    ///
    /// This is suitable for eBPF programs where returning a `Result` or panicking
    /// is not an option. Unknown values are mapped to `WireGuardType::Unknown`.
    fn from(value: u8) -> Self {
        match value {
            1 => WireGuardType::HandshakeInitiation,
            2 => WireGuardType::HandshakeResponse,
            3 => WireGuardType::CookieReply,
            4 => WireGuardType::TransportData,
            0 => WireGuardType::Unknown,
            _ => WireGuardType::Unknown,
        }
    }
}

pub const WIREGUARD_INITIATION_LEN: usize = 148;
pub const WIREGUARD_RESPONSE_LEN: usize = 92;
pub const WIREGUARD_COOKIE_REPLY_LEN: usize = 48;
pub const WIREGUARD_TRANSPORT_DATA_LEN: usize = 16;

pub type WgType = u8;
pub type WgReserved = [u8; 3];
pub type WgSenderIdx = [u8; 4];
pub type WgReceiverIdx = [u8; 4];
pub type WgCounter = [u8; 8];
pub type WgEphemeral = [u8; 32];
pub type WgNonce = [u8; 24];
pub type WgEncryptedCookie = [u8; 16];
pub type WgEncryptedNothing = [u8; 16];
pub type WgEncryptedStatic = [u8; 48];
pub type WgEncryptedTimestamp = [u8; 28];
pub type WgMac1 = [u8; 16];
pub type WgMac2 = [u8; 16];

#[inline]
pub fn type_(type_: WgType) -> WireGuardType {
    WireGuardType::from(type_)
}

#[inline]
pub fn sender_idx(sender_idx: WgSenderIdx) -> u32 {
    u32::from_le_bytes(sender_idx)
}

#[inline]
pub fn receiver_idx(receiver_idx: WgReceiverIdx) -> u32 {
    u32::from_le_bytes(receiver_idx)
}

#[inline]
pub fn mac_1(mac_1: WgMac1) -> u128 {
    u128::from_le_bytes(mac_1)
}

#[inline]
pub fn mac_2(mac_2: WgMac2) -> u128 {
    u128::from_le_bytes(mac_2)
}

#[inline]
pub fn encrypted_nothing(encrypted_nothing: WgEncryptedNothing) -> u128 {
    u128::from_le_bytes(encrypted_nothing)
}

#[inline]
pub fn encrypted_cookie(encrypted_cookie: WgEncryptedCookie) -> u128 {
    u128::from_le_bytes(encrypted_cookie)
}

#[inline]
pub fn counter(counter: WgCounter) -> u64 {
    u64::from_le_bytes(counter)
}

#[cfg(test)]
mod tests {
    use core::mem;

    use super::*;

    #[test]
    fn test_wireguard_type_from_u8() {
        assert_eq!(WireGuardType::from(1), WireGuardType::HandshakeInitiation);
        assert_eq!(WireGuardType::from(2), WireGuardType::HandshakeResponse);
        assert_eq!(WireGuardType::from(3), WireGuardType::CookieReply);
        assert_eq!(WireGuardType::from(4), WireGuardType::TransportData);
        assert_eq!(WireGuardType::from(0), WireGuardType::Unknown);
        assert_eq!(WireGuardType::from(255), WireGuardType::Unknown);
    }

    #[test]
    fn test_wireguard_type_helper_function() {
        assert_eq!(type_(1), WireGuardType::HandshakeInitiation);
        assert_eq!(type_(2), WireGuardType::HandshakeResponse);
        assert_eq!(type_(3), WireGuardType::CookieReply);
        assert_eq!(type_(4), WireGuardType::TransportData);
        assert_eq!(type_(0), WireGuardType::Unknown);
        assert_eq!(type_(255), WireGuardType::Unknown);
    }

    #[test]
    fn test_wireguard_sender_idx_helper_function() {
        let sender_idx_bytes: WgSenderIdx = [0x78, 0x56, 0x34, 0x12];
        assert_eq!(sender_idx(sender_idx_bytes), 0x12345678);

        let zero_bytes: WgSenderIdx = [0x00, 0x00, 0x00, 0x00];
        assert_eq!(sender_idx(zero_bytes), 0);

        let max_bytes: WgSenderIdx = [0xFF, 0xFF, 0xFF, 0xFF];
        assert_eq!(sender_idx(max_bytes), u32::MAX);
    }

    #[test]
    fn test_wireguard_mac_helper_functions() {
        let mac_1_bytes: WgMac1 = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
        let expected_mac_1 = u128::from_le_bytes(mac_1_bytes);
        assert_eq!(mac_1(mac_1_bytes), expected_mac_1);

        let mac_2_bytes: WgMac2 = [16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1];
        let expected_mac_2 = u128::from_le_bytes(mac_2_bytes);
        assert_eq!(mac_2(mac_2_bytes), expected_mac_2);

        // Test with zero values
        let zero_mac: WgMac1 = [0; 16];
        assert_eq!(mac_1(zero_mac), 0);

        // Test with max values
        let max_mac: WgMac1 = [0xFF; 16];
        assert_eq!(mac_1(max_mac), u128::MAX);
    }

    #[test]
    fn test_wireguard_encrypted_nothing_helper_function() {
        let encrypted_bytes: WgEncryptedNothing = [
            0xFF, 0xEE, 0xDD, 0xCC, 0xBB, 0xAA, 0x99, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22,
            0x11, 0x00,
        ];
        let expected = u128::from_le_bytes(encrypted_bytes);
        assert_eq!(encrypted_nothing(encrypted_bytes), expected);

        // Test with zero values
        let zero_bytes: WgEncryptedNothing = [0; 16];
        assert_eq!(encrypted_nothing(zero_bytes), 0);

        // Test with max values
        let max_bytes: WgEncryptedNothing = [0xFF; 16];
        assert_eq!(encrypted_nothing(max_bytes), u128::MAX);
    }

    #[test]
    fn test_wireguard_encrypted_cookie_helper_function() {
        let cookie_bytes: WgEncryptedCookie = [
            0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66,
            0x77, 0x88,
        ];
        let expected = u128::from_le_bytes(cookie_bytes);
        assert_eq!(encrypted_cookie(cookie_bytes), expected);

        // Test with zero values
        let zero_bytes: WgEncryptedCookie = [0; 16];
        assert_eq!(encrypted_cookie(zero_bytes), 0);

        // Test with max values
        let max_bytes: WgEncryptedCookie = [0xFF; 16];
        assert_eq!(encrypted_cookie(max_bytes), u128::MAX);
    }

    #[test]
    fn test_wireguard_counter_helper_function() {
        let counter_bytes: WgCounter = [0xF0, 0xDE, 0xBC, 0x9A, 0x78, 0x56, 0x34, 0x12];
        let expected = u64::from_le_bytes(counter_bytes);
        assert_eq!(counter(counter_bytes), expected);

        // Test with zero values
        let zero_bytes: WgCounter = [0; 8];
        assert_eq!(counter(zero_bytes), 0);

        // Test with max values
        let max_bytes: WgCounter = [0xFF; 8];
        assert_eq!(counter(max_bytes), u64::MAX);
    }

    #[test]
    fn test_wireguard_constants() {
        // Verify the length constants are correct
        assert_eq!(WIREGUARD_INITIATION_LEN, 148); // 1 + 3 + 4 + 32 + 48 + 28 + 16 + 16
        assert_eq!(WIREGUARD_RESPONSE_LEN, 92); // 1 + 3 + 4 + 4 + 32 + 16 + 16 + 16
        assert_eq!(WIREGUARD_COOKIE_REPLY_LEN, 48); // 1 + 3 + 4 + 24 + 16
        assert_eq!(WIREGUARD_TRANSPORT_DATA_LEN, 16); // 1 + 3 + 4 + 8
    }

    #[test]
    fn test_wireguard_type_aliases() {
        // Test that type aliases have the correct sizes
        assert_eq!(mem::size_of::<WgType>(), 1);
        assert_eq!(mem::size_of::<WgReserved>(), 3);
        assert_eq!(mem::size_of::<WgSenderIdx>(), 4);
        assert_eq!(mem::size_of::<WgReceiverIdx>(), 4);
        assert_eq!(mem::size_of::<WgCounter>(), 8);
        assert_eq!(mem::size_of::<WgEphemeral>(), 32);
        assert_eq!(mem::size_of::<WgNonce>(), 24);
        assert_eq!(mem::size_of::<WgEncryptedCookie>(), 16);
        assert_eq!(mem::size_of::<WgEncryptedNothing>(), 16);
        assert_eq!(mem::size_of::<WgEncryptedStatic>(), 48);
        assert_eq!(mem::size_of::<WgEncryptedTimestamp>(), 28);
        assert_eq!(mem::size_of::<WgMac1>(), 16);
        assert_eq!(mem::size_of::<WgMac2>(), 16);
    }

    #[test]
    fn test_wireguard_little_endian_conversion() {
        // Test that all helper functions use little-endian conversion as specified
        let sender_idx_bytes: WgSenderIdx = [0x78, 0x56, 0x34, 0x12];
        assert_eq!(sender_idx(sender_idx_bytes), 0x12345678);

        let counter_bytes: WgCounter = [0xF0, 0xDE, 0xBC, 0x9A, 0x78, 0x56, 0x34, 0x12];
        assert_eq!(counter(counter_bytes), 0x123456789ABCDEF0);

        // Test MAC little-endian conversion
        let mac_bytes: WgMac1 = [
            0x10, 0x32, 0x54, 0x76, 0x98, 0xBA, 0xDC, 0xFE, 0x0F, 0xED, 0xCB, 0xA9, 0x87, 0x65,
            0x43, 0x21,
        ];
        let expected_mac = 0x21436587A9CBED0FFEDCBA9876543210;
        assert_eq!(mac_1(mac_bytes), expected_mac);
    }

    #[test]
    fn test_wireguard_edge_cases() {
        // Test with maximum values
        let max_sender_idx: WgSenderIdx = [0xFF, 0xFF, 0xFF, 0xFF];
        assert_eq!(sender_idx(max_sender_idx), u32::MAX);

        let max_counter: WgCounter = [0xFF; 8];
        assert_eq!(counter(max_counter), u64::MAX);

        let max_mac: WgMac1 = [0xFF; 16];
        assert_eq!(mac_1(max_mac), u128::MAX);

        // Test with zero values
        let zero_sender_idx: WgSenderIdx = [0; 4];
        assert_eq!(sender_idx(zero_sender_idx), 0);

        let zero_counter: WgCounter = [0; 8];
        assert_eq!(counter(zero_counter), 0);

        let zero_mac: WgMac1 = [0; 16];
        assert_eq!(mac_1(zero_mac), 0);
    }
}
