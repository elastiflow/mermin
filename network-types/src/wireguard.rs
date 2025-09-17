use core::mem;

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

/// # WireGuard On-the-Wire Packet Formats
///
/// This document outlines the packet formats for the WireGuard protocol as they
/// appear on the wire.
///
/// WireGuard uses three primary message types for its operation:
/// 1. **Handshake Initiation**: To begin a session with a peer.
/// 2. **Handshake Response**: To complete the session key exchange.
/// 3. **Transport Data**: For sending encrypted data through an established tunnel.
///
/// All multi-byte integer fields are encoded in **little-endian** format.
///
/// ---
///
/// ## Message Type 1: Handshake Initiation
///
/// The first message sent by an initiator to a responder to establish a
/// secure tunnel. It carries the necessary public information to perform a
/// Diffie-Hellman key exchange and authenticate the initiator.
///
///
///  0                   1                   2                   3
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// |+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+|
/// |     Type=1    |                  Reserved=0                   |
/// |+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+|
/// |                        Sender Index (le32)                    |
/// |+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+|
/// |                                                               |
/// |                      Unencrypted Ephemeral                    |
/// |                          (32 bytes)                           |
/// |                                                               |
/// |                                                               |
/// |+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+|
/// |                                                               |
/// |                        Encrypted Static                       |
/// |                          (48 bytes)                           |
/// |                                                               |
/// |                                                               |
/// |+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+|
/// |                                                               |
/// |                      Encrypted Timestamp                      |
/// |                          (28 bytes)                           |
/// |+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+|
/// |                                                               |
/// |                             MAC 1                             |
/// |                          (16 bytes)                           |
/// |+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+|
/// |                                                               |
/// |                             MAC 2                             |
/// |                          (16 bytes)                           |
/// |+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+|
///
///
/// Fields
///
/// - **Type (8 bits)**: Identifies the message type. Set to `1` for Handshake Initiation.
/// - **Reserved (24 bits)**: Must be all zeroes.
/// - **Sender Index (32 bits)**: A session identifier chosen by the initiator. The
///   responder will use this index in its reply to identify the session.
/// - **Unencrypted Ephemeral (32 bytes)**: The initiator's ephemeral (single-use)
///   Curve25519 public key.
/// - **Encrypted Static (48 bytes)**: The initiator's static (long-term) public key,
///   encrypted with the responder's public key. Includes a 16-byte AEAD
///   authentication tag.
/// - **Encrypted Timestamp (28 bytes)**: A high-resolution TAI64N timestamp,
///   encrypted to prevent replay attacks. Includes a 16-byte AEAD authentication tag.
/// - **MAC 1 & MAC 2 (16 bytes each)**: Message Authentication Codes (BLAKE2s) to
///   protect the header against tampering and provide some DoS resistance.
#[repr(C, packed)]
#[derive(Debug, Copy, Clone)]
pub struct WireGuardInitiation {
    pub type_: WireGuardType,
    pub reserved: [u8; 3],
    pub sender_ind: [u8; 4],
    pub ephemeral: [u8; 32],
    pub encrypted_static: [u8; 48],
    pub encrypted_timestamp: [u8; 28],
    pub mac_1: [u8; 16],
    pub mac_2: [u8; 16],
}

impl WireGuardInitiation {
    pub const LEN: usize = mem::size_of::<WireGuardInitiation>();

    #[inline]
    pub fn sender_ind(&self) -> u32 {
        u32::from_le_bytes(self.sender_ind)
    }

    #[inline]
    pub fn set_sender_ind(&mut self, sender_ind: u32) {
        self.sender_ind = sender_ind.to_le_bytes();
    }

    #[inline]
    pub fn mac_1(&self) -> u128 {
        u128::from_le_bytes(self.mac_1)
    }

    #[inline]
    pub fn set_mac_1(&mut self, mac_1: u128) {
        self.mac_1 = mac_1.to_le_bytes();
    }

    #[inline]
    pub fn mac_2(&self) -> u128 {
        u128::from_le_bytes(self.mac_2)
    }

    #[inline]
    pub fn set_mac_2(&mut self, mac_2: u128) {
        self.mac_2 = mac_2.to_le_bytes();
    }
}

///
/// ## Message Type 2: Handshake Response
///
/// The reply sent by the responder to complete the handshake. After this
/// message is successfully processed by the initiator, the tunnel is active
/// and ready for data transport.
///
///
///  0                   1                   2                   3
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// |+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+|
/// |     Type=2    |                  Reserved=0                   |
/// |+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+|
/// |                        Sender Index (le32)                    |
/// |+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+|
/// |                       Receiver Index (le32)                   |
/// |+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+|
/// |                                                               |
/// |                      Unencrypted Ephemeral                    |
/// |                          (32 bytes)                           |
/// |                                                               |
/// |+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+|
/// |                                                               |
/// |                       Encrypted Nothing                       |
/// |                          (16 bytes)                           |
/// |+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+|
/// |                                                               |
/// |                             MAC 1                             |
/// |                          (16 bytes)                           |
/// |+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+|
/// |                                                               |
/// |                             MAC 2                             |
/// |                          (16 bytes)                           |
/// |+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+|
///
///
/// Fields
///
/// - **Type (8 bits)**: Identifies the message type. Set to `2` for Handshake Response.
/// - **Reserved (24 bits)**: Must be all zeroes.
/// - **Sender Index (32 bits)**: A session identifier chosen by the responder.
/// - **Receiver Index (32 bits)**: The `Sender Index` from the initiation message,
///   echoed back by the responder to the initiator.
/// - **Unencrypted Ephemeral (32 bytes)**: The responder's ephemeral Curve25519
///   public key.
/// - **Encrypted Nothing (16 bytes)**: An empty payload that is encrypted and
///   authenticated using the new session key. Its successful decryption confirms
///   the key exchange. This field consists only of the 16-byte AEAD authentication tag.
/// - **MAC 1 & MAC 2 (16 bytes each)**: Message Authentication Codes.
///
#[repr(C, packed)]
#[derive(Debug, Copy, Clone)]
pub struct WireGuardResponse {
    pub type_: WireGuardType,
    pub reserved: [u8; 3],
    pub sender_ind: [u8; 4],
    pub receiver_ind: [u8; 4],
    pub ephemeral: [u8; 32],
    pub encrypted_nothing: [u8; 16],
    pub mac_1: [u8; 16],
    pub mac_2: [u8; 16],
}

impl WireGuardResponse {
    pub const LEN: usize = mem::size_of::<WireGuardResponse>();

    #[inline]
    pub fn sender_ind(&self) -> u32 {
        u32::from_le_bytes(self.sender_ind)
    }

    #[inline]
    pub fn set_sender_ind(&mut self, sender_ind: u32) {
        self.sender_ind = sender_ind.to_le_bytes();
    }

    #[inline]
    pub fn receiver_ind(&self) -> u32 {
        u32::from_le_bytes(self.receiver_ind)
    }

    #[inline]
    pub fn set_receiver_ind(&mut self, receiver_ind: u32) {
        self.receiver_ind = receiver_ind.to_le_bytes();
    }

    #[inline]
    pub fn encrypted_nothing(&self) -> u128 {
        u128::from_le_bytes(self.encrypted_nothing)
    }

    #[inline]
    pub fn set_encrypted_nothing(&mut self, encrypted_nothing: u128) {
        self.encrypted_nothing = encrypted_nothing.to_le_bytes();
    }

    #[inline]
    pub fn mac_1(&self) -> u128 {
        u128::from_le_bytes(self.mac_1)
    }

    #[inline]
    pub fn set_mac_1(&mut self, mac_1: u128) {
        self.mac_1 = mac_1.to_le_bytes();
    }

    #[inline]
    pub fn mac_2(&self) -> u128 {
        u128::from_le_bytes(self.mac_2)
    }

    #[inline]
    pub fn set_mac_2(&mut self, mac_2: u128) {
        self.mac_2 = mac_2.to_le_bytes();
    }
}

/// ## Message Type 3: Cookie Reply
///
/// A message sent by a responder that is currently under load. It instructs the
/// initiator to retry its handshake with the included cookie, which proves
/// ownership of the source IP address and mitigates DoS attacks.
///
///  0                   1                   2                   3
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// |+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+|
/// |     Type=3    |                  Reserved=0                   |
/// |+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+|
/// |                      Receiver Index (le32)                    |
/// |+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+|
/// |                                                               |
/// |                                                               |
/// |                                                               |
/// |                           Nonce                               |
/// |                          (24 bytes)                           |
/// |                                                               |
/// |                                                               |
/// |                                                               |
/// |                                                               |
/// |+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+|
/// |                                                               |
/// |                                                               |
/// |                      Encrypted Cookie                         |
/// |                         (16 bytes)                            |
/// |                                                               |
/// |+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+|
///
/// Fields
///
/// - **Type (8 bits)**: Identifies the message type. Set to `3` for a Cookie Reply.
/// - **Reserved (24 bits)**: Must be all zeroes.
/// - **Receiver Index (32 bits)**: The `Sender Index` from the handshake initiation
///   message that this reply is in response to, echoed back to the initiator.
/// - **Nonce (24 bytes)**: A random, single-use number provided by the responder.
/// - **Encrypted Cookie (16 bytes)**: A MAC of the initiator's source IP and port,
///   encrypted with the nonce. The initiator must include this cookie in its
///   next handshake initiation attempt.
///
#[repr(C, packed)]
#[derive(Debug, Copy, Clone)]
pub struct WireGuardCookieReply {
    pub type_: WireGuardType,
    pub reserved: [u8; 3],
    pub receiver_ind: [u8; 4],
    pub nonce: [u8; 24],
    pub encrypted_cookie: [u8; 16],
}

impl WireGuardCookieReply {
    pub const LEN: usize = mem::size_of::<WireGuardCookieReply>();

    #[inline]
    pub fn receiver_ind(&self) -> u32 {
        u32::from_le_bytes(self.receiver_ind)
    }

    #[inline]
    pub fn set_receiver_ind(&mut self, receiver_ind: u32) {
        self.receiver_ind = receiver_ind.to_le_bytes();
    }

    #[inline]
    pub fn encrypted_cookie(&self) -> u128 {
        u128::from_le_bytes(self.encrypted_cookie)
    }

    #[inline]
    pub fn set_encrypted_cookie(&mut self, encrypted_cookie: u128) {
        self.encrypted_cookie = encrypted_cookie.to_le_bytes();
    }
}

///
/// ## Message Type 4: Transport Data
///
/// The most common packet, used to send actual data through an established
/// tunnel. Its header is extremely minimal for high performance.
///
///
///  0                   1                   2                   3
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// |+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+|
/// |     Type=4    |                  Reserved=0                   |
/// |+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+|
/// |                       Receiver Index (le32)                   |
/// |+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+|
/// |                                                               |
/// |                         Counter (le64)                        |
/// |                                                               |
/// |+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+|
/// |                                                               |
/// .                                                               .
/// .                     Encrypted Packet Data                     .
/// .                                                               .
/// |                                                               |
/// |+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+|
///
///
/// Fields
///
/// - **Type (8 bits)**: Identifies the message type. Set to `4` for Transport Data.
/// - **Reserved (24 bits)**: Must be all zeroes.
/// - **Receiver Index (32 bits)**: The session identifier that tells the receiver
///   which key to use for decryption. This corresponds to a `Sender Index`
///   exchanged during the handshake.
/// - **Counter (64 bits)**: A per-packet nonce that is encrypted along with the data.
///   It protects against replay attacks and must be unique and ever-increasing
///   for a given key.
/// - **Encrypted Packet Data (variable length)**: The original IP packet, encrypted
///   with ChaCha20Poly1305. This payload includes a 16-byte authentication tag
///   at the end, which is generated by the AEAD cipher.
#[repr(C, packed)]
#[derive(Debug, Copy, Clone)]
pub struct WireGuardTransportData {
    pub type_: WireGuardType,
    pub reserved: [u8; 3],
    pub receiver_ind: [u8; 4],
    pub counter: [u8; 8],
}

impl WireGuardTransportData {
    pub const LEN: usize = mem::size_of::<WireGuardTransportData>();

    #[inline]
    pub fn receiver_ind(&self) -> u32 {
        u32::from_le_bytes(self.receiver_ind)
    }

    #[inline]
    pub fn set_receiver_ind(&mut self, receiver_ind: u32) {
        self.receiver_ind = receiver_ind.to_le_bytes();
    }

    #[inline]
    pub fn counter(&self) -> u64 {
        u64::from_le_bytes(self.counter)
    }

    #[inline]
    pub fn set_counter(&mut self, counter: u64) {
        self.counter = counter.to_le_bytes();
    }
}

#[cfg(test)]
mod tests {
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
    fn test_wireguard_initiation_len_constant() {
        assert_eq!(WireGuardInitiation::LEN, 148); // 1 + 3 + 4 + 32 + 48 + 28 + 16 + 16
        assert_eq!(
            WireGuardInitiation::LEN,
            mem::size_of::<WireGuardInitiation>()
        );
    }

    #[test]
    fn test_wireguard_initiation_getters_setters() {
        let mut initiation = WireGuardInitiation {
            type_: WireGuardType::HandshakeInitiation,
            reserved: [0; 3],
            sender_ind: [0; 4],
            ephemeral: [0; 32],
            encrypted_static: [0; 48],
            encrypted_timestamp: [0; 28],
            mac_1: [0; 16],
            mac_2: [0; 16],
        };

        // Test sender_ind field
        initiation.set_sender_ind(0x12345678);
        assert_eq!(initiation.sender_ind(), 0x12345678);
        assert_eq!(initiation.sender_ind, [0x78, 0x56, 0x34, 0x12]);

        // Test mac_1 field
        let test_mac_1 = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
        initiation.set_mac_1(u128::from_le_bytes(test_mac_1));
        assert_eq!(initiation.mac_1(), u128::from_le_bytes(test_mac_1));
        assert_eq!(initiation.mac_1, test_mac_1);

        // Test mac_2 field
        let test_mac_2 = [16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1];
        initiation.set_mac_2(u128::from_le_bytes(test_mac_2));
        assert_eq!(initiation.mac_2(), u128::from_le_bytes(test_mac_2));
        assert_eq!(initiation.mac_2, test_mac_2);
    }

    #[test]
    fn test_wireguard_response_len_constant() {
        assert_eq!(WireGuardResponse::LEN, 92); // 1 + 3 + 4 + 4 + 32 + 16 + 16 + 16
        assert_eq!(WireGuardResponse::LEN, mem::size_of::<WireGuardResponse>());
    }

    #[test]
    fn test_wireguard_response_getters_setters() {
        let mut response = WireGuardResponse {
            type_: WireGuardType::HandshakeResponse,
            reserved: [0; 3],
            sender_ind: [0; 4],
            receiver_ind: [0; 4],
            ephemeral: [0; 32],
            encrypted_nothing: [0; 16],
            mac_1: [0; 16],
            mac_2: [0; 16],
        };

        // Test sender_ind field
        response.set_sender_ind(0x87654321);
        assert_eq!(response.sender_ind(), 0x87654321);
        assert_eq!(response.sender_ind, [0x21, 0x43, 0x65, 0x87]);

        // Test receiver_ind field
        response.set_receiver_ind(0x11223344);
        assert_eq!(response.receiver_ind(), 0x11223344);
        assert_eq!(response.receiver_ind, [0x44, 0x33, 0x22, 0x11]);

        // Test encrypted_nothing field
        let test_encrypted = [
            0xFF, 0xEE, 0xDD, 0xCC, 0xBB, 0xAA, 0x99, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22,
            0x11, 0x00,
        ];
        response.set_encrypted_nothing(u128::from_le_bytes(test_encrypted));
        assert_eq!(
            response.encrypted_nothing(),
            u128::from_le_bytes(test_encrypted)
        );
        assert_eq!(response.encrypted_nothing, test_encrypted);

        // Test mac_1 field
        let test_mac_1 = [
            0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
            0x88, 0x99,
        ];
        response.set_mac_1(u128::from_le_bytes(test_mac_1));
        assert_eq!(response.mac_1(), u128::from_le_bytes(test_mac_1));
        assert_eq!(response.mac_1, test_mac_1);

        // Test mac_2 field
        let test_mac_2 = [
            0x99, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00, 0xFF, 0xEE, 0xDD, 0xCC,
            0xBB, 0xAA,
        ];
        response.set_mac_2(u128::from_le_bytes(test_mac_2));
        assert_eq!(response.mac_2(), u128::from_le_bytes(test_mac_2));
        assert_eq!(response.mac_2, test_mac_2);
    }

    #[test]
    fn test_wireguard_cookie_reply_len_constant() {
        assert_eq!(WireGuardCookieReply::LEN, 48); // 1 + 3 + 4 + 24 + 16
        assert_eq!(
            WireGuardCookieReply::LEN,
            mem::size_of::<WireGuardCookieReply>()
        );
    }

    #[test]
    fn test_wireguard_cookie_reply_getters_setters() {
        let mut cookie_reply = WireGuardCookieReply {
            type_: WireGuardType::CookieReply,
            reserved: [0; 3],
            receiver_ind: [0; 4],
            nonce: [0; 24],
            encrypted_cookie: [0; 16],
        };

        // Test receiver_ind field
        cookie_reply.set_receiver_ind(0xDEADBEEF);
        assert_eq!(cookie_reply.receiver_ind(), 0xDEADBEEF);
        assert_eq!(cookie_reply.receiver_ind, [0xEF, 0xBE, 0xAD, 0xDE]);

        // Test encrypted_cookie field
        let test_cookie = [
            0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66,
            0x77, 0x88,
        ];
        cookie_reply.set_encrypted_cookie(u128::from_le_bytes(test_cookie));
        assert_eq!(
            cookie_reply.encrypted_cookie(),
            u128::from_le_bytes(test_cookie)
        );
        assert_eq!(cookie_reply.encrypted_cookie, test_cookie);
    }

    #[test]
    fn test_wireguard_transport_data_len_constant() {
        assert_eq!(WireGuardTransportData::LEN, 16); // 1 + 3 + 4 + 8
        assert_eq!(
            WireGuardTransportData::LEN,
            mem::size_of::<WireGuardTransportData>()
        );
    }

    #[test]
    fn test_wireguard_transport_data_getters_setters() {
        let mut transport_data = WireGuardTransportData {
            type_: WireGuardType::TransportData,
            reserved: [0; 3],
            receiver_ind: [0; 4],
            counter: [0; 8],
        };

        // Test receiver_ind field
        transport_data.set_receiver_ind(0xCAFEBABE);
        assert_eq!(transport_data.receiver_ind(), 0xCAFEBABE);
        assert_eq!(transport_data.receiver_ind, [0xBE, 0xBA, 0xFE, 0xCA]);

        // Test counter field
        transport_data.set_counter(0x123456789ABCDEF0);
        assert_eq!(transport_data.counter(), 0x123456789ABCDEF0);
        assert_eq!(
            transport_data.counter,
            [0xF0, 0xDE, 0xBC, 0x9A, 0x78, 0x56, 0x34, 0x12]
        );
    }

    #[test]
    fn test_wireguard_struct_sizes() {
        // Verify that all structs have the expected sizes based on their fields
        assert_eq!(mem::size_of::<WireGuardInitiation>(), 148);
        assert_eq!(mem::size_of::<WireGuardResponse>(), 92);
        assert_eq!(mem::size_of::<WireGuardCookieReply>(), 48);
        assert_eq!(mem::size_of::<WireGuardTransportData>(), 16);
    }

    #[test]
    fn test_wireguard_little_endian_conversion() {
        // Test that all multi-byte fields use little-endian conversion as specified
        let mut initiation = WireGuardInitiation {
            type_: WireGuardType::HandshakeInitiation,
            reserved: [0; 3],
            sender_ind: [0; 4],
            ephemeral: [0; 32],
            encrypted_static: [0; 48],
            encrypted_timestamp: [0; 28],
            mac_1: [0; 16],
            mac_2: [0; 16],
        };

        // Test sender_ind little-endian conversion
        initiation.set_sender_ind(0x12345678);
        assert_eq!(initiation.sender_ind, [0x78, 0x56, 0x34, 0x12]); // Little-endian byte order
        assert_eq!(initiation.sender_ind(), 0x12345678);

        // Test MAC little-endian conversion
        let mac_value = 0x123456789ABCDEF0FEDCBA9876543210;
        initiation.set_mac_1(mac_value);
        assert_eq!(initiation.mac_1(), mac_value);
        // Verify the bytes are in little-endian order
        assert_eq!(initiation.mac_1[0], 0x10);
        assert_eq!(initiation.mac_1[15], 0x12);
    }

    #[test]
    fn test_wireguard_edge_cases() {
        // Test with maximum values
        let mut initiation = WireGuardInitiation {
            type_: WireGuardType::HandshakeInitiation,
            reserved: [0; 3],
            sender_ind: [0; 4],
            ephemeral: [0; 32],
            encrypted_static: [0; 48],
            encrypted_timestamp: [0; 28],
            mac_1: [0; 16],
            mac_2: [0; 16],
        };

        // Test maximum u32 value
        initiation.set_sender_ind(u32::MAX);
        assert_eq!(initiation.sender_ind(), u32::MAX);
        assert_eq!(initiation.sender_ind, [0xFF, 0xFF, 0xFF, 0xFF]);

        // Test maximum u128 value for MAC
        let max_mac = u128::MAX;
        initiation.set_mac_1(max_mac);
        assert_eq!(initiation.mac_1(), max_mac);
        assert_eq!(initiation.mac_1, [0xFF; 16]);

        // Test zero values
        initiation.set_sender_ind(0);
        assert_eq!(initiation.sender_ind(), 0);
        assert_eq!(initiation.sender_ind, [0; 4]);

        initiation.set_mac_1(0);
        assert_eq!(initiation.mac_1(), 0);
        assert_eq!(initiation.mac_1, [0; 16]);
    }

    #[test]
    fn test_wireguard_transport_data_edge_cases() {
        let mut transport_data = WireGuardTransportData {
            type_: WireGuardType::TransportData,
            reserved: [0; 3],
            receiver_ind: [0; 4],
            counter: [0; 8],
        };

        // Test maximum u32 value for receiver_ind
        transport_data.set_receiver_ind(u32::MAX);
        assert_eq!(transport_data.receiver_ind(), u32::MAX);
        assert_eq!(transport_data.receiver_ind, [0xFF, 0xFF, 0xFF, 0xFF]);

        // Test maximum u64 value for counter
        transport_data.set_counter(u64::MAX);
        assert_eq!(transport_data.counter(), u64::MAX);
        assert_eq!(transport_data.counter, [0xFF; 8]);

        // Test zero values
        transport_data.set_receiver_ind(0);
        transport_data.set_counter(0);
        assert_eq!(transport_data.receiver_ind(), 0);
        assert_eq!(transport_data.counter(), 0);
        assert_eq!(transport_data.receiver_ind, [0; 4]);
        assert_eq!(transport_data.counter, [0; 8]);
    }
}
