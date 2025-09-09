use core::mem;

use crate::ip::IpProto;
/// Represents the Host Identity Protocol (HIP) version 2 header.
///
/// HIP is used to separate the identifier and locator roles of IP addresses.
/// The HIP header is defined in RFC 7401.
///
/// Format
///
///  0                   1                   2                   3
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// | Next Header   | Header Length |0| Packet Type |Version| RES.|1|
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |           Checksum            |           Controls            |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                                                               |
/// |             Sender's Host Identity Tag (HIT)                  |
/// |                                                               |
/// |                                                               |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                                                               |
/// |           Receiver's Host Identity Tag (HIT)                  |
/// |                                                               |
/// |                                                               |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                                                               |
/// /                          HIP Parameters                         /
/// /                                                               /
/// |                                                               |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///
///
/// Fields
///
/// * **Next Header (8 bits)**: Identifies the type of header immediately following this one.
/// * **Header Length (8 bits)**: The length of the HIP header and parameters in 8-octet units, excluding the first 8 octets.
/// * **Packet Type (7 bits)**: Indicates the specific type of HIP packet (e.g., I1, R1, I2, R2).
/// * **Version (4 bits)**: The protocol version, which is 2 for this specification.
/// * **Checksum (16 bits)**: A checksum computed over the HIP header, parameters, and a pseudo-header.
/// * **Controls (16 bits)**: Contains flags that govern the processing of the HIP packet.
/// * **Sender's Host Identity Tag (HIT) (128 bits)**: The HIT of the packet's sender.
/// * **Receiver's Host Identity Tag (HIT) (128 bits)**: The HIT of the packet's intended receiver.
/// * **HIP Parameters (variable)**: A variable-length field for additional data, such as cryptographic material.
#[repr(C, packed)]
#[derive(Debug, Copy, Clone)]
pub struct HipHdr {
    /// Next Header field (8 bits)
    pub next_hdr: IpProto,
    /// Header Length field (8 bits)
    pub hdr_len: u8,
    /// Fixed bit (1 bit) + Packet Type (7 bits)
    pub packet_type_field: u8,
    /// Version (4 bits) + Reserved (3 bits) + Fixed bit (1 bit)
    pub version_field: u8,
    /// Checksum field (16 bits)
    pub checksum: [u8; 2],
    /// Controls field (16 bits)
    pub controls: [u8; 2],
    /// Sender's Host Identity Tag (HIT) (16 bytes)
    pub sender_hit: [u8; 16],
    /// Receiver's Host Identity Tag (HIT) (16 bytes)
    pub receiver_hit: [u8; 16],
}

impl HipHdr {
    /// The size of the fixed part of the HIP Header in bytes.
    pub const LEN: usize = mem::size_of::<HipHdr>();

    /// Gets the Next Header value.
    #[inline]
    pub fn next_hdr(&self) -> IpProto {
        self.next_hdr
    }

    /// Sets the Next Header value.
    #[inline]
    pub fn set_next_hdr(&mut self, next_hdr: IpProto) {
        self.next_hdr = next_hdr;
    }

    /// Gets the Header Length value. This is the length of the HIP header
    /// in 8-octet units, not including the first 8 octets.
    #[inline]
    pub fn hdr_len(&self) -> u8 {
        self.hdr_len
    }

    /// Sets the Header Length value.
    #[inline]
    pub fn set_hdr_len(&mut self, hdr_len: u8) {
        self.hdr_len = hdr_len;
    }

    /// Gets the Packet Type value (7 bits).
    #[inline]
    pub fn packet_type(&self) -> u8 {
        self.packet_type_field & 0x7F
    }

    /// Sets the Packet Type value (7 bits). The top bit is preserved.
    #[inline]
    pub fn set_packet_type(&mut self, packet_type: u8) {
        self.packet_type_field = (self.packet_type_field & 0x80) | (packet_type & 0x7F);
    }

    /// Gets the Version value (4 bits).
    #[inline]
    pub fn version(&self) -> u8 {
        self.version_field >> 4
    }

    /// Sets the Version value (4 bits). The lower 4 bits are preserved.
    #[inline]
    pub fn set_version(&mut self, version: u8) {
        self.version_field = (version << 4) | (self.version_field & 0x0F);
    }

    /// Gets the Checksum as a 16-bit value.
    #[inline]
    pub fn checksum(&self) -> u16 {
        u16::from_be_bytes(self.checksum)
    }

    /// Sets the Checksum from a 16-bit value.
    #[inline]
    pub fn set_checksum(&mut self, checksum: u16) {
        self.checksum = checksum.to_be_bytes();
    }

    /// Gets the Controls as a 16-bit value.
    #[inline]
    pub fn controls(&self) -> u16 {
        u16::from_be_bytes(self.controls)
    }

    /// Sets the Controls from a 16-bit value.
    #[inline]
    pub fn set_controls(&mut self, controls: u16) {
        self.controls = controls.to_be_bytes();
    }

    /// Gets the Sender's HIT as a 128-bit value.
    #[inline]
    pub fn sender_hit(&self) -> u128 {
        u128::from_be_bytes(self.sender_hit)
    }

    /// Sets the Sender's HIT from a 128-bit value.
    #[inline]
    pub fn set_sender_hit(&mut self, hit: u128) {
        self.sender_hit = hit.to_be_bytes();
    }

    /// Gets the Receiver's HIT as a 128-bit value.
    #[inline]
    pub fn receiver_hit(&self) -> u128 {
        u128::from_be_bytes(self.receiver_hit)
    }

    /// Sets the Receiver's HIT from a 128-bit value.
    #[inline]
    pub fn set_receiver_hit(&mut self, hit: u128) {
        self.receiver_hit = hit.to_be_bytes();
    }

    /// Calculates the total length of the HIP header in bytes.
    /// Total length = (hdr_len + 1) * 8.
    #[inline]
    pub fn total_hdr_len(&self) -> usize {
        (self.hdr_len as usize + 1) << 3
    }

    /// Calculates the length of the HIP parameters in bytes.
    #[inline]
    pub fn params_len(&self) -> usize {
        self.total_hdr_len().saturating_sub(Self::LEN)
    }
}

#[cfg(test)]
mod tests {
    use core::mem;

    use super::*;

    #[test]
    fn test_hiphdr_size() {
        assert_eq!(HipHdr::LEN, 40);
        assert_eq!(HipHdr::LEN, mem::size_of::<HipHdr>());
    }

    #[test]
    fn test_hiphdr_getters_and_setters() {
        let mut hip_hdr = HipHdr {
            next_hdr: IpProto::Ipv6NoNxt,
            hdr_len: 0,
            packet_type_field: 0,
            version_field: 0,
            checksum: [0; 2],
            controls: [0; 2],
            sender_hit: [0; 16],
            receiver_hit: [0; 16],
        };

        // Test next_hdr
        hip_hdr.set_next_hdr(IpProto::Tcp);
        assert_eq!(hip_hdr.next_hdr(), IpProto::Tcp);

        // Test hdr_len
        hip_hdr.set_hdr_len(5);
        assert_eq!(hip_hdr.hdr_len(), 5);

        // Test packet_type
        hip_hdr.set_packet_type(4); // R2 packet
        assert_eq!(hip_hdr.packet_type(), 4);

        // Test version
        hip_hdr.set_version(2);
        assert_eq!(hip_hdr.version(), 2);
        assert_eq!(hip_hdr.version_field & 0xF0, 0x20);

        // Test checksum
        hip_hdr.set_checksum(0x1234);
        assert_eq!(hip_hdr.checksum(), 0x1234);
        assert_eq!(hip_hdr.checksum, [0x12, 0x34]);

        // Test controls
        hip_hdr.set_controls(0xABCD);
        assert_eq!(hip_hdr.controls(), 0xABCD);
        assert_eq!(hip_hdr.controls, [0xAB, 0xCD]);

        // Test sender_hit
        let sender_hit_val: u128 = 0x0123_4567_89AB_CDEF_FEDC_BA98_7654_3210;
        hip_hdr.set_sender_hit(sender_hit_val);
        assert_eq!(hip_hdr.sender_hit(), sender_hit_val);
        assert_eq!(hip_hdr.sender_hit, sender_hit_val.to_be_bytes());

        // Test receiver_hit
        let receiver_hit_val: u128 = 0x1122_3344_5566_7788_8877_6655_4433_2211;
        hip_hdr.set_receiver_hit(receiver_hit_val);
        assert_eq!(hip_hdr.receiver_hit(), receiver_hit_val);
        assert_eq!(hip_hdr.receiver_hit, receiver_hit_val.to_be_bytes());
    }

    #[test]
    fn test_hiphdr_length_calculation() {
        let mut hip_hdr = HipHdr {
            next_hdr: IpProto::Ipv6NoNxt,
            hdr_len: 0,
            packet_type_field: 0,
            version_field: 0,
            checksum: [0; 2],
            controls: [0; 2],
            sender_hit: [0; 16],
            receiver_hit: [0; 16],
        };

        // If total length is 40 (base header), hdr_len = (40/8)-1 = 4.
        hip_hdr.set_hdr_len(4);
        assert_eq!(hip_hdr.total_hdr_len(), 40);
        assert_eq!(hip_hdr.params_len(), 0);

        // Test with hdr_len = 5 (one 8-octet parameter)
        hip_hdr.set_hdr_len(5);
        assert_eq!(hip_hdr.total_hdr_len(), 48);
        assert_eq!(hip_hdr.params_len(), 8);

        // Test with hdr_len = 255 (max value)
        hip_hdr.set_hdr_len(255);
        assert_eq!(hip_hdr.total_hdr_len(), (255 + 1) * 8);
        assert_eq!(hip_hdr.params_len(), (255 + 1) * 8 - HipHdr::LEN);
    }
}
