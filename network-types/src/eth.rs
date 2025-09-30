/// Ethernet header structure that appears at the beginning of every Ethernet frame.
///
/// This structure represents the standard IEEE 802.3 Ethernet header format.
///  0                   1                   2                   3
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
///  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///  |                     destination_mac_addr                      |
///  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///  | destination_mac_addr (con't)  |        source_mac_addr        |
///  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///  |                    source_mac_addr (con't)                    |
///  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
///  |           eth_type            |
///  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

/// The length of the Ethernet header.
pub const ETH_LEN: usize = 14;

/// Destination MAC address.
pub type DstMacAddr = [u8; 6];

/// Source MAC address.
pub type SrcMacAddr = [u8; 6];

/// Protocol which is encapsulated in the payload of the Ethernet frame.
/// These values represent the standard IEEE assigned protocol numbers
#[repr(u16)]
#[derive(PartialEq, Eq, Debug, Copy, Clone, Default)]
pub enum EtherType {
    Loop = 0x0060_u16.to_be(),
    #[default]
    Ipv4 = 0x0800_u16.to_be(),
    Arp = 0x0806_u16.to_be(),
    Ethernet = 0x6558_u16.to_be(),
    Ieee8021q = 0x8100_u16.to_be(),
    Ipv6 = 0x86DD_u16.to_be(),
    Ieee8021ad = 0x88A8_u16.to_be(),
    Ieee8021MacSec = 0x88E5_u16.to_be(),
    Ieee8021ah = 0x88E7_u16.to_be(),
    Ieee8021mvrp = 0x88F5_u16.to_be(),
    FibreChannel = 0x8906_u16.to_be(),
    Infiniband = 0x8915_u16.to_be(),
    LoopbackIeee8023 = 0x9000_u16.to_be(),
    Ieee8021QinQ1 = 0x9100_u16.to_be(),
    Ieee8021QinQ2 = 0x9200_u16.to_be(),
    Ieee8021QinQ3 = 0x9300_u16.to_be(),
}

// This allows converting a u16 value into an EtherType enum variant.
// This is useful when parsing headers.
impl TryFrom<u16> for EtherType {
    type Error = u16; // Return the unknown value itself as the error

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value.to_be() {
            0x0060_u16 => Ok(EtherType::Loop),
            0x0800_u16 => Ok(EtherType::Ipv4),
            0x0806_u16 => Ok(EtherType::Arp),
            0x6558_u16 => Ok(EtherType::Ethernet),
            0x8100_u16 => Ok(EtherType::Ieee8021q),
            0x86DD_u16 => Ok(EtherType::Ipv6),
            0x88A8_u16 => Ok(EtherType::Ieee8021ad),
            0x88E5_u16 => Ok(EtherType::Ieee8021MacSec),
            0x88E7_u16 => Ok(EtherType::Ieee8021ah),
            0x88F5_u16 => Ok(EtherType::Ieee8021mvrp),
            0x8906_u16 => Ok(EtherType::FibreChannel),
            0x8915_u16 => Ok(EtherType::Infiniband),
            0x9000_u16 => Ok(EtherType::LoopbackIeee8023),
            0x9100_u16 => Ok(EtherType::Ieee8021QinQ1),
            0x9200_u16 => Ok(EtherType::Ieee8021QinQ2),
            0x9300_u16 => Ok(EtherType::Ieee8021QinQ3),
            _ => Err(value),
        }
    }
}

// This allows converting an EtherType enum variant back to its u16 representation.
// This is useful when constructing headers.
impl From<EtherType> for u16 {
    fn from(ether_type: EtherType) -> Self {
        ether_type as u16
    }
}

impl EtherType {
    /// Returns a human-readable string representation of the EtherType.
    ///
    /// # Returns
    /// A static string slice representing the protocol name
    ///
    /// # Examples
    /// ```
    /// # use network_types::eth::EtherType;
    /// assert_eq!(EtherType::Ipv4.as_str(), "ipv4");
    /// assert_eq!(EtherType::Arp.as_str(), "arp");
    /// assert_eq!(EtherType::Ieee8021q.as_str(), "vlan");
    /// ```
    pub fn as_str(self) -> &'static str {
        match self {
            EtherType::Loop => "loop",
            EtherType::Ipv4 => "ipv4",
            EtherType::Arp => "arp",
            EtherType::Ethernet => "ethernet",
            EtherType::Ieee8021q => "vlan",
            EtherType::Ipv6 => "ipv6",
            EtherType::Ieee8021ad => "qinq",
            EtherType::Ieee8021MacSec => "macsec",
            EtherType::Ieee8021ah => "pbb",
            EtherType::Ieee8021mvrp => "mvrp",
            EtherType::FibreChannel => "fibre-channel",
            EtherType::Infiniband => "infiniband",
            EtherType::LoopbackIeee8023 => "loopback",
            EtherType::Ieee8021QinQ1 => "qinq-1",
            EtherType::Ieee8021QinQ2 => "qinq-2",
            EtherType::Ieee8021QinQ3 => "qinq-3",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_eth_hdr_len() {
        assert_eq!(ETH_LEN, 14);
        assert_eq!(ETH_LEN, 6 + 6 + 2);
    }

    #[test]
    fn test_ethertype_try_from_u16_known() {
        let ipv4_val = 0x0800_u16.to_be();
        assert_eq!(EtherType::try_from(ipv4_val), Ok(EtherType::Ipv4));

        let ipv6_val = 0x86DD_u16.to_be();
        assert_eq!(EtherType::try_from(ipv6_val), Ok(EtherType::Ipv6));

        let arp_val = 0x0806_u16.to_be();
        assert_eq!(EtherType::try_from(arp_val), Ok(EtherType::Arp));
    }

    #[test]
    fn test_ethertype_try_from_u16_unknown() {
        let unknown_val = 0x1234_u16.to_be();
        assert_eq!(EtherType::try_from(unknown_val), Err(unknown_val));
    }

    #[test]
    fn test_u16_from_ethertype() {
        assert_eq!(u16::from(EtherType::Ipv4), 0x0800_u16.to_be());
        assert_eq!(u16::from(EtherType::Arp), 0x0806_u16.to_be());
        assert_eq!(u16::from(EtherType::Ipv6), 0x86DD_u16.to_be());
        assert_eq!(u16::from(EtherType::Loop), 0x0060_u16.to_be());
    }

    #[test]
    fn test_ethertype_variants_unique_values() {
        let all_types = [
            EtherType::Loop,
            EtherType::Ipv4,
            EtherType::Arp,
            EtherType::Ethernet,
            EtherType::Ieee8021q,
            EtherType::Ipv6,
            EtherType::Ieee8021ad,
            EtherType::Ieee8021MacSec,
            EtherType::Ieee8021ah,
            EtherType::Ieee8021mvrp,
            EtherType::FibreChannel,
            EtherType::Infiniband,
            EtherType::LoopbackIeee8023,
            EtherType::Ieee8021QinQ1,
            EtherType::Ieee8021QinQ2,
            EtherType::Ieee8021QinQ3,
        ];

        for i in 0..all_types.len() {
            for j in (i + 1)..all_types.len() {
                // Compare the u16 representation of each EtherType
                let val_i = all_types[i] as u16;
                let val_j = all_types[j] as u16;
                assert_ne!(
                    val_i, val_j,
                    "Duplicate EtherType value found: {:?} and {:?} both have value {:#06x}",
                    all_types[i], all_types[j], val_i
                );
            }
        }
    }

    #[test]
    fn test_ethertype_as_str() {
        assert_eq!(EtherType::Loop.as_str(), "loop");
        assert_eq!(EtherType::Ipv4.as_str(), "ipv4");
        assert_eq!(EtherType::Arp.as_str(), "arp");
        assert_eq!(EtherType::Ethernet.as_str(), "ethernet");
        assert_eq!(EtherType::Ieee8021q.as_str(), "vlan");
        assert_eq!(EtherType::Ipv6.as_str(), "ipv6");
        assert_eq!(EtherType::Ieee8021ad.as_str(), "qinq");
        assert_eq!(EtherType::Ieee8021MacSec.as_str(), "macsec");
        assert_eq!(EtherType::Ieee8021ah.as_str(), "pbb");
        assert_eq!(EtherType::Ieee8021mvrp.as_str(), "mvrp");
        assert_eq!(EtherType::FibreChannel.as_str(), "fibre-channel");
        assert_eq!(EtherType::Infiniband.as_str(), "infiniband");
        assert_eq!(EtherType::LoopbackIeee8023.as_str(), "loopback");
        assert_eq!(EtherType::Ieee8021QinQ1.as_str(), "qinq-1");
        assert_eq!(EtherType::Ieee8021QinQ2.as_str(), "qinq-2");
        assert_eq!(EtherType::Ieee8021QinQ3.as_str(), "qinq-3");
    }
}
