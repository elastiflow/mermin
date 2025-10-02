//! ## IP Headers
//!
//! IPv4 header, which is present after the Ethernet header.
//!  0                   1                   2                   3
//!  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |ip_ver | h_len |  ip_dscp  |ecn|        ip_total_length        |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |       ip_identification       |flags|   ip_fragment_offset    |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |    ip_ttl     |  ip_protocol  |          ip_checksum          |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                         source_ipaddr                         |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                      destination_ipaddr                       |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                          ip_options                           |
//! /                              ...                              /
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//!
//! IPv6 header, which is present after the Ethernet header.
//!   0                   1                   2                   3
//!   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//!  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//!  |ip_ver |  ip_dscp  |ecn|             ip_flow_label             |
//!  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//!  |       ip_payload_length       |ip_next_header | ip_hop_limit  |
//!  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//!  |                         source_ipaddr                         |
//!  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//!  |                     source_ipaddr (con't)                     |
//!  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//!  |                     source_ipaddr (con't)                     |
//!  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//!  |                     source_ipaddr (con't)                     |
//!  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//!  |                      destination_ipaddr                       |
//!  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//!  |                  destination_ipaddr (con't)                   |
//!  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//!  |                  destination_ipaddr (con't)                   |
//!  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//!  |                  destination_ipaddr (con't)                   |
//!  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

/// IP headers, which are present after the Ethernet header.
pub enum IpHdr {
    V4,
    V6,
}

pub mod ipv4 {
    use crate::ip::IpProto;

    /// The length of the IPv4 header.
    pub const IPV4_LEN: usize = 20;

    pub type Vihl = u8;
    pub type DscpEcn = u8;
    pub type TotalLen = [u8; 2];
    pub type Identification = [u8; 2];
    pub type Fragment = [u8; 2];
    pub type Ttl = u8;
    pub type Protocol = IpProto;
    pub type Checksum = [u8; 2];
    pub type SrcAddr = [u8; 4];
    pub type DstAddr = [u8; 4];

    /// Returns the IP version field (should be 4).
    #[inline]
    pub fn version(vihl: Vihl) -> u8 {
        (vihl >> 4) & 0xF
    }

    /// Returns the IP header length in bytes.
    #[inline]
    pub fn ihl(vihl: Vihl) -> u8 {
        (vihl & 0xF) << 2
    }

    /// Returns the DSCP (Differentiated Services Code Point) field.
    #[inline]
    pub fn dscp(dscp_ecn: DscpEcn) -> u8 {
        (dscp_ecn >> 2) & 0x3F
    }

    /// Returns the ECN (Explicit Congestion Notification) field.
    #[inline]
    pub fn ecn(dscp_ecn: DscpEcn) -> u8 {
        dscp_ecn & 0x3
    }

    /// Returns the total length of the IP packet.
    #[inline]
    pub fn tot_len(total_len: TotalLen) -> u16 {
        u16::from_be_bytes(total_len)
    }

    /// Returns the identification field.
    #[inline]
    pub fn id(identification: Identification) -> u16 {
        u16::from_be_bytes(identification)
    }

    /// Returns the fragmentation flags (3 bits).
    #[inline]
    pub fn frag_flags(fragments: Fragment) -> u8 {
        (u16::from_be_bytes(fragments) >> 13) as u8
    }

    /// Returns the fragmentation offset (13 bits).
    #[inline]
    pub fn frag_offset(fragments: Fragment) -> u16 {
        u16::from_be_bytes(fragments) & 0x1FFF
    }

    /// Returns the checksum field.
    #[inline]
    pub fn checksum(checksum: Checksum) -> u16 {
        u16::from_be_bytes(checksum)
    }

    /// Returns the source address field.
    #[inline]
    pub fn src_addr(src_addr: SrcAddr) -> core::net::Ipv4Addr {
        core::net::Ipv4Addr::from(src_addr)
    }

    /// Returns the destination address field.
    #[inline]
    pub fn dst_addr(dst_addr: DstAddr) -> core::net::Ipv4Addr {
        core::net::Ipv4Addr::from(dst_addr)
    }
}

pub mod ipv6 {
    use crate::ip::IpProto;

    /// The length of the IPv6 header.
    pub const IPV6_LEN: usize = 40;

    pub type Vcf = [u8; 4];
    pub type PayloadLen = [u8; 2];
    pub type NextHdr = IpProto;
    pub type HopLimit = u8;
    pub type SrcAddr = [u8; 16];
    pub type DstAddr = [u8; 16];

    /// Returns the IP version field (should be 6).
    #[inline]
    pub fn version(vcf: Vcf) -> u8 {
        (vcf[0] >> 4) & 0xF
    }

    /// Returns the DSCP (Differentiated Services Code Point) field.
    #[inline]
    pub fn dscp(vcf: Vcf) -> u8 {
        ((vcf[0] & 0x0F) << 2) | ((vcf[1] >> 6) & 0x03)
    }

    /// Returns the ECN (Explicit Congestion Notification) field.
    #[inline]
    pub fn ecn(vcf: Vcf) -> u8 {
        (vcf[1] >> 4) & 0x03
    }

    /// Returns the flow label field (20 bits).
    #[inline]
    pub fn flow_label(vcf: Vcf) -> u32 {
        ((vcf[1] as u32 & 0x0F) << 16) | ((vcf[2] as u32) << 8) | (vcf[3] as u32)
    }

    /// Returns the payload length.
    #[inline]
    pub fn payload_len(payload_len: PayloadLen) -> u16 {
        u16::from_be_bytes(payload_len)
    }

    /// Returns the source address field.
    #[inline]
    pub fn src_addr(src_addr: SrcAddr) -> core::net::Ipv6Addr {
        core::net::Ipv6Addr::from(src_addr)
    }

    /// Returns the destination address field.
    #[inline]
    pub fn dst_addr(dst_addr: DstAddr) -> core::net::Ipv6Addr {
        core::net::Ipv6Addr::from(dst_addr)
    }
}

/// Protocol which is encapsulated in the IPv4 packet.
/// <https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml>
#[repr(u8)]
#[derive(Default, PartialEq, Eq, Debug, Copy, Clone)]
pub enum IpProto {
    /// IPv6 Hop-by-Hop Option
    #[default]
    // TODO: change default to reserved and set protocol to none when generating flow in userspace
    HopOpt = 0,
    /// Internet Control Message
    Icmp = 1,
    /// Internet Group Management
    Igmp = 2,
    /// Gateway-to-Gateway
    Ggp = 3,
    /// IPv4 encapsulation
    Ipv4 = 4,
    /// Stream
    Stream = 5,
    /// Transmission Control
    Tcp = 6,
    /// CBT
    Cbt = 7,
    /// Exterior Gateway Protocol
    Egp = 8,
    /// Any private interior gateway (used by Cisco for their IGRP)
    Igp = 9,
    /// BBN RCC Monitoring
    BbnRccMon = 10,
    /// Network Voice Protocol
    NvpII = 11,
    /// PUP
    Pup = 12,
    /// ARGUS
    Argus = 13,
    /// EMCON
    Emcon = 14,
    /// Cross Net Debugger
    Xnet = 15,
    /// Chaos
    Chaos = 16,
    /// User Datagram
    Udp = 17,
    /// Multiplexing
    Mux = 18,
    /// DCN Measurement Subsystems
    DcnMeas = 19,
    /// Host Monitoring
    Hmp = 20,
    /// Packet Radio Measurement
    Prm = 21,
    /// XEROX NS IDP
    Idp = 22,
    /// Trunk-1
    Trunk1 = 23,
    /// Trunk-2
    Trunk2 = 24,
    /// Leaf-1
    Leaf1 = 25,
    /// Leaf-2
    Leaf2 = 26,
    /// Reliable Data Protocol
    Rdp = 27,
    /// Internet Reliable Transaction
    Irtp = 28,
    /// ISO Transport Protocol Class 4
    Tp4 = 29,
    /// Bulk Data Transfer Protocol
    Netblt = 30,
    /// MFE Network Services Protocol
    MfeNsp = 31,
    /// MERIT Internodal Protocol
    MeritInp = 32,
    /// Datagram Congestion Control Protocol
    Dccp = 33,
    /// Third Party Connect Protocol
    ThirdPartyConnect = 34,
    /// Inter-Domain Policy Routing Protocol
    Idpr = 35,
    /// XTP
    Xtp = 36,
    /// Datagram Delivery Protocol
    Ddp = 37,
    /// IDPR Control Message Transport Proto
    IdprCmtp = 38,
    /// TP++ Transport Protocol
    TpPlusPlus = 39,
    /// IL Transport Protocol
    Il = 40,
    /// IPv6 encapsulation
    Ipv6 = 41,
    /// Source Demand Routing Protocol
    Sdrp = 42,
    /// Routing Header for IPv6
    Ipv6Route = 43,
    /// Fragment Header for IPv6
    Ipv6Frag = 44,
    /// Inter-Domain Routing Protocol
    Idrp = 45,
    /// Reservation Protocol
    Rsvp = 46,
    /// General Routing Encapsulation
    Gre = 47,
    /// Dynamic Source Routing Protocol
    Dsr = 48,
    /// BNA
    Bna = 49,
    /// Encap Security Payload
    Esp = 50,
    /// Authentication Header
    Ah = 51,
    /// Integrated Net Layer Security TUBA
    Inlsp = 52,
    /// IP with Encryption
    Swipe = 53,
    /// NBMA Address Resolution Protocol
    Narp = 54,
    /// IP Mobility
    Mobile = 55,
    /// Transport Layer Security Protocol using Kryptonet key management
    Tlsp = 56,
    /// SKIP
    Skip = 57,
    /// Internet Control Message Protocol for IPv6
    Ipv6Icmp = 58,
    /// No Next Header for IPv6
    Ipv6NoNxt = 59,
    /// Destination Options for IPv6
    Ipv6Opts = 60,
    /// Any host internal protocol
    AnyHostInternal = 61,
    /// CFTP
    Cftp = 62,
    /// Any local network
    AnyLocalNetwork = 63,
    /// SATNET and Backroom EXPAK
    SatExpak = 64,
    /// Kryptolan
    Kryptolan = 65,
    /// MIT Remote Virtual Disk Protocol
    Rvd = 66,
    /// Internet Pluribus Packet Core
    Ippc = 67,
    /// Any distributed file system
    AnyDistributedFileSystem = 68,
    /// SATNET Monitoring
    SatMon = 69,
    /// VISA Protocol
    Visa = 70,
    /// Internet Packet Core Utility
    Ipcv = 71,
    /// Computer Protocol Network Executive
    Cpnx = 72,
    /// Computer Protocol Heart Beat
    Cphb = 73,
    /// Wang Span Network
    Wsn = 74,
    /// Packet Video Protocol
    Pvp = 75,
    /// Backroom SATNET Monitoring
    BrSatMon = 76,
    /// SUN ND PROTOCOL-Temporary
    SunNd = 77,
    /// WIDEBAND Monitoring
    WbMon = 78,
    /// WIDEBAND EXPAK
    WbExpak = 79,
    /// ISO Internet Protocol
    IsoIp = 80,
    /// VMTP
    Vmtp = 81,
    /// SECURE-VMTP
    SecureVmtp = 82,
    /// VINES
    Vines = 83,
    /// Transaction Transport Protocol
    Ttp = 84,
    /// NSFNET-IGP
    NsfnetIgp = 85,
    /// Dissimilar Gateway Protocol
    Dgp = 86,
    /// TCF
    Tcf = 87,
    /// EIGRP
    Eigrp = 88,
    /// OSPFIGP
    Ospfigp = 89,
    /// Sprite RPC Protocol
    SpriteRpc = 90,
    /// Locus Address Resolution Protocol
    Larp = 91,
    /// Multicast Transport Protocol
    Mtp = 92,
    /// AX.25 Frames
    Ax25 = 93,
    /// IP-within-IP Encapsulation Protocol
    Ipip = 94,
    /// Mobile Internetworking Control Pro.
    Micp = 95,
    /// Semaphore Communications Sec. Pro.
    SccSp = 96,
    /// Ethernet-within-IP Encapsulation
    Etherip = 97,
    /// Encapsulation Header
    Encap = 98,
    /// Any private encryption scheme
    AnyPrivateEncryptionScheme = 99,
    /// GMTP
    Gmtp = 100,
    /// Ipsilon Flow Management Protocol
    Ifmp = 101,
    /// PNNI over IP
    Pnni = 102,
    /// Protocol Independent Multicast
    Pim = 103,
    /// ARIS
    Aris = 104,
    /// SCPS
    Scps = 105,
    /// QNX
    Qnx = 106,
    /// Active Networks
    ActiveNetworks = 107,
    /// IP Payload Compression Protocol
    IpComp = 108,
    /// Sitara Networks Protocol
    Snp = 109,
    /// Compaq Peer Protocol
    CompaqPeer = 110,
    /// IPX in IP
    IpxInIp = 111,
    /// Virtual Router Redundancy Protocol
    Vrrp = 112,
    /// PGM Reliable Transport Protocol
    Pgm = 113,
    /// Any 0-hop protocol
    AnyZeroHopProtocol = 114,
    /// Layer Two Tunneling Protocol
    L2tp = 115,
    /// D-II Data Exchange (DDX)
    Ddx = 116,
    /// Interactive Agent Transfer Protocol
    Iatp = 117,
    /// Schedule Transfer Protocol
    Stp = 118,
    /// SpectraLink Radio Protocol
    Srp = 119,
    /// UTI
    Uti = 120,
    /// Simple Message Protocol
    Smp = 121,
    /// Simple Multicast Protocol
    Sm = 122,
    /// Performance Transparency Protocol
    Ptp = 123,
    /// ISIS over IPv4
    IsisOverIpv4 = 124,
    /// FIRE
    Fire = 125,
    /// Combat Radio Transport Protocol
    Crtp = 126,
    /// Combat Radio User Datagram
    Crudp = 127,
    /// SSCOPMCE
    Sscopmce = 128,
    /// IPLT
    Iplt = 129,
    /// Secure Packet Shield
    Sps = 130,
    /// Private IP Encapsulation within IP
    Pipe = 131,
    /// Stream Control Transmission Protocol
    Sctp = 132,
    /// Fibre Channel
    Fc = 133,
    /// RSVP-E2E-IGNORE
    RsvpE2eIgnore = 134,
    /// Mobility Header
    MobilityHeader = 135,
    /// Lightweight User Datagram Protocol
    UdpLite = 136,
    /// MPLS-in-IP
    Mpls = 137,
    /// MANET Protocols
    Manet = 138,
    /// Host Identity Protocol
    Hip = 139,
    /// Shim6 Protocol
    Shim6 = 140,
    /// Wrapped Encapsulating Security Payload
    Wesp = 141,
    /// Robust Header Compression
    Rohc = 142,
    /// Ethernet in IPv4
    EthernetInIpv4 = 143,
    /// AGGFRAG encapsulation payload for ESP
    Aggfrag = 144,
    /// Use for experimentation and testing
    Test1 = 253,
    /// Use for experimentation and testing
    Test2 = 254,
    /// Reserved
    Reserved = 255,
}

impl IpProto {
    /// Returns human-readable string representation of the protocol
    pub fn as_str(&self) -> &'static str {
        match self {
            IpProto::HopOpt => "hopopt",
            IpProto::Icmp => "icmp",
            IpProto::Igmp => "igmp",
            IpProto::Ggp => "ggp",
            IpProto::Ipv4 => "ipv4",
            IpProto::Stream => "stream",
            IpProto::Tcp => "tcp",
            IpProto::Cbt => "cbt",
            IpProto::Egp => "egp",
            IpProto::Igp => "igp",
            IpProto::BbnRccMon => "bbn-rcc-mon",
            IpProto::NvpII => "nvp-ii",
            IpProto::Pup => "pup",
            IpProto::Argus => "argus",
            IpProto::Emcon => "emcon",
            IpProto::Xnet => "xnet",
            IpProto::Chaos => "chaos",
            IpProto::Udp => "udp",
            IpProto::Mux => "mux",
            IpProto::DcnMeas => "dcn-meas",
            IpProto::Hmp => "hmp",
            IpProto::Prm => "prm",
            IpProto::Idp => "idp",
            IpProto::Trunk1 => "trunk-1",
            IpProto::Trunk2 => "trunk-2",
            IpProto::Leaf1 => "leaf-1",
            IpProto::Leaf2 => "leaf-2",
            IpProto::Rdp => "rdp",
            IpProto::Irtp => "irtp",
            IpProto::Tp4 => "tp4",
            IpProto::Netblt => "netblt",
            IpProto::MfeNsp => "mfe-nsp",
            IpProto::MeritInp => "merit-inp",
            IpProto::Dccp => "dccp",
            IpProto::ThirdPartyConnect => "3pc",
            IpProto::Idpr => "idpr",
            IpProto::Xtp => "xtp",
            IpProto::Ddp => "ddp",
            IpProto::IdprCmtp => "idpr-cmtp",
            IpProto::TpPlusPlus => "tp++",
            IpProto::Il => "il",
            IpProto::Ipv6 => "ipv6",
            IpProto::Sdrp => "sdrp",
            IpProto::Ipv6Route => "ipv6-route",
            IpProto::Ipv6Frag => "ipv6-frag",
            IpProto::Idrp => "idrp",
            IpProto::Rsvp => "rsvp",
            IpProto::Gre => "gre",
            IpProto::Dsr => "dsr",
            IpProto::Bna => "bna",
            IpProto::Esp => "esp",
            IpProto::Ah => "ah",
            IpProto::Inlsp => "inlsp",
            IpProto::Swipe => "swipe",
            IpProto::Narp => "narp",
            IpProto::Mobile => "mobile",
            IpProto::Tlsp => "tlsp",
            IpProto::Skip => "skip",
            IpProto::Ipv6Icmp => "icmpv6",
            IpProto::Ipv6NoNxt => "ipv6-nonxt",
            IpProto::Ipv6Opts => "ipv6-opts",
            IpProto::AnyHostInternal => "any-host-internal",
            IpProto::Cftp => "cftp",
            IpProto::AnyLocalNetwork => "any-local-network",
            IpProto::SatExpak => "sat-expak",
            IpProto::Kryptolan => "kryptolan",
            IpProto::Rvd => "rvd",
            IpProto::Ippc => "ippc",
            IpProto::AnyDistributedFileSystem => "any-distributed-file-system",
            IpProto::SatMon => "sat-mon",
            IpProto::Visa => "visa",
            IpProto::Ipcv => "ipcv",
            IpProto::Cpnx => "cpnx",
            IpProto::Cphb => "cphb",
            IpProto::Wsn => "wsn",
            IpProto::Pvp => "pvp",
            IpProto::BrSatMon => "br-sat-mon",
            IpProto::SunNd => "sun-nd",
            IpProto::WbMon => "wb-mon",
            IpProto::WbExpak => "wb-expak",
            IpProto::IsoIp => "iso-ip",
            IpProto::Vmtp => "vmtp",
            IpProto::SecureVmtp => "secure-vmtp",
            IpProto::Vines => "vines",
            IpProto::Ttp => "ttp",
            IpProto::NsfnetIgp => "nsfnet-igp",
            IpProto::Dgp => "dgp",
            IpProto::Tcf => "tcf",
            IpProto::Eigrp => "eigrp",
            IpProto::Ospfigp => "ospfigp",
            IpProto::SpriteRpc => "sprite-rpc",
            IpProto::Larp => "larp",
            IpProto::Mtp => "mtp",
            IpProto::Ax25 => "ax.25",
            IpProto::Ipip => "ipip",
            IpProto::Micp => "micp",
            IpProto::SccSp => "scc-sp",
            IpProto::Etherip => "etherip",
            IpProto::Encap => "encap",
            IpProto::AnyPrivateEncryptionScheme => "any-private-encryption-scheme",
            IpProto::Gmtp => "gmtp",
            IpProto::Ifmp => "ifmp",
            IpProto::Pnni => "pnni",
            IpProto::Pim => "pim",
            IpProto::Aris => "aris",
            IpProto::Scps => "scps",
            IpProto::Qnx => "qnx",
            IpProto::ActiveNetworks => "active-networks",
            IpProto::IpComp => "ipcomp",
            IpProto::Snp => "snp",
            IpProto::CompaqPeer => "compaq-peer",
            IpProto::IpxInIp => "ipx-in-ip",
            IpProto::Vrrp => "vrrp",
            IpProto::Pgm => "pgm",
            IpProto::AnyZeroHopProtocol => "any-0-hop-protocol",
            IpProto::L2tp => "l2tp",
            IpProto::Ddx => "ddx",
            IpProto::Iatp => "iatp",
            IpProto::Stp => "stp",
            IpProto::Srp => "srp",
            IpProto::Uti => "uti",
            IpProto::Smp => "smp",
            IpProto::Sm => "sm",
            IpProto::Ptp => "ptp",
            IpProto::IsisOverIpv4 => "isis-over-ipv4",
            IpProto::Fire => "fire",
            IpProto::Crtp => "crtp",
            IpProto::Crudp => "crudp",
            IpProto::Sscopmce => "sscopmce",
            IpProto::Iplt => "iplt",
            IpProto::Sps => "sps",
            IpProto::Pipe => "pipe",
            IpProto::Sctp => "sctp",
            IpProto::Fc => "fc",
            IpProto::RsvpE2eIgnore => "rsvp-e2e-ignore",
            IpProto::MobilityHeader => "mobility-header",
            IpProto::UdpLite => "udplite",
            IpProto::Mpls => "mpls-in-ip",
            IpProto::Manet => "manet",
            IpProto::Hip => "hip",
            IpProto::Shim6 => "shim6",
            IpProto::Wesp => "wesp",
            IpProto::Rohc => "rohc",
            IpProto::EthernetInIpv4 => "ethernet-in-ipv4",
            IpProto::Aggfrag => "aggfrag",
            IpProto::Test1 => "test1",
            IpProto::Test2 => "test2",
            IpProto::Reserved => "reserved",
        }
    }

    /// Try to create an IpProto from a u8 value
    pub fn try_from_u8(value: u8) -> Option<Self> {
        match value {
            0 => Some(IpProto::HopOpt),
            1 => Some(IpProto::Icmp),
            2 => Some(IpProto::Igmp),
            3 => Some(IpProto::Ggp),
            4 => Some(IpProto::Ipv4),
            5 => Some(IpProto::Stream),
            6 => Some(IpProto::Tcp),
            7 => Some(IpProto::Cbt),
            8 => Some(IpProto::Egp),
            9 => Some(IpProto::Igp),
            10 => Some(IpProto::BbnRccMon),
            11 => Some(IpProto::NvpII),
            12 => Some(IpProto::Pup),
            13 => Some(IpProto::Argus),
            14 => Some(IpProto::Emcon),
            15 => Some(IpProto::Xnet),
            16 => Some(IpProto::Chaos),
            17 => Some(IpProto::Udp),
            18 => Some(IpProto::Mux),
            19 => Some(IpProto::DcnMeas),
            20 => Some(IpProto::Hmp),
            21 => Some(IpProto::Prm),
            22 => Some(IpProto::Idp),
            23 => Some(IpProto::Trunk1),
            24 => Some(IpProto::Trunk2),
            25 => Some(IpProto::Leaf1),
            26 => Some(IpProto::Leaf2),
            27 => Some(IpProto::Rdp),
            28 => Some(IpProto::Irtp),
            29 => Some(IpProto::Tp4),
            30 => Some(IpProto::Netblt),
            31 => Some(IpProto::MfeNsp),
            32 => Some(IpProto::MeritInp),
            33 => Some(IpProto::Dccp),
            34 => Some(IpProto::ThirdPartyConnect),
            35 => Some(IpProto::Idpr),
            36 => Some(IpProto::Xtp),
            37 => Some(IpProto::Ddp),
            38 => Some(IpProto::IdprCmtp),
            39 => Some(IpProto::TpPlusPlus),
            40 => Some(IpProto::Il),
            41 => Some(IpProto::Ipv6),
            42 => Some(IpProto::Sdrp),
            43 => Some(IpProto::Ipv6Route),
            44 => Some(IpProto::Ipv6Frag),
            45 => Some(IpProto::Idrp),
            46 => Some(IpProto::Rsvp),
            47 => Some(IpProto::Gre),
            48 => Some(IpProto::Dsr),
            49 => Some(IpProto::Bna),
            50 => Some(IpProto::Esp),
            51 => Some(IpProto::Ah),
            52 => Some(IpProto::Inlsp),
            53 => Some(IpProto::Swipe),
            54 => Some(IpProto::Narp),
            55 => Some(IpProto::Mobile),
            56 => Some(IpProto::Tlsp),
            57 => Some(IpProto::Skip),
            58 => Some(IpProto::Ipv6Icmp),
            59 => Some(IpProto::Ipv6NoNxt),
            60 => Some(IpProto::Ipv6Opts),
            61 => Some(IpProto::AnyHostInternal),
            62 => Some(IpProto::Cftp),
            63 => Some(IpProto::AnyLocalNetwork),
            64 => Some(IpProto::SatExpak),
            65 => Some(IpProto::Kryptolan),
            66 => Some(IpProto::Rvd),
            67 => Some(IpProto::Ippc),
            68 => Some(IpProto::AnyDistributedFileSystem),
            69 => Some(IpProto::SatMon),
            70 => Some(IpProto::Visa),
            71 => Some(IpProto::Ipcv),
            72 => Some(IpProto::Cpnx),
            73 => Some(IpProto::Cphb),
            74 => Some(IpProto::Wsn),
            75 => Some(IpProto::Pvp),
            76 => Some(IpProto::BrSatMon),
            77 => Some(IpProto::SunNd),
            78 => Some(IpProto::WbMon),
            79 => Some(IpProto::WbExpak),
            80 => Some(IpProto::IsoIp),
            81 => Some(IpProto::Vmtp),
            82 => Some(IpProto::SecureVmtp),
            83 => Some(IpProto::Vines),
            84 => Some(IpProto::Ttp),
            85 => Some(IpProto::NsfnetIgp),
            86 => Some(IpProto::Dgp),
            87 => Some(IpProto::Tcf),
            88 => Some(IpProto::Eigrp),
            89 => Some(IpProto::Ospfigp),
            90 => Some(IpProto::SpriteRpc),
            91 => Some(IpProto::Larp),
            92 => Some(IpProto::Mtp),
            93 => Some(IpProto::Ax25),
            94 => Some(IpProto::Ipip),
            95 => Some(IpProto::Micp),
            96 => Some(IpProto::SccSp),
            97 => Some(IpProto::Etherip),
            98 => Some(IpProto::Encap),
            99 => Some(IpProto::AnyPrivateEncryptionScheme),
            100 => Some(IpProto::Gmtp),
            101 => Some(IpProto::Ifmp),
            102 => Some(IpProto::Pnni),
            103 => Some(IpProto::Pim),
            104 => Some(IpProto::Aris),
            105 => Some(IpProto::Scps),
            106 => Some(IpProto::Qnx),
            107 => Some(IpProto::ActiveNetworks),
            108 => Some(IpProto::IpComp),
            109 => Some(IpProto::Snp),
            110 => Some(IpProto::CompaqPeer),
            111 => Some(IpProto::IpxInIp),
            112 => Some(IpProto::Vrrp),
            113 => Some(IpProto::Pgm),
            114 => Some(IpProto::AnyZeroHopProtocol),
            115 => Some(IpProto::L2tp),
            116 => Some(IpProto::Ddx),
            117 => Some(IpProto::Iatp),
            118 => Some(IpProto::Stp),
            119 => Some(IpProto::Srp),
            120 => Some(IpProto::Uti),
            121 => Some(IpProto::Smp),
            122 => Some(IpProto::Sm),
            123 => Some(IpProto::Ptp),
            124 => Some(IpProto::IsisOverIpv4),
            125 => Some(IpProto::Fire),
            126 => Some(IpProto::Crtp),
            127 => Some(IpProto::Crudp),
            128 => Some(IpProto::Sscopmce),
            129 => Some(IpProto::Iplt),
            130 => Some(IpProto::Sps),
            131 => Some(IpProto::Pipe),
            132 => Some(IpProto::Sctp),
            133 => Some(IpProto::Fc),
            134 => Some(IpProto::RsvpE2eIgnore),
            135 => Some(IpProto::MobilityHeader),
            136 => Some(IpProto::UdpLite),
            137 => Some(IpProto::Mpls),
            138 => Some(IpProto::Manet),
            139 => Some(IpProto::Hip),
            140 => Some(IpProto::Shim6),
            141 => Some(IpProto::Wesp),
            142 => Some(IpProto::Rohc),
            143 => Some(IpProto::EthernetInIpv4),
            144 => Some(IpProto::Aggfrag),
            253 => Some(IpProto::Test1),
            254 => Some(IpProto::Test2),
            255 => Some(IpProto::Reserved),
            _ => None,
        }
    }
}

impl core::fmt::Display for IpProto {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Protocol which is encapsulated in the IPv4 packet.
/// <https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml>
#[repr(u8)]
#[derive(Default, PartialEq, Eq, Debug, Copy, Clone)]
pub enum IpDscp {
    #[default]
    Df = 0,
    Cs1 = 8,
    Af11 = 10,
    Af12 = 12,
    Af13 = 14,
    Cs2 = 16,
    Af21 = 18,
    Af22 = 20,
    Af23 = 22,
    Cs3 = 24,
    Af31 = 26,
    Af32 = 28,
    Af33 = 30,
    Cs4 = 32,
    Af41 = 34,
    Af42 = 36,
    Af43 = 38,
    Cs5 = 40,
    Voice = 44,
    Ef = 46,
    Cs6 = 48,
    Cs7 = 56,
}

impl IpDscp {
    pub fn as_str(&self) -> &'static str {
        match self {
            IpDscp::Df => "df",
            IpDscp::Cs1 => "cs1",
            IpDscp::Af11 => "af11",
            IpDscp::Af12 => "af12",
            IpDscp::Af13 => "af13",
            IpDscp::Cs2 => "cs2",
            IpDscp::Af21 => "af21",
            IpDscp::Af22 => "af22",
            IpDscp::Af23 => "af23",
            IpDscp::Cs3 => "cs3",
            IpDscp::Af31 => "af31",
            IpDscp::Af32 => "af32",
            IpDscp::Af33 => "af33",
            IpDscp::Cs4 => "cs4",
            IpDscp::Af41 => "af41",
            IpDscp::Af42 => "af42",
            IpDscp::Af43 => "af43",
            IpDscp::Cs5 => "cs5",
            IpDscp::Voice => "voice",
            IpDscp::Ef => "ef",
            IpDscp::Cs6 => "cs6",
            IpDscp::Cs7 => "cs7",
        }
    }

    pub fn try_from_u8(value: u8) -> Option<Self> {
        match value {
            0 => Some(IpDscp::Df),
            8 => Some(IpDscp::Cs1),
            10 => Some(IpDscp::Af11),
            12 => Some(IpDscp::Af12),
            14 => Some(IpDscp::Af13),
            16 => Some(IpDscp::Cs2),
            18 => Some(IpDscp::Af21),
            20 => Some(IpDscp::Af22),
            22 => Some(IpDscp::Af23),
            24 => Some(IpDscp::Cs3),
            26 => Some(IpDscp::Af31),
            28 => Some(IpDscp::Af32),
            30 => Some(IpDscp::Af33),
            32 => Some(IpDscp::Cs4),
            34 => Some(IpDscp::Af41),
            36 => Some(IpDscp::Af42),
            38 => Some(IpDscp::Af43),
            40 => Some(IpDscp::Cs5),
            44 => Some(IpDscp::Voice),
            46 => Some(IpDscp::Ef),
            48 => Some(IpDscp::Cs6),
            56 => Some(IpDscp::Cs7),
            _ => None,
        }
    }
}

impl core::fmt::Display for IpDscp {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Explicit Congestion Notification (ECN) value from the IP header.
#[repr(u8)]
#[derive(Default, PartialEq, Eq, Debug, Copy, Clone)]
pub enum IpEcn {
    #[default]
    NonEct = 0,
    Ect1 = 1,
    Ect0 = 2,
    Ce = 3,
}

impl IpEcn {
    pub fn as_str(&self) -> &'static str {
        match self {
            IpEcn::NonEct => "non-ect",
            IpEcn::Ect1 => "ect1",
            IpEcn::Ect0 => "ect0",
            IpEcn::Ce => "ce",
        }
    }

    pub fn try_from_u8(value: u8) -> Option<Self> {
        match value {
            0 => Some(IpEcn::NonEct),
            1 => Some(IpEcn::Ect1),
            2 => Some(IpEcn::Ect0),
            3 => Some(IpEcn::Ce),
            _ => None,
        }
    }
}

impl core::fmt::Display for IpEcn {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use core::net::{Ipv4Addr, Ipv6Addr};

    use super::*;

    #[test]
    fn test_ipv4_len() {
        assert_eq!(ipv4::IPV4_LEN, 20);
    }

    #[test]
    fn test_ipv4_version() {
        let vihl: ipv4::Vihl = 0x45; // Version 4, IHL 5 words (20 bytes)
        assert_eq!(ipv4::version(vihl), 4);

        let vihl: ipv4::Vihl = 0x46; // Version 4, IHL 6 words (24 bytes)
        assert_eq!(ipv4::version(vihl), 4);
    }

    #[test]
    fn test_ipv4_ihl() {
        let vihl: ipv4::Vihl = 0x45; // Version 4, IHL 5 words (20 bytes)
        assert_eq!(ipv4::ihl(vihl), 20);

        let vihl: ipv4::Vihl = 0x46; // Version 4, IHL 6 words (24 bytes)
        assert_eq!(ipv4::ihl(vihl), 24);

        let vihl: ipv4::Vihl = 0x4F; // Version 4, IHL 15 words (60 bytes, max)
        assert_eq!(ipv4::ihl(vihl), 60);
    }

    #[test]
    fn test_ipv4_dscp() {
        let dscp_ecn: ipv4::DscpEcn = 0b00101001; // DSCP 10, ECN 1
        assert_eq!(ipv4::dscp(dscp_ecn), 0b001010);

        let dscp_ecn: ipv4::DscpEcn = 0b11001110; // DSCP 51, ECN 2
        assert_eq!(ipv4::dscp(dscp_ecn), 0b110011);
    }

    #[test]
    fn test_ipv4_ecn() {
        let dscp_ecn: ipv4::DscpEcn = 0b00101001; // DSCP 10, ECN 1
        assert_eq!(ipv4::ecn(dscp_ecn), 0b01);

        let dscp_ecn: ipv4::DscpEcn = 0b11001110; // DSCP 51, ECN 2
        assert_eq!(ipv4::ecn(dscp_ecn), 0b10);
    }

    #[test]
    fn test_ipv4_tot_len() {
        let tot_len: ipv4::TotalLen = [0x05, 0xDC]; // 1500 in big-endian
        assert_eq!(ipv4::tot_len(tot_len), 1500);

        let tot_len: ipv4::TotalLen = [0x00, 0x14]; // 20 in big-endian
        assert_eq!(ipv4::tot_len(tot_len), 20);
    }

    #[test]
    fn test_ipv4_id() {
        let id: ipv4::Identification = [0xAB, 0xCD];
        assert_eq!(ipv4::id(id), 0xABCD);
    }

    #[test]
    fn test_ipv4_frag_flags() {
        // Flags: 0b010 (DF set), Offset: 100
        let fragment: ipv4::Fragment = [0x41, 0x64]; // 0b0100000101100100
        assert_eq!(ipv4::frag_flags(fragment), 0b010);

        // Flags: 0b001 (MF set), Offset: 0
        let fragment: ipv4::Fragment = [0x20, 0x00]; // 0b0010000000000000
        assert_eq!(ipv4::frag_flags(fragment), 0b001);
    }

    #[test]
    fn test_ipv4_frag_offset() {
        // Flags: 0b010 (DF set), Offset: 356
        // 0x41 = 0b01000001, 0x64 = 0b01100100
        // Combined: 0b0100000101100100
        // Flags (top 3 bits): 0b010
        // Offset (bottom 13 bits): 0b0000101100100 = 356
        let fragment: ipv4::Fragment = [0x41, 0x64];
        assert_eq!(ipv4::frag_offset(fragment), 356);

        // Flags: 0b010 (DF set), Offset: 100
        // To get offset 100 = 0b0001100100, with flags 0b010
        // Combined: 0b0100001100100 = 0x4064
        let fragment: ipv4::Fragment = [0x40, 0x64];
        assert_eq!(ipv4::frag_offset(fragment), 100);

        // Flags: 0b001 (MF set), Offset: 0x0ABC (2748)
        let fragment: ipv4::Fragment = [0x2A, 0xBC];
        assert_eq!(ipv4::frag_offset(fragment), 0x0ABC);
    }

    #[test]
    fn test_ipv4_checksum() {
        let checksum: ipv4::Checksum = [0x12, 0x34];
        assert_eq!(ipv4::checksum(checksum), 0x1234);
    }

    #[test]
    fn test_ipv4_src_addr() {
        let src_addr: ipv4::SrcAddr = [192, 168, 1, 1];
        assert_eq!(ipv4::src_addr(src_addr), Ipv4Addr::new(192, 168, 1, 1));
    }

    #[test]
    fn test_ipv4_dst_addr() {
        let dst_addr: ipv4::DstAddr = [10, 0, 0, 1];
        assert_eq!(ipv4::dst_addr(dst_addr), Ipv4Addr::new(10, 0, 0, 1));
    }

    #[test]
    fn test_ipv6_len() {
        assert_eq!(ipv6::IPV6_LEN, 40);
    }

    #[test]
    fn test_ipv6_version() {
        let vcf: ipv6::Vcf = [0x60, 0x00, 0x00, 0x00]; // Version 6
        assert_eq!(ipv6::version(vcf), 6);

        let vcf: ipv6::Vcf = [0x6F, 0xFF, 0xFF, 0xFF]; // Version 6, all other bits set
        assert_eq!(ipv6::version(vcf), 6);
    }

    #[test]
    fn test_ipv6_dscp() {
        // DSCP: 0b001010 (10)
        // vcf[0] = version (0b0110) + DSCP bits 5-2 (0b0010) = 0b01100010 = 0x62
        // vcf[1] = DSCP bits 1-0 (0b10) in top 2 bits = 0b10000000 = 0x80
        let vcf: ipv6::Vcf = [0x62, 0x80, 0x00, 0x00];
        assert_eq!(ipv6::dscp(vcf), 0b001010);

        // DSCP: 0b111111 (63, max value)
        // vcf[0] = version (0b0110) + DSCP bits 5-2 (0b1111) = 0b01101111 = 0x6F
        // vcf[1] = DSCP bits 1-0 (0b11) in top 2 bits = 0b11000000 = 0xC0
        let vcf: ipv6::Vcf = [0x6F, 0xC0, 0x00, 0x00];
        assert_eq!(ipv6::dscp(vcf), 0b111111);
    }

    #[test]
    fn test_ipv6_ecn() {
        // ECN: 0b01 (1)
        let vcf: ipv6::Vcf = [0x60, 0x10, 0x00, 0x00]; // Version 6, ECN 1
        assert_eq!(ipv6::ecn(vcf), 0b01);
    }

    #[test]
    fn test_ipv6_flow_label() {
        // Flow label: 0x12345 (20-bit value)
        let vcf: ipv6::Vcf = [0x60, 0x01, 0x23, 0x45];
        assert_eq!(ipv6::flow_label(vcf), 0x12345);

        // Max flow label: 0xFFFFF
        let vcf: ipv6::Vcf = [0x6F, 0xFF, 0xFF, 0xFF];
        assert_eq!(ipv6::flow_label(vcf), 0xFFFFF);
    }

    #[test]
    fn test_ipv6_payload_len() {
        let payload_len: ipv6::PayloadLen = [0x0B, 0xB8]; // 3000 in big-endian
        assert_eq!(ipv6::payload_len(payload_len), 3000);
    }

    #[test]
    fn test_ipv6_src_addr() {
        let src_addr: ipv6::SrcAddr = [
            0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x01,
        ];
        assert_eq!(
            ipv6::src_addr(src_addr),
            Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 0x0001)
        );
    }

    #[test]
    fn test_ipv6_dst_addr() {
        let dst_addr: ipv6::DstAddr = [
            0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x02,
        ];
        assert_eq!(
            ipv6::dst_addr(dst_addr),
            Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 0x0002)
        );
    }

    #[test]
    fn test_ip_proto_variants() {
        assert_eq!(IpProto::Tcp as u8, 6);
        assert_eq!(IpProto::Udp as u8, 17);
        assert_eq!(IpProto::Icmp as u8, 1);
        assert_eq!(IpProto::Ipv6Icmp as u8, 58);
    }

    #[test]
    fn test_ip_proto_as_str() {
        assert_eq!(IpProto::Tcp.as_str(), "tcp");
        assert_eq!(IpProto::Udp.as_str(), "udp");
        assert_eq!(IpProto::Icmp.as_str(), "icmp");
        assert_eq!(IpProto::Ipv6Icmp.as_str(), "icmpv6");
        assert_eq!(IpProto::HopOpt.as_str(), "hopopt");
        assert_eq!(IpProto::Esp.as_str(), "esp");
        assert_eq!(IpProto::Ah.as_str(), "ah");
        assert_eq!(IpProto::Gre.as_str(), "gre");
        assert_eq!(IpProto::Sctp.as_str(), "sctp");
        assert_eq!(IpProto::Reserved.as_str(), "reserved");
    }

    #[test]
    fn test_ip_proto_try_from_u8() {
        assert_eq!(IpProto::try_from_u8(6), Some(IpProto::Tcp));
        assert_eq!(IpProto::try_from_u8(17), Some(IpProto::Udp));
        assert_eq!(IpProto::try_from_u8(1), Some(IpProto::Icmp));
        assert_eq!(IpProto::try_from_u8(58), Some(IpProto::Ipv6Icmp));
        assert_eq!(IpProto::try_from_u8(0), Some(IpProto::HopOpt));
        assert_eq!(IpProto::try_from_u8(50), Some(IpProto::Esp));
        assert_eq!(IpProto::try_from_u8(51), Some(IpProto::Ah));
        assert_eq!(IpProto::try_from_u8(132), Some(IpProto::Sctp));
        assert_eq!(IpProto::try_from_u8(255), Some(IpProto::Reserved));

        // Test invalid values
        assert_eq!(IpProto::try_from_u8(200), None);
        assert_eq!(IpProto::try_from_u8(145), None);
    }

    #[test]
    fn test_iphdr_enum() {
        // Test that IpHdr enum variants exist
        let _v4 = IpHdr::V4;
        let _v6 = IpHdr::V6;

        // Test matching on the enum
        match IpHdr::V4 {
            IpHdr::V4 => {}
            IpHdr::V6 => panic!("Expected V4"),
        }

        match IpHdr::V6 {
            IpHdr::V6 => {}
            IpHdr::V4 => panic!("Expected V6"),
        }
    }
}
