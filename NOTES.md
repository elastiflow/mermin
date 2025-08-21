# Notes

This is a markdown file to take notes about development that are relevant to share with others working on this project.

## Information Elements

- [IPFIX](https://www.iana.org/assignments/ipfix/ipfix.xhtml)
- [Antrea CNI Flow IEs](https://antrea.io/docs/v1.6.1/docs/network-flow-visibility/#types-of-flows-and-associated-information)

## Potential Recommended Custom IEs

| Rust Var       | Protocol  | IE Name               | IE Type | Done |
|----------------|-----------|-----------------------|---------|:---:|
| ip_ecn         | ipv4      | ipECN                 | u8      |  ❌  |
| ip_packet_size |           | ipPacketSize          | u32     |  ❌  |
| ipv4_checksum  |           | ipv4Checksum          | ???     |  ❌  |
| auth_reserved  | ipv6-auth | Reserved              | u16     |  ❌  |
| auth_spi       | ipv6-auth | IPSecSPI              | u32     |  ❌  |
| auth_seq_num   | ipv6-auth | tcpSequenceNumber (?) | u32     |  ❌  |
| auth_icv       | ipv6-auth |                       |         |  ❌  |
| esp_spi        | ipv6-esp  | IPSecSPI              | u32     |  ❌  |
| esp_seq_num    | ipv6-esp  | tcpSequenceNumber (?) | u32     |  ❌  |
| esp_payload    | ipv6-esp  |                       |         |  ❌  |
| esp_padding    | ipv6-esp  | paddingOctets         | bytes   |  ❌  |
| esp_pad_len    | ipv6-esp  | ?                     | u8      |  ❌  |
| esp_next_hdr   | ipv6-esp  | nextHeaderIPv6 (?)    | u8      |  ❌  |

## IPv6 Extension Headers Implementation Status

| Protocol         | Parsing Support | IE Name | IE Type | Done |
|------------------|-----------------|---------|---------|:----:|
| ipv6-hop-by-hop  | ✅ Implemented  |         |         |  ✅   |
| ipv6-route       | ✅ Implemented  |         |         |  ✅   |
| ipv6-fragment    | ✅ Implemented  |         |         |  ✅   |
| ipv6-dest-opts   | ✅ Implemented  |         |         |  ✅   |
| ipv6-mobility    | ✅ Implemented  |         |         |  ✅   |
| ipv6-hip         | ✅ Implemented  |         |         |  ✅   |
| ipv6-shim6       | ✅ Implemented  |         |         |  ✅   |

**Implementation Details:**
- Added `Ipv6ExtHdr` structure for standard extension headers (Hop-by-Hop, Routing, Destination Options, Mobility, HIP, Shim6)
- Added `Ipv6FragHdr` structure for Fragment headers (which have a different format)
- Implemented extension header traversal logic in eBPF parser
- Added safety mechanisms: bounded loops (MAX_HEADER_PARSE_DEPTH=16), size limits, bounds checking
- Parser correctly identifies final L4 protocols (TCP, UDP, ICMPv6, SCTP) after traversing extension header chain
- Maintains compatibility with IPv6 packets without extension headers

(Copy: ✅ | ❌)
