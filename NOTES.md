# Notes

This is a markdown file to take notes about development that are relevant to share with others working on this project.

## Information Elements

- [IPFIX](https://www.iana.org/assignments/ipfix/ipfix.xhtml)
- [Antrea CNI Flow IEs](https://antrea.io/docs/v1.6.1/docs/network-flow-visibility/#types-of-flows-and-associated-information)

## Recommended Custom IEs

| Rust Var       | Protocol | IE Name      | IE Type | Done |
|----------------|----------|--------------|---------|:----:|
| ip_ecn         | ipv4     | ipECN        | u8      |  ❌   |
| ip_packet_size |          | ipPacketSize | u32     |  ❌   |
| ipv4_checksum  |          | ipv4Checksum | ???     |  ❌   |

(Copy: ✅ | ❌)