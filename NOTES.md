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

## IPv6 Extension Headers to be Implemented

| Rust Var        | Protocol         | IE Name | IE Type | Done |
|-----------------|------------------|---------|---------|:----:|
| hop_opts_data   | ipv6-hop-by-hop  |         |         |  ❌   |
| route_data      | ipv6-route       |         |         |  ✅   |
| dest_opts_data  | ipv6-dest-opts   |         |         |  ❌   |
| mobility_opts   | ipv6-mobility    |         |         |  ❌   |
| hip_params      | ipv6-hip         |         |         |  ❌   |
| shim6_opts      | ipv6-shim6       |         |         |  ❌   |

(Copy: ✅ | ❌)
