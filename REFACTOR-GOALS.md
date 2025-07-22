# Refactor Goals

## Goal
In the user space program, log the 5-tuple key for a flow record and bytes on a packet. (src ip, src port, dst ip, dst port, protocol).

## TODOs

### Network types

[ ] eth
[ ] ip (ipv4 + ipv6)
[ ] tcp + udp
[ ] Integration suite for all 5

### Mermin eBPF

[ ] Send a 5-tuple key for a packet
[ ] Send bytes
[ ] Send to user space with a ring buffer

### Mermin Common

[ ] Reduce to the 5 tuple key and bytes only

### Mermin

[ ] Receive common struct from ring buffer
[ ] Log 5 tuple key and the bytes on the packet
[ ] Compile without errors with those 5 types and run and be able to decode basic network traffic (eth->ip-tcp / eth->ip->udp packets) and log the 5-tuple key.
[ ] Integration tests for packets with that basic information

## Notes
- https://www.iana.org/assignments/ipfix/ipfix.xhtml
