# Metrics Changes Log

This file tracks all changes made to Mermin metrics, including the reason for each change.

### Removed Metrics

#### `mermin_ebpf_ring_buffer_drops_total`
- **Status**: Removed
- **Reason**: 
  - This metric was registered but never incremented anywhere in the codebase
  - Cannot update Prometheus metrics from eBPF kernel-side code (where ring buffer drops occur)
  - Duplicates existing functionality: userspace ring buffer drops are already tracked by `mermin_flow_events_total{type="dropped_backpressure"}`
  - eBPF kernel-side drops (when ring buffer is full in kernel) cannot be tracked via Prometheus metrics from eBPF code
- **Replacement**: Use `mermin_flow_events_total{type="dropped_backpressure"}` for userspace backpressure drops

