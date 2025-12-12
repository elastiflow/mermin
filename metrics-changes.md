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

### Documentation Fixes

#### `mermin_flow_spans_active_total` (was incorrectly documented as `mermin_span_active`)
- **Status**: Documentation corrected
- **Reason**: 
  - Documentation in `docs/testing/metrics-guide.md` incorrectly referenced the metric as `mermin_span_active`
  - Actual metric name is `mermin_flow_spans_active_total` (defined in `mermin/src/metrics/registry.rs`)
  - Variable name `FLOWS_ACTIVE_TOTAL` is just a Rust identifier; the actual Prometheus metric name is what matters
- **Change**: Updated documentation to use correct metric name `mermin_flow_spans_active_total`

### Channel Label Renaming and Consolidation

#### `mermin_channel_*` metrics channel labels
- **Status**: Labels renamed for clarity and unified to output-centric perspective
- **Reason**: 
  - Original labels `exporter` and `exporter_input` were misleading about data flow direction
  - `exporter` channel actually represents producer output (producer → decorator)
  - `exporter_input` channel actually represents decorator output (decorator → exporter)
  - Unified to output-centric perspective for consistency (track from sender's perspective)
- **Changes**: 
  - `exporter` → `producer_output` (producer sends to decorator)
  - `exporter_input` → `decorator_output` (decorator sends to exporter)
  - **Removed** `decorator_input` (duplicate of `producer_output`, now unified)
- **Affected Metrics**: 
  - `mermin_channel_capacity{channel}`
  - `mermin_channel_size{channel}`
  - `mermin_channel_sends_total{channel, status}`
- **Migration**:
  | Old Label Value | New Label Value | Pipeline Stage |
  |----------------|-----------------|----------------|
  | `channel="exporter"` | `channel="producer_output"` | Producer → Decorator |
  | `channel="exporter_input"` | `channel="decorator_output"` | Decorator → Exporter |
  | `channel="decorator_input"` | `channel="producer_output"` | Producer → Decorator (unified) |

### Help Message Improvements

#### `mermin_channel_sends_total`
- **Status**: Help message clarified
- **Reason**: 
  - Original help message "Total number of channel send operations" was ambiguous about data flow direction
  - Users need to understand that this tracks sends TO channels (data flowing INTO channels from sender's perspective)
- **Change**: Updated help message to: "Total number of send operations to internal channels (data flows into channels: ringbuf → packet_worker, producer → producer_output, decorator → decorator_output)"
- **Labels**: `channel` (packet_worker, producer_output, decorator_output), `status` (success, error)

#### `mermin_ringbuf_packets_total`
- **Status**: Help message clarified
- **Reason**: 
  - Original help message "Total number of packets in the userspace ring buffer" was unclear about what the `type` label values mean
  - Users need to understand the difference between "received" and "filtered" packet types
- **Change**: Updated help message to explicitly explain label values: "Total number of packets processed from the userspace ring buffer. Labels: type=\"received\" (packets successfully received and processed), type=\"filtered\" (packets filtered out and not processed further)"
- **Labels**: `type` (received, filtered)

#### `mermin_flow_events_total` (documentation references to non-existent metrics)
- **Status**: Documentation corrected
- **Reason**: 
  - Documentation in `docs/configuration/global-options.md` referenced non-existent metrics: `mermin_flow_events_dropped_backpressure_total`, `mermin_flow_events_sampled_total`, and `mermin_flow_events_sampling_rate`
  - The actual metric is `mermin_flow_events_total` with a `type` label (values: "received", "dropped_backpressure", "dropped_error")
  - These are not separate metrics but label values on a single metric
- **Change**: Updated documentation to use correct metric name with label: `mermin_flow_events_total{type="dropped_backpressure"}` and `mermin_flow_events_total{type="dropped_error"}`

### eBPF Map Metrics Label Usage

#### `mermin_ebpf_map_entries`, `mermin_ebpf_map_capacity`, `mermin_ebpf_map_utilization_ratio`
- **Status**: Updated to use correct map names in labels
- **Reason**: 
  - These metrics already had `map` labels, but the helper function `set_map_entries()` was hardcoded to use "flow_stats" (lowercase)
  - Map names should match actual eBPF map names: "FLOW_STATS", "FLOW_EVENTS", "LISTENING_PORTS" (uppercase)
  - Added helper functions for setting capacity and utilization metrics
- **Changes**: 
  - Updated `set_map_entries()` to accept map name parameter
  - Added `set_map_entries("FLOW_STATS", entries)` helper function
  - Added `set_map_capacity(map, capacity)` helper function  
  - Added `set_map_utilization(map, utilization)` helper function
  - Updated call site in `producer.rs` to pass "FLOW_STATS" as map name
- **Note**: Capacity and utilization metrics are now available but need to be set at appropriate points in the code

#### `mermin_ringbuf_packets_total` (added status label, removed direction label)
- **Status**: Enhanced with status label, direction label removed
- **Reason**: 
  - Notes requested combining ring buffer metrics and adding status label to track success/failure
  - Initial implementation included direction label (in/out) but this was reconsidered
  - **Cannot track eBPF→ringbuf writes from userspace** (they occur in kernel space)
  - Can only track ringbuf→userspace reads from userspace code
  - Status label is still valuable to track operation outcomes
- **Changes**: 
  - **Removed** `direction` label (cannot track eBPF→ringbuf from userspace)
  - **Added** `status` label with values: "success" (read succeeded), "dropped" (packet dropped during processing), "error" (read failed)
  - Kept `type` label: "received" (successfully processed), "filtered" (filtered out)
  - Updated `inc_ringbuf_packets()` function signature: `(packet_type, status, count)`
  - Updated help message to clarify this tracks reads from ring buffer by userspace
- **Breaking Change**: Function signature changed - any existing call sites need to be updated
- **Note**: No existing call sites found, so this appears to be a new/prepared metric for future use

## Pending Implementation Tasks

### Implement eBPF Map Capacity and Utilization Tracking

The following tasks need to be completed to fully implement map capacity and utilization metrics:

#### Task 1: Set Map Capacities After eBPF Load ✅ COMPLETED
**Location**: `mermin/src/main.rs` (lines 445-451, after maps are extracted)

**Implementation**:
- [x] After `listening_ports_map` is created, added capacity metrics for all three maps:
  ```rust
  // Set eBPF map capacity metrics for monitoring utilization
  // FLOW_STATS: configurable via pipeline.ebpf_max_flows
  metrics::ebpf::set_map_capacity("FLOW_STATS", conf.pipeline.ebpf_max_flows as u64);
  // FLOW_EVENTS: 256 KB ring buffer (matches RING_BUF_SIZE_BYTES in mermin-ebpf/src/main.rs)
  metrics::ebpf::set_map_capacity("FLOW_EVENTS", 256 * 1024);
  // LISTENING_PORTS: 65536 max entries (matches HashMap definition in mermin-ebpf/src/main.rs)
  metrics::ebpf::set_map_capacity("LISTENING_PORTS", 65536);
  ```

**Notes**: 
- FLOW_STATS capacity is dynamic (from `conf.pipeline.ebpf_max_flows`)
- FLOW_EVENTS capacity is in bytes (256 KB), not entries - ring buffer semantics differ from hash maps
- LISTENING_PORTS is fixed at 65536 (all possible ports)

#### Task 2: Update Utilization When Entries Are Counted ✅ COMPLETED
**Location**: `mermin/src/span/producer.rs`

**Implementation** (Option A - pass through initialization):
- [x] Added `flow_stats_capacity: u64` field to `FlowSpanProducer` struct (line 104-105)
- [x] Initialized from `conf.pipeline.ebpf_max_flows as u64` in `new()` (line 192)
- [x] Added `flow_stats_capacity: u64` parameter to `orphan_scanner_task` function (line 1874)
- [x] Updated call site to pass `self.flow_stats_capacity` (line 265)
- [x] Added utilization calculation after setting entries (lines 1905-1911):
  ```rust
  // Update eBPF map metrics: entries count and utilization ratio
  let ebpf_map_entries = keys.len() as u64;
  metrics::ebpf::set_map_entries("FLOW_STATS", ebpf_map_entries);
  if flow_stats_capacity > 0 {
      let utilization = ebpf_map_entries as f64 / flow_stats_capacity as f64;
      metrics::ebpf::set_map_utilization("FLOW_STATS", utilization);
  }
  ```
- [x] Fixed inconsistent indentation in the metrics code section

**Notes**:
- Utilization is calculated every 5 minutes (orphan scanner interval)
- Division-by-zero protected with `if flow_stats_capacity > 0` guard
- Utilization ratio is 0.0-1.0 (e.g., 0.5 = 50% full)

#### Task 3: Track LISTENING_PORTS Map Utilization ✅ COMPLETED
**Location**: `mermin/src/main.rs` (lines 560-566, after `scan_and_populate()`)

**Implementation**:
- [x] ~~Set capacity~~ (already done in Task 1: `metrics::ebpf::set_map_capacity("LISTENING_PORTS", 65536);`)
- [x] Set entries and utilization after startup scan:
  ```rust
  // Set LISTENING_PORTS map metrics after initial scan
  // Note: This only reflects the startup state; eBPF kprobes maintain the map
  // in real-time after this, but those changes are not reflected in these metrics.
  metrics::ebpf::set_map_entries("LISTENING_PORTS", scanned_ports as u64);
  const LISTENING_PORTS_CAPACITY: u64 = 65536;
  let utilization = scanned_ports as f64 / LISTENING_PORTS_CAPACITY as f64;
  metrics::ebpf::set_map_utilization("LISTENING_PORTS", utilization);
  ```

**Design Decision / Tradeoff**:
- **Approach chosen**: Set metrics once at startup after `/proc/net/*` scan
- **Limitation**: After startup, eBPF kprobes maintain the LISTENING_PORTS map in real-time (adding/removing ports as services start/stop), but these runtime changes are **not reflected** in the metrics
- **Rationale**: 
  - Listening ports change infrequently compared to flow entries
  - Adding periodic scanning would require additional complexity (background task with map access)
  - The startup value provides a useful baseline for capacity planning
- **Future enhancement**: If real-time tracking is needed, could add periodic map scanning similar to orphan_scanner. As it is currently, this could lead to 
   a missleading metric if the listening ports are the source of the error :/

#### Task 4: Document Ring Buffer Capacity Tracking ✅ COMPLETED
**Location**: `mermin/src/metrics/registry.rs` (lines 36-52), `mermin/src/main.rs` (lines 445-451)

**Implementation**:
- [x] Updated help messages in `registry.rs` to clarify differences between hash maps and ring buffers:
  - `ebpf_map_entries`: "...For hash maps (FLOW_STATS, LISTENING_PORTS) this is the entry count. Not available for ring buffers (FLOW_EVENTS)."
  - `ebpf_map_capacity`: "...For hash maps (FLOW_STATS, LISTENING_PORTS) this is max entries. For ring buffers (FLOW_EVENTS) this is size in bytes."
  - `ebpf_map_utilization_ratio`: "...Available for hash maps (FLOW_STATS, LISTENING_PORTS). Not available for ring buffers (FLOW_EVENTS)."
- [x] Added code comment in `main.rs` explaining FLOW_EVENTS capacity semantics:
  ```rust
  // FLOW_EVENTS: 256 KB ring buffer (matches RING_BUF_SIZE_BYTES in mermin-ebpf/src/main.rs)
  // Note: Capacity is in BYTES, not entries. Ring buffers don't expose entry counts to userspace,
  // so entries/utilization metrics are not available for FLOW_EVENTS.
  ```

**Design Decision**:
- **Decision**: Skip entries/utilization tracking for ring buffers (FLOW_EVENTS)
- **Rationale**: 
  - Ring buffers don't expose a simple "entry count" to userspace like hash maps do
  - Tracking bytes written/available would require additional eBPF-side instrumentation
  - Capacity metric (256 KB) is still useful for documentation and capacity planning
  - If ring buffer overflow becomes an issue, `mermin_flow_events_total{type="dropped_backpressure"}` already tracks userspace backpressure

## Summary of eBPF Map Metrics After All Tasks

| Map | Capacity | Entries | Utilization | Notes |
|-----|----------|---------|-------------|-------|
| FLOW_STATS | ✅ Configurable (`ebpf_max_flows`) | ✅ Updated every 5 min | ✅ Updated every 5 min | Full tracking |
| LISTENING_PORTS | ✅ Fixed (65536) | ⚠️ Startup only | ⚠️ Startup only | eBPF kprobes update map at runtime but metrics don't reflect |
| FLOW_EVENTS | ✅ Fixed (256 KB in bytes) | ❌ Not available | ❌ Not available | Ring buffer, different semantics |

---

## Investigation: `ringbuf_packets_total` vs `packets_total` Discrepancy

### Problem
`ringbuf_packets_total` was observed to be 4x `packets_total` over long time periods.

### Root Causes Found

#### Issue 1: `ringbuf_packets_total` was misleadingly named
- It counted **flow events** from the ring buffer (one per NEW flow), not individual packets
- eBPF code writes to `FLOW_EVENTS` ring buffer only for NEW flows, not every packet
- This duplicated `flow_events_total{type="received"}` which tracked the same thing

#### Issue 2: `packets_total` was missing initial packets for every flow
- When a new flow is created, its initial packet counts are stored in flow span attributes
- But `inc_packets_total()` was NOT called for these initial packets
- Only subsequent DELTA packets (from periodic `record_flow()` calls) were counted
- This caused `packets_total` to be systematically undercounted

### Fixes Implemented

#### Fix 1: Add initial packet counting when flow is created ✅
**Location**: `mermin/src/span/producer.rs` (after line 1057, in `create_flow_span()`)

**Implementation**:
```rust
// Count initial packets in metrics (fixes undercounting bug where initial packets
// were stored in flow attributes but never added to the packets_total metric)
if stats.packets > 0 {
    metrics::flow::inc_packets_total(interface_name, stats.direction, stats.packets);
}
if stats.reverse_packets > 0 {
    let reverse_direction = match stats.direction {
        mermin_common::Direction::Ingress => mermin_common::Direction::Egress,
        mermin_common::Direction::Egress => mermin_common::Direction::Ingress,
    };
    metrics::flow::inc_packets_total(interface_name, reverse_direction, stats.reverse_packets);
}
```

#### Fix 2: Remove `ringbuf_packets_total` metric (replaced by `flow_events_total`) ✅

**Changes**:
1. Added `Filtered` variant to `FlowEventResult` enum in `metrics/flow.rs`
2. Removed `inc_ringbuf_packets()` calls from `producer.rs`, replaced with `inc_flow_events()`
3. Removed `RINGBUF_PACKETS_TOTAL` metric definition from `registry.rs`
4. Removed `inc_ringbuf_packets()` function and related enums from `userspace.rs`

**Migration**:
| Old Metric | New Metric |
|------------|------------|
| `ringbuf_packets_total{type="received"}` | `flow_events_total{type="received"}` |
| `ringbuf_packets_total{type="filtered"}` | `flow_events_total{type="filtered"}` |

**Note**: `flow_events_total` now has these types:
- `received` - flow events successfully processed
- `filtered` - flow events filtered out (new)
- `dropped_backpressure` - events dropped due to backpressure
- `dropped_error` - events dropped due to errors

---

## Metrics Registry Audit - Implementing Missing Metrics

### 1. Implemented `BYTES_TOTAL` (mermin_bytes_total) ✅

**Location**: `mermin/src/metrics/flow.rs`

**Implementation**:
- Added `inc_bytes_total(interface, direction, count)` helper function
- Called alongside `inc_packets_total()` in two locations in `producer.rs`:
  - When creating new flows (initial bytes)
  - In `record_flow()` when recording delta bytes

**Code added to flow.rs**:
```rust
pub fn inc_bytes_total(interface: &str, direction: Direction, count: u64) {
    registry::BYTES_TOTAL.inc_by(count);
    if registry::debug_enabled() {
        let direction_str = match direction {
            Direction::Ingress => "ingress",
            Direction::Egress => "egress",
        };
        registry::BYTES_BY_INTERFACE_TOTAL
            .with_label_values(&[interface, direction_str])
            .inc_by(count);
    }
}
```

### 2. Implemented `FLOW_STORE_SIZE` (mermin_flow_span_store_size) ✅

**Location**: `mermin/src/metrics/span.rs`

**Implementation**:
- Added `set_flow_store_size(poller_id, size)` helper function
- Called in `FlowPoller::run()` after each collection phase
- Tracks the number of flows each poller is responsible for

**Code added to span.rs**:
```rust
pub fn set_flow_store_size(poller_id: &str, size: usize) {
    registry::FLOW_STORE_SIZE
        .with_label_values(&[poller_id])
        .set(size as i64);
}
```

### 3. Implemented `FLOW_POLLER_QUEUE_SIZE` (mermin_producer_queue_size) ✅

**Location**: `mermin/src/metrics/span.rs`

**Implementation**:
- Added `set_poller_queue_size(poller_id, size)` helper function
- Called in `FlowPoller::run()` after each collection phase
- Tracks flows queued for processing (to_record + to_remove)
- Combined with `flow_span_store_size`, enables utilization calculation

**Code added to span.rs**:
```rust
pub fn set_poller_queue_size(poller_id: &str, size: usize) {
    registry::FLOW_POLLER_QUEUE_SIZE
        .with_label_values(&[poller_id])
        .set(size as i64);
}
```

**Usage in producer.rs**:
```rust
// Update flow store and queue size metrics for this poller
let poller_id_str = self.id.to_string();
metrics::span::set_flow_store_size(&poller_id_str, flows_checked);
let queue_size = flows_to_record.len() + flows_to_remove.len();
metrics::span::set_poller_queue_size(&poller_id_str, queue_size);
```

### 4. Implemented `EXPORT_TIMEOUTS_TOTAL` and `EXPORT_BLOCKING_TIME_SECONDS` ✅

**Location**: `mermin/src/metrics/export.rs`, `mermin/src/main.rs`

**Implementation**:
- Added `inc_export_timeouts()` helper function
- Added `observe_export_blocking_time(duration)` helper function
- Called in the exporter task in `main.rs`

**Code added to export.rs**:
```rust
pub fn inc_export_timeouts() {
    registry::EXPORT_TIMEOUTS_TOTAL.inc();
}

pub fn observe_export_blocking_time(duration: Duration) {
    registry::EXPORT_BLOCKING_TIME_SECONDS.observe(duration.as_secs_f64());
}
```

**Usage in main.rs**:
```rust
// Track export blocking time and timeouts
let export_start = std::time::Instant::now();
let export_result = tokio::time::timeout(Duration::from_secs(10), exporter.export(traceable)).await;
let export_duration = export_start.elapsed();
metrics::export::observe_export_blocking_time(export_duration);

if export_result.is_err() {
    metrics::export::inc_export_timeouts();
    warn!(event.name = "flow.export_timeout", "export call timed out, span may be lost");
}
```

---

## Updated Summary - All Metrics Now Implemented

| Metric | Status |
|--------|--------|
| `mermin_bytes_total` | ✅ Now implemented |
| `mermin_flow_span_store_size` | ✅ Now implemented |
| `mermin_producer_queue_size` | ✅ Now implemented |
| `mermin_export_timeouts_total` | ✅ Now implemented |
| `mermin_export_blocking_time_seconds` | ✅ Now implemented |

---

## Naming Inconsistencies Fixed ✅

Rust variable names in `registry.rs` have been renamed to match their Prometheus metric names for consistency and maintainability.

| Old Rust Variable Name | New Rust Variable Name | Prometheus Metric Name |
|------------------------|------------------------|------------------------|
| `FLOW_STORE_SIZE` | `FLOW_SPAN_STORE_SIZE` | `mermin_flow_span_store_size` |
| `FLOW_POLLER_QUEUE_SIZE` | `PRODUCER_QUEUE_SIZE` | `mermin_producer_queue_size` |
| `FLOWS_CREATED_TOTAL` | `FLOW_SPANS_CREATED_TOTAL` | `mermin_flow_spans_created_total` |
| `FLOWS_ACTIVE_TOTAL` | `FLOW_SPANS_ACTIVE_TOTAL` | `mermin_flow_spans_active_total` |
| `FLOW_STATS_ACCESS_TOTAL` | `FLOW_STATS_MAP_ACCESS_TOTAL` | `mermin_flow_stats_map_access_total` |

### Files Modified
- `mermin/src/metrics/registry.rs` - Renamed variable declarations and registration calls
- `mermin/src/metrics/flow.rs` - Updated usages of renamed variables
- `mermin/src/metrics/span.rs` - Updated usages of renamed variables

### Rationale
Having Rust variable names match their Prometheus metric names (in SCREAMING_SNAKE_CASE):
- Makes it easier to grep/search for metrics by name
- Reduces cognitive load when switching between code and Prometheus queries
- Prevents confusion about which metric a variable references

---

## High-Cardinality Metrics Moved to Debug

#### `mermin_flow_span_store_size{poller_id}` and `mermin_producer_queue_size{poller_id}`
- **Status**: Moved to debug endpoint
- **Reason**: 
  - The `poller_id` label can have up to 32 values (one per poller)
  - This creates up to 32 time series per metric, which is high-cardinality
  - These metrics are primarily useful for debugging sharded architecture issues
  - For production monitoring, aggregated flow span metrics are sufficient
- **Changes**:
  - Moved from `register_standard!` to `register_debug!` in `registry.rs`
  - Updated helper functions `set_flow_store_size()` and `set_poller_queue_size()` in `span.rs` to check `debug_enabled()` before setting
  - Updated documentation in `docs/observability/app-metrics.md` to mark as debug metrics
- **Access**: Only available via `/metrics/debug` endpoint when `metrics.debug_metrics_enabled = true`

---

## Metrics Standardization Phase 2

This section documents changes made to standardize metrics according to the 5 criteria:
1. Move all units into the metric name
2. Consolidate status-related metrics with status labels
3. Add operation labels to map/channel metrics
4. Ensure labels describe characteristics
5. Remove ringbuf metrics in favor of ebpf_map consolidation

### Criterion 1: Units in Metric Names

#### `mermin_export_batch_size` → `mermin_export_batch_spans`
- **Status**: Renamed
- **Reason**: 
  - The metric measures the number of spans in each export batch
  - "size" is ambiguous (could mean bytes, items, etc.)
  - "spans" explicitly indicates the unit being measured
- **Changes**:
  - Renamed `EXPORT_BATCH_SIZE` to `EXPORT_BATCH_SPANS` in `registry.rs`
  - Renamed helper function `observe_export_batch_size()` to `observe_export_batch_spans()` in `export.rs`
  - Updated call site in `otlp/metrics_exporter.rs`
- **Migration**: `mermin_export_batch_size` → `mermin_export_batch_spans`

### Criterion 2: Consolidate Status-Related Metrics

#### Task Lifecycle Counters Consolidated
- **Status**: Consolidated 4 metrics into 1
- **Reason**: 
  - All 4 metrics track task lifecycle events, differing only by outcome
  - Consolidating into a single metric with `status` label enables easier querying
  - `status=spawned` count should equal sum of other statuses over time (for debugging)
- **Old Metrics**:
  - `mermin_tasks_spawned_total`
  - `mermin_tasks_completed_total`
  - `mermin_tasks_cancelled_total`
  - `mermin_tasks_panicked_total`
- **New Metric**: `mermin_tasks_total{status}` where status = spawned | completed | cancelled | panicked
- **Changes**:
  - Replaced 4 `IntCounter` metrics with 1 `IntCounterVec` in `registry.rs`
  - Updated all call sites in `runtime/task_manager.rs` to use status labels
  - Updated `remove_task_metrics()` to clean up all status variants
- **Debug Metrics**:
  - Old: `mermin_tasks_spawned_by_name_total`, `mermin_tasks_completed_by_name_total`, etc.
  - New: `mermin_tasks_by_name_total{task_name, status}`
- **Unchanged**: `mermin_tasks_active_total` and `mermin_tasks_active_by_name_total` remain as gauges (they track current state, not lifecycle events)
- **Migration**:
  | Old Metric | New Metric |
  |------------|------------|
  | `mermin_tasks_spawned_total` | `mermin_tasks_total{status="spawned"}` |
  | `mermin_tasks_completed_total` | `mermin_tasks_total{status="completed"}` |
  | `mermin_tasks_cancelled_total` | `mermin_tasks_total{status="cancelled"}` |
  | `mermin_tasks_panicked_total` | `mermin_tasks_total{status="panicked"}` |

#### Shutdown Flow Counters Consolidated
- **Status**: Consolidated 2 metrics into 1
- **Reason**: 
  - Both metrics track flow outcomes during shutdown, differing only by result
  - Consolidating allows querying total shutdown flows easily: `sum(mermin_shutdown_flows_total)`
- **Old Metrics**:
  - `mermin_flows_preserved_shutdown_total`
  - `mermin_flows_lost_shutdown_total`
- **New Metric**: `mermin_shutdown_flows_total{status}` where status = preserved | lost
- **Changes**:
  - Replaced 2 `IntCounter` metrics with 1 `IntCounterVec` in `registry.rs`
  - Updated `runtime/shutdown.rs` to use status labels
  - Updated `docs/configuration/global-options.md` documentation
- **Migration**:
  | Old Metric | New Metric |
  |------------|------------|
  | `mermin_flows_preserved_shutdown_total` | `mermin_shutdown_flows_total{status="preserved"}` |
  | `mermin_flows_lost_shutdown_total` | `mermin_shutdown_flows_total{status="lost"}` |

#### K8s Watcher Errors Merged into Events
- **Status**: Consolidated 2 metrics into existing metric
- **Reason**: 
  - Errors are just another type of watcher event
  - Consolidating allows querying all watcher activity with one metric
  - Enables queries like `sum by (event_type) (rate(mermin_k8s_watcher_events_total[5m]))`
- **Old Metrics**:
  - `mermin_k8s_watcher_errors_total` (separate counter)
  - `mermin_k8s_watcher_errors_by_resource_total{resource}` (debug, separate counter)
- **New**: Added `event_type="error"` to existing `mermin_k8s_watcher_events_total`
- **Changes**:
  - Removed `K8S_WATCHER_ERRORS_TOTAL` and `K8S_WATCHER_ERRORS_BY_RESOURCE_TOTAL` from `registry.rs`
  - Updated `k8s/attributor.rs` to use `K8S_WATCHER_EVENTS_TOTAL{event_type="error"}`
  - Updated `remove_k8s_resource_metrics()` to include "error" event_type
- **Event Types**: apply, delete, init, init_done, error
- **Migration**:
  | Old Metric | New Metric |
  |------------|------------|
  | `mermin_k8s_watcher_errors_total` | `mermin_k8s_watcher_events_total{event_type="error"}` |
  | `mermin_k8s_watcher_errors_by_resource_total{resource="X"}` | `mermin_k8s_watcher_events_by_resource_total{resource="X", event_type="error"}` |

### Criterion 3: Operation Labels for Maps/Channels

#### FLOW_STATS_MAP_ACCESS → EBPF_MAP_OPERATIONS with Full Instrumentation
- **Status**: Generalized and expanded
- **Reason**: 
  - Original metric only tracked FLOW_STATS reads with status
  - Generalized to track all eBPF map operations: reads, writes, deletes
  - Supports multiple maps: FLOW_STATS, LISTENING_PORTS
  - Enables comprehensive eBPF map observability
- **Old Metric**: `mermin_flow_stats_map_access_total{status}`
- **New Metric**: `mermin_ebpf_map_operations_total{map, operation, status}`
- **Labels**:
  - `map`: FLOW_STATS, LISTENING_PORTS
  - `operation`: read, write, delete
  - `status`: ok, error, not_found
- **Changes**:
  - Renamed `FLOW_STATS_MAP_ACCESS_TOTAL` to `EBPF_MAP_OPERATIONS_TOTAL` in `registry.rs`
  - Added `EbpfMapName`, `EbpfMapOperation`, `EbpfMapStatus` enums to `ebpf.rs`
  - Added `inc_map_operation()` helper function
  - Removed `FlowStatsStatus` enum and `inc_flow_stats_map_access()` from `flow.rs`
  - Updated all existing FLOW_STATS read tracking in `producer.rs`
  - Added new FLOW_STATS write tracking (metadata reset)
  - Added new FLOW_STATS delete tracking (tunneled, filtered, timeout flows)
  - Added LISTENING_PORTS write tracking in `listening_ports.rs`
- **Not Tracked** (by design):
  - LISTENING_PORTS reads (high volume, direction detection on every flow)
  - Orphan scanner deletes (kept as separate `ebpf_orphans_cleaned_total` metric)
- **Migration**:
  | Old Metric | New Metric |
  |------------|------------|
  | `mermin_flow_stats_map_access_total{status="ok"}` | `mermin_ebpf_map_operations_total{map="FLOW_STATS", operation="read", status="ok"}` |
  | `mermin_flow_stats_map_access_total{status="error"}` | `mermin_ebpf_map_operations_total{map="FLOW_STATS", operation="read", status="error"}` |
  | `mermin_flow_stats_map_access_total{status="not_found"}` | `mermin_ebpf_map_operations_total{map="FLOW_STATS", operation="read", status="not_found"}` |

### Criterion 4: Labels Describe Characteristics

#### FLOW_EVENTS_TOTAL Label Renamed: `type` → `status`
- **Status**: Label renamed
- **Reason**: 
  - The label values (received, filtered, dropped_backpressure, dropped_error) describe outcomes/statuses, not types
  - Consistent with other metrics that use `status` for outcome labels
  - More semantically accurate
- **Old**: `mermin_flow_events_total{type="X"}`
- **New**: `mermin_flow_events_total{status="X"}`
- **Label Values** (unchanged): received, filtered, dropped_backpressure, dropped_error
- **Changes**:
  - Updated label name in `registry.rs` from `&["type"]` to `&["status"]`
  - Updated documentation in `docs/configuration/global-options.md`
- **Migration**:
  | Old Metric | New Metric |
  |------------|------------|
  | `mermin_flow_events_total{type="received"}` | `mermin_flow_events_total{status="received"}` |
  | `mermin_flow_events_total{type="filtered"}` | `mermin_flow_events_total{status="filtered"}` |
  | `mermin_flow_events_total{type="dropped_backpressure"}` | `mermin_flow_events_total{status="dropped_backpressure"}` |
  | `mermin_flow_events_total{type="dropped_error"}` | `mermin_flow_events_total{status="dropped_error"}` |

### Criterion 5: Consolidate Ring Buffer Metrics with eBPF Map Metrics

#### RINGBUF_BYTES_TOTAL → EBPF_MAP_BYTES_TOTAL
- **Status**: Migrated to eBPF map metrics namespace
- **Reason**: 
  - Groups all eBPF-related metrics together for easier discovery
  - FLOW_EVENTS is an eBPF ring buffer, logically part of eBPF subsystem
  - Consistent naming with other `ebpf_map_*` metrics
- **Old Metric**: `mermin_ringbuf_bytes_total` (no labels)
- **New Metric**: `mermin_ebpf_map_bytes_total{map="FLOW_EVENTS"}`
- **Changes**:
  - Renamed `RINGBUF_BYTES_TOTAL` to `EBPF_MAP_BYTES_TOTAL` in `registry.rs`
  - Added `map` label to support future byte tracking for other maps
  - Added `FlowEvents` variant to `EbpfMapName` enum in `ebpf.rs`
  - Added `inc_map_bytes()` helper function in `ebpf.rs`
  - Removed `inc_ringbuf_bytes()` from `userspace.rs`
  - Updated call site in `producer.rs`
- **Migration**:
  | Old Metric | New Metric |
  |------------|------------|
  | `mermin_ringbuf_bytes_total` | `mermin_ebpf_map_bytes_total{map="FLOW_EVENTS"}` |

---

## Removed "active" Status from Producer Flow Spans Metric

#### `mermin_producer_flow_spans_total{status="active"}` - Status Removed
- **Status**: Removed from tracking
- **Reason**: 
  - The "active" status was being incremented when flows were created, but could never be decremented
  - `PRODUCER_FLOW_SPANS_TOTAL` is an `IntCounterVec` (counter), which cannot be decremented in Prometheus
  - This created misleading metrics where "active" would only increase, never decrease
  - Active flow tracking is already properly handled by `mermin_flow_spans_active_total` (a gauge that can be incremented/decremented)
- **Changes**:
  - Removed `inc_producer_flow_spans(interface, FlowSpanProducerStatus::Active)` call from flow creation in `producer.rs`
  - Removed "active" label value cleanup from `remove_interface_metrics()` in `registry.rs`
  - The `FlowSpanProducerStatus::Active` enum variant remains for backwards compatibility but is no longer used
- **Replacement**: Use `mermin_flow_spans_active_total` (gauge) to track current number of active flows
- **Migration**: 
  - Old: `mermin_producer_flow_spans_total{status="active"}` (misleading, only incremented)
  - New: `mermin_flow_spans_active_total` (accurate gauge that tracks current state)

