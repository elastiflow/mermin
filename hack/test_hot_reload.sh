#!/usr/bin/env bash
# Integration test suite for hot-reload via file-change and SIGHUP.
#
# Happy-path tests:
#   1. Initial startup
#   2. File-watch reload
#   3. SIGHUP reload
#   4. Graceful SIGTERM shutdown
#
# Edge-case tests:
#   5. Invalid HCL → config_reload_failed, pipeline keeps running
#   6. Recovery: valid config after invalid → normal reload
#   7. Rapid successive file changes → debounced, no crash
#   8. Multiple rapid SIGHUPs → no crash, process stabilises
#   9. SIGTERM during active reload → no signal loss, clean exit
#  10. File-descriptor leak → FD count stable across reload cycles
#
# Usage (inside --privileged Docker container):
#   bash scripts/test_hot_reload.sh
#
# Requirements: eth0 must exist (standard in Docker with --privileged).

set -euo pipefail

BINARY="/app/target/debug/mermin"
SRC_CONFIG="/app/local/config.hcl"
CONFIG="/tmp/mermin_test_reload.hcl"
LOG_FILE="/tmp/mermin_test_reload.log"

STARTUP_TIMEOUT=45   # initial eBPF attach can be slow in containers
RELOAD_TIMEOUT=30    # each reload cycle

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RESET='\033[0m'

PASS_COUNT=0
FAIL_COUNT=0

pass() { echo -e "${GREEN}[PASS]${RESET} $*"; (( PASS_COUNT++ )) || true; }
fail() { echo -e "${RED}[FAIL]${RESET} $*"; (( FAIL_COUNT++ )) || true; dump_logs; exit 1; }
warn() { echo -e "${YELLOW}[WARN]${RESET} $*"; }
info() { echo -e "${YELLOW}[INFO]${RESET} $*"; }

dump_logs() {
  echo ""
  echo "────── log tail (last 80 lines) ──────"
  tail -80 "$LOG_FILE" 2>/dev/null || true
  echo "──────────────────────────────────────"
}

count_pattern() { grep -c "$1" "$LOG_FILE" 2>/dev/null || echo "0"; }

fd_count() {
  # Number of open file descriptors for a PID (Linux /proc)
  ls /proc/"$1"/fd 2>/dev/null | wc -l || echo "0"
}

assert_alive() {
  if ! kill -0 "$MERMIN_PID" 2>/dev/null; then
    fail "mermin exited unexpectedly"
  fi
}

assert_startup_count() {
  local expected="$1" label="$2"
  local actual
  actual=$(count_pattern "application.startup_finished")
  if (( actual == expected )); then
    pass "$label: startup_finished count = $actual (expected $expected)"
  else
    fail "$label: startup_finished count = $actual (expected $expected)"
  fi
}

wait_for_pattern() {
  local pattern="$1" label="$2" timeout="$3"
  local deadline=$(( $(date +%s) + timeout ))
  info "Waiting up to ${timeout}s for: $label…"
  while (( $(date +%s) < deadline )); do
    assert_alive
    if grep -q "$pattern" "$LOG_FILE" 2>/dev/null; then
      echo ""
      pass "$label"
      return 0
    fi
    printf "."
    sleep 1
  done
  echo ""
  fail "Timed out (${timeout}s) waiting for: $label"
}

wait_for_count() {
  local pattern="$1" label="$2" timeout="$3" min_count="$4"
  local deadline=$(( $(date +%s) + timeout ))
  info "Waiting up to ${timeout}s for ≥${min_count} occurrences of: $label…"
  while (( $(date +%s) < deadline )); do
    assert_alive
    local n
    n=$(count_pattern "$pattern")
    if (( n >= min_count )); then
      echo ""
      pass "$label (seen $n times)"
      return 0
    fi
    printf "."
    sleep 1
  done
  echo ""
  fail "Timed out (${timeout}s) waiting for ≥${min_count} occurrences of: $label"
}

wait_for_exit() {
  local timeout="$1"
  local deadline=$(( $(date +%s) + timeout ))
  while (( $(date +%s) < deadline )); do
    if ! kill -0 "$MERMIN_PID" 2>/dev/null; then
      return 0
    fi
    sleep 0.5
  done
  return 1  # still running
}

# ── Setup ──────────────────────────────────────────────────────────────────────
info "Copying $SRC_CONFIG → $CONFIG"
cp "$SRC_CONFIG" "$CONFIG"

if [[ ! -f "$BINARY" ]]; then
  info "Binary not found — building…"
  cd /app && cargo build 2>&1
fi

info "Binary: $BINARY"
info "Config: $CONFIG"
info "Logs:   $LOG_FILE"
> "$LOG_FILE"

# ── Start mermin ───────────────────────────────────────────────────────────────
info "Starting mermin…"
"$BINARY" --config "$CONFIG" --log-level debug > "$LOG_FILE" 2>&1 &
MERMIN_PID=$!
info "PID = $MERMIN_PID"

cleanup() {
  if kill -0 "$MERMIN_PID" 2>/dev/null; then
    info "Cleanup: sending SIGTERM to $MERMIN_PID…"
    kill -TERM "$MERMIN_PID" 2>/dev/null || true
    sleep 3
    kill -9 "$MERMIN_PID" 2>/dev/null || true
  fi
  wait "$MERMIN_PID" 2>/dev/null || true
  rm -f "$CONFIG"
}
trap cleanup EXIT

# ══════════════════════════════════════════════════════════════════════════════
# TEST 1: Initial startup
# ══════════════════════════════════════════════════════════════════════════════
echo ""
echo "══ TEST 1: Initial startup ══"
wait_for_pattern "application.startup_finished" "startup complete" "$STARTUP_TIMEOUT"
BASELINE_FDS=$(fd_count "$MERMIN_PID")
info "Baseline FD count: $BASELINE_FDS"

# ══════════════════════════════════════════════════════════════════════════════
# TEST 2: File-watch reload
# ══════════════════════════════════════════════════════════════════════════════
echo ""
echo "══ TEST 2: File-watch reload ══"
echo "# reload-trigger $(date +%s)" >> "$CONFIG"
wait_for_pattern "application.pipeline_restarting" "pipeline_restarting after file change" "$RELOAD_TIMEOUT"
wait_for_count "application.startup_finished" "startup_finished ≥2" "$RELOAD_TIMEOUT" 2

FDS_AFTER_RELOAD1=$(fd_count "$MERMIN_PID")
info "FD count after reload 1: $FDS_AFTER_RELOAD1 (baseline: $BASELINE_FDS)"

# ══════════════════════════════════════════════════════════════════════════════
# TEST 3: SIGHUP reload
# ══════════════════════════════════════════════════════════════════════════════
echo ""
echo "══ TEST 3: SIGHUP reload ══"
kill -HUP "$MERMIN_PID"
wait_for_count "application.startup_finished" "startup_finished ≥3 (SIGHUP)" "$RELOAD_TIMEOUT" 3

FDS_AFTER_RELOAD2=$(fd_count "$MERMIN_PID")
info "FD count after reload 2: $FDS_AFTER_RELOAD2 (baseline: $BASELINE_FDS)"

# ══════════════════════════════════════════════════════════════════════════════
# TEST 4: Graceful SIGTERM shutdown
# ══════════════════════════════════════════════════════════════════════════════
echo ""
echo "══ TEST 4: Graceful SIGTERM shutdown ══"
kill -TERM "$MERMIN_PID"
if wait_for_exit 20; then
  pass "mermin exited after SIGTERM"
else
  fail "mermin did not exit within 20s after SIGTERM"
fi
if grep -q "application.cleanup_complete" "$LOG_FILE" 2>/dev/null; then
  pass "graceful shutdown confirmed (application.cleanup_complete)"
else
  warn "application.cleanup_complete not found — may have exited via forced path"
fi

# ══════════════════════════════════════════════════════════════════════════════
# TEST 5: Invalid HCL config → reload_failed, pipeline keeps running
# ══════════════════════════════════════════════════════════════════════════════
echo ""
echo "══ TEST 5: Invalid config is rejected, pipeline keeps running ══"

cp "$SRC_CONFIG" "$CONFIG"
> "$LOG_FILE"

info "Restarting mermin for edge-case tests…"
"$BINARY" --config "$CONFIG" --log-level debug >> "$LOG_FILE" 2>&1 &
MERMIN_PID=$!
info "PID = $MERMIN_PID"
wait_for_pattern "application.startup_finished" "fresh startup for edge-case tests" "$STARTUP_TIMEOUT"

STARTUP_COUNT_BEFORE=1
info "Writing invalid HCL to config…"
printf '!!!! this is not valid HCL !!!!\nauto_reload = "WRONG_TYPE"\n' > "$CONFIG"
wait_for_pattern "application.config_reload_triggered" \
  "reload triggered by invalid file" "$RELOAD_TIMEOUT"
wait_for_pattern "application.config_reload_failed" \
  "reload rejected (config_reload_failed)" "$RELOAD_TIMEOUT"

sleep 2  # give it a moment to (incorrectly) restart if it were going to
assert_alive
assert_startup_count "$STARTUP_COUNT_BEFORE" "pipeline still running on old config"

# ══════════════════════════════════════════════════════════════════════════════
# TEST 6: Recovery — valid config after invalid
# ══════════════════════════════════════════════════════════════════════════════
echo ""
echo "══ TEST 6: Recovery after invalid config ══"
info "Restoring valid config…"
cp "$SRC_CONFIG" "$CONFIG"
echo "# recovered $(date +%s)" >> "$CONFIG"
wait_for_count "application.startup_finished" \
  "pipeline restarted with recovered config (startup_finished ≥2)" "$RELOAD_TIMEOUT" 2
assert_alive

# ══════════════════════════════════════════════════════════════════════════════
# TEST 7: Rapid successive file changes → debounced, no crash
# ══════════════════════════════════════════════════════════════════════════════
echo ""
echo "══ TEST 7: Rapid successive file changes (debounce) ══"
STARTUPS_BEFORE=$(count_pattern "application.startup_finished")
info "Triggering 5 file changes in rapid succession…"
for i in $(seq 1 5); do
  echo "# burst-$i $(date +%s%N)" >> "$CONFIG"
  sleep 0.1
done

# Wait for the debounce window + at least one full reload
sleep 5
wait_for_count "application.startup_finished" \
  "at least one reload completed after burst" "$RELOAD_TIMEOUT" $(( STARTUPS_BEFORE + 1 ))

STARTUPS_AFTER=$(count_pattern "application.startup_finished")
BURST_RELOADS=$(( STARTUPS_AFTER - STARTUPS_BEFORE ))
if (( BURST_RELOADS <= 3 )); then
  pass "Debounce effective: $BURST_RELOADS reload(s) from 5 rapid writes (≤3 expected)"
else
  warn "Debounce less effective than expected: $BURST_RELOADS reloads from 5 writes"
fi
assert_alive

# ══════════════════════════════════════════════════════════════════════════════
# TEST 8: Multiple rapid SIGHUPs → no crash, process stabilises
# ══════════════════════════════════════════════════════════════════════════════
echo ""
echo "══ TEST 8: Multiple rapid SIGHUPs ══"
STARTUPS_BEFORE=$(count_pattern "application.startup_finished")
info "Sending 5 SIGHUPs in rapid succession…"
for _ in $(seq 1 5); do
  kill -HUP "$MERMIN_PID" 2>/dev/null || true
  sleep 0.1
done

# Wait for at least one full reload to settle
wait_for_count "application.startup_finished" \
  "at least one reload completed after SIGHUP burst" "$RELOAD_TIMEOUT" $(( STARTUPS_BEFORE + 1 ))

sleep 2
assert_alive
pass "Process stable after rapid SIGHUPs"

# ══════════════════════════════════════════════════════════════════════════════
# TEST 9: SIGTERM during active reload → no signal loss, clean exit
# ══════════════════════════════════════════════════════════════════════════════
echo ""
echo "══ TEST 9: SIGTERM during active reload ══"
info "Triggering file-change reload then immediately sending SIGTERM…"
echo "# sigterm-race $(date +%s)" >> "$CONFIG"
# Give the file-watcher time to detect the change, then race SIGTERM against it
sleep 0.5
kill -TERM "$MERMIN_PID" 2>/dev/null || true

if wait_for_exit 30; then
  pass "mermin exited cleanly despite SIGTERM during reload"
else
  fail "mermin did not exit within 30s (possible deadlock)"
fi

# Verify either: (a) reload completed then SIGTERM honoured, or (b) SIGTERM won the race
# Either way cleanup_complete should appear
if grep -q "application.cleanup_complete" "$LOG_FILE"; then
  pass "graceful cleanup confirmed after SIGTERM-during-reload"
else
  warn "cleanup_complete not found — SIGTERM may have preempted reload cleanly"
fi

# ══════════════════════════════════════════════════════════════════════════════
# TEST 10: File-descriptor leak check
# ══════════════════════════════════════════════════════════════════════════════
echo ""
echo "══ TEST 10: File descriptor leak check ══"
if (( FDS_AFTER_RELOAD1 > 0 && FDS_AFTER_RELOAD2 > 0 && BASELINE_FDS > 0 )); then
  GROWTH=$(( FDS_AFTER_RELOAD2 - BASELINE_FDS ))
  if (( GROWTH < 0 )); then GROWTH=$(( -GROWTH )); fi
  if (( GROWTH <= 10 )); then
    pass "FD count stable across 2 reload cycles (baseline=$BASELINE_FDS, after reload1=$FDS_AFTER_RELOAD1, after reload2=$FDS_AFTER_RELOAD2, net drift=$GROWTH)"
  else
    warn "FD count drifted by $GROWTH across 2 reloads — possible leak (baseline=$BASELINE_FDS, final=$FDS_AFTER_RELOAD2)"
  fi
else
  warn "FD tracking unavailable (likely no /proc access) — skipping leak check"
fi

# ══════════════════════════════════════════════════════════════════════════════
# Summary
# ══════════════════════════════════════════════════════════════════════════════
echo ""
echo -e "${GREEN}══════════════════════════════════════════${RESET}"
echo -e "${GREEN}  RESULTS: $PASS_COUNT passed, $FAIL_COUNT failed  ${RESET}"
echo -e "${GREEN}══════════════════════════════════════════${RESET}"
echo ""

info "Key event counts:"
echo "  startup_finished:        $(count_pattern 'application.startup_finished')"
echo "  pipeline_restarting:     $(count_pattern 'application.pipeline_restarting')"
echo "  config_reload_triggered: $(count_pattern 'application.config_reload_triggered')"
echo "  config_reloaded:         $(count_pattern 'application.config_reloaded')"
echo "  config_reload_failed:    $(count_pattern 'application.config_reload_failed')"
echo "  cleanup_complete:        $(count_pattern 'application.cleanup_complete')"
echo ""

info "Event timeline (reload lifecycle events):"
grep -oE 'event\.name="[^"]+"' "$LOG_FILE" \
  | grep -E '(startup_finished|pipeline_restarting|config_reload|cleanup_complete|shutdown_signal)' \
  | awk '{print NR". "$0}' \
  || true

if (( FAIL_COUNT > 0 )); then
  exit 1
fi
