#!/bin/bash
echo "=== eBPF Call Chain Analysis ==="

# Force a fresh build and capture the result
echo "🔄 Building eBPF program..."
BUILD_RESULT=$(docker run --privileged --mount type=bind,source=.,target=/app mermin-builder:latest /bin/bash -c "cargo build --release" 2>&1)
BUILD_EXIT_CODE=$?

if [ $BUILD_EXIT_CODE -ne 0 ]; then
    echo "❌ Build failed!"
    echo "$BUILD_RESULT"
    exit 1
fi

# Find the eBPF binary
EBPF_BINARY=$(docker run --privileged --mount type=bind,source=.,target=/app mermin-builder:latest /bin/bash -c "find target -name 'mermin' -path '*/mermin-ebpf/*' -path '*/bpfel-unknown-none/release/*' | head -1")

if [ -z "$EBPF_BINARY" ]; then
    echo "❌ No eBPF binary found!"
    exit 1
fi

# Show what we're analyzing for transparency
echo "📍 Analyzing binary: $EBPF_BINARY"
BINARY_INFO=$(ls -l "$EBPF_BINARY" 2>/dev/null || echo "Binary info not available locally")
echo "📅 Binary timestamp: $BINARY_INFO"
echo ""

# Analyze function calls
echo "📞 Function Calls Found:"
FUNCTION_CALLS=$(docker run --privileged --mount type=bind,source=.,target=/app mermin-builder:latest /bin/bash -c "llvm-objdump-20 -d --section=classifier ${EBPF_BINARY} | grep -E 'call.*0x[0-9a-f]+' | grep -v 'call -0x'")

if [ -z "$FUNCTION_CALLS" ]; then
    echo "  ✅ No user function calls found (only eBPF helpers)"
    echo "  📋 eBPF helper calls found:"
    docker run --privileged --mount type=bind,source=.,target=/app mermin-builder:latest /bin/bash -c "llvm-objdump-20 -d --section=classifier ${EBPF_BINARY} | grep -E 'call.*-0x'" | head -3
else
    echo "$FUNCTION_CALLS" | head -5
    if [ $(echo "$FUNCTION_CALLS" | wc -l) -gt 5 ]; then
        echo "  ... and $(($(echo "$FUNCTION_CALLS" | wc -l) - 5)) more function calls"
    fi
fi

echo ""

# Analyze stack usage
echo "📊 Stack Usage Analysis:"
STACK_OFFSETS=$(docker run --privileged --mount type=bind,source=.,target=/app mermin-builder:latest /bin/bash -c "llvm-objdump-20 -d --section=classifier ${EBPF_BINARY} | grep -oE 'r10.*-.*0x[0-9a-f]+' | sed 's/.*-.*0x//' | sort -nr | uniq")

if [ -z "$STACK_OFFSETS" ]; then
    echo "  🎉 NO STACK USAGE FOUND!"
else
    MAX_STACK_HEX=$(echo "$STACK_OFFSETS" | head -1)
    MAX_STACK_DECIMAL=$((0x${MAX_STACK_HEX}))
    
    echo "  🎯 Maximum individual stack: ${MAX_STACK_DECIMAL} bytes (0x${MAX_STACK_HEX})"
    
    # Provide clear assessment
    if [ $MAX_STACK_DECIMAL -le 32 ]; then
        echo "  🎉 EXCELLENT: Minimal stack usage!"
    elif [ $MAX_STACK_DECIMAL -le 192 ]; then
        echo "  ✅ GOOD: Low stack usage"
    elif [ $MAX_STACK_DECIMAL -le 320 ]; then
        echo "  ⚠️ WARNING: Moderate stack usage - monitor call depth"
    else
        echo "  🔥 CRITICAL: High stack usage - likely to cause cumulative overflow!"
    fi
    
    echo "  📈 All stack levels:"
    echo "$STACK_OFFSETS" | head -5 | while read hex; do
        if [ ! -z "$hex" ]; then
            decimal=$((0x$hex))
            echo "    • $decimal bytes (0x$hex)"
        fi
    done
fi

echo ""
echo "💡 Understanding Results:"
if [ -z "$FUNCTION_CALLS" ] && [ -z "$STACK_OFFSETS" ]; then
    echo "   ✅ Your eBPF program is extremely lightweight!"
    echo "   ✅ No risk of cumulative stack overflow"
    echo "   ✅ Should pass eBPF verifier easily"
elif [ -z "$FUNCTION_CALLS" ] && [ ! -z "$STACK_OFFSETS" ] && [ $MAX_STACK_DECIMAL -lt 50 ]; then
    echo "   ✅ Your eBPF program is extremely lightweight!"
    echo "   ✅ No risk of cumulative stack overflow"
    echo "   ✅ Should pass eBPF verifier easily"
else
    echo "   1. Look for call sequences like: call 0x1 → call 0x1a → (leaf)"
    echo "   2. Find stack usage near each call: r10 - 0xXX"
    echo "   3. Add them up: Stack_A + Stack_B + Stack_C = Total"
    echo "   4. If Total > 512 bytes → Verifier failure"
fi