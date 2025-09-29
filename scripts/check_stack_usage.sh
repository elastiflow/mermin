#!/bin/bash
echo "Building and analyzing eBPF stack usage..."
docker run --privileged --mount type=bind,source=.,target=/app mermin-builder:latest /bin/bash -c "cargo build --release"

EBPF_BINARY=$(docker run --privileged --mount type=bind,source=.,target=/app mermin-builder:latest /bin/bash -c "find target -name 'mermin' -path '*/mermin-ebpf/*' -path '*/bpfel-unknown-none/release/*' | head -1")

MAX_STACK=$(docker run --privileged --mount type=bind,source=.,target=/app mermin-builder:latest /bin/bash -c "llvm-objdump-20 -d --section=classifier ${EBPF_BINARY} | grep -oE 'r10.*-.*0x[0-9a-f]+' | sed 's/.*-.*0x//' | sort -nr | head -1")

if [ ! -z "$MAX_STACK" ]; then
    DECIMAL_STACK=$((0x${MAX_STACK}))
    echo "📊 Individual function max stack: ${DECIMAL_STACK} bytes (0x${MAX_STACK})"
    
    if [ $DECIMAL_STACK -gt 320 ]; then
        echo "🔥 CRITICAL: Very high individual stack usage - will likely cause cumulative overflow!"
    elif [ $DECIMAL_STACK -gt 192 ]; then
        echo "⚠️  WARNING: High individual stack usage - monitor call chain depth"
    else
        echo "✅ GOOD: Individual stack usage within safe limits"
    fi
    
    echo ""
    echo "⚠️  IMPORTANT: This measures individual functions only."
    echo "   Verifier failures like 'combined stack size...544. Too large'"
    echo "   are CUMULATIVE across function call chains."
else
    echo "❌ Could not analyze stack usage"
fi