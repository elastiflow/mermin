#!/bin/bash
echo "🔄 Building and analyzing eBPF stack usage..."

# Force a fresh build and capture the result
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
echo "📍 Analyzing: $EBPF_BINARY"

# Get the maximum stack usage from .text section where the actual program logic is
MAX_STACK=$(docker run --privileged --mount type=bind,source=.,target=/app mermin-builder:latest /bin/bash -c "llvm-objdump-20 -d --section=.text ${EBPF_BINARY} | grep -oE 'r10.*-.*0x[0-9a-fA-F]+' | sed 's/.*-.*0x//' | sort -nr | head -1")

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
    echo "💡 NOTE: This measures individual functions only."
    echo "   Verifier failures like 'combined stack size...544. Too large'"
    echo "   are CUMULATIVE across function call chains."
else
    echo "🎉 NO STACK USAGE FOUND!"
    echo "   Your eBPF program uses minimal stack space."
    echo "   This is excellent for eBPF verifier compatibility!"
fi