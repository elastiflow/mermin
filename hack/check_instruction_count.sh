#!/bin/bash
echo "🔄 Building and analyzing eBPF instruction count..."

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
echo ""

# Get instruction counts for each section
echo "📊 Instruction count by section:"
echo "================================"

# Analyze .text section (main program logic)
TEXT_INSTRUCTIONS=$(docker run --privileged --mount type=bind,source=.,target=/app mermin-builder:latest /bin/bash -c "llvm-objdump-20 -d --section=.text ${EBPF_BINARY} 2>/dev/null | grep -E '^\s+[0-9a-f]+:' | wc -l")
echo ".text section:        ${TEXT_INSTRUCTIONS} instructions"

# Analyze classifier section (TC classifier)
CLASSIFIER_INSTRUCTIONS=$(docker run --privileged --mount type=bind,source=.,target=/app mermin-builder:latest /bin/bash -c "llvm-objdump-20 -d --section=classifier ${EBPF_BINARY} 2>/dev/null | grep -E '^\s+[0-9a-f]+:' | wc -l")
if [ "$CLASSIFIER_INSTRUCTIONS" != "0" ]; then
    echo "classifier section:   ${CLASSIFIER_INSTRUCTIONS} instructions"
fi

# Get all sections
echo ""
echo "📋 All sections in binary:"
docker run --privileged --mount type=bind,source=.,target=/app mermin-builder:latest /bin/bash -c "llvm-objdump-20 --section-headers ${EBPF_BINARY} 2>/dev/null | grep -E '^\s*[0-9]+\s+\.'"

# Calculate total from all code sections
TOTAL_INSTRUCTIONS=$(docker run --privileged --mount type=bind,source=.,target=/app mermin-builder:latest /bin/bash -c "llvm-objdump-20 -d ${EBPF_BINARY} 2>/dev/null | grep -E '^\s+[0-9a-f]+:' | wc -l")

echo ""
echo "================================"
echo "📊 TOTAL INSTRUCTIONS: ${TOTAL_INSTRUCTIONS}"
echo "================================"

# Check against limits
# Note: The verifier limit is 1 million instructions for kernels 5.2+
# Earlier kernels had lower limits (4096)
if [ "$TOTAL_INSTRUCTIONS" -gt 500000 ]; then
    echo "⚠️  WARNING: Very high instruction count - approaching limits"
elif [ "$TOTAL_INSTRUCTIONS" -gt 100000 ]; then
    echo "⚠️  WARNING: High instruction count - monitor complexity"
elif [ "$TOTAL_INSTRUCTIONS" -gt 50000 ]; then
    echo "✅ GOOD: Moderate instruction count"
else
    echo "✅ EXCELLENT: Low instruction count"
fi

echo ""
echo "💡 NOTE: Modern kernels (5.2+) allow up to 1M instructions per program."
echo "   Complex programs with many helper calls will have higher counts."
echo "   If you see verifier failures, try simplifying logic or splitting programs."
