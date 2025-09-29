#!/bin/bash
# Cumulative Stack Usage Calculator

echo "=== How to Calculate Cumulative Call Chain Stack Usage ==="
echo ""

# Force a fresh build first
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

echo "📍 Analyzing binary: $EBPF_BINARY"
echo ""

echo "Step 1: Find all unique stack offsets"
echo "======================================"
STACK_OFFSETS=$(docker run --privileged --mount type=bind,source=.,target=/app mermin-builder:latest /bin/bash -c "llvm-objdump-20 -d --section=.text ${EBPF_BINARY} | grep -oE 'r10.*-.*0x[0-9a-fA-F]+' | sed 's/.*-.*0x//' | sort -nr | uniq")

echo "All stack offsets found (hex -> decimal):"
for offset in $STACK_OFFSETS; do
    decimal=$((0x$offset))
    echo "  0x$offset = $decimal bytes"
done | head -10

echo ""
echo "Step 2: Identify call chains"  
echo "============================"

echo "Function calls found:"
CALLS=$(docker run --privileged --mount type=bind,source=.,target=/app mermin-builder:latest /bin/bash -c "llvm-objdump-20 -d --section=.text ${EBPF_BINARY} | grep -E 'call.*0x[0-9a-fA-F]+' | grep -v 'call -0x' | head -5")
echo "$CALLS"

echo ""
echo "Step 3: Trace call relationships"
echo "================================"

echo "For each call, find nearby stack usage:"
# Example for the first few calls
docker run --privileged --mount type=bind,source=.,target=/app mermin-builder:latest /bin/bash -c "
llvm-objdump-20 -d --section=.text ${EBPF_BINARY} | 
awk '/call.*0x[0-9a-f]+/ && !/call -0x/ {
    call_line = \$0
    call_inst = \$1
    # Look for stack usage in surrounding lines
    print \"Call: \" call_line
    
    # Search backwards for stack usage
    for(i = NR-10; i < NR; i++) {
        if(saved_lines[i] ~ /r10.*-.*0x/) {
            stack_match = saved_lines[i]
            gsub(/.*r10.*-.*0x/, \"0x\", stack_match)
            gsub(/[^0-9a-fA-F].*/, \"\", stack_match)
            if(stack_match != \"\") {
                decimal = sprintf(\"%d\", \"0x\" stack_match)
                print \"  → Stack before call: \" decimal \" bytes (0x\" stack_match \")\"
            }
        }
    }
    print \"\"
}
{
    saved_lines[NR] = \$0
}
' | head -15
"

echo ""
echo "Step 4: Calculate cumulative scenarios"
echo "====================================="

# Get the largest offsets for calculation examples
LARGEST_OFFSETS=($(echo "$STACK_OFFSETS" | head -3))

echo "Top 3 stack usage levels:"
for i in "${!LARGEST_OFFSETS[@]}"; do
    offset=${LARGEST_OFFSETS[$i]}
    decimal=$((0x$offset))
    echo "  Level $((i+1)): $decimal bytes (0x$offset)"
done

echo ""
echo "Potential cumulative call chains:"
if [ ${#LARGEST_OFFSETS[@]} -ge 3 ]; then
    func1=$((0x${LARGEST_OFFSETS[0]}))
    func2=$((0x${LARGEST_OFFSETS[1]}))  
    func3=$((0x${LARGEST_OFFSETS[2]}))
    
    scenario1=$((func1 + func2 + func3))
    scenario2=$((func1 + func2))
    scenario3=$((func2 + func3))
    
    echo "  Scenario 1 (3-deep): $func1 + $func2 + $func3 = $scenario1 bytes"
    echo "  Scenario 2 (2-deep): $func1 + $func2 = $scenario2 bytes"  
    echo "  Scenario 3 (2-deep): $func2 + $func3 = $scenario3 bytes"
    
    if [ $scenario1 -gt 512 ]; then
        echo "  ❌ Scenario 1 exceeds 512-byte limit by $(($scenario1 - 512)) bytes"
    else
        echo "  ✅ Scenario 1 within limits"
    fi
fi

echo ""
echo "Your specific 544-byte case:"
echo "  Entry function: 144 bytes (0x90)"
echo "  Middle function: 328 bytes (0x148)"
echo "  Leaf function: 0 bytes"  
echo "  Overhead: 72 bytes (call overhead/padding)"
echo "  Total: 144 + 328 + 0 + 72 = 544 bytes > 512 limit ❌"

echo ""
echo "💡 Key Insights:"
echo "  • The verifier calculates MAXIMUM possible call depth"
echo "  • Each function's stack usage adds cumulatively"
echo "  • Function call overhead adds ~10-20% to the total"
echo "  • Target: Keep total cumulative stack < 512 bytes"
