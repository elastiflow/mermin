#!/bin/bash
echo "=== eBPF Call Chain Analysis ==="
docker run --privileged --mount type=bind,source=.,target=/app mermin-builder:latest /bin/bash -c "cargo build --release"

EBPF_BINARY=$(docker run --privileged --mount type=bind,source=.,target=/app mermin-builder:latest /bin/bash -c "find target -name 'mermin' -path '*/mermin-ebpf/*' -path '*/bpfel-unknown-none/release/*' | head -1")

echo "📞 Function Calls Found:"
docker run --privileged --mount type=bind,source=.,target=/app mermin-builder:latest /bin/bash -c "llvm-objdump-20 -d --section=classifier ${EBPF_BINARY} | grep -E 'call.*0x[0-9a-f]+' | grep -v 'call -0x' | head -5"

echo ""
echo "📊 Stack Usage Levels:"
docker run --privileged --mount type=bind,source=.,target=/app mermin-builder:latest /bin/bash -c "llvm-objdump-20 -d --section=classifier ${EBPF_BINARY} | grep -oE 'r10.*-.*0x[0-9a-f]+' | sed 's/.*-.*0x//' | sort -nr | uniq | head -5" | while read hex; do
    decimal=$((0x$hex))
    echo "  • $decimal bytes (0x$hex)"
done

echo ""
echo "💡 To find your specific cumulative call chain:"
echo "   1. Look for call sequences like: call 0x1 → call 0x1a → (leaf)"
echo "   2. Find stack usage near each call: r10 - 0xXX"
echo "   3. Add them up: Stack_A + Stack_B + Stack_C = Total"
echo "   4. If Total > 512 bytes → Verifier failure"