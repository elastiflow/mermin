# Simplifying the Tests Directory Structure

After exploring the `./tests` directory, I've identified several opportunities to simplify the code. The current implementation is indeed heavy-handed, with significant duplication across different network protocol tests.

## Current Structure Issues

1. **Duplicated Test Infrastructure**: Each protocol (BGP, OSPF, GRE, GENEVE, SCTP, etc.) has:
    - A separate test file in `eth-ebpf-test/tests/`
    - A separate implementation file in `eth-ebpf-test-ebpf/src/`
    - A separate entry point in `main.rs`
    - Nearly identical test setup and teardown code

2. **Repetitive Virtual Interface Management**: Each test creates and destroys a virtual Ethernet (veth) pair, even though this could be shared across tests.

3. **Similar Map Operations**: Each protocol has similar code for creating, accessing, and cleaning up eBPF maps.

4. **Sequential Test Execution**: The `run_tests.sh` script runs each protocol test separately with almost identical commands.

## Simplification Recommendations

1. **Unified Test Framework**:
    - Create a generic test harness that can be reused across all protocol tests
    - Define a trait or interface that each protocol test can implement
    - Example:
   ```rust
   trait ProtocolTest {
       fn get_test_packet(&self) -> Vec<u8>;
       fn verify_results(&self, map_results: &[u32]) -> Result<(), String>;
   }
   ```

2. **Shared Infrastructure**:
    - Create a single veth pair setup/teardown that can be reused
    - Use test fixtures or a setup/teardown pattern instead of duplicating in each test
    - Consider using a test framework like `rstest` for parameterized tests

3. **Consolidated eBPF Program**:
    - Create a single eBPF program that can handle multiple protocols
    - Use a protocol identifier in the packet or configuration to determine which parser to use
    - Share common parsing logic across protocols

4. **Map Abstraction**:
    - Create a helper struct to manage map operations consistently
    - Example:
   ```rust
   struct TestResultMap {
       map: UserHashMap<u32, u32>,
   }

   impl TestResultMap {
       fn new(bpf: &mut Ebpf, name: &str) -> Result<Self> { /* ... */ }
       fn get_results(&mut self) -> Result<Vec<u32>> { /* ... */ }
       fn clear(&mut self) -> Result<()> { /* ... */ }
   }
   ```

5. **Parameterized Tests**:
    - Use a data-driven approach to test multiple protocols with the same test code
    - Example:
   ```rust
   #[rstest]
   #[case("BGP", bgp_test_packet(), vec![0xFF, 23, 5, 1, 1])]
   #[case("OSPF", ospf_test_packet(), vec![2, 1, 44, 0xC0A80101, 0])]
   async fn test_protocol_parsing(
       #[case] name: &str,
       #[case] packet: Vec<u8>,
       #[case] expected: Vec<u32>
   ) -> Result<()> {
       // Shared test implementation
   }
   ```

6. **Simplified Test Runner**:
    - Modify `run_tests.sh` to run all tests in a single command
    - Use test tags or features to selectively run tests if needed

## Implementation Example

Here's a sketch of how the simplified structure might look:

```rust
// In a shared test_utils.rs file
pub async fn setup_test_environment() -> Result<Ebpf> {
    create_veth().await?;
    let bpf = load_and_attach_bpf("unified_protocol_test")?;
    Ok(bpf)
}

pub async fn teardown_test_environment() {
    destroy_veth();
}

// In a unified test file
#[tokio::test]
async fn test_all_protocols() -> Result<()> {
    setup_logging();
    let mut bpf = setup_test_environment().await?;

    // Test BGP
    send_packet(create_bgp_packet()).await?;
    let results = get_map_results(&mut bpf, "BGP_RESULT").await?;
    verify_bgp_results(results)?;

    // Test OSPF
    send_packet(create_ospf_packet()).await?;
    let results = get_map_results(&mut bpf, "OSPF_RESULT").await?;
    verify_ospf_results(results)?;

    // More protocols...

    teardown_test_environment().await;
    Ok(())
}
```

By implementing these changes, you can significantly reduce code duplication, make the tests more maintainable, and potentially improve test execution time by avoiding repeated setup/teardown operations.

The simplified approach would make it easier to add new protocol tests in the future while keeping the codebase clean and focused.
