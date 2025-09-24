Mermin Developer Guidelines (Project-Specific)

Audience: Experienced Rust developers contributing to this workspace.

Scope: Build/configuration specifics, testing workflow, and development conventions particular to this repository.

1. Workspace layout and build specifics

- Workspace members
  - Primary crates: mermin (agent), mermin-common (shared), mermin-ebpf (eBPF programs), network-types (no_std packet types)
  - Test-only helper crates (for integration suites): network-types/tests/integration, network-types/tests/integration-common, network-types/tests/integration-ebpf
  - Cargo workspace settings: see Cargo.toml at root
    - resolver = 2
    - default-members = ["mermin", "mermin-common", "network-types"] (eBPF crate excluded from default build)
    - panic = "abort" in both dev and release profiles

- Toolchains and external dependencies (from README and code behavior)
  - Rust toolchains: stable and nightly are both recommended
    - nightly is needed for eBPF build scripts and rust-src (rustup component)
  - eBPF linker: bpf-linker must be installed (cargo install bpf-linker). On macOS use --no-default-features
  - Cross-compilation (when targeting MUSL): set ARCH and provide musl toolchain and LLVM; see README

- Build commands
  - Build default workspace members: cargo build
  - Build full workspace including eBPF crate: cargo build --workspace
  - Run the mermin agent (requires elevated privileges via runner):
    cargo run --release --config 'target."cfg(all())".runner="sudo -E"'
  - Docker/Kubernetes: See README for kind + Helm flow; common make targets exist via included makefiles/*.mk (e.g., helm-upgrade, k8s-get, k8s-diff)

- Notes on network-types (no_std)
  - network-types is #![no_std] and uses explicit unsafe blocks for pointer arithmetic when parsing headers
  - If you introduce features (e.g., serde derives), define them in network-types/Cargo.toml. The code contains #[cfg_attr(feature = "serde", ...)] hooks; without a feature, rustc emits an "unexpected cfg value: serde" warning under check-cfg. Define and gate it to avoid the warning if you plan to enable serde

2. Testing: running, adding, and demonstrating

- Running tests
  - Entire workspace (default members): cargo test
  - Specific crate: cargo test -p network-types
  - Filter by test name substring: cargo test <pattern>
  - Run ignored tests: cargo test -- --ignored
  - Run with full workspace: cargo test --workspace

- Integration test structure
  - network-types has additional crates under network-types/tests/... to facilitate cross-crate integration testing. These are declared as workspace members in the root Cargo.toml so cargo test picks them up
  - Typical Rust integration tests for a crate can also be placed under that crate's tests/ directory as .rs files compiled as separate crates

- eBPF-related tests
  - mermin-ebpf requires the eBPF toolchain to build/run artifacts; tests that rely on kernel features or elevated permissions should be conditioned accordingly
  - Default test runs (cargo test) exclude mermin-ebpf because it's not in default-members; use --workspace to include it

- Lints, formatting, and style
  - Formatting: cargo fmt (rustfmt configuration is at repo root rustfmt.toml)
  - Clippy: recommended commands from README
    - cargo clippy --package mermin-ebpf -- -D warnings
    - cargo clippy --all-features -- -D warnings

- Safety and Rust 2024 edition notes
  - The workspace uses edition = "2024" (see network-types/Cargo.toml). In 2024 edition, unsafe operations inside unsafe fn require explicit unsafe blocks. You will see warnings like E0133 (unsafe_op_in_unsafe_fn) if calls to .add() or ptr::copy_nonoverlapping are not wrapped in unsafe { ... }. When modifying code in these areas, preserve or introduce explicit unsafe blocks with clear safety docs

- How to add a new test (demonstrated)
  - Example: adding an integration test to network-types
    - File path: network-types/tests/example_parsing.rs
    - Minimal content example:
      #[test]
      fn parses_safely() {
          // Use public APIs from network_types
          assert_eq!(1 + 1, 2);
      }
    - Run it: cargo test -p network-types parses_safely

- Demonstration (executed and verified during this update)
  - A temporary integration test was created at network-types/tests/demo_add_test.rs with content:
      #[test]
      fn demo_adds_numbers() { assert_eq!(2 + 2, 4); }
  - It was executed successfully via:
      cargo test -p network-types demo_adds_numbers
  - After verifying the test runs and passes, the temporary file was removed to keep the repo clean

3. Development conventions and tips specific to this repo

- Packet parsing in network-types
  - Header structs (e.g., AhHdr) operate on raw pointers and slices; use explicit unsafe with clear Safety sections in docs
  - Avoid assuming alignment; convert from byte slices carefully and respect endianness
  - Chunk reading helper (chunk_reader) provides read_chunks<T, N>; ensure T implements FromBytesWithKnownSize<N> and that N matches size_of::<T>() to avoid InvalidChunkLength

- Workspace membership and default-members
  - CI/local workflows typically use default-members for speed. If you change dependencies or add new test crates under network-types/tests/..., update root Cargo.toml if you want cargo test --workspace to include them, or keep them out of default-members if they are heavy or environment-sensitive

- Running mermin locally with traffic
  - The runner config uses sudo; ensure your environment allows passwordless sudo or set up proper permissions. Generate traffic (e.g., ping -c 5 localhost) to observe logs

- Kubernetes/dev environment
  - Use kind for quick local clusters and Helm chart under charts/mermin. The Makefile includes make targets (helm-upgrade, k8s-get, k8s-diff) pulled from makefiles/*.mk, which wrap common kubectl/helm workflows

- Feature gating and cfg checks
  - If you add crate-level features (e.g., serde support in network-types), define them in the crate’s Cargo.toml and, if useful, wire them up via [workspace.dependencies] with features = ["serde"] at the member level rather than the workspace root

- Common commands quick reference
  - Build default members: cargo build
  - Build all (including eBPF): cargo build --workspace
  - Run agent (sudo runner): RUST_LOG=info cargo run --release --config 'target."cfg(all())".runner="sudo -E"'
  - Format: cargo fmt
  - Lint: cargo clippy --all-features -- -D warnings
  - Tests: cargo test (or -p <crate>)

4. Known warnings and how to address them

- unexpected cfg value: serde (check-cfg): either define a serde feature for the crate that uses #[cfg_attr(feature = "serde", ...)] or remove the attribute if serde is not intended
- unsafe_op_in_unsafe_fn (E0133 warnings): wrap pointer operations and other unsafe calls in explicit unsafe blocks inside unsafe fns; add/maintain thorough safety docs

5. Troubleshooting

- Building eBPF on macOS:
  - Install bpf-linker with --no-default-features
  - Ensure LLVM is available (brew install llvm), and set the appropriate PATH if needed
- Cross-compiling mermin:
  - Use the command in README with CC and --target set for ${ARCH}-unknown-linux-musl
- Permissions
  - Running the agent requires CAP_BPF and other capabilities; using cargo runner with sudo is the simplest local approach outlined in README
