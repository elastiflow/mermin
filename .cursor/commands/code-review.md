---
name: Comprehensive Code Review
description: Perform a thorough code review checking for Rust best practices, eBPF constraints, security, and potential bugs
params:
  base_branch:
    type: string
    description: The base branch to compare changes against
    default: beta
---

# Code Review Checklist

Review the code changes compared to the `{{base_branch}}` branch with particular attention to the following areas:

## 1. Rust Idioms & Best Practices

- [ ] Use idiomatic Rust patterns (e.g., `Iterator` chains, `Result`/`Option` combinators)
- [ ] Prefer `match` over nested `if let` when handling multiple variants
- [ ] Use `?` operator for error propagation instead of manual unwrapping
- [ ] Avoid unnecessary `.clone()` calls - prefer borrowing when possible
- [ ] Use appropriate lifetime annotations where needed
- [ ] Prefer `impl Trait` or generics over trait objects when possible
- [ ] Use `const` for compile-time constants, `static` only when necessary
- [ ] Check for proper use of `Copy` vs `Clone` traits
- [ ] Ensure `unwrap()` and `expect()` are only used when justified
- [ ] Use `#[must_use]` attribute on functions whose return values shouldn't be ignored

## 2. eBPF-Specific Concerns

### For `mermin-ebpf/` code

- [ ] **Bounded Loops**: All loops must have explicit, provable upper bounds (max iterations like `1500` for Ethernet frames)
- [ ] **Memory Access**: All memory reads/writes include proper bounds checking before access
- [ ] **Stack Usage**: Total stack usage stays well under 512 bytes limit
- [ ] **No Unbounded Operations**: No dynamic allocation, recursion, or unbounded data structures
- [ ] **Map Operations**: Proper error handling for map operations (`get`, `insert`, `remove`)
- [ ] **Logging**: Minimal logging with simple messages (avoid complex format strings that can fail verification)
- [ ] **Error Handling**: Graceful error handling - don't drop packets unnecessarily (prefer `TC_ACT_PIPE`)
- [ ] **Instruction Count**: Consider instruction count for verifier complexity limits

### For userspace code interacting with eBPF

- [ ] Proper `unsafe` block usage with clear justification
- [ ] Correct handling of eBPF program loading and attachment
- [ ] Map size limits are appropriate for the use case

## 3. Security Concerns

- [ ] Input validation on all external data (network packets, user config, etc.)
- [ ] No buffer overflows - all array/slice accesses are bounds-checked
- [ ] Sensitive data (credentials, keys) is not logged or exposed
- [ ] Proper use of `unsafe` blocks with minimal scope and clear safety invariants
- [ ] Time-of-check-time-of-use (TOCTOU) vulnerabilities avoided
- [ ] Integer overflow checks where arithmetic operations could overflow
- [ ] Resource exhaustion prevention (bounded collections, rate limiting)
- [ ] Proper privilege separation and least-privilege principle

## 4. Concurrency & Race Conditions

- [ ] Shared mutable state is properly synchronized (Mutex, RwLock, atomic types)
- [ ] No data races - check for proper `Send`/`Sync` trait bounds
- [ ] Arc/Rc usage is appropriate for the ownership scenario
- [ ] Async code properly handles cancellation and doesn't leak resources
- [ ] Lock ordering is consistent to prevent deadlocks
- [ ] Atomic operations use appropriate `Ordering` (Relaxed, Acquire, Release, AcqRel, SeqCst)
- [ ] Channel usage is correct (avoiding send/recv deadlocks)

## 5. Potential Bugs

- [ ] **Intent Verification**: Code changes actually accomplish their intended purpose (verify logic matches requirements)
- [ ] Off-by-one errors in loops, slices, or ranges
- [ ] Incorrect type conversions or casts (especially with `as`)
- [ ] Logic errors in conditional statements
- [ ] Missing error handling paths
- [ ] Uninitialized or partially initialized structs
- [ ] Incorrect assumptions about data format or protocol
- [ ] Edge cases handled (empty collections, zero values, max values)
- [ ] Timezone or time handling bugs (use UTC, avoid local time)
- [ ] Endianness issues in network protocol parsing

## 6. Documentation

- [ ] All public functions have `///` doc comments with:
  - Description of what the function does
  - `# Arguments` section for parameters
  - `# Returns` section for return values
  - `# Errors` section if returning `Result`
  - `# Panics` section if function can panic
  - `# Examples` for non-obvious usage
- [ ] All public structs and enums are documented
- [ ] All public fields on structs are documented
- [ ] Module-level documentation (`//!`) provides overview
- [ ] Private items are documented only when complexity warrants it

## 7. Comment Quality

- [ ] Comments explain **WHY**, not **WHAT** (code should be self-documenting for "what")
- [ ] No redundant comments that merely restate the code
- [ ] Complex algorithms have explanatory comments
- [ ] Non-obvious design decisions are documented
- [ ] TODOs, FIXMEs, or HACKs are justified and tracked
- [ ] Comments are kept up-to-date with code changes
- [ ] No commented-out code (use version control instead)

## 8. Code Simplification Opportunities

- [ ] Can complex logic be broken into smaller, well-named functions?
- [ ] Are there repeated patterns that could be extracted?
- [ ] Can iterator methods replace manual loops?
- [ ] Could pattern matching simplify nested conditionals?
- [ ] Are there unnecessary intermediate variables?
- [ ] Can `if let` chains be replaced with `match`?
- [ ] Are there opportunities to use standard library traits/methods?
- [ ] Can macros reduce boilerplate (without sacrificing clarity)?
- [ ] Are error types appropriately specific (not overly generic)?

## 9. Additional Rust Best Practices

- [ ] Modules are appropriately sized and cohesive
- [ ] Public API surface is minimal and well-designed
- [ ] Types make invalid states unrepresentable
- [ ] Builder pattern used for complex configuration
- [ ] Zero-cost abstractions leveraged where possible
- [ ] Tests are included for new functionality
- [ ] Benchmarks added for performance-critical code
- [ ] Feature flags used appropriately for optional dependencies
- [ ] Cargo.toml dependencies are specific (avoid wildcards)
- [ ] No warnings from `cargo clippy` with `-D warnings`

---

## Review Instructions

1. Examine each changed file systematically
2. For each issue found, provide:
   - **Location**: File and line number
   - **Issue**: What's wrong
   - **Severity**: Critical/High/Medium/Low
   - **Recommendation**: How to fix it
   - **Example**: Show corrected code when applicable

3. Prioritize issues by severity
4. Be constructive and specific in feedback
5. Acknowledge good practices when present

## Final Assessment

Provide a summary with:

- Overall code quality rating
- Number of issues by severity
- Most critical issues to address first
- Positive highlights
- General recommendations
