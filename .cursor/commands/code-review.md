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

### Documentation Hierarchy & Content

- [ ] **Crate-level** (`lib.rs`/`main.rs`): Documents the "big What" (purpose) and "big How" (getting started, examples)
- [ ] **Module-level** (`//!`): Describes types in the module and how they interact with the rest of the crate
- [ ] **Type-level**: Documents construction, destruction/dropping behavior, and performance characteristics
- [ ] **Function-level**: Provides semantic descriptions and code examples showing the detailed "How"

### Documentation Standards

- [ ] All public items (functions, structs, enums, traits) have `///` doc comments
- [ ] Documentation focuses on **What** (what it does) and **How** (how to use it), not implementation details
- [ ] Documentation is concise - assumes users know Rust, avoids over-explaining
- [ ] All public fields on structs have doc comments
- [ ] Private items are documented only when complexity warrants it

### Required Documentation Sections (in priority order)

- [ ] **`# Examples`** (plural, even if only one):
  - Present on all public items where usage isn't completely obvious
  - Examples should compile and run as doc-tests (avoid `ignore` unless necessary)
  - Cover both common use cases and edge cases
  - Use ` ```ignore` or ` ```text` only for intentionally non-compiling examples

- [ ] **`# Errors`** (for functions returning `Result`):
  - Explains **why** each error variant can occur (rare case where "why" is needed)
  - Links to error type variants using `[ErrorVariant](path::to::ErrorType::ErrorVariant)`

- [ ] **`# Panics`**:
  - Documents any conditions under which the function will panic
  - Required if function can panic in normal usage

- [ ] **`# Safety`**:
  - Required for all `unsafe` functions
  - Documents safety invariants that callers must uphold

### Documentation Anti-patterns to Avoid

- [ ] **No `# Arguments` sections** - parameter names and types should be self-documenting
  - Exception: Only if there's a non-obvious assumption or undefined behavior with certain values

- [ ] **No `# Returns` sections** - return type and function description should be clear enough

- [ ] **No redundant documentation** - don't repeat what the code/types already express

### Documentation Quality

- [ ] All code references link to their definitions using rustdoc link syntax: `` [`Type`](path::to::Type) ``
- [ ] References to std types are also linked: `` [`String`](std::string::String) ``
- [ ] Document traits themselves, not trait implementations (implementations inherit trait docs)
- [ ] Non-obvious design decisions are documented (especially those that go against intuition)
- [ ] Lifetimes are documented if they serve a non-obvious purpose
- [ ] Documentation is kept up-to-date with code changes

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
