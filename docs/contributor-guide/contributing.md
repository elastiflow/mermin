# Contributing to Mermin

Thank you for your interest in contributing to Mermin! This guide will help you understand our contribution process and how to get your changes successfully merged.

## Getting Started

Before you start contributing:

1. **Read the** [**Development Workflow**](development-workflow.md) guide to set up your environment.
2. **Browse existing issues** on [GitHub Issues](https://github.com/elastiflow/mermin/issues) to find something to work on.
3. **Join the discussion** on [GitHub Discussions](https://github.com/elastiflow/mermin/discussions).
4. **Review our** [**Code of Conduct**](code-of-conduct.md) to understand our community standards.

### Finding Something to Work On

* **Good First Issues**: Look for issues labeled `good first issue` for beginner-friendly tasks.
* **Help Wanted**: Issues labeled `help wanted` are actively seeking contributors.
* **Feature Requests**: Check the discussions board for feature ideas.
* **Bug Reports**: Any unassigned bug is fair game!

If you want to work on something not yet tracked, please **open an issue first** to discuss your idea with the maintainers.

## Contribution Workflow

### 1. Fork and Clone

Fork the repository on GitHub, then clone your fork:

```shell
git clone https://github.com/YOUR_USERNAME/mermin.git
cd mermin
git remote add upstream https://github.com/elastiflow/mermin.git
```

### 2. Create a Feature Branch

Always create a new branch for your work:

```shell
# Fetch latest changes from upstream
git fetch upstream
git checkout -b feature/my-new-feature upstream/beta

# Or for bug fixes
git checkout -b fix/issue-123 upstream/beta
```

**Branch naming conventions:**

* `feature/` - New features or enhancements
* `fix/` - Bug fixes
* `docs/` - Documentation updates
* `refactor/` - Code refactoring
* `test/` - Adding or improving tests
* `chore/` - Maintenance tasks

### 3. Make Your Changes

* Follow the existing code style and conventions.
* Add tests for new functionality.
* Update documentation as needed.
* Keep commits focused and atomic.
* Write clear commit messages (see [Commit Guidelines](contributing.md#commit-message-guidelines)).

### 4. Test Your Changes

Before submitting, ensure all checks pass locally:

```shell
# Format your code
cargo fmt

# Run linting
cargo clippy -p mermin-ebpf -- -D warnings
cargo clippy --all-features -- -D warnings

# Run tests
cargo test
cargo test -p mermin-ebpf --features test

# Run integration tests
cd network-types/tests
make test-ci
```

See the [Development Workflow](development-workflow.md) guide for more testing details.

### 5. Push and Create Pull Request

```shell
git push origin feature/my-new-feature
```

Then open a pull request on GitHub from your fork to the `beta` branch of the main repository.

## Commit Message Guidelines

Mermin uses **Conventional Commits** for all commit messages. This enables automatic changelog generation and semantic versioning.

### Commit Message Format

```
<type>[optional scope]: <description>

[optional body]

[optional footer(s)]
```

### Types

* **feat**: A new feature, will trigger a minor semver bump
* **fix**: A bug fix, will trigger a patch semver bump
* **feat!**: A new breaking feature, will trigger a major semver bump
* **fix!**: A breaking bug fix, will trigger a major semver bump
* **docs**: Documentation changes only, will not trigger a release neither get to the changelog
* **style**: Code style changes (formatting, missing semicolons, etc.). Will not trigger a release neither get to the changelog
* **refactor**: Code changes that neither fix a bug nor add a feature, will not trigger a release neither get to the changelog
* **perf**: Performance improvements, will not trigger a release neither get to the changelog
* **test**: Adding or updating tests, will not trigger a release neither get to the changelog
* **build**: Changes to build system or dependencies, will not trigger a release neither get to the changelog
* **ci**: Changes to CI configuration files and scripts, will not trigger a release neither get to the changelog
* **chore**: Other changes that don't modify src or test files, will not trigger a release neither get to the changelog

### Examples

```
feat(ebpf): add support for GRE tunnel detection

Add GRE header parsing to the eBPF packet parser to enable
flow tracking through GRE tunnels.

Closes #123
```

```
fix(k8s): resolve pod metadata race condition

Ensure pod informer cache is synced before processing flows
to prevent missing metadata enrichment.

Fixes #456
```

```
docs: update quickstart guide with new configuration options
```

### Breaking Changes

If your change introduces a breaking change, add `BREAKING CHANGE:` in the footer:

```
feat(config)!: change default log level to warn

BREAKING CHANGE: The default log_level has changed from "info" to "warn".
Users who relied on the default info-level logging will need to explicitly
set log_level = "info" in their configuration.
```

### Important Notes

* Use the **imperative, present tense**: "add" not "added" or "adds".
* **Description must be lowercase**: Don't capitalize the first letter of the description.
* No period (.) at the end of the description.
* Reference issues and pull requests in the footer.
* **PR titles must also follow this format**: Your PR title must be a valid conventional commit (lowercase description).

## Pull Request Process

### Before Submitting

* [ ] Ensure your branch is up to date with `upstream/beta`.
* [ ] All tests pass locally.
* [ ] Code is formatted with `cargo fmt`.
* [ ] No clippy warnings.
* [ ] Documentation is updated.
* [ ] Commit messages follow conventional commits.
* [ ] You've tested your changes end-to-end if possible.

### PR Description Template

When creating a PR, provide:

1. **What**: A clear description of what you changed.
2. **Why**: The motivation for the change.
3. **How**: Technical details of the implementation.
4. **Testing**: How you tested the changes.
5. **Screenshots**: If UI/output changes, include before/after.
6. **Related Issues**: Link to any related issues.

### Review Process

1. **Automated checks** will run (see [CI Checks](contributing.md#ci-checks)).
2. **Maintainer review**: A maintainer will review your code.
3. **Feedback**: Address any requested changes.
4. **Approval**: Once approved, a maintainer will merge your PR.

**Response time:** We aim to provide initial feedback within 3-5 business days.

### After Your PR is Merged

* Delete your feature branch.
*   Update your local repository:

    ```shell
    git checkout beta
    git pull upstream beta
    ```

## CI Checks

All pull requests must pass these automated checks:

### 1. PR Title and Commit Checks

* PR title must follow conventional commits format
* All commits must follow conventional commits format

### 2. Formatting

* `cargo fmt -- --check` must pass
* Code must be formatted according to `rustfmt.toml`

### 3. Linting

* eBPF code: `cargo clippy -p mermin-ebpf -- -D warnings`
* Userspace code: `cargo clippy -- -D warnings`
* Dockerfile: `hadolint` checks

### 4. Tests

* Unit tests: `cargo nextest run` for all workspace packages
* Doc tests: `cargo test --doc`
* eBPF tests: `cargo test -p mermin-ebpf --features test`
* Integration tests: Network types integration suite
* E2E tests: CNI compatibility across Calico, Cilium, Flannel, kindnetd

### 5. Helm Checks

* Chart linting with `ct lint`
* Template validation

### 6. Docker Builds

* Multi-architecture builds (amd64, arm64)
* Both `runner` and `runner-debug` targets

### 7. Schema Version Check

If you modify `FlowKey` or `FlowStats` structs in `mermin-common/src/lib.rs`, you **must** increment `EBPF_MAP_SCHEMA_VERSION` in `mermin/src/main.rs`. The CI will fail if this is not done.

**Why?** Changing these structs breaks eBPF map compatibility. Incrementing the version ensures old pinned maps are not reused.

### Running CI Checks Locally

You can run most CI checks locally before pushing:

```shell
# Format check
cargo fmt -- --check

# Linting
cargo clippy -p mermin-ebpf -- -D warnings
cargo clippy --all-features -- -D warnings

# Tests
cargo nextest run --workspace --exclude mermin-ebpf --exclude integration --exclude integration-common --exclude integration-ebpf
cargo test --doc
cargo test -p mermin-ebpf --features test
cd network-types/tests && make test-ci

# Dockerfile linting
docker run --rm -i hadolint/hadolint < Dockerfile
```

## Community and Communication

### Where to Get Help

* **Questions**: Use [GitHub Discussions](https://github.com/elastiflow/mermin/discussions) for general questions.
* **Bugs**: Report bugs via [GitHub Issues](https://github.com/elastiflow/mermin/issues).
* **Feature Requests**: Discuss features in [GitHub Discussions](https://github.com/elastiflow/mermin/discussions).
* **Security Issues**: See our security policy for reporting vulnerabilities.

### Communication Guidelines

* Be respectful and inclusive.
* Search existing issues/discussions before creating new ones.
* Provide clear, detailed information when reporting bugs.
* Include steps to reproduce for bug reports.
* Be patient - maintainers are often volunteers.

## Code of Conduct

All contributors must adhere to our [Code of Conduct](code-of-conduct.md). We are committed to providing a welcoming and inclusive environment for everyone.

## License

By contributing to Mermin, you agree that your contributions will be licensed under the same licenses as the project:

* **GPL-2.0** for eBPF code (`mermin-ebpf/`)
* **Apache-2.0** for user space code

See [LICENSE-GPL2](https://github.com/elastiflow/mermin/blob/beta/LICENSE-GPL2/README.md) and [LICENSE-APACHE](https://github.com/elastiflow/mermin/blob/beta/LICENSE-APACHE/README.md) for full license text.

## Questions?

If you have questions about contributing, feel free to:

* Open a discussion on [GitHub Discussions](https://github.com/elastiflow/mermin/discussions).
* Comment on the issue you're interested in working on.
* Reach out to the maintainers.

Thank you for contributing to Mermin! 🎉
