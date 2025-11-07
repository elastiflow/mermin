# Mermin Project Pull Request

This command provides a complete eBPF-focused PR workflow for the Mermin project. It validates code quality, analyzes changes, and helps create well-documented pull requests using the project's official template.

## What this command does

1. **Change Analysis**:
   - Runs `git diff alpha..HEAD` to analyze actual code changes
   - Identifies which components were modified (eBPF, Kubernetes, etc.)
   - Suggests appropriate PR categorization based on file changes
   - Generates smart commit summaries

2. **Mermin-Specific Validation**:
   - Verifies Docker container builds successfully
   - Runs eBPF compilation tests in containerized environment
   - Checks code formatting and linting with cargo fmt/clippy
   - Validates Kubernetes manifests and Helm charts

3. **Smart PR Preparation**:
   - Uses the existing `.github/PULL_REQUEST_TEMPLATE.md`
   - Pre-analyzes changes to suggest PR description content
   - Ensures all testing requirements are documented

4. **Quality Assurance**:
   - All eBPF programs compile and pass verification
   - Docker security practices validated
   - Kubernetes deployment readiness confirmed
   - No linting errors or formatting issues

## Usage

Type `/pr-prepare` to start the comprehensive Mermin PR workflow.

## Workflow Steps

### 1. Change Analysis

```bash
# Analyze what files changed
git diff --name-status alpha..HEAD

# Get detailed diff for PR context
git diff alpha..HEAD

# Check commit history
git log --oneline alpha..HEAD
```

### 2. Mermin Validations

**Docker Build**:

```bash
docker build -t mermin-builder:latest --target builder .
```

**eBPF Compilation**:

```bash
docker run --privileged --mount type=bind,source=.,target=/app \
  mermin-builder:latest /bin/bash -c "cargo build"
```

**Code Quality**:

```bash
# Format check
docker run --privileged --mount type=bind,source=.,target=/app \
  mermin-builder:latest /bin/bash -c "cargo fmt -- --check"

# Linting
docker run --privileged --mount type=bind,source=.,target=/app \
  mermin-builder:latest /bin/bash -c "cargo clippy -- -D warnings"
```

**Kubernetes Validation**:

```bash
helm lint charts/mermin/
helm template charts/mermin/ --values docs/deployment/examples/local/values.yaml
```

### 3. PR Content Generation

Based on `git diff` analysis, suggests:

- **PR Type**: Bug fix, feature, refactor, docs, etc.
- **Description**: Summary based on changed files
- **Testing**: Relevant test categories based on components modified
- **Checklist**: Pre-filled based on validation results

#### PR Content Requirements

**Conventional Commits as PR Titles**:

```markdown
type(scope): description

Examples:
feat(ebpf): add TCP flow tracking to packet parser
fix(k8s): resolve daemonset privilege escalation
perf(net): optimize packet processing bounds
refactor(build): simplify conditional compilation
```

**PR Templapte**:

```markdown
## Description

<!-- Please describe the purpose of this pull request and what changes it introduces. Include:
- What problem it solves or what feature it adds.
- Any relevant context or background information.
- If applicable, link to related issues (e.g., Fixes #123). -->

## Type of Change

<!-- Please check the box that applies to this pull request. -->

- [ ] Bug fix (non-breaking change that resolves an issue)
- [ ] New feature (non-breaking change that adds functionality)
- [ ] Breaking change (fix or feature that would cause existing functionality to change)
- [ ] Documentation update
- [ ] Refactoring (no functional changes, just code improvements)
- [ ] Other (please describe):

## How Has This Been Tested?

<!-- Describe how you tested the changes to ensure they work as expected. Include:
- Tests added or updated (e.g., unit tests, integration tests).
- Manual testing steps, if applicable.
- Any specific environment details (e.g., OS, browser, Node.js version). -->

- **Environment**:
    - OS: Debian 12
    - Rust: 1.88.0

## Checklist

<!-- Confirm the following by checking the boxes. -->

- [ ] My code follows the project's coding style guidelines.
- [ ] I have performed a self-review of my code.
- [ ] I have commented my code, particularly in hard-to-understand areas.
- [ ] I have updated the documentation where necessary.
- [ ] My changes generate no new warnings or errors.
- [ ] I have added or updated tests that verify my changes.
- [ ] All new and existing tests pass.

## Screenshots (if applicable)

<!-- If your changes involve UI updates, please include screenshots or GIFs to demonstrate the changes. -->

## Additional Notes

<!-- Any additional information for reviewers, such as:
- Potential risks or trade-offs.
- Areas where you'd like specific feedback.
- Dependencies or prerequisites for this change. -->
```

## Smart PR Suggestions

The command analyzes your `git diff` and suggests:

**For eBPF changes** (`mermin-ebpf/`):

- Emphasizes eBPF verification requirements
- Suggests instruction count analysis
- Highlights bounded loop validation

**For Kubernetes changes** (`charts/`, `k8s/`):

- Focuses on deployment testing
- Suggests RBAC validation
- Emphasizes security considerations

**For Core changes** (`mermin/src/`):

- Suggests integration testing
- Focuses on API compatibility
- Highlights performance impact

**For Network types** (`network-types/`):

- Suggests protocol testing
- Focuses on packet parsing validation
- Emphasizes backward compatibility

## Example Workflow Output

```shell
🔍 Analyzing changes...
   Modified: mermin-ebpf/src/main.rs (2 insertions, 2 deletions)

📋 Suggested PR Info:
   Type: Refactor
   Scope: eBPF conditional compilation
   Focus: Build configuration improvement

✅ All Validations Passed:
   ✓ Docker build successful
   ✓ eBPF compilation clean
   ✓ Code quality checks passed
   ✓ Kubernetes manifests valid

🚀 Opening PR: https://github.com/elastiflow/mermin/compare/main...your-branch
   Template: Using .github/PULL_REQUEST_TEMPLATE.md
   Pre-filled: Based on git diff analysis
```

**Note**: This command provides intelligent PR creation by combining automated validation with actual change analysis, ensuring high-quality contributions to the Mermin eBPF project.
