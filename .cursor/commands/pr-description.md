# Mermin Project Pull Request Description Generation

This command provides a complete eBPF-focused PR workflow for the Mermin project. It validates code quality, analyzes changes, and helps create well-documented pull requests using the project's official template.

## What this command does

1. **Change Analysis**:
   - Runs `git diff beta..HEAD` to analyze actual code changes
   - Identifies which components were modified (eBPF, Kubernetes, etc.)
   - Suggests appropriate PR categorization based on file changes
   - Generates smart commit summaries

2. **Smart PR Preparation**:
   - Uses the existing `.github/PULL_REQUEST_TEMPLATE.md`
   - Pre-analyzes changes to suggest PR description content
   - Ensures all testing requirements are documented
   - Keep the output very concise and to the point. Avoid fluff as much as possible.
   - **Always** generate the output as a markdown file so I can easily copy it.

## Usage

Type `/pr-description` to start the comprehensive Mermin PR workflow.

## Workflow Steps

### 1. Change Analysis

```bash
# Analyze what files changed
git diff --name-status beta..HEAD

# Get detailed diff for PR context
git diff beta..HEAD

# Check commit history
git log --oneline beta..HEAD
```

### 2. PR Content Generation

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
## Changes

<!-- Briefly describe what changes this introduces and why -->

Fixes #(issue)

### Type of change

- [ ] Bug fix
- [ ] New feature
- [ ] Breaking change
- [ ] Documentation
- [ ] Other:

## Testing

<!-- How did you test this? What environment did you use? -->

## Proof it works

<!-- Screenshots, logs, test output, or other evidence showing your changes work as expected -->

## Checklist

- [ ] I've tested my changes
- [ ] I've updated relevant documentation
- [ ] My code follows the project's style (run `cargo fmt` and `cargo clippy`)
- [ ] All tests pass

## Notes

<!-- Anything else reviewers should know? Areas where you'd like feedback? -->
```
