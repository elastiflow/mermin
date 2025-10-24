# Generate Commit Message

Analyze the currently staged git changes and generate a concise, descriptive commit message.

## Instructions

1. Run `git diff --cached` to view all staged changes
2. Analyze the changes to understand:
   - What functionality was added, modified, or removed
   - Bug fixes or refactoring that was done
   - Any configuration or structural changes
3. Generate a commit message that:
   - Uses imperative mood (e.g., "Fix", "Add", "Refactor", not "Fixed", "Added")
   - Has a clear, concise subject line (50-72 characters)
   - Optionally includes bullet points for multiple significant changes
   - Groups related changes together logically
4. Provide both a single-line version and a detailed version (if needed)

## Output Format

Provide the commit message in a code block so it can be easily copied.
