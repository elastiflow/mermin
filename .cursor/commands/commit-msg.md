# Generate Commit Message

Analyze the currently staged git changes and generate a concise, descriptive commit message.

## Instructions

1. Run `git diff --cached` to view all staged changes
2. Analyze the changes to understand:
   - What functionality was added, modified, or removed
   - Bug fixes or refactoring that was done
   - Any configuration or structural changes
3. Generate a commit message using **Conventional Commits format**:
   - Format: `<type>: <description>`
   - Use one of these types:
     - `feat`: new feature
     - `fix`: bug fix
     - `docs`: documentation changes
     - `style`: formatting, missing semicolons, etc.
     - `refactor`: code restructuring without changing behavior
     - `perf`: performance improvements
     - `test`: adding or updating tests
     - `build`: build system or dependency changes
     - `ci`: CI/CD pipeline changes
     - `chore`: other changes (tooling, configs, etc.)
   - **Title must be entirely lowercase** (e.g., "feat: add user authentication")
   - Use imperative mood in description (e.g., "add", "fix", "update", not "added", "fixed")
   - Keep the subject line under 72 characters
   - Optionally add a body with bullet points for multiple significant changes
   - Group related changes together logically
4. Provide both a single-line version and a detailed version (if needed)

## Output Format

Provide the commit message in a code block so it can be easily copied.
