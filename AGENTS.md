# Agent Instructions

## Development Requirements

- Run formatting checks before committing: `cargo fmt --check`.
- Run the test suite before committing: `cargo test`.
- Run linting before committing: `cargo clippy -- -D warnings`.
- Fix any formatting, test, or lint failures before creating a commit.

## Commit Messages

- Use Conventional Commit messages.
- Keep the entire commit message lowercase.
- Use the format `<type>: <description>`.
- Start the description with a verb.
- Write a specific description that explains the change being made.
- Prefer concise descriptions in the imperative mood.
- Avoid vague descriptions such as `update docs`, `fix stuff`, or `changes`.

Examples:

- `feat: add expression parser`
- `fix: handle empty cli input`
- `test: add cli integration test`
- `chore: setup development tooling checks`
