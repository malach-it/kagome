# Agent Instructions

## Development Requirements

- Run formatting checks before committing: `cargo fmt --check`.
- Run the test suite before committing: `cargo test`.
- Run linting before committing: `cargo clippy -- -D warnings`.
- Test both passing behavior and error or edge cases for changed logic.
- Fix any formatting, test, or lint failures before creating a commit.

## Testing Strategy

### Identity Flow Integration Tests

- Organize identity flow integration tests by specification under
  `tests/integration/flows/<specification_name>/`.
- Cover one business rule per test case.
- Exercise flows end to end through HTTP requests and assert externally observable
  response behavior instead of implementation details.
- Use deterministic fixtures or fixture builders when a flow requires tokens,
  authorization codes, credentials, or other setup data.
- Keep fixtures focused on test setup; do not use them to replace the behavior the
  test is intended to exercise.
- Put tests shared by multiple specifications in
  `tests/integration/flows/common.rs`.
- Put reusable OAuth fixtures and helpers in
  `tests/integration/flows/oauth/mod.rs`.
- Add both success and error or edge-case coverage for the flow affected by a
  change.

### Branch-Case Test Matrix

- Before writing tests, identify every behavior-affecting branch in the flow and
  list its possible cases.
- Build a test matrix from those cases, including valid and invalid inputs,
  required and optional values, supported representations, authentication
  outcomes, and intermediate and final flow states where applicable.
- Add a test for every reachable combination in the matrix. Keep each test
  focused on one expected business rule or outcome.
- Mark impossible combinations explicitly and explain why they cannot occur.
- Document combinations that are intentionally equivalent, but only collapse
  them into one test when they exercise the same path and produce the same
  observable result.
- Update the matrix whenever flow logic gains, removes, or changes a branch.

### Flow and Endpoint Branch Graphs

- Maintain a Mermaid branch graph for every identity flow and HTTP endpoint.
- Store each Mermaid source at
  `docs/flows/<specification_name>/<flow_or_endpoint>.mmd` and its rendered SVG
  beside it as `<flow_or_endpoint>.svg`.
- Treat the Mermaid source as canonical and regenerate the SVG from it; do not
  edit the generated SVG by hand.
- Show every behavior-affecting decision, labeled branch, intermediate state,
  and terminal success or error response represented in the branch-case test
  matrix.
- Keep every graph closed: each branch must start at a defined node and end at a
  defined state or terminal outcome, with no dangling edges or unterminated
  paths.
- Use the same terminology in graphs, test matrices, and test names so branches
  can be traced between documentation and coverage.
- Update both the Mermaid source and rendered SVG whenever a flow or endpoint
  branch is added, removed, reordered, or changes its observable outcome.
- Review graph changes together with the corresponding test changes and verify
  that every reachable graph path is covered by the branch-case test matrix.

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
