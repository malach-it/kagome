# Agent Instructions

## Development Requirements

- Run formatting checks before committing: `cargo fmt --check`.
- Run the test suite before committing: `cargo test`.
- Run linting before committing: `cargo clippy -- -D warnings`.
- Test both passing behavior and error or edge cases for changed logic.
- Fix any formatting, test, or lint failures before creating a commit.

## Handler, Request, and Resource Architecture

### Handlers

- Keep one public routed endpoint handler per file. Private branch-selection and
  pipeline-composition helpers may remain beside that handler; shared response
  and resource logic belongs in dedicated modules.
- Structure a handler as a branch selector around monadic `Result` pipelines.
  The handler chooses the applicable flow, while each selected branch composes
  validation, generation, and response steps.
- Thread an owned request value through each pipeline. Every step must have the
  shape `T -> Result<T, OAuthError>` until the final response conversion, so
  validated and generated state remains in the request's response state.
- Compose sequential protocol rules with `.and_then(...)`; use `?` when a branch
  must run multiple pipelines or combine their results. Rely on `Result`
  short-circuiting instead of manually checking and forwarding every error.
- Preserve protocol order in the pipeline. A step may consume only state made
  available by preceding steps; do not bypass the sequence by reading or
  mutating downstream response state directly in the handler.
- Make behavior-affecting branches explicit with `match`, preferably over typed
  enums or ordered slices of them. Keep each arm focused on selecting or
  composing a pipeline, and make every supported and terminal case visible.
- Make all branches converge on the same `Result<_, OAuthError>` shape and a
  shared success/error boundary. Log successful responses through
  `logged_response`; log failures once and convert them to the endpoint's HTTP
  error format at the outer handler boundary.
- Keep reusable validation, generation, parsing, cryptographic rules, and HTTP
  serialization out of branch arms. Put them in resource, request, or shared
  response modules and compose them from the handler.
- Keep routing separate from branching: routers select an endpoint from the HTTP
  method and path; handlers select and execute the endpoint's protocol flow.

### Requests

- Keep each request struct in its own file together with its paired response
  state and resource capability implementations. Use the parent module only for
  declaring those files and re-exporting their public types.
- Treat each request type as the explicit input contract for one flow stage.
  Parse into it all and only the HTTP parameters needed to select branches,
  validate inputs, and generate that stage's result.
- A parsed field may be optional at the HTTP boundary even when a later resource
  operation requires it. Preserve the value as `Option<_>` on the request and
  let the operation responsible for the protocol rule decide whether absence is
  valid or produces an `OAuthError`.
- Parse the flow's parameters once, in its constructor, through the shared query
  or request-parameter helpers. Downstream handlers and resource operations must
  use the request fields through capability traits instead of searching the raw
  `KagomeRequest` again.
- When a flow begins to depend on another parameter, add that parameter to the
  request type, parse it in every applicable constructor, and expose it through
  the resource capability that consumes it.
- Pair each request type with a response-state type. Keep parsed input parameters
  on the request and keep validated or generated values on its `response` field;
  do not use response state as a substitute for parsing required flow inputs.
- Retain a reference to the original `KagomeRequest` only when response
  generation, logging, or other request metadata requires it—not as an alternate
  source for flow parameters.
- Use `from_request` for the first stage of a flow. When a stage follows an
  earlier validation, use a constructor such as `from_grant_type_response` or
  `from_requests` that explicitly carries forward the validated response state.
- Implement only the resource capability traits required by a request type.
  Trait accessors expose raw or accumulated values, and trait mutation methods
  write validated or generated values into response state.
- Make `to_response` reject missing required output as an
  `invalid_token_response`, then delegate wire-format construction to a shared
  response helper.
- Re-export request and response types through their parent module instead of
  making handlers depend on private module paths.

### Resources

- Keep each protocol resource module focused on one domain concept and colocate
  its typed value, constants, validation or generation traits, and operations.
- Document every resource action with Rustdoc that explains its purpose,
  required input or previously validated state, state added or changed on
  success, and possible error outcomes. Keep this documentation beside the
  action instead of maintaining a separate resource-action catalog.
- Define reusable operations as generic functions over capability traits. They
  should take an owned mutable request, return `Result<T, OAuthError>`, and add
  validated or generated state through the trait before returning the request.
- Provide separate required and optional operations, such as `validate` and
  `validate_optional`, when absence has different protocol semantics. Optional
  operations must still validate values when they are present.
- Use trait defaults for genuinely optional inputs or flow-specific policy, and
  override them on request types whose requirements differ.
- Construct failures with the centralized `OAuthError` constructors so error
  codes, descriptions, and formats remain consistent across flows.
- Keep artifact serialization, signing, encryption, and time-bound validation
  inside the resource that owns the artifact; expose typed results rather than
  leaking those implementation details into handlers.

### Stateless Flow State

- Prefer carrying short-lived flow state in authenticated encrypted artifacts
  instead of adding server-side in-memory or persistent storage.
- Use COSE encryption when flow state is confidential. Give each artifact type
  a distinct secret and external AAD so ciphertext cannot be substituted across
  protocol contexts.
- Validate the COSE structure, authenticated decryption, required claims,
  issuance time, and expiration before accepting encrypted flow state.
- Do not add storage solely to enforce single use unless the protocol profile
  explicitly requires replay state. When single-use tracking is intentionally
  omitted, retain applicable mitigations such as short expiration and a
  separately delivered transaction code, and document the limitation.

## Testing Strategy

### Identity Flows Integration Tests

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
- Keep graphs at the handler-pipeline level. Quote only resource actions, using
  their exact `module::function` names; do not expand validation or generation
  rules implemented inside a resource into separate graph nodes.
- Show handler branch selection, resource-action success or error transitions,
  and terminal HTTP outcomes. Keep detailed resource-rule combinations in the
  branch-case test matrix instead of duplicating them in the graph.
- Store each Mermaid source at
  `docs/flows/<specification_name>/<flow_or_endpoint>.mmd` and its rendered SVG
  beside it as `<flow_or_endpoint>.svg`.
- Maintain `docs/flows/README.md` as the complete root catalog of rendered flow
  SVGs. Add, rename, reorder, or remove its source links and embedded images
  whenever the corresponding graph set changes. Regenerate its self-contained
  `docs/flows/all.svg` overview with
  `node scripts/compose-flow-svgs.mjs` after any rendered SVG changes.
- Treat the Mermaid source as canonical and regenerate the SVG from it; do not
  edit the generated SVG by hand.
- After creating or changing a Mermaid source, render its adjacent SVG before
  completing the change. Verify that the SVG is valid XML, is newer than or
  otherwise demonstrably matches its source, and preserves every visible label,
  including word spaces and bold `HTTP <status>` terminal-response prefixes.
- Show every behavior-affecting handler decision, labeled branch, intermediate
  pipeline state, and terminal success or error response represented in the
  branch-case test matrix.
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
