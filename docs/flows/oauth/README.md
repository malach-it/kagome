# OAuth Flow Graphs

This directory documents the branching behavior of Kagome's OAuth flows and
endpoints. Mermaid (`.mmd`) files are the canonical sources; matching `.svg`
files are generated artifacts for viewing in documentation and code reviews.

Flow graphs describe the end-to-end business rules for a grant or authorization
flow. Endpoint graphs describe request dispatch and how flow results become HTTP
responses.

## Authorization Code Flow

[Mermaid source](authorization_code.mmd)

![Authorization code flow](authorization_code.svg)

## Client Credentials Flow

[Mermaid source](client_credentials.mmd)

![Client credentials flow](client_credentials.svg)

## Resource Owner Password Credentials Flow

[Mermaid source](resource_owner_password_credentials.mmd)

![Resource owner password credentials flow](resource_owner_password_credentials.svg)

## Code-Chain Flow

[Mermaid source](code_chain.mmd)

![Code-chain flow](code_chain.svg)

## `/authorize` Endpoint

[Mermaid source](authorize_endpoint.mmd)

![Authorize endpoint](authorize_endpoint.svg)

## `/token` Endpoint

[Mermaid source](token_endpoint.mmd)

![Token endpoint](token_endpoint.svg)

## Review Checklist

- Update the Mermaid source and rendered SVG together.
- Keep the graph closed: every edge starts at a defined node, and every path
  ends at a defined success or error outcome.
- Include every behavior-affecting decision represented by the implementation.
- Use branch labels and outcome names that match the integration-test matrix.
- Add or update tests for every reachable path changed by the graph update.
- Document impossible or intentionally equivalent paths in the relevant test
  module's branch matrix.
