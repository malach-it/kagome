# SIOPv2 Flow Graphs

These graphs document Kagome's stateless Self-Issued OpenID Provider v2
direct-post authentication stage for OAuth authorization. The encrypted state
retains the requested response types, client, redirect URI, client state, and
optional authorization `code`. The request's authorization `response_type` is
also copied to the top-level state claims and drives the authorize continuation
after SIOPv2 authentication. Mermaid (`.mmd`) files are canonical; the
adjacent SVG files are rendered for direct review.

The request endpoint redirects to the validated OAuth `redirect_uri`, appending
the generated SIOPv2 authorization response fields as query parameters.
The configured `server.issuer` is the verifier origin used for the callback and
is authenticated as part of the encrypted state.
ID Token signature validation accepts both raw P-256 and Boruta Wallet's
canonical `jwk_jcs-pub` P-256 `did:key` representation.
Wallet and validation errors redirect to the trusted client `redirect_uri` with
`error`, optional `error_description`, and optional client `state` query
parameters. If no trusted redirect URI can be recovered, the endpoint returns
an escaped HTML error page.

## SIOPv2 Flow

[Mermaid source](siopv2.mmd)

![SIOPv2 flow](siopv2.svg)

## Authorization Request Endpoint

[Mermaid source](authorization_request_endpoint.mmd)

![SIOPv2 authorization request endpoint](authorization_request_endpoint.svg)

## Response Endpoint

[Mermaid source](response_endpoint.mmd)

![SIOPv2 response endpoint](response_endpoint.svg)

## Review Checklist

- Keep every graph closed with no dangling paths.
- Keep branch labels aligned with the integration-test matrix.
- Update Mermaid sources, rendered SVGs, and tests together.
