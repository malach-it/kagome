# OpenID4VP Flow Graphs

These graphs document Kagome's bounded OpenID for Verifiable Presentations 1.0
direct-post verifier profile. Mermaid (`.mmd`) files are canonical; the adjacent
SVG files are rendered for direct review.

## Presentation Flow

[Mermaid source](presentation.mmd)

![OpenID4VP presentation flow](presentation.svg)

## Presentation Request Endpoint

[Mermaid source](presentation_request_endpoint.mmd)

![Presentation request endpoint](presentation_request_endpoint.svg)

## Presentation Response Endpoint

[Mermaid source](presentation_response_endpoint.mmd)

![Presentation response endpoint](presentation_response_endpoint.svg)

## Review Checklist

- Keep every graph closed with no dangling paths.
- Keep branch labels aligned with the integration-test matrix.
- Update Mermaid sources, rendered SVGs, and tests together.
