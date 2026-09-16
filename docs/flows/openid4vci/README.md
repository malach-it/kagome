# OpenID4VCI Flow Graphs

These graphs document Kagome's bounded OpenID for Verifiable Credential
Issuance 1.0 pre-authorized-code profile. Mermaid (`.mmd`) files are canonical;
the adjacent SVG files are rendered for direct review.

## Issuance Flow

[Mermaid source](pre_authorized_code.mmd)

![Pre-authorized code issuance flow](pre_authorized_code.svg)

## Credential Issuer Metadata Endpoint

[Mermaid source](credential_issuer_metadata_endpoint.mmd)

![Credential Issuer metadata endpoint](credential_issuer_metadata_endpoint.svg)

## Authorization Server Metadata Endpoint

[Mermaid source](authorization_server_metadata_endpoint.mmd)

![Authorization Server metadata endpoint](authorization_server_metadata_endpoint.svg)

## Credential Endpoint

The credential request must include a JWT proof. A valid asymmetric proof binds
the issued credential subject and `cnf.jwk` to the wallet's DID and public key;
the proof audience must be the credential issuer, its `iat` must be recent, and
its `nonce` must equal the draft-11 `c_nonce` returned with and carried by the
credential access token. Requests without a proof are rejected with
`invalid_or_missing_proof`.
For an authorize client configured with `require_wallet_binding: true`, the
incoming authorization code must carry a validated asymmetric public JWK,
either directly from a SIOPv2 continuation or from a valid ID token. Kagome
carries that JWK through the encrypted pre-authorized code
and encrypted credential access token and verifies
the proof signature against both its declared wallet key and the ID-token key.

[Mermaid source](credential_endpoint.mmd)

![Credential endpoint](credential_endpoint.svg)

## JWKS Endpoint

[Mermaid source](jwks_endpoint.mmd)

![JWKS endpoint](jwks_endpoint.svg)

## Review Checklist

- Keep every graph closed with no dangling paths.
- Keep branch labels aligned with the integration-test matrix.
- Update Mermaid sources, rendered SVGs, and tests together.
