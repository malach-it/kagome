# kagome

Proof of concept of OAuth 2.0 and satellite specifications implementation in
Rust

## OpenID for Verifiable Credential Issuance

Kagome implements a bounded profile of the OpenID for Verifiable Credential
Issuance 1.0 Final specification:

- Credential Issuer metadata at `/.well-known/openid-credential-issuer`
- OAuth Authorization Server metadata at
  `/.well-known/oauth-authorization-server`
- A Credential Offer by reference at `/credential-offer`
- The Pre-Authorized Code grant at `/token`
- Immediate issuance of one `jwt_vc_json` University Degree Credential at
  `/credential`
- The Ed25519 credential-signing public key at `/jwks`

The Pre-Authorized Code is a five-minute COSE_Encrypt0 artifact containing the
authorized credential configuration and subject. Its transaction code is
`493536`. The profile is stateless, so a Pre-Authorized Code can be exchanged
more than once until it expires; no redemption store is used.

The issued JWT VC is signed with Ed25519 and bound through its `cnf` claim to
the demonstration holder key used by the presentation profile. This proof of
concept does not require a proof in the Credential Request and does not support
a nonce endpoint, deferred issuance, request or response encryption, batch
issuance, or notifications. The embedded keys and fixed transaction code are
development fixtures and must be replaced for deployment.

## OpenID for Verifiable Presentations

Kagome implements a bounded verifier profile of OpenID for Verifiable
Presentations 1.0 Final:

- `GET /presentation-request` creates authorization request parameters using
  `response_type=vp_token`, `response_mode=direct_post`, and a DCQL query for
  one `jwt_vc_json` University Degree Credential.
- `POST /presentation-response` accepts the form-encoded direct-post response.
- Presentation JWTs and embedded Credential JWTs use Ed25519. The verifier
  validates their signatures, validity periods, requested type and claims,
  holder key and subject binding, audience, nonce, and DCQL response shape.
- Wallet error responses are accepted for the bounded set documented by the
  response implementation.

The presentation request endpoint is a proof-of-concept helper that returns the
authorization request parameters as JSON; wallet invocation and QR rendering
are outside this profile. The five-minute nonce and transaction context are
carried in COSE_Encrypt0 state. No Credential, Presentation, or replay state is
stored. A valid presentation response can therefore be replayed until its state
expires. Deployments that require replay prevention need an atomic shared
single-use store. The embedded verifier, issuer, and holder keys are development
fixtures and must be replaced for deployment.

## Agentic Chat (specification additions prototype)

Run the agentic chat script through Docker Compose with:

```bash
docker compose --profile tools run --rm agentic-chat
```

The script keeps a simple agentic workflow where a planner creates a plan, a
critic reviews it, and a writer produces the final reply locally.

Each agent has its own signing key. When an agent receives a message, it signs
an `id_token` and calls the local `/token` endpoint with the `code_chain` grant
before processing that message. The `id_token` remains a JWT, while issued
authorization codes are COSE_Mac0 values.

Optional environment variables:

```bash
KAGOME_TOKEN_TARGET=http://kagome:4000/token
KAGOME_CLIENT_ID=client_id
KAGOME_CLIENT_SECRET=client_secret
KAGOME_TOKEN_TIMEOUT=5
```

## License

This project is licensed under the MIT License. See [LICENSE](LICENSE).
