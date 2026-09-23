# kagome

Proof of concept of OAuth 2.0 and satellite specifications implementation in
Rust

The [identity flow graphs](docs/flows/README.md) document handler pipelines and
terminal HTTP outcomes. Resource actions document their purpose, prerequisites,
state effects, and failure boundaries inline through Rustdoc.

## Server configuration

Kagome’s configuration is organized into five areas: `server` defines the
listening address and public issuer URL; `crypto` points to the generated key
material; `tokens` sets token lifetimes and authorization-code chain limits;
`credentials` and `presentation_definitions` describe credentials and the
scopes that request them; and `clients` defines OAuth clients, redirect URIs,
supported protocol capabilities, wallet-binding/QR behavior, and optional
federation or password authentication. Copy the example configuration, set
`KAGOME_CONFIG` when using another file, and keep configuration and generated
keys private because they contain client secrets and signing material.

Copy the example configuration before starting Kagome:

```bash
cp kagome.example.yaml kagome.yaml
./scripts/generate-crypto-config.sh
```

Kagome loads `kagome.yaml` when it starts. The file has this structure:

```yaml
server:
  address: 0.0.0.0:4000
  issuer: http://localhost:4000
  workers: 4
  cors_origins:
    - "*"
  replay_protection: true
  rate_limit:
    count: 10
    time_unit: second
    penality: 500
    timeout: 5000
    memory_length: 50
crypto:
  key_file: kagome.crypto.yaml
tokens:
  access_token_ttl: 3600
  authorization_code_ttl: 600
  id_token_ttl: 3600
  pre_authorized_code_ttl: 300
  federation_state_ttl: 300
  presentation_state_ttl: 300
  siopv2_state_ttl: 300
credentials:
  - credential_configuration_id: UniversityDegreeCredential
    name: University Degree Credential
    vct: UniversityDegreeCredential
    type: [UniversityDegreeCredential]
presentation_definitions:
  - identifier: credential_presentation
    definition:
      id: credential_presentation
      input_descriptors:
        - id: credential
          constraints:
            fields:
              - path: [$.vc.type]
                filter:
                  type: array
                  contains: { const: UniversityDegreeCredential }
clients:
  - client_id: client_id
    client_secret: client_secret
    redirect_uris:
      - https://client.example.com/callback
    require_wallet_binding: false
    qr_code: false
    federated_server:
      client_id: kagome
      client_secret: federated_client_secret
      authorize_endpoint: https://identity.example.com/authorize
      token_endpoint: https://identity.example.com/token
      scope: openid profile
      endpoints:
        - endpoint: https://identity.example.com/userinfo
          claims:
            - claim: sub
              target: sub
              id_token: false
              credential: [UniversityDegreeCredential]
```

The example above is the complete configuration shape. In practice:

- `credentials` define issuable credential metadata and types.
- `presentation_definitions` map OAuth scopes to Presentation Exchange rules.
- `clients` must use unique IDs, non-empty secrets, and registered redirect URIs.
  Configure supported grants, response types, scopes, wallet binding, QR pages,
  password authentication, or federation as needed. A federated server's optional
  `scope` is sent only to that upstream server and is independent of the downstream
  client's requested scope.
- `server.replay_protection` defaults to `true` and controls process-local
  single-use checks for short-lived authorization artifacts. Set it to `false`
  only for controlled testing; replayed artifacts will then be accepted.
- `server.cors_origins` controls which browser origins may read CORS-enabled
  credential access-token, credential, JWKS, and well-known metadata responses.
  It defaults to `["*"]`; use exact HTTP or HTTPS origins, or an empty list to
  disable CORS. The wildcard cannot be combined with explicit origins.
- `server.rate_limit` applies Boruta-style adaptive throttling globally per
  client IP. `penality` and `timeout` are expressed in milliseconds, while
  `memory_length` controls the number of historical time-unit buckets. Set
  `server.rate_limit: false` to disable request throttling.
- `crypto.key_file` is generated once, resolved relative to the YAML file, and
  must be protected with owner-only permissions. Rotating keys invalidates
  related artifacts or signatures.
- `KAGOME_CONFIG` selects another configuration file. Startup rejects malformed
  YAML, unknown fields, invalid URLs, keys, clients, and capabilities.

For deployments, Kagome supports optional HTTPS through `KAGOME_HTTPS_CERT` and
`KAGOME_HTTPS_KEY`, and Docker Compose mounts configuration, keys, and password
files as read-only secrets under `/run/secrets`. The server enforces bounded
connection, request, header, body, and response-generation limits. Custom client
error and wallet templates can be mounted under `/templates`.

[`kagome.schema.json`](kagome.schema.json) provides editor validation and
completion; regenerate it with `cargo run --example generate_config_schema > kagome.schema.json`.

## OpenID for Verifiable Credential Issuance

Kagome provides a bounded OpenID4VCI 1.0 Final profile:

- Credential Issuer metadata at `/.well-known/openid-credential-issuer`
- OAuth Authorization Server metadata at
  `/.well-known/oauth-authorization-server`
- A pre-authorized-code `/authorize` response that redirects with a Credential Offer
- The Pre-Authorized Code grant at `/token`
- Immediate issuance of configured `jwt_vc` credentials at `/credential`
- Centralized public signing keys for credentials, ID tokens, and request
  objects at `/jwks`.

Pre-authorized codes and tokens are short-lived encrypted artifacts. Credential
proofs must include the access token’s `c_nonce`, and authorization-code or
chained flows require S256 PKCE. Credentials, ID tokens, and request objects use
separate signing identities. Replay tracking is bounded to the running process
and is not shared across replicas. Nonce endpoints, deferred or batch issuance,
request/response encryption, and notifications are not implemented. Replace
embedded development keys before deployment.

## OpenID for Verifiable Presentations

Kagome provides a bounded OpenID4VP 1.0 Final verifier profile:

- `GET /authorize?response_type=vp_token` creates a wallet authorization request
  using `response_mode=direct_post` for one configured presentation definition.
- `POST /presentation-response` accepts the form-encoded direct-post response.
- Presentation JWTs and embedded Credential JWTs use Ed25519. The verifier
  validates their signatures, validity periods, requested type and claims,
  holder key and subject binding, audience, nonce, and DCQL response shape.
- Wallet error responses are accepted for the bounded set documented by the
  response implementation.

Wallet invocation and QR rendering are handled by the authorization flow.
Transaction state is encrypted and short-lived, but replay state is not
persisted or shared across replicas. Strict single-use deployments must provide
an atomic shared store. Replace embedded development keys before deployment.

## Self-Issued OpenID Provider v2

Kagome implements a stateless SIOPv2 direct-post authentication stage for OAuth
authorization:

- `GET /siopv2-request` creates a signed self-issued ID-token request.
- `POST /siopv2-response` accepts the wallet’s form-encoded ID token or a
  supported wallet error.
- Requested response types, client and redirect parameters, client state, and
  optional authorization codes are retained in encrypted short-lived state.
- The configured `server.issuer` is the wallet-facing verifier `client_id`, and
  the returned ID token must use it as its audience.
- P-256 `did:key` and Boruta Wallet’s canonical `jwk_jcs-pub` representation are
  supported. S256 PKCE is required whenever the response includes `code`.

After validation, Kagome continues the original authorization flow and redirects
to the trusted client URI. Replay tracking is bounded to the running process and
is not shared across replicas; replace development signing keys before
deployment.

## Agent chat code-chain example

The agent-chat example demonstrates public-client authentication and chained
authorization codes: it obtains a hybrid `code id_token` response, then extends
the authorization-code chain for each agent handoff.

Run the example against the Docker Compose server with:

```bash
docker compose --profile tools run --rm agent-chat
```

Defaults match `kagome.example.yaml`; documented `KAGOME_*` variables override
the server, public host, redirect URI, credentials, and timeout.

## Load testing

The k6 scripts exercise every documented identity flow. Run one through Compose,
for example:

```bash
docker compose --profile loadtest run --rm k6-openid4vp
```

Services cover authorization code, client credentials, code chain, resource
owner password, implicit, pre-authorized code, SIOPv2, and OpenID4VP flows. Set
`K6_VUS` and `K6_DURATION` to change the defaults; flow-specific `KAGOME_*`
variables configure targets and credentials.

## Credits

This server is the result of an iterative research about authorization servers,
the result is still ongoing while the design is aimed to be compliant with the
standards. I would thank the people that participated and helped in the
research that led to this implementation. While the system provide a secure
rationale, the implementation cannot give insurance of perfect security. Do not
hesitate to give feedback if you see any impairment, to improve the
confidentiality, integrity or availability provided by the software.

## License

This project is licensed under the MIT License. See [LICENSE](LICENSE).
