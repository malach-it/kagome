# kagome

Proof of concept of OAuth 2.0 and satellite specifications implementation in
Rust

## Server configuration

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
crypto:
  key_file: kagome.crypto.yaml
tokens:
  access_token_ttl: 3600
  authorization_code_ttl: 600
  id_token_ttl: 3600
credentials:
  - credential_configuration_id: UniversityDegreeCredential
    name: University Degree Credential
    vct: UniversityDegreeCredential
    type: UniversityDegreeCredential
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
      endpoints:
        - endpoint: https://identity.example.com/userinfo
          claims:
            - claim: sub
              target: sub
              id_token: false
              credential: [UniversityDegreeCredential]
```

Each `credentials` entry is advertised under its
`credential_configuration_id`. Its `name` is used for display metadata, while
`type` and `vct` are carried by issued credentials and used by presentation
requests and validation.

Set `KAGOME_CONFIG` to load a different file. Startup fails with a descriptive
error when the file cannot be read, contains invalid YAML or unknown fields, or
configures invalid server settings or clients. Client IDs must be unique, and
each client must have a non-empty secret and at least one redirect URI. The
required `crypto.key_file` is resolved relative to the main configuration and
loaded once at startup. It contains the distinct COSE encryption secrets plus
the private and public JWK material for credential, ID-token, and request-object
signatures. Startup verifies the configured algorithms, key IDs, public-key
shape, and every private/public key pairing. Keep the local key file out of
version control; `kagome.crypto.yaml` is ignored. The generator creates fresh
encryption secrets, Ed25519 credential and ID-token pairs, and a P-256 request-
object pair without overwriting an existing file. It requires OpenSSL and writes
the result with owner-only permissions. Restrict the local file to the server
account (for example,
`chmod 600 kagome.crypto.yaml`). Replacing an encryption secret invalidates all
outstanding artifacts in that context; replacing a signing pair immediately
changes its published JWK and invalidates signatures made with the previous
key. Coordinate rotation with the configured token and state lifetimes. The
optional per-client `password_file` points to an nginx-style
`name:bcrypt-hash[:comment]` file. Other password-hash formats are rejected at
startup. Relative paths are resolved from the YAML file, and credentials are
loaded once at startup. A client without `password_file`
cannot authenticate local resource owners. The committed
`kagome.htpasswd.example` contains the example users; create the ignored local
file with `htpasswd -B kagome.htpasswd username`. The
optional per-client `require_wallet_binding` flag requires wallet presentation
and credential-proof signatures to verify with the public key from the ID token
carried by the incoming authorization `code`. Its default is `false`. The
optional per-client `qr_code` flag changes successful SIOPv2, OpenID4VP, and
pre-authorized-code wallet redirects into an HTML page containing an inline QR
code, an `open in wallet` button, and a copyable URL. The button opens the exact
deep link that would otherwise be returned in the `Location` header in a
390-by-844 popup, with a normal link fallback when JavaScript is disabled. Because
signed request URLs can exceed standard QR capacity, the QR contains a random,
five-minute issuer relay URL that redirects to the same deep link and remains
usable for retries until it expires. Its default is `false`. The
optional per-client `federated_server` block configures the upstream OAuth
client, its authorization and token endpoints, and identity endpoints. Each
identity endpoint is called once with the upstream bearer token. Its non-empty
`claims` list maps dot-separated JSON claim paths to arbitrary resource-owner
profile attributes. A `username` or `sub` target identifies the resource owner.
Set a claim's `id_token` flag to include the mapped attribute in the signed
ID-token `profile`. Set `credential` to an array of credential configuration
IDs to include the attribute only in those credentials' subjects. `id_token`
defaults to `false`, and `credential` defaults to an empty array. Clients without
this block
continue to use local authentication.
Each client must explicitly opt into protocol capabilities through
`supported_grant_types` and `supported_response_types`; omitted or empty lists
deny every corresponding type. Every type in a combined request must be
allowed. Authorization responses also require their associated grant:
`code` requires `authorization_code`, `token` and `id_token` require `implicit`,
and the pre-authorized-code response requires its pre-authorized-code grant.
The local `kagome.yaml` is ignored by Git.

`server.address` controls the listening socket, while `server.issuer` is the
public HTTP origin used to construct federation callback URLs. The `tokens`
values configure access-token, authorization-code, and ID-token lifetimes in
seconds. `tokens.authorization_code_chain_max_depth` bounds nested authorization
codes (default `8`, accepted range `1..=32`). Omitted `tokens` configuration uses
the example defaults.

For a federated client, `GET /authorize` redirects to the configured upstream
authorization endpoint with `response_type=code`, the upstream `client_id`, the
callback URI derived from `server.issuer`, and authenticated short-lived state.
The encrypted state carries the parsed authorization request attributes. The
callback restores an `AuthorizeLoginRequest`, exchanges a returned authorization
code at the upstream token endpoint, fetches and maps the configured identity
claims, and continues the authorize response flow. Local `POST /authorize`
authentication is disabled for that client.
Direct validation and generation failures from `/authorize` and
`/siopv2-request` render the branded HTML authorization-error page; these
endpoints do not return JSON error bodies.
[`kagome.schema.json`](kagome.schema.json) provides editor validation
and completion for the example. After changing the Rust configuration types,
regenerate it with:

```bash
cargo run --example generate_config_schema > kagome.schema.json
```

## OpenID for Verifiable Credential Issuance

Kagome implements a bounded profile of the OpenID for Verifiable Credential
Issuance 1.0 Final specification:

- Credential Issuer metadata at `/.well-known/openid-credential-issuer`
- OAuth Authorization Server metadata at
  `/.well-known/oauth-authorization-server`
- A pre-authorized-code `/authorize` response that redirects with a Credential Offer
- The Pre-Authorized Code grant at `/token`
- Immediate issuance of configured `jwt_vc` credentials at `/credential`
- Centralized public signing keys for credentials, ID tokens, and request
  objects at `/jwks`

The Pre-Authorized Code is a five-minute COSE_Encrypt0 artifact containing the
authorized credential configuration and subject. Its transaction code is
`493536`. The profile is stateless, so a Pre-Authorized Code can be exchanged
more than once until it expires; no redemption store is used.

OAuth access tokens and credential access tokens are opaque COSE_Encrypt0
artifacts. Encryption is centralized and domain-separated by artifact-specific
keys and external authenticated data, so an artifact cannot be substituted in
another protocol context. Server-generated credentials and ID tokens use
separate centralized Ed25519 signing identities; request objects retain their
centralized ES256 identity for wallet interoperability. All public keys are
published by the JWKS endpoint.

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
  one configured `jwt_vc` credential.
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
authorization codes are COSE_Encrypt0 values.

Optional environment variables:

```bash
KAGOME_TOKEN_TARGET=http://kagome:4000/token
KAGOME_CLIENT_ID=client_id
KAGOME_CLIENT_SECRET=client_secret
KAGOME_TOKEN_TIMEOUT=5
```

## Load testing

The k6 scripts cover every documented identity flow. Run one through its
Compose service, for example:

```bash
docker compose --profile loadtest run --rm k6-openid4vp
```

Available services are `k6-authorization-code`, `k6-client-credentials`,
`k6-code-chain`, `k6-resource-owner-password`, `k6-implicit`,
`k6-pre-authorized-code`, `k6-siopv2`, and `k6-openid4vp`. Set `K6_VUS` and
`K6_DURATION` to change the default four-user, 30-second run. The scripts also
accept `KAGOME_SERVER_TARGET`, `KAGOME_TOKEN_TARGET`, `KAGOME_CLIENT_ID`,
`KAGOME_CLIENT_SECRET`, `KAGOME_REDIRECT_URI`, `KAGOME_USERNAME`,
`KAGOME_PASSWORD`, `KAGOME_TX_CODE`, `KAGOME_ISSUER`,
`KAGOME_AUTHORIZE_CLIENT_ID`, `KAGOME_AUTHORIZE_METHOD`, and
`KAGOME_PUBLIC_HOST` where applicable.

## License

This project is licensed under the MIT License. See [LICENSE](LICENSE).
