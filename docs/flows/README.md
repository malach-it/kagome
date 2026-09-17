# Identity Flow Graphs

This catalog brings together every rendered identity-flow and endpoint graph.
Mermaid (`.mmd`) files remain the canonical sources; the adjacent SVG files are
generated artifacts. Detailed protocol notes live in each specification's
README.

## Complete Overview

The following self-contained landscape image combines every rendered graph in
this catalog.

![All identity flow graphs](all.svg)

## OAuth

[OAuth documentation](oauth/README.md)

### Flows

#### Authorization Code

[Mermaid source](oauth/authorization_code.mmd)

[Authorization code flow](oauth/authorization_code.svg)

#### Client Credentials

[Mermaid source](oauth/client_credentials.mmd)

[Client credentials flow](oauth/client_credentials.svg)

#### Code Chain

[Mermaid source](oauth/code_chain.mmd)

[Code-chain flow](oauth/code_chain.svg)

#### Implicit

[Mermaid source](oauth/implicit.mmd)

[Implicit flow](oauth/implicit.svg)

#### Resource Owner Password Credentials

[Mermaid source](oauth/resource_owner_password_credentials.mmd)

[Resource owner password credentials flow](oauth/resource_owner_password_credentials.svg)

### Endpoints

#### Authorize

[Mermaid source](oauth/authorize_endpoint.mmd)

[Authorize endpoint](oauth/authorize_endpoint.svg)

#### Federation Callback

[Mermaid source](oauth/federation_callback.mmd)

[Federation callback endpoint](oauth/federation_callback.svg)

#### Token

[Mermaid source](oauth/token_endpoint.mmd)

[Token endpoint](oauth/token_endpoint.svg)

#### Wallet Authorization

[Mermaid source](oauth/wallet_authorization_endpoint.mmd)

[Wallet authorization endpoint](oauth/wallet_authorization_endpoint.svg)

## OpenID4VCI

[OpenID4VCI documentation](openid4vci/README.md)

### Flows

#### Pre-Authorized Code

[Mermaid source](openid4vci/pre_authorized_code.mmd)

[Pre-authorized code flow](openid4vci/pre_authorized_code.svg)

### Endpoints

#### Authorization Server Metadata

[Mermaid source](openid4vci/authorization_server_metadata_endpoint.mmd)

[Authorization server metadata endpoint](openid4vci/authorization_server_metadata_endpoint.svg)

#### Credential

[Mermaid source](openid4vci/credential_endpoint.mmd)

[Credential endpoint](openid4vci/credential_endpoint.svg)

#### Credential Issuer Metadata

[Mermaid source](openid4vci/credential_issuer_metadata_endpoint.mmd)

[Credential issuer metadata endpoint](openid4vci/credential_issuer_metadata_endpoint.svg)

#### JWKS

[Mermaid source](openid4vci/jwks_endpoint.mmd)

[JWKS endpoint](openid4vci/jwks_endpoint.svg)

## OpenID4VP

[OpenID4VP documentation](openid4vp/README.md)

### Flows

#### Presentation

[Mermaid source](openid4vp/presentation.mmd)

[Presentation flow](openid4vp/presentation.svg)

### Endpoints

#### Presentation Request

[Mermaid source](openid4vp/presentation_request_endpoint.mmd)

[Presentation request endpoint](openid4vp/presentation_request_endpoint.svg)

#### Presentation Response

[Mermaid source](openid4vp/presentation_response_endpoint.mmd)

[Presentation response endpoint](openid4vp/presentation_response_endpoint.svg)

## SIOPv2

[SIOPv2 documentation](siopv2/README.md)

### Flows

#### SIOPv2

[Mermaid source](siopv2/siopv2.mmd)

[SIOPv2 flow](siopv2/siopv2.svg)

### Endpoints

#### Authorization Request

[Mermaid source](siopv2/authorization_request_endpoint.mmd)

[SIOPv2 authorization request endpoint](siopv2/authorization_request_endpoint.svg)

#### Response

[Mermaid source](siopv2/response_endpoint.mmd)

[SIOPv2 response endpoint](siopv2/response_endpoint.svg)

## Server

### Endpoints

#### Echo

[Mermaid source](server/echo_endpoint.mmd)

[Echo endpoint](server/echo_endpoint.svg)
