use serde::Serialize;

use crate::errors::OAuthError;

use super::{request_object, siopv2_state::SiopState};

pub const RESPONSE_PATH: &str = "/siopv2-response";
pub const RESPONSE_TYPE: &str = "id_token";

#[derive(Debug)]
pub struct SignedSiopRequest {
    pub value: String,
    pub client_id: String,
}

#[derive(Debug, Serialize)]
struct RequestClaims<'a> {
    iss: &'a str,
    aud: &'static str,
    client_id: &'a str,
    redirect_uri: &'a str,
    response_type: &'a str,
    response_mode: &'static str,
    scope: &'static str,
    nonce: &'a str,
    state: &'a str,
    iat: u64,
    exp: u64,
    client_metadata: ClientMetadata,
}

#[derive(Debug, Serialize)]
struct ClientMetadata {
    subject_syntax_types_supported: [&'static str; 2],
    id_token_signed_response_alg: &'static str,
}

pub trait Generate {
    fn siop_state(&self) -> Option<&SiopState>;
    fn add_signed_siop_request(&mut self, request: SignedSiopRequest);
}

/// Signs a SIOPv2 direct-post request from generated SIOP state.
///
/// Requires generated state and binds its verifier, nonce, lifetime, and encrypted transaction to
/// an ES256 self-issued-ID request. The signed request object and client ID are added to the
/// request; nonce, state, and redirect URI remain inside the signed claims instead of being
/// duplicated as wallet deep-link parameters.
///
/// # Errors
///
/// Returns `invalid_token_response` when state is absent or request-object signing fails.
pub fn generate<T: Generate>(mut request: T) -> Result<T, OAuthError> {
    let state = request
        .siop_state()
        .ok_or_else(|| OAuthError::invalid_token_response("siop state is required"))?;
    let client_id = response_uri(&state.claims.verifier);
    let redirect_uri = response_uri_with_state(&state.claims.verifier, &state.value);
    let claims = RequestClaims {
        iss: &client_id,
        aud: request_object::SELF_ISSUED_AUDIENCE,
        client_id: &client_id,
        redirect_uri: &redirect_uri,
        response_type: RESPONSE_TYPE,
        response_mode: "direct_post",
        scope: "openid",
        nonce: &state.claims.nonce,
        state: &state.value,
        iat: state.claims.iat,
        exp: state.claims.exp,
        client_metadata: ClientMetadata {
            subject_syntax_types_supported: ["did:key", "urn:ietf:params:oauth:jwk-thumbprint"],
            id_token_signed_response_alg: "ES256",
        },
    };
    let value = request_object::sign(&claims)?;

    request.add_signed_siop_request(SignedSiopRequest { value, client_id });
    Ok(request)
}

/// Constructs the verifier's SIOPv2 response endpoint URI.
///
/// The caller must provide a normalized verifier base URI; this helper appends
/// [`RESPONSE_PATH`] without modifying the base.
pub fn response_uri(verifier: &str) -> String {
    format!("{verifier}{RESPONSE_PATH}")
}

/// Constructs a SIOPv2 response URI carrying percent-encoded transaction state.
///
/// State is encoded as a single query parameter using the RFC 3986 unreserved character set.
pub fn response_uri_with_state(verifier: &str, state: &str) -> String {
    format!("{}?state={}", response_uri(verifier), percent_encode(state))
}

fn percent_encode(value: &str) -> String {
    value
        .bytes()
        .flat_map(|byte| match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                vec![byte as char]
            }
            byte => format!("%{byte:02X}").chars().collect(),
        })
        .collect()
}
