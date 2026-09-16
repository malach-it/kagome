use serde::Serialize;
use serde_json::{Value, json};

use crate::errors::OAuthError;

use super::{
    presentation_state::PresentationState, request_object, verifiable_presentation, verifier,
};

#[derive(Debug)]
pub struct SignedPresentationRequest {
    pub value: String,
    pub redirect_uri: String,
}

#[derive(Serialize)]
struct PresentationRequestClaims<'a> {
    iss: &'a str,
    aud: &'static str,
    client_id: &'a str,
    redirect_uri: &'a str,
    response_type: &'static str,
    response_mode: &'static str,
    nonce: &'a str,
    state: &'a str,
    presentation_definition: Value,
    client_metadata: Value,
    iat: u64,
    exp: u64,
}

pub trait Generate {
    fn verifier(&self) -> Option<&str>;
    fn presentation_state(&self) -> Option<&PresentationState>;
    fn add_signed_presentation_request(&mut self, request: SignedPresentationRequest);
}

/// Signs an OpenID4VP direct-post request from validated verifier and presentation state.
///
/// Requires verifier and generated presentation-state data. It binds the definition, nonce,
/// client identity, response endpoint, supported VP algorithms, and state lifetime into a signed
/// request object, then stores that object and its redirect URI. Nonce and state remain inside the
/// signed claims instead of being duplicated as wallet deep-link parameters.
///
/// # Errors
///
/// Returns `invalid_token_response` when prerequisite state is missing or request-object signing
/// fails.
pub fn generate<T: Generate>(mut request: T) -> Result<T, OAuthError> {
    let verifier = request
        .verifier()
        .ok_or_else(|| OAuthError::invalid_token_response("verifier is required"))?;
    let state = request
        .presentation_state()
        .ok_or_else(|| OAuthError::invalid_token_response("presentation state is required"))?;
    let redirect_uri = verifier::response_uri_with_state(verifier, &state.value);
    let claims = PresentationRequestClaims {
        iss: &state.claims.client_id,
        aud: request_object::SELF_ISSUED_AUDIENCE,
        client_id: &state.claims.client_id,
        redirect_uri: &redirect_uri,
        response_type: "vp_token",
        response_mode: "direct_post",
        nonce: &state.claims.nonce,
        state: &state.value,
        presentation_definition: state.claims.presentation_definition.clone(),
        client_metadata: json!({
            "vp_formats_supported": {
                "jwt_vp": {
                    "alg_values": verifiable_presentation::SUPPORTED_ALGORITHM_NAMES
                }
            }
        }),
        iat: state.claims.iat,
        exp: state.claims.exp,
    };
    let value = request_object::sign(&claims)?;

    request.add_signed_presentation_request(SignedPresentationRequest {
        value,
        redirect_uri,
    });
    Ok(request)
}
