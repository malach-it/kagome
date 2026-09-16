use serde::Serialize;
use serde_json::{Value, json};

use crate::errors::OAuthError;

use super::{
    credential_issuer, presentation_state::PresentationState, request_object,
    verifiable_presentation, verifier,
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

pub fn generate<T: Generate>(mut request: T) -> Result<T, OAuthError> {
    let verifier = request
        .verifier()
        .ok_or_else(|| OAuthError::invalid_token_response("verifier is required"))?;
    let state = request
        .presentation_state()
        .ok_or_else(|| OAuthError::invalid_token_response("presentation state is required"))?;
    let redirect_uri = verifier::response_uri_with_state(verifier, &state.value);
    let credential_types: Vec<_> = crate::config::Config::global()
        .credentials
        .iter()
        .map(|credential| credential.credential_type.as_str())
        .collect();
    let credential_vcts: Vec<_> = crate::config::Config::global()
        .credentials
        .iter()
        .map(|credential| credential.vct.as_str())
        .collect();
    let claims = PresentationRequestClaims {
        iss: &state.claims.client_id,
        aud: request_object::SELF_ISSUED_AUDIENCE,
        client_id: &state.claims.client_id,
        redirect_uri: &redirect_uri,
        response_type: "vp_token",
        response_mode: "direct_post",
        nonce: &state.claims.nonce,
        state: &state.value,
        presentation_definition: json!({
            "id": state.claims.presentation_definition_id,
            "input_descriptors": [{
                "id": state.claims.input_descriptor_id,
                "format": {
                    credential_issuer::CREDENTIAL_FORMAT: {
                        "alg": ["EdDSA"]
                    }
                },
                "constraints": {
                    "fields": [{
                        "path": ["$.vc.type"],
                        "filter": {
                            "type": "array",
                            "contains": {"enum": credential_types}
                        }
                    }, {
                        "path": ["$.vc.credentialSubject.id"]
                    }, {
                        "path": ["$.vct", "$.vc.vct"],
                        "filter": {"type": "string", "enum": credential_vcts}
                    }]
                }
            }]
        }),
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
