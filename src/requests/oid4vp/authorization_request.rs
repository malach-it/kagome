use crate::{
    errors::OAuthError,
    handlers::responses::oid4vp_json_response,
    resources::{
        credential_issuer::{CREDENTIAL_FORMAT, CREDENTIAL_TYPE},
        presentation_state::{self, PresentationState},
        verifier,
    },
    unit::{KagomeRequest, request_header},
};

#[derive(Debug)]
pub struct PresentationAuthorizationRequest<'a> {
    pub request: &'a KagomeRequest,
    pub host: Option<String>,
    pub response: PresentationAuthorizationResponse,
}

#[derive(Debug, Default)]
pub struct PresentationAuthorizationResponse {
    pub verifier: Option<String>,
    pub presentation_state: Option<PresentationState>,
}

impl<'a> PresentationAuthorizationRequest<'a> {
    pub fn from_request(request: &'a KagomeRequest) -> Self {
        Self {
            request,
            host: request_header(request, "host"),
            response: PresentationAuthorizationResponse::default(),
        }
    }

    pub fn to_response(&self) -> Result<String, OAuthError> {
        let verifier = self
            .response
            .verifier
            .as_deref()
            .ok_or_else(|| OAuthError::invalid_token_response("verifier is required"))?;
        let state =
            self.response.presentation_state.as_ref().ok_or_else(|| {
                OAuthError::invalid_token_response("presentation state is required")
            })?;
        let response_body = serde_json::json!({
            "client_id": state.claims.client_id,
            "response_uri": verifier::response_uri(verifier),
            "response_type": "vp_token",
            "response_mode": "direct_post",
            "nonce": state.claims.nonce,
            "state": state.value,
            "dcql_query": {
                "credentials": [{
                    "id": presentation_state::QUERY_ID,
                    "format": CREDENTIAL_FORMAT,
                    "meta": {
                        "type_values": [["VerifiableCredential", CREDENTIAL_TYPE]]
                    },
                    "claims": [
                        {"path": ["credentialSubject", "id"]},
                        {"path": ["credentialSubject", "degree"]}
                    ]
                }]
            },
            "client_metadata": {
                "vp_formats_supported": {
                    CREDENTIAL_FORMAT: {"alg_values": ["EdDSA"]}
                }
            }
        })
        .to_string();

        Ok(oid4vp_json_response(&response_body))
    }
}

impl verifier::Validate for PresentationAuthorizationRequest<'_> {
    fn request_host(&self) -> Option<&str> {
        self.host.as_deref()
    }

    fn add_verifier(&mut self, verifier: String) {
        self.response.verifier = Some(verifier);
    }
}

impl presentation_state::Generate for PresentationAuthorizationRequest<'_> {
    fn verifier(&self) -> Option<&str> {
        self.response.verifier.as_deref()
    }

    fn add_presentation_state(&mut self, state: PresentationState) {
        self.response.presentation_state = Some(state);
    }
}
