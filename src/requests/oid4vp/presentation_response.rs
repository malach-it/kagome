use crate::{
    errors::OAuthError,
    handlers::responses::oid4vp_json_response,
    resources::{
        presentation_state::{self, PresentationStateClaims},
        presentation_submission,
        verifiable_presentation::{self, ValidatedPresentation},
    },
    unit::{KagomeRequest, parse_request_parameter, request_header},
};

#[derive(Debug)]
pub struct PresentationResponseRequest<'a> {
    pub request: &'a KagomeRequest,
    pub content_type: Option<String>,
    pub state: Option<String>,
    pub vp_token: Option<String>,
    pub error: Option<String>,
    pub response: PresentationResponse,
}

#[derive(Debug, Default)]
pub struct PresentationResponse {
    pub state_claims: Option<PresentationStateClaims>,
    pub presentation: Option<ValidatedPresentation>,
    pub wallet_error: Option<String>,
}

impl<'a> PresentationResponseRequest<'a> {
    pub fn from_request(request: &'a KagomeRequest) -> Self {
        Self {
            request,
            content_type: request_header(request, "content-type"),
            state: parse_request_parameter(request, "state"),
            vp_token: parse_request_parameter(request, "vp_token"),
            error: parse_request_parameter(request, "error"),
            response: PresentationResponse::default(),
        }
    }

    pub fn to_response(&self) -> Result<String, OAuthError> {
        if self.response.state_claims.is_none() {
            return Err(OAuthError::invalid_token_response(
                "presentation state must be validated",
            ));
        }
        if self.response.presentation.is_none() && self.response.wallet_error.is_none() {
            return Err(OAuthError::invalid_token_response(
                "presentation response must be processed",
            ));
        }

        Ok(oid4vp_json_response("{}"))
    }
}

impl presentation_submission::ValidateEncoding for PresentationResponseRequest<'_> {
    fn request_content_type(&self) -> Option<&str> {
        self.content_type.as_deref()
    }
}

impl presentation_submission::ValidateWalletError for PresentationResponseRequest<'_> {
    fn request_wallet_error(&self) -> Option<&str> {
        self.error.as_deref()
    }

    fn request_vp_token(&self) -> Option<&str> {
        self.vp_token.as_deref()
    }

    fn add_wallet_error(&mut self, error: String) {
        self.response.wallet_error = Some(error);
    }
}

impl presentation_state::Validate for PresentationResponseRequest<'_> {
    fn request_state(&self) -> Option<&str> {
        self.state.as_deref()
    }

    fn add_presentation_state_claims(&mut self, claims: PresentationStateClaims) {
        self.response.state_claims = Some(claims);
    }
}

impl verifiable_presentation::Validate for PresentationResponseRequest<'_> {
    fn request_vp_token(&self) -> Option<&str> {
        self.vp_token.as_deref()
    }

    fn presentation_state_claims(&self) -> Option<&PresentationStateClaims> {
        self.response.state_claims.as_ref()
    }

    fn add_validated_presentation(&mut self, presentation: ValidatedPresentation) {
        self.response.presentation = Some(presentation);
    }
}
