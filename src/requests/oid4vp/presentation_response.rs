use crate::{
    errors::OAuthError,
    handlers::responses::{
        authorization_error_redirect_response, authorization_request_redirect_response,
    },
    resources::{
        authorization_code::{self, AuthorizationCode},
        client_credentials,
        pkce::CodeChallenge,
        presentation_state::{self, PresentationStateClaims},
        presentation_submission,
        verifiable_presentation::{self, ValidatedPresentation},
    },
    unit::{KagomeRequest, parse_query_parameter, parse_request_parameter, request_header},
};

#[derive(Debug)]
pub struct PresentationResponseRequest<'a> {
    pub request: &'a KagomeRequest,
    pub content_type: Option<String>,
    pub state: Option<String>,
    pub vp_token: Option<String>,
    pub presentation_submission: Option<String>,
    pub error: Option<String>,
    pub error_description: Option<String>,
    pub response: PresentationResponse,
}

#[derive(Debug, Default)]
pub struct PresentationResponse {
    pub state: Option<String>,
    pub state_claims: Option<PresentationStateClaims>,
    pub presentation: Option<ValidatedPresentation>,
    pub presentation_submission_validated: bool,
    pub wallet_error: Option<String>,
    pub authorization_code: Option<AuthorizationCode>,
    pub authorization_redirect_uri: Option<String>,
}

impl<'a> PresentationResponseRequest<'a> {
    pub fn from_request(request: &'a KagomeRequest) -> Self {
        Self {
            request,
            content_type: request_header(request, "content-type"),
            state: parse_query_parameter(request, "state")
                .or_else(|| parse_request_parameter(request, "state")),
            vp_token: parse_request_parameter(request, "vp_token"),
            presentation_submission: parse_request_parameter(request, "presentation_submission"),
            error: parse_request_parameter(request, "error"),
            error_description: parse_request_parameter(request, "error_description"),
            response: PresentationResponse::default(),
        }
    }

    pub fn to_response(&self) -> Result<String, OAuthError> {
        if self.response.state_claims.is_none() {
            return Err(OAuthError::invalid_token_response(
                "presentation state must be validated",
            ));
        }
        if self.response.authorization_redirect_uri.is_none() {
            return Err(OAuthError::invalid_token_response(
                "presentation redirect_uri must be validated",
            ));
        }
        if self.response.presentation.is_none() && self.response.wallet_error.is_none() {
            return Err(OAuthError::invalid_token_response(
                "presentation response must be processed",
            ));
        }

        if self.response.wallet_error.is_some() {
            let state = self.response.state_claims.as_ref().ok_or_else(|| {
                OAuthError::invalid_token_response("presentation state must be validated")
            })?;
            return Ok(authorization_error_redirect_response(
                self.response
                    .authorization_redirect_uri
                    .as_deref()
                    .ok_or_else(|| {
                        OAuthError::invalid_token_response(
                            "presentation redirect_uri must be validated",
                        )
                    })?,
                self.response
                    .wallet_error
                    .as_deref()
                    .unwrap_or("invalid_request"),
                self.error_description.as_deref(),
                state.authorization_state.as_deref(),
            ));
        }

        let state = self.response.state_claims.as_ref().ok_or_else(|| {
            OAuthError::invalid_token_response("presentation state must be validated")
        })?;
        let authorization_code = self.response.authorization_code.as_ref().ok_or_else(|| {
            OAuthError::invalid_token_response("presentation response requires authorization code")
        })?;
        let mut parameters = vec![("code", authorization_code.value.as_str())];
        if let Some(client_state) = state.authorization_state.as_deref() {
            parameters.push(("state", client_state));
        }

        Ok(authorization_request_redirect_response(
            self.response
                .authorization_redirect_uri
                .as_deref()
                .ok_or_else(|| {
                    OAuthError::invalid_token_response(
                        "presentation redirect_uri must be validated",
                    )
                })?,
            &parameters,
        ))
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

    fn request_presentation_submission(&self) -> Option<&str> {
        self.presentation_submission.as_deref()
    }

    fn add_wallet_error(&mut self, error: String) {
        self.response.wallet_error = Some(error);
    }
}

impl presentation_submission::Validate for PresentationResponseRequest<'_> {
    fn request_presentation_submission(&self) -> Option<&str> {
        self.presentation_submission.as_deref()
    }

    fn presentation_state_claims(&self) -> Option<&PresentationStateClaims> {
        self.response.state_claims.as_ref()
    }

    fn mark_presentation_submission_validated(&mut self) {
        self.response.presentation_submission_validated = true;
    }
}

impl presentation_state::Validate for PresentationResponseRequest<'_> {
    fn request_state(&self) -> Option<&str> {
        self.state.as_deref()
    }

    fn add_presentation_state_claims(&mut self, state: &str, claims: PresentationStateClaims) {
        self.response.state = Some(state.to_owned());
        self.response.state_claims = Some(claims);
    }
}

impl presentation_state::Consume for PresentationResponseRequest<'_> {
    fn validated_presentation_state(&self) -> Option<&str> {
        self.response.state.as_deref()
    }

    fn presentation_state_expiration(&self) -> Option<u64> {
        self.response.state_claims.as_ref().map(|claims| claims.exp)
    }
}

impl client_credentials::Validate for PresentationResponseRequest<'_> {
    fn request_client_id(&self) -> Option<&str> {
        self.response
            .state_claims
            .as_ref()
            .map(|state| state.authorization_client_id.as_str())
    }

    fn require_client_secret(&self) -> bool {
        false
    }

    fn request_redirect_uri(&self) -> Option<&str> {
        self.response
            .state_claims
            .as_ref()
            .map(|state| state.authorization_redirect_uri.as_str())
    }

    fn require_redirect_uri(&self) -> bool {
        true
    }

    fn add_client_credentials(
        &mut self,
        client_credentials: client_credentials::ClientCredentials,
    ) {
        self.response.authorization_redirect_uri = client_credentials.redirect_uri;
    }
}

impl verifiable_presentation::Validate for PresentationResponseRequest<'_> {
    fn request_vp_token(&self) -> Option<&str> {
        self.vp_token.as_deref()
    }

    fn presentation_state_claims(&self) -> Option<&PresentationStateClaims> {
        self.response.state_claims.as_ref()
    }

    fn presentation_submission_validated(&self) -> bool {
        self.response.presentation_submission_validated
    }

    fn add_validated_presentation(&mut self, presentation: ValidatedPresentation) {
        self.response.presentation = Some(presentation);
    }
}

impl authorization_code::Generate for PresentationResponseRequest<'_> {
    fn previous_authorization_code(&self) -> Option<&str> {
        None
    }

    fn client_id(&self) -> Option<&str> {
        self.response
            .state_claims
            .as_ref()
            .map(|state| state.authorization_client_id.as_str())
    }

    fn id_token(&self) -> Option<&str> {
        None
    }

    fn code_challenge(&self) -> Option<&CodeChallenge> {
        self.response
            .state_claims
            .as_ref()
            .and_then(|state| state.code_challenge.as_ref())
    }

    fn username(&self) -> Option<&str> {
        self.response
            .presentation
            .as_ref()
            .map(|presentation| presentation.subject.as_str())
    }

    fn add_authorization_code(&mut self, authorization_code: AuthorizationCode) {
        self.response.authorization_code = Some(authorization_code);
    }

    fn require_id_token(&self) -> bool {
        false
    }

    fn require_username(&self) -> bool {
        true
    }
}
