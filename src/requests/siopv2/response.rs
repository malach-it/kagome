use crate::{
    errors::OAuthError,
    handlers::responses::{oauth_error_html_response, siopv2_error_redirect_response},
    resources::{
        self_issued_id_token::{self, ValidatedSelfIssuedIdToken, ValidatedWalletError},
        siopv2_state::{self, SiopStateClaims},
    },
    unit::{KagomeRequest, parse_query_parameter, parse_request_parameter, request_header},
};

#[derive(Debug)]
pub struct SiopResponseRequest<'a> {
    pub request: &'a KagomeRequest,
    pub content_type: Option<String>,
    pub state: Option<String>,
    pub id_token: Option<String>,
    pub error: Option<String>,
    pub error_description: Option<String>,
    pub response: SiopResponse,
}

#[derive(Debug, Default)]
pub struct SiopResponse {
    pub state: Option<String>,
    pub state_claims: Option<SiopStateClaims>,
    pub error_context: Option<SiopErrorContext>,
    pub id_token: Option<ValidatedSelfIssuedIdToken>,
    pub wallet_error: Option<ValidatedWalletError>,
}

#[derive(Clone, Debug)]
pub struct SiopErrorContext {
    pub redirect_uri: String,
    pub state: Option<String>,
}

impl<'a> SiopResponseRequest<'a> {
    pub fn from_request(request: &'a KagomeRequest) -> Self {
        Self {
            request,
            content_type: request_header(request, "content-type"),
            state: parse_query_parameter(request, "state")
                .or_else(|| parse_request_parameter(request, "state")),
            id_token: parse_request_parameter(request, "id_token"),
            error: parse_request_parameter(request, "error"),
            error_description: parse_request_parameter(request, "error_description"),
            response: SiopResponse::default(),
        }
    }

    pub fn error_context(&self) -> Option<SiopErrorContext> {
        self.response.error_context.clone()
    }

    pub fn to_response(&self) -> Result<String, OAuthError> {
        let state =
            self.response.state_claims.as_ref().ok_or_else(|| {
                OAuthError::invalid_token_response("siop state must be validated")
            })?;
        let wallet_error = self.response.wallet_error.as_ref().ok_or_else(|| {
            OAuthError::invalid_token_response("siop id_token must continue the authorize flow")
        })?;
        let Some(error_context) = self.response.error_context.as_ref() else {
            return Ok(oauth_error_html_response(
                state.authorization.client_id.as_deref(),
                &wallet_error.error,
                wallet_error.error_description.as_deref(),
            ));
        };

        Ok(siopv2_error_redirect_response(
            &error_context.redirect_uri,
            &wallet_error.error,
            wallet_error.error_description.as_deref(),
            error_context.state.as_deref(),
        ))
    }
}

impl siopv2_state::Validate for SiopResponseRequest<'_> {
    fn request_state(&self) -> Option<&str> {
        self.state.as_deref()
    }

    fn add_siop_state_claims(&mut self, state: &str, claims: SiopStateClaims) {
        self.response.error_context =
            claims
                .authorization
                .redirect_uri
                .as_ref()
                .map(|uri| SiopErrorContext {
                    redirect_uri: uri.clone(),
                    state: claims.authorization.state.clone(),
                });
        self.response.state = Some(state.to_owned());
        self.response.state_claims = Some(claims);
    }
}

impl siopv2_state::Consume for SiopResponseRequest<'_> {
    fn validated_state(&self) -> Option<&str> {
        self.response.state.as_deref()
    }

    fn state_expiration(&self) -> Option<u64> {
        self.response.state_claims.as_ref().map(|claims| claims.exp)
    }
}

impl self_issued_id_token::Validate for SiopResponseRequest<'_> {
    fn request_id_token(&self) -> Option<&str> {
        self.id_token.as_deref()
    }

    fn state_claims(&self) -> Option<&SiopStateClaims> {
        self.response.state_claims.as_ref()
    }

    fn add_validated_id_token(&mut self, id_token: ValidatedSelfIssuedIdToken) {
        self.response.id_token = Some(id_token);
    }
}

impl self_issued_id_token::ValidateEncoding for SiopResponseRequest<'_> {
    fn request_content_type(&self) -> Option<&str> {
        self.content_type.as_deref()
    }
}

impl self_issued_id_token::ValidateWalletError for SiopResponseRequest<'_> {
    fn request_wallet_error(&self) -> Option<&str> {
        self.error.as_deref()
    }

    fn request_wallet_error_description(&self) -> Option<&str> {
        self.error_description.as_deref()
    }

    fn request_id_token(&self) -> Option<&str> {
        self.id_token.as_deref()
    }

    fn add_wallet_error(&mut self, error: ValidatedWalletError) {
        self.response.wallet_error = Some(error);
    }
}
