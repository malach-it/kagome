use crate::{
    errors::OAuthError,
    handlers::responses::{authorization_request_uri, wallet_authorization_response},
    resources::{
        siopv2_request::{self, SignedSiopRequest},
        siopv2_state::{self, SiopAuthorizationParameters, SiopState},
    },
    unit::KagomeRequest,
};

#[derive(Debug)]
pub struct SiopAuthorizationRequest<'a> {
    pub request: &'a KagomeRequest,
    pub authorization: SiopAuthorizationParameters,
    pub response: SiopAuthorizationResponse,
}

#[derive(Debug, Default)]
pub struct SiopAuthorizationResponse {
    pub state: Option<SiopState>,
    pub signed_request: Option<SignedSiopRequest>,
}

impl<'a> SiopAuthorizationRequest<'a> {
    pub fn from_authorize(request: crate::requests::AuthorizeLoginRequest<'a>) -> Self {
        Self {
            request: request.request,
            authorization: SiopAuthorizationParameters {
                response_type: request.response_type,
                client_id: request.client_id,
                redirect_uri: request.redirect_uri,
                state: request.state,
                authorization_code: request.authorization_code,
                metadata_policy: request.metadata_policy,
                scope: request.scope,
                code_challenge: request.code_challenge,
                code_challenge_method: request.code_challenge_method,
            },
            response: SiopAuthorizationResponse::default(),
        }
    }

    pub fn to_response(&self) -> Result<String, OAuthError> {
        let _state = self
            .response
            .state
            .as_ref()
            .ok_or_else(|| OAuthError::invalid_token_response("siop state is required"))?;
        let signed_request =
            self.response.signed_request.as_ref().ok_or_else(|| {
                OAuthError::invalid_token_response("signed siop request is required")
            })?;
        let redirect_uri = self.authorization.redirect_uri.as_deref().ok_or_else(|| {
            OAuthError::invalid_token_response("authorize redirect_uri is required")
        })?;
        let client_id =
            self.authorization.client_id.as_deref().ok_or_else(|| {
                OAuthError::invalid_token_response("authorize client_id is required")
            })?;

        let authorization_uri = authorization_request_uri(
            redirect_uri,
            &[
                ("client_id", &signed_request.client_id),
                ("response_type", siopv2_request::RESPONSE_TYPE),
                ("response_mode", "direct_post"),
                ("scope", "openid"),
                ("request", &signed_request.value),
            ],
        );

        wallet_authorization_response(client_id, &authorization_uri)
    }
}

impl siopv2_state::Generate for SiopAuthorizationRequest<'_> {
    fn authorization_parameters(&self) -> SiopAuthorizationParameters {
        self.authorization.clone()
    }

    fn add_siop_state(&mut self, state: SiopState) {
        self.response.state = Some(state);
    }
}

impl siopv2_request::Generate for SiopAuthorizationRequest<'_> {
    fn siop_state(&self) -> Option<&SiopState> {
        self.response.state.as_ref()
    }

    fn add_signed_siop_request(&mut self, request: SignedSiopRequest) {
        self.response.signed_request = Some(request);
    }
}
