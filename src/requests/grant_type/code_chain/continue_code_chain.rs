use crate::{
    errors::OAuthError,
    handlers::responses::authorization_code_response,
    resources::{
        authorization_code::{self, AuthorizationCode},
        grant_type::GrantType,
        id_token,
    },
    unit::{KagomeRequest, parse_request_parameter},
};

use super::CodeChainRequest;

#[derive(Debug)]
pub struct ContinueCodeChainRequest<'a> {
    pub response: ContinueCodeChainResponse,
    pub request: &'a KagomeRequest,
    id_token: Option<String>,
}

#[derive(Debug)]
pub struct ContinueCodeChainResponse {
    pub authorization_code: Option<AuthorizationCode>,
    pub previous_authorization_code: Option<String>,
    pub client_id: Option<String>,
    pub client_secret: Option<String>,
    pub grant_type: Option<GrantType>,
    pub id_token: Option<String>,
}

impl<'a> ContinueCodeChainRequest<'a> {
    pub fn from_code_chain_request(request: CodeChainRequest<'a>) -> Self {
        Self {
            response: ContinueCodeChainResponse {
                authorization_code: None,
                previous_authorization_code: request.response.previous_authorization_code,
                client_id: request.response.client_id,
                client_secret: request.response.client_secret,
                grant_type: request.response.grant_type,
                id_token: None,
            },
            request: request.request,
            id_token: parse_request_parameter(request.request, "id_token"),
        }
    }

    pub fn to_response(&self) -> Result<String, OAuthError> {
        let authorization_code = self.response.authorization_code.as_ref().ok_or_else(|| {
            OAuthError::invalid_token_response("token response requires authorization_code")
        })?;

        Ok(authorization_code_response(authorization_code))
    }
}

impl<'a> authorization_code::Generate for ContinueCodeChainRequest<'a> {
    fn previous_authorization_code(&self) -> Option<&str> {
        self.response.previous_authorization_code.as_deref()
    }

    fn client_id(&self) -> Option<&str> {
        self.response.client_id.as_deref()
    }

    fn id_token(&self) -> Option<&str> {
        self.response.id_token.as_deref()
    }

    fn add_authorization_code(&mut self, authorization_code: AuthorizationCode) {
        self.response.authorization_code = Some(authorization_code);
    }
}

impl<'a> id_token::Validate for ContinueCodeChainRequest<'a> {
    fn request_id_token(&self) -> Option<&str> {
        self.id_token.as_deref()
    }

    fn add_id_token(&mut self, id_token: &str) {
        self.response.id_token = Some(id_token.to_owned());
    }
}
