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
pub struct NewCodeChainRequest<'a> {
    pub response: NewCodeChainResponse,
    pub request: &'a KagomeRequest,
    id_token: Option<String>,
}

#[derive(Debug)]
pub struct NewCodeChainResponse {
    pub authorization_code: Option<AuthorizationCode>,
    pub client_id: Option<String>,
    pub client_secret: Option<String>,
    pub grant_type: Option<GrantType>,
    pub id_token: Option<String>,
}

impl<'a> NewCodeChainRequest<'a> {
    pub fn from_code_chain_request(request: CodeChainRequest<'a>) -> Self {
        Self {
            response: NewCodeChainResponse {
                authorization_code: None,
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

impl<'a> authorization_code::Generate for NewCodeChainRequest<'a> {
    fn previous_authorization_code(&self) -> Option<&str> {
        None
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

impl<'a> id_token::Validate for NewCodeChainRequest<'a> {
    fn request_id_token(&self) -> Option<&str> {
        self.id_token.as_deref()
    }

    fn add_id_token(&mut self, id_token: &str) {
        self.response.id_token = Some(id_token.to_owned());
    }
}
