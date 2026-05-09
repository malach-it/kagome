use crate::{
    errors::OAuthError,
    resources::{authorization_code, client_credentials, grant_type::GrantType},
    unit::{KagomeRequest, parse_request_parameter},
};

use super::grant_type::GrantTypeRequest;

mod continue_code_chain;
mod new_code_chain;

pub use continue_code_chain::{ContinueCodeChainRequest, ContinueCodeChainResponse};
pub use new_code_chain::{NewCodeChainRequest, NewCodeChainResponse};

#[derive(Debug)]
pub struct CodeChainRequest<'a> {
    pub response: CodeChainResponse,
    pub request: &'a KagomeRequest,
    pub authorization_code: Option<String>,
    pub client_id: Option<String>,
    pub client_secret: Option<String>,
}

#[derive(Debug)]
pub struct CodeChainResponse {
    pub previous_authorization_code: Option<String>,
    pub client_id: Option<String>,
    pub client_secret: Option<String>,
    pub grant_type: Option<GrantType>,
}

impl<'a> CodeChainRequest<'a> {
    pub fn empty(request: &'a KagomeRequest) -> Self {
        Self {
            response: CodeChainResponse::empty(),
            request,
            authorization_code: parse_request_parameter(request, "authorization_code"),
            client_id: parse_request_parameter(request, "client_id"),
            client_secret: parse_request_parameter(request, "client_secret"),
        }
    }

    pub fn from_grant_type_response(
        response: GrantTypeRequest<'a>,
        request: &'a KagomeRequest,
    ) -> Self {
        Self {
            response: CodeChainResponse {
                grant_type: response.response.grant_type,
                ..CodeChainResponse::empty()
            },
            request,
            authorization_code: parse_request_parameter(request, "authorization_code"),
            client_id: parse_request_parameter(request, "client_id"),
            client_secret: parse_request_parameter(request, "client_secret"),
        }
    }

    pub fn authorization_code(&self) -> Option<&str> {
        self.response.previous_authorization_code.as_deref()
    }

    pub fn to_response(&self) -> Result<String, OAuthError> {
        Err(OAuthError::invalid_token_response(
            "token response requires authorization_code",
        ))
    }
}

impl CodeChainResponse {
    fn empty() -> Self {
        Self {
            previous_authorization_code: None,
            client_id: None,
            client_secret: None,
            grant_type: None,
        }
    }
}

impl<'a> client_credentials::Validate for CodeChainRequest<'a> {
    fn request_client_id(&self) -> Option<&str> {
        self.client_id.as_deref()
    }

    fn request_client_secret(&self) -> Option<&str> {
        self.client_secret.as_deref()
    }

    fn add_client_credentials(
        &mut self,
        client_credentials: client_credentials::ClientCredentials,
    ) {
        self.response.client_id = Some(client_credentials.client_id);
        self.response.client_secret = Some(client_credentials.client_secret);
    }
}

impl<'a> authorization_code::Validate for CodeChainRequest<'a> {
    fn request_authorization_code(&self) -> Option<&str> {
        self.authorization_code.as_deref()
    }

    fn client_id(&self) -> Option<&str> {
        self.response.client_id.as_deref()
    }

    fn add_authorization_code(&mut self, authorization_code: &str) {
        self.response.previous_authorization_code = Some(authorization_code.to_owned());
    }
}
