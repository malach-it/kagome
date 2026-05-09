use crate::{
    errors::OAuthError,
    resources::{
        authorization_code::{self, AuthorizationCode},
        client_credentials,
        grant_type::{self, GrantType},
        id_token,
    },
    unit::{KagomeRequest, parse_request_parameter},
};

use super::grant_type::GrantTypeRequest;
use crate::handlers::responses::authorization_code_response;

#[derive(Debug)]
pub struct CodeChainRequest<'a> {
    pub response: CodeChainResponse,
    pub request: &'a KagomeRequest,
    pub authorization_code: Option<String>,
    pub client_id: Option<String>,
    pub client_secret: Option<String>,
    pub grant_type: Option<String>,
    pub id_token: Option<String>,
}

#[derive(Debug)]
pub struct CodeChainResponse {
    pub authorization_code: Option<AuthorizationCode>,
    pub previous_authorization_code: Option<String>,
    pub client_id: Option<String>,
    pub client_secret: Option<String>,
    pub grant_type: Option<GrantType>,
    pub id_token: Option<String>,
}

impl<'a> CodeChainRequest<'a> {
    pub fn empty(request: &'a KagomeRequest) -> Self {
        Self {
            response: CodeChainResponse::empty(),
            request,
            authorization_code: parse_request_parameter(request, "authorization_code"),
            client_id: parse_request_parameter(request, "client_id"),
            client_secret: parse_request_parameter(request, "client_secret"),
            grant_type: parse_request_parameter(request, "grant_type"),
            id_token: parse_request_parameter(request, "id_token"),
        }
    }

    pub fn from_grant_type_response(
        response: GrantTypeRequest<'a>,
        request: &'a KagomeRequest,
    ) -> Self {
        Self {
            response: CodeChainResponse {
                ..CodeChainResponse::empty()
            },
            request,
            authorization_code: parse_request_parameter(request, "authorization_code"),
            client_id: parse_request_parameter(request, "client_id"),
            client_secret: parse_request_parameter(request, "client_secret"),
            grant_type: response
                .response
                .grant_type
                .map(|grant_type| grant_type.as_str().to_owned()),
            id_token: parse_request_parameter(request, "id_token"),
        }
    }

    pub fn to_response(&self) -> Result<String, OAuthError> {
        let authorization_code = self.response.authorization_code.as_ref().ok_or_else(|| {
            OAuthError::invalid_token_response("token response requires authorization_code")
        })?;

        Ok(authorization_code_response(authorization_code))
    }

    pub fn previous_authorization_code(&self) -> Option<&str> {
        self.response.previous_authorization_code.as_deref()
    }
}

impl CodeChainResponse {
    fn empty() -> Self {
        Self {
            authorization_code: None,
            previous_authorization_code: None,
            client_id: None,
            client_secret: None,
            grant_type: None,
            id_token: None,
        }
    }
}

impl<'a> authorization_code::Generate for CodeChainRequest<'a> {
    fn authorization_code(&self) -> Option<&str> {
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

impl<'a> grant_type::Validate for CodeChainRequest<'a> {
    fn request_grant_type(&self) -> Option<&str> {
        self.grant_type.as_deref()
    }

    fn add_grant_type(&mut self, grant_type: &GrantType) {
        self.response.grant_type = Some(*grant_type);
    }
}

impl<'a> id_token::Validate for CodeChainRequest<'a> {
    fn request_id_token(&self) -> Option<&str> {
        self.id_token.as_deref()
    }

    fn add_id_token(&mut self, id_token: &str) {
        self.response.id_token = Some(id_token.to_owned());
    }
}

impl<'a> authorization_code::Validate for CodeChainRequest<'a> {
    fn request_authorization_code(&self) -> Option<&str> {
        self.authorization_code.as_deref()
    }

    fn client_id(&self) -> Option<&str> {
        self.client_id.as_deref()
    }

    fn add_authorization_code(&mut self, authorization_code: &str) {
        self.response.previous_authorization_code = Some(authorization_code.to_owned());
    }
}
