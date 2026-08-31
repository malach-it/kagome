use crate::{
    errors::OAuthError,
    handlers::responses::authorization_code_response,
    resources::{authorization_code, client_credentials, grant_type::GrantType},
    unit::{KagomeRequest, parse_request_parameter},
};

use super::GrantTypeRequest;

mod code_chain_authorization_code;

use crate::resources::{authorization_code::AuthorizationCode, id_token};
pub use code_chain_authorization_code::{
    CodeChainAuthorizationCodeRequest, CodeChainAuthorizationCodeResponse,
};

#[derive(Debug)]
pub struct CodeChainRequest<'a> {
    pub response: CodeChainResponse,
    pub request: &'a KagomeRequest,
    pub authorization_code: Option<String>,
    pub client_id: Option<String>,
    pub client_secret: Option<String>,
    pub code_verifier: Option<String>,
    id_token: Option<String>,
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
            code_verifier: parse_request_parameter(request, "code_verifier"),
            id_token: parse_request_parameter(request, "id_token"),
        }
    }

    pub fn from_grant_type_response(
        response: &GrantTypeRequest<'a>,
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
            code_verifier: parse_request_parameter(request, "code_verifier"),
            id_token: parse_request_parameter(request, "id_token"),
        }
    }

    pub fn authorization_code(&self) -> Option<&str> {
        self.response.previous_authorization_code.as_deref()
    }

    pub fn to_response(&self) -> Result<String, OAuthError> {
        let authorization_code = self.response.authorization_code.as_ref().ok_or_else(|| {
            OAuthError::invalid_token_response("token response requires authorization_code")
        })?;

        Ok(authorization_code_response(authorization_code))
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
        self.response.client_secret = client_credentials.client_secret;
    }
}

impl<'a> authorization_code::Validate for CodeChainRequest<'a> {
    fn request_authorization_code(&self) -> Option<&str> {
        self.authorization_code.as_deref()
    }

    fn client_id(&self) -> Option<&str> {
        self.response.client_id.as_deref()
    }

    fn code_verifier(&self) -> Option<&str> {
        self.code_verifier.as_deref()
    }

    fn add_authorization_code(&mut self, authorization_code: &str) {
        self.response.previous_authorization_code = Some(authorization_code.to_owned());
    }
}

impl<'a> authorization_code::Generate for CodeChainRequest<'a> {
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

impl<'a> id_token::Validate for CodeChainRequest<'a> {
    fn request_id_token(&self) -> Option<&str> {
        self.id_token.as_deref()
    }

    fn add_id_token(&mut self, id_token: &str) {
        self.response.id_token = Some(id_token.to_owned());
    }
}
