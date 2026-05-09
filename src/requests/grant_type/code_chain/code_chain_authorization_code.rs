use crate::{
    errors::OAuthError,
    handlers::responses::access_token_response,
    resources::{
        access_token::{self, AccessToken},
        authorization_code::{self, AuthorizationCode},
        client_credentials,
        grant_type::GrantType,
    },
    unit::KagomeRequest,
};

use super::CodeChainRequest;
use crate::requests::grant_type::AuthorizationCodeRequest;

#[derive(Debug)]
pub struct CodeChainAuthorizationCodeRequest<'a> {
    pub response: CodeChainAuthorizationCodeResponse,
    pub request: &'a KagomeRequest,
    pub authorization_code: Option<String>,
    pub client_id: Option<String>,
    pub client_secret: Option<String>,
}

#[derive(Debug)]
pub struct CodeChainAuthorizationCodeResponse {
    pub access_token: Option<AccessToken>,
    pub authorization_code: Option<AuthorizationCode>,
    pub previous_authorization_code: Option<String>,
    pub client_id: Option<String>,
    pub client_secret: Option<String>,
    pub grant_type: Option<GrantType>,
}

impl<'a> CodeChainAuthorizationCodeRequest<'a> {
    pub fn from_requests(
        code_chain_request: CodeChainRequest<'a>,
        authorization_code_request: AuthorizationCodeRequest<'a>,
    ) -> Self {
        Self {
            response: CodeChainAuthorizationCodeResponse {
                access_token: authorization_code_request.response.access_token,
                authorization_code: code_chain_request.response.authorization_code,
                previous_authorization_code: code_chain_request
                    .response
                    .previous_authorization_code,
                client_id: authorization_code_request
                    .response
                    .client_id
                    .or(code_chain_request.response.client_id),
                client_secret: authorization_code_request
                    .response
                    .client_secret
                    .or(code_chain_request.response.client_secret),
                grant_type: code_chain_request
                    .response
                    .grant_type
                    .or(authorization_code_request.response.grant_type),
            },
            request: code_chain_request.request,
            authorization_code: authorization_code_request.authorization_code,
            client_id: authorization_code_request
                .client_id
                .or(code_chain_request.client_id),
            client_secret: authorization_code_request
                .client_secret
                .or(code_chain_request.client_secret),
        }
    }

    pub fn to_response(&self) -> Result<String, OAuthError> {
        let access_token = self.response.access_token.as_ref().ok_or_else(|| {
            OAuthError::invalid_token_response("token response requires access_token")
        })?;

        Ok(access_token_response(access_token))
    }
}

impl<'a> access_token::Generate for CodeChainAuthorizationCodeRequest<'a> {
    fn client_id(&self) -> Option<&str> {
        self.response.client_id.as_deref()
    }

    fn add_access_token(&mut self, access_token: AccessToken) {
        self.response.access_token = Some(access_token);
    }
}

impl<'a> client_credentials::Validate for CodeChainAuthorizationCodeRequest<'a> {
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

impl<'a> authorization_code::Validate for CodeChainAuthorizationCodeRequest<'a> {
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
