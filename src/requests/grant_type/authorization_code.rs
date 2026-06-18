use crate::{
    errors::OAuthError,
    resources::{
        access_token::{self, AccessToken},
        authorization_code, client_credentials,
        grant_type::{self, GrantType},
    },
    unit::{KagomeRequest, parse_request_parameter},
};

use super::GrantTypeRequest;
use crate::handlers::responses::access_token_response;

#[derive(Debug)]
pub struct AuthorizationCodeRequest<'a> {
    pub response: AuthorizationCodeResponse,
    pub request: &'a KagomeRequest,
    pub authorization_code: Option<String>,
    pub client_id: Option<String>,
    pub client_secret: Option<String>,
    pub grant_type: Option<String>,
}

#[derive(Debug)]
pub struct AuthorizationCodeResponse {
    pub access_token: Option<AccessToken>,
    pub authorization_code: Option<String>,
    pub client_id: Option<String>,
    pub client_secret: Option<String>,
    pub grant_type: Option<GrantType>,
}

impl<'a> AuthorizationCodeRequest<'a> {
    pub fn empty(request: &'a KagomeRequest) -> Self {
        Self {
            response: AuthorizationCodeResponse::empty(),
            request,
            authorization_code: parse_request_parameter(request, "authorization_code"),
            client_id: parse_request_parameter(request, "client_id"),
            client_secret: parse_request_parameter(request, "client_secret"),
            grant_type: parse_request_parameter(request, "grant_type"),
        }
    }

    pub fn from_grant_type_response(
        response: &GrantTypeRequest<'a>,
        request: &'a KagomeRequest,
    ) -> Self {
        Self {
            response: AuthorizationCodeResponse {
                ..AuthorizationCodeResponse::empty()
            },
            request,
            authorization_code: parse_request_parameter(request, "authorization_code"),
            client_id: parse_request_parameter(request, "client_id"),
            client_secret: parse_request_parameter(request, "client_secret"),
            grant_type: response
                .response
                .grant_type
                .map(|grant_type| grant_type.as_str().to_owned()),
        }
    }

    pub fn to_response(&self) -> Result<String, OAuthError> {
        let access_token = self.response.access_token.as_ref().ok_or_else(|| {
            OAuthError::invalid_token_response("token response requires access_token")
        })?;

        Ok(access_token_response(access_token))
    }
}

impl AuthorizationCodeResponse {
    fn empty() -> Self {
        Self {
            access_token: None,
            authorization_code: None,
            client_id: None,
            client_secret: None,
            grant_type: None,
        }
    }
}

impl<'a> grant_type::Validate for AuthorizationCodeRequest<'a> {
    fn request_grant_type(&self) -> Option<&str> {
        self.grant_type.as_deref()
    }

    fn add_grant_type(&mut self, grant_type: &GrantType) {
        self.response.grant_type = Some(*grant_type);
    }
}

impl<'a> access_token::Generate for AuthorizationCodeRequest<'a> {
    fn client_id(&self) -> Option<&str> {
        self.response.client_id.as_deref()
    }

    fn add_access_token(&mut self, access_token: AccessToken) {
        self.response.access_token = Some(access_token);
    }
}

impl<'a> client_credentials::Validate for AuthorizationCodeRequest<'a> {
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

impl<'a> authorization_code::Validate for AuthorizationCodeRequest<'a> {
    fn request_authorization_code(&self) -> Option<&str> {
        self.authorization_code.as_deref()
    }

    fn client_id(&self) -> Option<&str> {
        self.response.client_id.as_deref()
    }

    fn add_authorization_code(&mut self, authorization_code: &str) {
        self.response.authorization_code = Some(authorization_code.to_owned());
    }
}
