use crate::{
    errors::OAuthError,
    resources::{
        access_token::{self, AccessToken},
        client_credentials,
        grant_type::{self, GrantType},
    },
    unit::{KagomeRequest, parse_request_parameter},
};

use super::grant_type::GrantTypeRequest;
use crate::handlers::responses::access_token_response;

#[derive(Debug)]
pub struct ClientCredentialsRequest<'a> {
    pub response: ClientCredentialsResponse,
    pub request: &'a KagomeRequest,
    pub client_id: Option<String>,
    pub client_secret: Option<String>,
    pub grant_type: Option<String>,
}

#[derive(Debug)]
pub struct ClientCredentialsResponse {
    pub access_token: Option<AccessToken>,
    pub client_id: Option<String>,
    pub client_secret: Option<String>,
    pub grant_type: Option<GrantType>,
}

impl<'a> ClientCredentialsRequest<'a> {
    pub fn empty(request: &'a KagomeRequest) -> Self {
        Self {
            response: ClientCredentialsResponse::empty(),
            request,
            client_id: parse_request_parameter(request, "client_id"),
            client_secret: parse_request_parameter(request, "client_secret"),
            grant_type: parse_request_parameter(request, "grant_type"),
        }
    }

    pub fn from_grant_type_response(
        response: GrantTypeRequest<'a>,
        request: &'a KagomeRequest,
    ) -> Self {
        Self {
            response: ClientCredentialsResponse {
                ..ClientCredentialsResponse::empty()
            },
            request,
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

impl ClientCredentialsResponse {
    fn empty() -> Self {
        Self {
            access_token: None,
            client_id: None,
            client_secret: None,
            grant_type: None,
        }
    }
}

impl<'a> access_token::Generate for ClientCredentialsRequest<'a> {
    fn client_id(&self) -> Option<&str> {
        self.response.client_id.as_deref()
    }

    fn add_access_token(&mut self, access_token: AccessToken) {
        self.response.access_token = Some(access_token);
    }
}

impl<'a> client_credentials::Validate for ClientCredentialsRequest<'a> {
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

impl<'a> grant_type::Validate for ClientCredentialsRequest<'a> {
    fn request_grant_type(&self) -> Option<&str> {
        self.grant_type.as_deref()
    }

    fn add_grant_type(&mut self, grant_type: &GrantType) {
        self.response.grant_type = Some(*grant_type);
    }
}
