use crate::{
    errors::OAuthError,
    handlers::responses::access_token_response,
    resources::{
        access_token::{self, AccessToken},
        client_credentials,
        grant_type::{self, GrantType},
        resource_owner,
    },
    unit::{KagomeRequest, parse_request_parameter},
};

use super::GrantTypeRequest;

#[derive(Debug)]
pub struct ResourceOwnerPasswordCredentialsRequest {
    pub response: ResourceOwnerPasswordCredentialsResponse,
    pub client_id: Option<String>,
    pub client_secret: Option<String>,
    pub grant_type: Option<String>,
    pub username: Option<String>,
    pub password: Option<String>,
}

#[derive(Debug)]
pub struct ResourceOwnerPasswordCredentialsResponse {
    pub access_token: Option<AccessToken>,
    pub client_id: Option<String>,
    pub client_secret: Option<String>,
    pub grant_type: Option<GrantType>,
    pub username: Option<String>,
}

impl ResourceOwnerPasswordCredentialsRequest {
    pub fn from_grant_type_response(
        response: &GrantTypeRequest<'_>,
        request: &KagomeRequest,
    ) -> Self {
        Self {
            response: ResourceOwnerPasswordCredentialsResponse::empty(),
            client_id: parse_request_parameter(request, "client_id"),
            client_secret: parse_request_parameter(request, "client_secret"),
            grant_type: response
                .response
                .grant_type
                .map(|grant_type| grant_type.as_str().to_owned()),
            username: parse_request_parameter(request, "username"),
            password: parse_request_parameter(request, "password"),
        }
    }

    pub fn to_response(&self) -> Result<String, OAuthError> {
        let access_token = self.response.access_token.as_ref().ok_or_else(|| {
            OAuthError::invalid_token_response("token response requires access_token")
        })?;

        Ok(access_token_response(access_token))
    }
}

impl ResourceOwnerPasswordCredentialsResponse {
    fn empty() -> Self {
        Self {
            access_token: None,
            client_id: None,
            client_secret: None,
            grant_type: None,
            username: None,
        }
    }
}

impl access_token::Generate for ResourceOwnerPasswordCredentialsRequest {
    fn client_id(&self) -> Option<&str> {
        self.response.client_id.as_deref()
    }

    fn add_access_token(&mut self, access_token: AccessToken) {
        self.response.access_token = Some(access_token);
    }

    fn username(&self) -> Option<&str> {
        self.response.username.as_deref()
    }
}

impl client_credentials::Validate for ResourceOwnerPasswordCredentialsRequest {
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

impl grant_type::Validate for ResourceOwnerPasswordCredentialsRequest {
    fn request_grant_type(&self) -> Option<&str> {
        self.grant_type.as_deref()
    }

    fn add_grant_type(&mut self, grant_type: &GrantType) {
        self.response.grant_type = Some(*grant_type);
    }
}

impl resource_owner::Validate for ResourceOwnerPasswordCredentialsRequest {
    fn client_id(&self) -> Option<&str> {
        self.response.client_id.as_deref()
    }

    fn request_username(&self) -> Option<&str> {
        self.username.as_deref()
    }

    fn request_password(&self) -> Option<&str> {
        self.password.as_deref()
    }

    fn add_resource_owner(&mut self, resource_owner: resource_owner::ResourceOwner) {
        self.response.username = Some(resource_owner.username);
    }
}
