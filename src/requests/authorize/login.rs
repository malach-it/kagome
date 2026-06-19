use crate::{
    errors::OAuthError,
    handlers::responses::{
        access_token_redirect_response, authorize_redirect_response,
        code_access_token_redirect_response, code_id_token_access_token_redirect_response,
        code_id_token_redirect_response, code_redirect_response, code_ssh_keys_redirect_response,
        id_token_access_token_redirect_response, id_token_redirect_response, login_page_response,
        ssh_keys_redirect_response,
    },
    resources::{
        access_token::{self, AccessToken},
        authorization_code::{self, AuthorizationCode},
        client_credentials,
        id_token::{self, IdToken},
        metadata_policy, resource_owner,
        response_type::{self, ResponseType},
        ssh_keys::{self, SshKeys},
    },
    unit::{KagomeRequest, parse_query_parameter},
};

use super::{client_id_username, response_type_query, valid_authorize_client_id};

type MetadataPolicy = metadata_policy::MetadataPolicy;

#[derive(Debug)]
pub struct AuthorizeLoginRequest<'a> {
    pub response: AuthorizeLoginResponse,
    pub request: &'a KagomeRequest,
    pub response_type: Option<String>,
    pub client_id: Option<String>,
    pub redirect_uri: Option<String>,
    pub authorization_code: Option<String>,
    pub metadata_policy: Option<String>,
    pub username: Option<String>,
    pub password: Option<String>,
}

#[derive(Debug)]
pub struct AuthorizeLoginResponse {
    pub access_token: Option<AccessToken>,
    pub authorization_code: Option<AuthorizationCode>,
    pub id_token: Option<IdToken>,
    pub ssh_keys: Option<SshKeys>,
    pub client_id: Option<String>,
    pub client_secret: Option<String>,
    pub redirect_uri: Option<String>,
    pub previous_authorization_code: Option<String>,
    pub username: Option<String>,
    pub metadata_policy: Option<MetadataPolicy>,
    pub response_types: Vec<ResponseType>,
    pub next_response_types: Vec<ResponseType>,
}

impl<'a> AuthorizeLoginRequest<'a> {
    pub fn from_request(request: &'a KagomeRequest) -> Self {
        Self {
            response: AuthorizeLoginResponse::empty(),
            request,
            response_type: parse_query_parameter(request, "response_type"),
            client_id: parse_query_parameter(request, "client_id"),
            redirect_uri: parse_query_parameter(request, "redirect_uri"),
            authorization_code: parse_query_parameter(request, "code"),
            metadata_policy: parse_query_parameter(request, "metadata_policy"),
            username: None,
            password: None,
        }
    }

    pub fn has_resource_owner(&self) -> bool {
        self.response.username.is_some()
    }

    pub fn to_response(&self) -> Result<String, OAuthError> {
        if let (Some(authorization_code), Some(id_token), Some(access_token)) = (
            self.response.authorization_code.as_ref(),
            self.response.id_token.as_ref(),
            self.response.access_token.as_ref(),
        ) {
            let redirect_uri = self.response.redirect_uri.as_ref().ok_or_else(|| {
                OAuthError::invalid_token_response("authorize response requires redirect_uri")
            })?;

            return Ok(code_id_token_access_token_redirect_response(
                redirect_uri,
                authorization_code,
                id_token,
                access_token,
            ));
        }

        if let (Some(authorization_code), Some(id_token)) = (
            self.response.authorization_code.as_ref(),
            self.response.id_token.as_ref(),
        ) {
            let redirect_uri = self.response.redirect_uri.as_ref().ok_or_else(|| {
                OAuthError::invalid_token_response("authorize response requires redirect_uri")
            })?;

            return Ok(code_id_token_redirect_response(
                redirect_uri,
                authorization_code,
                id_token,
            ));
        }

        if let (Some(authorization_code), Some(access_token)) = (
            self.response.authorization_code.as_ref(),
            self.response.access_token.as_ref(),
        ) {
            let redirect_uri = self.response.redirect_uri.as_ref().ok_or_else(|| {
                OAuthError::invalid_token_response("authorize response requires redirect_uri")
            })?;

            return Ok(code_access_token_redirect_response(
                redirect_uri,
                authorization_code,
                access_token,
            ));
        }

        if let (Some(authorization_code), Some(ssh_keys)) = (
            self.response.authorization_code.as_ref(),
            self.response.ssh_keys.as_ref(),
        ) {
            let redirect_uri = self.response.redirect_uri.as_ref().ok_or_else(|| {
                OAuthError::invalid_token_response("authorize response requires redirect_uri")
            })?;

            return Ok(code_ssh_keys_redirect_response(
                redirect_uri,
                authorization_code,
                ssh_keys,
            ));
        }

        if let (Some(id_token), Some(access_token)) = (
            self.response.id_token.as_ref(),
            self.response.access_token.as_ref(),
        ) {
            let redirect_uri = self.response.redirect_uri.as_ref().ok_or_else(|| {
                OAuthError::invalid_token_response("authorize response requires redirect_uri")
            })?;

            return Ok(id_token_access_token_redirect_response(
                redirect_uri,
                id_token,
                access_token,
            ));
        }

        if let Some(access_token) = self.response.access_token.as_ref() {
            let redirect_uri = self.response.redirect_uri.as_ref().ok_or_else(|| {
                OAuthError::invalid_token_response("authorize response requires redirect_uri")
            })?;

            return Ok(access_token_redirect_response(redirect_uri, access_token));
        }

        if let Some(id_token) = self.response.id_token.as_ref() {
            let redirect_uri = self.response.redirect_uri.as_ref().ok_or_else(|| {
                OAuthError::invalid_token_response("authorize response requires redirect_uri")
            })?;

            return Ok(id_token_redirect_response(redirect_uri, id_token));
        }

        if let Some(ssh_keys) = self.response.ssh_keys.as_ref() {
            let redirect_uri = self.response.redirect_uri.as_ref().ok_or_else(|| {
                OAuthError::invalid_token_response("authorize response requires redirect_uri")
            })?;

            return Ok(ssh_keys_redirect_response(redirect_uri, ssh_keys));
        }

        let Some(authorization_code) = self.response.authorization_code.as_ref() else {
            return Ok(login_page_response(self));
        };

        if let Some(response_type) = response_type_query(&self.response.next_response_types) {
            return Ok(authorize_redirect_response(
                &self.request.query_params,
                &response_type,
                authorization_code,
            ));
        }

        let redirect_uri = self.response.redirect_uri.as_ref().ok_or_else(|| {
            OAuthError::invalid_token_response("authorize response requires redirect_uri")
        })?;

        Ok(code_redirect_response(redirect_uri, authorization_code))
    }

    fn validated_authorization_code_client_id(&self) -> Option<&str> {
        self.response.client_id.as_deref()
    }
}

impl AuthorizeLoginResponse {
    fn empty() -> Self {
        Self {
            access_token: None,
            authorization_code: None,
            id_token: None,
            ssh_keys: None,
            client_id: None,
            client_secret: None,
            redirect_uri: None,
            previous_authorization_code: None,
            username: None,
            metadata_policy: None,
            response_types: Vec::new(),
            next_response_types: Vec::new(),
        }
    }
}

impl<'a> response_type::Validate for AuthorizeLoginRequest<'a> {
    fn request_response_type(&self) -> Option<&str> {
        self.response_type.as_deref()
    }

    fn add_response_types(&mut self, response_types: Vec<ResponseType>) {
        self.response.response_types = response_types;
    }

    fn add_next_response_types(&mut self, response_types: Vec<ResponseType>) {
        self.response.next_response_types = response_types;
    }
}

impl<'a> client_credentials::Validate for AuthorizeLoginRequest<'a> {
    fn request_client_id(&self) -> Option<&str> {
        self.client_id.as_deref()
    }

    fn valid_client_id(&self, client_id: &str) -> bool {
        client_id == client_credentials::CLIENT_ID
            || client_id == client_credentials::USERNAME_LOCALHOST_CLIENT_ID
            || valid_authorize_client_id(client_id, self.request)
    }

    fn require_client_secret(&self) -> bool {
        false
    }

    fn request_redirect_uri(&self) -> Option<&str> {
        self.redirect_uri.as_deref()
    }

    fn require_redirect_uri(&self) -> bool {
        true
    }

    fn add_client_credentials(
        &mut self,
        client_credentials: client_credentials::ClientCredentials,
    ) {
        self.response.client_id = Some(client_credentials.client_id);
        self.response.client_secret = client_credentials.client_secret;
        self.response.redirect_uri = client_credentials.redirect_uri;
    }

    fn add_resource_owner_credentials(&mut self, username: &str, password: &str) {
        self.username = Some(username.to_owned());
        self.password = Some(password.to_owned());
    }
}

impl<'a> metadata_policy::Validate for AuthorizeLoginRequest<'a> {
    fn request_metadata_policy(&self) -> Option<&str> {
        self.metadata_policy.as_deref()
    }

    fn request_authorization_code(&self) -> Option<&str> {
        self.authorization_code.as_deref()
    }

    fn client_id(&self) -> Option<&str> {
        self.validated_authorization_code_client_id()
    }

    fn add_metadata_policy(&mut self, metadata_policy: metadata_policy::MetadataPolicy) {
        self.response.metadata_policy = Some(metadata_policy);
    }
}

impl<'a> resource_owner::Validate for AuthorizeLoginRequest<'a> {
    fn request_username(&self) -> Option<&str> {
        self.username.as_deref()
    }

    fn request_password(&self) -> Option<&str> {
        self.password.as_deref()
    }

    fn client_id_username(&self) -> Option<&str> {
        client_id_username(self.response.client_id.as_deref())
    }

    fn add_resource_owner(&mut self, resource_owner: resource_owner::ResourceOwner) {
        self.response.username = Some(resource_owner.username);
    }
}

impl<'a> authorization_code::Validate for AuthorizeLoginRequest<'a> {
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

impl<'a> authorization_code::Generate for AuthorizeLoginRequest<'a> {
    fn previous_authorization_code(&self) -> Option<&str> {
        self.response.previous_authorization_code.as_deref()
    }

    fn client_id(&self) -> Option<&str> {
        self.response.client_id.as_deref()
    }

    fn id_token(&self) -> Option<&str> {
        None
    }

    fn username(&self) -> Option<&str> {
        self.response.username.as_deref()
    }

    fn add_authorization_code(&mut self, authorization_code: AuthorizationCode) {
        self.response.authorization_code = Some(authorization_code);
    }

    fn require_id_token(&self) -> bool {
        false
    }

    fn require_username(&self) -> bool {
        true
    }
}

impl<'a> access_token::Generate for AuthorizeLoginRequest<'a> {
    fn client_id(&self) -> Option<&str> {
        self.response.client_id.as_deref()
    }

    fn add_access_token(&mut self, access_token: AccessToken) {
        self.response.access_token = Some(access_token);
    }
}

impl<'a> id_token::Generate for AuthorizeLoginRequest<'a> {
    fn client_id(&self) -> Option<&str> {
        self.response.client_id.as_deref()
    }

    fn username(&self) -> Option<&str> {
        self.response.username.as_deref()
    }

    fn add_generated_id_token(&mut self, id_token: IdToken) {
        self.response.id_token = Some(id_token);
    }
}

impl<'a> ssh_keys::Generate for AuthorizeLoginRequest<'a> {
    fn client_id(&self) -> Option<&str> {
        self.response.client_id.as_deref()
    }

    fn username(&self) -> Option<&str> {
        self.response.username.as_deref()
    }

    fn add_ssh_keys(&mut self, ssh_keys: SshKeys) {
        self.response.ssh_keys = Some(ssh_keys);
    }
}
