use crate::{
    errors::OAuthError,
    handlers::responses::{
        access_token_redirect_response, authorize_redirect_response,
        code_access_token_redirect_response, code_id_token_access_token_redirect_response,
        code_id_token_redirect_response, code_redirect_response,
        federated_authorize_redirect_response, id_token_access_token_redirect_response,
        id_token_redirect_response, login_page_response,
    },
    requests::FederationCallbackRequest,
    resources::{
        access_token::{self, AccessToken},
        authorization_code::{self, AuthorizationCode},
        client_credentials, federated_server,
        id_token::{self, IdToken},
        metadata_policy, resource_owner,
        response_type::{self, ResponseType},
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
    pub state: Option<String>,
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
    pub client_id: Option<String>,
    pub client_secret: Option<String>,
    pub redirect_uri: Option<String>,
    pub previous_authorization_code: Option<String>,
    pub username: Option<String>,
    pub metadata_policy: Option<MetadataPolicy>,
    pub response_types: Vec<ResponseType>,
    pub next_response_types: Vec<ResponseType>,
    pub federated_authorization: Option<federated_server::FederatedAuthorization>,
    pub federation_authorization_code: Option<String>,
    pub federated_access_token: Option<String>,
}

impl<'a> AuthorizeLoginRequest<'a> {
    pub fn from_request(request: &'a KagomeRequest) -> Self {
        Self {
            response: AuthorizeLoginResponse::empty(),
            request,
            response_type: parse_query_parameter(request, "response_type"),
            client_id: parse_query_parameter(request, "client_id"),
            redirect_uri: parse_query_parameter(request, "redirect_uri"),
            state: parse_query_parameter(request, "state"),
            authorization_code: parse_query_parameter(request, "code"),
            metadata_policy: parse_query_parameter(request, "metadata_policy"),
            username: None,
            password: None,
        }
    }

    pub fn from_state(
        callback: FederationCallbackRequest,
        request: &'a KagomeRequest,
    ) -> Result<Self, OAuthError> {
        let encoded_state = callback.state.as_deref().ok_or_else(|| {
            OAuthError::invalid_request("federation callback state is invalid or expired")
        })?;
        let state = federated_server::decrypt_state(encoded_state)?;
        let parameters = state.request_parameters;

        if parameters.client_id.as_deref() != Some(state.client_id.as_str()) {
            return Err(OAuthError::invalid_request(
                "federation callback state is invalid or expired",
            ));
        }

        let mut response = AuthorizeLoginResponse::empty();
        response.federation_authorization_code = callback.response.authorization_code;

        Ok(Self {
            response,
            request,
            response_type: parameters.response_type,
            client_id: parameters.client_id,
            redirect_uri: parameters.redirect_uri,
            state: parameters.state,
            authorization_code: parameters.authorization_code,
            metadata_policy: parameters.metadata_policy,
            username: parameters.username,
            password: parameters.password,
        })
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

            return Ok(access_token_redirect_response(
                redirect_uri,
                access_token,
                self.state.as_deref(),
            ));
        }

        if let Some(id_token) = self.response.id_token.as_ref() {
            let redirect_uri = self.response.redirect_uri.as_ref().ok_or_else(|| {
                OAuthError::invalid_token_response("authorize response requires redirect_uri")
            })?;

            return Ok(id_token_redirect_response(redirect_uri, id_token));
        }

        let Some(authorization_code) = self.response.authorization_code.as_ref() else {
            if let Some(authorization) = self.response.federated_authorization.as_ref() {
                return Ok(federated_authorize_redirect_response(
                    &authorization.authorize_endpoint,
                    &authorization.client_id,
                    &authorization.redirect_uri,
                    &authorization.state,
                ));
            }

            return Ok(login_page_response(self));
        };

        if let Some(response_type) = response_type_query(&self.response.next_response_types) {
            let restored_query_parameters = self.restored_query_parameters();
            let query_parameters = if self.response.federated_access_token.is_some() {
                &restored_query_parameters
            } else {
                &self.request.query_params
            };

            return Ok(authorize_redirect_response(
                query_parameters,
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

    fn restored_query_parameters(&self) -> Vec<(String, String)> {
        [
            ("response_type", self.response_type.as_ref()),
            ("client_id", self.client_id.as_ref()),
            ("redirect_uri", self.redirect_uri.as_ref()),
            ("state", self.state.as_ref()),
            ("code", self.authorization_code.as_ref()),
            ("metadata_policy", self.metadata_policy.as_ref()),
        ]
        .into_iter()
        .filter_map(|(name, value)| value.map(|value| (name.to_owned(), value.clone())))
        .collect()
    }
}

impl AuthorizeLoginResponse {
    fn empty() -> Self {
        Self {
            access_token: None,
            authorization_code: None,
            id_token: None,
            client_id: None,
            client_secret: None,
            redirect_uri: None,
            previous_authorization_code: None,
            username: None,
            metadata_policy: None,
            response_types: Vec::new(),
            next_response_types: Vec::new(),
            federated_authorization: None,
            federation_authorization_code: None,
            federated_access_token: None,
        }
    }
}

impl federated_server::Authorize for AuthorizeLoginRequest<'_> {
    fn validated_client_id(&self) -> Option<&str> {
        self.response.client_id.as_deref()
    }

    fn request_parameters(&self) -> federated_server::FederationRequestParameters {
        federated_server::FederationRequestParameters {
            response_type: self.response_type.clone(),
            client_id: self.client_id.clone(),
            redirect_uri: self.redirect_uri.clone(),
            state: self.state.clone(),
            authorization_code: self.authorization_code.clone(),
            metadata_policy: self.metadata_policy.clone(),
            username: self.username.clone(),
            password: self.password.clone(),
        }
    }

    fn add_federated_authorization(
        &mut self,
        authorization: federated_server::FederatedAuthorization,
    ) {
        self.response.federated_authorization = Some(authorization);
    }
}

impl federated_server::ExchangeToken for AuthorizeLoginRequest<'_> {
    fn federation_authorization_code(&self) -> Option<&str> {
        self.response.federation_authorization_code.as_deref()
    }

    fn federation_client_id(&self) -> Option<&str> {
        self.response.client_id.as_deref()
    }

    fn add_federated_access_token(&mut self, access_token: String) {
        self.response.federated_access_token = Some(access_token);
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

    fn valid_unregistered_client_id(&self, client_id: &str) -> bool {
        valid_authorize_client_id(client_id, self.request)
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
        self.response.federated_access_token.is_none()
    }
}

impl<'a> access_token::Generate for AuthorizeLoginRequest<'a> {
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
