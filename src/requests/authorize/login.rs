use crate::{
    config::Config,
    errors::OAuthError,
    handlers::responses::{
        access_token_redirect_response, authorization_request_uri, authorize_redirect_response,
        code_access_token_redirect_response, code_id_token_access_token_redirect_response,
        code_id_token_redirect_response, code_redirect_response,
        federated_authorize_redirect_response, id_token_access_token_redirect_response,
        id_token_redirect_response, not_implemented_response,
        wallet_authorization_redirect_response, wallet_authorization_response,
    },
    requests::{FederationCallbackRequest, SiopResponseRequest},
    resources::{
        access_token::{self, AccessToken},
        authorization_code::{self, AuthorizationCode},
        client_credentials, credential_issuer, federated_server,
        id_token::{self, IdToken},
        metadata_policy, pre_authorized_code,
        presentation_request::{self, SignedPresentationRequest},
        presentation_state, resource_owner,
        response_type::{self, ResponseType},
        verifier,
    },
    unit::{KagomeRequest, parse_query_parameter, request_header},
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
    pub host: Option<String>,
}

#[derive(Debug)]
pub struct AuthorizeLoginResponse {
    pub access_token: Option<AccessToken>,
    pub authorization_code: Option<AuthorizationCode>,
    pub id_token: Option<IdToken>,
    pub pre_authorized_code: Option<String>,
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
    pub siop_authenticated: bool,
    pub verifier: Option<String>,
    pub presentation_state: Option<presentation_state::PresentationState>,
    pub signed_presentation_request: Option<SignedPresentationRequest>,
    pub credential_issuer: Option<String>,
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
            host: request_header(request, "host"),
        }
    }

    pub fn from_state(
        callback: FederationCallbackRequest,
        request: &'a KagomeRequest,
    ) -> Result<Self, OAuthError> {
        let state = callback.response.federation_state.ok_or_else(|| {
            OAuthError::invalid_request("federation callback state is invalid or expired")
        })?;
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
            host: request_header(request, "host"),
        })
    }

    pub fn from_siop(
        siop_response: SiopResponseRequest<'a>,
        request: &'a KagomeRequest,
    ) -> Result<Self, OAuthError> {
        let state = siop_response.response.state_claims.ok_or_else(|| {
            OAuthError::invalid_request("siop response state is invalid or expired")
        })?;
        let id_token = siop_response.response.id_token.ok_or_else(|| {
            OAuthError::invalid_request("siop response requires a validated id_token")
        })?;
        let response_type = state.response_type;
        let parameters = state.authorization;
        let mut response = AuthorizeLoginResponse::empty();
        response.username = Some(id_token.subject);
        response.siop_authenticated = true;

        Ok(Self {
            response,
            request,
            response_type: Some(response_type),
            client_id: parameters.client_id,
            redirect_uri: parameters.redirect_uri,
            state: parameters.state,
            authorization_code: parameters.authorization_code,
            metadata_policy: parameters.metadata_policy,
            username: None,
            password: None,
            host: request_header(request, "host"),
        })
    }

    pub fn has_resource_owner(&self) -> bool {
        self.response.username.is_some()
    }

    pub fn to_response(&self) -> Result<String, OAuthError> {
        if let Some(state) = self.response.presentation_state.as_ref() {
            let redirect_uri = self.response.redirect_uri.as_deref().ok_or_else(|| {
                OAuthError::invalid_token_response("authorize response requires redirect_uri")
            })?;
            let signed_request = self
                .response
                .signed_presentation_request
                .as_ref()
                .ok_or_else(|| {
                    OAuthError::invalid_token_response("signed presentation request is required")
                })?;

            let authorization_uri = authorization_request_uri(
                redirect_uri,
                &[
                    ("client_id", &state.claims.client_id),
                    ("response_type", "vp_token"),
                    ("redirect_uri", &signed_request.redirect_uri),
                    ("request", &signed_request.value),
                ],
            );

            return self.wallet_authorization_response(
                &state.claims.authorization_client_id,
                &authorization_uri,
            );
        }

        if let Some(pre_authorized_code) = self.response.pre_authorized_code.as_deref() {
            let redirect_uri = self.response.redirect_uri.as_deref().ok_or_else(|| {
                OAuthError::invalid_token_response("authorize response requires redirect_uri")
            })?;

            let client_id = self.response.client_id.as_deref().ok_or_else(|| {
                OAuthError::invalid_token_response("authorize response requires client_id")
            })?;
            let authorization_uri = crate::handlers::responses::credential_offer_uri(
                redirect_uri,
                &Config::global().server.issuer,
                pre_authorized_code,
            );

            return self.wallet_authorization_response(client_id, &authorization_uri);
        }

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

            return Ok(not_implemented_response());
        };

        if let Some(response_type) = response_type_query(&self.response.next_response_types) {
            let restored_query_parameters = self.restored_query_parameters();
            let query_parameters = if self.response.federated_access_token.is_some()
                || self.response.siop_authenticated
            {
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

    fn wallet_authorization_response(
        &self,
        client_id: &str,
        authorization_uri: &str,
    ) -> Result<String, OAuthError> {
        if self.response.siop_authenticated {
            return Ok(wallet_authorization_redirect_response(authorization_uri));
        }

        wallet_authorization_response(client_id, authorization_uri)
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
            pre_authorized_code: None,
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
            siop_authenticated: false,
            verifier: None,
            presentation_state: None,
            signed_presentation_request: None,
            credential_issuer: None,
        }
    }
}

impl verifier::Validate for AuthorizeLoginRequest<'_> {
    fn add_verifier(&mut self, verifier: String) {
        self.response.verifier = Some(verifier);
    }
}

impl credential_issuer::Validate for AuthorizeLoginRequest<'_> {
    fn request_host(&self) -> Option<&str> {
        self.host.as_deref()
    }

    fn add_credential_issuer(&mut self, credential_issuer: String) {
        self.response.credential_issuer = Some(credential_issuer);
    }
}

impl presentation_state::Generate for AuthorizeLoginRequest<'_> {
    fn verifier(&self) -> Option<&str> {
        self.response.verifier.as_deref()
    }

    fn credential_issuer(&self) -> Option<&str> {
        self.response.credential_issuer.as_deref()
    }

    fn authorization_client_id(&self) -> Option<&str> {
        self.response.client_id.as_deref()
    }

    fn authorization_redirect_uri(&self) -> Option<&str> {
        self.response.redirect_uri.as_deref()
    }

    fn authorization_state(&self) -> Option<&str> {
        self.state.as_deref()
    }

    fn authorization_code(&self) -> Option<&str> {
        self.response.previous_authorization_code.as_deref()
    }

    fn require_wallet_binding(&self) -> bool {
        !self.response.siop_authenticated
            && self
                .response
                .client_id
                .as_deref()
                .is_some_and(client_credentials::requires_wallet_binding)
    }

    fn add_presentation_state(&mut self, state: presentation_state::PresentationState) {
        self.response.presentation_state = Some(state);
    }
}

impl presentation_request::Generate for AuthorizeLoginRequest<'_> {
    fn verifier(&self) -> Option<&str> {
        self.response.verifier.as_deref()
    }

    fn presentation_state(&self) -> Option<&presentation_state::PresentationState> {
        self.response.presentation_state.as_ref()
    }

    fn add_signed_presentation_request(&mut self, request: SignedPresentationRequest) {
        self.response.signed_presentation_request = Some(request);
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

impl federated_server::FetchIdentity for AuthorizeLoginRequest<'_> {
    fn federated_access_token(&self) -> Option<&str> {
        self.response.federated_access_token.as_deref()
    }

    fn federation_client_id(&self) -> Option<&str> {
        self.response.client_id.as_deref()
    }

    fn add_federated_identity(
        &mut self,
        target: crate::config::FederatedIdentityTarget,
        value: String,
    ) {
        match target {
            crate::config::FederatedIdentityTarget::Username => {
                self.response.username = Some(value);
            }
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
        if let Some(username) = client_credentials.authenticated_username {
            self.response.username = Some(username);
        }
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
    fn client_id(&self) -> Option<&str> {
        self.response.client_id.as_deref()
    }

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

impl pre_authorized_code::Generate for AuthorizeLoginRequest<'_> {
    fn client_id(&self) -> Option<&str> {
        self.response.client_id.as_deref()
    }

    fn authorization_code(&self) -> Option<&str> {
        self.response.previous_authorization_code.as_deref()
    }

    fn require_wallet_binding(&self) -> bool {
        !self.response.siop_authenticated
            && self
                .response
                .client_id
                .as_deref()
                .is_some_and(client_credentials::requires_wallet_binding)
    }

    fn subject(&self) -> Option<&str> {
        self.response.username.as_deref()
    }

    fn require_subject(&self) -> bool {
        true
    }

    fn add_pre_authorized_code(&mut self, pre_authorized_code: String) {
        self.response.pre_authorized_code = Some(pre_authorized_code);
    }
}
