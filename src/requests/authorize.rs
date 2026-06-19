use crate::{
    errors::OAuthError,
    handlers::responses::{
        authorize_redirect_response, code_redirect_response, login_page_response,
    },
    resources::{
        authorization_code::{self, AuthorizationCode},
        client_credentials, resource_owner,
        response_type::{self, ResponseType},
    },
    unit::{KagomeRequest, parse_query_parameter, parse_request_parameter},
};

#[derive(Debug)]
pub struct AuthorizeLoginRequest<'a> {
    pub response: AuthorizeLoginResponse,
    pub request: &'a KagomeRequest,
    pub response_type: Option<String>,
    pub client_id: Option<String>,
    pub redirect_uri: Option<String>,
    pub authorization_code: Option<String>,
}

#[derive(Debug)]
pub struct AuthorizeLoginResponse {
    pub client_id: Option<String>,
    pub client_secret: Option<String>,
    pub redirect_uri: Option<String>,
    pub previous_authorization_code: Option<String>,
    pub response_types: Vec<ResponseType>,
}

#[derive(Debug)]
pub struct AuthorizeCodeRequest<'a> {
    pub response: AuthorizeCodeResponse,
    pub request: &'a KagomeRequest,
    pub response_type: Option<String>,
    pub client_id: Option<String>,
    pub redirect_uri: Option<String>,
    pub authorization_code: Option<String>,
    pub username: Option<String>,
    pub password: Option<String>,
}

#[derive(Debug)]
pub struct AuthorizeCodeResponse {
    pub authorization_code: Option<AuthorizationCode>,
    pub previous_authorization_code: Option<String>,
    pub client_id: Option<String>,
    pub client_secret: Option<String>,
    pub redirect_uri: Option<String>,
    pub username: Option<String>,
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
            authorization_code: parse_query_parameter(request, "authorization_code"),
        }
    }

    pub fn to_response(&self) -> Result<String, OAuthError> {
        Ok(login_page_response(self))
    }
}

impl AuthorizeLoginResponse {
    fn empty() -> Self {
        Self {
            client_id: None,
            client_secret: None,
            redirect_uri: None,
            previous_authorization_code: None,
            response_types: Vec::new(),
        }
    }
}

impl<'a> AuthorizeCodeRequest<'a> {
    pub fn from_request(request: &'a KagomeRequest) -> Self {
        Self {
            response: AuthorizeCodeResponse::empty(),
            request,
            response_type: parse_query_parameter(request, "response_type"),
            client_id: parse_query_parameter(request, "client_id"),
            redirect_uri: parse_query_parameter(request, "redirect_uri"),
            authorization_code: parse_query_parameter(request, "authorization_code"),
            username: parse_request_parameter(request, "username"),
            password: parse_request_parameter(request, "password"),
        }
    }

    pub fn to_response(&self) -> Result<String, OAuthError> {
        let authorization_code = self.response.authorization_code.as_ref().ok_or_else(|| {
            OAuthError::invalid_token_response("authorize response requires code")
        })?;

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
}

impl AuthorizeCodeResponse {
    fn empty() -> Self {
        Self {
            authorization_code: None,
            previous_authorization_code: None,
            client_id: None,
            client_secret: None,
            redirect_uri: None,
            username: None,
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
}

impl<'a> response_type::Validate for AuthorizeCodeRequest<'a> {
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
}

impl<'a> client_credentials::Validate for AuthorizeCodeRequest<'a> {
    fn request_client_id(&self) -> Option<&str> {
        self.client_id.as_deref()
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
}

impl<'a> resource_owner::Validate for AuthorizeCodeRequest<'a> {
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

impl<'a> authorization_code::Validate for AuthorizeCodeRequest<'a> {
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

impl<'a> authorization_code::Generate for AuthorizeCodeRequest<'a> {
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

fn response_type_query(response_types: &[ResponseType]) -> Option<String> {
    if response_types.is_empty() {
        return None;
    }

    Some(
        response_types
            .iter()
            .map(|response_type| response_type.as_str())
            .collect::<Vec<_>>()
            .join(" "),
    )
}
