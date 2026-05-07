use crate::{
    errors::OAuthError,
    resources::{
        access_token::{AccessToken, TokenResponseAccessToken},
        authorization_code::{
            AuthorizationCode, TokenResponseAuthorizationCode,
            TokenResponseValidatedAuthorizationCode,
        },
        client_id::TokenResponseClientId,
        client_secret::TokenResponseClientSecret,
        grant_type::{GrantType, TokenResponseGrantType},
        id_token::TokenResponseIdToken,
    },
};

#[derive(Debug)]
pub struct GrantTypeResponse {
    pub grant_type: Option<GrantType>,
}

#[derive(Debug)]
pub struct ClientCredentialsResponse {
    pub access_token: Option<AccessToken>,
    pub client_id: Option<String>,
    pub client_secret: Option<String>,
    pub grant_type: Option<GrantType>,
}

#[derive(Debug)]
pub struct AuthorizationCodeResponse {
    pub access_token: Option<AccessToken>,
    pub authorization_code: Option<String>,
    pub client_id: Option<String>,
    pub client_secret: Option<String>,
    pub grant_type: Option<GrantType>,
}

#[derive(Debug)]
pub struct CodeChainResponse {
    pub authorization_code: Option<AuthorizationCode>,
    pub client_id: Option<String>,
    pub client_secret: Option<String>,
    pub grant_type: Option<GrantType>,
    pub id_token: Option<String>,
}

impl GrantTypeResponse {
    pub fn empty() -> Self {
        Self { grant_type: None }
    }
}

impl ClientCredentialsResponse {
    pub fn empty() -> Self {
        Self {
            access_token: None,
            client_id: None,
            client_secret: None,
            grant_type: None,
        }
    }

    pub fn to_response(&self) -> Result<String, OAuthError> {
        let access_token = self.access_token.as_ref().ok_or_else(|| {
            OAuthError::invalid_token_response("token response requires access_token")
        })?;

        Ok(access_token_response(access_token))
    }
}

impl AuthorizationCodeResponse {
    pub fn empty() -> Self {
        Self {
            access_token: None,
            authorization_code: None,
            client_id: None,
            client_secret: None,
            grant_type: None,
        }
    }

    pub fn to_response(&self) -> Result<String, OAuthError> {
        let access_token = self.access_token.as_ref().ok_or_else(|| {
            OAuthError::invalid_token_response("token response requires access_token")
        })?;

        Ok(access_token_response(access_token))
    }
}

impl CodeChainResponse {
    pub fn empty() -> Self {
        Self {
            authorization_code: None,
            client_id: None,
            client_secret: None,
            grant_type: None,
            id_token: None,
        }
    }

    pub fn to_response(&self) -> Result<String, OAuthError> {
        let authorization_code = self.authorization_code.as_ref().ok_or_else(|| {
            OAuthError::invalid_token_response("token response requires authorization_code")
        })?;

        Ok(authorization_code_response(authorization_code))
    }
}

impl From<GrantTypeResponse> for ClientCredentialsResponse {
    fn from(response: GrantTypeResponse) -> Self {
        Self {
            access_token: None,
            client_id: None,
            client_secret: None,
            grant_type: response.grant_type,
        }
    }
}

impl From<GrantTypeResponse> for AuthorizationCodeResponse {
    fn from(response: GrantTypeResponse) -> Self {
        Self {
            access_token: None,
            authorization_code: None,
            client_id: None,
            client_secret: None,
            grant_type: response.grant_type,
        }
    }
}

impl From<GrantTypeResponse> for CodeChainResponse {
    fn from(response: GrantTypeResponse) -> Self {
        Self {
            authorization_code: None,
            client_id: None,
            client_secret: None,
            grant_type: response.grant_type,
            id_token: None,
        }
    }
}

impl TokenResponseGrantType for GrantTypeResponse {
    fn add_grant_type(&mut self, grant_type: &GrantType) {
        self.grant_type = Some(*grant_type);
    }
}

impl TokenResponseAccessToken for ClientCredentialsResponse {
    fn add_access_token(&mut self, access_token: AccessToken) {
        self.access_token = Some(access_token);
    }
}

impl TokenResponseClientId for ClientCredentialsResponse {
    fn add_client_id(&mut self, client_id: &str) {
        self.client_id = Some(client_id.to_owned());
    }
}

impl TokenResponseClientSecret for ClientCredentialsResponse {
    fn add_client_secret(&mut self, client_secret: &str) {
        self.client_secret = Some(client_secret.to_owned());
    }
}

impl TokenResponseGrantType for ClientCredentialsResponse {
    fn add_grant_type(&mut self, grant_type: &GrantType) {
        self.grant_type = Some(*grant_type);
    }
}

impl TokenResponseGrantType for AuthorizationCodeResponse {
    fn add_grant_type(&mut self, grant_type: &GrantType) {
        self.grant_type = Some(*grant_type);
    }
}

impl TokenResponseAccessToken for AuthorizationCodeResponse {
    fn add_access_token(&mut self, access_token: AccessToken) {
        self.access_token = Some(access_token);
    }
}

impl TokenResponseClientId for AuthorizationCodeResponse {
    fn add_client_id(&mut self, client_id: &str) {
        self.client_id = Some(client_id.to_owned());
    }
}

impl TokenResponseClientSecret for AuthorizationCodeResponse {
    fn add_client_secret(&mut self, client_secret: &str) {
        self.client_secret = Some(client_secret.to_owned());
    }
}

impl TokenResponseValidatedAuthorizationCode for AuthorizationCodeResponse {
    fn add_validated_authorization_code(&mut self, authorization_code: &str) {
        self.authorization_code = Some(authorization_code.to_owned());
    }
}

impl TokenResponseAuthorizationCode for CodeChainResponse {
    fn add_authorization_code(&mut self, authorization_code: AuthorizationCode) {
        self.authorization_code = Some(authorization_code);
    }
}

impl TokenResponseClientId for CodeChainResponse {
    fn add_client_id(&mut self, client_id: &str) {
        self.client_id = Some(client_id.to_owned());
    }
}

impl TokenResponseClientSecret for CodeChainResponse {
    fn add_client_secret(&mut self, client_secret: &str) {
        self.client_secret = Some(client_secret.to_owned());
    }
}

impl TokenResponseIdToken for CodeChainResponse {
    fn add_id_token(&mut self, id_token: &str) {
        self.id_token = Some(id_token.to_owned());
    }
}

fn access_token_response(access_token: &AccessToken) -> String {
    let response_body = format!(
        "{{\"token_type\":\"{}\",\"access_token\":\"{}\",\"expires_in\":{}}}",
        escape_json(&access_token.payload.token_type),
        escape_json(&access_token.value),
        access_token.expires_in
    );

    format!(
        "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
        response_body.len(),
        response_body
    )
}

fn authorization_code_response(authorization_code: &AuthorizationCode) -> String {
    let response_body = format!(
        "{{\"authorization_code\":\"{}\",\"expires_in\":{}}}",
        escape_json(&authorization_code.value),
        authorization_code.expires_in
    );

    format!(
        "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
        response_body.len(),
        response_body
    )
}

fn escape_json(value: &str) -> String {
    value.chars().fold(String::new(), |mut escaped, character| {
        match character {
            '"' => escaped.push_str("\\\""),
            '\\' => escaped.push_str("\\\\"),
            '\n' => escaped.push_str("\\n"),
            '\r' => escaped.push_str("\\r"),
            '\t' => escaped.push_str("\\t"),
            character if character.is_control() => {
                escaped.push_str(&format!("\\u{:04x}", character as u32));
            }
            character => escaped.push(character),
        }

        escaped
    })
}
