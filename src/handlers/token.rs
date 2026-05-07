use crate::{
    errors::OAuthError,
    resources::{
        access_token::{self, AccessToken, TokenResponseAccessToken},
        client_id::{self, TokenResponseClientId},
        client_secret::{self, TokenResponseClientSecret},
        grant_type::{self, GrantType, TokenResponseGrantType},
    },
    unit::KagomeRequest,
};

#[derive(Debug)]
pub struct TokenResponse {
    pub access_token: Option<AccessToken>,
    pub client_id: Option<String>,
    pub client_secret: Option<String>,
    pub grant_type: Option<GrantType>,
}

pub fn handle(request: &KagomeRequest) -> String {
    match grant_type::validate(TokenResponse::empty(), request)
        .and_then(|token_response| client_id::validate(token_response, request))
        .and_then(|token_response| client_secret::validate(token_response, request))
        .and_then(|token_response| access_token::generate(token_response, request))
        .and_then(|token_response| token_response.to_response())
    {
        Ok(response) => response,
        Err(error) => error.to_response(),
    }
}

impl TokenResponse {
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

        let response_body = format!(
            "{{\"token_type\":\"{}\",\"access_token\":\"{}\",\"expires_in\":{}}}",
            escape_json(&access_token.payload.token_type),
            escape_json(&access_token.value),
            access_token.expires_in
        );

        Ok(format!(
            "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
            response_body.len(),
            response_body
        ))
    }
}

impl TokenResponseAccessToken for TokenResponse {
    fn add_access_token(&mut self, access_token: AccessToken) {
        self.access_token = Some(access_token);
    }
}

impl TokenResponseClientId for TokenResponse {
    fn add_client_id(&mut self, client_id: &str) {
        self.client_id = Some(client_id.to_owned());
    }
}

impl TokenResponseClientSecret for TokenResponse {
    fn add_client_secret(&mut self, client_secret: &str) {
        self.client_secret = Some(client_secret.to_owned());
    }
}

impl TokenResponseGrantType for TokenResponse {
    fn add_grant_type(&mut self, grant_type: &GrantType) {
        self.grant_type = Some(*grant_type);
    }
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
