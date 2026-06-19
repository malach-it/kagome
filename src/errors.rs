use std::{error::Error, fmt};

#[derive(Debug)]
pub struct OAuthError {
    pub error: String,
    pub error_description: String,
    pub format: String,
}

impl OAuthError {
    pub const DEFAULT_FORMAT: &'static str = "json";

    pub fn unsupported_response_type(supported_response_types: &[&str]) -> Self {
        Self::new(
            "unsupported_response_type",
            format!(
                "response_type must be one of: {}",
                supported_response_types.join(", ")
            ),
        )
    }

    pub fn unsupported_grant_type(supported_grant_types: &[&str]) -> Self {
        Self::new(
            "unsupported_grant_type",
            format!(
                "grant_type must be one of: {}",
                supported_grant_types.join(", ")
            ),
        )
    }

    pub fn invalid_client_id(expected_client_id: &str) -> Self {
        Self::new(
            "invalid_client",
            format!("client_id must be: {expected_client_id}"),
        )
    }

    pub fn missing_client_id() -> Self {
        Self::new("invalid_client", "client_id is required")
    }

    pub fn invalid_client_secret(expected_client_secret: &str) -> Self {
        Self::new(
            "invalid_client",
            format!("client_secret must be: {expected_client_secret}"),
        )
    }

    pub fn missing_client_secret() -> Self {
        Self::new("invalid_client", "client_secret is required")
    }

    pub fn invalid_username(expected_username: &str) -> Self {
        Self::new(
            "invalid_grant",
            format!("username must be: {expected_username}"),
        )
    }

    pub fn missing_username() -> Self {
        Self::new("invalid_grant", "username is required")
    }

    pub fn invalid_password(expected_password: &str) -> Self {
        Self::new(
            "invalid_grant",
            format!("password must be: {expected_password}"),
        )
    }

    pub fn missing_password() -> Self {
        Self::new("invalid_grant", "password is required")
    }

    pub fn invalid_redirect_uri(expected_redirect_uri: &str) -> Self {
        Self::new(
            "invalid_request",
            format!("redirect_uri must be: {expected_redirect_uri}"),
        )
    }

    pub fn missing_redirect_uri() -> Self {
        Self::new("invalid_request", "redirect_uri is required")
    }

    pub fn invalid_id_token(error_description: impl Into<String>) -> Self {
        Self::new("invalid_grant", error_description)
    }

    pub fn missing_id_token() -> Self {
        Self::new("invalid_grant", "id_token is required")
    }

    pub fn invalid_authorization_code(error_description: impl Into<String>) -> Self {
        Self::new("invalid_grant", error_description)
    }

    pub fn missing_authorization_code() -> Self {
        Self::new("invalid_grant", "authorization_code is required")
    }

    pub fn invalid_token_response(error_description: impl Into<String>) -> Self {
        Self::new("invalid_token_response", error_description)
    }

    pub fn with_format(mut self, format: impl Into<String>) -> Self {
        self.format = format.into();
        self
    }

    fn new(error: impl Into<String>, error_description: impl Into<String>) -> Self {
        Self {
            error: error.into(),
            error_description: error_description.into(),
            format: Self::DEFAULT_FORMAT.to_owned(),
        }
    }

    pub fn to_response(&self) -> String {
        if self.format == "login" {
            return self.to_login_response();
        }

        self.to_json_response()
    }

    fn to_json_response(&self) -> String {
        let response_body = format!(
            "{{\"error\":\"{}\",\"error_description\":\"{}\"}}",
            escape_json(&self.error),
            escape_json(&self.error_description)
        );

        format!(
            "HTTP/1.1 400 Bad Request\r\ncontent-type: {}\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
            self.content_type(),
            response_body.len(),
            response_body
        )
    }

    fn to_login_response(&self) -> String {
        let response_body = format!(
            "<!doctype html><html><head><title>kagome login</title></head><body><main><h1>kagome login</h1><p role=\"alert\">{}</p><form method=\"post\" action=\"/authorize\"><label>username <input name=\"username\" autocomplete=\"username\"></label><label>password <input name=\"password\" type=\"password\" autocomplete=\"current-password\"></label><button type=\"submit\">sign in</button></form></main></body></html>",
            escape_html(&self.error_description)
        );

        format!(
            "HTTP/1.1 400 Bad Request\r\ncontent-type: text/html\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
            response_body.len(),
            response_body
        )
    }

    fn content_type(&self) -> &str {
        match self.format.as_str() {
            "json" => "application/json",
            format => format,
        }
    }
}

impl fmt::Display for OAuthError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}: {}", self.error, self.error_description)
    }
}

impl Error for OAuthError {}

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

fn escape_html(value: &str) -> String {
    value.chars().fold(String::new(), |mut escaped, character| {
        match character {
            '&' => escaped.push_str("&amp;"),
            '<' => escaped.push_str("&lt;"),
            '>' => escaped.push_str("&gt;"),
            '"' => escaped.push_str("&quot;"),
            '\'' => escaped.push_str("&#39;"),
            character => escaped.push(character),
        }

        escaped
    })
}
