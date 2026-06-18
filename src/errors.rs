use std::{error::Error, fmt};

#[derive(Debug)]
pub struct OAuthError {
    pub error: String,
    pub error_description: String,
}

impl OAuthError {
    pub fn unsupported_response_type(supported_response_types: &[&str]) -> Self {
        Self {
            error: "unsupported_response_type".to_owned(),
            error_description: format!(
                "response_type must be one of: {}",
                supported_response_types.join(", ")
            ),
        }
    }

    pub fn unsupported_grant_type(supported_grant_types: &[&str]) -> Self {
        Self {
            error: "unsupported_grant_type".to_owned(),
            error_description: format!(
                "grant_type must be one of: {}",
                supported_grant_types.join(", ")
            ),
        }
    }

    pub fn invalid_client_id(expected_client_id: &str) -> Self {
        Self {
            error: "invalid_client".to_owned(),
            error_description: format!("client_id must be: {expected_client_id}"),
        }
    }

    pub fn missing_client_id() -> Self {
        Self {
            error: "invalid_client".to_owned(),
            error_description: "client_id is required".to_owned(),
        }
    }

    pub fn invalid_client_secret(expected_client_secret: &str) -> Self {
        Self {
            error: "invalid_client".to_owned(),
            error_description: format!("client_secret must be: {expected_client_secret}"),
        }
    }

    pub fn missing_client_secret() -> Self {
        Self {
            error: "invalid_client".to_owned(),
            error_description: "client_secret is required".to_owned(),
        }
    }

    pub fn invalid_redirect_uri(expected_redirect_uri: &str) -> Self {
        Self {
            error: "invalid_request".to_owned(),
            error_description: format!("redirect_uri must be: {expected_redirect_uri}"),
        }
    }

    pub fn missing_redirect_uri() -> Self {
        Self {
            error: "invalid_request".to_owned(),
            error_description: "redirect_uri is required".to_owned(),
        }
    }

    pub fn invalid_id_token(error_description: impl Into<String>) -> Self {
        Self {
            error: "invalid_grant".to_owned(),
            error_description: error_description.into(),
        }
    }

    pub fn missing_id_token() -> Self {
        Self {
            error: "invalid_grant".to_owned(),
            error_description: "id_token is required".to_owned(),
        }
    }

    pub fn invalid_authorization_code(error_description: impl Into<String>) -> Self {
        Self {
            error: "invalid_grant".to_owned(),
            error_description: error_description.into(),
        }
    }

    pub fn missing_authorization_code() -> Self {
        Self {
            error: "invalid_grant".to_owned(),
            error_description: "authorization_code is required".to_owned(),
        }
    }

    pub fn invalid_token_response(error_description: impl Into<String>) -> Self {
        Self {
            error: "invalid_token_response".to_owned(),
            error_description: error_description.into(),
        }
    }

    pub fn to_response(&self) -> String {
        let response_body = format!(
            "{{\"error\":\"{}\",\"error_description\":\"{}\"}}",
            escape_json(&self.error),
            escape_json(&self.error_description)
        );

        format!(
            "HTTP/1.1 400 Bad Request\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
            response_body.len(),
            response_body
        )
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
