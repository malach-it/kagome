use crate::{errors::OAuthError, unit::KagomeRequest};

pub const CLIENT_SECRET: &str = "client_secret";

pub trait TokenResponseClientSecret {
    fn add_client_secret(&mut self, client_secret: &str);
}

pub fn validate<T: TokenResponseClientSecret>(
    mut token_response: T,
    request: &KagomeRequest,
) -> Result<T, OAuthError> {
    let client_secret = request
        .client_secret
        .as_deref()
        .ok_or_else(OAuthError::missing_client_secret)?;

    if client_secret != CLIENT_SECRET {
        return Err(OAuthError::invalid_client_secret(CLIENT_SECRET));
    }

    token_response.add_client_secret(CLIENT_SECRET);
    Ok(token_response)
}
