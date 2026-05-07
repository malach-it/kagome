use crate::{errors::OAuthError, unit::KagomeRequest};

pub const CLIENT_SECRET: &str = "client_secret";

pub trait Validate {
    fn request_client_secret(&self) -> Option<&str>;
    fn add_client_secret(&mut self, client_secret: &str);
}

pub fn validate<T: Validate>(
    mut token_request: T,
    _request: &KagomeRequest,
) -> Result<T, OAuthError> {
    let client_secret = token_request
        .request_client_secret()
        .ok_or_else(OAuthError::missing_client_secret)?;

    if client_secret != CLIENT_SECRET {
        return Err(OAuthError::invalid_client_secret(CLIENT_SECRET));
    }

    token_request.add_client_secret(CLIENT_SECRET);
    Ok(token_request)
}
