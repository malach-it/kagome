use crate::{errors::OAuthError, unit::KagomeRequest};

pub const CLIENT_ID: &str = "client_id";

pub trait Validate {
    fn request_client_id(&self) -> Option<&str>;
    fn add_client_id(&mut self, client_id: &str);
}

pub fn validate<T: Validate>(
    mut token_request: T,
    _request: &KagomeRequest,
) -> Result<T, OAuthError> {
    let client_id = token_request
        .request_client_id()
        .ok_or_else(OAuthError::missing_client_id)?;

    if client_id != CLIENT_ID {
        return Err(OAuthError::invalid_client_id(CLIENT_ID));
    }

    token_request.add_client_id(CLIENT_ID);
    Ok(token_request)
}
