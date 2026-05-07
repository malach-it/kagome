use crate::{errors::OAuthError, unit::KagomeRequest};

pub const CLIENT_ID: &str = "client_id";

pub trait TokenResponseClientId {
    fn add_client_id(&mut self, client_id: &str);
}

pub fn validate<T: TokenResponseClientId>(
    mut token_response: T,
    request: &KagomeRequest,
) -> Result<T, OAuthError> {
    let client_id = request
        .client_id
        .as_deref()
        .ok_or_else(OAuthError::missing_client_id)?;

    if client_id != CLIENT_ID {
        return Err(OAuthError::invalid_client_id(CLIENT_ID));
    }

    token_response.add_client_id(CLIENT_ID);
    Ok(token_response)
}
