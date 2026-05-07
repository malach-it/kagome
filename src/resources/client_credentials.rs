use crate::errors::OAuthError;

pub const CLIENT_ID: &str = "client_id";
pub const CLIENT_SECRET: &str = "client_secret";

#[derive(Debug)]
pub struct ClientCredentials {
    pub client_id: String,
    pub client_secret: String,
}

pub trait Validate {
    fn request_client_id(&self) -> Option<&str>;
    fn request_client_secret(&self) -> Option<&str>;
    fn add_client_credentials(&mut self, client_credentials: ClientCredentials);
}

pub fn validate<T: Validate>(mut token_request: T) -> Result<T, OAuthError> {
    let client_id = token_request
        .request_client_id()
        .ok_or_else(OAuthError::missing_client_id)?;

    if client_id != CLIENT_ID {
        return Err(OAuthError::invalid_client_id(CLIENT_ID));
    }

    let client_secret = token_request
        .request_client_secret()
        .ok_or_else(OAuthError::missing_client_secret)?;

    if client_secret != CLIENT_SECRET {
        return Err(OAuthError::invalid_client_secret(CLIENT_SECRET));
    }

    token_request.add_client_credentials(ClientCredentials {
        client_id: CLIENT_ID.to_owned(),
        client_secret: CLIENT_SECRET.to_owned(),
    });
    Ok(token_request)
}
