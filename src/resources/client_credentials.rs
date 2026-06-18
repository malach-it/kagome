use crate::errors::OAuthError;

pub const CLIENT_ID: &str = "client_id";
pub const CLIENT_SECRET: &str = "client_secret";
pub const REDIRECT_URI: &str = "https://client.example.com/callback";

#[derive(Debug)]
pub struct ClientCredentials {
    pub client_id: String,
    pub client_secret: Option<String>,
    pub redirect_uri: Option<String>,
}

pub trait Validate {
    fn request_client_id(&self) -> Option<&str>;
    fn request_client_secret(&self) -> Option<&str> {
        None
    }
    fn require_client_secret(&self) -> bool {
        true
    }
    fn request_redirect_uri(&self) -> Option<&str> {
        None
    }
    fn require_redirect_uri(&self) -> bool {
        false
    }
    fn add_client_credentials(&mut self, client_credentials: ClientCredentials);
}

pub fn validate<T: Validate>(mut request: T) -> Result<T, OAuthError> {
    let client_id = request
        .request_client_id()
        .ok_or_else(OAuthError::missing_client_id)?;

    if client_id != CLIENT_ID {
        return Err(OAuthError::invalid_client_id(CLIENT_ID));
    }

    let client_secret = if request.require_client_secret() {
        let client_secret = request
            .request_client_secret()
            .ok_or_else(OAuthError::missing_client_secret)?;

        if client_secret != CLIENT_SECRET {
            return Err(OAuthError::invalid_client_secret(CLIENT_SECRET));
        }

        Some(CLIENT_SECRET.to_owned())
    } else {
        None
    };

    let redirect_uri = if request.require_redirect_uri() {
        let redirect_uri = request
            .request_redirect_uri()
            .ok_or_else(OAuthError::missing_redirect_uri)?;

        if redirect_uri != REDIRECT_URI {
            return Err(OAuthError::invalid_redirect_uri(REDIRECT_URI));
        }

        Some(REDIRECT_URI.to_owned())
    } else {
        None
    };

    request.add_client_credentials(ClientCredentials {
        client_id: CLIENT_ID.to_owned(),
        client_secret,
        redirect_uri,
    });
    Ok(request)
}
