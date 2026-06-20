use crate::errors::OAuthError;

pub const CLIENT_ID: &str = "client_id";
pub const CLIENT_SECRET: &str = "client_secret";
pub const REDIRECT_URI: &str = "https://client.example.com/callback";
pub const LOOPBACK_REDIRECT_URI_SCHEME: &str = "http";
pub const USERNAME_LOCALHOST_CLIENT_ID: &str = "username@localhost:4000";
pub const OTHER_USERNAME_LOCALHOST_CLIENT_ID: &str = "other_username@localhost:4000";
pub const USERNAME_LOCALHOST_REDIRECT_URI: &str = "http://127.0.0.1:4001/oauth/callback";
const LOOPBACK_CLIENT_IDS: [&str; 2] = [
    USERNAME_LOCALHOST_CLIENT_ID,
    OTHER_USERNAME_LOCALHOST_CLIENT_ID,
];

#[derive(Debug)]
pub struct ClientCredentials {
    pub client_id: String,
    pub client_secret: Option<String>,
    pub redirect_uri: Option<String>,
}

pub trait Validate {
    fn request_client_id(&self) -> Option<&str>;
    fn valid_client_id(&self, client_id: &str) -> bool {
        client_id == CLIENT_ID || valid_loopback_client_id(client_id)
    }
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
    fn add_resource_owner_credentials(&mut self, _username: &str, _password: &str) {}
    fn add_client_credentials(&mut self, client_credentials: ClientCredentials);
}

pub fn validate<T: Validate>(mut request: T) -> Result<T, OAuthError> {
    let client_id = request
        .request_client_id()
        .ok_or_else(OAuthError::missing_client_id)?
        .to_owned();

    if !request.valid_client_id(&client_id) {
        return Err(OAuthError::invalid_client_id());
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

        if !valid_redirect_uri(&client_id, redirect_uri) {
            return Err(OAuthError::invalid_redirect_uri(REDIRECT_URI));
        }

        Some(redirect_uri.to_owned())
    } else {
        None
    };

    let validated_client_id =
        if let Some((username, password, host)) = resource_owner_credentials(&client_id) {
            request.add_resource_owner_credentials(username, password);
            format!("{username}@{host}")
        } else {
            client_id
        };

    request.add_client_credentials(ClientCredentials {
        client_id: validated_client_id,
        client_secret,
        redirect_uri,
    });
    Ok(request)
}

pub fn client_id_resource_owner_credentials(client_id: &str) -> bool {
    resource_owner_credentials(client_id).is_some()
}

pub fn loopback_redirect_uri() -> String {
    loopback_redirect_uri_for_address(&crate::http_server::loopback_address_from_environment())
}

pub fn loopback_redirect_uri_for_address(address: &str) -> String {
    format!(
        "{LOOPBACK_REDIRECT_URI_SCHEME}://{address}{}",
        crate::ssh_login::OAUTH_CALLBACK_PATH
    )
}

pub fn valid_loopback_client_id(client_id: &str) -> bool {
    LOOPBACK_CLIENT_IDS.contains(&client_id)
}

fn valid_redirect_uri(client_id: &str, redirect_uri: &str) -> bool {
    redirect_uri == REDIRECT_URI
        || (valid_loopback_client_id(client_id) && redirect_uri == USERNAME_LOCALHOST_REDIRECT_URI)
        || (resource_owner_credentials(client_id).is_some()
            && redirect_uri == loopback_redirect_uri())
}

fn resource_owner_credentials(client_id: &str) -> Option<(&str, &str, &str)> {
    let (credentials, host) = client_id.split_once('@')?;
    if credentials.is_empty() || host.is_empty() {
        return None;
    }

    let (username, password) = credentials.split_once(':')?;
    if username.is_empty() || password.is_empty() {
        return None;
    }

    Some((username, password, host))
}
