use crate::{
    config::{ClientConfig, Config},
    errors::OAuthError,
};

#[derive(Debug)]
pub struct ClientCredentials {
    pub client_id: String,
    pub client_secret: Option<String>,
    pub redirect_uri: Option<String>,
}

pub trait Validate {
    fn request_client_id(&self) -> Option<&str>;
    fn is_authorize_post_request(&self) -> bool {
        false
    }
    fn valid_unregistered_client_id(&self, _client_id: &str) -> bool {
        false
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

pub fn validate<T: Validate>(request: T) -> Result<T, OAuthError> {
    validate_with_clients(request, &Config::global().clients)
}

pub fn validate_with_clients<T: Validate>(
    mut request: T,
    clients: &[ClientConfig],
) -> Result<T, OAuthError> {
    let client_id = request
        .request_client_id()
        .ok_or_else(OAuthError::missing_client_id)?
        .to_owned();

    let configured_client = clients.iter().find(|client| client.client_id == client_id);

    if configured_client.is_none() && !request.valid_unregistered_client_id(&client_id) {
        return Err(OAuthError::invalid_client_id());
    }

    let client_secret = if request.require_client_secret() {
        let client_secret = request
            .request_client_secret()
            .ok_or_else(OAuthError::missing_client_secret)?;

        let expected_client_secret = configured_client
            .map(|client| client.client_secret.as_str())
            .ok_or_else(OAuthError::invalid_client_id)?;

        if client_secret != expected_client_secret {
            return Err(OAuthError::invalid_client_secret());
        }

        Some(client_secret.to_owned())
    } else {
        None
    };

    let redirect_uri = if request.require_redirect_uri() {
        let redirect_uri = request
            .request_redirect_uri()
            .ok_or_else(OAuthError::missing_redirect_uri)?;

        let redirect_uri_is_configured = configured_client.map_or_else(
            || {
                clients
                    .iter()
                    .flat_map(|client| client.redirect_uris.iter())
                    .any(|configured_redirect_uri| configured_redirect_uri == redirect_uri)
            },
            |client| {
                client
                    .redirect_uris
                    .iter()
                    .any(|configured_redirect_uri| configured_redirect_uri == redirect_uri)
            },
        );

        if !redirect_uri_is_configured {
            return Err(OAuthError::invalid_redirect_uri());
        }

        Some(redirect_uri.to_owned())
    } else {
        None
    };

    if request.is_authorize_post_request()
        && configured_client.is_some_and(|client| client.federated_server.is_some())
    {
        return Err(OAuthError::invalid_request(
            "POST /authorize is disabled for federated clients",
        ));
    }

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
