use crate::{
    config::{ClientConfig, Config},
    errors::OAuthError,
    resources::{grant_type::GrantType, response_type::ResponseType},
};

#[derive(Debug)]
pub struct ClientCredentials {
    pub client_id: String,
    pub client_secret: Option<String>,
    pub redirect_uri: Option<String>,
    pub authenticated_username: Option<String>,
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
    fn requested_grant_types(&self) -> &[GrantType] {
        &[]
    }
    fn requested_response_types(&self) -> &[ResponseType] {
        &[]
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

    let exact_client = clients.iter().find(|client| client.client_id == client_id);
    let public_host = public_client_host(&client_id);
    let public_client = if exact_client.is_none() {
        clients.iter().find(|client| {
            client.public.as_deref().is_some_and(|configured| {
                public_host.is_some_and(|host| configured.eq_ignore_ascii_case(host))
            })
        })
    } else {
        None
    };
    let is_public_client_id = public_client.is_some()
        && (request.require_client_secret() || request.valid_unregistered_client_id(&client_id));
    let configured_client =
        exact_client.or_else(|| is_public_client_id.then_some(public_client).flatten());

    if configured_client.is_none() && !is_public_client_id {
        return Err(OAuthError::invalid_client_id());
    }

    let client_secret = if request.require_client_secret() {
        let client_secret = request
            .request_client_secret()
            .ok_or_else(OAuthError::missing_client_secret)?;

        let client_secret_is_configured =
            configured_client.is_some_and(|client| client.client_secret == client_secret);

        if !client_secret_is_configured {
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

        let redirect_uri_is_configured = configured_client.is_some_and(|client| {
            client
                .redirect_uris
                .iter()
                .any(|configured_redirect_uri| configured_redirect_uri == redirect_uri)
        });

        if !redirect_uri_is_configured {
            return Err(OAuthError::invalid_redirect_uri());
        }

        Some(redirect_uri.to_owned())
    } else {
        None
    };

    let configured_client = configured_client.ok_or_else(OAuthError::invalid_client_id)?;
    if let Some(grant_type) = request
        .requested_grant_types()
        .iter()
        .find(|grant_type| !configured_client.supported_grant_types.contains(grant_type))
    {
        return Err(OAuthError::unauthorized_client(format!(
            "client does not support grant_type {}",
            grant_type.as_str()
        )));
    }
    if let Some(response_type) = request
        .requested_response_types()
        .iter()
        .find(|response_type| {
            !configured_client
                .supported_response_types
                .contains(response_type)
        })
    {
        return Err(OAuthError::unauthorized_client(format!(
            "client does not support response_type {}",
            response_type.as_str()
        )));
    }

    if request.is_authorize_post_request() && configured_client.federated_server.is_some() {
        return Err(OAuthError::invalid_request(
            "POST /authorize is disabled for federated clients",
        ));
    }
    for response_type in request.requested_response_types() {
        let required_grant_type = match response_type {
            ResponseType::Code => Some(GrantType::AuthorizationCode),
            ResponseType::IdToken | ResponseType::Token => Some(GrantType::Implicit),
            ResponseType::PreAuthorizedCode => Some(GrantType::PreAuthorizedCode),
            ResponseType::VpToken => None,
        };
        if let Some(grant_type) = required_grant_type
            && !configured_client
                .supported_grant_types
                .contains(&grant_type)
        {
            return Err(OAuthError::unauthorized_client(format!(
                "client does not support grant_type {}",
                grant_type.as_str()
            )));
        }
    }

    let authenticated_username = is_public_client_id
        .then(|| public_client_username(&client_id))
        .flatten()
        .map(str::to_owned);
    let validated_client_id =
        if let Some((username, password, host)) = resource_owner_credentials(&client_id) {
            request.add_resource_owner_credentials(username, password);
            format!("{username}@{host}")
        } else {
            client_id
        };

    request.add_client_credentials(ClientCredentials {
        authenticated_username,
        client_id: validated_client_id,
        client_secret,
        redirect_uri,
    });
    Ok(request)
}

pub fn client_id_resource_owner_credentials(client_id: &str) -> bool {
    resource_owner_credentials(client_id).is_some()
}

pub fn requires_wallet_binding(client_id: &str) -> bool {
    Config::global()
        .client(client_id)
        .is_some_and(|client| client.require_wallet_binding)
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

fn public_client_username(client_id: &str) -> Option<&str> {
    let (username, host) = client_id.split_once('@')?;

    (!username.is_empty() && !username.contains(':') && !host.is_empty()).then_some(username)
}

fn public_client_host(client_id: &str) -> Option<&str> {
    let (identifier, host) = client_id.split_once('@')?;

    (!identifier.is_empty() && !host.is_empty()).then_some(host)
}
