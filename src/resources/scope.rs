use crate::{
    config::{ClientConfig, Config},
    errors::OAuthError,
};

pub trait Validate {
    fn request_scope(&self) -> Option<&str>;
    fn validated_client_id(&self) -> Option<&str>;
}

pub fn validate<T: Validate>(request: T) -> Result<T, OAuthError> {
    validate_with_clients(request, &Config::global().clients)
}

pub fn validate_with_clients<T: Validate>(
    request: T,
    clients: &[ClientConfig],
) -> Result<T, OAuthError> {
    let Some(scope) = request.request_scope() else {
        return Ok(request);
    };
    let client_id = request
        .validated_client_id()
        .ok_or_else(|| OAuthError::invalid_token_response("scope validation requires client_id"))?;
    let client = configured_client(clients, client_id).ok_or_else(OAuthError::invalid_client_id)?;
    let requested_scopes = scope.split_ascii_whitespace().collect::<Vec<_>>();

    if requested_scopes.is_empty() {
        return Err(OAuthError::invalid_scope("scope must not be empty"));
    }
    if let Some(scope) = requested_scopes
        .iter()
        .find(|scope| !client.scopes.iter().any(|configured| configured == **scope))
    {
        return Err(OAuthError::invalid_scope(format!(
            "scope is not authorized for client: {scope}"
        )));
    }

    Ok(request)
}

fn configured_client<'a>(clients: &'a [ClientConfig], client_id: &str) -> Option<&'a ClientConfig> {
    clients
        .iter()
        .find(|client| client.client_id == client_id)
        .or_else(|| {
            let (_, host) = client_id.split_once('@')?;
            clients.iter().find(|client| {
                client
                    .public
                    .as_deref()
                    .is_some_and(|public| public.eq_ignore_ascii_case(host))
            })
        })
}
