use htpasswd_verify::Htpasswd;

use crate::{
    config::Config,
    errors::{OAuthError, OAuthErrorCode},
};

#[derive(Debug)]
pub struct ResourceOwner {
    pub username: String,
}

pub trait Validate {
    fn client_id(&self) -> Option<&str>;
    fn request_username(&self) -> Option<&str>;
    fn request_password(&self) -> Option<&str>;
    fn client_id_username(&self) -> Option<&str> {
        None
    }
    fn add_resource_owner(&mut self, resource_owner: ResourceOwner);
}

pub fn validate<T: Validate>(mut request: T) -> Result<T, OAuthError> {
    let Some(resource_owner) = validate_resource_owner(&request)? else {
        return Err(OAuthError::missing_username());
    };

    request.add_resource_owner(resource_owner);
    Ok(request)
}

pub fn validate_optional<T: Validate>(mut request: T) -> Result<T, OAuthError> {
    let resource_owner = match validate_resource_owner(&request) {
        Ok(resource_owner) => resource_owner,
        Err(error) if error.kind == OAuthErrorCode::MissingPassword => None,
        Err(error) => return Err(error),
    };

    let Some(resource_owner) = resource_owner else {
        return Ok(request);
    };

    request.add_resource_owner(resource_owner);
    Ok(request)
}

fn validate_resource_owner<T: Validate>(request: &T) -> Result<Option<ResourceOwner>, OAuthError> {
    if request.client_id_username().is_none()
        && request.request_username().is_none()
        && request.request_password().is_none()
    {
        return Ok(None);
    }

    let username = request
        .client_id_username()
        .or_else(|| request.request_username())
        .ok_or_else(OAuthError::missing_username)?;

    let client_id = request
        .client_id()
        .ok_or_else(OAuthError::invalid_client_id)?;
    let Some((passwords, usernames)) = Config::global().client_password_file(client_id) else {
        return Err(OAuthError::invalid_username(&[]));
    };
    if !usernames.iter().any(|configured| configured == username) {
        let expected_usernames = usernames.iter().map(String::as_str).collect::<Vec<_>>();
        return Err(OAuthError::invalid_username(&expected_usernames));
    }

    let password = request
        .request_password()
        .ok_or_else(OAuthError::missing_password)?;

    if !Htpasswd::from(passwords).check(username, password) {
        return Err(OAuthError::invalid_password());
    }

    Ok(Some(ResourceOwner {
        username: username.to_owned(),
    }))
}

pub fn configured_username(client_id: &str, username: &str) -> bool {
    Config::global()
        .client_password_file(client_id)
        .is_some_and(|(_, usernames)| usernames.iter().any(|configured| configured == username))
}
