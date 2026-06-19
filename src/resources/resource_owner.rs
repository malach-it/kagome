use crate::errors::{OAuthError, OAuthErrorCode};

pub const USERNAME: &str = "username";
pub const PASSWORD: &str = "password";
pub const OTHER_USERNAME: &str = "other_username";
pub const OTHER_PASSWORD: &str = "other_password";
pub const USERNAMES: [&str; 2] = [USERNAME, OTHER_USERNAME];
const RESOURCE_OWNERS: [(&str, &str); 2] = [(USERNAME, PASSWORD), (OTHER_USERNAME, OTHER_PASSWORD)];

#[derive(Debug)]
pub struct ResourceOwner {
    pub username: String,
}

pub trait Validate {
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
    if request.request_username().is_none() && request.request_password().is_none() {
        return Ok(None);
    }

    let username = request
        .request_username()
        .ok_or_else(OAuthError::missing_username)?;

    if let Some(client_id_username) = request.client_id_username()
        && username != client_id_username
    {
        return Err(OAuthError::invalid_username(&[client_id_username]));
    }

    let Some((username, expected_password)) = RESOURCE_OWNERS
        .iter()
        .find(|(resource_owner_username, _)| *resource_owner_username == username)
    else {
        return Err(OAuthError::invalid_username(&USERNAMES));
    };

    let password = request
        .request_password()
        .ok_or_else(OAuthError::missing_password)?;

    if password != *expected_password {
        return Err(OAuthError::invalid_password());
    }

    Ok(Some(ResourceOwner {
        username: (*username).to_owned(),
    }))
}
