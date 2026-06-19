use crate::errors::OAuthError;

pub const USERNAME: &str = "username";
pub const PASSWORD: &str = "password";

#[derive(Debug)]
pub struct ResourceOwner {
    pub username: String,
}

pub trait Validate {
    fn request_username(&self) -> Option<&str>;
    fn request_password(&self) -> Option<&str>;
    fn add_resource_owner(&mut self, resource_owner: ResourceOwner);
}

pub fn validate<T: Validate>(mut request: T) -> Result<T, OAuthError> {
    let username = request
        .request_username()
        .ok_or_else(OAuthError::missing_username)?;

    if username != USERNAME {
        return Err(OAuthError::invalid_username(USERNAME));
    }

    let password = request
        .request_password()
        .ok_or_else(OAuthError::missing_password)?;

    if password != PASSWORD {
        return Err(OAuthError::invalid_password(PASSWORD));
    }

    request.add_resource_owner(ResourceOwner {
        username: USERNAME.to_owned(),
    });
    Ok(request)
}
