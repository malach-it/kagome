use crate::{
    config::{Config, CredentialConfig},
    errors::OAuthError,
};

pub const CREDENTIAL_FORMAT: &str = "jwt_vc";

pub trait Validate {
    fn add_credential_issuer(&mut self, credential_issuer: String);
}

pub fn validate<T: Validate>(mut request: T) -> Result<T, OAuthError> {
    // Request headers are attacker-controlled and must not define issuer identity.
    request.add_credential_issuer(Config::global().server.issuer.clone());
    Ok(request)
}

pub trait ValidateConfiguration {
    fn request_content_type(&self) -> Option<&str>;
    fn request_credential_identifier(&self) -> Option<&str>;
    fn authorized_credential_configuration_ids(&self) -> &[String];
    fn add_credential_configuration(&mut self, credential: CredentialConfig);
}

pub fn validate_configuration<T: ValidateConfiguration>(mut request: T) -> Result<T, OAuthError> {
    let media_type = request
        .request_content_type()
        .and_then(|content_type| content_type.split(';').next())
        .map(str::trim);
    if !media_type.is_some_and(|media_type| media_type.eq_ignore_ascii_case("application/json")) {
        return Err(OAuthError::invalid_credential_request(
            "credential request content-type must be application/json",
        ));
    }

    let credential_configuration_id = match request.request_credential_identifier() {
        None => {
            return Err(OAuthError::invalid_credential_request(
                "credential_identifier is required",
            ));
        }
        Some(credential_configuration_id) => credential_configuration_id,
    };
    let credential = Config::global()
        .credential(credential_configuration_id)
        .cloned()
        .ok_or_else(OAuthError::unknown_credential_configuration)?;

    if !request
        .authorized_credential_configuration_ids()
        .iter()
        .any(|authorized| authorized == credential_configuration_id)
    {
        return Err(OAuthError::invalid_access_token(
            "access token does not authorize the requested credential",
        ));
    }

    request.add_credential_configuration(credential);
    Ok(request)
}
