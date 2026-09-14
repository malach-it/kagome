use crate::errors::OAuthError;

pub const CREDENTIAL_CONFIGURATION_ID: &str = "UniversityDegreeCredential";
pub const CREDENTIAL_SCOPE: &str = "UniversityDegree";
pub const CREDENTIAL_FORMAT: &str = "jwt_vc_json";
pub const CREDENTIAL_TYPE: &str = "UniversityDegreeCredential";

pub trait Validate {
    fn request_host(&self) -> Option<&str>;
    fn add_credential_issuer(&mut self, credential_issuer: String);
}

pub fn validate<T: Validate>(mut request: T) -> Result<T, OAuthError> {
    let host = request
        .request_host()
        .ok_or_else(|| OAuthError::invalid_request("host header is required"))?;

    if host.is_empty()
        || !host.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b':' | b'[' | b']')
        })
    {
        return Err(OAuthError::invalid_request("host header is invalid"));
    }

    request.add_credential_issuer(format!("https://{host}"));
    Ok(request)
}

pub trait ValidateConfiguration {
    fn request_content_type(&self) -> Option<&str>;
    fn request_credential_configuration_id(&self) -> Option<&str>;
    fn authorized_credential_configuration_id(&self) -> Option<&str>;
    fn add_credential_configuration(&mut self, credential_configuration_id: String);
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

    let credential_configuration_id = match request.request_credential_configuration_id() {
        None => {
            return Err(OAuthError::invalid_credential_request(
                "credential_configuration_id is required",
            ));
        }
        Some(CREDENTIAL_CONFIGURATION_ID) => CREDENTIAL_CONFIGURATION_ID,
        Some(_) => return Err(OAuthError::unknown_credential_configuration()),
    };

    if request.authorized_credential_configuration_id() != Some(credential_configuration_id) {
        return Err(OAuthError::invalid_access_token(
            "access token does not authorize the requested credential",
        ));
    }

    request.add_credential_configuration(credential_configuration_id.to_owned());
    Ok(request)
}
