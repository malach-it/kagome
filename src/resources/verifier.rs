use crate::errors::OAuthError;

pub const PRESENTATION_RESPONSE_PATH: &str = "/presentation-response";

pub trait Validate {
    fn request_host(&self) -> Option<&str>;
    fn add_verifier(&mut self, verifier: String);
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

    request.add_verifier(format!("https://{host}"));
    Ok(request)
}

pub fn response_uri(verifier: &str) -> String {
    format!("{verifier}{PRESENTATION_RESPONSE_PATH}")
}

pub fn client_id(verifier: &str) -> String {
    format!("redirect_uri:{}", response_uri(verifier))
}
