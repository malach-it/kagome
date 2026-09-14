use crate::errors::OAuthError;

pub const SUPPORTED_WALLET_ERRORS: &[&str] = &[
    "access_denied",
    "invalid_request",
    "vp_formats_not_supported",
    "wallet_unavailable",
];

pub trait ValidateEncoding {
    fn request_content_type(&self) -> Option<&str>;
}

pub trait ValidateWalletError {
    fn request_wallet_error(&self) -> Option<&str>;
    fn request_vp_token(&self) -> Option<&str>;
    fn add_wallet_error(&mut self, error: String);
}

pub fn validate_encoding<T: ValidateEncoding>(request: T) -> Result<T, OAuthError> {
    let media_type = request
        .request_content_type()
        .and_then(|content_type| content_type.split(';').next())
        .map(str::trim);

    if !media_type.is_some_and(|media_type| {
        media_type.eq_ignore_ascii_case("application/x-www-form-urlencoded")
    }) {
        return Err(OAuthError::invalid_request(
            "presentation response content-type must be application/x-www-form-urlencoded",
        ));
    }

    Ok(request)
}

pub fn validate_wallet_error<T: ValidateWalletError>(mut request: T) -> Result<T, OAuthError> {
    let error = request
        .request_wallet_error()
        .ok_or_else(|| OAuthError::invalid_request("wallet error is required"))?;

    if request.request_vp_token().is_some() {
        return Err(OAuthError::invalid_request(
            "wallet error response must not include vp_token",
        ));
    }

    if !SUPPORTED_WALLET_ERRORS.contains(&error) {
        return Err(OAuthError::invalid_request("wallet error is unsupported"));
    }

    request.add_wallet_error(error.to_owned());
    Ok(request)
}
