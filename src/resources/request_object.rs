use serde::Serialize;

use crate::{
    errors::OAuthError,
    resources::crypto::{self, SigningArtifact},
};

pub const SELF_ISSUED_AUDIENCE: &str = "https://self-issued.me/v2";

/// Signs request-object claims with Kagome's configured request-object identity.
///
/// The signing key manager supplies the request-object key, algorithm, and key identifier.
///
/// # Errors
///
/// Returns `invalid_token_response` when claims cannot be serialized or signed.
pub fn sign<T: Serialize>(claims: &T) -> Result<String, OAuthError> {
    crypto::sign_jwt(claims, SigningArtifact::RequestObject)
        .map_err(|_| OAuthError::invalid_token_response("request object generation failed"))
}
