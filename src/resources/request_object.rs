use serde::Serialize;

use crate::{
    errors::OAuthError,
    resources::crypto::{self, SigningArtifact},
};

pub const SELF_ISSUED_AUDIENCE: &str = "https://self-issued.me/v2";

pub fn sign<T: Serialize>(claims: &T) -> Result<String, OAuthError> {
    crypto::sign_jwt(claims, SigningArtifact::RequestObject)
        .map_err(|_| OAuthError::invalid_token_response("request object generation failed"))
}
