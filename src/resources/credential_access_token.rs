use std::time::{SystemTime, UNIX_EPOCH};

use jsonwebtoken::{
    Algorithm, DecodingKey, EncodingKey, Header, Validation, decode, encode, get_current_timestamp,
};
use serde::{Deserialize, Serialize};

use crate::errors::OAuthError;

const SECRET: &str = "static_credential_access_token_secret";
pub const TTL_SECONDS: u64 = 3600;

#[derive(Debug)]
pub struct CredentialAccessToken {
    pub value: String,
    pub expires_in: u64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CredentialAccessTokenClaims {
    pub credential_configuration_id: String,
    pub subject: String,
    pub iat: u64,
    pub exp: u64,
}

pub trait Generate {
    fn credential_configuration_id(&self) -> Option<&str>;
    fn subject(&self) -> Option<&str>;
    fn add_credential_access_token(&mut self, access_token: CredentialAccessToken);
}

pub trait Validate {
    fn request_access_token(&self) -> Option<&str>;
    fn add_credential_access_token_claims(&mut self, claims: CredentialAccessTokenClaims);
}

pub fn generate<T: Generate>(mut request: T) -> Result<T, OAuthError> {
    let credential_configuration_id = request.credential_configuration_id().ok_or_else(|| {
        OAuthError::invalid_token_response("credential configuration is required")
    })?;
    let subject = request
        .subject()
        .ok_or_else(|| OAuthError::invalid_token_response("credential subject is required"))?;
    let iat = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| OAuthError::invalid_token_response("access token generation failed"))?
        .as_secs();
    let claims = CredentialAccessTokenClaims {
        credential_configuration_id: credential_configuration_id.to_owned(),
        subject: subject.to_owned(),
        iat,
        exp: iat + TTL_SECONDS,
    };
    let access_token = CredentialAccessToken {
        value: encode(
            &Header::new(Algorithm::HS512),
            &claims,
            &EncodingKey::from_secret(SECRET.as_bytes()),
        )
        .map_err(|_| OAuthError::invalid_token_response("access token generation failed"))?,
        expires_in: TTL_SECONDS,
    };

    request.add_credential_access_token(access_token);
    Ok(request)
}

pub fn validate<T: Validate>(mut request: T) -> Result<T, OAuthError> {
    let access_token = request
        .request_access_token()
        .ok_or_else(|| OAuthError::invalid_access_token("bearer access token is required"))?;
    let validation = Validation::new(Algorithm::HS512);
    let claims = decode::<CredentialAccessTokenClaims>(
        access_token,
        &DecodingKey::from_secret(SECRET.as_bytes()),
        &validation,
    )
    .map_err(|_| OAuthError::invalid_access_token("bearer access token is invalid or expired"))?
    .claims;

    if claims.iat > get_current_timestamp() || claims.exp <= claims.iat {
        return Err(OAuthError::invalid_access_token(
            "bearer access token is invalid or expired",
        ));
    }

    request.add_credential_access_token_claims(claims);
    Ok(request)
}
