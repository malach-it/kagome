use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::{
    config::{Config, DEFAULT_ACCESS_TOKEN_TTL_SECONDS},
    errors::OAuthError,
    resources::crypto::{self, CoseEncrypt0Errors, EncryptedArtifact},
};

pub const ACCESS_TOKEN_TTL_SECONDS: u64 = DEFAULT_ACCESS_TOKEN_TTL_SECONDS;
pub const TOKEN_TYPE: &str = "bearer";
const COSE_ENCRYPT0_ERRORS: CoseEncrypt0Errors = CoseEncrypt0Errors {
    invalid_cose: "access token must be a cose_encrypt0",
    missing_ciphertext: "access token ciphertext is required",
    missing_nonce: "access token nonce is required",
    decryption_failed: "access token decryption failed",
};

#[derive(Debug)]
pub struct AccessToken {
    pub value: String,
    pub expires_in: u64,
    pub payload: AccessTokenClaims,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AccessTokenClaims {
    pub token_type: String,
    pub client_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    pub iat: u64,
    pub exp: u64,
}

pub trait Generate {
    fn client_id(&self) -> Option<&str>;
    fn add_access_token(&mut self, access_token: AccessToken);

    fn username(&self) -> Option<&str> {
        None
    }
}

pub fn generate<T: Generate>(mut token_request: T) -> Result<T, OAuthError> {
    let client_id = token_request
        .client_id()
        .ok_or_else(OAuthError::missing_client_id)?
        .to_owned();
    let username = token_request.username().map(str::to_owned);
    let iat = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| OAuthError::invalid_token_response("access token generation failed"))?
        .as_secs();
    let exp = iat
        .checked_add(Config::token_ttls().access_token_ttl)
        .ok_or_else(|| OAuthError::invalid_token_response("access token lifetime is too large"))?;
    let payload = AccessTokenClaims {
        token_type: TOKEN_TYPE.to_owned(),
        client_id,
        username,
        iat,
        exp,
    };
    let mut plaintext = Vec::new();
    ciborium::into_writer(&payload, &mut plaintext)
        .map_err(|_| OAuthError::invalid_token_response("access token generation failed"))?;
    let access_token = AccessToken {
        value: crypto::encode_cose_encrypt0(&plaintext, EncryptedArtifact::AccessToken)
            .map_err(|_| OAuthError::invalid_token_response("access token generation failed"))?,
        expires_in: exp - iat,
        payload,
    };

    token_request.add_access_token(access_token);
    Ok(token_request)
}

pub fn decode_cose_payload(access_token: &str) -> Result<AccessTokenClaims, OAuthError> {
    let plaintext = crypto::decode_cose_encrypt0(
        access_token,
        EncryptedArtifact::AccessToken,
        COSE_ENCRYPT0_ERRORS,
    )
    .map_err(|_| OAuthError::invalid_access_token("access token is invalid or expired"))?;

    ciborium::from_reader(plaintext.as_slice())
        .map_err(|_| OAuthError::invalid_access_token("access token is invalid or expired"))
}
