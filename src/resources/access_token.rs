use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::{errors::OAuthError, unit::KagomeRequest};

pub const SECRET: &str = "static_secret";
pub const ACCESS_TOKEN_TTL_SECONDS: u64 = 3600;
pub const TOKEN_TYPE: &str = "bearer";

#[derive(Debug)]
pub struct AccessToken {
    pub value: String,
    pub expires_in: u64,
    pub payload: AccessTokenJwtPayload,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AccessTokenJwtPayload {
    pub token_type: String,
    pub client_id: String,
    pub iat: u64,
    pub exp: u64,
}

pub trait TokenResponseAccessToken {
    fn add_access_token(&mut self, access_token: AccessToken);
}

pub fn generate<T: TokenResponseAccessToken>(
    mut token_response: T,
    request: &KagomeRequest,
) -> Result<T, OAuthError> {
    let client_id = request
        .client_id
        .as_deref()
        .ok_or_else(OAuthError::missing_client_id)?;
    let iat = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| OAuthError::invalid_token_response("access token generation failed"))?
        .as_secs();
    let exp = iat + ACCESS_TOKEN_TTL_SECONDS;
    let payload = AccessTokenJwtPayload {
        token_type: TOKEN_TYPE.to_owned(),
        client_id: client_id.to_owned(),
        iat,
        exp,
    };
    let access_token = AccessToken {
        value: encode(
            &Header::new(Algorithm::HS512),
            &payload,
            &EncodingKey::from_secret(SECRET.as_bytes()),
        )
        .map_err(|_| OAuthError::invalid_token_response("access token generation failed"))?,
        expires_in: exp - iat,
        payload,
    };

    token_response.add_access_token(access_token);
    Ok(token_response)
}
