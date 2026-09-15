use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::{
    config::{Config, DEFAULT_ACCESS_TOKEN_TTL_SECONDS},
    errors::OAuthError,
};

pub const SECRET: &str = "static_secret";
pub const ACCESS_TOKEN_TTL_SECONDS: u64 = DEFAULT_ACCESS_TOKEN_TTL_SECONDS;
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
    let payload = AccessTokenJwtPayload {
        token_type: TOKEN_TYPE.to_owned(),
        client_id,
        username,
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

    token_request.add_access_token(access_token);
    Ok(token_request)
}
