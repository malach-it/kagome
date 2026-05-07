use jsonwebtoken::{
    Algorithm, DecodingKey, EncodingKey, Header, Validation, decode, encode,
    errors::{Error as JwtError, ErrorKind},
    get_current_timestamp,
};
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::{errors::OAuthError, unit::KagomeRequest};

pub const SECRET: &str = "static_authorization_code_secret";
pub const AUTHORIZATION_CODE_TTL_SECONDS: u64 = 600;

#[derive(Debug)]
pub struct AuthorizationCode {
    pub value: String,
    pub expires_in: u64,
    pub previous_code: Option<String>,
    pub payload: AuthorizationCodeJwtPayload,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AuthorizationCodeJwtPayload {
    pub client_id: String,
    pub id_token: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub previous_code: Option<String>,
    pub iat: u64,
    pub exp: u64,
}

pub trait TokenResponseAuthorizationCode {
    fn add_authorization_code(&mut self, authorization_code: AuthorizationCode);
}

pub fn validate<T>(token_response: T, request: &KagomeRequest) -> Result<T, OAuthError> {
    let Some(authorization_code) = request.authorization_code.as_deref() else {
        return Ok(token_response);
    };

    let payload = validate_jwt(authorization_code)?;

    if let Some(client_id) = request.client_id.as_deref()
        && payload.client_id != client_id
    {
        return Err(invalid_authorization_code(
            "authorization_code client_id does not match request",
        ));
    }

    Ok(token_response)
}

pub fn generate<T: TokenResponseAuthorizationCode>(
    mut token_response: T,
    request: &KagomeRequest,
) -> Result<T, OAuthError> {
    let client_id = request
        .client_id
        .as_deref()
        .ok_or_else(OAuthError::missing_client_id)?;
    let id_token = request
        .id_token
        .as_deref()
        .ok_or_else(OAuthError::missing_id_token)?;
    let iat = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| OAuthError::invalid_token_response("authorization code generation failed"))?
        .as_secs();
    let exp = iat + AUTHORIZATION_CODE_TTL_SECONDS;
    let payload = AuthorizationCodeJwtPayload {
        client_id: client_id.to_owned(),
        id_token: id_token.to_owned(),
        previous_code: request.authorization_code.clone(),
        iat,
        exp,
    };
    let authorization_code = AuthorizationCode {
        value: encode(
            &Header::new(Algorithm::HS512),
            &payload,
            &EncodingKey::from_secret(SECRET.as_bytes()),
        )
        .map_err(|_| OAuthError::invalid_token_response("authorization code generation failed"))?,
        expires_in: exp - iat,
        previous_code: request.authorization_code.clone(),
        payload,
    };

    token_response.add_authorization_code(authorization_code);
    Ok(token_response)
}

fn validate_jwt(authorization_code: &str) -> Result<AuthorizationCodeJwtPayload, OAuthError> {
    let mut validation = Validation::new(Algorithm::HS512);
    validation.set_required_spec_claims(&["exp"]);
    validation.validate_aud = false;

    let token_data = decode::<AuthorizationCodeJwtPayload>(
        authorization_code,
        &DecodingKey::from_secret(SECRET.as_bytes()),
        &validation,
    )
    .map_err(invalid_decode_error)?;
    let now = get_current_timestamp();

    if token_data.claims.iat > now + validation.leeway {
        return Err(invalid_authorization_code(
            "authorization_code iat must not be in the future",
        ));
    }

    if token_data.claims.exp <= token_data.claims.iat {
        return Err(invalid_authorization_code(
            "authorization_code exp must be after iat",
        ));
    }

    Ok(token_data.claims)
}

fn invalid_decode_error(error: JwtError) -> OAuthError {
    match error.kind() {
        ErrorKind::InvalidToken => invalid_authorization_code("authorization_code must be a jwt"),
        ErrorKind::InvalidSignature => {
            invalid_authorization_code("authorization_code signature is invalid")
        }
        ErrorKind::ExpiredSignature => invalid_authorization_code("authorization_code is expired"),
        ErrorKind::MissingRequiredClaim(claim) if claim == "exp" => {
            invalid_authorization_code("authorization_code exp is required")
        }
        _ => invalid_authorization_code("authorization_code claims are invalid"),
    }
}

fn invalid_authorization_code(error_description: &str) -> OAuthError {
    OAuthError::invalid_authorization_code(error_description)
}
