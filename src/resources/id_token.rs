use jsonwebtoken::{
    DecodingKey, Validation, decode, decode_header,
    errors::{Error as JwtError, ErrorKind},
    get_current_timestamp,
};
use serde::Deserialize;

use crate::errors::OAuthError;

pub trait Validate {
    fn request_id_token(&self) -> Option<&str>;
    fn add_id_token(&mut self, id_token: &str);
}

pub fn validate<T: Validate>(mut token_request: T) -> Result<T, OAuthError> {
    let id_token = token_request
        .request_id_token()
        .map(str::to_owned)
        .ok_or_else(OAuthError::missing_id_token)?;

    validate_jwt(&id_token)?;

    token_request.add_id_token(&id_token);
    Ok(token_request)
}

#[derive(Debug, Deserialize)]
struct IdTokenClaims {
    iat: Option<u64>,
    exp: Option<u64>,
}

fn validate_jwt(id_token: &str) -> Result<(), OAuthError> {
    let header = decode_header(id_token).map_err(|_| invalid_id_token("id_token must be a jwt"))?;
    let jwk = header
        .jwk
        .ok_or_else(|| invalid_id_token("id_token header must include jwk"))?;
    let decoding_key =
        DecodingKey::from_jwk(&jwk).map_err(|_| invalid_id_token("id_token jwk must be valid"))?;
    let mut validation = Validation::new(header.alg);
    validation.set_required_spec_claims(&["exp"]);
    validation.validate_aud = false;

    let token_data = decode::<IdTokenClaims>(id_token, &decoding_key, &validation)
        .map_err(invalid_decode_error)?;
    let now = get_current_timestamp();
    let iat = token_data
        .claims
        .iat
        .ok_or_else(|| invalid_id_token("id_token iat is required"))?;
    let exp = token_data
        .claims
        .exp
        .ok_or_else(|| invalid_id_token("id_token exp is required"))?;

    if iat > now + validation.leeway {
        return Err(invalid_id_token("id_token iat must not be in the future"));
    }

    if exp <= iat {
        return Err(invalid_id_token("id_token exp must be after iat"));
    }

    Ok(())
}

fn invalid_decode_error(error: JwtError) -> OAuthError {
    match error.kind() {
        ErrorKind::InvalidSignature => invalid_id_token("id_token signature is invalid"),
        ErrorKind::ExpiredSignature => invalid_id_token("id_token is expired"),
        ErrorKind::MissingRequiredClaim(claim) if claim == "exp" => {
            invalid_id_token("id_token exp is required")
        }
        _ => invalid_id_token("id_token claims are invalid"),
    }
}

fn invalid_id_token(error_description: &str) -> OAuthError {
    OAuthError::invalid_id_token(error_description)
}
