use jsonwebtoken::{
    AlgorithmFamily, DecodingKey, Validation, decode, decode_header,
    errors::{Error as JwtError, ErrorKind},
    get_current_timestamp,
};
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::{
    config::{Config, DEFAULT_ID_TOKEN_TTL_SECONDS},
    errors::OAuthError,
    resources::{
        crypto::{self, SigningArtifact},
        resource_owner::{ResourceOwner, ResourceOwnerProfile},
    },
};

pub const ID_TOKEN_TTL_SECONDS: u64 = DEFAULT_ID_TOKEN_TTL_SECONDS;

#[derive(Debug)]
pub struct IdToken {
    pub value: String,
    pub expires_in: u64,
    pub payload: IdTokenJwtPayload,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct IdTokenJwtPayload {
    pub client_id: String,
    pub username: String,
    pub profile: ResourceOwnerProfile,
    pub iat: u64,
    pub exp: u64,
}

pub trait Validate {
    fn request_id_token(&self) -> Option<&str>;
    fn add_id_token(&mut self, id_token: &str);
}

pub trait Generate {
    fn client_id(&self) -> Option<&str>;
    fn username(&self) -> Option<&str>;
    fn resource_owner_profile(&self) -> Option<&ResourceOwnerProfile> {
        None
    }
    fn add_generated_id_token(&mut self, id_token: IdToken);
}

/// Signs an ID token for the authenticated resource owner and selected profile.
///
/// Requires client and username state. It uses the accumulated resource-owner profile when
/// available, otherwise creates the minimal username profile, then stores the signed token and
/// configured lifetime.
///
/// # Errors
///
/// Returns an OAuth error for missing client or authenticated owner state, invalid system time or
/// lifetime, or signing failure.
pub fn generate<T: Generate>(mut request: T) -> Result<T, OAuthError> {
    let client_id = request
        .client_id()
        .ok_or_else(OAuthError::missing_client_id)?;
    let username = request.username().ok_or_else(OAuthError::unauthenticated)?;
    let profile = request
        .resource_owner_profile()
        .cloned()
        .unwrap_or_else(|| ResourceOwner::from_username(username.to_owned()).profile);
    let iat = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| OAuthError::invalid_token_response("id_token generation failed"))?
        .as_secs();
    let exp = iat
        .checked_add(Config::token_ttls().id_token_ttl)
        .ok_or_else(|| OAuthError::invalid_token_response("ID token lifetime is too large"))?;
    let payload = IdTokenJwtPayload {
        client_id: client_id.to_owned(),
        username: username.to_owned(),
        profile,
        iat,
        exp,
    };
    let id_token = IdToken {
        value: crypto::sign_jwt(&payload, SigningArtifact::IdToken)
            .map_err(|_| OAuthError::invalid_token_response("id_token generation failed"))?,
        expires_in: exp - iat,
        payload,
    };

    request.add_generated_id_token(id_token);
    Ok(request)
}

/// Verifies an asymmetric, JWK-bearing ID token and records its encoded value.
///
/// Requires a JWT with an embedded non-HMAC public JWK, valid signature, required expiration, and
/// coherent issuance time. Successful validation stores the original encoded token.
///
/// # Errors
///
/// Returns `missing_id_token` when absent and `invalid_id_token` for malformed, symmetric,
/// unsigned, expired, future-issued, or otherwise invalid tokens.
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

/// Verifies an ID token and returns its trusted embedded public JWK.
///
/// The returned JSON key has passed the same signature, algorithm, issuance-time, and expiration
/// checks as [`validate`].
///
/// # Errors
///
/// Returns `invalid_id_token` when token validation or JWK serialization fails.
pub fn validated_public_jwk(id_token: &str) -> Result<serde_json::Value, OAuthError> {
    let jwk = validate_jwt(id_token)?;
    serde_json::to_value(jwk).map_err(|_| invalid_id_token("id_token jwk must be valid"))
}

fn validate_jwt(id_token: &str) -> Result<jsonwebtoken::jwk::Jwk, OAuthError> {
    let header = decode_header(id_token).map_err(|_| invalid_id_token("id_token must be a jwt"))?;
    if header.alg.family() == AlgorithmFamily::Hmac {
        return Err(invalid_id_token("id_token algorithm must be asymmetric"));
    }
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

    Ok(jwk)
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
