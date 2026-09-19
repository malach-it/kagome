use jsonwebtoken::{
    Validation, decode, decode_header,
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
    pub iss: String,
    pub sub: String,
    pub aud: String,
    pub client_id: String,
    pub username: String,
    pub profile: ResourceOwnerProfile,
    pub iat: u64,
    pub exp: u64,
}

#[derive(Debug, Deserialize)]
struct ValidatedIdTokenClaims {
    iss: Option<String>,
    sub: Option<String>,
    aud: Option<String>,
    client_id: String,
    username: String,
    profile: ResourceOwnerProfile,
    iat: Option<u64>,
    exp: Option<u64>,
}

pub trait Validate {
    fn request_id_token(&self) -> Option<&str>;
    fn validated_client_id(&self) -> Option<&str>;
    fn add_id_token(&mut self, id_token: &str);
    fn add_id_token_subject(&mut self, _subject: &str) {}
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
        .ok_or_else(OAuthError::missing_client_id)?
        .to_owned();
    let username = request
        .username()
        .ok_or_else(OAuthError::unauthenticated)?
        .to_owned();
    let profile = request
        .resource_owner_profile()
        .cloned()
        .unwrap_or_else(|| ResourceOwner::from_username(username.clone()).profile);
    let iat = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| OAuthError::invalid_token_response("id_token generation failed"))?
        .as_secs();
    let exp = iat
        .checked_add(Config::token_ttls().id_token_ttl)
        .ok_or_else(|| OAuthError::invalid_token_response("ID token lifetime is too large"))?;
    let payload = IdTokenJwtPayload {
        iss: Config::global().server.issuer.clone(),
        sub: username.clone(),
        aud: client_id.clone(),
        client_id,
        username,
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

/// Verifies a Kagome-issued, client-bound ID token and records its encoded value and subject.
///
/// Requires the configured ID-token algorithm, key identifier and signing key, standard issuer,
/// subject and audience claims, and coherent issuance/expiration times. Successful validation
/// stores the original encoded token.
///
/// # Errors
///
/// Returns `missing_id_token` when absent and `invalid_id_token` for missing validation context,
/// malformed or untrusted tokens, claim mismatches, expiration, or invalid time relationships.
pub fn validate<T: Validate>(mut token_request: T) -> Result<T, OAuthError> {
    let id_token = token_request
        .request_id_token()
        .map(str::to_owned)
        .ok_or_else(OAuthError::missing_id_token)?;

    let client_id = token_request
        .validated_client_id()
        .ok_or_else(OAuthError::missing_client_id)?;
    let payload = validate_jwt(&id_token, client_id)?;

    token_request.add_id_token(&id_token);
    token_request.add_id_token_subject(&payload.sub);
    Ok(token_request)
}

fn validate_jwt(id_token: &str, client_id: &str) -> Result<IdTokenJwtPayload, OAuthError> {
    let header = decode_header(id_token).map_err(|_| invalid_id_token("id_token must be a jwt"))?;
    if header.alg != SigningArtifact::IdToken.algorithm() {
        return Err(invalid_id_token("id_token algorithm is invalid"));
    }
    if header.kid.as_deref() != Some(SigningArtifact::IdToken.key_id()) {
        return Err(invalid_id_token("id_token signing key is invalid"));
    }
    if header.jwk.is_some() {
        return Err(invalid_id_token("id_token header must not include jwk"));
    }
    let decoding_key = SigningArtifact::IdToken
        .decoding_key()
        .map_err(|_| invalid_id_token("id_token signing key is invalid"))?;
    let mut validation = Validation::new(SigningArtifact::IdToken.algorithm());
    validation.set_required_spec_claims(&["exp", "iss", "sub", "aud"]);
    validation.set_issuer(&[Config::global().server.issuer.as_str()]);
    validation.set_audience(&[client_id]);

    let token_data = decode::<ValidatedIdTokenClaims>(id_token, &decoding_key, &validation)
        .map_err(invalid_decode_error)?;
    let now = get_current_timestamp();
    let claims = token_data.claims;
    let iat = claims
        .iat
        .ok_or_else(|| invalid_id_token("id_token iat is required"))?;
    let exp = claims
        .exp
        .ok_or_else(|| invalid_id_token("id_token exp is required"))?;
    let iss = claims
        .iss
        .ok_or_else(|| invalid_id_token("id_token iss is required"))?;
    let sub = claims
        .sub
        .ok_or_else(|| invalid_id_token("id_token sub is required"))?;
    let aud = claims
        .aud
        .ok_or_else(|| invalid_id_token("id_token aud is required"))?;

    if iat > now + validation.leeway {
        return Err(invalid_id_token("id_token iat must not be in the future"));
    }

    if exp <= iat {
        return Err(invalid_id_token("id_token exp must be after iat"));
    }

    if sub != claims.username {
        return Err(invalid_id_token("id_token subject is invalid"));
    }
    if claims.client_id != client_id {
        return Err(invalid_id_token("id_token client_id is invalid"));
    }
    Ok(IdTokenJwtPayload {
        iss,
        sub,
        aud,
        client_id: claims.client_id,
        username: claims.username,
        profile: claims.profile,
        iat,
        exp,
    })
}

fn invalid_decode_error(error: JwtError) -> OAuthError {
    match error.kind() {
        ErrorKind::InvalidSignature => invalid_id_token("id_token signature is invalid"),
        ErrorKind::ExpiredSignature => invalid_id_token("id_token is expired"),
        ErrorKind::MissingRequiredClaim(claim) => {
            invalid_id_token(&format!("id_token {claim} is required"))
        }
        ErrorKind::InvalidIssuer => invalid_id_token("id_token issuer is invalid"),
        ErrorKind::InvalidAudience => invalid_id_token("id_token audience is invalid"),
        ErrorKind::InvalidAlgorithm => invalid_id_token("id_token algorithm is invalid"),
        _ => invalid_id_token("id_token claims are invalid"),
    }
}

fn invalid_id_token(error_description: &str) -> OAuthError {
    OAuthError::invalid_id_token(error_description)
}
