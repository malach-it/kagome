use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use jsonwebtoken::{
    Algorithm, DecodingKey, Validation, decode, decode_header, get_current_timestamp,
};
use p256::elliptic_curve::sec1::ToEncodedPoint;
use ring::digest;
use serde::Deserialize;
use serde_json::{Value, json};

use crate::errors::OAuthError;

use super::{siopv2_request, siopv2_state::SiopStateClaims};

pub const SUPPORTED_WALLET_ERRORS: &[&str] = &[
    "access_denied",
    "invalid_request",
    "login_required",
    "user_cancelled",
];

const JWK_THUMBPRINT_PREFIX: &str = "urn:ietf:params:oauth:jwk-thumbprint:sha-256:";
const P256_PUB_MULTICODEC_PREFIX: &[u8] = &[0x80, 0x24];
const JWK_JCS_PUB_MULTICODEC_PREFIX: &[u8] = &[0xd1, 0xd6, 0x03];

#[derive(Debug)]
pub struct ValidatedSelfIssuedIdToken {
    pub subject: String,
    pub public_jwk: Value,
}

#[derive(Debug)]
pub struct ValidatedWalletError {
    pub error: String,
    pub error_description: Option<String>,
}

#[derive(Debug, Deserialize)]
struct SelfIssuedClaims {
    iss: String,
    sub: String,
    aud: Value,
    nonce: String,
    iat: u64,
    exp: u64,
    #[serde(default)]
    sub_jwk: Option<Value>,
}

pub trait ValidateEncoding {
    fn request_content_type(&self) -> Option<&str>;
}

pub trait ValidateWalletError {
    fn request_wallet_error(&self) -> Option<&str>;
    fn request_wallet_error_description(&self) -> Option<&str>;
    fn request_id_token(&self) -> Option<&str>;
    fn add_wallet_error(&mut self, error: ValidatedWalletError);
}

pub trait Validate {
    fn request_id_token(&self) -> Option<&str>;
    fn request_state(&self) -> Option<&str>;
    fn state_claims(&self) -> Option<&SiopStateClaims>;
    fn add_validated_id_token(&mut self, id_token: ValidatedSelfIssuedIdToken);
}

/// Requires a form URL-encoded SIOPv2 direct-post response.
///
/// Parameters on the media type are accepted and its name is compared case-insensitively. This
/// action validates the HTTP representation without changing request state.
///
/// # Errors
///
/// Returns `invalid_request` when `Content-Type` is absent or is not
/// `application/x-www-form-urlencoded`.
pub fn validate_encoding<T: ValidateEncoding>(request: T) -> Result<T, OAuthError> {
    let media_type = request
        .request_content_type()
        .and_then(|content_type| content_type.split(';').next())
        .map(str::trim);

    if !media_type.is_some_and(|media_type| {
        media_type.eq_ignore_ascii_case("application/x-www-form-urlencoded")
    }) {
        return Err(invalid(
            "siop response content-type must be application/x-www-form-urlencoded",
        ));
    }

    Ok(request)
}

/// Validates an allowlisted negative wallet response that contains no ID token.
///
/// A supported wallet error may carry an optional description but cannot be mixed with a success
/// ID token. The validated error is added to response state for downstream redirection.
///
/// # Errors
///
/// Returns `invalid_request` when the error is missing, unsupported, or accompanied by an ID
/// token.
pub fn validate_wallet_error<T: ValidateWalletError>(mut request: T) -> Result<T, OAuthError> {
    let error = request
        .request_wallet_error()
        .ok_or_else(|| invalid("wallet error is required"))?;

    if request.request_id_token().is_some() {
        return Err(invalid("wallet error response must not include id_token"));
    }
    if !SUPPORTED_WALLET_ERRORS.contains(&error) {
        return Err(invalid("wallet error is unsupported"));
    }

    request.add_wallet_error(ValidatedWalletError {
        error: error.to_owned(),
        error_description: request
            .request_wallet_error_description()
            .map(str::to_owned),
    });
    Ok(request)
}

/// Verifies a self-issued ID token against restored SIOPv2 state and stores its wallet key.
///
/// Requires SIOPv2 state to be validated first. The token must use ES256 and a P-256 `did:key` or
/// thumbprint-bound `sub_jwk`; signature, issuer/subject, callback audience, nonce, issuance time,
/// and expiration are verified before the subject and public key are stored.
///
/// # Errors
///
/// Returns `invalid_request` for missing prerequisite fields or any malformed, unsupported,
/// untrusted, wrongly addressed, stale, or incorrectly bound self-issued token.
pub fn validate<T: Validate>(mut request: T) -> Result<T, OAuthError> {
    let token = request
        .request_id_token()
        .ok_or_else(|| invalid("id_token is required"))?;
    let state_value = request
        .request_state()
        .ok_or_else(|| invalid("state must be validated before id_token"))?;
    let state = request
        .state_claims()
        .ok_or_else(|| invalid("state must be validated before id_token"))?;
    let header = decode_header(token).map_err(|_| invalid("id_token must be a jwt"))?;

    if header.alg != Algorithm::ES256 {
        return Err(invalid("id_token algorithm must be ES256"));
    }

    let unverified_claims = decode_unverified_claims(token)?;
    let (key, public_jwk) = subject_key(&unverified_claims, header.kid.as_deref())?;
    let mut validation = Validation::new(Algorithm::ES256);
    validation.set_required_spec_claims(&["exp"]);
    validation.validate_aud = false;
    let claims = decode::<SelfIssuedClaims>(token, &key, &validation)
        .map_err(|_| invalid("id_token is invalid or expired"))?
        .claims;
    let expected_audience = siopv2_request::response_uri_with_state(&state.verifier, state_value);

    validate_claims(&claims, state, &expected_audience)?;
    request.add_validated_id_token(ValidatedSelfIssuedIdToken {
        subject: claims.sub,
        public_jwk,
    });
    Ok(request)
}

fn decode_unverified_claims(token: &str) -> Result<SelfIssuedClaims, OAuthError> {
    let mut segments = token.split('.');
    let _header = segments.next();
    let payload = segments
        .next()
        .ok_or_else(|| invalid("id_token must be a jwt"))?;
    if segments.next().is_none() || segments.next().is_some() {
        return Err(invalid("id_token must be a jwt"));
    }
    let payload = URL_SAFE_NO_PAD
        .decode(payload)
        .map_err(|_| invalid("id_token must be a jwt"))?;

    serde_json::from_slice(&payload).map_err(|_| invalid("id_token claims are invalid"))
}

fn subject_key(
    claims: &SelfIssuedClaims,
    key_id: Option<&str>,
) -> Result<(DecodingKey, Value), OAuthError> {
    if claims.sub.starts_with("did:key:") {
        if claims.sub_jwk.is_some() {
            return Err(invalid("did:key id_token must not include sub_jwk"));
        }
        if !key_id.is_some_and(|key_id| {
            key_id == claims.sub
                || key_id
                    .strip_prefix(&claims.sub)
                    .is_some_and(|v| v.starts_with('#'))
        }) {
            return Err(invalid("id_token kid must identify the subject key"));
        }

        let jwk = did_key_jwk(&claims.sub)?;
        let (x, y) = p256_jwk_coordinates(&jwk)
            .map_err(|_| invalid("id_token did:key contains an invalid P-256 key"))?;
        let key = DecodingKey::from_ec_components(&x, &y)
            .map_err(|_| invalid("id_token did:key contains an invalid P-256 key"))?;
        return Ok((key, jwk));
    }

    let jwk = claims
        .sub_jwk
        .as_ref()
        .ok_or_else(|| invalid("id_token must use did:key or include sub_jwk"))?;
    let (x, y) = p256_jwk_coordinates(jwk)?;
    let thumbprint = jwk_thumbprint(&x, &y);
    if claims.sub != format!("{JWK_THUMBPRINT_PREFIX}{thumbprint}") {
        return Err(invalid("id_token subject does not match sub_jwk"));
    }

    let key = DecodingKey::from_ec_components(&x, &y)
        .map_err(|_| invalid("id_token sub_jwk is invalid"))?;
    Ok((
        key,
        json!({
            "kty": "EC",
            "crv": "P-256",
            "x": x,
            "y": y
        }),
    ))
}

fn validate_claims(
    claims: &SelfIssuedClaims,
    state: &SiopStateClaims,
    expected_audience: &str,
) -> Result<(), OAuthError> {
    let now = get_current_timestamp();

    if claims.iss != claims.sub {
        return Err(invalid("id_token issuer must equal subject"));
    }
    if !audience_contains(&claims.aud, expected_audience) {
        return Err(invalid("id_token audience is invalid"));
    }
    if claims.nonce != state.nonce {
        return Err(invalid("id_token nonce is invalid"));
    }
    if claims.iat > now || claims.exp <= claims.iat {
        return Err(invalid("id_token time claims are invalid"));
    }

    Ok(())
}

fn audience_contains(audience: &Value, expected: &str) -> bool {
    audience.as_str() == Some(expected)
        || audience
            .as_array()
            .is_some_and(|values| values.iter().any(|value| value.as_str() == Some(expected)))
}

/// Decodes a canonical raw P-256 or JWK-JCS `did:key` subject into a public JWK.
///
/// Supports the P-256 public-key multicodec and canonical JWK-JCS public-key multicodec. The
/// returned JWK contains only the normalized public EC parameters.
///
/// # Errors
///
/// Returns `invalid_request` for invalid multibase/multicodec data, non-P-256 material,
/// non-canonical JWK-JCS, or invalid curve coordinates.
pub(crate) fn did_key_jwk(subject: &str) -> Result<Value, OAuthError> {
    let multibase = subject
        .strip_prefix("did:key:z")
        .ok_or_else(|| invalid("id_token did:key is invalid"))?;
    let decoded = decode_base58btc(multibase)?;
    if let Some(sec1) = decoded.strip_prefix(P256_PUB_MULTICODEC_PREFIX) {
        return p256_sec1_jwk(sec1);
    }
    if let Some(jwk) = decoded.strip_prefix(JWK_JCS_PUB_MULTICODEC_PREFIX) {
        return jwk_jcs_jwk(jwk);
    }

    Err(invalid("id_token did:key must contain a P-256 key"))
}

fn p256_sec1_jwk(sec1: &[u8]) -> Result<Value, OAuthError> {
    let public_key = p256::PublicKey::from_sec1_bytes(sec1)
        .map_err(|_| invalid("id_token did:key contains an invalid P-256 key"))?;
    let point = public_key.to_encoded_point(false);
    let x = point
        .x()
        .ok_or_else(|| invalid("id_token did:key contains an invalid P-256 key"))?;
    let y = point
        .y()
        .ok_or_else(|| invalid("id_token did:key contains an invalid P-256 key"))?;

    Ok(json!({
        "kty": "EC",
        "crv": "P-256",
        "x": URL_SAFE_NO_PAD.encode(x),
        "y": URL_SAFE_NO_PAD.encode(y)
    }))
}

fn jwk_jcs_jwk(encoded_jwk: &[u8]) -> Result<Value, OAuthError> {
    let jwk: Value = serde_json::from_slice(encoded_jwk)
        .map_err(|_| invalid("id_token did:key contains an invalid JWK-JCS key"))?;
    let (x, y) = p256_jwk_coordinates(&jwk)
        .map_err(|_| invalid("id_token did:key contains an invalid JWK-JCS key"))?;
    let canonical = format!(r#"{{"crv":"P-256","kty":"EC","x":"{x}","y":"{y}"}}"#);
    if encoded_jwk != canonical.as_bytes() {
        return Err(invalid(
            "id_token did:key contains a non-canonical JWK-JCS key",
        ));
    }

    let x_bytes = URL_SAFE_NO_PAD
        .decode(&x)
        .map_err(|_| invalid("id_token did:key contains an invalid JWK-JCS key"))?;
    let y_bytes = URL_SAFE_NO_PAD
        .decode(&y)
        .map_err(|_| invalid("id_token did:key contains an invalid JWK-JCS key"))?;
    if x_bytes.len() != 32 || y_bytes.len() != 32 {
        return Err(invalid("id_token did:key contains an invalid JWK-JCS key"));
    }
    let mut sec1 = Vec::with_capacity(65);
    sec1.push(0x04);
    sec1.extend(x_bytes);
    sec1.extend(y_bytes);
    p256::PublicKey::from_sec1_bytes(&sec1)
        .map_err(|_| invalid("id_token did:key contains an invalid JWK-JCS key"))?;

    Ok(jwk)
}

fn p256_jwk_coordinates(jwk: &Value) -> Result<(String, String), OAuthError> {
    if jwk.get("kty").and_then(Value::as_str) != Some("EC")
        || jwk.get("crv").and_then(Value::as_str) != Some("P-256")
    {
        return Err(invalid("id_token sub_jwk must be a P-256 key"));
    }
    let x = jwk
        .get("x")
        .and_then(Value::as_str)
        .ok_or_else(|| invalid("id_token sub_jwk is invalid"))?;
    let y = jwk
        .get("y")
        .and_then(Value::as_str)
        .ok_or_else(|| invalid("id_token sub_jwk is invalid"))?;
    if URL_SAFE_NO_PAD.decode(x).is_err() || URL_SAFE_NO_PAD.decode(y).is_err() {
        return Err(invalid("id_token sub_jwk is invalid"));
    }

    Ok((x.to_owned(), y.to_owned()))
}

fn jwk_thumbprint(x: &str, y: &str) -> String {
    let canonical = format!(r#"{{"crv":"P-256","kty":"EC","x":"{x}","y":"{y}"}}"#);
    URL_SAFE_NO_PAD.encode(digest::digest(&digest::SHA256, canonical.as_bytes()))
}

fn decode_base58btc(value: &str) -> Result<Vec<u8>, OAuthError> {
    if value.is_empty() {
        return Err(invalid("id_token did:key is invalid"));
    }
    let alphabet = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    let mut little_endian = vec![0_u8];

    for character in value.bytes() {
        let digit = alphabet
            .iter()
            .position(|candidate| *candidate == character)
            .ok_or_else(|| invalid("id_token did:key is invalid"))? as u32;
        let mut carry = digit;
        for byte in &mut little_endian {
            carry += u32::from(*byte) * 58;
            *byte = carry as u8;
            carry >>= 8;
        }
        while carry > 0 {
            little_endian.push(carry as u8);
            carry >>= 8;
        }
    }

    let leading_zeroes = value.bytes().take_while(|byte| *byte == b'1').count();
    let mut decoded = vec![0; leading_zeroes];
    decoded.extend(little_endian.into_iter().rev());
    Ok(decoded)
}

fn invalid(description: &str) -> OAuthError {
    OAuthError::invalid_request(description)
}
