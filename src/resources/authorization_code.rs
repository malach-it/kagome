use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::{
    config::{Config, DEFAULT_AUTHORIZATION_CODE_TTL_SECONDS},
    errors::OAuthError,
    resources::{
        crypto,
        crypto::EncryptedArtifact,
        pkce::CodeChallenge,
        replay::{self, Artifact, ConsumeError},
    },
};

pub const AUTHORIZATION_CODE_TTL_SECONDS: u64 = DEFAULT_AUTHORIZATION_CODE_TTL_SECONDS;
pub const MAX_AUTHORIZATION_CODE_BYTES: usize = 128 * 1024;
pub const MAX_AUTHORIZATION_CODE_PAYLOAD_BYTES: usize = 64 * 1024;
const COSE_ENCRYPT0_ERRORS: crypto::CoseEncrypt0Errors = crypto::CoseEncrypt0Errors {
    invalid_cose: "authorization_code must be a cose_encrypt0",
    missing_ciphertext: "authorization_code ciphertext is required",
    missing_nonce: "authorization_code nonce is required",
    decryption_failed: "authorization_code decryption failed",
};

#[derive(Debug)]
pub struct AuthorizationCode {
    pub value: String,
    pub expires_in: u64,
    pub payload: AuthorizationCodeCosePayload,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AuthorizationCodeCosePayload {
    pub client_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id_token: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id_token_public_jwk: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub previous_code: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub code_challenge: Option<CodeChallenge>,
    pub iat: u64,
    pub exp: u64,
}

pub trait Generate {
    fn previous_authorization_code(&self) -> Option<&str>;
    fn client_id(&self) -> Option<&str>;
    fn id_token(&self) -> Option<&str>;
    fn add_authorization_code(&mut self, authorization_code: AuthorizationCode);

    fn code_challenge(&self) -> Option<&CodeChallenge> {
        None
    }

    fn id_token_public_jwk(&self) -> Option<&Value> {
        None
    }

    fn username(&self) -> Option<&str> {
        None
    }

    fn require_username(&self) -> bool {
        false
    }

    fn require_id_token(&self) -> bool {
        true
    }
}

pub trait Validate {
    fn request_authorization_code(&self) -> Option<&str>;
    fn client_id(&self) -> Option<&str>;
    fn validate_client_id(&self) -> bool {
        true
    }
    fn add_authorization_code(&mut self, authorization_code: &str);
    fn add_authorization_code_subject(&mut self, _subject: Option<&str>) {}
}

pub trait Consume {
    fn validated_authorization_code(&self) -> Option<&str>;
    fn validated_client_id(&self) -> Option<&str>;
}

/// Requires a valid authorization code chain and records the code and optional authenticated
/// subject as validated state.
///
/// Validation authenticates every nested code and enforces encoded/plaintext size, lifetime,
/// configured chain depth, and optional client binding.
///
/// # Errors
///
/// Returns an OAuth error when the code is absent or any code or claim in its chain is invalid.
pub fn validate<T: Validate>(mut request: T) -> Result<T, OAuthError> {
    let authorization_code = request
        .request_authorization_code()
        .map(str::to_owned)
        .ok_or_else(OAuthError::missing_authorization_code)?;

    let claims = validate_request_authorization_code(
        &authorization_code,
        request
            .validate_client_id()
            .then(|| request.client_id())
            .flatten(),
    )?;

    request.add_authorization_code(&authorization_code);
    request.add_authorization_code_subject(claims.username.as_deref());
    Ok(request)
}

/// Validates and records an authorization code and optional authenticated subject when present,
/// otherwise leaves the request unchanged.
///
/// Present values receive the same chain, lifetime, size, depth, and client checks as [`validate`].
///
/// # Errors
///
/// Returns an OAuth error only when a supplied code is invalid.
pub fn validate_optional<T: Validate>(mut request: T) -> Result<T, OAuthError> {
    let Some(authorization_code) = request.request_authorization_code().map(str::to_owned) else {
        return Ok(request);
    };

    let claims = validate_request_authorization_code(
        &authorization_code,
        request
            .validate_client_id()
            .then(|| request.client_id())
            .flatten(),
    )?;

    request.add_authorization_code(&authorization_code);
    request.add_authorization_code_subject(claims.username.as_deref());
    Ok(request)
}

/// Atomically consumes a validated authorization code so it cannot be exchanged again.
///
/// The code and client binding are revalidated before a domain-separated digest is inserted into
/// the process-local replay store. Call this only after all exchange checks, including PKCE, have
/// succeeded so invalid requests cannot burn a valid code.
///
/// # Errors
///
/// Returns `invalid_token_response` when prerequisite state or replay storage is unavailable, and
/// `invalid_grant` when the code is invalid, expired, client-mismatched, or already consumed.
pub fn consume<T: Consume>(request: T) -> Result<T, OAuthError> {
    let authorization_code = request.validated_authorization_code().ok_or_else(|| {
        OAuthError::invalid_token_response(
            "authorization_code must be validated before consumption",
        )
    })?;
    let client_id = request.validated_client_id().ok_or_else(|| {
        OAuthError::invalid_token_response("client_id must be validated before code consumption")
    })?;
    let claims = validate_request_authorization_code(authorization_code, Some(client_id))?;

    replay::consume(Artifact::AuthorizationCode, authorization_code, claims.exp).map_err(
        |error| match error {
            ConsumeError::AlreadyConsumed => {
                invalid_authorization_code("authorization_code has already been used")
            }
            ConsumeError::CapacityExceeded
            | ConsumeError::StorageUnavailable
            | ConsumeError::TimeUnavailable => {
                OAuthError::invalid_token_response("authorization code replay storage failed")
            }
        },
    )?;

    Ok(request)
}

/// Atomically consumes a validated authorization code when one was supplied.
///
/// Requests without an authorization code pass through unchanged. Present codes must first have
/// been validated with [`validate_optional`].
///
/// # Errors
///
/// Returns the same errors as [`consume`] when a validated authorization code is present.
pub fn consume_optional<T: Consume>(request: T) -> Result<T, OAuthError> {
    if request.validated_authorization_code().is_none() {
        return Ok(request);
    }

    consume(request)
}

/// Generates an expiring encrypted code carrying identity, PKCE, wallet, and continuation state.
///
/// Required identity fields are controlled by [`Generate::require_id_token`] and
/// [`Generate::require_username`]. A previous code is authenticated before it is linked, and the
/// new code is added to the request.
///
/// # Errors
///
/// Returns an OAuth error for missing required state, an excessive chain, invalid time/lifetime,
/// oversized claims, serialization failure, or encryption failure.
pub fn generate<T: Generate>(mut request: T) -> Result<T, OAuthError> {
    let client_id = request
        .client_id()
        .ok_or_else(OAuthError::missing_client_id)?;
    let id_token = match (request.id_token(), request.require_id_token()) {
        (Some(id_token), _) => Some(id_token.to_owned()),
        (None, true) => return Err(OAuthError::missing_id_token()),
        (None, false) => None,
    };
    let username = match (request.username(), request.require_username()) {
        (Some(username), _) => Some(username.to_owned()),
        (None, true) => return Err(OAuthError::unauthenticated()),
        (None, false) => None,
    };
    let id_token_public_jwk = request.id_token_public_jwk().cloned();
    let previous_code = request.previous_authorization_code().map(str::to_owned);
    if let Some(previous_code) = previous_code.as_deref()
        && validated_code_chain(previous_code, Some(client_id))?.len()
            >= Config::token_ttls().authorization_code_chain_max_depth
    {
        return Err(invalid_authorization_code(
            "authorization_code chain exceeds maximum depth",
        ));
    }
    let code_challenge = request.code_challenge().cloned();
    let iat = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| OAuthError::invalid_token_response("authorization code generation failed"))?
        .as_secs();
    let exp = iat
        .checked_add(Config::token_ttls().authorization_code_ttl)
        .ok_or_else(|| {
            OAuthError::invalid_token_response("authorization code lifetime is too large")
        })?;
    let payload = AuthorizationCodeCosePayload {
        client_id: client_id.to_owned(),
        id_token,
        id_token_public_jwk,
        username,
        previous_code,
        code_challenge,
        iat,
        exp,
    };
    let authorization_code = AuthorizationCode {
        value: encode_cose_encrypt0(&payload)?,
        expires_in: exp - iat,
        payload,
    };

    request.add_authorization_code(authorization_code);
    Ok(request)
}

fn validate_request_authorization_code(
    authorization_code: &str,
    client_id: Option<&str>,
) -> Result<AuthorizationCodeCosePayload, OAuthError> {
    validated_code_chain(authorization_code, client_id)?
        .into_iter()
        .next()
        .ok_or_else(|| invalid_authorization_code("authorization_code claims are invalid"))
}

fn validate_single_authorization_code(
    authorization_code: &str,
    client_id: Option<&str>,
) -> Result<AuthorizationCodeCosePayload, OAuthError> {
    let payload = validate_cose_encrypt0(authorization_code)?;

    if let Some(client_id) = client_id
        && payload.client_id != client_id
    {
        return Err(invalid_authorization_code(
            "authorization_code client_id does not match request",
        ));
    }

    Ok(payload)
}

fn validated_code_chain(
    authorization_code: &str,
    client_id: Option<&str>,
) -> Result<Vec<AuthorizationCodeCosePayload>, OAuthError> {
    let maximum_depth = Config::token_ttls().authorization_code_chain_max_depth;
    let mut current_code = Some(authorization_code.to_owned());
    let mut payloads = Vec::with_capacity(maximum_depth);

    while let Some(code) = current_code {
        if payloads.len() >= maximum_depth {
            return Err(invalid_authorization_code(
                "authorization_code chain exceeds maximum depth",
            ));
        }

        let payload = validate_single_authorization_code(&code, client_id)?;
        current_code = payload.previous_code.clone();
        payloads.push(payload);
    }

    Ok(payloads)
}

fn encode_cose_encrypt0(payload: &AuthorizationCodeCosePayload) -> Result<String, OAuthError> {
    let mut payload_bytes = Vec::new();
    ciborium::into_writer(payload, &mut payload_bytes)
        .map_err(|_| OAuthError::invalid_token_response("authorization code generation failed"))?;
    if payload_bytes.len() > MAX_AUTHORIZATION_CODE_PAYLOAD_BYTES {
        return Err(OAuthError::invalid_token_response(
            "authorization code payload is too large",
        ));
    }

    crypto::encode_cose_encrypt0(&payload_bytes, EncryptedArtifact::AuthorizationCode).map_err(
        |error| {
            if error.error == "invalid_token_response" {
                OAuthError::invalid_token_response("authorization code generation failed")
            } else {
                error
            }
        },
    )
}

/// Authenticates and decodes one code payload without validating time, client, or nested-chain rules.
///
/// # Errors
///
/// Returns `invalid_grant` when encoded/plaintext limits, COSE authentication, or CBOR decoding
/// fail.
pub fn decode_cose_payload(
    authorization_code: &str,
) -> Result<AuthorizationCodeCosePayload, OAuthError> {
    let payload = decode_cose_encrypt0(authorization_code)?;

    ciborium::from_reader(payload.as_slice())
        .map_err(|_| invalid_authorization_code("authorization_code claims are invalid"))
}

/// Validates a client-bound code chain and returns its explicit wallet-binding public key, if any.
///
/// ID-token signing keys represent issuer identity and are never reused as holder proof keys.
///
/// # Errors
///
/// Returns an OAuth error when the code chain or client binding is invalid.
pub fn validated_id_token_public_jwk(
    authorization_code: &str,
    client_id: &str,
) -> Result<Option<serde_json::Value>, OAuthError> {
    let payload = validate_request_authorization_code(authorization_code, Some(client_id))?;
    Ok(payload.id_token_public_jwk)
}

/// Validates a code chain and returns its authenticated usernames in oldest-to-newest order.
///
/// Absence of a code produces an empty list.
///
/// # Errors
///
/// Returns an OAuth error when the code chain or optional client binding is invalid.
pub fn chain_usernames(
    authorization_code: Option<&str>,
    client_id: Option<&str>,
) -> Result<Vec<String>, OAuthError> {
    let Some(authorization_code) = authorization_code else {
        return Ok(Vec::new());
    };

    Ok(validated_code_chain(authorization_code, client_id)?
        .into_iter()
        .rev()
        .filter_map(|payload| payload.username)
        .collect())
}

fn validate_cose_encrypt0(
    authorization_code: &str,
) -> Result<AuthorizationCodeCosePayload, OAuthError> {
    let payload = decode_cose_encrypt0(authorization_code)?;
    let payload: AuthorizationCodeCosePayload = ciborium::from_reader(payload.as_slice())
        .map_err(|_| invalid_authorization_code("authorization_code claims are invalid"))?;
    let now = current_timestamp()?;

    if payload.iat > now {
        return Err(invalid_authorization_code(
            "authorization_code iat must not be in the future",
        ));
    }

    if payload.exp <= payload.iat {
        return Err(invalid_authorization_code(
            "authorization_code exp must be after iat",
        ));
    }

    if payload.exp <= now {
        return Err(invalid_authorization_code("authorization_code is expired"));
    }

    Ok(payload)
}

fn decode_cose_encrypt0(authorization_code: &str) -> Result<Vec<u8>, OAuthError> {
    if authorization_code.len() > MAX_AUTHORIZATION_CODE_BYTES {
        return Err(invalid_authorization_code(
            "authorization_code is too large",
        ));
    }

    let payload = crypto::decode_cose_encrypt0(
        authorization_code,
        EncryptedArtifact::AuthorizationCode,
        COSE_ENCRYPT0_ERRORS,
    )?;
    if payload.len() > MAX_AUTHORIZATION_CODE_PAYLOAD_BYTES {
        return Err(invalid_authorization_code(
            "authorization_code payload is too large",
        ));
    }

    Ok(payload)
}

fn current_timestamp() -> Result<u64, OAuthError> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| OAuthError::invalid_token_response("authorization code validation failed"))?
        .as_secs())
}

fn invalid_authorization_code(error_description: &str) -> OAuthError {
    OAuthError::invalid_authorization_code(error_description)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_decrypted_payload_larger_than_the_cbor_limit() {
        let payload = vec![0; MAX_AUTHORIZATION_CODE_PAYLOAD_BYTES + 1];
        let authorization_code =
            crypto::encode_cose_encrypt0(&payload, EncryptedArtifact::AuthorizationCode).unwrap();

        let error = decode_cose_encrypt0(&authorization_code).unwrap_err();

        assert_eq!(error.error, "invalid_grant");
        assert_eq!(
            error.error_description,
            "authorization_code payload is too large"
        );
    }
}
