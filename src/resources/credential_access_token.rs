use std::time::{SystemTime, UNIX_EPOCH};

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use ring::rand::{SecureRandom, SystemRandom};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{
    errors::OAuthError,
    resources::{
        crypto::{self, CoseEncrypt0Errors, EncryptedArtifact},
        replay::{self, Artifact, ConsumeError},
        resource_owner::CredentialProfiles,
    },
};

pub const TTL_SECONDS: u64 = 3600;
const C_NONCE_BYTES: usize = 32;
const COSE_ENCRYPT0_ERRORS: CoseEncrypt0Errors = CoseEncrypt0Errors {
    invalid_cose: "credential access token must be a cose_encrypt0",
    missing_ciphertext: "credential access token ciphertext is required",
    missing_nonce: "credential access token nonce is required",
    decryption_failed: "credential access token decryption failed",
};

#[derive(Debug)]
pub struct CredentialAccessToken {
    pub value: String,
    pub expires_in: u64,
    pub c_nonce: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CredentialAccessTokenClaims {
    pub credential_configuration_ids: Vec<String>,
    pub subject: String,
    #[serde(default)]
    pub credential_profile: CredentialProfiles,
    pub id_token_public_jwk: Option<Value>,
    pub require_wallet_binding: bool,
    pub c_nonce: String,
    pub iat: u64,
    pub exp: u64,
}

pub trait Generate {
    fn credential_configuration_ids(&self) -> &[String];
    fn subject(&self) -> Option<&str>;
    fn credential_profile(&self) -> Option<&CredentialProfiles> {
        None
    }
    fn id_token_public_jwk(&self) -> Option<&Value> {
        None
    }
    fn require_wallet_binding(&self) -> bool {
        false
    }
    fn add_credential_access_token(&mut self, access_token: CredentialAccessToken);
}

pub trait Validate {
    fn request_access_token(&self) -> Option<&str>;
    fn add_credential_access_token_claims(&mut self, claims: CredentialAccessTokenClaims);
}

pub trait ConsumeNonce {
    fn credential_nonce(&self) -> Option<&str>;
    fn credential_nonce_expiration(&self) -> Option<u64>;
}

/// Issues an encrypted bearer token authorizing configured credentials for one subject.
///
/// Carries the authorized configuration IDs, credential-specific profile, optional wallet key,
/// binding policy, a fresh 256-bit credential nonce, and one-hour lifetime, then adds
/// [`CredentialAccessToken`] state. The same nonce is exposed in the token response and required
/// in any subsequent JWT issuance proof.
///
/// # Errors
///
/// Returns an OAuth error when configurations or subject are missing, time is unavailable, or
/// serialization/encryption fails.
pub fn generate<T: Generate>(mut request: T) -> Result<T, OAuthError> {
    let credential_configuration_ids = request.credential_configuration_ids();
    if credential_configuration_ids.is_empty() {
        return Err(OAuthError::invalid_token_response(
            "credential configuration is required",
        ));
    }
    let subject = request
        .subject()
        .ok_or_else(|| OAuthError::invalid_token_response("credential subject is required"))?;
    let iat = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| OAuthError::invalid_token_response("access token generation failed"))?
        .as_secs();
    let c_nonce = generate_c_nonce()?;
    let claims = CredentialAccessTokenClaims {
        credential_configuration_ids: credential_configuration_ids.to_owned(),
        subject: subject.to_owned(),
        credential_profile: request.credential_profile().cloned().unwrap_or_default(),
        id_token_public_jwk: request.id_token_public_jwk().cloned(),
        require_wallet_binding: request.require_wallet_binding(),
        c_nonce: c_nonce.clone(),
        iat,
        exp: iat + TTL_SECONDS,
    };
    let mut plaintext = Vec::new();
    ciborium::into_writer(&claims, &mut plaintext)
        .map_err(|_| OAuthError::invalid_token_response("access token generation failed"))?;
    let access_token = CredentialAccessToken {
        value: crypto::encode_cose_encrypt0(&plaintext, EncryptedArtifact::CredentialAccessToken)
            .map_err(|_| OAuthError::invalid_token_response("access token generation failed"))?,
        expires_in: TTL_SECONDS,
        c_nonce,
    };

    request.add_credential_access_token(access_token);
    Ok(request)
}

/// Authenticates a credential bearer token and stores its validated authorization claims.
///
/// Enforces artifact separation, CBOR structure, lifetime, public-JWK shape, and required binding
/// key consistency.
///
/// # Errors
///
/// Returns `invalid_token` when the bearer token is absent, invalid, expired, or internally
/// inconsistent.
pub fn validate<T: Validate>(mut request: T) -> Result<T, OAuthError> {
    let access_token = request
        .request_access_token()
        .ok_or_else(|| OAuthError::invalid_access_token("bearer access token is required"))?;
    let plaintext = crypto::decode_cose_encrypt0(
        access_token,
        EncryptedArtifact::CredentialAccessToken,
        COSE_ENCRYPT0_ERRORS,
    )
    .map_err(|_| OAuthError::invalid_access_token("bearer access token is invalid or expired"))?;
    let claims: CredentialAccessTokenClaims =
        ciborium::from_reader(plaintext.as_slice()).map_err(|_| {
            OAuthError::invalid_access_token("bearer access token is invalid or expired")
        })?;

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| OAuthError::invalid_access_token("bearer access token is invalid or expired"))?
        .as_secs();
    if claims.iat > now || claims.exp <= claims.iat || claims.exp <= now {
        return Err(OAuthError::invalid_access_token(
            "bearer access token is invalid or expired",
        ));
    }
    if claims
        .id_token_public_jwk
        .as_ref()
        .is_some_and(|jwk| !jwk.is_object())
        || claims.require_wallet_binding && claims.id_token_public_jwk.is_none()
        || !valid_c_nonce(&claims.c_nonce)
    {
        return Err(OAuthError::invalid_access_token(
            "bearer access token is invalid or expired",
        ));
    }

    request.add_credential_access_token_claims(claims);
    Ok(request)
}

/// Atomically consumes a validated credential nonce after its issuance proof succeeds.
///
/// The nonce is recorded as a domain-separated digest until the credential access token expires.
/// Calling this after proof validation prevents invalid requests from burning an outstanding nonce
/// while ensuring only one credential can be issued for it, including under concurrent requests.
///
/// # Errors
///
/// Returns `invalid_or_missing_proof` when the nonce was already consumed and
/// `invalid_token_response` when validated nonce state or replay storage is unavailable.
pub fn consume_nonce<T: ConsumeNonce>(request: T) -> Result<T, OAuthError> {
    let c_nonce = request.credential_nonce().ok_or_else(|| {
        OAuthError::invalid_token_response("credential nonce must be validated before consumption")
    })?;
    let expires_at = request.credential_nonce_expiration().ok_or_else(|| {
        OAuthError::invalid_token_response(
            "credential nonce expiration must be validated before consumption",
        )
    })?;

    replay::consume(Artifact::CredentialNonce, c_nonce, expires_at).map_err(
        |error| match error {
            ConsumeError::AlreadyConsumed => {
                OAuthError::invalid_or_missing_proof("credential nonce has already been used")
            }
            ConsumeError::CapacityExceeded
            | ConsumeError::StorageUnavailable
            | ConsumeError::TimeUnavailable => {
                OAuthError::invalid_token_response("credential nonce replay storage failed")
            }
        },
    )?;

    Ok(request)
}

fn generate_c_nonce() -> Result<String, OAuthError> {
    let mut bytes = [0_u8; C_NONCE_BYTES];
    SystemRandom::new()
        .fill(&mut bytes)
        .map_err(|_| OAuthError::invalid_token_response("access token generation failed"))?;
    Ok(URL_SAFE_NO_PAD.encode(bytes))
}

fn valid_c_nonce(c_nonce: &str) -> bool {
    URL_SAFE_NO_PAD
        .decode(c_nonce)
        .is_ok_and(|bytes| bytes.len() == C_NONCE_BYTES)
}
