use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{errors::OAuthError, resources::resource_owner::CredentialProfiles};

use super::{
    authorization_code, crypto,
    crypto::EncryptedArtifact,
    replay::{self, Artifact, ConsumeError},
};

const COSE_ENCRYPT0_ERRORS: crypto::CoseEncrypt0Errors = crypto::CoseEncrypt0Errors {
    invalid_cose: "pre-authorized_code must be a cose_encrypt0",
    missing_ciphertext: "pre-authorized_code ciphertext is required",
    missing_nonce: "pre-authorized_code nonce is required",
    decryption_failed: "pre-authorized_code decryption failed",
};
pub const GRANT_TYPE: &str = "urn:ietf:params:oauth:grant-type:pre-authorized_code";
pub const TTL_SECONDS: u64 = 300;

#[derive(Debug, Serialize, Deserialize)]
pub struct PreAuthorizedCodeClaims {
    pub credential_configuration_ids: Vec<String>,
    pub subject: String,
    #[serde(default)]
    pub credential_profile: CredentialProfiles,
    pub id_token_public_jwk: Option<Value>,
    pub require_wallet_binding: bool,
    pub iat: u64,
    pub exp: u64,
}

pub trait Generate {
    fn add_pre_authorized_code(&mut self, pre_authorized_code: String);

    fn add_wallet_authenticated(&mut self) {}

    fn client_id(&self) -> Option<&str> {
        None
    }

    fn authorization_code(&self) -> Option<&str> {
        None
    }

    fn require_wallet_binding(&self) -> bool {
        false
    }

    fn subject(&self) -> Option<&str> {
        None
    }

    fn credential_profile(&self) -> Option<&CredentialProfiles> {
        None
    }

    fn require_subject(&self) -> bool {
        false
    }
}

pub trait Validate {
    fn request_pre_authorized_code(&self) -> Option<&str>;
    fn add_pre_authorized_code_claims(
        &mut self,
        pre_authorized_code: &str,
        claims: PreAuthorizedCodeClaims,
    );
}

pub trait Consume {
    fn validated_pre_authorized_code(&self) -> Option<&str>;
    fn pre_authorized_code_expiration(&self) -> Option<u64>;
}

/// Generates an encrypted credential grant bound to identity and optional wallet key.
///
/// Captures all configured credential IDs and the selected credential profile. When an
/// authorization code is present, its client-bound ID-token key supplies wallet binding and marks
/// the wallet authenticated.
///
/// # Errors
///
/// Returns an OAuth error for missing required identity/client state, an invalid binding code,
/// required binding without a key, time failure, serialization, or encryption.
pub fn generate<T: Generate>(mut request: T) -> Result<T, OAuthError> {
    let iat = now("pre-authorized code generation failed")?;
    let subject = match (request.subject(), request.require_subject()) {
        (Some(subject), _) => subject.to_owned(),
        (None, true) => return Err(OAuthError::unauthenticated()),
        (None, false) => "did:example:alice".to_owned(),
    };
    let id_token_public_jwk = match (request.authorization_code(), request.client_id()) {
        (Some(code), Some(client_id)) => {
            authorization_code::validated_id_token_public_jwk(code, client_id)?
        }
        (Some(_), None) => {
            return Err(OAuthError::invalid_token_response(
                "client_id must be validated before wallet binding",
            ));
        }
        (None, _) => None,
    };
    let require_wallet_binding = request.require_wallet_binding();
    if require_wallet_binding && id_token_public_jwk.is_none() {
        return Err(OAuthError::invalid_request(
            "wallet binding requires a code containing an id_token public key",
        ));
    }
    let wallet_authenticated = id_token_public_jwk.is_some();
    let claims = PreAuthorizedCodeClaims {
        credential_configuration_ids: crate::config::Config::global()
            .credentials
            .iter()
            .map(|credential| credential.credential_configuration_id.clone())
            .collect(),
        subject,
        credential_profile: request.credential_profile().cloned().unwrap_or_default(),
        id_token_public_jwk,
        require_wallet_binding,
        iat,
        exp: iat + TTL_SECONDS,
    };
    let mut claims_bytes = Vec::new();
    ciborium::into_writer(&claims, &mut claims_bytes)
        .map_err(|_| OAuthError::invalid_token_response("pre-authorized code generation failed"))?;
    let code = crypto::encode_cose_encrypt0(&claims_bytes, EncryptedArtifact::PreAuthorizedCode)?;

    if wallet_authenticated {
        request.add_wallet_authenticated();
    }
    request.add_pre_authorized_code(code);
    Ok(request)
}

/// Validates a pre-authorized code, lifetime, and binding claims.
///
/// Successful validation stores [`PreAuthorizedCodeClaims`] for token issuance.
///
/// # Errors
///
/// Returns `invalid_request` for a missing code and `invalid_grant` for an invalid, expired, or
/// internally inconsistent encrypted grant.
pub fn validate<T: Validate>(mut request: T) -> Result<T, OAuthError> {
    let code = request
        .request_pre_authorized_code()
        .map(str::to_owned)
        .ok_or_else(|| OAuthError::invalid_request("pre-authorized_code is required"))?;
    let claims_bytes = crypto::decode_cose_encrypt0(
        &code,
        EncryptedArtifact::PreAuthorizedCode,
        COSE_ENCRYPT0_ERRORS,
    )
    .map_err(|_| OAuthError::invalid_grant("pre-authorized_code is invalid or expired"))?;
    let claims: PreAuthorizedCodeClaims = ciborium::from_reader(claims_bytes.as_slice())
        .map_err(|_| OAuthError::invalid_grant("pre-authorized_code is invalid or expired"))?;
    let now = now("pre-authorized code validation failed")?;
    if claims.iat > now || claims.exp <= claims.iat || claims.exp <= now {
        return Err(OAuthError::invalid_grant(
            "pre-authorized_code is invalid or expired",
        ));
    }
    if claims
        .id_token_public_jwk
        .as_ref()
        .is_some_and(|jwk| !jwk.is_object())
        || claims.require_wallet_binding && claims.id_token_public_jwk.is_none()
    {
        return Err(OAuthError::invalid_grant(
            "pre-authorized_code is invalid or expired",
        ));
    }

    request.add_pre_authorized_code_claims(&code, claims);
    Ok(request)
}

/// Atomically consumes a validated Pre-Authorized Code so it cannot be exchanged again.
///
/// A domain-separated digest is inserted into the process-local replay store after validation and
/// before credential access-token generation.
///
/// # Errors
///
/// Returns `invalid_token_response` when validated state or replay storage is unavailable, and
/// `invalid_grant` when the code was already consumed.
pub fn consume<T: Consume>(request: T) -> Result<T, OAuthError> {
    let code = request.validated_pre_authorized_code().ok_or_else(|| {
        OAuthError::invalid_token_response(
            "pre-authorized_code must be validated before consumption",
        )
    })?;
    let expires_at = request.pre_authorized_code_expiration().ok_or_else(|| {
        OAuthError::invalid_token_response(
            "pre-authorized_code expiration must be validated before consumption",
        )
    })?;

    replay::consume(Artifact::PreAuthorizedCode, code, expires_at).map_err(
        |error| match error {
            ConsumeError::AlreadyConsumed => {
                OAuthError::invalid_grant("pre-authorized_code has already been used")
            }
            ConsumeError::CapacityExceeded
            | ConsumeError::StorageUnavailable
            | ConsumeError::TimeUnavailable => {
                OAuthError::invalid_token_response("pre-authorized code replay storage failed")
            }
        },
    )?;

    Ok(request)
}

fn now(error_description: &str) -> Result<u64, OAuthError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|_| OAuthError::invalid_token_response(error_description))
}
