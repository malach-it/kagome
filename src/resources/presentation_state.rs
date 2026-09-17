use std::time::{SystemTime, UNIX_EPOCH};

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use ring::rand::{SecureRandom, SystemRandom};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{
    config::{Config, PresentationDefinitionConfig},
    errors::OAuthError,
};

use super::{
    authorization_code, crypto,
    crypto::EncryptedArtifact,
    pkce,
    pkce::CodeChallenge,
    replay::{self, Artifact, ConsumeError},
    verifier,
};

pub const TTL_SECONDS: u64 = 300;
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PresentationStateClaims {
    pub nonce: String,
    pub client_id: String,
    pub verifier: String,
    pub credential_issuer: String,
    pub authorization_client_id: String,
    pub authorization_redirect_uri: String,
    pub authorization_state: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub code_challenge: Option<CodeChallenge>,
    pub id_token_public_jwk: Option<Value>,
    pub presentation_definition_identifier: String,
    pub presentation_definition: Value,
    pub presentation_definition_id: String,
    pub input_descriptor_id: String,
    pub iat: u64,
    pub exp: u64,
}

#[derive(Debug)]
pub struct PresentationState {
    pub value: String,
    pub claims: PresentationStateClaims,
}

pub trait Generate {
    fn presentation_definition(&self) -> Option<&PresentationDefinitionConfig>;
    fn verifier(&self) -> Option<&str>;
    fn credential_issuer(&self) -> Option<&str>;
    fn authorization_client_id(&self) -> Option<&str>;
    fn authorization_redirect_uri(&self) -> Option<&str>;
    fn authorization_state(&self) -> Option<&str>;
    fn authorization_code(&self) -> Option<&str>;
    fn code_challenge(&self) -> Option<&CodeChallenge>;
    fn require_wallet_binding(&self) -> bool {
        false
    }
    fn add_presentation_state(&mut self, state: PresentationState);
}

pub trait Validate {
    fn request_state(&self) -> Option<&str>;
    fn add_presentation_state_claims(&mut self, state: &str, claims: PresentationStateClaims);
}

pub trait Consume {
    fn validated_presentation_state(&self) -> Option<&str>;
    fn presentation_state_expiration(&self) -> Option<u64>;
}

/// Generates encrypted presentation state from validated policy, client, issuer, and verifier data.
///
/// Requires a selected definition and validated verifier, credential issuer, authorization client,
/// and redirect URI. It optionally carries authorization state, PKCE, and the ID-token public key
/// from an authorization code, then stores an encrypted five-minute transaction artifact.
///
/// # Errors
///
/// Returns an OAuth error for missing prerequisite state, invalid definition structure or
/// authorization code, required wallet binding without a key, clock/randomness failure, or
/// serialization/encryption failure.
pub fn generate<T: Generate>(mut request: T) -> Result<T, OAuthError> {
    let presentation_definition = request.presentation_definition().ok_or_else(|| {
        OAuthError::invalid_token_response("presentation definition must be selected")
    })?;
    let presentation_definition_id = presentation_definition.definition_id().ok_or_else(|| {
        OAuthError::invalid_token_response("presentation definition id is required")
    })?;
    let input_descriptor_id = presentation_definition
        .input_descriptor_id()
        .ok_or_else(|| {
            OAuthError::invalid_token_response("presentation input descriptor id is required")
        })?;
    let verifier = request
        .verifier()
        .ok_or_else(|| OAuthError::invalid_token_response("verifier is required"))?;
    let credential_issuer = request
        .credential_issuer()
        .ok_or_else(|| OAuthError::invalid_token_response("credential issuer must be validated"))?;
    let authorization_client_id = request.authorization_client_id().ok_or_else(|| {
        OAuthError::invalid_token_response("authorization client_id must be validated")
    })?;
    let authorization_redirect_uri = request.authorization_redirect_uri().ok_or_else(|| {
        OAuthError::invalid_token_response("authorization redirect_uri must be validated")
    })?;
    let id_token_public_jwk = request
        .authorization_code()
        .map(|code| {
            authorization_code::validated_id_token_public_jwk(code, authorization_client_id)
        })
        .transpose()?
        .flatten();
    if request.require_wallet_binding() && id_token_public_jwk.is_none() {
        return Err(OAuthError::invalid_request(
            "wallet binding requires a code containing an id_token public key",
        ));
    }
    let iat = now().map_err(|_| OAuthError::invalid_token_response("state generation failed"))?;
    let claims = PresentationStateClaims {
        nonce: random_identifier()?,
        client_id: verifier::client_id(verifier),
        verifier: verifier.to_owned(),
        credential_issuer: credential_issuer.to_owned(),
        authorization_client_id: authorization_client_id.to_owned(),
        authorization_redirect_uri: authorization_redirect_uri.to_owned(),
        authorization_state: request.authorization_state().map(str::to_owned),
        code_challenge: request.code_challenge().cloned(),
        id_token_public_jwk,
        presentation_definition_identifier: presentation_definition.identifier.clone(),
        presentation_definition: presentation_definition.definition.clone(),
        presentation_definition_id: presentation_definition_id.to_owned(),
        input_descriptor_id: input_descriptor_id.to_owned(),
        iat,
        exp: iat + Config::token_ttls().presentation_state_ttl,
    };
    let mut plaintext = Vec::new();
    ciborium::into_writer(&claims, &mut plaintext)
        .map_err(|_| OAuthError::invalid_token_response("state generation failed"))?;
    let value = crypto::encode_cose_encrypt0(&plaintext, EncryptedArtifact::PresentationState)?;

    request.add_presentation_state(PresentationState { value, claims });
    Ok(request)
}

/// Authenticates presentation state and restores its validated transaction claims.
///
/// The encrypted artifact must contain well-formed identifiers and optional PKCE/JWK values, match
/// the verifier-derived client ID and current configured presentation definition, and have a valid
/// five-minute lifetime. Validated claims are added to the request.
///
/// # Errors
///
/// Returns `invalid_request` when state is absent, malformed, unauthenticated, expired,
/// inconsistent, or no longer matches configuration.
pub fn validate<T: Validate>(mut request: T) -> Result<T, OAuthError> {
    let state = request
        .request_state()
        .map(str::to_owned)
        .ok_or_else(|| OAuthError::invalid_request("state is required"))?;
    let plaintext = crypto::decode_cose_encrypt0(
        &state,
        EncryptedArtifact::PresentationState,
        crypto::CoseEncrypt0Errors {
            invalid_cose: "state is invalid",
            missing_ciphertext: "state is invalid",
            missing_nonce: "state is invalid",
            decryption_failed: "state is invalid",
        },
    )
    .map_err(|_| OAuthError::invalid_request("state is invalid or expired"))?;
    let claims: PresentationStateClaims = ciborium::from_reader(plaintext.as_slice())
        .map_err(|_| OAuthError::invalid_request("state is invalid or expired"))?;
    let now = now().map_err(|_| OAuthError::invalid_request("state is invalid or expired"))?;

    if claims.nonce.is_empty()
        || !claims
            .nonce
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~'))
        || claims.client_id.is_empty()
        || claims.verifier.is_empty()
        || claims.credential_issuer.is_empty()
        || claims.authorization_client_id.is_empty()
        || claims.authorization_redirect_uri.is_empty()
        || claims
            .code_challenge
            .as_ref()
            .is_some_and(|challenge| !pkce::valid_code_challenge(&challenge.value))
        || claims
            .id_token_public_jwk
            .as_ref()
            .is_some_and(|jwk| !jwk.is_object())
        || claims.client_id != verifier::client_id(&claims.verifier)
        || !Config::global()
            .presentation_definition(&claims.presentation_definition_identifier)
            .is_some_and(|configured| {
                configured.definition == claims.presentation_definition
                    && configured.definition_id() == Some(&claims.presentation_definition_id)
                    && configured.input_descriptor_id() == Some(&claims.input_descriptor_id)
            })
        || claims.iat > now
        || claims.exp <= claims.iat
        || claims.exp - claims.iat > Config::token_ttls().presentation_state_ttl
        || claims.exp <= now
    {
        return Err(OAuthError::invalid_request("state is invalid or expired"));
    }

    request.add_presentation_state_claims(&state, claims);
    Ok(request)
}

/// Atomically consumes validated presentation state after accepting a wallet response.
///
/// The encrypted state is recorded as a domain-separated digest until its validated expiration.
/// Call this only after the presentation and submission, or the supported wallet error, have been
/// validated so malformed responses cannot invalidate an outstanding presentation request.
///
/// # Errors
///
/// Returns `invalid_request` when state was already consumed and `invalid_token_response` when
/// validated state or replay storage is unavailable.
pub fn consume<T: Consume>(request: T) -> Result<T, OAuthError> {
    let state = request.validated_presentation_state().ok_or_else(|| {
        OAuthError::invalid_token_response(
            "presentation state must be validated before consumption",
        )
    })?;
    let expires_at = request.presentation_state_expiration().ok_or_else(|| {
        OAuthError::invalid_token_response(
            "presentation state expiration must be validated before consumption",
        )
    })?;

    replay::consume(Artifact::PresentationState, state, expires_at).map_err(
        |error| match error {
            ConsumeError::AlreadyConsumed => {
                OAuthError::invalid_request("presentation state has already been used")
            }
            ConsumeError::CapacityExceeded
            | ConsumeError::StorageUnavailable
            | ConsumeError::TimeUnavailable => {
                OAuthError::invalid_token_response("presentation state replay storage failed")
            }
        },
    )?;

    Ok(request)
}

fn random_identifier() -> Result<String, OAuthError> {
    let mut bytes = [0_u8; 32];
    SystemRandom::new()
        .fill(&mut bytes)
        .map_err(|_| OAuthError::invalid_token_response("state generation failed"))?;
    Ok(URL_SAFE_NO_PAD.encode(bytes))
}

fn now() -> Result<u64, std::time::SystemTimeError> {
    Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())
}
