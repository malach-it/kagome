use std::time::{SystemTime, UNIX_EPOCH};

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use ring::rand::{SecureRandom, SystemRandom};
use serde::{Deserialize, Serialize};

use crate::{config::Config, errors::OAuthError};

use super::crypto::{self, EncryptedArtifact};

pub const TTL_SECONDS: u64 = 300;

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SiopStateClaims {
    pub nonce: String,
    pub verifier: String,
    pub response_type: String,
    pub authorization: SiopAuthorizationParameters,
    pub iat: u64,
    pub exp: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SiopAuthorizationParameters {
    pub response_type: Option<String>,
    pub client_id: Option<String>,
    pub redirect_uri: Option<String>,
    pub state: Option<String>,
    pub authorization_code: Option<String>,
    pub metadata_policy: Option<String>,
    #[serde(default)]
    pub scope: Option<String>,
    #[serde(default)]
    pub code_challenge: Option<String>,
    #[serde(default)]
    pub code_challenge_method: Option<String>,
}

#[derive(Debug)]
pub struct SiopState {
    pub value: String,
    pub claims: SiopStateClaims,
}

pub trait Generate {
    fn authorization_parameters(&self) -> SiopAuthorizationParameters;
    fn add_siop_state(&mut self, state: SiopState);
}

pub trait Validate {
    fn request_state(&self) -> Option<&str>;
    fn add_siop_state_claims(&mut self, claims: SiopStateClaims);
}

/// Encrypts downstream authorization parameters into fresh, short-lived SIOPv2 state.
///
/// Requires the downstream response type and captures the complete authorization transaction with
/// the configured verifier issuer, a fresh nonce, and a five-minute lifetime. The encrypted state
/// and its claims are added to the request.
///
/// # Errors
///
/// Returns `invalid_token_response` for missing response type, clock/randomness failure, or
/// serialization/encryption failure.
pub fn generate<T: Generate>(mut request: T) -> Result<T, OAuthError> {
    let iat = now().map_err(|_| OAuthError::invalid_token_response("state generation failed"))?;
    let authorization = request.authorization_parameters();
    let response_type = authorization
        .response_type
        .clone()
        .ok_or_else(|| OAuthError::invalid_token_response("state generation failed"))?;
    let claims = SiopStateClaims {
        nonce: random_identifier()?,
        verifier: configured_issuer(),
        response_type,
        authorization,
        iat,
        exp: iat + TTL_SECONDS,
    };
    let mut plaintext = Vec::new();
    ciborium::into_writer(&claims, &mut plaintext)
        .map_err(|_| OAuthError::invalid_token_response("state generation failed"))?;
    let value = crypto::encode_cose_encrypt0(&plaintext, EncryptedArtifact::Siopv2State)?;

    request.add_siop_state(SiopState { value, claims });
    Ok(request)
}

/// Authenticates SIOPv2 state and restores its validated authorization transaction.
///
/// Enforces artifact authentication, nonce syntax, exact configured verifier and response-type
/// consistency, required downstream client and redirect URI, and a valid five-minute lifetime.
/// Successful validation adds the restored claims to the request.
///
/// # Errors
///
/// Returns `invalid_request` when state is missing, malformed, unauthenticated, expired, or
/// internally inconsistent.
pub fn validate<T: Validate>(mut request: T) -> Result<T, OAuthError> {
    let state = request
        .request_state()
        .ok_or_else(|| OAuthError::invalid_request("state is required"))?;
    let plaintext = crypto::decode_cose_encrypt0(
        state,
        EncryptedArtifact::Siopv2State,
        crypto::CoseEncrypt0Errors {
            invalid_cose: "state is invalid",
            missing_ciphertext: "state is invalid",
            missing_nonce: "state is invalid",
            decryption_failed: "state is invalid",
        },
    )
    .map_err(|_| OAuthError::invalid_request("state is invalid or expired"))?;
    let claims: SiopStateClaims = ciborium::from_reader(plaintext.as_slice())
        .map_err(|_| OAuthError::invalid_request("state is invalid or expired"))?;
    let current_time =
        now().map_err(|_| OAuthError::invalid_request("state is invalid or expired"))?;

    if claims.nonce.is_empty()
        || !claims
            .nonce
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~'))
        || claims.verifier != configured_issuer()
        || claims.response_type.is_empty()
        || claims.authorization.response_type.as_deref() != Some(claims.response_type.as_str())
        || claims
            .authorization
            .client_id
            .as_deref()
            .is_none_or(str::is_empty)
        || claims
            .authorization
            .redirect_uri
            .as_deref()
            .is_none_or(str::is_empty)
        || claims.iat > current_time
        || claims.exp <= claims.iat
        || claims.exp - claims.iat > TTL_SECONDS
        || claims.exp <= current_time
    {
        return Err(OAuthError::invalid_request("state is invalid or expired"));
    }

    request.add_siop_state_claims(claims);
    Ok(request)
}

fn configured_issuer() -> String {
    Config::global()
        .server
        .issuer
        .trim_end_matches('/')
        .to_owned()
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
