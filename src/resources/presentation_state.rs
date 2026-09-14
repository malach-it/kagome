use std::time::{SystemTime, UNIX_EPOCH};

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use ring::rand::{SecureRandom, SystemRandom};
use serde::{Deserialize, Serialize};

use crate::errors::OAuthError;

use super::{crypto, verifier};

pub const SECRET: &str = "static_openid4vp_presentation_state_secret";
pub const COSE_EXTERNAL_AAD: &[u8] = b"kagome:openid4vp:presentation-state:v1";
pub const TTL_SECONDS: u64 = 300;
pub const QUERY_ID: &str = "degree_credential";

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PresentationStateClaims {
    pub nonce: String,
    pub client_id: String,
    pub credential_issuer: String,
    pub query_id: String,
    pub iat: u64,
    pub exp: u64,
}

#[derive(Debug)]
pub struct PresentationState {
    pub value: String,
    pub claims: PresentationStateClaims,
}

pub trait Generate {
    fn verifier(&self) -> Option<&str>;
    fn add_presentation_state(&mut self, state: PresentationState);
}

pub trait Validate {
    fn request_state(&self) -> Option<&str>;
    fn add_presentation_state_claims(&mut self, claims: PresentationStateClaims);
}

pub fn generate<T: Generate>(mut request: T) -> Result<T, OAuthError> {
    let verifier = request
        .verifier()
        .ok_or_else(|| OAuthError::invalid_token_response("verifier is required"))?;
    let iat = now().map_err(|_| OAuthError::invalid_token_response("state generation failed"))?;
    let claims = PresentationStateClaims {
        nonce: random_identifier()?,
        client_id: verifier::client_id(verifier),
        credential_issuer: verifier.to_owned(),
        query_id: QUERY_ID.to_owned(),
        iat,
        exp: iat + TTL_SECONDS,
    };
    let mut plaintext = Vec::new();
    ciborium::into_writer(&claims, &mut plaintext)
        .map_err(|_| OAuthError::invalid_token_response("state generation failed"))?;
    let value = crypto::encode_cose_encrypt0(&plaintext, SECRET, COSE_EXTERNAL_AAD)?;

    request.add_presentation_state(PresentationState { value, claims });
    Ok(request)
}

pub fn validate<T: Validate>(mut request: T) -> Result<T, OAuthError> {
    let state = request
        .request_state()
        .ok_or_else(|| OAuthError::invalid_request("state is required"))?;
    let plaintext = crypto::decode_cose_encrypt0(
        state,
        SECRET,
        COSE_EXTERNAL_AAD,
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
        || claims.credential_issuer.is_empty()
        || claims.client_id != verifier::client_id(&claims.credential_issuer)
        || claims.query_id != QUERY_ID
        || claims.iat > now
        || claims.exp <= claims.iat
        || claims.exp - claims.iat > TTL_SECONDS
        || claims.exp <= now
    {
        return Err(OAuthError::invalid_request("state is invalid or expired"));
    }

    request.add_presentation_state_claims(claims);
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
