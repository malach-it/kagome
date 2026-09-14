use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::errors::OAuthError;

use super::{credential_issuer::CREDENTIAL_CONFIGURATION_ID, crypto};

pub const SECRET: &str = "static_pre_authorized_code_secret";
pub const COSE_EXTERNAL_AAD: &[u8] = b"kagome.pre_authorized_code";
const COSE_ENCRYPT0_ERRORS: crypto::CoseEncrypt0Errors = crypto::CoseEncrypt0Errors {
    invalid_cose: "pre-authorized_code must be a cose_encrypt0",
    missing_ciphertext: "pre-authorized_code ciphertext is required",
    missing_nonce: "pre-authorized_code nonce is required",
    decryption_failed: "pre-authorized_code decryption failed",
};
pub const GRANT_TYPE: &str = "urn:ietf:params:oauth:grant-type:pre-authorized_code";
pub const TX_CODE: &str = "493536";
pub const TTL_SECONDS: u64 = 300;

#[derive(Debug, Serialize, Deserialize)]
pub struct PreAuthorizedCodeClaims {
    pub credential_configuration_id: String,
    pub subject: String,
    pub iat: u64,
    pub exp: u64,
}

pub trait Generate {
    fn add_pre_authorized_code(&mut self, pre_authorized_code: String);
}

pub trait Validate {
    fn request_pre_authorized_code(&self) -> Option<&str>;
    fn request_tx_code(&self) -> Option<&str>;
    fn add_pre_authorized_code_claims(&mut self, claims: PreAuthorizedCodeClaims);
}

pub fn generate<T: Generate>(mut request: T) -> Result<T, OAuthError> {
    let iat = now("pre-authorized code generation failed")?;
    let claims = PreAuthorizedCodeClaims {
        credential_configuration_id: CREDENTIAL_CONFIGURATION_ID.to_owned(),
        subject: "did:example:alice".to_owned(),
        iat,
        exp: iat + TTL_SECONDS,
    };
    let mut claims_bytes = Vec::new();
    ciborium::into_writer(&claims, &mut claims_bytes)
        .map_err(|_| OAuthError::invalid_token_response("pre-authorized code generation failed"))?;
    let code = crypto::encode_cose_encrypt0(&claims_bytes, SECRET, COSE_EXTERNAL_AAD)?;

    request.add_pre_authorized_code(code);
    Ok(request)
}

pub fn validate<T: Validate>(mut request: T) -> Result<T, OAuthError> {
    let code = request
        .request_pre_authorized_code()
        .ok_or_else(|| OAuthError::invalid_request("pre-authorized_code is required"))?;
    let tx_code = request
        .request_tx_code()
        .ok_or_else(|| OAuthError::invalid_request("tx_code is required"))?;

    if tx_code != TX_CODE {
        return Err(OAuthError::invalid_grant("tx_code is invalid"));
    }

    let claims_bytes =
        crypto::decode_cose_encrypt0(code, SECRET, COSE_EXTERNAL_AAD, COSE_ENCRYPT0_ERRORS)
            .map_err(|_| OAuthError::invalid_grant("pre-authorized_code is invalid or expired"))?;
    let claims: PreAuthorizedCodeClaims = ciborium::from_reader(claims_bytes.as_slice())
        .map_err(|_| OAuthError::invalid_grant("pre-authorized_code is invalid or expired"))?;
    let now = now("pre-authorized code validation failed")?;
    if claims.iat > now || claims.exp <= claims.iat || claims.exp <= now {
        return Err(OAuthError::invalid_grant(
            "pre-authorized_code is invalid or expired",
        ));
    }

    request.add_pre_authorized_code_claims(claims);
    Ok(request)
}

fn now(error_description: &str) -> Result<u64, OAuthError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|_| OAuthError::invalid_token_response(error_description))
}
