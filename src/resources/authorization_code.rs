use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::{errors::OAuthError, resources::crypto};

pub const SECRET: &str = "static_authorization_code_secret";
pub const AUTHORIZATION_CODE_TTL_SECONDS: u64 = 600;
const COSE_EXTERNAL_AAD: &[u8] = b"kagome.authorization_code";
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
    pub id_token: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub previous_code: Option<String>,
    pub iat: u64,
    pub exp: u64,
}

pub trait Generate {
    fn previous_authorization_code(&self) -> Option<&str>;
    fn client_id(&self) -> Option<&str>;
    fn id_token(&self) -> Option<&str>;
    fn add_authorization_code(&mut self, authorization_code: AuthorizationCode);
}

pub trait Validate {
    fn request_authorization_code(&self) -> Option<&str>;
    fn client_id(&self) -> Option<&str>;
    fn add_authorization_code(&mut self, authorization_code: &str);
}

pub fn validate<T: Validate>(mut token_request: T) -> Result<T, OAuthError> {
    let authorization_code = token_request
        .request_authorization_code()
        .map(str::to_owned)
        .ok_or_else(OAuthError::missing_authorization_code)?;

    validate_request_authorization_code(&authorization_code, token_request.client_id())?;

    token_request.add_authorization_code(&authorization_code);
    Ok(token_request)
}

pub fn validate_optional<T: Validate>(mut token_request: T) -> Result<T, OAuthError> {
    let Some(authorization_code) = token_request
        .request_authorization_code()
        .map(str::to_owned)
    else {
        return Ok(token_request);
    };

    validate_request_authorization_code(&authorization_code, token_request.client_id())?;

    token_request.add_authorization_code(&authorization_code);
    Ok(token_request)
}

pub fn generate<T: Generate>(mut token_request: T) -> Result<T, OAuthError> {
    let client_id = token_request
        .client_id()
        .ok_or_else(OAuthError::missing_client_id)?;
    let id_token = token_request
        .id_token()
        .ok_or_else(OAuthError::missing_id_token)?;
    let previous_code = token_request
        .previous_authorization_code()
        .map(str::to_owned);
    let iat = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| OAuthError::invalid_token_response("authorization code generation failed"))?
        .as_secs();
    let exp = iat + AUTHORIZATION_CODE_TTL_SECONDS;
    let payload = AuthorizationCodeCosePayload {
        client_id: client_id.to_owned(),
        id_token: id_token.to_owned(),
        previous_code,
        iat,
        exp,
    };
    let authorization_code = AuthorizationCode {
        value: encode_cose_encrypt0(&payload)?,
        expires_in: exp - iat,
        payload,
    };

    token_request.add_authorization_code(authorization_code);
    Ok(token_request)
}

fn validate_request_authorization_code(
    authorization_code: &str,
    client_id: Option<&str>,
) -> Result<(), OAuthError> {
    let payload = validate_cose_encrypt0(authorization_code)?;

    if let Some(client_id) = client_id
        && payload.client_id != client_id
    {
        return Err(invalid_authorization_code(
            "authorization_code client_id does not match request",
        ));
    }

    Ok(())
}

fn encode_cose_encrypt0(payload: &AuthorizationCodeCosePayload) -> Result<String, OAuthError> {
    let mut payload_bytes = Vec::new();
    ciborium::into_writer(payload, &mut payload_bytes)
        .map_err(|_| OAuthError::invalid_token_response("authorization code generation failed"))?;

    crypto::encode_cose_encrypt0(&payload_bytes, SECRET, COSE_EXTERNAL_AAD).map_err(|error| {
        if error.error == "invalid_token_response" {
            OAuthError::invalid_token_response("authorization code generation failed")
        } else {
            error
        }
    })
}

pub fn decode_cose_payload(
    authorization_code: &str,
) -> Result<AuthorizationCodeCosePayload, OAuthError> {
    let payload = decode_cose_encrypt0(authorization_code)?;

    ciborium::from_reader(payload.as_slice())
        .map_err(|_| invalid_authorization_code("authorization_code claims are invalid"))
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
    crypto::decode_cose_encrypt0(
        authorization_code,
        SECRET,
        COSE_EXTERNAL_AAD,
        COSE_ENCRYPT0_ERRORS,
    )
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
