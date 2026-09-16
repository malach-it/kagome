use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::{
    config::{Config, DEFAULT_AUTHORIZATION_CODE_TTL_SECONDS},
    errors::OAuthError,
    resources::{crypto, crypto::EncryptedArtifact, id_token, pkce::CodeChallenge},
};

pub const AUTHORIZATION_CODE_TTL_SECONDS: u64 = DEFAULT_AUTHORIZATION_CODE_TTL_SECONDS;
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
}

pub fn validate<T: Validate>(mut request: T) -> Result<T, OAuthError> {
    let authorization_code = request
        .request_authorization_code()
        .map(str::to_owned)
        .ok_or_else(OAuthError::missing_authorization_code)?;

    validate_request_authorization_code(
        &authorization_code,
        request
            .validate_client_id()
            .then(|| request.client_id())
            .flatten(),
    )?;

    request.add_authorization_code(&authorization_code);
    Ok(request)
}

pub fn validate_optional<T: Validate>(mut request: T) -> Result<T, OAuthError> {
    let Some(authorization_code) = request.request_authorization_code().map(str::to_owned) else {
        return Ok(request);
    };

    validate_request_authorization_code(
        &authorization_code,
        request
            .validate_client_id()
            .then(|| request.client_id())
            .flatten(),
    )?;

    request.add_authorization_code(&authorization_code);
    Ok(request)
}

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
        (None, true) => return Err(OAuthError::missing_username()),
        (None, false) => None,
    };
    let previous_code = request.previous_authorization_code().map(str::to_owned);
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

fn encode_cose_encrypt0(payload: &AuthorizationCodeCosePayload) -> Result<String, OAuthError> {
    let mut payload_bytes = Vec::new();
    ciborium::into_writer(payload, &mut payload_bytes)
        .map_err(|_| OAuthError::invalid_token_response("authorization code generation failed"))?;

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

pub fn decode_cose_payload(
    authorization_code: &str,
) -> Result<AuthorizationCodeCosePayload, OAuthError> {
    let payload = decode_cose_encrypt0(authorization_code)?;

    ciborium::from_reader(payload.as_slice())
        .map_err(|_| invalid_authorization_code("authorization_code claims are invalid"))
}

pub fn validated_id_token_public_jwk(
    authorization_code: &str,
    client_id: &str,
) -> Result<Option<serde_json::Value>, OAuthError> {
    let payload = validate_request_authorization_code(authorization_code, Some(client_id))?;
    payload
        .id_token
        .as_deref()
        .map(id_token::validated_public_jwk)
        .transpose()
}

pub fn chain_usernames(
    authorization_code: Option<&str>,
    client_id: Option<&str>,
) -> Result<Vec<String>, OAuthError> {
    let Some(authorization_code) = authorization_code else {
        return Ok(Vec::new());
    };

    let payload = validate_request_authorization_code(authorization_code, client_id)?;
    let mut usernames = chain_usernames(payload.previous_code.as_deref(), client_id)?;

    if let Some(username) = payload.username {
        usernames.push(username);
    }

    Ok(usernames)
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
        EncryptedArtifact::AuthorizationCode,
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
