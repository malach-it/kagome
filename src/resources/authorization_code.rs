use serde::{Deserialize, Serialize};
use std::{
    env,
    ffi::OsString,
    time::{SystemTime, UNIX_EPOCH},
};

use crate::{
    errors::OAuthError,
    resources::{code_verifier, crypto},
};

pub const SECRET_ENV_VAR: &str = "KAGOME_AUTHORIZATION_CODE_SECRET";
pub const DEFAULT_SECRET: &str = "static_authorization_code_secret";
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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id_token: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub previous_code: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub code_challenge: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub code_challenge_method: Option<String>,
    pub iat: u64,
    pub exp: u64,
}

pub trait Generate {
    fn previous_authorization_code(&self) -> Option<&str>;
    fn client_id(&self) -> Option<&str>;
    fn id_token(&self) -> Option<&str>;
    fn code_challenge(&self) -> Option<&str> {
        None
    }
    fn code_challenge_method(&self) -> Option<&str> {
        None
    }
    fn add_authorization_code(&mut self, authorization_code: AuthorizationCode);

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
    fn code_verifier(&self) -> Option<&str> {
        None
    }
    fn validate_client_id(&self) -> bool {
        true
    }
    fn validate_code_verifier(&self) -> bool {
        true
    }
    fn require_code_challenge(&self) -> bool {
        false
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
        &request,
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
        &request,
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
    let code_challenge = code_verifier::validate_code_challenge(&request)?;
    let iat = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| OAuthError::invalid_token_response("authorization code generation failed"))?
        .as_secs();
    let exp = iat + AUTHORIZATION_CODE_TTL_SECONDS;
    let payload = AuthorizationCodeCosePayload {
        client_id: client_id.to_owned(),
        id_token,
        username,
        previous_code,
        code_challenge,
        code_challenge_method: request.code_challenge_method().map(str::to_owned),
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
    request: &impl code_verifier::CodeVerifierRequest,
) -> Result<AuthorizationCodeCosePayload, OAuthError> {
    let payload = validate_cose_encrypt0(authorization_code)?;

    if let Some(client_id) = client_id
        && payload.client_id != client_id
    {
        return Err(invalid_authorization_code(
            "authorization_code client_id does not match request",
        ));
    }

    code_verifier::validate_code_verifier(request, &payload)?;

    Ok(payload)
}

fn encode_cose_encrypt0(payload: &AuthorizationCodeCosePayload) -> Result<String, OAuthError> {
    let mut payload_bytes = Vec::new();
    ciborium::into_writer(payload, &mut payload_bytes)
        .map_err(|_| OAuthError::invalid_token_response("authorization code generation failed"))?;

    crypto::encode_cose_encrypt0(
        &payload_bytes,
        &secret_from_environment(),
        COSE_EXTERNAL_AAD,
    )
    .map_err(|error| {
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

pub fn chain_usernames(
    authorization_code: Option<&str>,
    client_id: Option<&str>,
) -> Result<Vec<String>, OAuthError> {
    let Some(authorization_code) = authorization_code else {
        return Ok(Vec::new());
    };

    let payload =
        validate_request_authorization_code(authorization_code, client_id, &NoCodeVerifierRequest)?;
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
        &secret_from_environment(),
        COSE_EXTERNAL_AAD,
        COSE_ENCRYPT0_ERRORS,
    )
}

struct NoCodeVerifierRequest;

impl code_verifier::CodeVerifierRequest for NoCodeVerifierRequest {
    fn request_code_verifier(&self) -> Option<&str> {
        None
    }

    fn validate_code_verifier(&self) -> bool {
        false
    }

    fn require_code_challenge(&self) -> bool {
        false
    }
}

pub fn secret_from_environment() -> String {
    secret_from_environment_value(env::var_os(SECRET_ENV_VAR))
}

fn secret_from_environment_value(value: Option<OsString>) -> String {
    value
        .filter(|value| !value.is_empty())
        .map(|value| value.to_string_lossy().into_owned())
        .unwrap_or_else(|| DEFAULT_SECRET.to_owned())
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
    use super::{DEFAULT_SECRET, secret_from_environment_value};
    use std::ffi::OsString;

    #[test]
    fn defaults_secret_when_environment_value_is_missing_or_empty() {
        assert_eq!(secret_from_environment_value(None), DEFAULT_SECRET);
        assert_eq!(
            secret_from_environment_value(Some(OsString::new())),
            DEFAULT_SECRET
        );
    }

    #[test]
    fn uses_configured_secret_environment_value() {
        assert_eq!(
            secret_from_environment_value(Some(OsString::from("configured-secret"))),
            "configured-secret"
        );
    }
}
