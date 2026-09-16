use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use ring::digest;
use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;

use crate::{errors::OAuthError, resources::authorization_code};

pub const CODE_CHALLENGE_METHOD: &str = "S256";

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CodeChallenge {
    pub value: String,
}

pub trait Validate {
    fn request_code_challenge(&self) -> Option<&str>;
    fn request_code_challenge_method(&self) -> Option<&str>;
    fn require_code_challenge(&self) -> bool {
        false
    }
    fn add_code_challenge(&mut self, code_challenge: CodeChallenge);
}

pub trait Verify {
    fn request_code_verifier(&self) -> Option<&str>;
    fn validated_authorization_code(&self) -> Option<&str>;
}

/// Validates an S256 challenge pair and stores the typed challenge.
///
/// Challenge and method may both be absent unless the request requires PKCE. When present, they
/// must appear together, the method must be `S256`, and the challenge must be a 43-character
/// unpadded base64url value.
///
/// # Errors
///
/// Returns `invalid_request` for incomplete, unsupported, or malformed PKCE parameters.
pub fn validate<T: Validate>(mut request: T) -> Result<T, OAuthError> {
    match (
        request.request_code_challenge().map(str::to_owned),
        request.request_code_challenge_method().map(str::to_owned),
    ) {
        (None, None) if request.require_code_challenge() => {
            Err(OAuthError::invalid_request("code_challenge is required"))
        }
        (None, None) => Ok(request),
        (None, Some(_)) => Err(OAuthError::invalid_request(
            "code_challenge is required when code_challenge_method is provided",
        )),
        (Some(_), None) => Err(OAuthError::invalid_request(
            "code_challenge_method must be S256",
        )),
        (Some(_), Some(method)) if method != CODE_CHALLENGE_METHOD => Err(
            OAuthError::invalid_request("code_challenge_method must be S256"),
        ),
        (Some(code_challenge), Some(_)) if !valid_code_challenge(&code_challenge) => {
            Err(OAuthError::invalid_request("code_challenge is invalid"))
        }
        (Some(code_challenge), Some(_)) => {
            request.add_code_challenge(CodeChallenge {
                value: code_challenge,
            });
            Ok(request)
        }
    }
}

/// Verifies a code verifier against the challenge in a validated authorization code.
///
/// Requires the authorization code to have been validated first and to carry a challenge. The
/// verifier syntax and its constant-time S256 comparison are then enforced. This action validates
/// state without mutating it.
///
/// # Errors
///
/// Returns `invalid_token_response` when prerequisite code state is absent, an authorization-code
/// error when it cannot be decoded, or `invalid_grant` for a missing, malformed, or mismatched
/// verifier.
pub fn verify<T: Verify>(request: T) -> Result<T, OAuthError> {
    let authorization_code = request.validated_authorization_code().ok_or_else(|| {
        OAuthError::invalid_token_response("authorization_code must be validated before PKCE")
    })?;
    let payload = authorization_code::decode_cose_payload(authorization_code)?;
    let code_challenge = payload
        .code_challenge
        .ok_or_else(|| OAuthError::invalid_grant("authorization_code must use PKCE"))?;
    let code_verifier = request
        .request_code_verifier()
        .ok_or_else(|| OAuthError::invalid_grant("code_verifier is required"))?;

    if !valid_code_verifier(code_verifier) {
        return Err(OAuthError::invalid_grant("code_verifier is invalid"));
    }

    let calculated =
        URL_SAFE_NO_PAD.encode(digest::digest(&digest::SHA256, code_verifier.as_bytes()));
    if !bool::from(calculated.as_bytes().ct_eq(code_challenge.value.as_bytes())) {
        return Err(OAuthError::invalid_grant(
            "code_verifier does not match code_challenge",
        ));
    }

    Ok(request)
}

/// Reports whether a value has the required unpadded S256 base64url challenge syntax.
///
/// Valid values contain exactly 43 ASCII letters, digits, hyphens, or underscores.
pub fn valid_code_challenge(value: &str) -> bool {
    value.len() == 43
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
}

fn valid_code_verifier(value: &str) -> bool {
    (43..=128).contains(&value.len())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~'))
}
