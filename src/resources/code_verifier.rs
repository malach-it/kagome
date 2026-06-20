use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use ring::digest;

use crate::{
    errors::OAuthError,
    resources::authorization_code::{
        self, AuthorizationCodeCosePayload, Generate as AuthorizationCodeGenerate,
        Validate as AuthorizationCodeValidate,
    },
};

pub const CODE_CHALLENGE_METHOD_S256: &str = "S256";

pub trait CodeChallengeRequest {
    fn request_code_challenge(&self) -> Option<&str>;
    fn request_code_challenge_method(&self) -> Option<&str>;
}

pub trait CodeVerifierRequest {
    fn request_code_verifier(&self) -> Option<&str>;
    fn validate_code_verifier(&self) -> bool;
    fn require_code_challenge(&self) -> bool;
}

impl<T: AuthorizationCodeGenerate> CodeChallengeRequest for T {
    fn request_code_challenge(&self) -> Option<&str> {
        self.code_challenge()
    }

    fn request_code_challenge_method(&self) -> Option<&str> {
        self.code_challenge_method()
    }
}

impl<T: AuthorizationCodeValidate> CodeVerifierRequest for T {
    fn request_code_verifier(&self) -> Option<&str> {
        self.code_verifier()
    }

    fn validate_code_verifier(&self) -> bool {
        authorization_code::Validate::validate_code_verifier(self)
    }

    fn require_code_challenge(&self) -> bool {
        authorization_code::Validate::require_code_challenge(self)
    }
}

pub fn validate_code_challenge<T: CodeChallengeRequest>(
    request: &T,
) -> Result<Option<String>, OAuthError> {
    let code_challenge = request.request_code_challenge();
    let code_challenge_method = request.request_code_challenge_method();
    let Some(code_challenge) = code_challenge else {
        return Ok(None);
    };

    match code_challenge_method {
        Some(CODE_CHALLENGE_METHOD_S256) => Ok(Some(code_challenge.to_owned())),
        _ => Err(invalid_code_verifier("code_challenge_method must be S256")),
    }
}

pub fn validate_code_verifier<T: CodeVerifierRequest>(
    request: &T,
    payload: &AuthorizationCodeCosePayload,
) -> Result<(), OAuthError> {
    if !request.validate_code_verifier() {
        return Ok(());
    }

    let Some(code_challenge) = payload.code_challenge.as_deref() else {
        if request.require_code_challenge() {
            return Err(invalid_code_verifier(
                "authorization_code code_challenge is required",
            ));
        }
        return Ok(());
    };
    if payload.code_challenge_method.as_deref() != Some(CODE_CHALLENGE_METHOD_S256) {
        return Err(invalid_code_verifier(
            "authorization_code code_challenge_method must be S256",
        ));
    }
    let code_verifier = request
        .request_code_verifier()
        .ok_or_else(|| invalid_code_verifier("code_verifier is required for authorization_code"))?;

    if code_challenge_s256(code_verifier) != code_challenge {
        return Err(invalid_code_verifier("code_verifier is invalid"));
    }

    Ok(())
}

pub fn code_challenge_s256(code_verifier: &str) -> String {
    URL_SAFE_NO_PAD.encode(digest::digest(&digest::SHA256, code_verifier.as_bytes()))
}

fn invalid_code_verifier(error_description: &str) -> OAuthError {
    OAuthError::invalid_authorization_code(error_description)
}
