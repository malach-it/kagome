use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use coset::{CborSerializable, CoseMac0, CoseMac0Builder, HeaderBuilder, iana};
use hmac::{Hmac, KeyInit, Mac};
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::errors::OAuthError;

type HmacSha512 = Hmac<sha2::Sha512>;

pub const SECRET: &str = "static_authorization_code_secret";
pub const AUTHORIZATION_CODE_TTL_SECONDS: u64 = 600;
const COSE_EXTERNAL_AAD: &[u8] = b"kagome.authorization_code";

#[derive(Debug)]
pub struct AuthorizationCode {
    pub value: String,
    pub expires_in: u64,
    pub previous_code: Option<String>,
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
        previous_code: previous_code.clone(),
        iat,
        exp,
    };
    let authorization_code = AuthorizationCode {
        value: encode_cose_mac0(&payload)?,
        expires_in: exp - iat,
        previous_code,
        payload,
    };

    token_request.add_authorization_code(authorization_code);
    Ok(token_request)
}

fn validate_request_authorization_code(
    authorization_code: &str,
    client_id: Option<&str>,
) -> Result<(), OAuthError> {
    let payload = validate_cose_mac0(authorization_code)?;

    if let Some(client_id) = client_id
        && payload.client_id != client_id
    {
        return Err(invalid_authorization_code(
            "authorization_code client_id does not match request",
        ));
    }

    Ok(())
}

fn encode_cose_mac0(payload: &AuthorizationCodeCosePayload) -> Result<String, OAuthError> {
    let mut payload_bytes = Vec::new();
    ciborium::into_writer(payload, &mut payload_bytes)
        .map_err(|_| OAuthError::invalid_token_response("authorization code generation failed"))?;

    let cose = CoseMac0Builder::new()
        .protected(
            HeaderBuilder::new()
                .algorithm(iana::Algorithm::HMAC_512_512)
                .build(),
        )
        .payload(payload_bytes)
        .create_tag(COSE_EXTERNAL_AAD, hmac_sha512)
        .build();
    let cose_bytes = cose
        .to_vec()
        .map_err(|_| OAuthError::invalid_token_response("authorization code generation failed"))?;

    Ok(URL_SAFE_NO_PAD.encode(cose_bytes))
}

pub fn decode_cose_payload(
    authorization_code: &str,
) -> Result<AuthorizationCodeCosePayload, OAuthError> {
    let cose_bytes = URL_SAFE_NO_PAD
        .decode(authorization_code)
        .map_err(|_| invalid_authorization_code("authorization_code must be a cose_mac0"))?;
    let cose = CoseMac0::from_slice(&cose_bytes)
        .map_err(|_| invalid_authorization_code("authorization_code must be a cose_mac0"))?;
    let payload = cose
        .payload
        .as_deref()
        .ok_or_else(|| invalid_authorization_code("authorization_code payload is required"))?;

    ciborium::from_reader(payload)
        .map_err(|_| invalid_authorization_code("authorization_code claims are invalid"))
}

fn validate_cose_mac0(
    authorization_code: &str,
) -> Result<AuthorizationCodeCosePayload, OAuthError> {
    let cose_bytes = URL_SAFE_NO_PAD
        .decode(authorization_code)
        .map_err(|_| invalid_authorization_code("authorization_code must be a cose_mac0"))?;
    let cose = CoseMac0::from_slice(&cose_bytes)
        .map_err(|_| invalid_authorization_code("authorization_code must be a cose_mac0"))?;

    cose.verify_payload_tag(
        COSE_EXTERNAL_AAD,
        || invalid_authorization_code("authorization_code payload is required"),
        verify_hmac_sha512,
    )?;

    let payload = cose
        .payload
        .as_deref()
        .ok_or_else(|| invalid_authorization_code("authorization_code payload is required"))?;
    let payload: AuthorizationCodeCosePayload = ciborium::from_reader(payload)
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

fn hmac_sha512(data: &[u8]) -> Vec<u8> {
    let mut mac = HmacSha512::new_from_slice(SECRET.as_bytes())
        .expect("static authorization code secret is valid for hmac");
    mac.update(data);
    mac.finalize().into_bytes().to_vec()
}

fn verify_hmac_sha512(tag: &[u8], data: &[u8]) -> Result<(), OAuthError> {
    let mut mac = HmacSha512::new_from_slice(SECRET.as_bytes())
        .expect("static authorization code secret is valid for hmac");
    mac.update(data);
    mac.verify_slice(tag)
        .map_err(|_| invalid_authorization_code("authorization_code authentication tag is invalid"))
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
