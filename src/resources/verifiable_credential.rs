use std::{
    collections::BTreeMap,
    time::{SystemTime, UNIX_EPOCH},
};

use ring::rand::{SecureRandom, SystemRandom};
use serde::Serialize;
use serde_json::{Value, json};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};

use crate::{
    config::CredentialConfig,
    errors::OAuthError,
    resources::{
        crypto::{self, SigningArtifact},
        resource_owner::ResourceOwnerProfile,
    },
};

pub const HOLDER_PUBLIC_KEY_X: &str = "nwivBoQHlj3Z7OlrsnliD0Sm-_mSSFmg1umcwdeV1e4";
pub const TTL_SECONDS: u64 = 31_536_000;

#[derive(Debug)]
pub struct VerifiableCredential {
    pub value: String,
}

#[derive(Debug, Serialize)]
struct JwtVcClaims<'a> {
    iss: &'a str,
    sub: &'a str,
    iat: u64,
    nbf: u64,
    exp: u64,
    jti: String,
    cnf: Confirmation,
    #[serde(rename = "@context")]
    context: [&'static str; 1],
    id: String,
    #[serde(rename = "type")]
    credential_types: &'a [&'a str],
    vct: &'a str,
    issuer: &'a str,
    #[serde(rename = "issuanceDate")]
    issuance_date: String,
    #[serde(rename = "credentialSubject")]
    credential_subject: CredentialSubjects<'a>,
    vc: VerifiableCredentialClaims<'a>,
}

#[derive(Debug, Serialize)]
struct Confirmation {
    jwk: Value,
}

#[derive(Debug, Serialize)]
struct VerifiableCredentialClaims<'a> {
    id: String,
    #[serde(rename = "type")]
    credential_types: &'a [&'a str],
    vct: &'a str,
    issuer: &'a str,
    #[serde(rename = "issuanceDate")]
    issuance_date: String,
    #[serde(rename = "credentialSubject")]
    credential_subject: CredentialSubject<'a>,
}

#[derive(Clone, Debug, Serialize)]
struct CredentialSubject<'a> {
    id: &'a str,
    #[serde(flatten)]
    profile: &'a ResourceOwnerProfile,
}

#[derive(Debug, Serialize)]
struct CredentialSubjects<'a> {
    #[serde(flatten)]
    configured: BTreeMap<&'a str, CredentialSubject<'a>>,
    id: &'a str,
}

pub trait Generate {
    fn credential_configuration(&self) -> Option<&CredentialConfig>;
    fn credential_issuer(&self) -> Option<&str>;
    fn subject(&self) -> Option<&str>;
    fn holder_jwk(&self) -> Option<&Value> {
        None
    }
    fn credential_profile(&self) -> Option<&ResourceOwnerProfile> {
        None
    }
    fn add_verifiable_credential(&mut self, credential: VerifiableCredential);
}

pub fn generate<T: Generate>(mut request: T) -> Result<T, OAuthError> {
    let credential_configuration = request.credential_configuration().ok_or_else(|| {
        OAuthError::invalid_token_response("credential configuration is required")
    })?;
    let issuer = request
        .credential_issuer()
        .ok_or_else(|| OAuthError::invalid_token_response("credential issuer is required"))?;
    let subject = request
        .subject()
        .ok_or_else(|| OAuthError::invalid_token_response("credential subject is required"))?;
    let iat = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| OAuthError::invalid_token_response("credential generation failed"))?
        .as_secs();
    let credential_id = format!("{issuer}/credentials/{}", random_identifier()?);
    let issuance_date = OffsetDateTime::from_unix_timestamp(iat as i64)
        .map_err(|_| OAuthError::invalid_token_response("credential generation failed"))?
        .format(&Rfc3339)
        .map_err(|_| OAuthError::invalid_token_response("credential generation failed"))?;
    let empty_profile = ResourceOwnerProfile::new();
    let credential_profile = request.credential_profile().unwrap_or(&empty_profile);
    let credential_subject = CredentialSubject {
        id: subject,
        profile: credential_profile,
    };
    let mut configured_subject = BTreeMap::new();
    configured_subject.insert(
        credential_configuration
            .credential_configuration_id
            .as_str(),
        credential_subject.clone(),
    );
    let credential_types: Vec<_> = std::iter::once("VerifiableCredential")
        .chain(
            credential_configuration
                .credential_types
                .iter()
                .map(String::as_str),
        )
        .collect();
    let claims = JwtVcClaims {
        iss: issuer,
        sub: subject,
        iat,
        nbf: iat,
        exp: iat + TTL_SECONDS,
        jti: credential_id.clone(),
        cnf: Confirmation {
            jwk: request.holder_jwk().cloned().unwrap_or_else(
                || json!({"kty": "OKP", "crv": "Ed25519", "x": HOLDER_PUBLIC_KEY_X}),
            ),
        },
        context: ["https://www.w3.org/ns/credentials/v2"],
        id: credential_id.clone(),
        credential_types: &credential_types,
        vct: &credential_configuration.vct,
        issuer,
        issuance_date: issuance_date.clone(),
        credential_subject: CredentialSubjects {
            configured: configured_subject,
            id: subject,
        },
        vc: VerifiableCredentialClaims {
            id: credential_id,
            credential_types: &credential_types,
            vct: &credential_configuration.vct,
            issuer,
            issuance_date,
            credential_subject,
        },
    };
    let value = crypto::sign_jwt(&claims, SigningArtifact::Credential)
        .map_err(|_| OAuthError::invalid_token_response("credential generation failed"))?;

    request.add_verifiable_credential(VerifiableCredential { value });
    Ok(request)
}

fn random_identifier() -> Result<String, OAuthError> {
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};

    let mut bytes = [0_u8; 16];
    SystemRandom::new()
        .fill(&mut bytes)
        .map_err(|_| OAuthError::invalid_token_response("credential generation failed"))?;
    Ok(URL_SAFE_NO_PAD.encode(bytes))
}
