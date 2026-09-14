use std::time::{SystemTime, UNIX_EPOCH};

use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use ring::rand::{SecureRandom, SystemRandom};
use serde::Serialize;
use time::{OffsetDateTime, format_description::well_known::Rfc3339};

use crate::errors::OAuthError;

use super::credential_issuer::CREDENTIAL_TYPE;

pub const SIGNING_ALGORITHM: &str = "EdDSA";
pub const KEY_ID: &str = "kagome-credential-signing-key";
pub const PUBLIC_KEY_X: &str = "mbDL1A9YckRdA3AlHpbwDmEYpR9TJV3qQwKQkNbD63g";
pub const PUBLIC_KEY: &[u8] = b"-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAmbDL1A9YckRdA3AlHpbwDmEYpR9TJV3qQwKQkNbD63g=\n-----END PUBLIC KEY-----\n";
pub const HOLDER_PUBLIC_KEY_X: &str = "nwivBoQHlj3Z7OlrsnliD0Sm-_mSSFmg1umcwdeV1e4";
pub const TTL_SECONDS: u64 = 31_536_000;

const PRIVATE_KEY: &[u8] = b"-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEIDt2IW+OSTJfZcs+QLnyHa+IoZthF8Pbf7sBWYsElCKk\n-----END PRIVATE KEY-----\n";

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
    vc: VerifiableCredentialClaims<'a>,
}

#[derive(Debug, Serialize)]
struct Confirmation {
    jwk: HolderPublicJwk,
}

#[derive(Debug, Serialize)]
struct HolderPublicJwk {
    kty: &'static str,
    crv: &'static str,
    x: &'static str,
}

#[derive(Debug, Serialize)]
struct VerifiableCredentialClaims<'a> {
    id: String,
    #[serde(rename = "type")]
    credential_types: [&'static str; 2],
    issuer: &'a str,
    #[serde(rename = "issuanceDate")]
    issuance_date: String,
    #[serde(rename = "credentialSubject")]
    credential_subject: CredentialSubject<'a>,
}

#[derive(Debug, Serialize)]
struct CredentialSubject<'a> {
    id: &'a str,
    degree: Degree,
}

#[derive(Debug, Serialize)]
struct Degree {
    #[serde(rename = "type")]
    degree_type: &'static str,
    name: &'static str,
}

pub trait Generate {
    fn credential_issuer(&self) -> Option<&str>;
    fn subject(&self) -> Option<&str>;
    fn add_verifiable_credential(&mut self, credential: VerifiableCredential);
}

pub fn generate<T: Generate>(mut request: T) -> Result<T, OAuthError> {
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
    let claims = JwtVcClaims {
        iss: issuer,
        sub: subject,
        iat,
        nbf: iat,
        exp: iat + TTL_SECONDS,
        jti: credential_id.clone(),
        cnf: Confirmation {
            jwk: HolderPublicJwk {
                kty: "OKP",
                crv: "Ed25519",
                x: HOLDER_PUBLIC_KEY_X,
            },
        },
        vc: VerifiableCredentialClaims {
            id: credential_id,
            credential_types: ["VerifiableCredential", CREDENTIAL_TYPE],
            issuer,
            issuance_date: OffsetDateTime::from_unix_timestamp(iat as i64)
                .map_err(|_| OAuthError::invalid_token_response("credential generation failed"))?
                .format(&Rfc3339)
                .map_err(|_| OAuthError::invalid_token_response("credential generation failed"))?,
            credential_subject: CredentialSubject {
                id: subject,
                degree: Degree {
                    degree_type: "BachelorDegree",
                    name: "Bachelor of Science and Arts",
                },
            },
        },
    };
    let mut header = Header::new(Algorithm::EdDSA);
    header.kid = Some(KEY_ID.to_owned());
    let value = encode(
        &header,
        &claims,
        &EncodingKey::from_ed_pem(PRIVATE_KEY)
            .map_err(|_| OAuthError::invalid_token_response("credential signing key is invalid"))?,
    )
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
