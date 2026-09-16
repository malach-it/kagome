use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use coset::{CborSerializable, CoseEncrypt0, CoseEncrypt0Builder, HeaderBuilder, iana};
use jsonwebtoken::DecodingKey;
use ring::rand::{SecureRandom, SystemRandom};
use serde::Serialize;
use serde_json::Value;

use crate::{config::Config, errors::OAuthError, key_management::AES_GCM_NONCE_LEN};

pub use crate::key_management::{EncryptedArtifact, SigningArtifact};

impl SigningArtifact {
    pub fn public_jwk(self) -> Value {
        Config::key_manager().public_jwk(self)
    }

    pub fn decoding_key(self) -> Result<DecodingKey, jsonwebtoken::errors::Error> {
        Config::key_manager().decoding_key(self)
    }
}

/// Signs serializable claims with the key and algorithm assigned to a signing artifact domain.
///
/// The key manager supplies the private key, `alg`, and `kid` for Credential, ID-token, or
/// RequestObject artifacts.
///
/// # Errors
///
/// Returns the JWT library error produced by claim serialization or signing.
pub fn sign_jwt<T: Serialize>(
    claims: &T,
    artifact: SigningArtifact,
) -> Result<String, jsonwebtoken::errors::Error> {
    Config::key_manager().sign(claims, artifact)
}

#[derive(Clone, Copy)]
pub struct CoseEncrypt0Errors {
    pub invalid_cose: &'static str,
    pub missing_ciphertext: &'static str,
    pub missing_nonce: &'static str,
    pub decryption_failed: &'static str,
}

/// Encrypts plaintext as base64url COSE_Encrypt0 using an artifact-specific key and AAD.
///
/// A fresh AES-GCM nonce and domain-separated key/AAD prevent ciphertext substitution between
/// protocol contexts.
///
/// # Errors
///
/// Returns `invalid_token_response` when randomness, encryption, or COSE serialization fails.
pub fn encode_cose_encrypt0(
    plaintext: &[u8],
    artifact: EncryptedArtifact,
) -> Result<String, OAuthError> {
    let nonce = generate_nonce()?;
    let cose = CoseEncrypt0Builder::new()
        .protected(
            HeaderBuilder::new()
                .algorithm(iana::Algorithm::A256GCM)
                .build(),
        )
        .unprotected(HeaderBuilder::new().iv(nonce.to_vec()).build())
        .try_create_ciphertext(plaintext, artifact.external_aad(), |plaintext, aad| {
            Config::key_manager()
                .encrypt_aes_gcm(plaintext, aad, nonce, artifact)
                .map_err(|_| OAuthError::invalid_token_response("cose encryption failed"))
        })?
        .build();
    let cose_bytes = cose
        .to_vec()
        .map_err(|_| OAuthError::invalid_token_response("cose encryption failed"))?;

    Ok(URL_SAFE_NO_PAD.encode(cose_bytes))
}

/// Authenticates and decrypts COSE_Encrypt0 for the expected artifact domain.
///
/// The caller supplies descriptions for malformed COSE, missing nonce/ciphertext, and failed
/// decryption so higher-level resources can map them to their protocol domain.
///
/// # Errors
///
/// Returns an OAuth error when base64url/COSE parsing, required fields, artifact authentication, or
/// AES-GCM decryption fails.
pub fn decode_cose_encrypt0(
    encoded_cose: &str,
    artifact: EncryptedArtifact,
    errors: CoseEncrypt0Errors,
) -> Result<Vec<u8>, OAuthError> {
    let cose_bytes = URL_SAFE_NO_PAD
        .decode(encoded_cose)
        .map_err(|_| OAuthError::invalid_authorization_code(errors.invalid_cose))?;
    let cose = CoseEncrypt0::from_slice(&cose_bytes)
        .map_err(|_| OAuthError::invalid_authorization_code(errors.invalid_cose))?;
    let nonce = cose_nonce(&cose, errors.missing_nonce)?;

    cose.decrypt_ciphertext(
        artifact.external_aad(),
        || OAuthError::invalid_authorization_code(errors.missing_ciphertext),
        |ciphertext, aad| {
            Config::key_manager()
                .decrypt_aes_gcm(ciphertext, aad, nonce, artifact)
                .map_err(|_| OAuthError::invalid_authorization_code(errors.decryption_failed))
        },
    )
}

fn generate_nonce() -> Result<[u8; AES_GCM_NONCE_LEN], OAuthError> {
    let rng = SystemRandom::new();
    let mut nonce = [0; AES_GCM_NONCE_LEN];
    rng.fill(&mut nonce)
        .map_err(|_| OAuthError::invalid_token_response("cose encryption failed"))?;

    Ok(nonce)
}

fn cose_nonce(
    cose: &CoseEncrypt0,
    missing_nonce_error: &'static str,
) -> Result<[u8; AES_GCM_NONCE_LEN], OAuthError> {
    cose.unprotected
        .iv
        .as_slice()
        .try_into()
        .map_err(|_| OAuthError::invalid_authorization_code(missing_nonce_error))
}

#[cfg(test)]
mod tests {
    use jsonwebtoken::{Algorithm, Validation, decode, decode_header};
    use serde_json::{Value, json};

    use super::*;

    const ERRORS: CoseEncrypt0Errors = CoseEncrypt0Errors {
        invalid_cose: "invalid artifact",
        missing_ciphertext: "invalid artifact",
        missing_nonce: "invalid artifact",
        decryption_failed: "invalid artifact",
    };

    #[test]
    fn encrypts_and_decrypts_with_the_matching_artifact_context() {
        let encrypted =
            encode_cose_encrypt0(b"confidential", EncryptedArtifact::AccessToken).unwrap();

        assert_eq!(
            decode_cose_encrypt0(&encrypted, EncryptedArtifact::AccessToken, ERRORS).unwrap(),
            b"confidential"
        );
        assert!(
            decode_cose_encrypt0(&encrypted, EncryptedArtifact::CredentialAccessToken, ERRORS,)
                .is_err()
        );
    }

    #[test]
    fn signs_each_jwt_with_its_registered_key_and_algorithm() {
        for artifact in [
            SigningArtifact::Credential,
            SigningArtifact::IdToken,
            SigningArtifact::RequestObject,
        ] {
            let token = sign_jwt(&json!({"purpose": artifact.key_id()}), artifact).unwrap();
            let header = decode_header(&token).unwrap();
            let mut validation = Validation::new(artifact.algorithm());
            validation.required_spec_claims.clear();
            validation.validate_exp = false;
            validation.validate_aud = false;
            let claims = decode::<Value>(&token, &artifact.decoding_key().unwrap(), &validation)
                .unwrap()
                .claims;

            assert_eq!(header.kid.as_deref(), Some(artifact.key_id()));
            assert_eq!(claims["purpose"], artifact.key_id());
        }
    }

    #[test]
    fn does_not_accept_a_signature_from_another_registered_key() {
        let token = sign_jwt(&json!({"purpose": "id_token"}), SigningArtifact::IdToken).unwrap();
        let mut validation = Validation::new(Algorithm::EdDSA);
        validation.required_spec_claims.clear();
        validation.validate_exp = false;
        validation.validate_aud = false;

        assert!(
            decode::<Value>(
                &token,
                &SigningArtifact::Credential.decoding_key().unwrap(),
                &validation,
            )
            .is_err()
        );
    }
}
