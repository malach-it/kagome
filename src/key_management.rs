use std::{fmt, fs, io, path::Path};

use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation, decode, encode};
use ring::{
    aead::{self, Aad, LessSafeKey, Nonce, UnboundKey},
    digest,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;

pub(crate) const AES_GCM_NONCE_LEN: usize = 12;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EncryptedArtifact {
    AccessToken,
    AuthorizationCode,
    CredentialAccessToken,
    FederationState,
    PreAuthorizedCode,
    PresentationState,
    Siopv2State,
}

impl EncryptedArtifact {
    pub(crate) fn external_aad(self) -> &'static [u8] {
        match self {
            Self::AccessToken => b"kagome.access_token",
            Self::AuthorizationCode => b"kagome.authorization_code",
            Self::CredentialAccessToken => b"kagome.credential_access_token",
            Self::FederationState => b"kagome.federation_state",
            Self::PreAuthorizedCode => b"kagome.pre_authorized_code",
            Self::PresentationState => b"kagome:openid4vp:presentation-state:v1",
            Self::Siopv2State => b"kagome:siopv2:authorization-state:v1",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SigningArtifact {
    Credential,
    IdToken,
    RequestObject,
}

impl SigningArtifact {
    pub fn algorithm(self) -> Algorithm {
        match self {
            Self::RequestObject => Algorithm::ES256,
            Self::Credential | Self::IdToken => Algorithm::EdDSA,
        }
    }

    pub fn algorithm_name(self) -> &'static str {
        match self {
            Self::RequestObject => "ES256",
            Self::Credential | Self::IdToken => "EdDSA",
        }
    }

    pub fn key_id(self) -> &'static str {
        match self {
            Self::Credential => "kagome-credential-signing-key",
            Self::IdToken => "kagome-id-token-signing-key",
            Self::RequestObject => "kagome-request-signing-key",
        }
    }
}

#[derive(Default, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
struct KeyFile {
    encryption: EncryptionSecrets,
    signing: SigningKeys,
}

#[derive(Default, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
struct EncryptionSecrets {
    access_token: String,
    authorization_code: String,
    credential_access_token: String,
    federation_state: String,
    pre_authorized_code: String,
    presentation_state: String,
    siopv2_state: String,
}

#[derive(Default, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
struct SigningKeys {
    credential: SigningKeyPair,
    id_token: SigningKeyPair,
    request_object: SigningKeyPair,
}

#[derive(Default, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
struct SigningKeyPair {
    private_key: String,
    public_jwk: Value,
}

#[derive(Default, Eq, PartialEq)]
pub(crate) struct KeyManager {
    keys: KeyFile,
}

impl fmt::Debug for KeyManager {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("KeyManager")
            .field("encryption", &"<redacted>")
            .field("signing_private_keys", &"<redacted>")
            .field(
                "signing_public_jwks",
                &[
                    &self.keys.signing.credential.public_jwk,
                    &self.keys.signing.id_token.public_jwk,
                    &self.keys.signing.request_object.public_jwk,
                ],
            )
            .finish()
    }
}

impl KeyManager {
    pub(crate) fn load(path: &Path) -> Result<Self, KeyManagementError> {
        let yaml = fs::read_to_string(path).map_err(KeyManagementError::Read)?;
        Self::from_yaml(&yaml)
    }

    pub(crate) fn from_yaml(yaml: &str) -> Result<Self, KeyManagementError> {
        let keys = serde_yaml_ng::from_str(yaml).map_err(KeyManagementError::Parse)?;
        let manager = Self { keys };
        manager.validate().map_err(KeyManagementError::Validation)?;
        Ok(manager)
    }

    pub(crate) fn encrypt_aes_gcm(
        &self,
        plaintext: &[u8],
        aad: &[u8],
        nonce: [u8; AES_GCM_NONCE_LEN],
        artifact: EncryptedArtifact,
    ) -> Result<Vec<u8>, ring::error::Unspecified> {
        let key = self.aes_gcm_key(artifact)?;
        let mut ciphertext = plaintext.to_vec();
        key.seal_in_place_append_tag(
            Nonce::assume_unique_for_key(nonce),
            Aad::from(aad),
            &mut ciphertext,
        )?;

        Ok(ciphertext)
    }

    pub(crate) fn decrypt_aes_gcm(
        &self,
        ciphertext: &[u8],
        aad: &[u8],
        nonce: [u8; AES_GCM_NONCE_LEN],
        artifact: EncryptedArtifact,
    ) -> Result<Vec<u8>, ring::error::Unspecified> {
        let key = self.aes_gcm_key(artifact)?;
        let mut plaintext = ciphertext.to_vec();
        let plaintext = key.open_in_place(
            Nonce::assume_unique_for_key(nonce),
            Aad::from(aad),
            &mut plaintext,
        )?;

        Ok(plaintext.to_vec())
    }

    fn encryption_secret(&self, artifact: EncryptedArtifact) -> &str {
        let secrets = &self.keys.encryption;
        match artifact {
            EncryptedArtifact::AccessToken => &secrets.access_token,
            EncryptedArtifact::AuthorizationCode => &secrets.authorization_code,
            EncryptedArtifact::CredentialAccessToken => &secrets.credential_access_token,
            EncryptedArtifact::FederationState => &secrets.federation_state,
            EncryptedArtifact::PreAuthorizedCode => &secrets.pre_authorized_code,
            EncryptedArtifact::PresentationState => &secrets.presentation_state,
            EncryptedArtifact::Siopv2State => &secrets.siopv2_state,
        }
    }

    fn aes_gcm_key(
        &self,
        artifact: EncryptedArtifact,
    ) -> Result<LessSafeKey, ring::error::Unspecified> {
        let key = digest::digest(&digest::SHA256, self.encryption_secret(artifact).as_bytes());
        let unbound_key = UnboundKey::new(&aead::AES_256_GCM, key.as_ref())?;

        Ok(LessSafeKey::new(unbound_key))
    }

    pub(crate) fn sign<T: Serialize>(
        &self,
        claims: &T,
        artifact: SigningArtifact,
    ) -> Result<String, jsonwebtoken::errors::Error> {
        let mut header = Header::new(artifact.algorithm());
        header.kid = Some(artifact.key_id().to_owned());
        encode(&header, claims, &self.encoding_key(artifact)?)
    }

    pub(crate) fn public_jwk(&self, artifact: SigningArtifact) -> Value {
        self.key_pair(artifact).public_jwk.clone()
    }

    pub(crate) fn decoding_key(
        &self,
        artifact: SigningArtifact,
    ) -> Result<DecodingKey, jsonwebtoken::errors::Error> {
        DecodingKey::from_jwk(&serde_json::from_value(self.public_jwk(artifact))?)
    }

    fn key_pair(&self, artifact: SigningArtifact) -> &SigningKeyPair {
        match artifact {
            SigningArtifact::Credential => &self.keys.signing.credential,
            SigningArtifact::IdToken => &self.keys.signing.id_token,
            SigningArtifact::RequestObject => &self.keys.signing.request_object,
        }
    }

    fn encoding_key(
        &self,
        artifact: SigningArtifact,
    ) -> Result<EncodingKey, jsonwebtoken::errors::Error> {
        let pem = self.key_pair(artifact).private_key.as_bytes();
        match artifact {
            SigningArtifact::RequestObject => EncodingKey::from_ec_pem(pem),
            SigningArtifact::Credential | SigningArtifact::IdToken => EncodingKey::from_ed_pem(pem),
        }
    }

    fn validate(&self) -> Result<(), String> {
        let artifacts = [
            EncryptedArtifact::AccessToken,
            EncryptedArtifact::AuthorizationCode,
            EncryptedArtifact::CredentialAccessToken,
            EncryptedArtifact::FederationState,
            EncryptedArtifact::PreAuthorizedCode,
            EncryptedArtifact::PresentationState,
            EncryptedArtifact::Siopv2State,
        ];
        for artifact in artifacts {
            if self.encryption_secret(artifact).trim().is_empty() {
                return Err(format!(
                    "encryption.{} must not be empty",
                    encrypted_name(artifact)
                ));
            }
        }
        for (index, artifact) in artifacts.iter().enumerate() {
            for other in artifacts.iter().skip(index + 1) {
                if self.encryption_secret(*artifact) == self.encryption_secret(*other) {
                    return Err(format!(
                        "encryption.{} and encryption.{} must use distinct secrets",
                        encrypted_name(*artifact),
                        encrypted_name(*other)
                    ));
                }
            }
        }
        for artifact in [
            SigningArtifact::Credential,
            SigningArtifact::IdToken,
            SigningArtifact::RequestObject,
        ] {
            self.validate_signing_key(artifact)?;
        }
        Ok(())
    }

    fn validate_signing_key(&self, artifact: SigningArtifact) -> Result<(), String> {
        let pair = self.key_pair(artifact);
        let name = artifact.key_id();
        if pair.private_key.trim().is_empty() {
            return Err(format!("signing key {name} private_key must not be empty"));
        }
        let jwk = pair
            .public_jwk
            .as_object()
            .ok_or_else(|| format!("signing key {name} public_jwk must be an object"))?;
        if ["d", "k", "p", "q", "dp", "dq", "qi", "oth"]
            .iter()
            .any(|field| jwk.contains_key(*field))
        {
            return Err(format!(
                "signing key {name} public_jwk must not contain private key material"
            ));
        }
        for (field, expected) in [
            ("alg", artifact.algorithm_name()),
            ("kid", artifact.key_id()),
            ("use", "sig"),
        ] {
            if jwk.get(field).and_then(Value::as_str) != Some(expected) {
                return Err(format!(
                    "signing key {name} public_jwk.{field} must be {expected}"
                ));
            }
        }
        let (kty, crv) = match artifact {
            SigningArtifact::Credential | SigningArtifact::IdToken => ("OKP", "Ed25519"),
            SigningArtifact::RequestObject => ("EC", "P-256"),
        };
        if jwk.get("kty").and_then(Value::as_str) != Some(kty)
            || jwk.get("crv").and_then(Value::as_str) != Some(crv)
        {
            return Err(format!(
                "signing key {name} public_jwk must use {kty} {crv}"
            ));
        }
        let token = self
            .sign(&serde_json::json!({"key_validation": name}), artifact)
            .map_err(|_| format!("signing key {name} private_key is invalid"))?;
        let mut validation = Validation::new(artifact.algorithm());
        validation.required_spec_claims.clear();
        validation.validate_exp = false;
        validation.validate_aud = false;
        decode::<Value>(
            &token,
            &self
                .decoding_key(artifact)
                .map_err(|_| format!("signing key {name} public_jwk is invalid"))?,
            &validation,
        )
        .map_err(|_| format!("signing key {name} private_key does not match public_jwk"))?;
        Ok(())
    }
}

fn encrypted_name(artifact: EncryptedArtifact) -> &'static str {
    match artifact {
        EncryptedArtifact::AccessToken => "access_token",
        EncryptedArtifact::AuthorizationCode => "authorization_code",
        EncryptedArtifact::CredentialAccessToken => "credential_access_token",
        EncryptedArtifact::FederationState => "federation_state",
        EncryptedArtifact::PreAuthorizedCode => "pre_authorized_code",
        EncryptedArtifact::PresentationState => "presentation_state",
        EncryptedArtifact::Siopv2State => "siopv2_state",
    }
}

#[derive(Debug)]
pub(crate) enum KeyManagementError {
    Read(io::Error),
    Parse(serde_yaml_ng::Error),
    Validation(String),
}
