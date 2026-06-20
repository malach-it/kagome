use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use coset::{
    CborSerializable, CoseEncrypt0, CoseEncrypt0Builder, HeaderBuilder, Label, cbor::value::Value,
    iana,
};
use ring::{
    aead::{self, Aad, LessSafeKey, Nonce, UnboundKey},
    agreement, digest,
    rand::{SecureRandom, SystemRandom},
};

use crate::errors::OAuthError;

const AES_GCM_NONCE_LEN: usize = 12;
const COSE_SENDER_PUBLIC_KEY_HEADER: &str = "kagome_sender_public_key";

pub const ASYMMETRIC_CLIENT_ENCRYPTION_ALG: &str = "ECDH-ES+A256GCM";

#[derive(Clone, Copy)]
pub struct CoseEncrypt0Errors {
    pub invalid_cose: &'static str,
    pub missing_ciphertext: &'static str,
    pub missing_nonce: &'static str,
    pub decryption_failed: &'static str,
}

pub struct AsymmetricKeyPair {
    private_key: agreement::EphemeralPrivateKey,
    public_key: String,
}

impl AsymmetricKeyPair {
    pub fn public_key(&self) -> &str {
        &self.public_key
    }
}

pub fn generate_asymmetric_key_pair() -> Result<AsymmetricKeyPair, OAuthError> {
    let rng = SystemRandom::new();
    let private_key =
        agreement::EphemeralPrivateKey::generate(&agreement::X25519, &rng).map_err(|_| {
            OAuthError::invalid_token_response("client encryption key generation failed")
        })?;
    let public_key = private_key.compute_public_key().map_err(|_| {
        OAuthError::invalid_token_response("client encryption key generation failed")
    })?;

    Ok(AsymmetricKeyPair {
        private_key,
        public_key: URL_SAFE_NO_PAD.encode(public_key.as_ref()),
    })
}

pub fn encode_cose_encrypt0(
    plaintext: &[u8],
    secret: &str,
    external_aad: &[u8],
) -> Result<String, OAuthError> {
    let nonce = generate_nonce()?;
    let cose = CoseEncrypt0Builder::new()
        .protected(
            HeaderBuilder::new()
                .algorithm(iana::Algorithm::A256GCM)
                .build(),
        )
        .unprotected(HeaderBuilder::new().iv(nonce.to_vec()).build())
        .try_create_ciphertext(plaintext, external_aad, |plaintext, aad| {
            encrypt_aes_gcm(plaintext, aad, nonce, secret)
        })?
        .build();
    let cose_bytes = cose
        .to_vec()
        .map_err(|_| OAuthError::invalid_token_response("cose encryption failed"))?;

    Ok(URL_SAFE_NO_PAD.encode(cose_bytes))
}

pub fn decode_cose_encrypt0(
    encoded_cose: &str,
    secret: &str,
    external_aad: &[u8],
    errors: CoseEncrypt0Errors,
) -> Result<Vec<u8>, OAuthError> {
    let cose_bytes = URL_SAFE_NO_PAD
        .decode(encoded_cose)
        .map_err(|_| OAuthError::invalid_authorization_code(errors.invalid_cose))?;
    let cose = CoseEncrypt0::from_slice(&cose_bytes)
        .map_err(|_| OAuthError::invalid_authorization_code(errors.invalid_cose))?;
    let nonce = cose_nonce(&cose, errors.missing_nonce)?;

    cose.decrypt_ciphertext(
        external_aad,
        || OAuthError::invalid_authorization_code(errors.missing_ciphertext),
        |ciphertext, aad| decrypt_aes_gcm(ciphertext, aad, nonce, secret, errors.decryption_failed),
    )
}

pub fn encode_cose_encrypt0_for_public_key(
    plaintext: &[u8],
    recipient_public_key: &str,
    external_aad: &[u8],
) -> Result<String, OAuthError> {
    let recipient_public_key = URL_SAFE_NO_PAD.decode(recipient_public_key).map_err(|_| {
        OAuthError::invalid_token_response("client_encryption_key must be an x25519 public key")
    })?;
    let sender_key_pair = generate_asymmetric_key_pair()?;
    let sender_public_key = URL_SAFE_NO_PAD
        .decode(sender_key_pair.public_key())
        .map_err(|_| OAuthError::invalid_token_response("cose encryption failed"))?;
    let secret = derive_shared_secret(sender_key_pair.private_key, &recipient_public_key)
        .map_err(|_| OAuthError::invalid_token_response("cose encryption failed"))?;
    let nonce = generate_nonce()?;
    let cose = CoseEncrypt0Builder::new()
        .protected(
            HeaderBuilder::new()
                .algorithm(iana::Algorithm::A256GCM)
                .build(),
        )
        .unprotected(
            HeaderBuilder::new()
                .iv(nonce.to_vec())
                .text_value(
                    COSE_SENDER_PUBLIC_KEY_HEADER.to_owned(),
                    Value::Bytes(sender_public_key),
                )
                .build(),
        )
        .try_create_ciphertext(plaintext, external_aad, |plaintext, aad| {
            encrypt_aes_gcm_with_secret(plaintext, aad, nonce, &secret)
        })?
        .build();
    let cose_bytes = cose
        .to_vec()
        .map_err(|_| OAuthError::invalid_token_response("cose encryption failed"))?;

    Ok(URL_SAFE_NO_PAD.encode(cose_bytes))
}

pub fn decode_cose_encrypt0_with_private_key(
    encoded_cose: &str,
    recipient_key_pair: AsymmetricKeyPair,
    external_aad: &[u8],
    errors: CoseEncrypt0Errors,
) -> Result<Vec<u8>, OAuthError> {
    let cose_bytes = URL_SAFE_NO_PAD
        .decode(encoded_cose)
        .map_err(|_| OAuthError::invalid_authorization_code(errors.invalid_cose))?;
    let cose = CoseEncrypt0::from_slice(&cose_bytes)
        .map_err(|_| OAuthError::invalid_authorization_code(errors.invalid_cose))?;
    let nonce = cose_nonce(&cose, errors.missing_nonce)?;
    let sender_public_key = cose_sender_public_key(&cose, errors.invalid_cose)?;
    let secret = derive_shared_secret(recipient_key_pair.private_key, sender_public_key)
        .map_err(|_| OAuthError::invalid_authorization_code(errors.decryption_failed))?;

    cose.decrypt_ciphertext(
        external_aad,
        || OAuthError::invalid_authorization_code(errors.missing_ciphertext),
        |ciphertext, aad| {
            decrypt_aes_gcm_with_secret(ciphertext, aad, nonce, &secret, errors.decryption_failed)
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

fn encrypt_aes_gcm(
    plaintext: &[u8],
    aad: &[u8],
    nonce: [u8; AES_GCM_NONCE_LEN],
    secret: &str,
) -> Result<Vec<u8>, OAuthError> {
    let key = aes_gcm_key(secret.as_bytes())
        .map_err(|_| OAuthError::invalid_token_response("cose encryption failed"))?;
    encrypt_aes_gcm_with_key(plaintext, aad, nonce, key)
}

fn encrypt_aes_gcm_with_secret(
    plaintext: &[u8],
    aad: &[u8],
    nonce: [u8; AES_GCM_NONCE_LEN],
    secret: &[u8],
) -> Result<Vec<u8>, OAuthError> {
    let key = aes_gcm_key(secret)
        .map_err(|_| OAuthError::invalid_token_response("cose encryption failed"))?;
    encrypt_aes_gcm_with_key(plaintext, aad, nonce, key)
}

fn encrypt_aes_gcm_with_key(
    plaintext: &[u8],
    aad: &[u8],
    nonce: [u8; AES_GCM_NONCE_LEN],
    key: LessSafeKey,
) -> Result<Vec<u8>, OAuthError> {
    let mut ciphertext = plaintext.to_vec();
    key.seal_in_place_append_tag(
        Nonce::assume_unique_for_key(nonce),
        Aad::from(aad),
        &mut ciphertext,
    )
    .map_err(|_| OAuthError::invalid_token_response("cose encryption failed"))?;

    Ok(ciphertext)
}

fn decrypt_aes_gcm(
    ciphertext: &[u8],
    aad: &[u8],
    nonce: [u8; AES_GCM_NONCE_LEN],
    secret: &str,
    decryption_failed_error: &'static str,
) -> Result<Vec<u8>, OAuthError> {
    let key = aes_gcm_key(secret.as_bytes())
        .map_err(|_| OAuthError::invalid_authorization_code(decryption_failed_error))?;
    decrypt_aes_gcm_with_key(ciphertext, aad, nonce, key, decryption_failed_error)
}

fn decrypt_aes_gcm_with_secret(
    ciphertext: &[u8],
    aad: &[u8],
    nonce: [u8; AES_GCM_NONCE_LEN],
    secret: &[u8],
    decryption_failed_error: &'static str,
) -> Result<Vec<u8>, OAuthError> {
    let key = aes_gcm_key(secret)
        .map_err(|_| OAuthError::invalid_authorization_code(decryption_failed_error))?;
    decrypt_aes_gcm_with_key(ciphertext, aad, nonce, key, decryption_failed_error)
}

fn decrypt_aes_gcm_with_key(
    ciphertext: &[u8],
    aad: &[u8],
    nonce: [u8; AES_GCM_NONCE_LEN],
    key: LessSafeKey,
    decryption_failed_error: &'static str,
) -> Result<Vec<u8>, OAuthError> {
    let mut plaintext = ciphertext.to_vec();
    let plaintext = key
        .open_in_place(
            Nonce::assume_unique_for_key(nonce),
            Aad::from(aad),
            &mut plaintext,
        )
        .map_err(|_| OAuthError::invalid_authorization_code(decryption_failed_error))?;

    Ok(plaintext.to_vec())
}

fn derive_shared_secret(
    private_key: agreement::EphemeralPrivateKey,
    peer_public_key: &[u8],
) -> Result<Vec<u8>, ring::error::Unspecified> {
    let peer_public_key = agreement::UnparsedPublicKey::new(&agreement::X25519, peer_public_key);

    agreement::agree_ephemeral(private_key, &peer_public_key, |shared_secret| {
        digest::digest(&digest::SHA256, shared_secret)
            .as_ref()
            .to_vec()
    })
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

fn cose_sender_public_key<'a>(
    cose: &'a CoseEncrypt0,
    invalid_cose_error: &'static str,
) -> Result<&'a [u8], OAuthError> {
    cose.unprotected
        .rest
        .iter()
        .find_map(|(label, value)| match (label, value) {
            (Label::Text(label), Value::Bytes(public_key))
                if label == COSE_SENDER_PUBLIC_KEY_HEADER =>
            {
                Some(public_key.as_slice())
            }
            _ => None,
        })
        .ok_or_else(|| OAuthError::invalid_authorization_code(invalid_cose_error))
}

fn aes_gcm_key(secret: &[u8]) -> Result<LessSafeKey, ring::error::Unspecified> {
    let key = digest::digest(&digest::SHA256, secret);
    let unbound_key = UnboundKey::new(&aead::AES_256_GCM, key.as_ref())?;

    Ok(LessSafeKey::new(unbound_key))
}
