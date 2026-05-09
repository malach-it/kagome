use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use coset::{CborSerializable, CoseEncrypt0, CoseEncrypt0Builder, HeaderBuilder, iana};
use ring::{
    aead::{self, Aad, LessSafeKey, Nonce, UnboundKey},
    digest,
    rand::{SecureRandom, SystemRandom},
};

use crate::errors::OAuthError;

const AES_GCM_NONCE_LEN: usize = 12;

#[derive(Clone, Copy)]
pub struct CoseEncrypt0Errors {
    pub invalid_cose: &'static str,
    pub missing_ciphertext: &'static str,
    pub missing_nonce: &'static str,
    pub decryption_failed: &'static str,
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
    let key = aes_gcm_key(secret)
        .map_err(|_| OAuthError::invalid_token_response("cose encryption failed"))?;
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
    let key = aes_gcm_key(secret)
        .map_err(|_| OAuthError::invalid_authorization_code(decryption_failed_error))?;
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

fn aes_gcm_key(secret: &str) -> Result<LessSafeKey, ring::error::Unspecified> {
    let key = digest::digest(&digest::SHA256, secret.as_bytes());
    let unbound_key = UnboundKey::new(&aead::AES_256_GCM, key.as_ref())?;

    Ok(LessSafeKey::new(unbound_key))
}
