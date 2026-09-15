use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use serde::Serialize;

use crate::errors::OAuthError;

pub const KEY_ID: &str = "kagome-request-signing-key";
pub const PUBLIC_KEY_X: &str = "fZxTjqb9GBJdanaBB3uPe-vXcalkLVr6uokEndezZuI";
pub const PUBLIC_KEY_Y: &str = "KEthkspMaXerL9EPTAnHjr5PMCSv4P4G0HZG7UP8HPs";
pub const SIGNING_ALGORITHM: &str = "ES256";
pub const SELF_ISSUED_AUDIENCE: &str = "https://self-issued.me/v2";

const PRIVATE_KEY: &[u8] = b"-----BEGIN PRIVATE KEY-----\nMIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgVW2Jp8GefPD2+UXt\nbha/i609CuG2sBUhr+ReRUGWptKhRANCAAR9nFOOpv0YEl1qdoEHe49769dxqWQt\nWvq6iQSd17Nm4ihLYZLKTGl3qy/RD0wJx46+TzAkr+D+BtB2Ru1D/Bz7\n-----END PRIVATE KEY-----\n";

pub fn sign<T: Serialize>(claims: &T) -> Result<String, OAuthError> {
    let mut header = Header::new(Algorithm::ES256);
    header.kid = Some(KEY_ID.to_owned());

    encode(
        &header,
        claims,
        &EncodingKey::from_ec_pem(PRIVATE_KEY)
            .map_err(|_| OAuthError::invalid_token_response("request signing key is invalid"))?,
    )
    .map_err(|_| OAuthError::invalid_token_response("request object generation failed"))
}
