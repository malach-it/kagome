use base64::{
    Engine,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use jsonwebtoken::jwk::{AlgorithmParameters, EllipticCurve};

use super::{JwkFields, parsed_public_key};

/// Encodes a supported public JWK as an OpenSSH public key line. Returns `None`
/// for unsupported key types or parameters that cannot be encoded.
pub(super) fn encode(fields: &JwkFields) -> Option<String> {
    let (_, jwk) = parsed_public_key(fields)?;
    let mut blob = Vec::new();
    let algorithm = match jwk.algorithm {
        AlgorithmParameters::OctetKeyPair(key) => {
            let algorithm = "ssh-ed25519";
            append_string(&mut blob, algorithm.as_bytes())?;
            append_string(&mut blob, &URL_SAFE_NO_PAD.decode(key.x).ok()?)?;
            algorithm
        }
        AlgorithmParameters::EllipticCurve(key) => {
            let (algorithm, curve, coordinate_size) = match key.curve {
                EllipticCurve::P256 => ("ecdsa-sha2-nistp256", "nistp256", 32),
                EllipticCurve::P384 => ("ecdsa-sha2-nistp384", "nistp384", 48),
                _ => return None,
            };
            let x = URL_SAFE_NO_PAD.decode(key.x).ok()?;
            let y = URL_SAFE_NO_PAD.decode(key.y).ok()?;
            if x.len() != coordinate_size || y.len() != coordinate_size {
                return None;
            }
            let mut point = vec![4]; // SEC 1 uncompressed point prefix.
            point.extend_from_slice(&x);
            point.extend_from_slice(&y);
            append_string(&mut blob, algorithm.as_bytes())?;
            append_string(&mut blob, curve.as_bytes())?;
            append_string(&mut blob, &point)?;
            algorithm
        }
        AlgorithmParameters::RSA(key) => {
            let algorithm = "ssh-rsa";
            append_string(&mut blob, algorithm.as_bytes())?;
            append_positive_mpint(&mut blob, &URL_SAFE_NO_PAD.decode(key.e).ok()?)?;
            append_positive_mpint(&mut blob, &URL_SAFE_NO_PAD.decode(key.n).ok()?)?;
            algorithm
        }
        AlgorithmParameters::OctetKey(_) => return None,
    };
    Some(format!("{algorithm} {}", STANDARD.encode(blob)))
}

fn append_string(blob: &mut Vec<u8>, bytes: &[u8]) -> Option<()> {
    let len = u32::try_from(bytes.len()).ok()?;
    blob.extend_from_slice(&len.to_be_bytes());
    blob.extend_from_slice(bytes);
    Some(())
}

fn append_positive_mpint(blob: &mut Vec<u8>, bytes: &[u8]) -> Option<()> {
    let start = bytes.iter().position(|&byte| byte != 0)?;
    let magnitude = &bytes[start..];
    let needs_sign_byte = *magnitude.first()? >= 128;
    if needs_sign_byte {
        let mut positive = vec![0];
        positive.extend_from_slice(magnitude);
        append_string(blob, &positive)
    } else {
        append_string(blob, magnitude)
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    // Ed25519 and legacy registry backfill are covered in tests/http_signature.rs.
    // These cover the other accepted representations and malformed parameters.
    #[test]
    fn encodes_ecdsa_keys_as_openssh_public_keys() {
        // Public keys and expected lines captured from OpenSSH ssh-keygen.
        for (algorithm, curve, x, y, expected) in [
            (
                "ES256",
                "P-256",
                "40v09wuUj3QzUy5Tk4JBoOJMLM3uES8FIvW0n6CMics",
                "KoH-IyJy1HxsK6n4FFEbRfbViAcvCF_eGnIwILqxLuE",
                concat!(
                    "ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBONL",
                    "9PcLlI90M1MuU5OCQaDiTCzN7hEvBSL1tJ+gjInLKoH+IyJy1HxsK6n4FFEbRfbViAcvCF/eGnIwILqxLuE="
                ),
            ),
            (
                "ES384",
                "P-384",
                "KHgtONxXDcLnUWLY1-LmJq8FIU98XayYbZfKLlvpetnRquJdgFEa7aS1eGWSuU7C",
                "OlNjughwgwb_oM0_8npKEoNBq0LEGNI3YkCDdKQ7p4ITjmeV_BEHO0w4shv38T02",
                concat!(
                    "ecdsa-sha2-nistp384 AAAAE2VjZHNhLXNoYTItbmlzdHAzODQAAAAIbmlzdHAzODQAAABhBCh4",
                    "LTjcVw3C51Fi2Nfi5iavBSFPfF2smG2Xyi5b6XrZ0ariXYBRGu2ktXhlkrlOwjpTY7oIcIMG/",
                    "6DNP/J6ShKDQatCxBjSN2JAg3SkO6eCE45nlfwRBztMOLIb9/E9Ng=="
                ),
            ),
        ] {
            let jwk = json!({"kty":"EC", "alg":algorithm, "crv":curve, "x":x, "y":y});
            assert_eq!(
                encode(&serde_json::from_value(jwk).unwrap()).as_deref(),
                Some(expected)
            );
        }
    }

    #[test]
    fn encodes_rsa_integers_with_one_sign_byte_when_needed() {
        let jwk = json!({"kty":"RSA", "alg":"RS256", "e":"AQAB", "n":"AACAAQ"});
        let encoded = encode(&serde_json::from_value(jwk).unwrap()).unwrap();
        let blob = STANDARD
            .decode(encoded.strip_prefix("ssh-rsa ").unwrap())
            .unwrap();
        assert_eq!(
            blob,
            b"\0\0\0\x07ssh-rsa\0\0\0\x03\x01\0\x01\0\0\0\x03\0\x80\x01"
        );
    }

    #[test]
    fn omits_keys_with_unsupported_or_malformed_parameters() {
        for jwk in [
            json!({"kty":"oct", "alg":"HS256", "k":"AQ"}),
            json!({"kty":"EC", "alg":"ES256", "crv":"P-256", "x":"AQ", "y":"AQ"}),
            json!({"kty":"RSA", "alg":"RS256", "e":"AQAB", "n":"AA"}),
        ] {
            assert!(encode(&serde_json::from_value(jwk).unwrap()).is_none());
        }
    }
}
