use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use jsonwebtoken::{
    AlgorithmFamily, DecodingKey, Validation, decode, decode_header, get_current_timestamp,
};
use serde::Deserialize;
use serde_json::Value;

use crate::errors::OAuthError;

use super::self_issued_id_token;

const MAX_PROOF_AGE_SECONDS: f64 = 300.0;
const CLOCK_SKEW_SECONDS: f64 = 60.0;

#[derive(Debug)]
pub struct ValidatedCredentialProof {
    pub subject: String,
    pub jwk: Value,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CredentialProof {
    proof_type: String,
    jwt: String,
}

#[derive(Deserialize)]
struct CredentialProofClaims {
    iss: String,
    sub: String,
    aud: Value,
    iat: f64,
}

#[derive(Deserialize)]
struct ProofIssuer {
    iss: String,
}

pub trait Validate {
    fn request_proof(&self) -> Option<&Value>;
    fn credential_issuer(&self) -> Option<&str>;
    fn add_validated_credential_proof(&mut self, proof: ValidatedCredentialProof);
}

pub fn validate_optional<T: Validate>(mut request: T) -> Result<T, OAuthError> {
    let Some(proof) = request.request_proof() else {
        return Ok(request);
    };
    let proof: CredentialProof = serde_json::from_value(proof.clone())
        .map_err(|_| invalid("proof must contain proof_type and jwt"))?;
    if proof.proof_type != "jwt" {
        return Err(invalid("proof_type must be jwt"));
    }

    let header = decode_header(&proof.jwt).map_err(|_| invalid("proof jwt is invalid"))?;
    if header.alg.family() == AlgorithmFamily::Hmac {
        return Err(invalid("proof jwt algorithm must be asymmetric"));
    }
    let issuer = decode_unverified_issuer(&proof.jwt)?;
    let jwk = match header.jwk {
        Some(jwk) => {
            serde_json::to_value(jwk).map_err(|_| invalid("proof jwt header jwk is invalid"))?
        }
        None => {
            let kid = header
                .kid
                .as_deref()
                .ok_or_else(|| invalid("proof jwt header must include jwk or a did:key kid"))?;
            if !issuer.iss.starts_with("did:key:")
                || !(kid == issuer.iss
                    || kid
                        .strip_prefix(&issuer.iss)
                        .is_some_and(|fragment| fragment.starts_with('#')))
            {
                return Err(invalid("proof jwt kid must identify the issuer did:key"));
            }
            self_issued_id_token::did_key_jwk(&issuer.iss)
                .map_err(|_| invalid("proof jwt kid must contain a valid P-256 did:key"))?
        }
    };
    let key: jsonwebtoken::jwk::Jwk = serde_json::from_value(jwk.clone())
        .map_err(|_| invalid("proof jwt public key is invalid"))?;
    let mut validation = Validation::new(header.alg);
    validation.required_spec_claims.clear();
    validation.validate_exp = false;
    validation.validate_aud = false;
    let claims = decode::<CredentialProofClaims>(
        &proof.jwt,
        &DecodingKey::from_jwk(&key).map_err(|_| invalid("proof jwt public key is invalid"))?,
        &validation,
    )
    .map_err(|_| invalid("proof jwt signature is invalid"))?
    .claims;

    if claims.iss != claims.sub {
        return Err(invalid("proof jwt issuer must equal subject"));
    }
    let credential_issuer = request
        .credential_issuer()
        .ok_or_else(|| invalid("credential issuer must be validated before proof"))?;
    if !audience_contains(&claims.aud, credential_issuer) {
        return Err(invalid("proof jwt audience is invalid"));
    }
    let now = get_current_timestamp() as f64;
    if claims.iat > now + CLOCK_SKEW_SECONDS || claims.iat + MAX_PROOF_AGE_SECONDS < now {
        return Err(invalid("proof jwt iat is invalid"));
    }

    request.add_validated_credential_proof(ValidatedCredentialProof {
        subject: claims.sub,
        jwk,
    });
    Ok(request)
}

fn decode_unverified_issuer(token: &str) -> Result<ProofIssuer, OAuthError> {
    let mut segments = token.split('.');
    let _header = segments.next();
    let payload = segments
        .next()
        .ok_or_else(|| invalid("proof jwt is invalid"))?;
    if segments.next().is_none() || segments.next().is_some() {
        return Err(invalid("proof jwt is invalid"));
    }
    let payload = URL_SAFE_NO_PAD
        .decode(payload)
        .map_err(|_| invalid("proof jwt claims are invalid"))?;

    serde_json::from_slice(&payload).map_err(|_| invalid("proof jwt claims are invalid"))
}

fn audience_contains(audience: &Value, expected: &str) -> bool {
    audience.as_str() == Some(expected)
        || audience
            .as_array()
            .is_some_and(|values| values.iter().any(|value| value.as_str() == Some(expected)))
}

fn invalid(description: &str) -> OAuthError {
    OAuthError::invalid_credential_request(description)
}
