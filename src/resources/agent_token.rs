//! Verification of AAuth agent tokens against configured provider keys.

use std::collections::{BTreeMap, HashSet};

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use jsonwebtoken::{
    Algorithm, AlgorithmFamily, DecodingKey,
    crypto::verify,
    jwk::{AlgorithmParameters, EllipticCurve, Jwk, ThumbprintHash},
};
use serde::{Deserialize, de::DeserializeOwned};
use serde_json::Value;

use crate::{
    config::{AgentProviderConfig, AgentProviderJwks},
    errors::OAuthError,
};

mod jwks;
pub(super) mod registry;

pub const AGENT_TOKEN_TYPE: &str = "aa-agent+jwt";
const METADATA_DOCUMENT: &str = "aauth-agent.json";

type JwkFields = BTreeMap<String, Value>;

#[derive(Deserialize)]
struct TokenHeader {
    typ: String,
    alg: String,
    kid: String,
    crit: Option<Vec<String>>,
    b64: Option<bool>,
}

#[derive(Deserialize)]
struct Issuer {
    iss: String,
}

#[derive(Deserialize)]
struct Claims {
    iss: String,
    sub: String,
    dwk: String,
    jti: String,
    iat: u64,
    exp: u64,
    cnf: Confirmation,
    ps: Option<String>,
    parent_agent: Option<String>,
}

#[derive(Deserialize)]
struct Confirmation {
    jwk: JwkFields,
}

/// The identity and confirmation key vouched for by a configured agent provider.
#[derive(Debug)]
pub struct VerifiedAgentToken {
    pub issuer: String,
    pub subject: String,
    pub public_jwk: JwkFields,
    key_thumbprint: String,
    expires_at: u64,
}

/// Checks that the provider has an inline key set, an HTTPS endpoint, or both.
/// Returns a configuration error message for invalid endpoints or pinned keys.
pub(crate) fn validate_provider_key_sources(
    provider: &AgentProviderConfig,
) -> Result<(), &'static str> {
    if provider.jwks.is_none() && provider.jwks_uri.is_none() {
        return Err("jwks or jwks_uri is required");
    }
    if let Some(uri) = &provider.jwks_uri
        && !jwks::valid_endpoint(uri)
    {
        return Err("jwks_uri must be an absolute HTTPS URL without userinfo or a fragment");
    }

    match &provider.jwks {
        Some(jwks) => validate_pinned_keys(jwks),
        None => Ok(()),
    }
}

fn validate_pinned_keys(jwks: &AgentProviderJwks) -> Result<(), &'static str> {
    if jwks.keys.is_empty() {
        return Err("jwks.keys must contain at least one public signing key");
    }
    let mut kids = HashSet::new();
    for key in &jwks.keys {
        let kid = key
            .get("kid")
            .and_then(Value::as_str)
            .filter(|kid| !kid.trim().is_empty())
            .ok_or("jwks.keys entries require a nonempty kid")?;
        if !kids.insert(kid) {
            return Err("jwks.keys kid values must be unique within the provider");
        }
        public_key(key)
            .ok_or("jwks.keys entries require a supported asymmetric public signing key")?;
    }
    Ok(())
}

/// Verifies the provider signature and agent claims before returning the agent
/// identity and the key needed for HTTP message signature verification.
/// Returns `invalid_request` for invalid claims, unknown issuers or keys,
/// unsupported algorithms, or a bad signature.
pub(super) fn verify_token(
    jwt: &str,
    providers: &[AgentProviderConfig],
    now: u64,
) -> Result<VerifiedAgentToken, OAuthError> {
    let (message, signature) = jwt.rsplit_once('.').ok_or_else(malformed)?;
    let (header, payload) = message.split_once('.').ok_or_else(malformed)?;
    let header: TokenHeader = decode_part(header).ok_or_else(malformed)?;
    if header.typ != AGENT_TOKEN_TYPE || header.kid.trim().is_empty() {
        return Err(invalid(
            "agent token must use aa-agent+jwt and include a kid",
        ));
    }

    if header.crit.is_some() || header.b64 == Some(false) {
        return Err(invalid(
            "agent token uses unsupported JOSE header parameters",
        ));
    }

    let issuer: Issuer = decode_part(payload).ok_or_else(malformed)?;
    let mut matching_providers = providers
        .iter()
        .filter(|provider| provider.issuer == issuer.iss);
    let provider = match (matching_providers.next(), matching_providers.next()) {
        (Some(provider), None) => provider,
        _ => return Err(invalid("agent token issuer is not trusted")),
    };
    let pinned_keys = provider.jwks.as_ref().map_or(&[][..], |jwks| &jwks.keys);
    let remote_key;
    let key = match jwks::find_key(pinned_keys, &header.kid)? {
        Some(key) => key,
        None => {
            remote_key = jwks::remote_key(provider, &header.kid)?;
            &remote_key
        }
    };
    if key.get("alg").and_then(Value::as_str) != Some(header.alg.as_str()) {
        return Err(invalid(
            "agent token algorithm does not match the provider key",
        ));
    }
    let (algorithm, key) =
        public_key(key).ok_or_else(|| invalid("agent token provider key is invalid"))?;
    if !verify(signature, message.as_bytes(), &key, algorithm).unwrap_or(false) {
        return Err(invalid("agent token provider signature is invalid"));
    }

    let claims: Claims = decode_part(payload).ok_or_else(malformed)?;
    if claims.exp <= now || claims.exp <= claims.iat {
        return Err(invalid("agent token expiration is invalid"));
    }
    let domain = claims.iss.strip_prefix("https://").ok_or_else(malformed)?;
    if claims.dwk != METADATA_DOCUMENT
        || claims.jti.trim().is_empty()
        || !valid_server_identifier(&claims.iss)
        || agent_domain(&claims.sub) != Some(domain)
        || claims
            .ps
            .as_deref()
            .is_some_and(|ps| !valid_server_identifier(ps))
        || claims
            .parent_agent
            .as_deref()
            .is_some_and(|parent| agent_domain(parent).is_none())
    {
        return Err(malformed());
    }
    let (_, agent_jwk) = parsed_public_key(&claims.cnf.jwk)
        .filter(|(_, jwk)| DecodingKey::from_jwk(jwk).is_ok())
        .ok_or_else(|| invalid("agent token cnf.jwk must be an asymmetric public signing key"))?;

    Ok(VerifiedAgentToken {
        issuer: claims.iss,
        subject: claims.sub,
        public_jwk: claims.cnf.jwk,
        key_thumbprint: agent_jwk.thumbprint(ThumbprintHash::SHA256),
        expires_at: claims.exp,
    })
}

fn decode_part<T: DeserializeOwned>(encoded: &str) -> Option<T> {
    let bytes = URL_SAFE_NO_PAD.decode(encoded).ok()?;
    serde_json::from_slice(&bytes).ok()
}

fn public_key(fields: &JwkFields) -> Option<(Algorithm, DecodingKey)> {
    let (algorithm, jwk) = parsed_public_key(fields)?;
    Some((algorithm, DecodingKey::from_jwk(&jwk).ok()?))
}

fn parsed_public_key(fields: &JwkFields) -> Option<(Algorithm, Jwk)> {
    if ["k", "d", "p", "q", "dp", "dq", "qi", "oth"]
        .iter()
        .any(|name| fields.contains_key(*name))
        || fields.get("use").is_some_and(|value| value.as_str() != Some("sig"))
        || fields.get("key_ops").is_some_and(|value| {
            !matches!(value.as_array().map(Vec::as_slice), Some([operation]) if operation.as_str() == Some("verify"))
        })
    {
        return None;
    }

    let algorithm = match fields.get("alg")?.as_str()? {
        "Ed25519" => Algorithm::EdDSA,
        "EdDSA" => return None,
        value => value.parse().ok()?,
    };
    let mut key_fields = fields.clone();
    // jsonwebtoken names its Ed25519 primitive EdDSA. Keep the wire identifier
    // exact and use the library name only for the cryptographic operation.
    key_fields.remove("alg");
    let jwk: Jwk = serde_json::from_value(serde_json::to_value(key_fields).ok()?).ok()?;
    let compatible = match &jwk.algorithm {
        AlgorithmParameters::RSA(_) => algorithm.family() == AlgorithmFamily::Rsa,
        AlgorithmParameters::EllipticCurve(key) => matches!(
            (&key.curve, algorithm),
            (EllipticCurve::P256, Algorithm::ES256) | (EllipticCurve::P384, Algorithm::ES384)
        ),
        AlgorithmParameters::OctetKeyPair(key) => {
            key.curve == EllipticCurve::Ed25519
                && algorithm == Algorithm::EdDSA
                && URL_SAFE_NO_PAD
                    .decode(&key.x)
                    .is_ok_and(|bytes| bytes.len() == 32)
        }
        AlgorithmParameters::OctetKey(_) => false,
    };
    if !compatible {
        return None;
    }
    Some((algorithm, jwk))
}

pub(crate) fn valid_server_identifier(issuer: &str) -> bool {
    issuer.strip_prefix("https://").is_some_and(valid_domain)
}

fn agent_domain(identifier: &str) -> Option<&str> {
    let (local, domain) = identifier.strip_prefix("aauth:")?.split_once('@')?;
    (!local.is_empty()
        && local.len() <= 255
        && local
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"-_+.".contains(&byte))
        && valid_domain(domain))
    .then_some(domain)
}

fn valid_domain(domain: &str) -> bool {
    domain.len() <= 253
        && domain.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        })
}

fn invalid(description: &str) -> OAuthError {
    OAuthError::invalid_request(description)
}

fn malformed() -> OAuthError {
    invalid("agent token is malformed or has invalid claims")
}
