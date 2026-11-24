//! Signature-Key parsing and verification of provider-issued agent tokens.

use crate::{
    config::{AgentProviderConfig, Config},
    errors::OAuthError,
};

use super::agent_token::{VerifiedAgentToken, registry, verify_token};

mod signature_key;

pub use super::agent_token::AGENT_TOKEN_TYPE;
pub use signature_key::{KeyParameter, SignatureKey, parse_signature_key};

pub const SIGNATURE_KEY_HEADER: &str = "signature-key";

/// Provider-verified agent token associated with a Signature-Key label.
#[derive(Debug)]
pub struct VerifiedSignatureKey {
    pub label: String,
    pub agent_token: VerifiedAgentToken,
}

pub trait Validate {
    /// Header field values in wire order, including repeated field lines.
    fn signature_key_fields(&self) -> &[&str];
    fn add_verified_signature_keys(&mut self, keys: Vec<VerifiedSignatureKey>);
}

/// Validates the agent tokens in one required `Signature-Key` field line.
///
/// Each member must carry an agent token signed by a configured provider key.
/// Stores the verified identities and confirmation keys after all entries pass.
/// If a registry is configured, records the provider-attested keys before updating
/// the request state.
/// A subsequent step must verify the HTTP message signature with the corresponding
/// confirmation key before using the identity to authenticate the request.
///
/// # Errors
///
/// Returns `invalid_request` for missing, repeated, or malformed header fields,
/// unsupported schemes, invalid tokens, and untrusted providers or keys.
/// Returns `invalid_token_response` if the configured registry cannot be updated.
pub fn validate<T: Validate>(mut request: T) -> Result<T, OAuthError> {
    let field = match request.signature_key_fields() {
        [field] => field,
        [] => return Err(OAuthError::invalid_request("Signature-Key is required")),
        _ => {
            return Err(OAuthError::invalid_request(
                "Signature-Key must appear once",
            ));
        }
    };

    let providers = Config::trusted_agent_providers();
    let now = jsonwebtoken::get_current_timestamp();
    let keys = parse_signature_key(field)?
        .into_iter()
        .map(|entry| validate_entry(entry, providers, now))
        .collect::<Result<Vec<_>, _>>()?;
    if let Some(path) = Config::agent_key_file() {
        registry::record(path, keys.iter().map(|entry| &entry.agent_token), now).map_err(|_| {
            OAuthError::invalid_token_response("agent key registry could not be updated")
        })?;
    }
    request.add_verified_signature_keys(keys);
    Ok(request)
}

fn validate_entry(
    entry: SignatureKey<'_>,
    providers: &[AgentProviderConfig],
    now: u64,
) -> Result<VerifiedSignatureKey, OAuthError> {
    if entry.scheme != "jwt" {
        return Err(OAuthError::invalid_request(
            "Signature-Key scheme must be jwt",
        ));
    }
    let Some(KeyParameter::String(jwt)) = entry.parameters.get("jwt") else {
        return Err(OAuthError::invalid_request(
            "Signature-Key jwt parameter must be a string",
        ));
    };
    Ok(VerifiedSignatureKey {
        label: entry.label.to_owned(),
        agent_token: verify_token(jwt, providers, now)?,
    })
}
