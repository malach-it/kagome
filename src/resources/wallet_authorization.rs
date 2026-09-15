use std::{
    collections::HashMap,
    sync::{Mutex, OnceLock},
    time::{SystemTime, UNIX_EPOCH},
};

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use ring::rand::{SecureRandom, SystemRandom};

use crate::{config::Config, errors::OAuthError};

pub const TTL_SECONDS: u64 = 300;
const MAX_AUTHORIZATIONS: usize = 1024;

static AUTHORIZATIONS: OnceLock<Mutex<HashMap<String, StoredAuthorization>>> = OnceLock::new();

#[derive(Debug)]
struct StoredAuthorization {
    uri: String,
    expires_at: u64,
}

#[derive(Debug)]
pub struct WalletAuthorizationRelay {
    pub identifier: String,
    pub uri: String,
}

pub fn store(uri: &str) -> Result<WalletAuthorizationRelay, OAuthError> {
    let mut identifier = [0_u8; 32];
    SystemRandom::new().fill(&mut identifier).map_err(|_| {
        OAuthError::invalid_token_response("wallet authorization relay generation failed")
    })?;
    let identifier = URL_SAFE_NO_PAD.encode(identifier);
    let now = now().map_err(|_| {
        OAuthError::invalid_token_response("wallet authorization relay generation failed")
    })?;
    let mut authorizations = authorizations().lock().map_err(|_| {
        OAuthError::invalid_token_response("wallet authorization relay generation failed")
    })?;
    authorizations.retain(|_, authorization| authorization.expires_at > now);
    if authorizations.len() >= MAX_AUTHORIZATIONS
        && let Some(oldest) = authorizations
            .iter()
            .min_by_key(|(_, authorization)| authorization.expires_at)
            .map(|(identifier, _)| identifier.clone())
    {
        authorizations.remove(&oldest);
    }
    authorizations.insert(
        identifier.clone(),
        StoredAuthorization {
            uri: uri.to_owned(),
            expires_at: now + TTL_SECONDS,
        },
    );

    Ok(WalletAuthorizationRelay {
        uri: format!(
            "{}/wallet-authorization?id={identifier}",
            Config::global().server.issuer.trim_end_matches('/')
        ),
        identifier,
    })
}

pub fn resolve(identifier: Option<&str>) -> Result<String, OAuthError> {
    let identifier = identifier
        .filter(|identifier| !identifier.is_empty())
        .ok_or_else(|| OAuthError::invalid_request("wallet authorization id is required"))?;
    let now = now().map_err(|_| {
        OAuthError::invalid_request("wallet authorization relay is invalid or expired")
    })?;
    let mut authorizations = authorizations().lock().map_err(|_| {
        OAuthError::invalid_request("wallet authorization relay is invalid or expired")
    })?;
    authorizations.retain(|_, authorization| authorization.expires_at > now);
    authorizations
        .get(identifier)
        .map(|authorization| authorization.uri.clone())
        .ok_or_else(|| {
            OAuthError::invalid_request("wallet authorization relay is invalid or expired")
        })
}

fn authorizations() -> &'static Mutex<HashMap<String, StoredAuthorization>> {
    AUTHORIZATIONS.get_or_init(|| Mutex::new(HashMap::new()))
}

fn now() -> Result<u64, std::time::SystemTimeError> {
    Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_expired_wallet_authorization_relay() {
        let identifier = "expired-wallet-authorization";
        authorizations().lock().unwrap().insert(
            identifier.to_owned(),
            StoredAuthorization {
                uri: "https://wallet.example.com/authorize".to_owned(),
                expires_at: 0,
            },
        );

        let error = resolve(Some(identifier)).expect_err("expired relay should be rejected");

        assert_eq!(
            error.error_description,
            "wallet authorization relay is invalid or expired"
        );
    }
}
