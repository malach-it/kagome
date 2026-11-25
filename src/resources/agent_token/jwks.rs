use std::{
    collections::HashMap,
    sync::{Arc, LazyLock, Mutex},
    time::{Duration, Instant},
};

use axum::http::Uri;
use serde::Deserialize;
use serde_json::Value;

use crate::{config::AgentProviderConfig, errors::OAuthError};

use super::{JwkFields, invalid};

const CACHE_TTL: Duration = Duration::from_secs(300);
const MIN_FETCH_INTERVAL: Duration = Duration::from_secs(60);
const FETCH_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_RESPONSE_BYTES: u64 = 64 * 1024;

type ProviderCaches = HashMap<(String, String), Arc<Mutex<CacheEntry>>>;
static CACHE: LazyLock<Mutex<ProviderCaches>> = LazyLock::new(Mutex::default);
static HTTP_AGENT: LazyLock<ureq::Agent> = LazyLock::new(|| {
    ureq::Agent::config_builder()
        .https_only(true)
        .max_redirects(0)
        .timeout_global(Some(FETCH_TIMEOUT))
        .build()
        .into()
});

#[derive(Deserialize)]
struct RemoteJwks {
    keys: Vec<JwkFields>,
}

#[derive(Default)]
struct CacheEntry {
    last_attempt: Option<Instant>,
    cached: Option<(Instant, RemoteJwks)>,
}

pub(super) fn valid_endpoint(endpoint: &str) -> bool {
    if endpoint.contains(['#', '\\']) {
        return false;
    }
    let Ok(uri) = endpoint.parse::<Uri>() else {
        return false;
    };
    uri.scheme_str() == Some("https")
        && uri.authority().is_some_and(|authority| {
            !authority.host().is_empty()
                && !authority.as_str().contains('@')
                && (authority.host().len() == authority.as_str().len()
                    || authority.port_u16().is_some())
        })
}

pub(super) fn find_key<'a>(
    keys: &'a [JwkFields],
    kid: &str,
) -> Result<Option<&'a JwkFields>, OAuthError> {
    let mut matches = keys
        .iter()
        .filter(|key| key.get("kid").and_then(Value::as_str) == Some(kid));
    let key = matches.next();
    if matches.next().is_some() {
        return Err(invalid("agent token kid is ambiguous for its issuer"));
    }
    Ok(key)
}

/// Resolves a key from the provider-configured endpoint with bounded HTTPS I/O.
/// Caches a successful response and limits fetches, including failed refreshes,
/// to one per minute per provider. Returns an OAuth error for an unavailable
/// endpoint, an absent key, or an ambiguous key identifier.
pub(super) fn remote_key(
    provider: &AgentProviderConfig,
    kid: &str,
) -> Result<JwkFields, OAuthError> {
    let Some(endpoint) = &provider.jwks_uri else {
        return Err(unknown_key());
    };
    if !valid_endpoint(endpoint) {
        return Err(unavailable());
    }
    let cache = {
        let mut cache = CACHE.lock().map_err(|_| unavailable())?;
        cache
            .entry((provider.issuer.clone(), endpoint.clone()))
            .or_default()
            .clone()
    };
    cache
        .lock()
        .map_err(|_| unavailable())?
        .lookup(kid, Instant::now(), || fetch(&HTTP_AGENT, endpoint))
}

impl CacheEntry {
    fn lookup(
        &mut self,
        kid: &str,
        now: Instant,
        fetch_keys: impl FnOnce() -> Result<RemoteJwks, OAuthError>,
    ) -> Result<JwkFields, OAuthError> {
        let fresh = self
            .cached
            .as_ref()
            .filter(|(fetched, _)| now.duration_since(*fetched) < CACHE_TTL);
        if let Some((_, jwks)) = fresh
            && let Some(key) = find_key(&jwks.keys, kid)?
        {
            return Ok(key.clone());
        }

        if self
            .last_attempt
            .is_some_and(|attempt| now.duration_since(attempt) < MIN_FETCH_INTERVAL)
        {
            return Err(if fresh.is_some() {
                unknown_key()
            } else {
                unavailable()
            });
        }

        self.last_attempt = Some(now);
        let jwks = fetch_keys()?;
        let result = find_key(&jwks.keys, kid).and_then(|key| key.cloned().ok_or_else(unknown_key));
        self.cached = Some((now, jwks));
        result
    }
}

fn fetch(agent: &ureq::Agent, endpoint: &str) -> Result<RemoteJwks, OAuthError> {
    let mut response = agent
        .get(endpoint)
        .header("accept", "application/jwk-set+json, application/json")
        .call()
        .map_err(|_| unavailable())?;
    if !response.status().is_success() {
        return Err(unavailable());
    }
    response
        .body_mut()
        .with_config()
        .limit(MAX_RESPONSE_BYTES)
        .read_json()
        .map_err(|_| unavailable())
}

fn unknown_key() -> OAuthError {
    invalid("agent token kid is not trusted for its issuer")
}

fn unavailable() -> OAuthError {
    invalid("agent provider JWKS is unavailable or invalid")
}

#[cfg(test)]
mod tests {
    use std::{
        io::{BufRead, BufReader, Write},
        net::TcpListener,
        thread,
    };

    use super::*;

    fn keys(ids: &[&str]) -> RemoteJwks {
        RemoteJwks {
            keys: ids
                .iter()
                .map(|kid| JwkFields::from([("kid".to_owned(), Value::from(*kid))]))
                .collect(),
        }
    }

    #[test]
    fn uses_a_fresh_key_and_throttles_unknown_kid_refreshes() {
        let mut cache = CacheEntry::default();
        let start = Instant::now();

        let first = cache.lookup("old", start, || Ok(keys(&["old"]))).unwrap();
        assert_eq!(first["kid"], "old");
        let early = start + Duration::from_secs(1);
        assert!(
            cache
                .lookup("old", early, || panic!("fresh key should be reused"))
                .is_ok()
        );
        let missing = cache
            .lookup("new", early, || panic!("refresh should be throttled"))
            .unwrap_err();
        assert_eq!(missing.error_description, unknown_key().error_description);

        let rotated = cache
            .lookup("new", start + MIN_FETCH_INTERVAL, || Ok(keys(&["new"])))
            .unwrap();
        assert_eq!(rotated["kid"], "new");
        assert!(
            cache
                .lookup("old", start + MIN_FETCH_INTERVAL, || panic!(
                    "rotation removed the old key"
                ))
                .is_err()
        );
    }

    #[test]
    fn keeps_fresh_keys_after_a_failed_refresh_and_never_uses_expired_keys() {
        let mut cache = CacheEntry::default();
        let start = Instant::now();
        cache.lookup("old", start, || Ok(keys(&["old"]))).unwrap();
        let refresh = start + MIN_FETCH_INTERVAL;

        let failure = cache
            .lookup("new", refresh, || Err(unavailable()))
            .unwrap_err();
        assert_eq!(failure.error_description, unavailable().error_description);
        assert!(
            cache
                .lookup("old", refresh, || panic!("fresh key should be reused"))
                .is_ok()
        );
        assert!(
            cache
                .lookup("new", refresh, || panic!(
                    "failed refresh should be throttled"
                ))
                .is_err()
        );

        let expired = start + CACHE_TTL;
        assert!(cache.lookup("old", expired, || Err(unavailable())).is_err());
        assert!(
            cache
                .lookup("old", expired, || panic!(
                    "failed fetch should be throttled"
                ))
                .is_err()
        );
        assert!(
            cache
                .lookup("old", expired + MIN_FETCH_INTERVAL, || Ok(keys(&["old"])))
                .is_ok()
        );
    }

    #[test]
    fn rejects_ambiguous_kids_and_ignores_unselected_keys() {
        let jwks = keys(&["selected", "unselected", "unselected"]);
        assert!(find_key(&jwks.keys, "selected").unwrap().is_some());
        assert!(find_key(&jwks.keys, "unselected").is_err());
        assert!(find_key(&jwks.keys, "unknown").unwrap().is_none());
    }

    #[test]
    fn fetches_jwks_and_rejects_redirects_invalid_json_and_oversized_responses() {
        let agent: ureq::Agent = ureq::Agent::config_builder()
            .proxy(None)
            .max_redirects(0)
            .timeout_global(Some(FETCH_TIMEOUT))
            .build()
            .into();
        let oversized = format!(
            "{{\"keys\": []}}{}",
            " ".repeat(MAX_RESPONSE_BYTES as usize)
        );
        for (status, headers, body, succeeds) in [
            ("200 OK", "", r#"{"keys":[{"kid":"remote"}]}"#, true),
            (
                "302 Found",
                "Location: http://127.0.0.1:1/another\r\n",
                "",
                false,
            ),
            ("200 OK", "", "invalid JSON", false),
            ("200 OK", "", oversized.as_str(), false),
        ] {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let endpoint = format!("http://{}/jwks", listener.local_addr().unwrap());
            let response = format!(
                "HTTP/1.1 {status}\r\n{headers}Connection: close\r\nContent-Length: {}\r\n\r\n{body}",
                body.len()
            );
            let server = thread::spawn(move || {
                let (mut stream, _) = listener.accept().unwrap();
                stream.set_read_timeout(Some(FETCH_TIMEOUT)).unwrap();
                let mut reader = BufReader::new(&mut stream);
                loop {
                    let mut line = String::new();
                    if reader.read_line(&mut line).unwrap() == 0 || line == "\r\n" {
                        break;
                    }
                }
                let _ = stream.write_all(response.as_bytes());
            });
            let result = fetch(&agent, &endpoint);
            server.join().unwrap();
            if succeeds {
                assert!(find_key(&result.unwrap().keys, "remote").unwrap().is_some());
            } else {
                assert!(result.is_err(), "{status}");
            }
        }
    }
}
