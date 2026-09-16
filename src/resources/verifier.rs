use crate::{config::Config, errors::OAuthError};

pub const PRESENTATION_RESPONSE_PATH: &str = "/presentation-response";

pub trait Validate {
    fn add_verifier(&mut self, verifier: String);
}

/// Stores the configured server issuer as the trusted verifier base URL.
///
/// Trailing slashes are removed before the verifier is added to request state. Request-controlled
/// host values are deliberately ignored.
///
/// # Errors
///
/// The current implementation is infallible; the `Result` shape keeps it composable in resource
/// pipelines.
pub fn validate<T: Validate>(mut request: T) -> Result<T, OAuthError> {
    request.add_verifier(
        Config::global()
            .server
            .issuer
            .trim_end_matches('/')
            .to_owned(),
    );
    Ok(request)
}

/// Constructs the verifier's OpenID4VP direct-post response URI.
///
/// The caller must provide a normalized verifier base URI; this helper appends
/// [`PRESENTATION_RESPONSE_PATH`] without modifying the base.
pub fn response_uri(verifier: &str) -> String {
    format!("{verifier}{PRESENTATION_RESPONSE_PATH}")
}

/// Constructs a presentation response URI carrying percent-encoded state.
///
/// State is encoded as a single query parameter using the RFC 3986 unreserved character set.
pub fn response_uri_with_state(verifier: &str, state: &str) -> String {
    format!("{}?state={}", response_uri(verifier), percent_encode(state))
}

/// Returns the verifier's pre-registered wallet-protocol client identifier.
///
/// The normalized configured issuer identifies the signer of OpenID4VP and SIOPv2 request objects;
/// callback response URIs remain separate protocol parameters.
pub fn client_id(verifier: &str) -> String {
    verifier.to_owned()
}

fn percent_encode(value: &str) -> String {
    value
        .bytes()
        .flat_map(|byte| match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                vec![byte as char]
            }
            byte => format!("%{byte:02X}").chars().collect(),
        })
        .collect()
}
