use crate::{config::Config, errors::OAuthError};

pub const PRESENTATION_RESPONSE_PATH: &str = "/presentation-response";

pub trait Validate {
    fn add_verifier(&mut self, verifier: String);
}

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

pub fn response_uri(verifier: &str) -> String {
    format!("{verifier}{PRESENTATION_RESPONSE_PATH}")
}

pub fn response_uri_with_state(verifier: &str, state: &str) -> String {
    format!("{}?state={}", response_uri(verifier), percent_encode(state))
}

pub fn client_id(verifier: &str) -> String {
    format!("redirect_uri:{}", response_uri(verifier))
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
