use std::{collections::BTreeSet, fmt::Write};

use axum::http::uri::Authority;

use crate::{config::Config, errors::OAuthError};

use super::{
    SIGNATURE_KEY_HEADER, VerifiedSignatureKey,
    signature_key::{parse_bytes, parse_key, parse_string, take_while},
};

pub const SIGNATURE_HEADER: &str = "signature";
pub const SIGNATURE_INPUT_HEADER: &str = "signature-input";
const REQUIRED_COMPONENTS: [&str; 4] = ["@method", "@authority", "@path", SIGNATURE_KEY_HEADER];
const SIGNATURE_WINDOW: u64 = 60;

pub trait VerifyMessage {
    fn method(&self) -> &str;
    fn path(&self) -> &str;
    fn target_authority(&self) -> Option<&str>;
    fn target_scheme(&self) -> Option<&str>;
    fn field_lines(&self, name: &str) -> &[&str];
    fn verified_signature_keys(&self) -> &[VerifiedSignatureKey];
    fn set_authenticated_agent(&mut self, key_index: usize);
}

/// Verifies a single HTTP Message Signature with the corresponding
/// provider-verified agent token from `http_signature::validate`. Requires the
/// method, authority, path, and Signature-Key to be covered and the signed
/// timestamps to be current. Stores the authenticated agent's key index.
///
/// # Errors
/// Returns `invalid_request` for missing or malformed signature fields,
/// unsupported input, missing coverage, invalid times, unmatched labels, or an
/// invalid message signature.
pub fn verify_message<T: VerifyMessage>(mut request: T) -> Result<T, OAuthError> {
    let input = match request.field_lines(SIGNATURE_INPUT_HEADER) {
        [line] => parse_input(line).ok_or_else(invalid_input)?,
        _ => return Err(invalid_input()),
    };
    let signature = match request.field_lines(SIGNATURE_HEADER) {
        [line] => parse_signature(line, input.label).ok_or_else(invalid_signature)?,
        _ => return Err(invalid_signature()),
    };

    if !REQUIRED_COMPONENTS.iter().all(|required| {
        input
            .components
            .iter()
            .any(|component| component == required)
    }) {
        return Err(OAuthError::invalid_request(
            "HTTP signature must cover @method, @authority, @path, and signature-key",
        ));
    }
    let now = jsonwebtoken::get_current_timestamp();
    if input.created.abs_diff(now) > SIGNATURE_WINDOW
        || input
            .expires
            .is_some_and(|expires| expires <= now || expires <= input.created)
    {
        return Err(OAuthError::invalid_request(
            "HTTP signature timestamp is invalid",
        ));
    }

    let (index, key) = request
        .verified_signature_keys()
        .iter()
        .enumerate()
        .find(|(_, key)| key.label == input.label)
        .ok_or_else(|| {
            OAuthError::invalid_request("Signature-Key label does not match Signature-Input")
        })?;
    let base = signature_base(&request, &input).ok_or_else(invalid_input)?;
    if !key
        .agent_token
        .verify_signature(base.as_bytes(), &signature, input.key_id.as_deref())
    {
        return Err(invalid_signature());
    }

    request.set_authenticated_agent(index);
    Ok(request)
}

struct SignatureInput<'a> {
    label: &'a str,
    components: Vec<String>,
    serialized: String,
    created: u64,
    expires: Option<u64>,
    key_id: Option<String>,
}

fn parse_input(field: &str) -> Option<SignatureInput<'_>> {
    let mut rest = field.trim_matches([' ', '\t']);
    let label = parse_key(&mut rest)?;
    rest = rest.strip_prefix("=(")?.trim_start_matches(' ');

    let mut components = Vec::new();
    while !rest.starts_with(')') {
        let component = parse_string(&mut rest)?;
        if components.contains(&component) {
            return None;
        }
        components.push(component);
        if !rest.starts_with(')') {
            rest = rest.strip_prefix(' ')?.trim_start_matches(' ');
        }
    }
    rest = rest.strip_prefix(')')?;

    let mut serialized = format!(
        "({})",
        components
            .iter()
            .map(|component| format!("{component:?}"))
            .collect::<Vec<_>>()
            .join(" ")
    );
    let mut seen = BTreeSet::new();
    let (mut created, mut expires, mut key_id) = (None, None, None);
    while let Some(parameter) = rest.strip_prefix(';') {
        rest = parameter.trim_start_matches(' ');
        let name = parse_key(&mut rest)?;
        if !seen.insert(name) {
            return None;
        }
        rest = rest.strip_prefix('=')?;
        match name {
            "created" | "expires" => {
                let digits = take_while(&mut rest, |ch| ch.is_ascii_digit());
                if digits.len() > 15 {
                    return None;
                }
                let timestamp = digits.parse::<u64>().ok()?;
                match name {
                    "created" => created = Some(timestamp),
                    _ => expires = Some(timestamp),
                }
                write!(serialized, ";{name}={timestamp}").ok()?;
            }
            "alg" | "keyid" | "nonce" | "tag" => {
                let value = parse_string(&mut rest)?;
                write!(serialized, ";{name}={value:?}").ok()?;
                if name == "keyid" {
                    key_id = Some(value);
                }
            }
            _ => return None,
        }
    }
    rest.is_empty().then_some(SignatureInput {
        label,
        components,
        serialized,
        created: created?,
        expires,
        key_id,
    })
}

fn parse_signature(field: &str, expected_label: &str) -> Option<Vec<u8>> {
    let mut rest = field.trim_matches([' ', '\t']);
    if parse_key(&mut rest)? != expected_label {
        return None;
    }
    rest = rest.strip_prefix('=')?;
    let signature = parse_bytes(&mut rest)?;
    (rest.is_empty() && !signature.is_empty()).then_some(signature)
}

fn signature_base(request: &impl VerifyMessage, input: &SignatureInput<'_>) -> Option<String> {
    let mut base = String::new();
    for component in &input.components {
        match component.as_str() {
            "@method" => writeln!(base, "\"@method\": {}", request.method()).ok()?,
            "@path" => writeln!(base, "\"@path\": {}", request.path()).ok()?,
            "@authority" => {
                writeln!(base, "\"@authority\": {}", authority(request)?).ok()?;
            }
            field
                if field.bytes().all(|byte| !byte.is_ascii_uppercase())
                    && axum::http::HeaderName::from_bytes(field.as_bytes()).is_ok() =>
            {
                let lines = request.field_lines(field);
                if lines.is_empty()
                    || lines
                        .iter()
                        .any(|line| !line.is_ascii() || line.contains(['\r', '\n']))
                {
                    return None;
                }
                let value = lines
                    .iter()
                    .map(|line| line.trim_matches([' ', '\t']))
                    .collect::<Vec<_>>()
                    .join(", ");
                writeln!(base, "{field:?}: {value}").ok()?;
            }
            _ => return None,
        }
    }
    write!(base, "\"@signature-params\": {}", input.serialized).ok()?;
    Some(base)
}

fn authority(request: &impl VerifyMessage) -> Option<String> {
    let host = match (request.target_authority(), request.field_lines("host")) {
        (Some(authority), _) => authority,
        (None, [host]) => host,
        _ => return None,
    };
    let authority: Authority = host.trim_matches([' ', '\t']).parse().ok()?;
    let port = authority.port_u16();
    if authority.host().is_empty()
        || authority.as_str().contains('@')
        || (authority.as_str() != authority.host() && port.is_none())
    {
        return None;
    }
    let scheme = request.target_scheme().or_else(|| {
        Config::global()
            .server
            .issuer
            .split_once("://")
            .map(|(scheme, _)| scheme)
    })?;
    let default_port = match scheme {
        "http" => 80,
        "https" => 443,
        _ => return None,
    };
    if port == Some(default_port) {
        Some(authority.host().to_ascii_lowercase())
    } else {
        Some(authority.as_str().to_ascii_lowercase())
    }
}

fn invalid_input() -> OAuthError {
    OAuthError::invalid_request("Signature-Input is missing, malformed, or unsupported")
}

fn invalid_signature() -> OAuthError {
    OAuthError::invalid_request("HTTP message signature is missing or invalid")
}
