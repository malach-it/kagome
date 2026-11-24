use std::collections::{BTreeMap, BTreeSet};

use base64::{
    Engine,
    alphabet::STANDARD,
    engine::{DecodePaddingMode, GeneralPurpose, GeneralPurposeConfig},
};

use crate::errors::OAuthError;

const BYTE_SEQUENCE: GeneralPurpose = GeneralPurpose::new(
    &STANDARD,
    GeneralPurposeConfig::new().with_decode_padding_mode(DecodePaddingMode::Indifferent),
);

#[derive(Debug, Eq, PartialEq)]
pub enum KeyParameter {
    String(String),
    Bytes(Vec<u8>),
    Boolean(bool),
}

#[derive(Debug, Eq, PartialEq)]
pub struct SignatureKey<'a> {
    pub label: &'a str,
    pub scheme: &'a str,
    pub parameters: BTreeMap<&'a str, KeyParameter>,
}

/// Parses one Signature-Key field into members in wire order.
///
/// Supports the header's dictionary of scheme tokens and its string, byte
/// sequence, and boolean parameters. Bare parameters mean true.
///
/// # Errors
///
/// Returns `invalid_request` for empty or malformed fields, duplicate labels
/// or parameters, and values outside the Signature-Key grammar.
pub fn parse_signature_key(field: &str) -> Result<Vec<SignatureKey<'_>>, OAuthError> {
    let mut remaining = field.trim_matches([' ', '\t']);
    let mut entries = Vec::new();
    let mut labels = BTreeSet::new();

    loop {
        let entry = parse_member(&mut remaining).ok_or_else(malformed)?;
        if !labels.insert(entry.label) {
            return Err(OAuthError::invalid_request(
                "Signature-Key labels must be unique",
            ));
        }
        entries.push(entry);

        remaining = remaining.trim_start_matches([' ', '\t']);
        match remaining.strip_prefix(',') {
            Some(rest) => remaining = rest.trim_start_matches([' ', '\t']),
            None if remaining.is_empty() => return Ok(entries),
            None => return Err(malformed()),
        }
    }
}

fn parse_member<'a>(input: &mut &'a str) -> Option<SignatureKey<'a>> {
    let label = parse_key(input)?;
    *input = input.strip_prefix('=')?;
    let scheme = parse_token(input)?;

    let mut parameters = BTreeMap::new();
    while let Some(rest) = input.strip_prefix(';') {
        *input = rest.trim_start_matches(' ');
        let key = parse_key(input)?;
        let value = match input.strip_prefix('=') {
            Some(rest) => {
                *input = rest;
                parse_parameter(input)?
            }
            None => KeyParameter::Boolean(true),
        };
        if parameters.insert(key, value).is_some() {
            return None;
        }
    }

    Some(SignatureKey {
        label,
        scheme,
        parameters,
    })
}

pub(super) fn parse_key<'a>(input: &mut &'a str) -> Option<&'a str> {
    match input.as_bytes().first()? {
        b'a'..=b'z' | b'*' => Some(take_while(input, |ch| {
            ch.is_ascii_lowercase() || ch.is_ascii_digit() || "_-.*".contains(ch)
        })),
        _ => None,
    }
}

fn parse_token<'a>(input: &mut &'a str) -> Option<&'a str> {
    match input.as_bytes().first()? {
        b'A'..=b'Z' | b'a'..=b'z' | b'*' => Some(take_while(input, |ch| {
            ch.is_ascii_alphanumeric() || "!#$%&'*+-.^_`|~:/".contains(ch)
        })),
        _ => None,
    }
}

pub(super) fn take_while<'a>(input: &mut &'a str, allowed: impl Fn(char) -> bool) -> &'a str {
    let end = input.find(|ch| !allowed(ch)).unwrap_or(input.len());
    let (value, rest) = input.split_at(end);
    *input = rest;
    value
}

fn parse_parameter(input: &mut &str) -> Option<KeyParameter> {
    match input.as_bytes().first()? {
        b'"' => parse_string(input).map(KeyParameter::String),
        b':' => parse_bytes(input).map(KeyParameter::Bytes),
        b'?' => {
            let (value, rest) = match input.as_bytes().get(1)? {
                b'0' => (false, &input[2..]),
                b'1' => (true, &input[2..]),
                _ => return None,
            };
            *input = rest;
            Some(KeyParameter::Boolean(value))
        }
        _ => None,
    }
}

pub(super) fn parse_bytes(input: &mut &str) -> Option<Vec<u8>> {
    let (encoded, rest) = input.strip_prefix(':')?.split_once(':')?;
    let bytes = BYTE_SEQUENCE.decode(encoded).ok()?;
    *input = rest;
    Some(bytes)
}

pub(super) fn parse_string(input: &mut &str) -> Option<String> {
    let mut chars = input.strip_prefix('"')?.chars();
    let mut value = String::new();
    while let Some(ch) = chars.next() {
        match ch {
            '"' => {
                *input = chars.as_str();
                return Some(value);
            }
            '\\' => match chars.next()? {
                escaped @ ('"' | '\\') => value.push(escaped),
                _ => return None,
            },
            ' '..='~' => value.push(ch),
            _ => return None,
        }
    }
    None
}

fn malformed() -> OAuthError {
    OAuthError::invalid_request("Signature-Key is malformed")
}
