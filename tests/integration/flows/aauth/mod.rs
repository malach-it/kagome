use base64::{
    Engine,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use kagome::config::{AgentProviderConfig, AgentProviderJwks};
use ring::signature::{Ed25519KeyPair, KeyPair};
use serde_json::{Value, json};

use super::super::server::send_request;

const ISSUER: &str = "https://agents.example";
const HOST: &str = "resource.example";
const PATH: &str = "/agent/resource";
const KID: &str = "provider-key";

// Branch matrix:
// - Router: GET | other method (404).
// - Signature-Key: provider-attested key | absent, repeated, malformed,
//   unsupported scheme, untrusted provider, or expired token (401).
// - Signature-Input and Signature: one field and label each | absent, repeated,
//   malformed, or mismatched (401). One failed rule stops the pipeline, so
//   subsequent validation outcomes are unreachable for that request.
// - Coverage: four required components, with optional plain fields | missing,
//   repeated, unsupported, or unresolved component (401).
// - Timestamps: current with absent or valid expiry | missing creation time,
//   stale or future creation, or expired signature (401).
// - Proof: matching confirmation key and request components (501) | wrong key,
//   modified request, or mismatched key identifier (401). The selected label
//   may appear anywhere in Signature-Key, and the signed value covers all entries.
// - Authority: Host for origin-form | target authority for absolute-form |
//   malformed authority (401).
// - Registry I/O failure (500) is unreachable with the integration server's
//   disabled registry. Missing authenticated output (500) is unreachable after
//   successful verification, which stores an index into the verified keys.

fn key(seed: u8) -> Ed25519KeyPair {
    Ed25519KeyPair::from_seed_unchecked(&[seed; 32]).unwrap()
}

fn public_jwk(key: &Ed25519KeyPair, kid: &str) -> Value {
    json!({
        "kty": "OKP",
        "crv": "Ed25519",
        "alg": "Ed25519",
        "kid": kid,
        "x": URL_SAFE_NO_PAD.encode(key.public_key().as_ref()),
    })
}

pub(in crate::integration) fn agent_provider() -> AgentProviderConfig {
    AgentProviderConfig {
        issuer: ISSUER.to_owned(),
        jwks: Some(AgentProviderJwks {
            keys: vec![serde_json::from_value(public_jwk(&key(1), KID)).unwrap()],
        }),
        jwks_uri: None,
    }
}

fn signature_key(issuer: &str, expires: u64) -> String {
    let header = URL_SAFE_NO_PAD.encode(
        json!({
            "typ": "aa-agent+jwt", "alg": "Ed25519", "kid": KID,
        })
        .to_string(),
    );
    let claims = URL_SAFE_NO_PAD.encode(
        json!({
            "iss": issuer, "sub": "aauth:test@agents.example", "dwk": "aauth-agent.json",
            "jti": "agent-resource-test", "iat": expires - 300, "exp": expires,
            "cnf": {"jwk": public_jwk(&key(2), "agent-key")},
        })
        .to_string(),
    );
    let payload = format!("{header}.{claims}");
    let signature = URL_SAFE_NO_PAD.encode(key(1).sign(payload.as_bytes()).as_ref());
    format!("sig=jwt;jwt=\"{payload}.{signature}\"")
}

fn signed_request(
    components: &[(&str, &str)],
    params: &str,
    signature_key: &str,
    seed: u8,
) -> String {
    let names = components
        .iter()
        .map(|(name, _)| format!("{name:?}"))
        .collect::<Vec<_>>()
        .join(" ");
    let input = format!("({names}){params}");
    let mut base: String = components
        .iter()
        .map(|(name, value)| format!("{name:?}: {value}\n"))
        .collect();
    base.push_str(&format!("\"@signature-params\": {input}"));
    let signature = STANDARD.encode(key(seed).sign(base.as_bytes()).as_ref());
    format!(
        "GET {PATH} HTTP/1.1\r\nHost: {HOST}\r\nSignature-Key: {signature_key}\r\nSignature-Input: sig={input}\r\nSignature: sig=:{signature}:\r\n\r\n"
    )
}

fn components(signature_key: &str) -> [(&str, &str); 4] {
    [
        ("@method", "GET"),
        ("@authority", HOST),
        ("@path", PATH),
        ("signature-key", signature_key),
    ]
}

fn current_request() -> String {
    let now = jsonwebtoken::get_current_timestamp();
    let signature_key = signature_key(ISSUER, now + 300);
    signed_request(
        &components(&signature_key),
        &format!(";created={now}"),
        &signature_key,
        2,
    )
}

fn without_header(request: &str, name: &str) -> String {
    request
        .split_inclusive("\r\n")
        .filter(|line| !line.starts_with(name))
        .collect()
}

fn assert_rejected(request: &str, description: &str) {
    let response = send_request(request);
    assert!(
        response.starts_with("HTTP/1.1 401 Unauthorized\r\n"),
        "{response}"
    );
    assert!(
        response.contains("signature-error: error=invalid_signature\r\n"),
        "{response}"
    );
    assert!(
        response.contains("aauth-requirement: requirement=agent-token\r\n"),
        "{response}"
    );
    assert!(response.contains(description), "{response}");
}

#[test]
fn returns_501_for_a_valid_signature() {
    let response = send_request(&current_request());
    assert!(
        response.starts_with("HTTP/1.1 501 Not Implemented\r\n"),
        "{response}"
    );
    assert!(response.contains("cache-control: no-store\r\n"));
    assert!(response.ends_with("\r\n\r\nnot implemented"));
}

#[test]
fn returns_404_for_a_non_get_method() {
    let response = send_request(&current_request().replacen("GET ", "POST ", 1));
    assert!(
        response.starts_with("HTTP/1.1 404 Not Found\r\n"),
        "{response}"
    );
}

#[test]
fn rejects_missing_repeated_or_malformed_signature_key() {
    let request = current_request();
    for (edited, expected) in [
        (
            without_header(&request, "Signature-Key:"),
            "Signature-Key is required",
        ),
        (
            request.replace(
                "Signature-Key: ",
                "Signature-Key: another=jwt\r\nSignature-Key: ",
            ),
            "Signature-Key must appear once",
        ),
        (
            request.replace("Signature-Key: sig=", "Signature-Key: invalid sig="),
            "Signature-Key is malformed",
        ),
        (
            request.replace("Signature-Key: sig=jwt", "Signature-Key: sig=x509"),
            "Signature-Key scheme must be jwt",
        ),
    ] {
        assert_rejected(&edited, expected);
    }
}

#[test]
fn rejects_an_untrusted_or_expired_agent_token() {
    let now = jsonwebtoken::get_current_timestamp();
    for (issuer, expires, expected) in [
        (
            "https://untrusted.example",
            now + 300,
            "agent token issuer is not trusted",
        ),
        (ISSUER, now - 1, "agent token expiration is invalid"),
    ] {
        let signature_key = signature_key(issuer, expires);
        let request = signed_request(
            &components(&signature_key),
            &format!(";created={now}"),
            &signature_key,
            2,
        );
        assert_rejected(&request, expected);
    }
}

#[test]
fn rejects_missing_repeated_or_malformed_message_headers() {
    let request = current_request();
    for (header, malformed_prefix, expected) in [
        (
            "Signature-Input:",
            "Signature-Input: sig=(",
            "Signature-Input is missing, malformed, or unsupported",
        ),
        (
            "Signature:",
            "Signature: sig=:",
            "HTTP message signature is missing or invalid",
        ),
    ] {
        assert_rejected(&without_header(&request, header), expected);
        assert_rejected(
            &request.replace(header, &format!("{header} invalid\r\n{header}")),
            expected,
        );
        assert_rejected(
            &request.replace(malformed_prefix, &format!("{header} invalid")),
            expected,
        );
    }
}

#[test]
fn rejects_mismatched_signature_labels() {
    let request = current_request();
    assert_rejected(
        &request.replace("Signature: sig=", "Signature: other="),
        "HTTP message signature is missing or invalid",
    );
    let request = request
        .replace("Signature: sig=", "Signature: other=")
        .replace("Signature-Input: sig=", "Signature-Input: other=");
    assert_rejected(
        &request,
        "Signature-Key label does not match Signature-Input",
    );
}

#[test]
fn rejects_missing_or_duplicate_required_components() {
    let now = jsonwebtoken::get_current_timestamp();
    let signature_key = signature_key(ISSUER, now + 300);
    let required = components(&signature_key);
    for (index, _) in required.iter().enumerate() {
        let mut coverage = required.to_vec();
        coverage.remove(index);
        let request = signed_request(&coverage, &format!(";created={now}"), &signature_key, 2);
        assert_rejected(&request, "HTTP signature must cover");
    }
    let mut repeated = required.to_vec();
    repeated.push(required[0]);
    let request = signed_request(&repeated, &format!(";created={now}"), &signature_key, 2);
    assert_rejected(
        &request,
        "Signature-Input is missing, malformed, or unsupported",
    );
}

#[test]
fn rejects_stale_future_or_expired_message_signatures() {
    let now = jsonwebtoken::get_current_timestamp();
    let signature_key = signature_key(ISSUER, now + 300);
    for params in [
        format!(";created={}", now - 90),
        format!(";created={}", now + 90),
        format!(";created={};expires={}", now - 10, now - 1),
        format!(";created={now};expires={now}"),
    ] {
        let request = signed_request(&components(&signature_key), &params, &signature_key, 2);
        assert_rejected(&request, "HTTP signature timestamp is invalid");
    }
}

#[test]
fn rejects_missing_or_duplicate_creation_time() {
    let now = jsonwebtoken::get_current_timestamp();
    let signature_key = signature_key(ISSUER, now + 300);
    for params in [String::new(), format!(";created={now};created={now}")] {
        let request = signed_request(&components(&signature_key), &params, &signature_key, 2);
        assert_rejected(
            &request,
            "Signature-Input is missing, malformed, or unsupported",
        );
    }
}

#[test]
fn rejects_a_signature_from_the_provider_key_instead_of_the_confirmation_key() {
    let now = jsonwebtoken::get_current_timestamp();
    let signature_key = signature_key(ISSUER, now + 300);
    let request = signed_request(
        &components(&signature_key),
        &format!(";created={now}"),
        &signature_key,
        1,
    );
    assert_rejected(&request, "HTTP message signature is missing or invalid");
}

#[test]
fn rejects_modified_signed_authority() {
    let request = current_request().replace(HOST, "other.example");
    assert_rejected(&request, "HTTP message signature is missing or invalid");
}

#[test]
fn rejects_a_malformed_authority() {
    let request = current_request().replace(HOST, "resource.example:invalid");
    assert_rejected(
        &request,
        "Signature-Input is missing, malformed, or unsupported",
    );
}

#[test]
fn binds_the_entire_signature_key_field_when_selecting_a_label() {
    let now = jsonwebtoken::get_current_timestamp();
    let signature_key = signature_key(ISSUER, now + 300);
    let other = signature_key.replacen("sig=", "other=", 1);
    let dictionary = format!("{other}, {signature_key}");
    let params = format!(";created={now}");
    let request = signed_request(&components(&dictionary), &params, &dictionary, 2);
    let response = send_request(&request);
    assert!(
        response.starts_with("HTTP/1.1 501 Not Implemented\r\n"),
        "{response}"
    );
    let request = request.replace(&dictionary, &signature_key);
    assert_rejected(&request, "HTTP message signature is missing or invalid");
}

#[test]
fn uses_absolute_target_authority_when_present() {
    let request =
        current_request().replace(&format!("GET {PATH}"), &format!("GET http://{HOST}{PATH}"));
    let response = send_request(&request.replace(&format!("Host: {HOST}"), "Host: other.example"));
    assert!(
        response.starts_with("HTTP/1.1 501 Not Implemented\r\n"),
        "{response}"
    );
    let request = request.replace(&format!("http://{HOST}"), "http://other.example");
    assert_rejected(&request, "HTTP message signature is missing or invalid");
}

#[test]
fn accepts_valid_expiry_and_additional_signed_fields() {
    let now = jsonwebtoken::get_current_timestamp();
    let signature_key = signature_key(ISSUER, now + 300);
    let mut coverage = components(&signature_key).to_vec();
    coverage.push(("x-agent-context", "first, second"));
    let params = format!(
        ";created={now};expires={};keyid=\"agent-key\";alg=\"ignored\"",
        now + 30
    );
    let request = signed_request(&coverage, &params, &signature_key, 2).replace(
        "Host: resource.example",
        "Host: RESOURCE.EXAMPLE:80\r\nX-Agent-Context: first\r\nX-Agent-Context: second",
    );
    let response = send_request(&request);
    assert!(
        response.starts_with("HTTP/1.1 501 Not Implemented\r\n"),
        "{response}"
    );
    assert_rejected(
        &without_header(&request, "X-Agent-Context:"),
        "Signature-Input is missing, malformed, or unsupported",
    );
}

#[test]
fn rejects_a_key_id_that_cannot_identify_the_confirmation_key() {
    let now = jsonwebtoken::get_current_timestamp();
    let signature_key = signature_key(ISSUER, now + 300);
    let request = signed_request(
        &components(&signature_key),
        &format!(";created={now};keyid=\"other-key\""),
        &signature_key,
        2,
    );
    assert_rejected(&request, "HTTP message signature is missing or invalid");
}
