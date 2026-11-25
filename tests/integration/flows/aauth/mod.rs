use std::{
    collections::BTreeMap,
    fs,
    io::Write,
    path::Path,
    process::{Command, Stdio},
};

use base64::{
    Engine,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use kagome::config::{
    AgentProviderConfig, AgentProviderJwks, AgentSshConfig, AgentSshScopes,
    ScopedAgentSshCommandConfig,
};
use ring::signature::{Ed25519KeyPair, KeyPair};
use serde_json::{Value, json};

use super::super::server::{agent_ssh_directory, send_request};

const ISSUER: &str = "https://agents.example";
const HOST: &str = "resource.example";
const PATH: &str = "/agent/resource";
const KID: &str = "provider-key";
const SUBJECT: &str = "aauth:test@agents.example";

// Branch matrix:
// - Router: GET | POST | other method (404).
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
// - POST registration: granted signed scope with configured commands (200) |
//   different subject, ungranted scope or scope without commands (403) |
//   missing, repeated, malformed, unsigned or modified scope (401). GET
//   stops after signature verification (501). POST cannot register a second,
//   unproven key in Signature-Key.
// - SSH invocation after registration: exact allowed argument vector runs |
//   omitted, extra, or differently grouped arguments are denied at execution.
//   An allowed invocation receives SSH stdin only if its grant opts in.
// - Registration key, token lifetime, and file update rules are covered in the
//   resource tests and the Docker handoff. An unencodable key after proof and a
//   token expiring between verification and registration are terminal denials.

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

pub(in crate::integration) fn agent_ssh_configuration(directory: &Path) -> AgentSshConfig {
    let mut scopes = BTreeMap::<_, Vec<_>>::from([("resource:empty".to_owned(), Vec::new())]);
    for (name, scope, executable) in [
        ("details", "resource:read", "/bin/uname"),
        ("resource", "resource:read", "/bin/hostname"),
        ("inspect", "resource:inspect", "/bin/uname"),
        ("say", "resource:args", "/bin/echo"),
        ("cat", "resource:write", "/bin/cat"),
        ("tee", "resource:write", "/usr/bin/tee"),
    ] {
        scopes
            .entry(scope.to_owned())
            .or_default()
            .push(ScopedAgentSshCommandConfig {
                name: name.to_owned(),
                executable: executable.into(),
                allowed_args: match name {
                    "say" => vec![
                        vec!["hello world".to_owned()],
                        vec!["semi;colon".to_owned()],
                    ],
                    "tee" => vec![vec![directory.join("test.txt").display().to_string()]],
                    _ => Vec::new(),
                },
                allow_stdin: name == "tee",
            });
    }
    AgentSshConfig {
        issuer: ISSUER.to_owned(),
        subject: SUBJECT.to_owned(),
        host: HOST.to_owned(),
        port: 2222,
        executable: None,
        scopes: AgentSshScopes::Grouped(scopes),
        commands: BTreeMap::new(),
        state_directory: directory.to_owned(),
    }
}

#[test]
fn registers_only_exact_configured_argument_lists() {
    let now = jsonwebtoken::get_current_timestamp();
    let signed = signature_key_for(ISSUER, SUBJECT, now + 120, 25);
    let response = send_request(&ssh_request_for(&signed, now, 25, &["resource:args"], true));
    assert!(response.starts_with("HTTP/1.1 200 OK\r\n"), "{response}");
    let body: Value = serde_json::from_str(response.split_once("\r\n\r\n").unwrap().1).unwrap();
    assert_eq!(
        body["commands"],
        json!(["say 'hello world'", "say 'semi;colon'"])
    );

    let run = |invocation: &str| registered_command(25, invocation).output().unwrap();
    for (invocation, expected) in [
        ("say 'hello world'", "hello world\n"),
        ("say 'semi;colon'", "semi;colon\n"),
    ] {
        let output = run(invocation);
        assert!(output.status.success());
        assert_eq!(std::str::from_utf8(&output.stdout).unwrap(), expected);
    }
    for invocation in ["say", "say hello world", "say 'hello world' extra"] {
        let output = run(invocation);
        assert_eq!(output.status.code(), Some(126));
        assert!(output.stdout.is_empty());
    }
}

#[test]
fn forwards_stdin_to_the_exact_command_in_the_write_scope() {
    register_write_scope(26);
    let path = agent_ssh_directory().join("test.txt");
    let invocation = format!("tee {}", path.display());
    let payload = b"file contents\n";
    let mut child = registered_command(26, &invocation)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(payload).unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(output.status.success());
    assert_eq!(output.stdout, payload);
    assert_eq!(fs::read(path).unwrap(), payload);
}

#[test]
fn discards_stdin_for_a_grant_without_the_option() {
    register_write_scope(27);
    let path = agent_ssh_directory().join("stdin-fixture.txt");
    fs::write(&path, b"ignored\n").unwrap();
    let input = fs::File::open(path).unwrap();
    let output = registered_command(27, "cat").stdin(input).output().unwrap();
    assert!(output.status.success());
    assert!(output.stdout.is_empty());
}

fn register_write_scope(seed: u8) {
    let now = jsonwebtoken::get_current_timestamp();
    let signed = signature_key_for(ISSUER, SUBJECT, now + 120, seed);
    let response = send_request(&ssh_request_for(
        &signed,
        now,
        seed,
        &["resource:write"],
        true,
    ));
    assert!(response.starts_with("HTTP/1.1 200 OK\r\n"), "{response}");
}

fn registered_command(seed: u8, invocation: &str) -> Command {
    let entries = authorized_keys();
    let key = ssh_key(seed);
    let entry = entries.lines().find(|entry| entry.contains(&key)).unwrap();
    let encoded = entry
        .split_once("kagome-ssh-resource v2 ")
        .unwrap()
        .1
        .split_once('"')
        .unwrap()
        .0;
    let mut command = Command::new(env!("CARGO_BIN_EXE_kagome"));
    command
        .args(["--ssh-command", encoded])
        .env("SSH_ORIGINAL_COMMAND", invocation);
    command
}

fn ssh_key(seed: u8) -> String {
    let mut blob = b"\0\0\0\x0bssh-ed25519\0\0\0\x20".to_vec();
    blob.extend_from_slice(key(seed).public_key().as_ref());
    format!("ssh-ed25519 {}", STANDARD.encode(blob))
}

fn signature_key(issuer: &str, expires: u64) -> String {
    signature_key_for(issuer, SUBJECT, expires, 2)
}

fn signature_key_for(issuer: &str, subject: &str, expires: u64, seed: u8) -> String {
    let header = URL_SAFE_NO_PAD.encode(
        json!({
            "typ": "aa-agent+jwt", "alg": "Ed25519", "kid": KID,
        })
        .to_string(),
    );
    let claims = URL_SAFE_NO_PAD.encode(
        json!({
            "iss": issuer, "sub": subject, "dwk": "aauth-agent.json",
            "jti": "agent-resource-test", "iat": expires - 300, "exp": expires,
            "cnf": {"jwk": public_jwk(&key(seed), "agent-key")},
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
    signed_request_for("GET", components, params, signature_key, seed)
}

fn signed_request_for(
    method: &str,
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
        "{method} {PATH} HTTP/1.1\r\nHost: {HOST}\r\nSignature-Key: {signature_key}\r\nSignature-Input: sig={input}\r\nSignature: sig=:{signature}:\r\n\r\n"
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

fn ssh_request(signature_key: &str, created: u64, seed: u8) -> String {
    ssh_request_for(signature_key, created, seed, &["resource:read"], true)
}

fn ssh_request_for(
    signature_key: &str,
    created: u64,
    seed: u8,
    scopes: &[&str],
    covered: bool,
) -> String {
    let mut components = components(signature_key);
    components[0].1 = "POST";
    let mut components = components.to_vec();
    let scope_value = scopes.join(", ");
    if covered {
        components.push(("ssh-scope", &scope_value));
    }
    let mut request = signed_request_for(
        "POST",
        &components,
        &format!(";created={created}"),
        signature_key,
        seed,
    );
    for scope in scopes {
        request.insert_str(request.len() - 2, &format!("SSH-Scope: {scope}\r\n"));
    }
    request
}

fn authorized_keys() -> String {
    fs::read_to_string(agent_ssh_directory().join("authorized_keys")).unwrap()
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
fn returns_ssh_action_after_registering_the_proven_key() {
    let now = jsonwebtoken::get_current_timestamp();
    let expires_at = now + 45;
    let selected = signature_key_for(ISSUER, SUBJECT, expires_at, 11);
    let other = signature_key_for(ISSUER, SUBJECT, expires_at, 12).replacen("sig=", "other=", 1);
    let response = send_request(&ssh_request(&format!("{other}, {selected}"), now, 11));
    assert!(response.starts_with("HTTP/1.1 200 OK\r\n"), "{response}");
    assert!(response.contains("cache-control: no-store\r\n"));
    let (_, body) = response.split_once("\r\n\r\n").unwrap();
    assert_eq!(
        serde_json::from_str::<Value>(body).unwrap(),
        json!({"action":"ssh", "host":HOST, "port":2222, "user":"kagome",
            "scope":"resource:read", "commands":["details","resource"], "expires_at":expires_at}),
    );
    let entries = authorized_keys();
    assert!(entries.contains(&format!(
        "restrict,command=\"/usr/local/bin/kagome-ssh-resource details {expires_at} /bin/uname resource {expires_at} /bin/hostname\" {}",
        ssh_key(11),
    )));
    assert!(!entries.contains(&ssh_key(12)));
    assert!(entries.contains("# static SSH keys"));
}

#[test]
fn registers_all_commands_in_each_requested_scope_with_its_own_expiry() {
    let now = jsonwebtoken::get_current_timestamp();
    for (scope, expires, commands) in [
        (
            "resource:read",
            now + 30,
            &[("details", "/bin/uname"), ("resource", "/bin/hostname")][..],
        ),
        (
            "resource:inspect",
            now + 50,
            &[("inspect", "/bin/uname")][..],
        ),
    ] {
        let signed = signature_key_for(ISSUER, SUBJECT, expires, 21);
        let response = send_request(&ssh_request_for(&signed, now, 21, &[scope], true));
        assert!(response.starts_with("HTTP/1.1 200 OK\r\n"), "{response}");
        let body: Value = serde_json::from_str(response.split_once("\r\n\r\n").unwrap().1).unwrap();
        assert_eq!(body["scope"], scope);
        assert_eq!(
            body["commands"],
            json!(commands.iter().map(|(name, _)| name).collect::<Vec<_>>())
        );
        let entries = authorized_keys();
        let key = ssh_key(21);
        let entry = entries.lines().find(|entry| entry.contains(&key)).unwrap();
        assert!(entry.contains(&format!("resource {} /bin/hostname", now + 30)));
        for (command, executable) in commands {
            assert!(entry.contains(&format!("{command} {expires} {executable}")));
        }
        assert!(!entry.contains("admin "));
        assert_eq!(entries.matches(&key).count(), 1);
    }
}

#[test]
fn registers_multiple_scopes_in_one_signed_request() {
    let now = jsonwebtoken::get_current_timestamp();
    let expires = now + 120;
    let signed = signature_key_for(ISSUER, SUBJECT, expires, 31);
    let scopes = "resource:args resource:read";
    let response = send_request(&ssh_request_for(&signed, now, 31, &[scopes], true));
    assert!(response.starts_with("HTTP/1.1 200 OK\r\n"), "{response}");
    let body: Value = serde_json::from_str(response.split_once("\r\n\r\n").unwrap().1).unwrap();
    assert_eq!(body["scope"], scopes);
    assert_eq!(
        body["commands"],
        json!([
            "say 'hello world'",
            "say 'semi;colon'",
            "details",
            "resource"
        ]),
    );
    assert_eq!(body["expires_at"], now + 60);
    for command in ["say 'hello world'", "details", "resource"] {
        let output = registered_command(31, command).output().unwrap();
        assert!(output.status.success(), "{command}: {output:?}");
    }
    let denied = registered_command(31, "admin").output().unwrap();
    assert!(!denied.status.success());
}

#[test]
fn rejects_ungranted_scopes_and_scopes_without_configured_commands() {
    let now = jsonwebtoken::get_current_timestamp();
    let signed = signature_key_for(ISSUER, SUBJECT, now + 120, 22);
    for (scope, error) in [
        (
            "resource:admin",
            "agent is not authorized for this SSH scope",
        ),
        ("resource:empty", "SSH scope has no configured commands"),
    ] {
        for scopes in [scope.to_owned(), format!("resource:read {scope}")] {
            let response = send_request(&ssh_request_for(&signed, now, 22, &[&scopes], true));
            assert!(
                response.starts_with("HTTP/1.1 403 Forbidden\r\n"),
                "{response}"
            );
            assert!(response.contains(error));
        }
    }
    assert!(!authorized_keys().contains(&ssh_key(22)));
}

#[test]
fn requires_a_single_valid_signed_scope_header() {
    let now = jsonwebtoken::get_current_timestamp();
    let signed = signature_key_for(ISSUER, SUBJECT, now + 120, 23);
    let invalid = "exactly one SSH-Scope header with valid, unique scope tokens is required";
    for (scopes, covered, description) in [
        (&[][..], false, invalid),
        (&["resource:read", "resource:inspect"][..], true, invalid),
        (&["resource:read resource:read"][..], true, invalid),
        (&["resource:read resource:\"inspect"][..], true, invalid),
        (
            &["resource:read resource:inspect"][..],
            false,
            "HTTP signature must cover ssh-scope",
        ),
    ] {
        assert_rejected(
            &ssh_request_for(&signed, now, 23, scopes, covered),
            description,
        );
    }
    let changed = ssh_request(&signed, now, 23).replace(
        "SSH-Scope: resource:read",
        "SSH-Scope: resource:read resource:inspect",
    );
    assert_rejected(&changed, "HTTP message signature is missing or invalid");
    assert!(!authorized_keys().contains(&ssh_key(23)));
}

#[test]
fn ignores_command_selection_in_a_scope_registration() {
    let now = jsonwebtoken::get_current_timestamp();
    let signed = signature_key_for(ISSUER, SUBJECT, now + 120, 24);
    let mut request = ssh_request(&signed, now, 24);
    request.insert_str(request.len() - 2, "SSH-Command: admin\r\n");
    let response = send_request(&request);
    assert!(response.starts_with("HTTP/1.1 200 OK\r\n"), "{response}");
    let body: Value = serde_json::from_str(response.split_once("\r\n\r\n").unwrap().1).unwrap();
    assert_eq!(body["commands"], json!(["details", "resource"]));
}

#[test]
fn caps_repeated_registration_at_the_signed_creation_time() {
    let now = jsonwebtoken::get_current_timestamp();
    let signed = signature_key_for(ISSUER, SUBJECT, now + 600, 13);
    let request = ssh_request(&signed, now - 30, 13);
    for _ in 0..2 {
        let response = send_request(&request);
        assert!(response.starts_with("HTTP/1.1 200 OK\r\n"), "{response}");
        let body = response.split_once("\r\n\r\n").unwrap().1;
        assert_eq!(
            serde_json::from_str::<Value>(body).unwrap()["expires_at"],
            now + 30
        );
    }
    assert_eq!(authorized_keys().matches(&ssh_key(13)).count(), 1);
}

#[test]
fn denies_a_valid_signature_from_an_agent_outside_the_ssh_policy() {
    let now = jsonwebtoken::get_current_timestamp();
    let signed = signature_key_for(ISSUER, "aauth:other@agents.example", now + 300, 14);
    let response = send_request(&ssh_request(&signed, now, 14));
    assert!(
        response.starts_with("HTTP/1.1 403 Forbidden\r\n"),
        "{response}"
    );
    assert!(!authorized_keys().contains(&ssh_key(14)));
}

#[test]
fn rejects_unproven_ssh_keys_before_registration() {
    let now = jsonwebtoken::get_current_timestamp();
    let signed = signature_key_for(ISSUER, SUBJECT, now + 300, 15);
    assert_rejected(
        &ssh_request(&signed, now, 16),
        "HTTP message signature is missing or invalid",
    );
    assert!(!authorized_keys().contains(&ssh_key(15)));
}

#[test]
fn returns_404_for_an_unsupported_method() {
    let response = send_request(&current_request().replacen("GET ", "PUT ", 1));
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
