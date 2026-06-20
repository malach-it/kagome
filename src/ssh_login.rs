use std::{
    env, fs, io,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

use crate::{
    errors::OAuthError,
    resources::{
        authorization_code::{self, AuthorizationCodeCosePayload},
        client_credentials::CLIENT_SECRET,
        crypto::{self, ASYMMETRIC_CLIENT_ENCRYPTION_ALG, AsymmetricKeyPair, CoseEncrypt0Errors},
    },
    unit::{KagomeRequest, parse_query_parameter},
};

pub const OAUTH_CALLBACK_PATH: &str = "/oauth/callback";
pub const SSH_KEYS_ENV_VAR: &str = "KAGOME_SSH_KEYS";
const SSH_KEY_FILENAME_PREFIX: &str = "id_ed25519";
const SSH_KEYS_RESPONSE_EXTERNAL_AAD: &[u8] = b"kagome ssh_keys token response";

#[derive(serde::Deserialize)]
struct SshKeysResponseBody {
    ssh_private_key: String,
    ssh_public_key: String,
    ssh_certificate: String,
}

pub fn ssh_keys_path_from_environment() -> Option<PathBuf> {
    env::var_os(SSH_KEYS_ENV_VAR)
        .map(PathBuf::from)
        .or_else(|| Some(PathBuf::from("./.ssh")))
}

pub fn route_raw_request(request: &str) -> String {
    let request = crate::unit::parse_request(request);

    let ssh_keys_path = ssh_keys_path_from_environment();
    route_request_with_ssh_keys_path_code_verifier_and_client_id(
        &request,
        ssh_keys_path.as_deref(),
        None,
        None,
    )
}

pub fn route_raw_request_with_code_verifier(request: &str, code_verifier: &str) -> String {
    let request = crate::unit::parse_request(request);

    route_request_with_ssh_keys_path_code_verifier_and_client_id(
        &request,
        ssh_keys_path_from_environment().as_deref(),
        Some(code_verifier),
        None,
    )
}

pub fn route_raw_request_with_code_verifier_and_client_id(
    request: &str,
    code_verifier: &str,
    client_id: &str,
) -> String {
    let request = crate::unit::parse_request(request);

    route_request_with_ssh_keys_path_code_verifier_and_client_id(
        &request,
        ssh_keys_path_from_environment().as_deref(),
        Some(code_verifier),
        Some(client_id),
    )
}

pub fn route_request(request: &KagomeRequest) -> String {
    route_request_with_ssh_keys_path_code_verifier_and_client_id(
        request,
        ssh_keys_path_from_environment().as_deref(),
        None,
        None,
    )
}

pub fn route_raw_request_with_ssh_keys_path(request: &str, ssh_keys_path: Option<&Path>) -> String {
    let request = crate::unit::parse_request(request);

    route_request_with_ssh_keys_path_code_verifier_and_client_id(
        &request,
        ssh_keys_path,
        None,
        None,
    )
}

pub fn route_request_with_ssh_keys_path(
    request: &KagomeRequest,
    ssh_keys_path: Option<&Path>,
) -> String {
    route_request_with_ssh_keys_path_code_verifier_and_client_id(request, ssh_keys_path, None, None)
}

pub fn route_raw_request_with_ssh_keys_path_and_code_verifier(
    request: &str,
    ssh_keys_path: Option<&Path>,
    code_verifier: &str,
) -> String {
    let request = crate::unit::parse_request(request);

    route_request_with_ssh_keys_path_code_verifier_and_client_id(
        &request,
        ssh_keys_path,
        Some(code_verifier),
        None,
    )
}

pub fn route_raw_request_with_ssh_keys_path_code_verifier_and_client_id(
    request: &str,
    ssh_keys_path: Option<&Path>,
    code_verifier: &str,
    client_id: &str,
) -> String {
    let request = crate::unit::parse_request(request);

    route_request_with_ssh_keys_path_code_verifier_and_client_id(
        &request,
        ssh_keys_path,
        Some(code_verifier),
        Some(client_id),
    )
}

fn route_request_with_ssh_keys_path_code_verifier_and_client_id(
    request: &KagomeRequest,
    ssh_keys_path: Option<&Path>,
    code_verifier: Option<&str>,
    client_id: Option<&str>,
) -> String {
    if request.method.eq_ignore_ascii_case("GET") && request.path == OAUTH_CALLBACK_PATH {
        return oauth_callback_response(request, ssh_keys_path, code_verifier, client_id);
    }

    crate::router::route_request(request)
}

fn oauth_callback_response(
    request: &KagomeRequest,
    ssh_keys_path: Option<&Path>,
    code_verifier: Option<&str>,
    client_id: Option<&str>,
) -> String {
    let Some(code) = parse_query_parameter(request, "code") else {
        return OAuthError::missing_authorization_code().to_response();
    };
    let payload = match authorization_code::decode_cose_payload(&code) {
        Ok(payload) => payload,
        Err(error) => return error.to_response(),
    };
    let client_encryption_key_pair = match crypto::generate_asymmetric_key_pair() {
        Ok(client_encryption_key_pair) => client_encryption_key_pair,
        Err(error) => return error.to_response(),
    };
    let body = ssh_keys_token_request_body(
        &payload,
        &code,
        client_encryption_key_pair.public_key(),
        code_verifier,
        client_id,
    );
    let token_request = format!(
        "POST /token HTTP/1.1\r\nhost: localhost\r\ncontent-type: application/x-www-form-urlencoded\r\ncontent-length: {}\r\n\r\n{}",
        body.len(),
        body
    );

    let response = crate::handlers::token::handle(&crate::unit::parse_request(&token_request));
    let response = match decrypt_ssh_keys_token_response(&response, client_encryption_key_pair) {
        Ok(response) => response,
        Err(error) => return error.to_response(),
    };

    if let Some(ssh_keys_path) = ssh_keys_path
        && response.starts_with("HTTP/1.1 200 OK\r\n")
    {
        return store_ssh_keys_response(ssh_keys_path, &response, &payload);
    }

    response
}

fn ssh_keys_token_request_body(
    payload: &AuthorizationCodeCosePayload,
    code: &str,
    client_encryption_key: &str,
    code_verifier: Option<&str>,
    client_id: Option<&str>,
) -> String {
    let client_id = client_id.unwrap_or(&payload.client_id);
    let mut body = format!(
        "client_id={}&client_secret={}&grant_type=ssh_keys&code={}&client_encryption_key={}&client_encryption_alg={}",
        form_encode(client_id),
        form_encode(CLIENT_SECRET),
        form_encode(code),
        form_encode(client_encryption_key),
        form_encode(ASYMMETRIC_CLIENT_ENCRYPTION_ALG)
    );

    if let Some(code_verifier) = code_verifier {
        body.push_str("&code_verifier=");
        body.push_str(&form_encode(code_verifier));
    }

    body
}

fn decrypt_ssh_keys_token_response(
    response: &str,
    client_encryption_key_pair: AsymmetricKeyPair,
) -> Result<String, OAuthError> {
    if !response.starts_with("HTTP/1.1 200 OK\r\n")
        || !response.contains("content-type: application/cose\r\n")
    {
        return Ok(response.to_owned());
    }

    let Some(encoded_cose) = response.split_once("\r\n\r\n").map(|(_, body)| body) else {
        return Err(OAuthError::invalid_token_response(
            "encrypted token response did not include a body",
        ));
    };
    let plaintext = crypto::decode_cose_encrypt0_with_private_key(
        encoded_cose,
        client_encryption_key_pair,
        SSH_KEYS_RESPONSE_EXTERNAL_AAD,
        CoseEncrypt0Errors {
            invalid_cose: "ssh_keys token response must be a cose_encrypt0",
            missing_ciphertext: "ssh_keys token response must include ciphertext",
            missing_nonce: "ssh_keys token response must include nonce",
            decryption_failed: "ssh_keys token response decryption failed",
        },
    )?;
    let body = String::from_utf8(plaintext)
        .map_err(|_| OAuthError::invalid_token_response("ssh_keys token response must be utf-8"))?;

    Ok(format!(
        "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
        body.len(),
        body
    ))
}

fn store_ssh_keys_response(
    ssh_keys_path: &Path,
    response: &str,
    payload: &AuthorizationCodeCosePayload,
) -> String {
    let Some(body) = response.split_once("\r\n\r\n").map(|(_, body)| body) else {
        return storage_error_response("token response did not include a body");
    };

    let ssh_keys = match serde_json::from_str::<SshKeysResponseBody>(body) {
        Ok(ssh_keys) => ssh_keys,
        Err(error) => {
            return storage_error_response(&format!("failed to parse ssh keys: {error}"));
        }
    };

    let stored_ssh_keys = match store_ssh_keys(ssh_keys_path, &ssh_keys) {
        Ok(stored_ssh_keys) => stored_ssh_keys,
        Err(error) => {
            return storage_error_response(&format!("failed to store ssh keys: {error}"));
        }
    };

    ssh_keys_created_response(&stored_ssh_keys, payload)
}

struct StoredSshKeys {
    private_key_path: PathBuf,
    public_key_path: PathBuf,
    certificate_path: PathBuf,
}

fn store_ssh_keys(
    ssh_keys_path: &Path,
    ssh_keys: &SshKeysResponseBody,
) -> io::Result<StoredSshKeys> {
    fs::create_dir_all(ssh_keys_path)?;
    let key_filename = timestamped_ssh_key_filename();
    let private_key_path = ssh_keys_path.join(&key_filename);
    let public_key_path = ssh_keys_path.join(format!("{key_filename}.pub"));
    let certificate_path = ssh_keys_path.join(format!("{key_filename}-cert.pub"));

    write_ssh_key_file(&private_key_path, &ssh_keys.ssh_private_key, 0o600)?;
    write_ssh_key_file(&public_key_path, &ssh_keys.ssh_public_key, 0o644)?;
    write_ssh_key_file(&certificate_path, &ssh_keys.ssh_certificate, 0o644)?;

    Ok(StoredSshKeys {
        private_key_path,
        public_key_path,
        certificate_path,
    })
}

fn ssh_keys_created_response(
    stored_ssh_keys: &StoredSshKeys,
    payload: &AuthorizationCodeCosePayload,
) -> String {
    let body = ssh_keys_created_body(stored_ssh_keys, payload);

    format!(
        "HTTP/1.1 200 OK\r\ncontent-type: text/html\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
        body.len(),
        body
    )
}

fn ssh_keys_created_body(
    stored_ssh_keys: &StoredSshKeys,
    _payload: &AuthorizationCodeCosePayload,
) -> String {
    let private_key_path = stored_ssh_keys.private_key_path.display().to_string();
    let public_key_path = stored_ssh_keys.public_key_path.display().to_string();
    let certificate_path = stored_ssh_keys.certificate_path.display().to_string();

    format!(
        "<!doctype html><html><head><title>kagome ssh keys</title></head><body><main><h1>temporary ssh keys have been created</h1><p>private key: <code>{}</code></p><p>public key: <code>{}</code></p><p>certificate: <code>{}</code></p></main></body></html>",
        escape_html(&private_key_path),
        escape_html(&public_key_path),
        escape_html(&certificate_path)
    )
}

fn timestamped_ssh_key_filename() -> String {
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or_default();

    format!("{SSH_KEY_FILENAME_PREFIX}_{timestamp}")
}

fn write_ssh_key_file(path: &Path, contents: &str, mode: u32) -> io::Result<()> {
    fs::write(path, contents)?;
    set_file_mode(path, mode)
}

#[cfg(unix)]
fn set_file_mode(path: &Path, mode: u32) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;

    fs::set_permissions(path, fs::Permissions::from_mode(mode))
}

#[cfg(not(unix))]
fn set_file_mode(_path: &Path, _mode: u32) -> io::Result<()> {
    Ok(())
}

fn storage_error_response(message: &str) -> String {
    format!(
        "HTTP/1.1 500 Internal Server Error\r\ncontent-type: text/plain\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
        message.len(),
        message
    )
}

fn escape_html(value: &str) -> String {
    value
        .chars()
        .flat_map(|character| match character {
            '&' => "&amp;".chars().collect::<Vec<_>>(),
            '<' => "&lt;".chars().collect(),
            '>' => "&gt;".chars().collect(),
            '"' => "&quot;".chars().collect(),
            '\'' => "&#39;".chars().collect(),
            _ => vec![character],
        })
        .collect()
}

fn form_encode(value: &str) -> String {
    value
        .bytes()
        .flat_map(|byte| match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                vec![byte as char]
            }
            b' ' => vec!['+'],
            _ => {
                let hex = b"0123456789ABCDEF";
                vec![
                    '%',
                    hex[(byte >> 4) as usize] as char,
                    hex[(byte & 0x0F) as usize] as char,
                ]
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::{
        SSH_KEYS_RESPONSE_EXTERNAL_AAD, decrypt_ssh_keys_token_response,
        ssh_keys_path_from_environment, ssh_keys_token_request_body,
    };
    use std::path::PathBuf;

    use crate::resources::{
        authorization_code::AuthorizationCodeCosePayload,
        crypto::{
            ASYMMETRIC_CLIENT_ENCRYPTION_ALG, encode_cose_encrypt0_for_public_key,
            generate_asymmetric_key_pair,
        },
    };

    #[test]
    fn defaults_ssh_keys_path_to_local_ssh_directory() {
        assert_eq!(
            ssh_keys_path_from_environment(),
            Some(PathBuf::from("./.ssh"))
        );
    }

    #[test]
    fn ssh_keys_token_request_includes_client_encryption_parameters() {
        let body = ssh_keys_token_request_body(
            &AuthorizationCodeCosePayload {
                client_id: "username@example.com".to_owned(),
                id_token: None,
                username: Some("username".to_owned()),
                previous_code: None,
                code_challenge: None,
                code_challenge_method: None,
                iat: 1,
                exp: 2,
            },
            "authorization code",
            "client encryption key",
            Some("code verifier"),
            Some("username@example.com"),
        );

        assert!(body.contains("client_id=username%40example.com"));
        assert!(body.contains("code=authorization+code"));
        assert!(body.contains("client_encryption_key=client+encryption+key"));
        assert!(body.contains("code_verifier=code+verifier"));
        assert!(body.contains(&format!(
            "client_encryption_alg={}",
            ASYMMETRIC_CLIENT_ENCRYPTION_ALG.replace('+', "%2B")
        )));
    }

    #[test]
    fn decrypts_cose_ssh_keys_token_response_to_json_response() {
        let body = "{\"ssh_private_key\":\"private\"}";
        let client_encryption_key_pair = generate_asymmetric_key_pair().unwrap();
        let cose = encode_cose_encrypt0_for_public_key(
            body.as_bytes(),
            client_encryption_key_pair.public_key(),
            SSH_KEYS_RESPONSE_EXTERNAL_AAD,
        )
        .unwrap();
        let response = format!(
            "HTTP/1.1 200 OK\r\ncontent-type: application/cose\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
            cose.len(),
            cose
        );

        assert_eq!(
            decrypt_ssh_keys_token_response(&response, client_encryption_key_pair).unwrap(),
            "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: 29\r\nconnection: close\r\n\r\n{\"ssh_private_key\":\"private\"}"
        );
    }
}
