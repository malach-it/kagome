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
    },
    unit::{KagomeRequest, parse_query_parameter},
};

pub const OAUTH_CALLBACK_PATH: &str = "/oauth/callback";
pub const SSH_KEYS_ENV_VAR: &str = "KAGOME_SSH_KEYS";
const SSH_KEY_FILENAME_PREFIX: &str = "id_ed25519";

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
    route_request_with_ssh_keys_path(&request, ssh_keys_path.as_deref())
}

pub fn route_request(request: &KagomeRequest) -> String {
    route_request_with_ssh_keys_path(request, ssh_keys_path_from_environment().as_deref())
}

pub fn route_raw_request_with_ssh_keys_path(request: &str, ssh_keys_path: Option<&Path>) -> String {
    let request = crate::unit::parse_request(request);

    route_request_with_ssh_keys_path(&request, ssh_keys_path)
}

pub fn route_request_with_ssh_keys_path(
    request: &KagomeRequest,
    ssh_keys_path: Option<&Path>,
) -> String {
    if request.method.eq_ignore_ascii_case("GET") && request.path == OAUTH_CALLBACK_PATH {
        return oauth_callback_response(request, ssh_keys_path);
    }

    crate::router::route_request(request)
}

fn oauth_callback_response(request: &KagomeRequest, ssh_keys_path: Option<&Path>) -> String {
    let Some(code) = parse_query_parameter(request, "code") else {
        return OAuthError::missing_authorization_code().to_response();
    };
    let payload = match authorization_code::decode_cose_payload(&code) {
        Ok(payload) => payload,
        Err(error) => return error.to_response(),
    };
    let body = format!(
        "client_id={}&client_secret={}&grant_type=ssh_keys&code={}",
        form_encode(&payload.client_id),
        form_encode(CLIENT_SECRET),
        form_encode(&code)
    );
    let token_request = format!(
        "POST /token HTTP/1.1\r\nhost: localhost\r\ncontent-type: application/x-www-form-urlencoded\r\ncontent-length: {}\r\n\r\n{}",
        body.len(),
        body
    );

    let response = crate::handlers::token::handle(&crate::unit::parse_request(&token_request));

    if let Some(ssh_keys_path) = ssh_keys_path
        && response.starts_with("HTTP/1.1 200 OK\r\n")
    {
        return store_ssh_keys_response(ssh_keys_path, &response, &payload);
    }

    response
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
    let ssh_command = ssh_command(stored_ssh_keys, payload)
        .map(|command| format!("ssh command: {command}\n"))
        .unwrap_or_default();
    let body = format!(
        "temporary ssh keys have been created\nprivate key: {}\npublic key: {}\ncertificate: {}\n{}",
        stored_ssh_keys.private_key_path.display(),
        stored_ssh_keys.public_key_path.display(),
        stored_ssh_keys.certificate_path.display(),
        ssh_command
    );

    format!(
        "HTTP/1.1 200 OK\r\ncontent-type: text/plain\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
        body.len(),
        body
    )
}

fn ssh_command(
    stored_ssh_keys: &StoredSshKeys,
    payload: &AuthorizationCodeCosePayload,
) -> Option<String> {
    let username = payload.username.as_deref()?;
    let host = ssh_host_from_client_id(&payload.client_id)?;

    Some(format!(
        "ssh -i {} {username}@{host}",
        stored_ssh_keys.private_key_path.display()
    ))
}

fn ssh_host_from_client_id(client_id: &str) -> Option<&str> {
    let (_, host) = client_id.split_once('@')?;
    let host = host.split_once(':').map_or(host, |(host, _)| host);

    (!host.is_empty()).then_some(host)
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
    use super::ssh_keys_path_from_environment;
    use std::path::PathBuf;

    #[test]
    fn defaults_ssh_keys_path_to_local_ssh_directory() {
        assert_eq!(
            ssh_keys_path_from_environment(),
            Some(PathBuf::from("./.ssh"))
        );
    }
}
