use std::{
    fs,
    path::PathBuf,
    process::Command,
    time::{SystemTime, UNIX_EPOCH},
};

const CODE_VERIFIER: &str = "correct horse battery staple";

#[test]
fn oauth_callback_exchanges_authorization_code_for_ssh_keys() {
    let code = valid_authorization_code("username@example.com", "username");
    let response =
        kagome::ssh_login::route_raw_request_with_ssh_keys_path_code_verifier_and_client_id(
            &format!(
                "GET /oauth/callback?code={} HTTP/1.1\r\nhost: localhost\r\n\r\n",
                query_encode(&code)
            ),
            None,
            CODE_VERIFIER,
            "username@example.com",
        );
    let certificate = json_string_field(&response, "ssh_certificate")
        .expect("callback response should include ssh certificate");

    assert!(response.starts_with("HTTP/1.1 200 OK\r\n"));
    assert!(response.contains("content-type: application/json\r\n"));
    assert!(response.contains("\"ssh_private_key\":\""));
    assert!(response.contains("\"ssh_public_key\":\"ssh-ed25519 "));
    assert!(certificate.starts_with("ssh-ed25519-cert-v01@openssh.com "));
    assert!(response.contains(&format!(
        "\"expires_in\":{}",
        kagome::resources::ssh_keys::SSH_KEYS_TTL_SECONDS
    )));
    assert_ssh_certificate_principal(&certificate, "username");
}

#[test]
fn oauth_callback_stores_ssh_keys_when_path_is_configured() {
    let code = valid_authorization_code("username@example.com", "username");
    let ssh_keys_path = temporary_ssh_keys_path();
    let response =
        kagome::ssh_login::route_raw_request_with_ssh_keys_path_code_verifier_and_client_id(
            &format!(
                "GET /oauth/callback?code={} HTTP/1.1\r\nhost: localhost\r\n\r\n",
                query_encode(&code)
            ),
            Some(&ssh_keys_path),
            CODE_VERIFIER,
            "username@example.com",
        );
    let (private_key_path, public_key_path, certificate_path) =
        stored_ssh_key_paths(&ssh_keys_path);
    let private_key = fs::read_to_string(&private_key_path).expect("private key should be stored");
    let public_key = fs::read_to_string(&public_key_path).expect("public key should be stored");
    let certificate = fs::read_to_string(&certificate_path).expect("certificate should be stored");

    assert!(response.starts_with("HTTP/1.1 200 OK\r\n"));
    assert!(response.contains("content-type: text/html\r\n"));
    assert!(response.contains("temporary ssh keys have been created"));
    assert!(response.contains(&format!(
        "private key: <code>{}</code>",
        private_key_path.display()
    )));
    assert!(response.contains(&format!(
        "public key: <code>{}</code>",
        public_key_path.display()
    )));
    assert!(response.contains(&format!(
        "certificate: <code>{}</code>",
        certificate_path.display()
    )));
    assert!(!response.contains("name=\"host\""));
    assert!(!response.contains("ssh command:"));
    assert_eq!(
        public_key_path.file_name().and_then(|name| name.to_str()),
        private_key_path
            .file_name()
            .and_then(|name| name.to_str())
            .map(|name| format!("{name}.pub"))
            .as_deref()
    );
    assert_eq!(
        certificate_path.file_name().and_then(|name| name.to_str()),
        private_key_path
            .file_name()
            .and_then(|name| name.to_str())
            .map(|name| format!("{name}-cert.pub"))
            .as_deref()
    );
    assert!(private_key.starts_with("-----BEGIN OPENSSH PRIVATE KEY-----"));
    assert!(public_key.starts_with("ssh-ed25519 "));
    assert!(certificate.starts_with("ssh-ed25519-cert-v01@openssh.com "));
    assert_private_key_permissions(&private_key_path);
    assert_ssh_certificate_principal(&certificate, "username");

    let _ = fs::remove_dir_all(&ssh_keys_path);
}

#[test]
fn oauth_callback_does_not_render_host_prompt() {
    let code = valid_authorization_code("username@localhost:4000", "username");
    let ssh_keys_path = temporary_ssh_keys_path();
    let response =
        kagome::ssh_login::route_raw_request_with_ssh_keys_path_code_verifier_and_client_id(
            &format!(
                "GET /oauth/callback?code={} HTTP/1.1\r\nhost: localhost\r\n\r\n",
                query_encode(&code)
            ),
            Some(&ssh_keys_path),
            CODE_VERIFIER,
            "username@localhost:4000",
        );

    assert!(response.starts_with("HTTP/1.1 200 OK\r\n"));
    assert!(!response.contains("name=\"host\""));
    assert!(!response.contains("ssh-command"));

    let _ = fs::remove_dir_all(&ssh_keys_path);
}

#[test]
fn oauth_callback_returns_oauth_error_when_code_verifier_is_missing() {
    let code = valid_authorization_code("username@example.com", "username");
    let response = kagome::ssh_login::route_raw_request_with_ssh_keys_path(
        &format!(
            "GET /oauth/callback?code={} HTTP/1.1\r\nhost: localhost\r\n\r\n",
            query_encode(&code)
        ),
        None,
    );

    assert!(response.starts_with("HTTP/1.1 400 Bad Request\r\n"));
    assert!(response.contains("\"error\":\"invalid_grant\""));
    assert!(
        response
            .contains("\"error_description\":\"code_verifier is required for authorization_code\"")
    );
}

#[test]
fn oauth_callback_returns_oauth_error_when_code_is_missing() {
    let response = kagome::ssh_login::route_raw_request(
        "GET /oauth/callback HTTP/1.1\r\nhost: localhost\r\n\r\n",
    );

    assert!(response.starts_with("HTTP/1.1 400 Bad Request\r\n"));
    assert!(response.contains("\"error\":\"invalid_grant\""));
    assert!(response.contains("\"error_description\":\"authorization_code is required\""));
}

#[test]
fn oauth_callback_does_not_store_ssh_keys_when_code_is_missing() {
    let ssh_keys_path = temporary_ssh_keys_path();
    let response = kagome::ssh_login::route_raw_request_with_ssh_keys_path(
        "GET /oauth/callback HTTP/1.1\r\nhost: localhost\r\n\r\n",
        Some(&ssh_keys_path),
    );

    assert!(response.starts_with("HTTP/1.1 400 Bad Request\r\n"));
    assert!(!ssh_keys_path.exists());

    let _ = fs::remove_dir_all(&ssh_keys_path);
}

#[test]
fn main_router_does_not_route_oauth_callback() {
    let code = valid_authorization_code("username@example.com", "username");
    let response = kagome::router::route_raw_request(&format!(
        "GET /oauth/callback?code={} HTTP/1.1\r\nhost: localhost\r\n\r\n",
        query_encode(&code)
    ));

    assert!(response.starts_with("HTTP/1.1 404 Not Found\r\n"));
}

fn valid_authorization_code(client_id: &'static str, username: &'static str) -> String {
    struct TestAuthorizationCodeRequest {
        authorization_code: Option<kagome::resources::authorization_code::AuthorizationCode>,
        client_id: &'static str,
        username: &'static str,
        code_challenge: String,
    }

    impl kagome::resources::authorization_code::Generate for TestAuthorizationCodeRequest {
        fn previous_authorization_code(&self) -> Option<&str> {
            None
        }

        fn client_id(&self) -> Option<&str> {
            Some(self.client_id)
        }

        fn id_token(&self) -> Option<&str> {
            None
        }

        fn username(&self) -> Option<&str> {
            Some(self.username)
        }

        fn code_challenge(&self) -> Option<&str> {
            Some(&self.code_challenge)
        }

        fn code_challenge_method(&self) -> Option<&str> {
            Some(kagome::resources::code_verifier::CODE_CHALLENGE_METHOD_S256)
        }

        fn require_id_token(&self) -> bool {
            false
        }

        fn require_username(&self) -> bool {
            true
        }

        fn add_authorization_code(
            &mut self,
            authorization_code: kagome::resources::authorization_code::AuthorizationCode,
        ) {
            self.authorization_code = Some(authorization_code);
        }
    }

    let request = TestAuthorizationCodeRequest {
        authorization_code: None,
        client_id,
        username,
        code_challenge: kagome::resources::code_verifier::code_challenge_s256(CODE_VERIFIER),
    };

    kagome::resources::authorization_code::generate(request)
        .unwrap()
        .authorization_code
        .unwrap()
        .value
}

fn json_string_field(response: &str, field: &str) -> Option<String> {
    let field = format!("\"{field}\":\"");
    let start = response.find(&field)? + field.len();
    let end = response[start..].find('"')?;

    Some(response[start..start + end].replace("\\n", "\n"))
}

fn assert_ssh_certificate_principal(certificate: &str, principal: &str) {
    let certificate_path = temporary_certificate_path();
    fs::write(&certificate_path, certificate).expect("failed to write ssh certificate");

    let output = Command::new("ssh-keygen")
        .arg("-Lf")
        .arg(&certificate_path)
        .output()
        .expect("failed to inspect ssh certificate");

    let _ = fs::remove_file(&certificate_path);

    assert!(output.status.success());
    let certificate_details = String::from_utf8_lossy(&output.stdout);
    assert!(
        certificate_details.contains(&format!("        {principal}\n")),
        "certificate did not contain principal {principal}: {}",
        certificate_details
    );
}

fn stored_ssh_key_paths(ssh_keys_path: &PathBuf) -> (PathBuf, PathBuf, PathBuf) {
    let paths = fs::read_dir(ssh_keys_path)
        .expect("ssh keys directory should exist")
        .map(|entry| entry.expect("ssh key entry should be readable").path())
        .collect::<Vec<_>>();
    let private_key_path = paths
        .iter()
        .find(|path| {
            path.file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.starts_with("id_ed25519_") && !name.ends_with(".pub"))
        })
        .expect("private key should be stored")
        .to_owned();
    let public_key_path = paths
        .iter()
        .find(|path| {
            path.file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| {
                    name.starts_with("id_ed25519_")
                        && name.ends_with(".pub")
                        && !name.ends_with("-cert.pub")
                })
        })
        .expect("public key should be stored")
        .to_owned();
    let certificate_path = paths
        .iter()
        .find(|path| {
            path.file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.starts_with("id_ed25519_") && name.ends_with("-cert.pub"))
        })
        .expect("certificate should be stored")
        .to_owned();

    (private_key_path, public_key_path, certificate_path)
}

#[cfg(unix)]
fn assert_private_key_permissions(private_key_path: &PathBuf) {
    use std::os::unix::fs::PermissionsExt;

    let mode = fs::metadata(private_key_path)
        .expect("private key metadata should be readable")
        .permissions()
        .mode()
        & 0o777;

    assert_eq!(mode, 0o600);
}

#[cfg(not(unix))]
fn assert_private_key_permissions(_private_key_path: &PathBuf) {}

fn temporary_certificate_path() -> PathBuf {
    temporary_path("cert", "pub")
}

fn temporary_ssh_keys_path() -> PathBuf {
    temporary_path("ssh-keys", "json")
}

fn temporary_path(name: &str, extension: &str) -> PathBuf {
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock before unix epoch")
        .as_nanos();

    std::env::temp_dir().join(format!(
        "kagome-{name}-{}-{unique}.{extension}",
        std::process::id()
    ))
}

fn query_encode(value: &str) -> String {
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
