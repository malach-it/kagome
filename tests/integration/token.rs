use super::server::send_request;
use std::{
    fs,
    path::PathBuf,
    process::Command,
    time::{SystemTime, UNIX_EPOCH},
};

const SSH_KEYS_CODE_VERIFIER: &str = "correct horse battery staple";

#[test]
fn returns_token_response_for_form_client_credentials_grant_type() {
    let response = send_request(
        "POST /token HTTP/1.1\r\nhost: example.com\r\ncontent-type: application/x-www-form-urlencoded\r\ncontent-length: 77\r\n\r\nclient_id=client_id&client_secret=client_secret&grant_type=client_credentials",
    );

    assert!(response.starts_with("HTTP/1.1 200 OK\r\n"));
    assert!(response.contains("content-type: application/json\r\n"));
    assert!(response.contains("connection: close\r\n"));
    assert!(response.contains("\"token_type\":\"bearer\""));
    assert!(response.contains("\"access_token\":\""));
    assert!(response.contains("\"expires_in\":3600"));
    assert!(!response.contains("\"authorization_code\""));
    assert!(!response.contains("\"client_id\""));
    assert!(!response.contains("\"client_secret\""));
    assert!(!response.contains("\"grant_type\""));
}

#[test]
fn returns_token_response_for_username_host_client_credentials_grant_type() {
    let body = "client_id=username%40localhost%3A4000&client_secret=client_secret&grant_type=client_credentials";
    let response = send_request(&format!(
        "POST /token HTTP/1.1\r\nhost: localhost:4000\r\ncontent-type: application/x-www-form-urlencoded\r\ncontent-length: {}\r\n\r\n{}",
        body.len(),
        body
    ));

    assert!(response.starts_with("HTTP/1.1 200 OK\r\n"));
    assert!(response.contains("content-type: application/json\r\n"));
    assert!(response.contains("\"token_type\":\"bearer\""));
    assert!(response.contains("\"access_token\":\""));
    assert!(response.contains("\"expires_in\":3600"));
}

#[test]
fn returns_token_response_for_json_client_credentials_grant_type() {
    let response = send_request(
        "POST /token HTTP/1.1\r\nhost: example.com\r\ncontent-type: application/json\r\ncontent-length: 91\r\n\r\n{\"client_id\":\"client_id\",\"client_secret\":\"client_secret\",\"grant_type\":\"client_credentials\"}",
    );

    assert!(response.starts_with("HTTP/1.1 200 OK\r\n"));
    assert!(response.contains("content-type: application/json\r\n"));
    assert!(response.contains("connection: close\r\n"));
    assert!(response.contains("\"token_type\":\"bearer\""));
    assert!(response.contains("\"access_token\":\""));
    assert!(response.contains("\"expires_in\":3600"));
    assert!(!response.contains("\"authorization_code\""));
    assert!(!response.contains("\"client_id\""));
    assert!(!response.contains("\"client_secret\""));
    assert!(!response.contains("\"grant_type\""));
}

#[test]
fn returns_token_response_for_form_code_chain_grant_type() {
    let body = format!(
        "client_id=client_id&client_secret=client_secret&grant_type=code_chain&id_token={}",
        valid_id_token()
    );
    let response = send_form_token_request(&body);

    assert!(response.starts_with("HTTP/1.1 200 OK\r\n"));
    assert!(response.contains("content-type: application/json\r\n"));
    assert!(response.contains("connection: close\r\n"));
    assert!(response.contains("\"authorization_code\":\""));
    assert!(response.contains("\"expires_in\":600"));
    assert!(!response.contains("\"token_type\""));
    assert!(!response.contains("\"access_token\""));
    assert!(!response.contains("\"client_id\""));
    assert!(!response.contains("\"client_secret\""));
    assert!(!response.contains("\"grant_type\""));
}

#[test]
fn returns_encrypted_authorization_code_containing_request_claims() {
    let id_token = valid_id_token();
    let body = format!(
        "client_id=client_id&client_secret=client_secret&grant_type=code_chain&id_token={id_token}",
    );
    let response = send_form_token_request(&body);
    let authorization_code = json_string_field(&response, "authorization_code")
        .expect("token response should include authorization_code");

    let payload =
        kagome::resources::authorization_code::decode_cose_payload(&authorization_code).unwrap();

    assert_eq!(payload.client_id, "client_id");
    assert_eq!(payload.id_token, Some(id_token));
    assert_eq!(payload.previous_code, None);
    assert_eq!(
        payload.exp,
        payload.iat + kagome::resources::authorization_code::AUTHORIZATION_CODE_TTL_SECONDS
    );
}

#[test]
fn returns_token_response_for_json_code_chain_grant_type() {
    let body = format!(
        "{{\"client_id\":\"client_id\",\"client_secret\":\"client_secret\",\"grant_type\":\"code_chain\",\"id_token\":\"{}\"}}",
        valid_id_token()
    );
    let response = send_json_token_request(&body);

    assert!(response.starts_with("HTTP/1.1 200 OK\r\n"));
    assert!(response.contains("content-type: application/json\r\n"));
    assert!(response.contains("connection: close\r\n"));
    assert!(response.contains("\"authorization_code\":\""));
    assert!(response.contains("\"expires_in\":600"));
    assert!(!response.contains("\"token_type\""));
    assert!(!response.contains("\"access_token\""));
    assert!(!response.contains("\"client_id\""));
    assert!(!response.contains("\"client_secret\""));
    assert!(!response.contains("\"grant_type\""));
}

#[test]
fn returns_token_response_for_form_authorization_code_grant_type() {
    let body = format!(
        "client_id=client_id&client_secret=client_secret&grant_type=authorization_code&code={}",
        valid_authorization_code()
    );
    let response = send_form_token_request(&body);

    assert!(response.starts_with("HTTP/1.1 200 OK\r\n"));
    assert!(response.contains("content-type: application/json\r\n"));
    assert!(response.contains("connection: close\r\n"));
    assert!(response.contains("\"token_type\":\"bearer\""));
    assert!(response.contains("\"access_token\":\""));
    assert!(response.contains("\"expires_in\":3600"));
    assert!(!response.contains("\"authorization_code\""));
    assert!(!response.contains("\"client_id\""));
    assert!(!response.contains("\"client_secret\""));
    assert!(!response.contains("\"grant_type\""));
}

#[test]
fn returns_token_response_for_json_authorization_code_grant_type() {
    let body = format!(
        "{{\"client_id\":\"client_id\",\"client_secret\":\"client_secret\",\"grant_type\":\"authorization_code\",\"code\":\"{}\"}}",
        valid_authorization_code()
    );
    let response = send_json_token_request(&body);

    assert!(response.starts_with("HTTP/1.1 200 OK\r\n"));
    assert!(response.contains("content-type: application/json\r\n"));
    assert!(response.contains("connection: close\r\n"));
    assert!(response.contains("\"token_type\":\"bearer\""));
    assert!(response.contains("\"access_token\":\""));
    assert!(response.contains("\"expires_in\":3600"));
    assert!(!response.contains("\"authorization_code\""));
}

#[test]
fn returns_token_response_for_authorization_code_with_matching_code_verifier() {
    let code_verifier = "correct horse battery staple";
    let body = format!(
        "client_id=client_id&client_secret=client_secret&grant_type=authorization_code&code={}&code_verifier={}",
        valid_authorization_code_with_code_challenge(code_verifier),
        query_encode(code_verifier)
    );
    let response = send_form_token_request(&body);

    assert!(response.starts_with("HTTP/1.1 200 OK\r\n"));
    assert!(response.contains("\"token_type\":\"bearer\""));
    assert!(response.contains("\"access_token\":\""));
}

#[test]
fn returns_oauth_error_for_authorization_code_with_missing_code_verifier() {
    let response = send_form_token_request(&format!(
        "client_id=client_id&client_secret=client_secret&grant_type=authorization_code&code={}",
        valid_authorization_code_with_code_challenge("correct horse battery staple")
    ));

    assert!(response.starts_with("HTTP/1.1 400 Bad Request\r\n"));
    assert!(response.contains("\"error\":\"invalid_grant\""));
    assert!(
        response
            .contains("\"error_description\":\"code_verifier is required for authorization_code\"")
    );
}

#[test]
fn returns_oauth_error_for_authorization_code_with_invalid_code_verifier() {
    let response = send_form_token_request(&format!(
        "client_id=client_id&client_secret=client_secret&grant_type=authorization_code&code={}&code_verifier=wrong",
        valid_authorization_code_with_code_challenge("correct horse battery staple")
    ));

    assert!(response.starts_with("HTTP/1.1 400 Bad Request\r\n"));
    assert!(response.contains("\"error\":\"invalid_grant\""));
    assert!(response.contains("\"error_description\":\"code_verifier is invalid\""));
}

#[test]
fn returns_oauth_error_for_ssh_keys_authorization_code_without_code_challenge() {
    let response = send_form_token_request(&format!(
        "client_id=client_id&client_secret=client_secret&grant_type=ssh_keys&code={}&code_verifier={}",
        valid_authorization_code_with_username_without_code_challenge("username"),
        query_encode(SSH_KEYS_CODE_VERIFIER)
    ));

    assert!(response.starts_with("HTTP/1.1 400 Bad Request\r\n"));
    assert!(response.contains("\"error\":\"invalid_grant\""));
    assert!(
        response
            .contains("\"error_description\":\"authorization_code code_challenge is required\"")
    );
}

#[test]
fn returns_ssh_keys_response_for_form_ssh_keys_grant_type() {
    let body = format!(
        "client_id=client_id&client_secret=client_secret&grant_type=ssh_keys&code={}&code_verifier={}",
        valid_authorization_code_with_username("username"),
        query_encode(SSH_KEYS_CODE_VERIFIER)
    );
    let response = send_form_token_request(&body);
    let certificate = json_string_field(&response, "ssh_certificate")
        .expect("token response should include ssh certificate");

    assert!(response.starts_with("HTTP/1.1 200 OK\r\n"));
    assert!(response.contains("content-type: application/json\r\n"));
    assert!(response.contains("connection: close\r\n"));
    assert!(response.contains("\"ssh_private_key\":\""));
    assert!(response.contains("\"ssh_public_key\":\"ssh-ed25519 "));
    assert!(certificate.starts_with("ssh-ed25519-cert-v01@openssh.com "));
    assert!(response.contains(&format!(
        "\"expires_in\":{}",
        kagome::resources::ssh_keys::SSH_KEYS_TTL_SECONDS
    )));
    assert_ssh_certificate_principal(&certificate, "username");
    assert!(!response.contains("\"access_token\""));
    assert!(!response.contains("\"authorization_code\""));
}

#[test]
fn returns_ssh_keys_response_for_json_ssh_keys_grant_type() {
    let body = format!(
        "{{\"client_id\":\"client_id\",\"client_secret\":\"client_secret\",\"grant_type\":\"ssh_keys\",\"code\":\"{}\",\"code_verifier\":\"{}\"}}",
        valid_authorization_code_with_username("other_username"),
        SSH_KEYS_CODE_VERIFIER
    );
    let response = send_json_token_request(&body);
    let certificate = json_string_field(&response, "ssh_certificate")
        .expect("token response should include ssh certificate");

    assert!(response.starts_with("HTTP/1.1 200 OK\r\n"));
    assert!(response.contains("content-type: application/json\r\n"));
    assert!(response.contains("connection: close\r\n"));
    assert!(response.contains("\"ssh_private_key\":\""));
    assert!(response.contains("\"ssh_public_key\":\"ssh-ed25519 "));
    assert!(certificate.starts_with("ssh-ed25519-cert-v01@openssh.com "));
    assert!(response.contains(&format!(
        "\"expires_in\":{}",
        kagome::resources::ssh_keys::SSH_KEYS_TTL_SECONDS
    )));
    assert_ssh_certificate_principal(&certificate, "other_username");
    assert!(!response.contains("\"access_token\""));
    assert!(!response.contains("\"authorization_code\""));
}

#[test]
fn returns_cose_encrypted_ssh_keys_response_when_client_encryption_is_requested() {
    let client_encryption_key_pair = kagome::resources::crypto::generate_asymmetric_key_pair()
        .expect("client encryption key pair should be generated");
    let body = format!(
        "client_id=client_id&client_secret=client_secret&grant_type=ssh_keys&code={}&client_encryption_key={}&client_encryption_alg=ECDH-ES%2BA256GCM&code_verifier={}",
        valid_authorization_code_with_username("username"),
        client_encryption_key_pair.public_key(),
        query_encode(SSH_KEYS_CODE_VERIFIER)
    );
    let response = send_form_token_request(&body);
    let plaintext = decrypt_cose_response_body(&response, client_encryption_key_pair);
    let certificate = json_string_value(&plaintext, "ssh_certificate")
        .expect("encrypted token response should include ssh certificate");

    assert!(response.starts_with("HTTP/1.1 200 OK\r\n"));
    assert!(response.contains("content-type: application/cose\r\n"));
    assert!(response.contains("connection: close\r\n"));
    assert!(!response.contains("\"ssh_private_key\""));
    assert!(plaintext.contains("\"ssh_private_key\":\""));
    assert!(plaintext.contains("\"ssh_public_key\":\"ssh-ed25519 "));
    assert!(certificate.starts_with("ssh-ed25519-cert-v01@openssh.com "));
    assert!(plaintext.contains(&format!(
        "\"expires_in\":{}",
        kagome::resources::ssh_keys::SSH_KEYS_TTL_SECONDS
    )));
    assert_ssh_certificate_principal(&certificate, "username");
}

#[test]
fn returns_oauth_error_for_unsupported_client_encryption_alg() {
    let body = format!(
        "client_id=client_id&client_secret=client_secret&grant_type=ssh_keys&code={}&client_encryption_key={}&client_encryption_alg=dir&code_verifier={}",
        valid_authorization_code_with_username("username"),
        kagome::resources::crypto::generate_asymmetric_key_pair()
            .expect("client encryption key pair should be generated")
            .public_key(),
        query_encode(SSH_KEYS_CODE_VERIFIER)
    );
    let response = send_form_token_request(&body);

    assert!(response.starts_with("HTTP/1.1 400 Bad Request\r\n"));
    assert!(response.contains("content-type: application/json\r\n"));
    assert!(response.contains("\"error\":\"invalid_token_response\""));
    assert!(
        response
            .contains("\"error_description\":\"client_encryption_alg must be ECDH-ES+A256GCM\"")
    );
}

#[test]
fn returns_ssh_keys_response_for_userinfo_authorization_code_client_id() {
    let body = format!(
        "client_id=username%40example.com&client_secret=client_secret&grant_type=ssh_keys&code={}&code_verifier={}",
        valid_authorization_code_with_client_id_and_username("username@example.com", "username"),
        query_encode(SSH_KEYS_CODE_VERIFIER)
    );
    let response = send_form_token_request(&body);
    let certificate = json_string_field(&response, "ssh_certificate")
        .expect("token response should include ssh certificate");

    assert!(response.starts_with("HTTP/1.1 200 OK\r\n"));
    assert!(response.contains("content-type: application/json\r\n"));
    assert!(response.contains("\"ssh_private_key\":\""));
    assert!(response.contains("\"ssh_public_key\":\"ssh-ed25519 "));
    assert!(certificate.starts_with("ssh-ed25519-cert-v01@openssh.com "));
    assert_ssh_certificate_key_id(&certificate, "username@example.com");
    assert_ssh_certificate_principal(&certificate, "username");
}

#[test]
fn returns_token_response_for_form_code_chain_authorization_code_grant_type() {
    let body = format!(
        "client_id=client_id&client_secret=client_secret&grant_type=code_chain+authorization_code&id_token={}&code={}",
        valid_id_token(),
        valid_authorization_code()
    );
    let response = send_form_token_request(&body);

    assert!(response.starts_with("HTTP/1.1 200 OK\r\n"));
    assert!(response.contains("content-type: application/json\r\n"));
    assert!(response.contains("connection: close\r\n"));
    assert!(response.contains("\"token_type\":\"bearer\""));
    assert!(response.contains("\"access_token\":\""));
    assert!(response.contains("\"expires_in\":3600"));
    assert!(!response.contains("\"authorization_code\""));
    assert!(!response.contains("\"client_id\""));
    assert!(!response.contains("\"client_secret\""));
    assert!(!response.contains("\"grant_type\""));
}

#[test]
fn returns_token_response_for_json_code_chain_authorization_code_grant_type() {
    let body = format!(
        "{{\"client_id\":\"client_id\",\"client_secret\":\"client_secret\",\"grant_type\":\"code_chain authorization_code\",\"id_token\":\"{}\",\"code\":\"{}\"}}",
        valid_id_token(),
        valid_authorization_code()
    );
    let response = send_json_token_request(&body);

    assert!(response.starts_with("HTTP/1.1 200 OK\r\n"));
    assert!(response.contains("content-type: application/json\r\n"));
    assert!(response.contains("connection: close\r\n"));
    assert!(response.contains("\"token_type\":\"bearer\""));
    assert!(response.contains("\"access_token\":\""));
    assert!(response.contains("\"expires_in\":3600"));
    assert!(!response.contains("\"authorization_code\""));
    assert!(!response.contains("\"client_id\""));
    assert!(!response.contains("\"client_secret\""));
    assert!(!response.contains("\"grant_type\""));
}

#[test]
fn returns_oauth_error_for_missing_authorization_code_grant_type_client_id() {
    let response = send_request(
        "POST /token HTTP/1.1\r\nhost: example.com\r\ncontent-type: application/x-www-form-urlencoded\r\ncontent-length: 29\r\n\r\ngrant_type=authorization_code",
    );

    assert_missing_client_id_response(&response);
}

#[test]
fn returns_oauth_error_for_missing_authorization_code_grant_type_client_secret() {
    let response = send_form_token_request("client_id=client_id&grant_type=authorization_code");

    assert_missing_client_secret_response(&response);
}

#[test]
fn returns_oauth_error_for_missing_authorization_code_grant_type_authorization_code() {
    let response = send_form_token_request(
        "client_id=client_id&client_secret=client_secret&grant_type=authorization_code",
    );

    assert_missing_authorization_code_response(&response);
}

#[test]
fn returns_oauth_error_for_invalid_authorization_code_grant_type_authorization_code() {
    let response = send_form_token_request(
        "client_id=client_id&client_secret=client_secret&grant_type=authorization_code&code=app",
    );

    assert_invalid_authorization_code_response(&response);
}

#[test]
fn returns_oauth_error_for_missing_code_chain_id_token() {
    let response = send_request(
        "POST /token HTTP/1.1\r\nhost: example.com\r\ncontent-type: application/x-www-form-urlencoded\r\ncontent-length: 69\r\n\r\nclient_id=client_id&client_secret=client_secret&grant_type=code_chain",
    );

    assert_missing_id_token_response(&response);
}

#[test]
fn returns_oauth_error_for_invalid_code_chain_id_token() {
    let response = send_request(
        "POST /token HTTP/1.1\r\nhost: example.com\r\ncontent-type: application/x-www-form-urlencoded\r\ncontent-length: 82\r\n\r\nclient_id=client_id&client_secret=client_secret&grant_type=code_chain&id_token=app",
    );

    assert_invalid_id_token_response(&response);
}

#[test]
fn returns_oauth_error_for_invalid_code_chain_authorization_code() {
    let body = format!(
        "client_id=client_id&client_secret=client_secret&grant_type=code_chain&id_token={}&authorization_code=app",
        valid_id_token()
    );
    let response = send_form_token_request(&body);

    assert_invalid_authorization_code_response(&response);
}

#[test]
fn returns_oauth_error_for_unsupported_form_grant_type() {
    let response = send_request(
        "POST /token HTTP/1.1\r\nhost: example.com\r\ncontent-type: application/x-www-form-urlencoded\r\ncontent-length: 67\r\n\r\nclient_id=client_id&client_secret=client_secret&grant_type=password",
    );

    assert_unsupported_grant_type_response(&response);
}

#[test]
fn returns_oauth_error_for_unsupported_json_grant_type() {
    let response = send_request(
        "POST /token HTTP/1.1\r\nhost: example.com\r\ncontent-type: application/json\r\ncontent-length: 81\r\n\r\n{\"client_id\":\"client_id\",\"client_secret\":\"client_secret\",\"grant_type\":\"password\"}",
    );

    assert_unsupported_grant_type_response(&response);
}

#[test]
fn returns_oauth_error_for_missing_grant_type() {
    let response = send_request(
        "POST /token HTTP/1.1\r\nhost: example.com\r\ncontent-type: application/x-www-form-urlencoded\r\ncontent-length: 47\r\n\r\nclient_id=client_id&client_secret=client_secret",
    );

    assert_unsupported_grant_type_response(&response);
}

#[test]
fn returns_oauth_error_for_missing_client_id() {
    let response = send_request(
        "POST /token HTTP/1.1\r\nhost: example.com\r\ncontent-type: application/x-www-form-urlencoded\r\ncontent-length: 57\r\n\r\nclient_secret=client_secret&grant_type=client_credentials",
    );

    assert_missing_client_id_response(&response);
}

#[test]
fn returns_oauth_error_for_invalid_client_id() {
    let response = send_request(
        "POST /token HTTP/1.1\r\nhost: example.com\r\ncontent-type: application/x-www-form-urlencoded\r\ncontent-length: 71\r\n\r\nclient_id=app&client_secret=client_secret&grant_type=client_credentials",
    );

    assert_invalid_client_id_response(&response);
}

#[test]
fn returns_oauth_error_for_missing_client_secret() {
    let response = send_request(
        "POST /token HTTP/1.1\r\nhost: example.com\r\ncontent-type: application/x-www-form-urlencoded\r\ncontent-length: 49\r\n\r\nclient_id=client_id&grant_type=client_credentials",
    );

    assert_missing_client_secret_response(&response);
}

#[test]
fn returns_oauth_error_for_invalid_client_secret() {
    let response = send_request(
        "POST /token HTTP/1.1\r\nhost: example.com\r\ncontent-type: application/x-www-form-urlencoded\r\ncontent-length: 67\r\n\r\nclient_id=client_id&client_secret=app&grant_type=client_credentials",
    );

    assert_invalid_client_secret_response(&response);
}

#[test]
fn returns_not_found_for_non_post_token_request() {
    let response = send_request("GET /token HTTP/1.1\r\nhost: example.com\r\n\r\n");

    assert!(response.starts_with("HTTP/1.1 404 Not Found\r\n"));
    assert!(response.contains("content-type: text/plain\r\n"));
    assert!(response.contains("connection: close\r\n"));
    assert!(response.ends_with("not found"));
}

fn assert_unsupported_grant_type_response(response: &str) {
    assert!(response.starts_with("HTTP/1.1 400 Bad Request\r\n"));
    assert!(response.contains("content-type: application/json\r\n"));
    assert!(response.contains("connection: close\r\n"));
    assert!(response.contains("\"error\":\"unsupported_grant_type\""));
    assert!(response.contains(
        "\"error_description\":\"grant_type must be one of: client_credentials, code_chain, authorization_code, ssh_keys\""
    ));
}

fn assert_missing_authorization_code_response(response: &str) {
    assert!(response.starts_with("HTTP/1.1 400 Bad Request\r\n"));
    assert!(response.contains("content-type: application/json\r\n"));
    assert!(response.contains("connection: close\r\n"));
    assert!(response.contains("\"error\":\"invalid_grant\""));
    assert!(response.contains("\"error_description\":\"authorization_code is required\""));
}

fn assert_invalid_client_id_response(response: &str) {
    assert!(response.starts_with("HTTP/1.1 400 Bad Request\r\n"));
    assert!(response.contains("content-type: application/json\r\n"));
    assert!(response.contains("connection: close\r\n"));
    assert!(response.contains("\"error\":\"invalid_client\""));
    assert!(response.contains("\"error_description\":\"client_id is invalid\""));
}

fn assert_missing_client_id_response(response: &str) {
    assert!(response.starts_with("HTTP/1.1 400 Bad Request\r\n"));
    assert!(response.contains("content-type: application/json\r\n"));
    assert!(response.contains("connection: close\r\n"));
    assert!(response.contains("\"error\":\"invalid_client\""));
    assert!(response.contains("\"error_description\":\"client_id is required\""));
}

fn assert_invalid_client_secret_response(response: &str) {
    assert!(response.starts_with("HTTP/1.1 400 Bad Request\r\n"));
    assert!(response.contains("content-type: application/json\r\n"));
    assert!(response.contains("connection: close\r\n"));
    assert!(response.contains("\"error\":\"invalid_client\""));
    assert!(response.contains("\"error_description\":\"client_secret must be: client_secret\""));
}

fn assert_missing_client_secret_response(response: &str) {
    assert!(response.starts_with("HTTP/1.1 400 Bad Request\r\n"));
    assert!(response.contains("content-type: application/json\r\n"));
    assert!(response.contains("connection: close\r\n"));
    assert!(response.contains("\"error\":\"invalid_client\""));
    assert!(response.contains("\"error_description\":\"client_secret is required\""));
}

fn assert_missing_id_token_response(response: &str) {
    assert!(response.starts_with("HTTP/1.1 400 Bad Request\r\n"));
    assert!(response.contains("content-type: application/json\r\n"));
    assert!(response.contains("connection: close\r\n"));
    assert!(response.contains("\"error\":\"invalid_grant\""));
    assert!(response.contains("\"error_description\":\"id_token is required\""));
}

fn assert_invalid_id_token_response(response: &str) {
    assert!(response.starts_with("HTTP/1.1 400 Bad Request\r\n"));
    assert!(response.contains("content-type: application/json\r\n"));
    assert!(response.contains("connection: close\r\n"));
    assert!(response.contains("\"error\":\"invalid_grant\""));
    assert!(response.contains("\"error_description\":\"id_token must be a jwt\""));
}

fn assert_invalid_authorization_code_response(response: &str) {
    assert!(response.starts_with("HTTP/1.1 400 Bad Request\r\n"));
    assert!(response.contains("content-type: application/json\r\n"));
    assert!(response.contains("connection: close\r\n"));
    assert!(response.contains("\"error\":\"invalid_grant\""));
    assert!(
        response.contains("\"error_description\":\"authorization_code must be a cose_encrypt0\"")
    );
}

fn send_form_token_request(body: &str) -> String {
    send_request(&format!(
        "POST /token HTTP/1.1\r\nhost: example.com\r\ncontent-type: application/x-www-form-urlencoded\r\ncontent-length: {}\r\n\r\n{}",
        body.len(),
        body
    ))
}

fn send_json_token_request(body: &str) -> String {
    send_request(&format!(
        "POST /token HTTP/1.1\r\nhost: example.com\r\ncontent-type: application/json\r\ncontent-length: {}\r\n\r\n{}",
        body.len(),
        body
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

fn json_string_field(response: &str, field: &str) -> Option<String> {
    json_string_value(response, field)
}

fn json_string_value(json: &str, field: &str) -> Option<String> {
    let field = format!("\"{field}\":\"");
    let start = json.find(&field)? + field.len();
    let end = json[start..].find('"')?;

    Some(json[start..start + end].to_owned())
}

fn decrypt_cose_response_body(
    response: &str,
    client_encryption_key_pair: kagome::resources::crypto::AsymmetricKeyPair,
) -> String {
    let encoded_cose = response
        .split_once("\r\n\r\n")
        .map(|(_, body)| body)
        .expect("response should include body");
    let plaintext = kagome::resources::crypto::decode_cose_encrypt0_with_private_key(
        encoded_cose,
        client_encryption_key_pair,
        b"kagome ssh_keys token response",
        kagome::resources::crypto::CoseEncrypt0Errors {
            invalid_cose: "response must be a cose_encrypt0",
            missing_ciphertext: "response must include ciphertext",
            missing_nonce: "response must include nonce",
            decryption_failed: "response decryption failed",
        },
    )
    .expect("response should decrypt");

    String::from_utf8(plaintext).expect("response should be utf-8")
}

fn valid_id_token() -> String {
    #[derive(serde::Serialize)]
    struct Claims {
        iat: u64,
        exp: u64,
    }

    let mut header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::HS256);
    header.jwk = Some(jwk());
    let now = jsonwebtoken::get_current_timestamp();

    jsonwebtoken::encode(
        &header,
        &Claims {
            iat: now,
            exp: now + 3600,
        },
        &jsonwebtoken::EncodingKey::from_secret(b"secret"),
    )
    .unwrap()
}

fn valid_authorization_code() -> String {
    struct TestAuthorizationCodeRequest {
        authorization_code: Option<kagome::resources::authorization_code::AuthorizationCode>,
        id_token: String,
    }

    impl kagome::resources::authorization_code::Generate for TestAuthorizationCodeRequest {
        fn previous_authorization_code(&self) -> Option<&str> {
            None
        }

        fn client_id(&self) -> Option<&str> {
            Some("client_id")
        }

        fn id_token(&self) -> Option<&str> {
            Some(&self.id_token)
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
        id_token: valid_id_token(),
    };

    kagome::resources::authorization_code::generate(request)
        .unwrap()
        .authorization_code
        .unwrap()
        .value
}

fn valid_authorization_code_with_code_challenge(code_verifier: &str) -> String {
    struct TestAuthorizationCodeRequest {
        authorization_code: Option<kagome::resources::authorization_code::AuthorizationCode>,
        id_token: String,
        code_challenge: String,
    }

    impl kagome::resources::authorization_code::Generate for TestAuthorizationCodeRequest {
        fn previous_authorization_code(&self) -> Option<&str> {
            None
        }

        fn client_id(&self) -> Option<&str> {
            Some("client_id")
        }

        fn id_token(&self) -> Option<&str> {
            Some(&self.id_token)
        }

        fn code_challenge(&self) -> Option<&str> {
            Some(&self.code_challenge)
        }

        fn code_challenge_method(&self) -> Option<&str> {
            Some(kagome::resources::code_verifier::CODE_CHALLENGE_METHOD_S256)
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
        id_token: valid_id_token(),
        code_challenge: kagome::resources::code_verifier::code_challenge_s256(code_verifier),
    };

    kagome::resources::authorization_code::generate(request)
        .unwrap()
        .authorization_code
        .unwrap()
        .value
}

fn valid_authorization_code_with_username(username: &'static str) -> String {
    valid_authorization_code_with_client_id_and_username("client_id", username)
}

fn valid_authorization_code_with_username_without_code_challenge(username: &'static str) -> String {
    struct TestAuthorizationCodeRequest {
        authorization_code: Option<kagome::resources::authorization_code::AuthorizationCode>,
        username: &'static str,
    }

    impl kagome::resources::authorization_code::Generate for TestAuthorizationCodeRequest {
        fn previous_authorization_code(&self) -> Option<&str> {
            None
        }

        fn client_id(&self) -> Option<&str> {
            Some("client_id")
        }

        fn id_token(&self) -> Option<&str> {
            None
        }

        fn username(&self) -> Option<&str> {
            Some(self.username)
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
        username,
    };

    kagome::resources::authorization_code::generate(request)
        .unwrap()
        .authorization_code
        .unwrap()
        .value
}

fn valid_authorization_code_with_client_id_and_username(
    client_id: &'static str,
    username: &'static str,
) -> String {
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
        code_challenge: kagome::resources::code_verifier::code_challenge_s256(
            SSH_KEYS_CODE_VERIFIER,
        ),
    };

    kagome::resources::authorization_code::generate(request)
        .unwrap()
        .authorization_code
        .unwrap()
        .value
}

fn assert_ssh_certificate_principal(certificate: &str, principal: &str) {
    let certificate_details = ssh_certificate_details(certificate);

    assert!(
        certificate_details.contains(&format!("        {principal}\n")),
        "certificate did not contain principal {principal}: {}",
        certificate_details
    );
    assert!(
        certificate_details.contains("Valid: from ") && certificate_details.contains(" to "),
        "certificate did not include finite validity: {certificate_details}"
    );
    assert!(
        !certificate_details.contains("forever"),
        "certificate should not be valid forever: {certificate_details}"
    );
}

fn assert_ssh_certificate_key_id(certificate: &str, key_id: &str) {
    let certificate_details = ssh_certificate_details(certificate);

    assert!(
        certificate_details.contains(&format!("Key ID: \"{key_id}\"")),
        "certificate did not contain key id {key_id}: {}",
        certificate_details
    );
}

fn ssh_certificate_details(certificate: &str) -> String {
    let certificate_path = temporary_certificate_path();
    fs::write(&certificate_path, certificate).expect("failed to write ssh certificate");

    let output = Command::new("ssh-keygen")
        .arg("-Lf")
        .arg(&certificate_path)
        .output()
        .expect("failed to inspect ssh certificate");

    let _ = fs::remove_file(&certificate_path);

    assert!(output.status.success());
    String::from_utf8_lossy(&output.stdout).into_owned()
}

fn temporary_certificate_path() -> PathBuf {
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock before unix epoch")
        .as_nanos();

    std::env::temp_dir().join(format!("kagome-cert-{}-{unique}.pub", std::process::id()))
}

fn jwk() -> jsonwebtoken::jwk::Jwk {
    jsonwebtoken::jwk::Jwk {
        common: jsonwebtoken::jwk::CommonParameters {
            key_algorithm: Some(jsonwebtoken::jwk::KeyAlgorithm::HS256),
            ..Default::default()
        },
        algorithm: jsonwebtoken::jwk::AlgorithmParameters::OctetKey(
            jsonwebtoken::jwk::OctetKeyParameters {
                key_type: jsonwebtoken::jwk::OctetKeyType::Octet,
                value: "c2VjcmV0".to_owned(),
            },
        ),
    }
}
