use super::*;

// Branch matrix:
// - representation: form | JSON (success exercises both parser branches)
// - access-token artifact: opaque COSE_Encrypt0
// - client_id: first configured | second configured | public username@host | missing |
//   unconfigured
// - client_secret: matching | missing | invalid
// Missing and invalid credential failures are representation-independent after parsing,
// so each equivalent validation path is exercised once with form input.

#[test]
fn returns_token_response_for_form_client_credentials_grant_type() {
    let response = send_request(
        "POST /token HTTP/1.1\r\nhost: example.com\r\ncontent-type: application/x-www-form-urlencoded\r\ncontent-length: 77\r\n\r\nclient_id=client_id&client_secret=client_secret&grant_type=client_credentials",
    );

    assert!(response.starts_with("HTTP/1.1 200 OK\r\n"));
    assert!(response.contains("content-type: application/json\r\n"));
    assert!(response.contains("access-control-allow-origin: *\r\n"));
    assert!(response.contains("connection: close\r\n"));
    assert!(response.contains("\"token_type\":\"bearer\""));
    assert!(response.contains("\"access_token\":\""));
    assert!(
        !json_string_field(&response, "access_token")
            .unwrap()
            .contains('.')
    );
    assert!(response.contains("\"expires_in\":3600"));
    assert!(!response.contains("\"authorization_code\""));
    assert!(!response.contains("\"client_id\""));
    assert!(!response.contains("\"client_secret\""));
    assert!(!response.contains("\"grant_type\""));
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
    assert!(
        !json_string_field(&response, "access_token")
            .unwrap()
            .contains('.')
    );
    assert!(response.contains("\"expires_in\":3600"));
    assert!(!response.contains("\"authorization_code\""));
    assert!(!response.contains("\"client_id\""));
    assert!(!response.contains("\"client_secret\""));
    assert!(!response.contains("\"grant_type\""));
}

#[test]
fn returns_token_response_for_second_configured_client() {
    let response = send_form_token_request(
        "client_id=configured_client&client_secret=configured_secret&grant_type=client_credentials",
    );

    assert!(response.starts_with("HTTP/1.1 200 OK\r\n"));
    assert!(response.contains("\"token_type\":\"bearer\""));
    assert!(response.contains("\"access_token\":\""));
}

#[test]
fn authenticates_public_username_host_client_id_with_client_secret() {
    let response = send_form_token_request(
        "client_id=username%40example.com&client_secret=client_secret&grant_type=client_credentials",
    );

    assert!(response.starts_with("HTTP/1.1 200 OK\r\n"));
    assert!(response.contains("\"token_type\":\"bearer\""));
    assert!(response.contains("\"access_token\":\""));
}

#[test]
fn rejects_public_username_host_client_id_with_invalid_client_secret() {
    let response = send_form_token_request(
        "client_id=username%40example.com&client_secret=app&grant_type=client_credentials",
    );

    assert_invalid_client_secret_response(&response);
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
