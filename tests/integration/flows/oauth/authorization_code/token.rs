use super::super::*;

// Branch matrix:
// - representation: form | JSON (success exercises both parser branches)
// - client_id: valid | missing | invalid
// - client_secret: valid | missing | invalid
// - code: valid | missing | invalid | issued to another client
// Credential and code failures are representation-independent after parsing, so each
// equivalent validation path is exercised once with form input.

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
fn returns_oauth_error_for_invalid_authorization_code_grant_type_client_id() {
    let response = send_form_token_request(
        "client_id=app&client_secret=client_secret&grant_type=authorization_code&code=app",
    );

    assert_invalid_client_id_response(&response);
}

#[test]
fn returns_oauth_error_for_invalid_authorization_code_grant_type_client_secret() {
    let response = send_form_token_request(
        "client_id=client_id&client_secret=app&grant_type=authorization_code&code=app",
    );

    assert_invalid_client_secret_response(&response);
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
fn returns_oauth_error_for_authorization_code_issued_to_another_client() {
    let body = format!(
        "client_id=client_id&client_secret=client_secret&grant_type=authorization_code&code={}",
        authorization_code_for_client_id("other_client")
    );
    let response = send_form_token_request(&body);

    assert!(response.starts_with("HTTP/1.1 400 Bad Request\r\n"));
    assert!(response.contains("\"error\":\"invalid_grant\""));
    assert!(
        response.contains(
            "\"error_description\":\"authorization_code client_id does not match request\""
        )
    );
}
