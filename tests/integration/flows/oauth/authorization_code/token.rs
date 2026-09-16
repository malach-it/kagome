use super::super::*;

// Branch matrix:
// - representation: form | JSON (success exercises both parser branches)
// - access-token artifact: opaque COSE_Encrypt0
// - client_id: valid | missing | invalid
// - client_secret: valid | missing | invalid
// - code: valid | missing | invalid | issued to another client
// - redemption count: first succeeds | repeated is rejected by the process-local replay store
// - scope: omitted | authorized | unauthorized
// - PKCE-bound code: matching S256 verifier | missing verifier | malformed verifier |
//   valid but mismatching verifier
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
fn rejects_repeated_authorization_code_exchange() {
    let code = valid_authorization_code();
    let body = format!(
        "client_id=client_id&client_secret=client_secret&grant_type=authorization_code&code={code}"
    );

    let first = send_form_token_request(&body);
    let second = send_form_token_request(&body);

    assert!(first.starts_with("HTTP/1.1 200 OK\r\n"));
    assert!(second.starts_with("HTTP/1.1 400 Bad Request\r\n"));
    assert!(second.contains("\"error\":\"invalid_grant\""));
    assert!(second.contains("authorization_code has already been used"));
}

#[test]
fn rejects_unauthorized_authorization_code_grant_scope_before_code_validation() {
    let response = send_form_token_request(
        "client_id=client_id&client_secret=client_secret&grant_type=authorization_code&code=invalid&scope=admin",
    );

    assert!(response.starts_with("HTTP/1.1 400 Bad Request\r\n"));
    assert!(response.contains("\"error\":\"invalid_scope\""));
}

#[test]
fn exchanges_s256_pkce_bound_authorization_code() {
    let code = authorization_code_for_client_id_and_challenge("client_id", Some(PKCE_CHALLENGE));
    let body = format!(
        "client_id=client_id&client_secret=client_secret&grant_type=authorization_code&code={code}&code_verifier={PKCE_VERIFIER}"
    );
    let response = send_form_token_request(&body);

    assert!(response.starts_with("HTTP/1.1 200 OK\r\n"));
    assert!(response.contains("\"access_token\":\""));
}

#[test]
fn rejects_pkce_bound_code_without_verifier() {
    let code = authorization_code_for_client_id_and_challenge("client_id", Some(PKCE_CHALLENGE));
    let body = format!(
        "client_id=client_id&client_secret=client_secret&grant_type=authorization_code&code={code}"
    );
    let response = send_form_token_request(&body);

    assert!(response.starts_with("HTTP/1.1 400 Bad Request\r\n"));
    assert!(response.contains("\"error\":\"invalid_grant\""));
    assert!(response.contains("code_verifier is required"));
}

#[test]
fn rejects_malformed_pkce_code_verifier() {
    let code = authorization_code_for_client_id_and_challenge("client_id", Some(PKCE_CHALLENGE));
    let body = format!(
        "client_id=client_id&client_secret=client_secret&grant_type=authorization_code&code={code}&code_verifier=short"
    );
    let response = send_form_token_request(&body);

    assert!(response.starts_with("HTTP/1.1 400 Bad Request\r\n"));
    assert!(response.contains("\"error\":\"invalid_grant\""));
    assert!(response.contains("code_verifier is invalid"));
}

#[test]
fn rejects_pkce_code_verifier_that_does_not_match_challenge() {
    let code = authorization_code_for_client_id_and_challenge("client_id", Some(PKCE_CHALLENGE));
    let verifier = "a".repeat(43);
    let body = format!(
        "client_id=client_id&client_secret=client_secret&grant_type=authorization_code&code={code}&code_verifier={verifier}"
    );
    let response = send_form_token_request(&body);

    assert!(response.starts_with("HTTP/1.1 400 Bad Request\r\n"));
    assert!(response.contains("\"error\":\"invalid_grant\""));
    assert!(response.contains("code_verifier does not match code_challenge"));
}

#[test]
fn invalid_pkce_verifier_does_not_consume_authorization_code() {
    let code = authorization_code_for_client_id_and_challenge("client_id", Some(PKCE_CHALLENGE));
    let invalid_verifier = "a".repeat(43);
    let invalid_body = format!(
        "client_id=client_id&client_secret=client_secret&grant_type=authorization_code&code={code}&code_verifier={invalid_verifier}"
    );
    let valid_body = format!(
        "client_id=client_id&client_secret=client_secret&grant_type=authorization_code&code={code}&code_verifier={PKCE_VERIFIER}"
    );

    let invalid_response = send_form_token_request(&invalid_body);
    let valid_response = send_form_token_request(&valid_body);

    assert!(invalid_response.starts_with("HTTP/1.1 400 Bad Request\r\n"));
    assert!(invalid_response.contains("code_verifier does not match code_challenge"));
    assert!(valid_response.starts_with("HTTP/1.1 200 OK\r\n"));
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
