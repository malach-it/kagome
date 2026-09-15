use super::*;

// Branch matrix:
// - representation: form | JSON
// - access-token artifact: opaque COSE_Encrypt0
// - client_id: valid | missing | invalid
// - client_secret: valid | missing | invalid
// - client password file: configured | omitted
// - username: first configured owner | second configured owner | missing | invalid
// - password: valid | missing | invalid
//
// Both representations and both configured owners are covered by successful cases.
// Validation failures are representation-independent after parsing, so each is
// exercised once with form input. Client credentials are validated before resource
// owner credentials; combinations containing failures in both stages intentionally
// collapse to the client-credential error produced by Result short-circuiting.
// Additional grant-type suffixes select the same password pipeline and have the same
// observable result as `password` alone.
// Access-token generation failure requires an invalid system clock or signing
// failure and cannot be reached through a valid deterministic HTTP request.

#[test]
fn returns_resource_owner_access_token_for_form_password_grant_type() {
    let response = send_form_token_request(
        "client_id=client_id&client_secret=client_secret&grant_type=password&username=username&password=password",
    );

    assert_access_token_response(&response, "client_id", "username");
}

#[test]
fn returns_resource_owner_access_token_for_json_password_grant_type() {
    let response = send_json_token_request(
        r#"{"client_id":"client_id","client_secret":"client_secret","grant_type":"password","username":"other_username","password":"other_password"}"#,
    );

    assert_access_token_response(&response, "client_id", "other_username");
}

#[test]
fn returns_oauth_error_for_missing_password_grant_client_id() {
    let response = send_form_token_request(
        "client_secret=client_secret&grant_type=password&username=username&password=password",
    );

    assert_missing_client_id_response(&response);
}

#[test]
fn returns_oauth_error_for_invalid_password_grant_client_id() {
    let response = send_form_token_request(
        "client_id=app&client_secret=client_secret&grant_type=password&username=username&password=password",
    );

    assert_invalid_client_id_response(&response);
}

#[test]
fn returns_oauth_error_for_missing_password_grant_client_secret() {
    let response = send_form_token_request(
        "client_id=client_id&grant_type=password&username=username&password=password",
    );

    assert_missing_client_secret_response(&response);
}

#[test]
fn returns_oauth_error_for_invalid_password_grant_client_secret() {
    let response = send_form_token_request(
        "client_id=client_id&client_secret=app&grant_type=password&username=username&password=password",
    );

    assert_invalid_client_secret_response(&response);
}

#[test]
fn returns_oauth_error_when_client_has_no_password_file() {
    let response = send_form_token_request(
        "client_id=federated_client&client_secret=federated_secret&grant_type=password&username=username&password=password",
    );

    assert_invalid_grant_response(&response, "username must be one of: ");
}

#[test]
fn returns_oauth_error_for_missing_password_grant_username() {
    let response = send_form_token_request(
        "client_id=client_id&client_secret=client_secret&grant_type=password&password=password",
    );

    assert_invalid_grant_response(&response, "username is required");
}

#[test]
fn returns_oauth_error_when_password_grant_omits_resource_owner_credentials() {
    let response = send_form_token_request(
        "client_id=client_id&client_secret=client_secret&grant_type=password",
    );

    assert_invalid_grant_response(&response, "username is required");
}

#[test]
fn returns_oauth_error_for_invalid_password_grant_username() {
    let response = send_form_token_request(
        "client_id=client_id&client_secret=client_secret&grant_type=password&username=app&password=password",
    );

    assert_invalid_grant_response(
        &response,
        "username must be one of: username, other_username",
    );
}

#[test]
fn returns_oauth_error_for_missing_password_grant_password() {
    let response = send_form_token_request(
        "client_id=client_id&client_secret=client_secret&grant_type=password&username=username",
    );

    assert_invalid_grant_response(&response, "password is required");
}

#[test]
fn returns_oauth_error_for_invalid_password_grant_password() {
    let response = send_form_token_request(
        "client_id=client_id&client_secret=client_secret&grant_type=password&username=username&password=app",
    );

    assert_invalid_grant_response(&response, "password is invalid");
}

fn assert_access_token_response(response: &str, client_id: &str, username: &str) {
    assert!(response.starts_with("HTTP/1.1 200 OK\r\n"));
    assert!(response.contains("content-type: application/json\r\n"));
    assert!(response.contains("cache-control: no-store\r\n"));
    assert!(response.contains("pragma: no-cache\r\n"));
    assert!(response.contains("connection: close\r\n"));
    assert!(response.contains("\"token_type\":\"bearer\""));
    assert!(response.contains("\"expires_in\":3600"));

    let access_token = json_string_field(response, "access_token")
        .expect("password grant response should contain an access token");
    assert!(!access_token.contains('.'));
    let payload = kagome::resources::access_token::decode_cose_payload(&access_token)
        .expect("password grant access token should contain valid encrypted claims");

    assert_eq!(payload.client_id, client_id);
    assert_eq!(payload.username.as_deref(), Some(username));
}

fn assert_invalid_grant_response(response: &str, description: &str) {
    assert!(response.starts_with("HTTP/1.1 400 Bad Request\r\n"));
    assert!(response.contains("content-type: application/json\r\n"));
    assert!(response.contains("connection: close\r\n"));
    assert!(response.contains("\"error\":\"invalid_grant\""));
    assert!(response.contains(&format!("\"error_description\":\"{description}\"")));
}
