use base64::Engine;

use super::*;

// Branch matrix:
// - method: GET without credentials | GET with client_id credentials | POST
// - client_id: valid | public username@host | missing | invalid
// - redirect_uri: valid | missing | invalid
// - resource owner: first configured owner | second configured owner | missing username |
//   invalid username | missing password | invalid password | invalid embedded credentials
// - state: absent | present
// - response: federated redirect | access-token fragment | not implemented | HTML error |
//   redirect error
//
// `response_type=token` is fixed for this flow; missing, unsupported, and invalidly
// ordered response types are endpoint-level cases covered by the authorize tests.
// Access-token generation failure requires an invalid system clock or signing
// failure and cannot be reached through a valid deterministic HTTP request.

#[test]
fn redirects_implicit_get_request_to_federated_server() {
    let response = send_implicit_get(
        "response_type=token&client_id=federated_client&redirect_uri=https%3A%2F%2Fclient.example.com%2Fcallback&state=opaque%20state",
    );

    assert!(response.starts_with("HTTP/1.1 302 Found\r\n"));
    assert!(response.contains(
        "location: https://identity.example.com/authorize?response_type=code&client_id=kagome&redirect_uri=http%3A%2F%2Flocalhost%3A4000%2Ffederation_callback&state="
    ));
    assert!(!response.contains("access_token="));
    assert!(!response.contains("<form"));
}

#[test]
fn returns_not_implemented_for_implicit_get_without_resource_owner() {
    let response = send_implicit_get(
        "response_type=token&client_id=client_id&redirect_uri=https%3A%2F%2Fclient.example.com%2Fcallback&state=opaque%20state",
    );

    assert!(response.starts_with("HTTP/1.1 501 Not Implemented\r\n"));
    assert!(response.contains("content-type: text/plain\r\n"));
    assert!(response.ends_with("\r\n\r\nnot implemented"));
    assert!(!response.contains("<form"));
}

#[test]
fn redirects_implicit_access_token_and_state_for_valid_post_request() {
    let response = send_implicit_post(
        "response_type=token&client_id=client_id&redirect_uri=https%3A%2F%2Fclient.example.com%2Fcallback&state=opaque%20state",
        "username=username&password=password",
    );

    assert_implicit_token_response(&response, "client_id", "username");
    assert!(response.contains("&state=opaque%20state\r\n"));
}

#[test]
fn redirects_implicit_access_token_for_valid_client_id_credentials() {
    let response = send_implicit_get(
        "response_type=token&client_id=other_username%3Aother_password%40example.com&redirect_uri=https%3A%2F%2Fclient.example.com%2Fcallback",
    );

    assert_implicit_token_response(&response, "other_username@example.com", "other_username");
    assert!(!response.contains("&state="));
}

#[test]
fn authenticates_public_username_host_client_id_for_implicit_get() {
    let response = send_implicit_get(
        "response_type=token&client_id=username%40example.com&redirect_uri=https%3A%2F%2Fclient.example.com%2Fcallback",
    );

    assert_implicit_token_response(&response, "username@example.com", "username");
}

#[test]
fn returns_oauth_error_for_missing_implicit_client_id() {
    let response = send_implicit_post(
        "response_type=token&redirect_uri=https%3A%2F%2Fclient.example.com%2Fcallback",
        "username=username&password=password",
    );

    assert_html_error(&response, "client_id is required");
}

#[test]
fn returns_oauth_error_for_invalid_implicit_client_id() {
    let response = send_implicit_post(
        "response_type=token&client_id=app&redirect_uri=https%3A%2F%2Fclient.example.com%2Fcallback",
        "username=username&password=password",
    );

    assert_html_error(&response, "client_id is invalid");
}

#[test]
fn returns_oauth_error_for_missing_implicit_redirect_uri() {
    let response = send_implicit_post(
        "response_type=token&client_id=client_id",
        "username=username&password=password",
    );

    assert_html_error(&response, "redirect_uri is required");
}

#[test]
fn returns_oauth_error_for_invalid_implicit_redirect_uri() {
    let response = send_implicit_post(
        "response_type=token&client_id=client_id&redirect_uri=https%3A%2F%2Fapp.example.com%2Fcallback",
        "username=username&password=password",
    );

    assert_html_error(&response, "redirect_uri is invalid");
}

#[test]
fn returns_oauth_error_for_missing_implicit_username() {
    let response = send_implicit_post(valid_implicit_query(), "password=password");

    assert_html_error(&response, "username is required");
}

#[test]
fn returns_oauth_error_for_invalid_implicit_username() {
    let response = send_implicit_post(valid_implicit_query(), "username=app&password=password");

    assert_html_error(
        &response,
        "username must be one of: username, other_username",
    );
}

#[test]
fn returns_oauth_error_for_missing_implicit_password() {
    let response = send_implicit_post(valid_implicit_query(), "username=username");

    assert_html_error(&response, "password is required");
}

#[test]
fn returns_oauth_error_for_invalid_implicit_password() {
    let response = send_implicit_post(valid_implicit_query(), "username=username&password=app");

    assert_html_error(&response, "password is invalid");
}

#[test]
fn redirects_error_for_invalid_implicit_client_id_credentials() {
    let response = send_implicit_get(
        "response_type=token&client_id=other_username%3Aapp%40example.com&redirect_uri=https%3A%2F%2Fclient.example.com%2Fcallback&state=opaque%20state",
    );

    assert!(response.starts_with("HTTP/1.1 302 Found\r\n"));
    assert!(response.contains(
        "location: https://client.example.com/callback?error=invalid_grant&error_description=password%20is%20invalid&state=opaque%20state\r\n"
    ));
}

fn send_implicit_get(query: &str) -> String {
    send_request(&format!(
        "GET /authorize?{query} HTTP/1.1\r\nhost: example.com\r\n\r\n"
    ))
}

fn send_implicit_post(query: &str, body: &str) -> String {
    send_request(&format!(
        "POST /authorize?{query} HTTP/1.1\r\nhost: example.com\r\ncontent-type: application/x-www-form-urlencoded\r\ncontent-length: {}\r\n\r\n{}",
        body.len(),
        body
    ))
}

fn valid_implicit_query() -> &'static str {
    "response_type=token&client_id=client_id&redirect_uri=https%3A%2F%2Fclient.example.com%2Fcallback"
}

fn assert_implicit_token_response(response: &str, client_id: &str, username: &str) {
    assert!(response.starts_with("HTTP/1.1 302 Found\r\n"));
    assert!(response.contains("location: https://client.example.com/callback#access_token="));
    assert_eq!(fragment_parameter(response, "token_type"), Some("bearer"));
    assert_eq!(fragment_parameter(response, "expires_in"), Some("3600"));
    assert!(!response.contains("?access_token="));
    assert!(!response.contains("code="));

    let access_token = fragment_parameter(response, "access_token")
        .expect("implicit response should contain an access token");
    let payload = decode_access_token(&access_token);

    assert_eq!(payload.client_id, client_id);
    assert_eq!(payload.username, username);
}

fn assert_html_error(response: &str, description: &str) {
    assert!(response.starts_with("HTTP/1.1 400 Bad Request\r\n"));
    assert!(response.contains("content-type: text/html\r\n"));
    assert!(response.contains("<title>authorization error</title>"));
    assert!(response.contains(&format!("<p role=\"alert\">{description}</p>")));
    assert!(!response.contains("<form"));
    assert!(!response.contains("access_token="));
}

fn fragment_parameter<'a>(response: &'a str, name: &str) -> Option<&'a str> {
    let location = response
        .lines()
        .find_map(|line| line.strip_prefix("location: "))?;
    let (_, fragment) = location.split_once('#')?;

    fragment.split('&').find_map(|parameter| {
        let (parameter_name, value) = parameter.split_once('=')?;
        (parameter_name == name).then_some(value)
    })
}

fn decode_access_token(access_token: &str) -> AccessTokenPayload {
    let encoded_payload = access_token
        .split('.')
        .nth(1)
        .expect("access token should contain a JWT payload");
    let payload = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(encoded_payload)
        .expect("JWT payload should use base64url encoding");

    serde_json::from_slice(&payload).expect("JWT payload should contain JSON")
}

#[derive(serde::Deserialize)]
struct AccessTokenPayload {
    client_id: String,
    username: String,
}
