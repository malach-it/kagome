use super::*;

// Branch matrix:
// - method: GET without credentials | GET with client_id credentials
// - client_id: valid | public username@host | missing | invalid
// - redirect_uri: valid | missing | invalid
// - resource owner: first configured owner | second configured owner | invalid embedded credentials
// - state: absent | present
// - scope: omitted | authorized | unauthorized
// - access-token artifact: opaque COSE_Encrypt0
// - federation: configured upstream scope included
// - response: federated redirect | access-token fragment | trusted error redirect with exact
//   state | not implemented | HTML error
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
        "location: https://identity.example.com/authorize?response_type=code&client_id=kagome&redirect_uri=http%3A%2F%2Flocalhost%3A4000%2Ffederation_callback&scope=openid%20profile&state="
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
fn redirects_invalid_implicit_client_id_credentials_with_exact_state() {
    let response = send_implicit_get(
        "response_type=token&client_id=other_username%3Aapp%40example.com&redirect_uri=https%3A%2F%2Fclient.example.com%2Fcallback&state=opaque%20state",
    );

    assert!(response.starts_with("HTTP/1.1 302 Found\r\n"));
    assert!(response.contains("error=invalid_grant"));
    assert!(response.contains("error_description=username%20or%20password%20is%20invalid"));
    assert!(response.contains("state=opaque%20state"));
}

fn send_implicit_get(query: &str) -> String {
    send_request(&format!(
        "GET /authorize?{query} HTTP/1.1\r\nhost: example.com\r\n\r\n"
    ))
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
    assert!(!access_token.contains('.'));
    let payload = decode_access_token(&access_token);

    assert_eq!(payload.client_id, client_id);
    assert_eq!(payload.username.as_deref(), Some(username));
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

fn decode_access_token(access_token: &str) -> kagome::resources::access_token::AccessTokenClaims {
    kagome::resources::access_token::decode_cose_payload(access_token).unwrap()
}
