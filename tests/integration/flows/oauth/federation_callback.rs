use super::*;

// Branch matrix:
// - method: GET | unsupported
// - authenticated state: valid | missing | invalid
// - authorization response: code | upstream error | code and error | neither
// - values: non-empty | empty
// - token endpoint: valid token | rejected request | malformed response
// The upstream-error cases cover both explicit and fallback descriptions.

#[test]
fn accepts_federation_callback_authorization_code() {
    let response = send_callback_request("code=federated-code");

    assert!(response.starts_with("HTTP/1.1 302 Found\r\n"));
    assert!(response.contains("location: https://client.example.com/callback?code="));
    assert!(!response.contains("federated-code"));
}

#[test]
fn restores_parsed_request_attributes_for_implicit_authorize_continuation() {
    let state = federation_state_for(
        "response_type=token&client_id=federated_client&redirect_uri=https%3A%2F%2Fclient.example.com%2Fcallback&state=client%20state",
    );
    let response = send_request(&format!(
        "GET /federation_callback?code=federated-code&state={state} HTTP/1.1\r\nhost: example.com\r\n\r\n"
    ));

    assert!(response.starts_with("HTTP/1.1 302 Found\r\n"));
    assert!(response.contains("location: https://client.example.com/callback#access_token="));
    assert!(response.contains("&state=client%20state\r\n"));
    assert!(!response.contains("federated-code"));
}

#[test]
fn rejects_federation_callback_when_token_request_fails() {
    let response = send_callback_request("code=rejected-code");

    assert!(response.starts_with("HTTP/1.1 400 Bad Request\r\n"));
    assert!(response.contains("\"error\":\"invalid_grant\""));
    assert!(response.contains("federated token request failed"));
}

#[test]
fn rejects_invalid_federated_token_response() {
    let response = send_callback_request("code=malformed-token");

    assert!(response.starts_with("HTTP/1.1 400 Bad Request\r\n"));
    assert!(response.contains("\"error\":\"invalid_grant\""));
    assert!(response.contains("federated token response is invalid"));
}

#[test]
fn rejects_empty_federated_access_token() {
    let response = send_callback_request("code=empty-token");

    assert!(response.starts_with("HTTP/1.1 400 Bad Request\r\n"));
    assert!(response.contains("\"error\":\"invalid_grant\""));
    assert!(response.contains("federated token response is invalid"));
}

#[test]
fn returns_oauth_error_for_federation_callback_error() {
    let response = send_callback_request(
        "error=access_denied&error_description=resource%20owner%20denied%20access",
    );

    assert!(response.starts_with("HTTP/1.1 400 Bad Request\r\n"));
    assert!(response.contains("\"error\":\"invalid_grant\""));
    assert!(response.contains(
        "\"error_description\":\"federated server returned an error: resource owner denied access\""
    ));
}

#[test]
fn uses_error_code_when_federation_callback_description_is_missing() {
    let response = send_callback_request("error=access_denied");

    assert!(response.starts_with("HTTP/1.1 400 Bad Request\r\n"));
    assert!(
        response.contains(
            "\"error_description\":\"federated server returned an error: access_denied\""
        )
    );
}

#[test]
fn rejects_federation_callback_with_code_and_error() {
    let response = send_callback_request("code=federated-code&error=access_denied");

    assert!(response.starts_with("HTTP/1.1 400 Bad Request\r\n"));
    assert!(response.contains("\"error\":\"invalid_request\""));
    assert!(response.contains("federation callback must not include both code and error"));
}

#[test]
fn rejects_federation_callback_without_authorization_response() {
    let response = send_callback_request("");

    assert!(response.starts_with("HTTP/1.1 400 Bad Request\r\n"));
    assert!(response.contains("\"error\":\"invalid_request\""));
    assert!(response.contains("federation callback requires code or error"));
}

#[test]
fn rejects_federation_callback_with_empty_code() {
    let response = send_callback_request("code=");

    assert!(response.starts_with("HTTP/1.1 400 Bad Request\r\n"));
    assert!(response.contains("federation callback code must not be empty"));
}

#[test]
fn rejects_federation_callback_with_empty_error() {
    let response = send_callback_request("error=");

    assert!(response.starts_with("HTTP/1.1 400 Bad Request\r\n"));
    assert!(response.contains("federation callback error must not be empty"));
}

#[test]
fn rejects_federation_callback_without_state() {
    let response = send_request(
        "GET /federation_callback?code=federated-code HTTP/1.1\r\nhost: example.com\r\n\r\n",
    );

    assert!(response.starts_with("HTTP/1.1 400 Bad Request\r\n"));
    assert!(response.contains("\"error\":\"invalid_request\""));
    assert!(response.contains("federation callback state is invalid or expired"));
}

#[test]
fn rejects_federation_callback_with_invalid_state() {
    let response = send_request(
        "GET /federation_callback?code=federated-code&state=invalid HTTP/1.1\r\nhost: example.com\r\n\r\n",
    );

    assert!(response.starts_with("HTTP/1.1 400 Bad Request\r\n"));
    assert!(response.contains("\"error\":\"invalid_request\""));
    assert!(response.contains("federation callback state is invalid or expired"));
}

#[test]
fn returns_not_found_for_federation_callback_post() {
    let response = send_request(
        "POST /federation_callback HTTP/1.1\r\nhost: example.com\r\ncontent-length: 0\r\n\r\n",
    );

    assert!(response.starts_with("HTTP/1.1 404 Not Found\r\n"));
}

fn send_callback_request(query: &str) -> String {
    let state = federation_state();
    let separator = if query.is_empty() { "" } else { "&" };

    send_request(&format!(
        "GET /federation_callback?{query}{separator}state={state} HTTP/1.1\r\nhost: example.com\r\n\r\n"
    ))
}

fn federation_state() -> String {
    federation_state_for(
        "response_type=code&client_id=federated_client&redirect_uri=https%3A%2F%2Fclient.example.com%2Fcallback",
    )
}

fn federation_state_for(authorize_query: &str) -> String {
    let response = send_request(&format!(
        "GET /authorize?{authorize_query} HTTP/1.1\r\nhost: example.com\r\n\r\n"
    ));
    let location = response
        .lines()
        .find_map(|line| line.strip_prefix("location: "))
        .expect("federated authorization response should contain a location");

    location
        .split_once('?')
        .expect("federated authorization location should contain a query")
        .1
        .split('&')
        .find_map(|parameter| parameter.strip_prefix("state="))
        .expect("federated authorization location should contain state")
        .to_owned()
}
