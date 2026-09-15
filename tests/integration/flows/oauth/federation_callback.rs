use super::*;

// Branch matrix:
// - method: GET | unsupported
// - authenticated state: valid | missing | invalid
// - authorization response: code | upstream error | code and error | neither
// - values: non-empty | empty
// - token endpoint: valid token | rejected request | malformed response
// - identity endpoint: valid string claim | rejected request | malformed response |
//   missing or non-string claim
// - identity error response: error_description | message | error | HTTP status fallback
// The upstream-error cases cover both explicit and fallback descriptions.
// Missing and non-string identity claims intentionally share a validation path and response.

#[test]
fn accepts_federation_callback_authorization_code() {
    let response = send_callback_request("code=federated-code");

    assert!(response.starts_with("HTTP/1.1 302 Found\r\n"));
    assert!(response.contains("location: https://client.example.com/callback?code="));
    assert!(!response.contains("federated-code"));
    let payload = kagome::resources::authorization_code::decode_cose_payload(
        &authorization_code_from_response(&response),
    )
    .expect("downstream authorization code should decode");
    assert_eq!(payload.username.as_deref(), Some("federated-user"));
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
fn rejects_failed_federated_identity_request() {
    let response = send_callback_request("code=identity-rejected");

    assert!(response.starts_with("HTTP/1.1 400 Bad Request\r\n"));
    assert!(response.contains("\"error\":\"invalid_grant\""));
    assert!(response.contains(
        "\"error_description\":\"federated identity request failed: federated access token expired\""
    ));
}

#[test]
fn returns_federated_identity_error_code() {
    let response = send_callback_request("code=identity-error-code");

    assert!(response.starts_with("HTTP/1.1 400 Bad Request\r\n"));
    assert!(response.contains(
        "\"error_description\":\"federated identity request failed: insufficient_scope\""
    ));
}

#[test]
fn returns_federated_identity_message() {
    let response = send_callback_request("code=identity-message");

    assert!(response.starts_with("HTTP/1.1 400 Bad Request\r\n"));
    assert!(response.contains(
        "\"error_description\":\"federated identity request failed: profile unavailable\""
    ));
}

#[test]
fn returns_federated_identity_http_status_without_message() {
    let response = send_callback_request("code=identity-no-message");

    assert!(response.starts_with("HTTP/1.1 400 Bad Request\r\n"));
    assert!(
        response.contains("\"error_description\":\"federated identity request failed: HTTP 502\"")
    );
}

#[test]
fn rejects_invalid_federated_identity_response() {
    let response = send_callback_request("code=identity-malformed");

    assert!(response.starts_with("HTTP/1.1 400 Bad Request\r\n"));
    assert!(response.contains("\"error\":\"invalid_grant\""));
    assert!(response.contains("federated identity response is invalid"));
}

#[test]
fn rejects_missing_federated_identity_claim() {
    let response = send_callback_request("code=identity-missing-claim");

    assert!(response.starts_with("HTTP/1.1 400 Bad Request\r\n"));
    assert!(response.contains("\"error\":\"invalid_grant\""));
    assert!(response.contains("federated identity claim is missing or invalid"));
}

#[test]
fn rejects_non_string_federated_identity_claim() {
    let response = send_callback_request("code=identity-non-string");

    assert!(response.starts_with("HTTP/1.1 400 Bad Request\r\n"));
    assert!(response.contains("\"error\":\"invalid_grant\""));
    assert!(response.contains("federated identity claim is missing or invalid"));
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

fn authorization_code_from_response(response: &str) -> String {
    response
        .lines()
        .find_map(|line| line.strip_prefix("location: "))
        .and_then(|location| location.split_once('?'))
        .map(|(_, query)| query)
        .and_then(|query| {
            query
                .split('&')
                .find_map(|value| value.strip_prefix("code="))
        })
        .expect("downstream authorization response should contain a code")
        .to_owned()
}
