use super::oauth::*;

// Branch matrix:
// - grant_type: missing | unsupported form value | unsupported JSON value
// - token endpoint method: POST | OPTIONS preflight | unsupported
// - CORS response: successful token | OAuth error
// Supported grant types are covered by their specification-specific flow modules.

#[test]
fn returns_oauth_error_for_unsupported_form_grant_type() {
    let response = send_request(
        "POST /token HTTP/1.1\r\nhost: example.com\r\ncontent-type: application/x-www-form-urlencoded\r\ncontent-length: 70\r\n\r\nclient_id=client_id&client_secret=client_secret&grant_type=unsupported",
    );

    assert_unsupported_grant_type_response(&response);
}

#[test]
fn returns_oauth_error_for_unsupported_json_grant_type() {
    let response = send_request(
        "POST /token HTTP/1.1\r\nhost: example.com\r\ncontent-type: application/json\r\ncontent-length: 84\r\n\r\n{\"client_id\":\"client_id\",\"client_secret\":\"client_secret\",\"grant_type\":\"unsupported\"}",
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
fn returns_not_found_for_non_post_token_request() {
    let response = send_request("GET /token HTTP/1.1\r\nhost: example.com\r\n\r\n");

    assert!(response.starts_with("HTTP/1.1 404 Not Found\r\n"));
    assert!(response.contains("content-type: text/plain\r\n"));
    assert!(response.contains("connection: close\r\n"));
    assert!(response.ends_with("not found"));
}

#[test]
fn returns_token_cors_preflight_response() {
    let response = send_request(
        "OPTIONS /token HTTP/1.1\r\nhost: example.com\r\norigin: https://client.example.com\r\naccess-control-request-method: POST\r\naccess-control-request-headers: content-type, authorization\r\n\r\n",
    );

    assert!(response.starts_with("HTTP/1.1 204 No Content\r\n"));
    assert!(response.contains("access-control-allow-origin: *\r\n"));
    assert!(response.contains("access-control-allow-methods: POST, OPTIONS\r\n"));
    assert!(response.contains("access-control-allow-headers: content-type, authorization\r\n"));
    assert!(response.contains("content-length: 0\r\n"));
}
