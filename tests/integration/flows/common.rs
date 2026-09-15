use super::oauth::*;

pub(super) fn qr_page_deep_link(response: &str) -> String {
    assert!(response.starts_with("HTTP/1.1 200 OK\r\n"), "{response}");
    assert!(response.contains("content-type: text/html; charset=utf-8\r\n"));
    assert!(response.contains("cache-control: no-store\r\n"));
    let script_nonce = response
        .split_once("<script nonce=\"")
        .and_then(|(_, remainder)| remainder.split_once("\">"))
        .map(|(nonce, _)| nonce)
        .expect("QR page should use a nonce-bound popup script");
    assert!(response.contains(&format!(
        "content-security-policy: default-src 'none'; script-src 'nonce-{script_nonce}';"
    )));
    assert!(response.contains("referrer-policy: no-referrer\r\n"));
    assert!(response.contains("<svg"));
    assert!(!response.contains("\r\nlocation:"));
    assert!(response.contains("popup,width=390,height=844,noopener,noreferrer"));

    let escaped_link = response
        .split_once("data-deep-link=\"")
        .and_then(|(_, remainder)| remainder.split_once("\">open in wallet</button>"))
        .map(|(link, _)| link)
        .expect("QR page should contain an open-in-wallet deep link");
    assert!(response.contains(&format!("<code>{escaped_link}</code>")));
    assert!(response.contains(&format!("<noscript><a href=\"{escaped_link}\"")));

    let escaped_qr_uri = response
        .split_once("<figure data-qr-uri=\"")
        .and_then(|(_, remainder)| remainder.split_once("\">"))
        .map(|(uri, _)| uri)
        .expect("QR page should expose its relay URI");
    let qr_uri = escaped_qr_uri.replace("&amp;", "&");
    let relay_path = qr_uri
        .strip_prefix("http://localhost:4000")
        .expect("QR relay should use the configured issuer");
    let relay_response = send_request(&format!(
        "GET {relay_path} HTTP/1.1\r\nhost: example.com\r\n\r\n"
    ));
    let deep_link = escaped_link.replace("&amp;", "&");

    assert!(relay_response.starts_with("HTTP/1.1 302 Found\r\n"));
    assert!(relay_response.contains(&format!("location: {deep_link}\r\n")));

    deep_link
}

// Branch matrix:
// - grant_type: missing | unsupported form value | unsupported JSON value
// - token endpoint method: POST | OPTIONS preflight | unsupported
// - CORS response: successful token | OAuth error
// - wallet authorization relay: valid (covered by each QR flow) | missing |
//   invalid | expired (resource unit test) | unsupported method
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

#[test]
fn rejects_missing_or_invalid_wallet_authorization_relay() {
    for path in ["/wallet-authorization", "/wallet-authorization?id=invalid"] {
        let response = send_request(&format!("GET {path} HTTP/1.1\r\nhost: example.com\r\n\r\n"));

        assert!(response.starts_with("HTTP/1.1 400 Bad Request\r\n"));
        assert!(response.contains("content-type: text/html\r\n"));
    }
}

#[test]
fn returns_not_found_for_non_get_wallet_authorization_relay() {
    let response = send_request(
        "POST /wallet-authorization?id=invalid HTTP/1.1\r\nhost: example.com\r\ncontent-length: 0\r\n\r\n",
    );

    assert!(response.starts_with("HTTP/1.1 404 Not Found\r\n"));
}
