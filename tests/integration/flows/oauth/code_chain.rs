use super::*;

// Branch matrix:
// - representation: form | JSON (success exercises both parser branches)
// - generated artifacts: COSE_Encrypt0 authorization code | optional access token
// - client_id: valid | missing | invalid
// - client_secret: valid | missing | invalid
// - id_token: valid asymmetric | missing | malformed | symmetric algorithm |
//   missing JWK | invalid JWK | invalid signature | invalid claims | missing iat |
//   missing exp | expired | future iat | exp before iat
// - previous authorization_code: missing | valid below maximum depth | valid at maximum depth |
//   exceeding maximum depth | invalid | issued to another client
// - chained authorization_code exchange: absent | valid | invalid
// Validation failures are representation-independent after parsing, so each equivalent
// failure path is exercised once with form input.

#[test]
fn returns_token_response_for_form_code_chain_grant_type() {
    let body = format!(
        "client_id=client_id&client_secret=client_secret&grant_type=code_chain&id_token={}",
        valid_id_token()
    );
    let response = send_form_token_request(&body);

    assert!(response.starts_with("HTTP/1.1 200 OK\r\n"));
    assert!(response.contains("content-type: application/json\r\n"));
    assert!(response.contains("connection: close\r\n"));
    assert!(response.contains("\"authorization_code\":\""));
    assert!(response.contains("\"expires_in\":600"));
    assert!(!response.contains("\"token_type\""));
    assert!(!response.contains("\"access_token\""));
    assert!(!response.contains("\"client_id\""));
    assert!(!response.contains("\"client_secret\""));
    assert!(!response.contains("\"grant_type\""));
}

#[test]
fn returns_authorization_code_for_valid_code_chain_request() {
    let body = format!(
        "client_id=client_id&client_secret=client_secret&grant_type=code_chain&id_token={}",
        valid_id_token()
    );
    let response = send_form_token_request(&body);
    let authorization_code = json_string_field(&response, "authorization_code")
        .expect("token response should include authorization_code");

    assert!(!authorization_code.is_empty());
}

#[test]
fn accepts_valid_previous_authorization_code() {
    let body = format!(
        "client_id=client_id&client_secret=client_secret&grant_type=code_chain&id_token={}&authorization_code={}",
        valid_id_token(),
        valid_authorization_code()
    );
    let response = send_form_token_request(&body);

    assert!(response.starts_with("HTTP/1.1 200 OK\r\n"));
    assert!(response.contains("\"authorization_code\":\""));
}

#[test]
fn accepts_previous_authorization_code_chain_at_maximum_depth() {
    let authorization_code =
        issue_authorization_code_chain(kagome::config::DEFAULT_AUTHORIZATION_CODE_CHAIN_MAX_DEPTH);

    assert!(!authorization_code.is_empty());
}

#[test]
fn rejects_previous_authorization_code_chain_exceeding_maximum_depth() {
    let previous_code =
        issue_authorization_code_chain(kagome::config::DEFAULT_AUTHORIZATION_CODE_CHAIN_MAX_DEPTH);
    let body = format!(
        "client_id=client_id&client_secret=client_secret&grant_type=code_chain&id_token={}&authorization_code={previous_code}",
        valid_id_token()
    );

    let response = send_form_token_request(&body);

    assert!(response.starts_with("HTTP/1.1 400 Bad Request\r\n"));
    assert!(response.contains("\"error\":\"invalid_grant\""));
    assert!(
        response
            .contains("\"error_description\":\"authorization_code chain exceeds maximum depth\"")
    );
}

#[test]
fn returns_token_response_for_json_code_chain_grant_type() {
    let body = format!(
        "{{\"client_id\":\"client_id\",\"client_secret\":\"client_secret\",\"grant_type\":\"code_chain\",\"id_token\":\"{}\"}}",
        valid_id_token()
    );
    let response = send_json_token_request(&body);

    assert!(response.starts_with("HTTP/1.1 200 OK\r\n"));
    assert!(response.contains("content-type: application/json\r\n"));
    assert!(response.contains("connection: close\r\n"));
    assert!(response.contains("\"authorization_code\":\""));
    assert!(response.contains("\"expires_in\":600"));
    assert!(!response.contains("\"token_type\""));
    assert!(!response.contains("\"access_token\""));
    assert!(!response.contains("\"client_id\""));
    assert!(!response.contains("\"client_secret\""));
    assert!(!response.contains("\"grant_type\""));
}

#[test]
fn returns_token_response_for_form_code_chain_authorization_code_grant_type() {
    let body = format!(
        "client_id=client_id&client_secret=client_secret&grant_type=code_chain+authorization_code&id_token={}&code={}",
        valid_id_token(),
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
fn returns_token_response_for_json_code_chain_authorization_code_grant_type() {
    let body = format!(
        "{{\"client_id\":\"client_id\",\"client_secret\":\"client_secret\",\"grant_type\":\"code_chain authorization_code\",\"id_token\":\"{}\",\"code\":\"{}\"}}",
        valid_id_token(),
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
    assert!(!response.contains("\"client_id\""));
    assert!(!response.contains("\"client_secret\""));
    assert!(!response.contains("\"grant_type\""));
}

#[test]
fn returns_oauth_error_for_missing_code_chain_id_token() {
    let response = send_request(
        "POST /token HTTP/1.1\r\nhost: example.com\r\ncontent-type: application/x-www-form-urlencoded\r\ncontent-length: 69\r\n\r\nclient_id=client_id&client_secret=client_secret&grant_type=code_chain",
    );

    assert_missing_id_token_response(&response);
}

#[test]
fn returns_oauth_error_for_missing_code_chain_client_id() {
    let body = format!(
        "client_secret=client_secret&grant_type=code_chain&id_token={}",
        valid_id_token()
    );
    let response = send_form_token_request(&body);

    assert_missing_client_id_response(&response);
}

#[test]
fn returns_oauth_error_for_invalid_code_chain_client_id() {
    let body = format!(
        "client_id=app&client_secret=client_secret&grant_type=code_chain&id_token={}",
        valid_id_token()
    );
    let response = send_form_token_request(&body);

    assert_invalid_client_id_response(&response);
}

#[test]
fn returns_oauth_error_for_missing_code_chain_client_secret() {
    let body = format!(
        "client_id=client_id&grant_type=code_chain&id_token={}",
        valid_id_token()
    );
    let response = send_form_token_request(&body);

    assert_missing_client_secret_response(&response);
}

#[test]
fn returns_oauth_error_for_invalid_code_chain_client_secret() {
    let body = format!(
        "client_id=client_id&client_secret=app&grant_type=code_chain&id_token={}",
        valid_id_token()
    );
    let response = send_form_token_request(&body);

    assert_invalid_client_secret_response(&response);
}

#[test]
fn returns_oauth_error_for_invalid_code_chain_id_token() {
    let response = send_request(
        "POST /token HTTP/1.1\r\nhost: example.com\r\ncontent-type: application/x-www-form-urlencoded\r\ncontent-length: 82\r\n\r\nclient_id=client_id&client_secret=client_secret&grant_type=code_chain&id_token=app",
    );

    assert_invalid_id_token_response(&response);
}

#[test]
fn returns_oauth_error_for_code_chain_id_token_without_jwk() {
    assert_code_chain_id_token_error(&id_token_without_jwk(), "id_token header must include jwk");
}

#[test]
fn returns_oauth_error_for_symmetric_code_chain_id_token() {
    let now = jsonwebtoken::get_current_timestamp();
    let mut header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::HS256);
    header.jwk = Some(
        serde_json::from_value(serde_json::json!({
            "kty": "oct",
            "k": "c2VjcmV0",
            "alg": "HS256"
        }))
        .unwrap(),
    );
    let token = jsonwebtoken::encode(
        &header,
        &serde_json::json!({"iat": now, "exp": now + 3600}),
        &jsonwebtoken::EncodingKey::from_secret(b"secret"),
    )
    .unwrap();

    assert_code_chain_id_token_error(&token, "id_token algorithm must be asymmetric");
}

#[test]
fn returns_oauth_error_for_code_chain_id_token_with_invalid_jwk() {
    assert_code_chain_id_token_error(&id_token_with_invalid_jwk(), "id_token jwk must be valid");
}

#[test]
fn returns_oauth_error_for_code_chain_id_token_with_invalid_signature() {
    assert_code_chain_id_token_error(
        &id_token_with_invalid_signature(),
        "id_token signature is invalid",
    );
}

#[test]
fn returns_oauth_error_for_code_chain_id_token_with_invalid_claims() {
    assert_code_chain_id_token_error(
        &id_token_with_invalid_claims(),
        "id_token claims are invalid",
    );
}

#[test]
fn returns_oauth_error_for_code_chain_id_token_without_iat() {
    assert_code_chain_id_token_error(&id_token_without_iat(), "id_token iat is required");
}

#[test]
fn returns_oauth_error_for_code_chain_id_token_without_exp() {
    assert_code_chain_id_token_error(&id_token_without_exp(), "id_token exp is required");
}

#[test]
fn returns_oauth_error_for_expired_code_chain_id_token() {
    assert_code_chain_id_token_error(&expired_id_token(), "id_token is expired");
}

#[test]
fn returns_oauth_error_for_code_chain_id_token_issued_in_the_future() {
    assert_code_chain_id_token_error(&future_id_token(), "id_token iat must not be in the future");
}

#[test]
fn returns_oauth_error_for_code_chain_id_token_expiring_before_iat() {
    assert_code_chain_id_token_error(
        &id_token_expiring_before_iat(),
        "id_token exp must be after iat",
    );
}

#[test]
fn returns_oauth_error_for_invalid_code_chain_authorization_code() {
    let body = format!(
        "client_id=client_id&client_secret=client_secret&grant_type=code_chain&id_token={}&authorization_code=app",
        valid_id_token()
    );
    let response = send_form_token_request(&body);

    assert_invalid_authorization_code_response(&response);
}

#[test]
fn returns_oauth_error_for_previous_authorization_code_issued_to_another_client() {
    let body = format!(
        "client_id=client_id&client_secret=client_secret&grant_type=code_chain&id_token={}&authorization_code={}",
        valid_id_token(),
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

#[test]
fn returns_oauth_error_for_missing_code_chain_authorization_code_exchange_code() {
    let body = format!(
        "client_id=client_id&client_secret=client_secret&grant_type=code_chain+authorization_code&id_token={}",
        valid_id_token()
    );
    let response = send_form_token_request(&body);

    assert_missing_authorization_code_response(&response);
}

#[test]
fn returns_oauth_error_for_invalid_code_chain_authorization_code_exchange_code() {
    let body = format!(
        "client_id=client_id&client_secret=client_secret&grant_type=code_chain+authorization_code&id_token={}&code=app",
        valid_id_token()
    );
    let response = send_form_token_request(&body);

    assert_invalid_authorization_code_response(&response);
}

fn assert_code_chain_id_token_error(id_token: &str, description: &str) {
    let body = format!(
        "client_id=client_id&client_secret=client_secret&grant_type=code_chain&id_token={id_token}"
    );
    let response = send_form_token_request(&body);

    assert_invalid_id_token_response_with_description(&response, description);
}

fn issue_authorization_code_chain(depth: usize) -> String {
    let mut previous_code = None;

    for _ in 0..depth {
        let authorization_code = previous_code
            .as_deref()
            .map(|code| format!("&authorization_code={code}"))
            .unwrap_or_default();
        let body = format!(
            "client_id=client_id&client_secret=client_secret&grant_type=code_chain&id_token={}{}",
            valid_id_token(),
            authorization_code
        );
        let response = send_form_token_request(&body);
        assert!(response.starts_with("HTTP/1.1 200 OK\r\n"));
        previous_code = json_string_field(&response, "authorization_code");
    }

    previous_code.expect("a non-empty chain should contain an authorization code")
}
