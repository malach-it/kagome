use super::server::send_request;

#[test]
fn returns_token_response_for_form_client_credentials_grant_type() {
    let response = send_request(
        "POST /token HTTP/1.1\r\nhost: example.com\r\ncontent-type: application/x-www-form-urlencoded\r\ncontent-length: 77\r\n\r\nclient_id=client_id&client_secret=client_secret&grant_type=client_credentials",
    );

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
fn returns_token_response_for_json_client_credentials_grant_type() {
    let response = send_request(
        "POST /token HTTP/1.1\r\nhost: example.com\r\ncontent-type: application/json\r\ncontent-length: 91\r\n\r\n{\"client_id\":\"client_id\",\"client_secret\":\"client_secret\",\"grant_type\":\"client_credentials\"}",
    );

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
fn returns_encrypted_authorization_code_containing_request_claims() {
    let id_token = valid_id_token();
    let body = format!(
        "client_id=client_id&client_secret=client_secret&grant_type=code_chain&id_token={id_token}",
    );
    let response = send_form_token_request(&body);
    let authorization_code = json_string_field(&response, "authorization_code")
        .expect("token response should include authorization_code");

    let payload =
        kagome::resources::authorization_code::decode_cose_payload(&authorization_code).unwrap();

    assert_eq!(payload.client_id, "client_id");
    assert_eq!(payload.id_token, Some(id_token));
    assert_eq!(payload.previous_code, None);
    assert_eq!(
        payload.exp,
        payload.iat + kagome::resources::authorization_code::AUTHORIZATION_CODE_TTL_SECONDS
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
fn returns_oauth_error_for_missing_code_chain_id_token() {
    let response = send_request(
        "POST /token HTTP/1.1\r\nhost: example.com\r\ncontent-type: application/x-www-form-urlencoded\r\ncontent-length: 69\r\n\r\nclient_id=client_id&client_secret=client_secret&grant_type=code_chain",
    );

    assert_missing_id_token_response(&response);
}

#[test]
fn returns_oauth_error_for_invalid_code_chain_id_token() {
    let response = send_request(
        "POST /token HTTP/1.1\r\nhost: example.com\r\ncontent-type: application/x-www-form-urlencoded\r\ncontent-length: 82\r\n\r\nclient_id=client_id&client_secret=client_secret&grant_type=code_chain&id_token=app",
    );

    assert_invalid_id_token_response(&response);
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
fn returns_oauth_error_for_unsupported_form_grant_type() {
    let response = send_request(
        "POST /token HTTP/1.1\r\nhost: example.com\r\ncontent-type: application/x-www-form-urlencoded\r\ncontent-length: 67\r\n\r\nclient_id=client_id&client_secret=client_secret&grant_type=password",
    );

    assert_unsupported_grant_type_response(&response);
}

#[test]
fn returns_oauth_error_for_unsupported_json_grant_type() {
    let response = send_request(
        "POST /token HTTP/1.1\r\nhost: example.com\r\ncontent-type: application/json\r\ncontent-length: 81\r\n\r\n{\"client_id\":\"client_id\",\"client_secret\":\"client_secret\",\"grant_type\":\"password\"}",
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
fn returns_oauth_error_for_missing_client_id() {
    let response = send_request(
        "POST /token HTTP/1.1\r\nhost: example.com\r\ncontent-type: application/x-www-form-urlencoded\r\ncontent-length: 57\r\n\r\nclient_secret=client_secret&grant_type=client_credentials",
    );

    assert_missing_client_id_response(&response);
}

#[test]
fn returns_oauth_error_for_invalid_client_id() {
    let response = send_request(
        "POST /token HTTP/1.1\r\nhost: example.com\r\ncontent-type: application/x-www-form-urlencoded\r\ncontent-length: 71\r\n\r\nclient_id=app&client_secret=client_secret&grant_type=client_credentials",
    );

    assert_invalid_client_id_response(&response);
}

#[test]
fn returns_oauth_error_for_missing_client_secret() {
    let response = send_request(
        "POST /token HTTP/1.1\r\nhost: example.com\r\ncontent-type: application/x-www-form-urlencoded\r\ncontent-length: 49\r\n\r\nclient_id=client_id&grant_type=client_credentials",
    );

    assert_missing_client_secret_response(&response);
}

#[test]
fn returns_oauth_error_for_invalid_client_secret() {
    let response = send_request(
        "POST /token HTTP/1.1\r\nhost: example.com\r\ncontent-type: application/x-www-form-urlencoded\r\ncontent-length: 67\r\n\r\nclient_id=client_id&client_secret=app&grant_type=client_credentials",
    );

    assert_invalid_client_secret_response(&response);
}

#[test]
fn returns_not_found_for_non_post_token_request() {
    let response = send_request("GET /token HTTP/1.1\r\nhost: example.com\r\n\r\n");

    assert!(response.starts_with("HTTP/1.1 404 Not Found\r\n"));
    assert!(response.contains("content-type: text/plain\r\n"));
    assert!(response.contains("connection: close\r\n"));
    assert!(response.ends_with("not found"));
}

fn assert_unsupported_grant_type_response(response: &str) {
    assert!(response.starts_with("HTTP/1.1 400 Bad Request\r\n"));
    assert!(response.contains("content-type: application/json\r\n"));
    assert!(response.contains("connection: close\r\n"));
    assert!(response.contains("\"error\":\"unsupported_grant_type\""));
    assert!(response.contains(
        "\"error_description\":\"grant_type must be one of: client_credentials, code_chain, authorization_code\""
    ));
}

fn assert_missing_authorization_code_response(response: &str) {
    assert!(response.starts_with("HTTP/1.1 400 Bad Request\r\n"));
    assert!(response.contains("content-type: application/json\r\n"));
    assert!(response.contains("connection: close\r\n"));
    assert!(response.contains("\"error\":\"invalid_grant\""));
    assert!(response.contains("\"error_description\":\"authorization_code is required\""));
}

fn assert_invalid_client_id_response(response: &str) {
    assert!(response.starts_with("HTTP/1.1 400 Bad Request\r\n"));
    assert!(response.contains("content-type: application/json\r\n"));
    assert!(response.contains("connection: close\r\n"));
    assert!(response.contains("\"error\":\"invalid_client\""));
    assert!(response.contains("\"error_description\":\"client_id is invalid\""));
}

fn assert_missing_client_id_response(response: &str) {
    assert!(response.starts_with("HTTP/1.1 400 Bad Request\r\n"));
    assert!(response.contains("content-type: application/json\r\n"));
    assert!(response.contains("connection: close\r\n"));
    assert!(response.contains("\"error\":\"invalid_client\""));
    assert!(response.contains("\"error_description\":\"client_id is required\""));
}

fn assert_invalid_client_secret_response(response: &str) {
    assert!(response.starts_with("HTTP/1.1 400 Bad Request\r\n"));
    assert!(response.contains("content-type: application/json\r\n"));
    assert!(response.contains("connection: close\r\n"));
    assert!(response.contains("\"error\":\"invalid_client\""));
    assert!(response.contains("\"error_description\":\"client_secret must be: client_secret\""));
}

fn assert_missing_client_secret_response(response: &str) {
    assert!(response.starts_with("HTTP/1.1 400 Bad Request\r\n"));
    assert!(response.contains("content-type: application/json\r\n"));
    assert!(response.contains("connection: close\r\n"));
    assert!(response.contains("\"error\":\"invalid_client\""));
    assert!(response.contains("\"error_description\":\"client_secret is required\""));
}

fn assert_missing_id_token_response(response: &str) {
    assert!(response.starts_with("HTTP/1.1 400 Bad Request\r\n"));
    assert!(response.contains("content-type: application/json\r\n"));
    assert!(response.contains("connection: close\r\n"));
    assert!(response.contains("\"error\":\"invalid_grant\""));
    assert!(response.contains("\"error_description\":\"id_token is required\""));
}

fn assert_invalid_id_token_response(response: &str) {
    assert!(response.starts_with("HTTP/1.1 400 Bad Request\r\n"));
    assert!(response.contains("content-type: application/json\r\n"));
    assert!(response.contains("connection: close\r\n"));
    assert!(response.contains("\"error\":\"invalid_grant\""));
    assert!(response.contains("\"error_description\":\"id_token must be a jwt\""));
}

fn assert_invalid_authorization_code_response(response: &str) {
    assert!(response.starts_with("HTTP/1.1 400 Bad Request\r\n"));
    assert!(response.contains("content-type: application/json\r\n"));
    assert!(response.contains("connection: close\r\n"));
    assert!(response.contains("\"error\":\"invalid_grant\""));
    assert!(
        response.contains("\"error_description\":\"authorization_code must be a cose_encrypt0\"")
    );
}

fn send_form_token_request(body: &str) -> String {
    send_request(&format!(
        "POST /token HTTP/1.1\r\nhost: example.com\r\ncontent-type: application/x-www-form-urlencoded\r\ncontent-length: {}\r\n\r\n{}",
        body.len(),
        body
    ))
}

fn send_json_token_request(body: &str) -> String {
    send_request(&format!(
        "POST /token HTTP/1.1\r\nhost: example.com\r\ncontent-type: application/json\r\ncontent-length: {}\r\n\r\n{}",
        body.len(),
        body
    ))
}

fn json_string_field(response: &str, field: &str) -> Option<String> {
    let field = format!("\"{field}\":\"");
    let start = response.find(&field)? + field.len();
    let end = response[start..].find('"')?;

    Some(response[start..start + end].to_owned())
}

fn valid_id_token() -> String {
    #[derive(serde::Serialize)]
    struct Claims {
        iat: u64,
        exp: u64,
    }

    let mut header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::HS256);
    header.jwk = Some(jwk());
    let now = jsonwebtoken::get_current_timestamp();

    jsonwebtoken::encode(
        &header,
        &Claims {
            iat: now,
            exp: now + 3600,
        },
        &jsonwebtoken::EncodingKey::from_secret(b"secret"),
    )
    .unwrap()
}

fn valid_authorization_code() -> String {
    struct TestAuthorizationCodeRequest {
        authorization_code: Option<kagome::resources::authorization_code::AuthorizationCode>,
        id_token: String,
    }

    impl kagome::resources::authorization_code::Generate for TestAuthorizationCodeRequest {
        fn previous_authorization_code(&self) -> Option<&str> {
            None
        }

        fn client_id(&self) -> Option<&str> {
            Some("client_id")
        }

        fn id_token(&self) -> Option<&str> {
            Some(&self.id_token)
        }

        fn add_authorization_code(
            &mut self,
            authorization_code: kagome::resources::authorization_code::AuthorizationCode,
        ) {
            self.authorization_code = Some(authorization_code);
        }
    }

    let request = TestAuthorizationCodeRequest {
        authorization_code: None,
        id_token: valid_id_token(),
    };

    kagome::resources::authorization_code::generate(request)
        .unwrap()
        .authorization_code
        .unwrap()
        .value
}

fn jwk() -> jsonwebtoken::jwk::Jwk {
    jsonwebtoken::jwk::Jwk {
        common: jsonwebtoken::jwk::CommonParameters {
            key_algorithm: Some(jsonwebtoken::jwk::KeyAlgorithm::HS256),
            ..Default::default()
        },
        algorithm: jsonwebtoken::jwk::AlgorithmParameters::OctetKey(
            jsonwebtoken::jwk::OctetKeyParameters {
                key_type: jsonwebtoken::jwk::OctetKeyType::Octet,
                value: "c2VjcmV0".to_owned(),
            },
        ),
    }
}
