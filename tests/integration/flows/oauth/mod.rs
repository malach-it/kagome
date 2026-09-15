mod authorization_code;
mod client_credentials;
mod code_chain;
mod federation_callback;
mod implicit;
mod resource_owner_password_credentials;

pub(super) use super::super::server::send_request;

pub(super) fn assert_unsupported_grant_type_response(response: &str) {
    assert!(response.starts_with("HTTP/1.1 400 Bad Request\r\n"));
    assert!(response.contains("content-type: application/json\r\n"));
    assert!(response.contains("connection: close\r\n"));
    assert!(response.contains("\"error\":\"unsupported_grant_type\""));
    assert!(response.contains(
        "\"error_description\":\"grant_type must be one of: client_credentials, password, code_chain, authorization_code, urn:ietf:params:oauth:grant-type:pre-authorized_code\""
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
    assert!(response.contains("\"error_description\":\"client_secret is invalid\""));
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
    assert_invalid_id_token_response_with_description(response, "id_token must be a jwt");
}

fn assert_invalid_id_token_response_with_description(response: &str, description: &str) {
    assert!(response.starts_with("HTTP/1.1 400 Bad Request\r\n"));
    assert!(response.contains("content-type: application/json\r\n"));
    assert!(response.contains("connection: close\r\n"));
    assert!(response.contains("\"error\":\"invalid_grant\""));
    assert!(response.contains(&format!("\"error_description\":\"{description}\"")));
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
    let now = jsonwebtoken::get_current_timestamp();
    encode_id_token("secret", Some(jwk()), Some(now), Some(now + 3600))
}

fn id_token_without_jwk() -> String {
    let now = jsonwebtoken::get_current_timestamp();
    encode_id_token("secret", None, Some(now), Some(now + 3600))
}

fn id_token_with_invalid_jwk() -> String {
    let now = jsonwebtoken::get_current_timestamp();
    encode_id_token("secret", Some(invalid_jwk()), Some(now), Some(now + 3600))
}

fn id_token_with_invalid_signature() -> String {
    let now = jsonwebtoken::get_current_timestamp();
    encode_id_token("other", Some(jwk()), Some(now), Some(now + 3600))
}

fn id_token_with_invalid_claims() -> String {
    let mut header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::HS256);
    header.jwk = Some(jwk());

    jsonwebtoken::encode(
        &header,
        &serde_json::json!({"iat": "now", "exp": "later"}),
        &jsonwebtoken::EncodingKey::from_secret(b"secret"),
    )
    .unwrap()
}

fn id_token_without_iat() -> String {
    let now = jsonwebtoken::get_current_timestamp();
    encode_id_token("secret", Some(jwk()), None, Some(now + 3600))
}

fn id_token_without_exp() -> String {
    let now = jsonwebtoken::get_current_timestamp();
    encode_id_token("secret", Some(jwk()), Some(now), None)
}

fn expired_id_token() -> String {
    let now = jsonwebtoken::get_current_timestamp();
    encode_id_token("secret", Some(jwk()), Some(now - 7200), Some(now - 3600))
}

fn future_id_token() -> String {
    let now = jsonwebtoken::get_current_timestamp();
    encode_id_token("secret", Some(jwk()), Some(now + 3600), Some(now + 7200))
}

fn id_token_expiring_before_iat() -> String {
    let now = jsonwebtoken::get_current_timestamp();
    encode_id_token("secret", Some(jwk()), Some(now), Some(now - 1))
}

fn encode_id_token(
    secret: &str,
    jwk: Option<jsonwebtoken::jwk::Jwk>,
    iat: Option<u64>,
    exp: Option<u64>,
) -> String {
    #[derive(serde::Serialize)]
    struct Claims {
        #[serde(skip_serializing_if = "Option::is_none")]
        iat: Option<u64>,
        #[serde(skip_serializing_if = "Option::is_none")]
        exp: Option<u64>,
    }

    let mut header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::HS256);
    header.jwk = jwk;

    jsonwebtoken::encode(
        &header,
        &Claims { iat, exp },
        &jsonwebtoken::EncodingKey::from_secret(secret.as_bytes()),
    )
    .unwrap()
}

fn valid_authorization_code() -> String {
    authorization_code_for_client_id("client_id")
}

fn authorization_code_for_client_id(client_id: &str) -> String {
    struct TestAuthorizationCodeRequest {
        authorization_code: Option<kagome::resources::authorization_code::AuthorizationCode>,
        client_id: String,
        id_token: String,
    }

    impl kagome::resources::authorization_code::Generate for TestAuthorizationCodeRequest {
        fn previous_authorization_code(&self) -> Option<&str> {
            None
        }

        fn client_id(&self) -> Option<&str> {
            Some(&self.client_id)
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
        client_id: client_id.to_owned(),
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

fn invalid_jwk() -> jsonwebtoken::jwk::Jwk {
    jsonwebtoken::jwk::Jwk {
        common: jsonwebtoken::jwk::CommonParameters {
            key_algorithm: Some(jsonwebtoken::jwk::KeyAlgorithm::HS256),
            ..Default::default()
        },
        algorithm: jsonwebtoken::jwk::AlgorithmParameters::OctetKey(
            jsonwebtoken::jwk::OctetKeyParameters {
                key_type: jsonwebtoken::jwk::OctetKeyType::Octet,
                value: "not-base64".to_owned(),
            },
        ),
    }
}
