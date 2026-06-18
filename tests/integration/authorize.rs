use super::server::send_request;

#[test]
fn redirects_to_client_redirect_uri_for_authorize_code_response_type() {
    let response = send_authorize_request(&format!(
        "response_type=code&client_id=client_id&redirect_uri={}&id_token={}",
        valid_redirect_uri(),
        valid_id_token()
    ));

    assert!(response.starts_with("HTTP/1.1 302 Found\r\n"));
    assert!(response.contains("location: https://client.example.com/callback?code="));
    assert!(response.contains("content-length: 0\r\n"));
    assert!(response.contains("connection: close\r\n"));
    assert!(!response.contains("content-type: application/json\r\n"));
    assert!(!response.contains("\"authorization_code\""));
    assert!(!response.contains("\"client_id\""));
    assert!(!response.contains("\"id_token\""));
    assert!(!response.contains("\"response_type\""));
}

#[test]
fn returns_encrypted_code_containing_authorize_request_claims() {
    let id_token = valid_id_token();
    let response = send_authorize_request(&format!(
        "response_type=code&client_id=client_id&redirect_uri={}&id_token={id_token}",
        valid_redirect_uri()
    ));
    let code = redirect_code(&response).expect("authorize redirect should include code");
    let payload = kagome::resources::authorization_code::decode_cose_payload(&code).unwrap();

    assert_eq!(payload.client_id, "client_id");
    assert_eq!(payload.id_token, id_token);
    assert_eq!(payload.previous_code, None);
    assert_eq!(
        payload.exp,
        payload.iat + kagome::resources::authorization_code::AUTHORIZATION_CODE_TTL_SECONDS
    );
}

#[test]
fn returns_oauth_error_for_missing_authorize_response_type() {
    let response = send_authorize_request(&format!(
        "client_id=client_id&redirect_uri={}",
        valid_redirect_uri()
    ));

    assert!(response.starts_with("HTTP/1.1 400 Bad Request\r\n"));
    assert!(response.contains("\"error\":\"unsupported_response_type\""));
    assert!(response.contains("\"error_description\":\"response_type must be one of: code\""));
}

#[test]
fn returns_oauth_error_for_unsupported_authorize_response_type() {
    let response = send_authorize_request(&format!(
        "response_type=token&client_id=client_id&redirect_uri={}",
        valid_redirect_uri()
    ));

    assert!(response.starts_with("HTTP/1.1 400 Bad Request\r\n"));
    assert!(response.contains("\"error\":\"unsupported_response_type\""));
    assert!(response.contains("\"error_description\":\"response_type must be one of: code\""));
}

#[test]
fn returns_oauth_error_for_missing_authorize_client_id() {
    let response = send_authorize_request("response_type=code");

    assert!(response.starts_with("HTTP/1.1 400 Bad Request\r\n"));
    assert!(response.contains("\"error\":\"invalid_client\""));
    assert!(response.contains("\"error_description\":\"client_id is required\""));
}

#[test]
fn returns_oauth_error_for_invalid_authorize_client_id() {
    let response = send_authorize_request(&format!(
        "response_type=code&client_id=app&redirect_uri={}",
        valid_redirect_uri()
    ));

    assert!(response.starts_with("HTTP/1.1 400 Bad Request\r\n"));
    assert!(response.contains("\"error\":\"invalid_client\""));
    assert!(response.contains("\"error_description\":\"client_id must be: client_id\""));
}

#[test]
fn returns_oauth_error_for_missing_authorize_id_token() {
    let response = send_authorize_request(&format!(
        "response_type=code&client_id=client_id&redirect_uri={}",
        valid_redirect_uri()
    ));

    assert!(response.starts_with("HTTP/1.1 400 Bad Request\r\n"));
    assert!(response.contains("\"error\":\"invalid_grant\""));
    assert!(response.contains("\"error_description\":\"id_token is required\""));
}

#[test]
fn returns_oauth_error_for_invalid_authorize_id_token() {
    let response = send_authorize_request(&format!(
        "response_type=code&client_id=client_id&redirect_uri={}&id_token=app",
        valid_redirect_uri()
    ));

    assert!(response.starts_with("HTTP/1.1 400 Bad Request\r\n"));
    assert!(response.contains("\"error\":\"invalid_grant\""));
    assert!(response.contains("\"error_description\":\"id_token must be a jwt\""));
}

#[test]
fn returns_not_found_for_non_get_authorize_request() {
    let response =
        send_request("POST /authorize HTTP/1.1\r\nhost: example.com\r\ncontent-length: 0\r\n\r\n");

    assert!(response.starts_with("HTTP/1.1 404 Not Found\r\n"));
}

#[test]
fn returns_oauth_error_for_missing_authorize_redirect_uri() {
    let response = send_authorize_request("response_type=code&client_id=client_id");

    assert!(response.starts_with("HTTP/1.1 400 Bad Request\r\n"));
    assert!(response.contains("\"error\":\"invalid_request\""));
    assert!(response.contains("\"error_description\":\"redirect_uri is required\""));
}

#[test]
fn returns_oauth_error_for_invalid_authorize_redirect_uri() {
    let response = send_authorize_request(
        "response_type=code&client_id=client_id&redirect_uri=https%3A%2F%2Fapp.example.com%2Fcallback",
    );

    assert!(response.starts_with("HTTP/1.1 400 Bad Request\r\n"));
    assert!(response.contains("\"error\":\"invalid_request\""));
    assert!(response.contains(
        "\"error_description\":\"redirect_uri must be: https://client.example.com/callback\""
    ));
}

fn send_authorize_request(query: &str) -> String {
    send_request(&format!(
        "GET /authorize?{query} HTTP/1.1\r\nhost: example.com\r\n\r\n"
    ))
}

fn redirect_code(response: &str) -> Option<String> {
    let location = response
        .lines()
        .find_map(|line| line.strip_prefix("location: "))?;
    let (_, query) = location.split_once('?')?;
    let encoded_code = query
        .split('&')
        .find_map(|parameter| parameter.strip_prefix("code="))?;

    Some(decode_form_value(encoded_code))
}

fn valid_redirect_uri() -> &'static str {
    "https%3A%2F%2Fclient.example.com%2Fcallback"
}

fn decode_form_value(value: &str) -> String {
    let mut decoded = Vec::with_capacity(value.len());
    let bytes = value.as_bytes();
    let mut index = 0;

    while index < bytes.len() {
        match bytes[index] {
            b'+' => {
                decoded.push(b' ');
                index += 1;
            }
            b'%' if index + 2 < bytes.len() => {
                if let Some(byte) = decode_hex_byte(bytes[index + 1], bytes[index + 2]) {
                    decoded.push(byte);
                    index += 3;
                } else {
                    decoded.push(bytes[index]);
                    index += 1;
                }
            }
            byte => {
                decoded.push(byte);
                index += 1;
            }
        }
    }

    String::from_utf8_lossy(&decoded).into_owned()
}

fn decode_hex_byte(high: u8, low: u8) -> Option<u8> {
    Some(decode_hex_digit(high)? * 16 + decode_hex_digit(low)?)
}

fn decode_hex_digit(digit: u8) -> Option<u8> {
    match digit {
        b'0'..=b'9' => Some(digit - b'0'),
        b'a'..=b'f' => Some(digit - b'a' + 10),
        b'A'..=b'F' => Some(digit - b'A' + 10),
        _ => None,
    }
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
