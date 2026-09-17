mod authorization_code;
mod client_credentials;
mod code_chain;
mod federation_callback;
mod implicit;
mod resource_owner_password_credentials;

const PKCE_VERIFIER: &str = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
const PKCE_CHALLENGE: &str = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

pub(super) use super::super::server::send_request;

pub(super) fn assert_unsupported_grant_type_response(response: &str) {
    assert!(response.starts_with("HTTP/1.1 400 Bad Request\r\n"));
    assert!(response.contains("content-type: application/json\r\n"));
    assert!(response.contains("connection: close\r\n"));
    assert!(!response.contains("access-control-allow-origin:"));
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
    assert!(
        response.contains(&format!("\"error_description\":\"{description}\"")),
        "unexpected response: {response}"
    );
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
    valid_id_token_for_client("client_id")
}

fn valid_id_token_for_client(client_id: &str) -> String {
    let now = jsonwebtoken::get_current_timestamp();
    sign_id_token(serde_json::json!({
        "iss": "http://localhost:4000",
        "sub": "username",
        "aud": client_id,
        "client_id": client_id,
        "username": "username",
        "profile": {"username": "username"},
        "iat": now,
        "exp": now + 3600,
    }))
}

fn id_token_with_invalid_signature() -> String {
    corrupt_signature(&valid_id_token())
}

fn corrupt_signature(token: &str) -> String {
    let (signed, signature) = token.rsplit_once('.').unwrap();
    let replacement = if signature.starts_with('A') { 'B' } else { 'A' };
    format!("{signed}.{replacement}{}", &signature[1..])
}

fn id_token_signed_by_untrusted_key() -> String {
    kagome::resources::crypto::sign_jwt(
        &valid_id_token_claims(),
        kagome::resources::crypto::SigningArtifact::Credential,
    )
    .unwrap()
}

fn id_token_with_embedded_jwk() -> String {
    const PRIVATE_KEY: &[u8] = b"-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEIDt2IW+OSTJfZcs+QLnyHa+IoZthF8Pbf7sBWYsElCKk\n-----END PRIVATE KEY-----\n";

    let mut header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::EdDSA);
    header.kid = Some(
        kagome::resources::crypto::SigningArtifact::IdToken
            .key_id()
            .to_owned(),
    );
    header.jwk = Some(
        serde_json::from_value(serde_json::json!({
            "kty": "OKP",
            "crv": "Ed25519",
            "x": "mbDL1A9YckRdA3AlHpbwDmEYpR9TJV3qQwKQkNbD63g"
        }))
        .unwrap(),
    );
    jsonwebtoken::encode(
        &header,
        &valid_id_token_claims(),
        &jsonwebtoken::EncodingKey::from_ed_pem(PRIVATE_KEY).unwrap(),
    )
    .unwrap()
}

fn id_token_without_claim(claim: &str) -> String {
    let mut claims = valid_id_token_claims();
    claims.as_object_mut().unwrap().remove(claim);
    sign_id_token(claims)
}

fn id_token_with_claim(claim: &str, value: &str) -> String {
    let mut claims = valid_id_token_claims();
    claims[claim] = serde_json::json!(value);
    sign_id_token(claims)
}

fn id_token_with_invalid_claims() -> String {
    let mut claims = valid_id_token_claims();
    claims["iat"] = serde_json::json!("now");
    sign_id_token(claims)
}

fn id_token_without_iat() -> String {
    let mut claims = valid_id_token_claims();
    claims.as_object_mut().unwrap().remove("iat");
    sign_id_token(claims)
}

fn id_token_without_exp() -> String {
    let mut claims = valid_id_token_claims();
    claims.as_object_mut().unwrap().remove("exp");
    sign_id_token(claims)
}

fn expired_id_token() -> String {
    let now = jsonwebtoken::get_current_timestamp();
    let mut claims = valid_id_token_claims();
    claims["iat"] = serde_json::json!(now - 7200);
    claims["exp"] = serde_json::json!(now - 3600);
    sign_id_token(claims)
}

fn future_id_token() -> String {
    let now = jsonwebtoken::get_current_timestamp();
    let mut claims = valid_id_token_claims();
    claims["iat"] = serde_json::json!(now + 3600);
    claims["exp"] = serde_json::json!(now + 7200);
    sign_id_token(claims)
}

fn id_token_expiring_before_iat() -> String {
    let now = jsonwebtoken::get_current_timestamp();
    let mut claims = valid_id_token_claims();
    claims["iat"] = serde_json::json!(now);
    claims["exp"] = serde_json::json!(now - 1);
    sign_id_token(claims)
}

fn valid_id_token_claims() -> serde_json::Value {
    let now = jsonwebtoken::get_current_timestamp();
    serde_json::json!({
        "iss": "http://localhost:4000",
        "sub": "username",
        "aud": "client_id",
        "client_id": "client_id",
        "username": "username",
        "profile": {"username": "username"},
        "iat": now,
        "exp": now + 3600,
    })
}

fn sign_id_token(claims: serde_json::Value) -> String {
    kagome::resources::crypto::sign_jwt(
        &claims,
        kagome::resources::crypto::SigningArtifact::IdToken,
    )
    .unwrap()
}

fn valid_authorization_code() -> String {
    authorization_code_for_client_id_and_challenge("client_id", Some(PKCE_CHALLENGE))
}

fn authorization_code_for_client_id(client_id: &str) -> String {
    authorization_code_for_client_id_and_challenge(client_id, None)
}

fn authorization_code_for_client_id_and_challenge(
    client_id: &str,
    code_challenge: Option<&str>,
) -> String {
    struct TestAuthorizationCodeRequest {
        authorization_code: Option<kagome::resources::authorization_code::AuthorizationCode>,
        client_id: String,
        id_token: String,
        id_token_public_jwk: serde_json::Value,
        code_challenge: Option<kagome::resources::pkce::CodeChallenge>,
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

        fn id_token_public_jwk(&self) -> Option<&serde_json::Value> {
            Some(&self.id_token_public_jwk)
        }

        fn code_challenge(&self) -> Option<&kagome::resources::pkce::CodeChallenge> {
            self.code_challenge.as_ref()
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
        id_token: valid_id_token_for_client(client_id),
        id_token_public_jwk: wallet_binding_jwk(),
        code_challenge: code_challenge.map(|value| kagome::resources::pkce::CodeChallenge {
            value: value.to_owned(),
        }),
    };

    kagome::resources::authorization_code::generate(request)
        .unwrap()
        .authorization_code
        .unwrap()
        .value
}

fn wallet_binding_jwk() -> serde_json::Value {
    serde_json::json!({
        "kty": "EC",
        "crv": "P-256",
        "x": "2OOMuJdc5XAbumGYaUtM3ngfBVFhqjeqb0fJ_N3Y7UI",
        "y": "Yp8TpPyvA3t9jF01vn7Z6SXYjpKkZOrO1Gg7CkxnMF8"
    })
}
