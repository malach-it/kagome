use jsonwebtoken::{Algorithm, DecodingKey, Validation};
use serde_json::Value;

use super::super::server::send_request;

const HOST: &str = "issuer.example.com";
const CONFIGURATION_ID: &str = "UniversityDegreeCredential";
const GRANT_TYPE: &str = "urn:ietf:params:oauth:grant-type:pre-authorized_code";
const RESPONSE_TYPE: &str = "urn:ietf:params:oauth:response-type:pre-authorized_code";

// Branch matrix:
// - discovery endpoint: issuer metadata | authorization-server metadata | JWKS
// - endpoint method: supported | credential OPTIONS preflight | unsupported
// - Host: valid | missing | invalid
// - token representation: form | JSON
// - pre-authorized_code: valid | missing | invalid | expired
// - tx_code: valid | omitted | invalid
// - successful token authorization_details: credential configuration | format | type
// - redemption count: first | repeated (equivalent because this stateless profile
//   deliberately permits reuse until expiration)
// - bearer token: valid | missing | malformed | invalid
// - credential request media type: application/json (case-insensitive, parameters
//   allowed) | missing | unsupported
// - credential_identifier: supported | missing | legacy credential_configuration_id | unknown
// - authorize response type: authenticated | unauthenticated | combined with another type
// A token/configuration mismatch is unreachable because this profile advertises
// and issues exactly one credential configuration.

#[test]
fn returns_credential_issuer_metadata() {
    let response = get("/.well-known/openid-credential-issuer");
    let body = json_body(&response);

    assert_ok_json(&response);
    assert_eq!(body["credential_issuer"], "https://issuer.example.com");
    assert_eq!(
        body["credential_endpoint"],
        "https://issuer.example.com/credential"
    );
    assert_eq!(
        body["credential_configurations_supported"][CONFIGURATION_ID]["format"],
        "jwt_vc"
    );
    assert_eq!(
        body["credential_configurations_supported"][CONFIGURATION_ID]["credential_signing_alg_values_supported"]
            [0],
        "EdDSA"
    );
    assert!(
        body["credential_configurations_supported"][CONFIGURATION_ID]
            .get("proof_types_supported")
            .is_none()
    );
}

#[test]
fn returns_authorization_server_metadata() {
    let response = get("/.well-known/oauth-authorization-server");
    let body = json_body(&response);

    assert_ok_json(&response);
    assert_eq!(body["issuer"], "https://issuer.example.com");
    assert_eq!(body["token_endpoint"], "https://issuer.example.com/token");
    assert_eq!(body["response_types_supported"][1], RESPONSE_TYPE);
    assert_eq!(body["grant_types_supported"][1], GRANT_TYPE);
    assert_eq!(
        body["pre-authorized_grant_anonymous_access_supported"],
        true
    );
}

#[test]
fn returns_credential_signing_jwk() {
    let response = get("/jwks");
    let body = json_body(&response);

    assert_ok_json(&response);
    assert_eq!(body["keys"][0]["kty"], "OKP");
    assert_eq!(body["keys"][0]["crv"], "Ed25519");
    assert_eq!(body["keys"][0]["alg"], "EdDSA");
}

#[test]
fn returns_pre_authorized_credential_offer_with_cose_code() {
    let response = credential_offer();
    let body = json_body(&response);
    let grant = &body["grants"][GRANT_TYPE];
    let code = grant["pre-authorized_code"].as_str().unwrap();

    assert_ok_json(&response);
    assert_eq!(body["credential_configuration_ids"][0], CONFIGURATION_ID);
    assert!(grant.get("tx_code").is_none());
    assert!(!code.contains('.'));
    assert!(
        base64::Engine::decode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, code).is_ok()
    );
}

#[test]
fn redirects_authenticated_authorize_request_with_credential_offer() {
    let response = authorize_preauthorized_code("", "username=username&password=password");
    let offer = redirected_credential_offer(&response);
    let grant = &offer["grants"][GRANT_TYPE];
    let code = grant["pre-authorized_code"].as_str().unwrap();

    assert!(response.starts_with("HTTP/1.1 302 Found\r\n"));
    assert_eq!(offer["credential_issuer"], "http://localhost:4000");
    assert_eq!(offer["credential_configuration_ids"][0], CONFIGURATION_ID);
    assert!(grant.get("tx_code").is_none());

    let token_response = token_request(&format!(
        "grant_type={GRANT_TYPE}&pre-authorized_code={code}&tx_code=493536"
    ));
    let access_token = json_body(&token_response)["access_token"]
        .as_str()
        .unwrap()
        .to_owned();
    let credential_response =
        credential_request(Some(&access_token), "application/json", CONFIGURATION_ID);
    let credential = json_body(&credential_response)["credential"]
        .as_str()
        .unwrap()
        .to_owned();
    let mut validation = Validation::new(Algorithm::EdDSA);
    validation.validate_aud = false;
    let claims = jsonwebtoken::decode::<Value>(
        &credential,
        &DecodingKey::from_ed_pem(kagome::resources::verifiable_credential::PUBLIC_KEY).unwrap(),
        &validation,
    )
    .unwrap()
    .claims;

    assert_eq!(claims["sub"], "username");
}

#[test]
fn returns_login_for_unauthenticated_preauthorized_code_request() {
    let response = send_request(&format!(
        "GET /authorize?response_type={RESPONSE_TYPE}&client_id=client_id&redirect_uri=https%3A%2F%2Fclient.example.com%2Fcallback HTTP/1.1\r\nhost: example.com\r\n\r\n"
    ));

    assert!(response.starts_with("HTTP/1.1 200 OK\r\n"));
    assert!(response.contains("<title>kagome login</title>"));
}

#[test]
fn rejects_preauthorized_code_combined_with_another_response_type() {
    let response = authorize_preauthorized_code("code+", "username=username&password=password");

    assert!(response.starts_with("HTTP/1.1 400 Bad Request\r\n"));
    assert!(response.contains("invalid final response type"));
}

#[test]
fn exchanges_pre_authorized_code_from_form_request() {
    let code = offered_code();
    let response = token_request(&format!(
        "grant_type={GRANT_TYPE}&pre-authorized_code={code}&tx_code=493536"
    ));

    assert_token_response(&response);
}

#[test]
fn exchanges_pre_authorized_code_from_json_request() {
    let code = offered_code();
    let body = serde_json::json!({
        "grant_type": GRANT_TYPE,
        "pre-authorized_code": code,
        "tx_code": "493536"
    })
    .to_string();
    let response = post_json("/token", None, &body);

    assert_token_response(&response);
}

#[test]
fn permits_repeated_exchange_of_encrypted_pre_authorized_code() {
    let code = offered_code();
    let body = format!("grant_type={GRANT_TYPE}&pre-authorized_code={code}&tx_code=493536");

    assert_token_response(&token_request(&body));
    assert_token_response(&token_request(&body));
}

#[test]
fn rejects_missing_pre_authorized_code() {
    let response = token_request(&format!("grant_type={GRANT_TYPE}&tx_code=493536"));

    assert_oauth_error(
        &response,
        "invalid_request",
        "pre-authorized_code is required",
    );
}

#[test]
fn rejects_invalid_pre_authorized_code() {
    let response = token_request(&format!(
        "grant_type={GRANT_TYPE}&pre-authorized_code=invalid&tx_code=493536"
    ));

    assert_oauth_error(
        &response,
        "invalid_grant",
        "pre-authorized_code is invalid or expired",
    );
}

#[test]
fn rejects_expired_pre_authorized_code() {
    let code = expired_code();
    let response = token_request(&format!(
        "grant_type={GRANT_TYPE}&pre-authorized_code={code}&tx_code=493536"
    ));

    assert_oauth_error(
        &response,
        "invalid_grant",
        "pre-authorized_code is invalid or expired",
    );
}

#[test]
fn exchanges_pre_authorized_code_without_transaction_code() {
    let code = offered_code();
    let response = token_request(&format!(
        "grant_type={GRANT_TYPE}&pre-authorized_code={code}"
    ));

    assert_token_response(&response);
}

#[test]
fn exchanges_json_pre_authorized_code_without_transaction_code() {
    let code = offered_code();
    let body = serde_json::json!({
        "grant_type": GRANT_TYPE,
        "pre-authorized_code": code
    })
    .to_string();
    let response = post_json("/token", None, &body);

    assert_token_response(&response);
}

#[test]
fn rejects_invalid_transaction_code() {
    let code = offered_code();
    let response = token_request(&format!(
        "grant_type={GRANT_TYPE}&pre-authorized_code={code}&tx_code=000000"
    ));

    assert_oauth_error(&response, "invalid_grant", "tx_code is invalid");
}

#[test]
fn rejects_invalid_json_transaction_code() {
    let code = offered_code();
    let body = serde_json::json!({
        "grant_type": GRANT_TYPE,
        "pre-authorized_code": code,
        "tx_code": "000000"
    })
    .to_string();
    let response = post_json("/token", None, &body);

    assert_oauth_error(&response, "invalid_grant", "tx_code is invalid");
}

#[test]
fn issues_ed25519_signed_jwt_vc() {
    let access_token = access_token();
    let response = credential_request(Some(&access_token), "application/json", CONFIGURATION_ID);
    let body = json_body(&response);
    let credential = body["credential"].as_str().unwrap();
    let mut validation = Validation::new(Algorithm::EdDSA);
    validation.validate_aud = false;
    let claims = jsonwebtoken::decode::<Value>(
        credential,
        &DecodingKey::from_ed_pem(kagome::resources::verifiable_credential::PUBLIC_KEY).unwrap(),
        &validation,
    )
    .unwrap()
    .claims;

    assert_ok_json(&response);
    assert!(response.contains("access-control-allow-origin: *\r\n"));
    assert_eq!(body["format"], "jwt_vc");
    assert_eq!(claims["iss"], "https://issuer.example.com");
    assert_eq!(claims["sub"], "did:example:alice");
    assert_eq!(
        claims["type"],
        serde_json::json!(["VerifiableCredential", CONFIGURATION_ID])
    );
    assert_eq!(
        claims["credentialSubject"][CONFIGURATION_ID]["degree"]["name"],
        "Bachelor of Science and Arts"
    );
}

#[test]
fn accepts_case_insensitive_json_credential_content_type_with_parameters() {
    let access_token = access_token();
    let response = credential_request(
        Some(&access_token),
        "Application/JSON; Charset=UTF-8",
        CONFIGURATION_ID,
    );

    assert_ok_json(&response);
}

#[test]
fn rejects_missing_bearer_token() {
    let response = credential_request(None, "application/json", CONFIGURATION_ID);

    assert_bearer_error(&response, "bearer access token is required");
}

#[test]
fn returns_credential_cors_preflight_response() {
    let response = send_request(
        "OPTIONS /credential HTTP/1.1\r\nhost: issuer.example.com\r\norigin: https://wallet.example.com\r\naccess-control-request-method: POST\r\naccess-control-request-headers: content-type, authorization\r\n\r\n",
    );

    assert!(response.starts_with("HTTP/1.1 204 No Content\r\n"));
    assert!(response.contains("access-control-allow-origin: *\r\n"));
    assert!(response.contains("access-control-allow-methods: POST, OPTIONS\r\n"));
    assert!(response.contains("access-control-allow-headers: content-type, authorization\r\n"));
    assert!(response.contains("content-length: 0\r\n"));
}

#[test]
fn rejects_malformed_bearer_authorization() {
    let response = post_json(
        "/credential",
        Some("Basic credentials"),
        &credential_body(CONFIGURATION_ID),
    );

    assert_bearer_error(&response, "bearer access token is required");
}

#[test]
fn rejects_invalid_bearer_token() {
    let response = credential_request(Some("invalid"), "application/json", CONFIGURATION_ID);

    assert_bearer_error(&response, "bearer access token is invalid or expired");
}

#[test]
fn rejects_missing_credential_identifier() {
    let access_token = access_token();
    let response = post_json("/credential", Some(&format!("Bearer {access_token}")), "{}");

    assert_credential_error(
        &response,
        "invalid_credential_request",
        "credential_identifier is required",
    );
}

#[test]
fn rejects_legacy_credential_configuration_id_request_parameter() {
    let access_token = access_token();
    let body = serde_json::json!({
        "credential_configuration_id": CONFIGURATION_ID
    })
    .to_string();
    let response = post_json(
        "/credential",
        Some(&format!("Bearer {access_token}")),
        &body,
    );

    assert_credential_error(
        &response,
        "invalid_credential_request",
        "credential_identifier is required",
    );
}

#[test]
fn rejects_unknown_credential_identifier() {
    let access_token = access_token();
    let response = credential_request(Some(&access_token), "application/json", "UnknownCredential");

    assert_credential_error(
        &response,
        "unknown_credential_configuration",
        "credential_identifier is unknown",
    );
}

#[test]
fn rejects_missing_credential_content_type() {
    let access_token = access_token();
    let body = credential_body(CONFIGURATION_ID);
    let response = send_request(&format!(
        "POST /credential HTTP/1.1\r\nhost: {HOST}\r\nauthorization: Bearer {access_token}\r\ncontent-length: {}\r\n\r\n{body}",
        body.len()
    ));

    assert_credential_error(
        &response,
        "invalid_credential_request",
        "credential request content-type must be application/json",
    );
}

#[test]
fn rejects_form_credential_request() {
    let access_token = access_token();
    let response = credential_request(
        Some(&access_token),
        "application/x-www-form-urlencoded",
        CONFIGURATION_ID,
    );

    assert_credential_error(
        &response,
        "invalid_credential_request",
        "credential request content-type must be application/json",
    );
}

#[test]
fn returns_not_found_for_unsupported_oid4vci_methods() {
    for path in [
        "/.well-known/openid-credential-issuer",
        "/.well-known/oauth-authorization-server",
        "/credential-offer",
        "/jwks",
    ] {
        let response = send_request(&format!("POST {path} HTTP/1.1\r\nhost: {HOST}\r\n\r\n"));
        assert!(response.starts_with("HTTP/1.1 404 Not Found\r\n"));
    }

    let response = send_request(&format!("GET /credential HTTP/1.1\r\nhost: {HOST}\r\n\r\n"));
    assert!(response.starts_with("HTTP/1.1 404 Not Found\r\n"));
}

#[test]
fn rejects_missing_or_invalid_host_for_issuer_endpoints() {
    let missing = send_request("GET /.well-known/openid-credential-issuer HTTP/1.1\r\n\r\n");
    assert_oauth_error(&missing, "invalid_request", "host header is required");

    let invalid = send_request(
        "GET /.well-known/openid-credential-issuer HTTP/1.1\r\nhost: issuer/example\r\n\r\n",
    );
    assert_oauth_error(&invalid, "invalid_request", "host header is invalid");
}

fn credential_offer() -> String {
    get("/credential-offer")
}

fn authorize_preauthorized_code(prefix: &str, body: &str) -> String {
    send_request(&format!(
        "POST /authorize?response_type={prefix}{RESPONSE_TYPE}&client_id=client_id&redirect_uri=https%3A%2F%2Fclient.example.com%2Fcallback HTTP/1.1\r\nhost: example.com\r\ncontent-type: application/x-www-form-urlencoded\r\ncontent-length: {}\r\n\r\n{body}",
        body.len()
    ))
}

fn redirected_credential_offer(response: &str) -> Value {
    let location = response
        .lines()
        .find_map(|line| line.strip_prefix("location: "))
        .expect("authorize response should contain a location");
    let encoded_offer = location
        .split_once('?')
        .and_then(|(_, query)| {
            query
                .split('&')
                .find_map(|value| value.strip_prefix("credential_offer="))
        })
        .expect("authorize response should contain a credential offer");

    serde_json::from_str(&decode_form_value(encoded_offer)).unwrap()
}

fn decode_form_value(value: &str) -> String {
    let mut decoded = Vec::with_capacity(value.len());
    let bytes = value.as_bytes();
    let mut index = 0;

    while index < bytes.len() {
        match bytes[index] {
            b'+' => decoded.push(b' '),
            b'%' if index + 2 < bytes.len() => {
                let byte = u8::from_str_radix(&value[index + 1..index + 3], 16).unwrap();
                decoded.push(byte);
                index += 2;
            }
            byte => decoded.push(byte),
        }
        index += 1;
    }

    String::from_utf8(decoded).unwrap()
}

fn offered_code() -> String {
    json_body(&credential_offer())["grants"][GRANT_TYPE]["pre-authorized_code"]
        .as_str()
        .unwrap()
        .to_owned()
}

fn expired_code() -> String {
    let claims = kagome::resources::pre_authorized_code::PreAuthorizedCodeClaims {
        credential_configuration_id: CONFIGURATION_ID.to_owned(),
        subject: "did:example:alice".to_owned(),
        iat: 1,
        exp: 2,
    };
    let mut bytes = Vec::new();
    ciborium::into_writer(&claims, &mut bytes).unwrap();
    kagome::resources::crypto::encode_cose_encrypt0(
        &bytes,
        kagome::resources::pre_authorized_code::SECRET,
        kagome::resources::pre_authorized_code::COSE_EXTERNAL_AAD,
    )
    .unwrap()
}

fn access_token() -> String {
    let code = offered_code();
    let response = token_request(&format!(
        "grant_type={GRANT_TYPE}&pre-authorized_code={code}&tx_code=493536"
    ));
    json_body(&response)["access_token"]
        .as_str()
        .unwrap()
        .to_owned()
}

fn get(path: &str) -> String {
    send_request(&format!("GET {path} HTTP/1.1\r\nhost: {HOST}\r\n\r\n"))
}

fn token_request(body: &str) -> String {
    send_request(&format!(
        "POST /token HTTP/1.1\r\nhost: {HOST}\r\ncontent-type: application/x-www-form-urlencoded\r\ncontent-length: {}\r\n\r\n{body}",
        body.len()
    ))
}

fn credential_request(
    access_token: Option<&str>,
    content_type: &str,
    credential_identifier: &str,
) -> String {
    let authorization = access_token.map(|token| format!("Bearer {token}"));
    post(
        "/credential",
        authorization.as_deref(),
        content_type,
        &credential_body(credential_identifier),
    )
}

fn post_json(path: &str, authorization: Option<&str>, body: &str) -> String {
    post(path, authorization, "application/json", body)
}

fn post(path: &str, authorization: Option<&str>, content_type: &str, body: &str) -> String {
    let authorization = authorization
        .map(|authorization| format!("authorization: {authorization}\r\n"))
        .unwrap_or_default();
    send_request(&format!(
        "POST {path} HTTP/1.1\r\nhost: {HOST}\r\ncontent-type: {content_type}\r\n{authorization}content-length: {}\r\n\r\n{body}",
        body.len()
    ))
}

fn credential_body(credential_identifier: &str) -> String {
    serde_json::json!({"credential_identifier": credential_identifier}).to_string()
}

fn json_body(response: &str) -> Value {
    serde_json::from_str(response.split_once("\r\n\r\n").unwrap().1).unwrap()
}

fn assert_ok_json(response: &str) {
    assert!(response.starts_with("HTTP/1.1 200 OK\r\n"));
    assert!(response.contains("content-type: application/json\r\n"));
    assert!(response.contains("cache-control: no-store\r\n"));
}

fn assert_token_response(response: &str) {
    assert_ok_json(response);
    let body = json_body(response);
    assert_eq!(body["token_type"], "Bearer");
    assert_eq!(body["expires_in"], 3600);
    assert_eq!(
        body["authorization_details"],
        serde_json::json!([{
            "type": "openid_credential",
            "format": "jwt_vc",
            "credential_configuration_id": CONFIGURATION_ID,
        }])
    );
    assert!(
        body["access_token"]
            .as_str()
            .is_some_and(|token| !token.is_empty())
    );
}

fn assert_oauth_error(response: &str, error: &str, description: &str) {
    assert!(response.starts_with("HTTP/1.1 400 Bad Request\r\n"));
    let body = json_body(response);
    assert_eq!(body["error"], error);
    assert_eq!(body["error_description"], description);
}

fn assert_credential_error(response: &str, error: &str, description: &str) {
    assert_oauth_error(response, error, description);
    assert!(response.contains("cache-control: no-store\r\n"));
    assert!(response.contains("access-control-allow-origin: *\r\n"));
}

fn assert_bearer_error(response: &str, description: &str) {
    assert!(response.starts_with("HTTP/1.1 401 Unauthorized\r\n"));
    assert!(response.contains("www-authenticate: Bearer error=\"invalid_token\"\r\n"));
    assert!(response.contains("access-control-allow-origin: *\r\n"));
    let body = json_body(response);
    assert_eq!(body["error"], "invalid_token");
    assert_eq!(body["error_description"], description);
}
