use std::time::{SystemTime, UNIX_EPOCH};

use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use serde_json::{Value, json};

use super::super::server::send_request;

const HOST: &str = "issuer.example.com";
const CLIENT_ID: &str = "redirect_uri:https://issuer.example.com/presentation-response";
const QUERY_ID: &str = "degree_credential";
const HOLDER_PRIVATE_KEY: &[u8] = b"-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEINJfaccWsYDZbi2f7pKdaHSEmgf8842Rvoli2GJ94YSk\n-----END PRIVATE KEY-----\n";
const ISSUER_PRIVATE_KEY: &[u8] = b"-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEIDt2IW+OSTJfZcs+QLnyHa+IoZthF8Pbf7sBWYsElCKk\n-----END PRIVATE KEY-----\n";

// Branch matrix:
// - endpoint method: supported | unsupported
// - Host on request creation: valid | missing | invalid
// - generated transaction values: fresh nonce/state | generation failure (not
//   reachable with the process RNG and embedded encryption key)
// - response media type: form (case-insensitive, parameters allowed) | missing |
//   unsupported
// - state: valid | missing | invalid | expired | replayed
// - response kind: vp_token | supported wallet error | unsupported wallet error |
//   neither | both (invalid)
// - VP Token shape: requested query with one string presentation | malformed JSON |
//   missing/wrong/additional query | zero/multiple presentations | non-string
// - presentation JWT: valid EdDSA with JWK | malformed | missing JWK | wrong
//   algorithm | untrusted key | invalid signature | expired
// - holder binding: matching audience/nonce/subject/key | mismatch for each
// - presentation contents: VerifiablePresentation with one credential | wrong type |
//   multiple credentials
// - credential: trusted issuer JWT satisfying type/claims | malformed/tampered
// A trusted credential with the wrong issuer, type, claims, or holder key is
// unreachable through Kagome's fixed issuer endpoint; tampering is covered as an
// invalid issuer signature.

#[test]
fn returns_dcql_direct_post_presentation_request() {
    let request = presentation_request();

    assert_ok_json(&request.response);
    assert_eq!(request.body["client_id"], CLIENT_ID);
    assert_eq!(
        request.body["response_uri"],
        "https://issuer.example.com/presentation-response"
    );
    assert_eq!(request.body["response_type"], "vp_token");
    assert_eq!(request.body["response_mode"], "direct_post");
    assert!(
        request.body["nonce"]
            .as_str()
            .is_some_and(|v| v.len() >= 32)
    );
    assert!(
        request.body["state"]
            .as_str()
            .is_some_and(|v| !v.is_empty())
    );
    assert_eq!(request.body["dcql_query"]["credentials"][0]["id"], QUERY_ID);
    assert_eq!(
        request.body["dcql_query"]["credentials"][0]["format"],
        "jwt_vc"
    );
    assert_eq!(
        request.body["dcql_query"]["credentials"][0]["meta"]["type_values"][0][1],
        "UniversityDegreeCredential"
    );
    assert_eq!(
        request.body["client_metadata"]["vp_formats_supported"]["jwt_vc"]["alg_values"][0],
        "EdDSA"
    );
}

#[test]
fn generates_fresh_nonce_and_state_for_each_request() {
    let first = presentation_request();
    let second = presentation_request();

    assert_ne!(first.body["nonce"], second.body["nonce"]);
    assert_ne!(first.body["state"], second.body["state"]);
}

#[test]
fn rejects_missing_or_invalid_host_for_presentation_request() {
    let missing = send_request("GET /presentation-request HTTP/1.1\r\n\r\n");
    assert_error(&missing, "host header is required");

    let invalid =
        send_request("GET /presentation-request HTTP/1.1\r\nhost: verifier/example\r\n\r\n");
    assert_error(&invalid, "host header is invalid");
}

#[test]
fn returns_not_found_for_unsupported_presentation_endpoint_methods() {
    let request = send_request(&format!(
        "POST /presentation-request HTTP/1.1\r\nhost: {HOST}\r\n\r\n"
    ));
    let response = send_request(&format!(
        "GET /presentation-response HTTP/1.1\r\nhost: {HOST}\r\n\r\n"
    ));

    assert!(request.starts_with("HTTP/1.1 404 Not Found\r\n"));
    assert!(response.starts_with("HTTP/1.1 404 Not Found\r\n"));
}

#[test]
fn accepts_holder_bound_verifiable_presentation() {
    let fixture = presentation_fixture(PresentationOverrides::default());
    let response = submit(
        &fixture.state,
        Some(&fixture.vp_token),
        None,
        FORM_CONTENT_TYPE,
    );

    assert_ok_json(&response);
    assert_eq!(json_body(&response), json!({}));
}

#[test]
fn accepts_case_insensitive_form_content_type_with_parameters() {
    let fixture = presentation_fixture(PresentationOverrides::default());
    let response = submit(
        &fixture.state,
        Some(&fixture.vp_token),
        None,
        "Application/X-WWW-Form-Urlencoded; Charset=UTF-8",
    );

    assert_ok_json(&response);
}

#[test]
fn rejects_missing_presentation_response_content_type() {
    let fixture = presentation_fixture(PresentationOverrides::default());
    let body = response_body(&fixture.state, Some(&fixture.vp_token), None);
    let response = send_request(&format!(
        "POST /presentation-response HTTP/1.1\r\nhost: {HOST}\r\ncontent-length: {}\r\n\r\n{body}",
        body.len()
    ));

    assert_error(
        &response,
        "presentation response content-type must be application/x-www-form-urlencoded",
    );
}

#[test]
fn rejects_json_presentation_response() {
    let fixture = presentation_fixture(PresentationOverrides::default());
    let response = submit(
        &fixture.state,
        Some(&fixture.vp_token),
        None,
        "application/json",
    );

    assert_error(
        &response,
        "presentation response content-type must be application/x-www-form-urlencoded",
    );
}

#[test]
fn rejects_missing_presentation_state() {
    let fixture = presentation_fixture(PresentationOverrides::default());
    let body = format!("vp_token={}", form_encode(&fixture.vp_token));
    let response = post_form(&body, FORM_CONTENT_TYPE);

    assert_error(&response, "state is required");
}

#[test]
fn rejects_invalid_presentation_state() {
    let response = submit("invalid", Some("{}"), None, FORM_CONTENT_TYPE);

    assert_error(&response, "state is invalid or expired");
}

#[test]
fn rejects_expired_presentation_state() {
    let state = expired_state();
    let response = submit(&state, Some("{}"), None, FORM_CONTENT_TYPE);

    assert_error(&response, "state is invalid or expired");
}

#[test]
fn rejects_missing_vp_token() {
    let request = presentation_request();
    let response = submit(&request.state(), None, None, FORM_CONTENT_TYPE);

    assert_error(&response, "vp_token is required");
}

#[test]
fn rejects_malformed_vp_token_json() {
    let request = presentation_request();
    let response = submit(&request.state(), Some("not-json"), None, FORM_CONTENT_TYPE);

    assert_error(&response, "vp_token must be a JSON object");
}

#[test]
fn rejects_vp_token_for_wrong_query() {
    let fixture = presentation_fixture(PresentationOverrides::default());
    let vp_token = json!({"other": [fixture.presentation]}).to_string();
    let response = submit(&fixture.state, Some(&vp_token), None, FORM_CONTENT_TYPE);

    assert_error(
        &response,
        "vp_token does not satisfy the requested credential query",
    );
}

#[test]
fn rejects_vp_token_with_additional_query() {
    let fixture = presentation_fixture(PresentationOverrides::default());
    let vp_token = json!({QUERY_ID: [fixture.presentation], "other": ["value"]}).to_string();
    let response = submit(&fixture.state, Some(&vp_token), None, FORM_CONTENT_TYPE);

    assert_error(
        &response,
        "vp_token must satisfy exactly one credential query",
    );
}

#[test]
fn rejects_vp_token_with_multiple_presentations() {
    let fixture = presentation_fixture(PresentationOverrides::default());
    let vp_token =
        json!({QUERY_ID: [fixture.presentation.clone(), fixture.presentation]}).to_string();
    let response = submit(&fixture.state, Some(&vp_token), None, FORM_CONTENT_TYPE);

    assert_error(
        &response,
        "vp_token credential query must contain exactly one presentation",
    );
}

#[test]
fn rejects_vp_token_without_a_presentation() {
    let request = presentation_request();
    let vp_token = json!({QUERY_ID: []}).to_string();
    let response = submit(&request.state(), Some(&vp_token), None, FORM_CONTENT_TYPE);

    assert_error(
        &response,
        "vp_token credential query must contain exactly one presentation",
    );
}

#[test]
fn rejects_non_string_presentation() {
    let request = presentation_request();
    let vp_token = json!({QUERY_ID: [42]}).to_string();
    let response = submit(&request.state(), Some(&vp_token), None, FORM_CONTENT_TYPE);

    assert_error(&response, "vp_token presentation must be a string");
}

#[test]
fn rejects_malformed_presentation_jwt() {
    let request = presentation_request();
    let vp_token = json!({QUERY_ID: ["invalid"]}).to_string();
    let response = submit(&request.state(), Some(&vp_token), None, FORM_CONTENT_TYPE);

    assert_error(&response, "vp_token presentation must be a jwt");
}

#[test]
fn rejects_presentation_without_holder_jwk() {
    let fixture = presentation_fixture(PresentationOverrides {
        include_jwk: false,
        ..Default::default()
    });
    let response = submit(
        &fixture.state,
        Some(&fixture.vp_token),
        None,
        FORM_CONTENT_TYPE,
    );

    assert_error(&response, "vp_token presentation header must include jwk");
}

#[test]
fn rejects_presentation_with_wrong_algorithm() {
    let request = presentation_request();
    let credential = issued_credential();
    let claims = presentation_claims(&request, &credential, &PresentationOverrides::default());
    let mut header = Header::new(Algorithm::HS512);
    header.jwk = Some(holder_jwk());
    let jwt = encode(&header, &claims, &EncodingKey::from_secret(b"secret")).unwrap();
    let vp_token = json!({QUERY_ID: [jwt]}).to_string();
    let response = submit(&request.state(), Some(&vp_token), None, FORM_CONTENT_TYPE);

    assert_error(&response, "vp_token presentation algorithm must be EdDSA");
}

#[test]
fn rejects_presentation_from_untrusted_holder_key() {
    let request = presentation_request();
    let credential = issued_credential();
    let claims = presentation_claims(&request, &credential, &PresentationOverrides::default());
    let mut header = Header::new(Algorithm::EdDSA);
    header.jwk = Some(issuer_jwk());
    let jwt = encode(
        &header,
        &claims,
        &EncodingKey::from_ed_pem(ISSUER_PRIVATE_KEY).unwrap(),
    )
    .unwrap();
    let vp_token = json!({QUERY_ID: [jwt]}).to_string();
    let response = submit(&request.state(), Some(&vp_token), None, FORM_CONTENT_TYPE);

    assert_error(&response, "vp_token presentation holder key is not trusted");
}

#[test]
fn rejects_presentation_with_invalid_signature() {
    let mut fixture = presentation_fixture(PresentationOverrides::default());
    fixture.presentation.push('x');
    fixture.vp_token = json!({QUERY_ID: [fixture.presentation]}).to_string();
    let response = submit(
        &fixture.state,
        Some(&fixture.vp_token),
        None,
        FORM_CONTENT_TYPE,
    );

    assert_error(&response, "vp_token presentation is invalid or expired");
}

#[test]
fn rejects_presentation_with_wrong_audience() {
    let fixture = presentation_fixture(PresentationOverrides {
        audience: Some("redirect_uri:https://attacker.example/response"),
        ..Default::default()
    });
    let response = submit(
        &fixture.state,
        Some(&fixture.vp_token),
        None,
        FORM_CONTENT_TYPE,
    );

    assert_error(&response, "vp_token presentation is invalid or expired");
}

#[test]
fn rejects_presentation_with_wrong_nonce() {
    let fixture = presentation_fixture(PresentationOverrides {
        nonce: Some("wrong-nonce"),
        ..Default::default()
    });
    let response = submit(
        &fixture.state,
        Some(&fixture.vp_token),
        None,
        FORM_CONTENT_TYPE,
    );

    assert_error(&response, "vp_token presentation nonce is invalid");
}

#[test]
fn rejects_expired_presentation() {
    let fixture = presentation_fixture(PresentationOverrides {
        expired: true,
        ..Default::default()
    });
    let response = submit(
        &fixture.state,
        Some(&fixture.vp_token),
        None,
        FORM_CONTENT_TYPE,
    );

    assert_error(&response, "vp_token presentation is invalid or expired");
}

#[test]
fn rejects_non_verifiable_presentation_type() {
    let fixture = presentation_fixture(PresentationOverrides {
        presentation_type: "OtherPresentation",
        ..Default::default()
    });
    let response = submit(
        &fixture.state,
        Some(&fixture.vp_token),
        None,
        FORM_CONTENT_TYPE,
    );

    assert_error(&response, "vp_token must be a VerifiablePresentation");
}

#[test]
fn rejects_presentation_with_multiple_credentials() {
    let fixture = presentation_fixture(PresentationOverrides {
        duplicate_credential: true,
        ..Default::default()
    });
    let response = submit(
        &fixture.state,
        Some(&fixture.vp_token),
        None,
        FORM_CONTENT_TYPE,
    );

    assert_error(
        &response,
        "vp_token presentation must contain exactly one credential",
    );
}

#[test]
fn rejects_tampered_issuer_credential() {
    let fixture = presentation_fixture(PresentationOverrides {
        tamper_credential: true,
        ..Default::default()
    });
    let response = submit(
        &fixture.state,
        Some(&fixture.vp_token),
        None,
        FORM_CONTENT_TYPE,
    );

    assert_error(&response, "presented credential is invalid or expired");
}

#[test]
fn rejects_presentation_holder_different_from_credential_subject() {
    let fixture = presentation_fixture(PresentationOverrides {
        holder: "did:example:mallory",
        ..Default::default()
    });
    let response = submit(
        &fixture.state,
        Some(&fixture.vp_token),
        None,
        FORM_CONTENT_TYPE,
    );

    assert_error(
        &response,
        "vp_token presentation holder must match the credential subject",
    );
}

#[test]
fn permits_replayed_presentation_response_without_server_side_state() {
    let fixture = presentation_fixture(PresentationOverrides::default());

    assert_ok_json(&submit(
        &fixture.state,
        Some(&fixture.vp_token),
        None,
        FORM_CONTENT_TYPE,
    ));
    assert_ok_json(&submit(
        &fixture.state,
        Some(&fixture.vp_token),
        None,
        FORM_CONTENT_TYPE,
    ));
}

#[test]
fn accepts_supported_wallet_error_response() {
    let request = presentation_request();
    let response = submit(
        &request.state(),
        None,
        Some("access_denied"),
        FORM_CONTENT_TYPE,
    );

    assert_ok_json(&response);
}

#[test]
fn rejects_unsupported_wallet_error_response() {
    let request = presentation_request();
    let response = submit(
        &request.state(),
        None,
        Some("unknown_error"),
        FORM_CONTENT_TYPE,
    );

    assert_error(&response, "wallet error is unsupported");
}

#[test]
fn rejects_wallet_error_response_with_vp_token() {
    let fixture = presentation_fixture(PresentationOverrides::default());
    let response = submit(
        &fixture.state,
        Some(&fixture.vp_token),
        Some("access_denied"),
        FORM_CONTENT_TYPE,
    );

    assert_error(&response, "wallet error response must not include vp_token");
}

const FORM_CONTENT_TYPE: &str = "application/x-www-form-urlencoded";

struct AuthorizationRequestFixture {
    response: String,
    body: Value,
}

impl AuthorizationRequestFixture {
    fn state(&self) -> String {
        self.body["state"].as_str().unwrap().to_owned()
    }

    fn nonce(&self) -> &str {
        self.body["nonce"].as_str().unwrap()
    }
}

struct PresentationFixture {
    state: String,
    presentation: String,
    vp_token: String,
}

#[derive(Clone)]
struct PresentationOverrides<'a> {
    audience: Option<&'a str>,
    nonce: Option<&'a str>,
    holder: &'a str,
    presentation_type: &'a str,
    include_jwk: bool,
    expired: bool,
    duplicate_credential: bool,
    tamper_credential: bool,
}

impl Default for PresentationOverrides<'_> {
    fn default() -> Self {
        Self {
            audience: None,
            nonce: None,
            holder: "did:example:alice",
            presentation_type: "VerifiablePresentation",
            include_jwk: true,
            expired: false,
            duplicate_credential: false,
            tamper_credential: false,
        }
    }
}

fn presentation_fixture(overrides: PresentationOverrides<'_>) -> PresentationFixture {
    let request = presentation_request();
    let mut credential = issued_credential();
    if overrides.tamper_credential {
        credential.push('x');
    }
    let claims = presentation_claims(&request, &credential, &overrides);
    let mut header = Header::new(Algorithm::EdDSA);
    if overrides.include_jwk {
        header.jwk = Some(holder_jwk());
    }
    let presentation = encode(
        &header,
        &claims,
        &EncodingKey::from_ed_pem(HOLDER_PRIVATE_KEY).unwrap(),
    )
    .unwrap();
    let vp_token = json!({QUERY_ID: [presentation]}).to_string();

    PresentationFixture {
        state: request.state(),
        presentation,
        vp_token,
    }
}

fn presentation_claims(
    request: &AuthorizationRequestFixture,
    credential: &str,
    overrides: &PresentationOverrides<'_>,
) -> Value {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let (iat, exp) = if overrides.expired {
        (1, 2)
    } else {
        (now, now + 300)
    };
    let mut credentials = vec![credential.to_owned()];
    if overrides.duplicate_credential {
        credentials.push(credential.to_owned());
    }

    json!({
        "iss": overrides.holder,
        "aud": overrides.audience.unwrap_or(CLIENT_ID),
        "nonce": overrides.nonce.unwrap_or_else(|| request.nonce()),
        "iat": iat,
        "nbf": iat,
        "exp": exp,
        "vp": {
            "type": [overrides.presentation_type],
            "verifiableCredential": credentials
        }
    })
}

fn holder_jwk() -> jsonwebtoken::jwk::Jwk {
    serde_json::from_value(json!({
        "kty": "OKP",
        "crv": "Ed25519",
        "x": kagome::resources::verifiable_credential::HOLDER_PUBLIC_KEY_X
    }))
    .unwrap()
}

fn issuer_jwk() -> jsonwebtoken::jwk::Jwk {
    serde_json::from_value(json!({
        "kty": "OKP",
        "crv": "Ed25519",
        "x": kagome::resources::verifiable_credential::PUBLIC_KEY_X
    }))
    .unwrap()
}

fn presentation_request() -> AuthorizationRequestFixture {
    let response = send_request(&format!(
        "GET /presentation-request HTTP/1.1\r\nhost: {HOST}\r\n\r\n"
    ));
    let body = json_body(&response);
    AuthorizationRequestFixture { response, body }
}

fn issued_credential() -> String {
    let offer_response = send_request(&format!(
        "GET /credential-offer HTTP/1.1\r\nhost: {HOST}\r\n\r\n"
    ));
    let offer = json_body(&offer_response);
    let grant_type = kagome::resources::pre_authorized_code::GRANT_TYPE;
    let code = offer["grants"][grant_type]["pre-authorized_code"]
        .as_str()
        .unwrap();
    let token_body = format!(
        "grant_type={}&pre-authorized_code={}&tx_code=493536",
        form_encode(grant_type),
        form_encode(code)
    );
    let token_response = post("/token", FORM_CONTENT_TYPE, None, &token_body);
    let access_token = json_body(&token_response)["access_token"]
        .as_str()
        .unwrap()
        .to_owned();
    let credential_body = json!({
        "credential_identifier": "UniversityDegreeCredential"
    })
    .to_string();
    let credential_response = post(
        "/credential",
        "application/json",
        Some(&format!("Bearer {access_token}")),
        &credential_body,
    );

    json_body(&credential_response)["credential"]
        .as_str()
        .unwrap()
        .to_owned()
}

fn expired_state() -> String {
    let claims = kagome::resources::presentation_state::PresentationStateClaims {
        nonce: "expired-nonce".to_owned(),
        client_id: CLIENT_ID.to_owned(),
        credential_issuer: "https://issuer.example.com".to_owned(),
        query_id: QUERY_ID.to_owned(),
        iat: 1,
        exp: 2,
    };
    let mut plaintext = Vec::new();
    ciborium::into_writer(&claims, &mut plaintext).unwrap();
    kagome::resources::crypto::encode_cose_encrypt0(
        &plaintext,
        kagome::resources::presentation_state::SECRET,
        kagome::resources::presentation_state::COSE_EXTERNAL_AAD,
    )
    .unwrap()
}

fn submit(state: &str, vp_token: Option<&str>, error: Option<&str>, content_type: &str) -> String {
    post_form(&response_body(state, vp_token, error), content_type)
}

fn response_body(state: &str, vp_token: Option<&str>, error: Option<&str>) -> String {
    let mut parameters = vec![format!("state={}", form_encode(state))];
    if let Some(vp_token) = vp_token {
        parameters.push(format!("vp_token={}", form_encode(vp_token)));
    }
    if let Some(error) = error {
        parameters.push(format!("error={}", form_encode(error)));
    }
    parameters.join("&")
}

fn post_form(body: &str, content_type: &str) -> String {
    post("/presentation-response", content_type, None, body)
}

fn post(path: &str, content_type: &str, authorization: Option<&str>, body: &str) -> String {
    let authorization = authorization
        .map(|value| format!("authorization: {value}\r\n"))
        .unwrap_or_default();
    send_request(&format!(
        "POST {path} HTTP/1.1\r\nhost: {HOST}\r\ncontent-type: {content_type}\r\n{authorization}content-length: {}\r\n\r\n{body}",
        body.len()
    ))
}

fn form_encode(value: &str) -> String {
    value
        .bytes()
        .map(|byte| match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                (byte as char).to_string()
            }
            _ => format!("%{byte:02X}"),
        })
        .collect()
}

fn json_body(response: &str) -> Value {
    serde_json::from_str(response.split_once("\r\n\r\n").unwrap().1).unwrap()
}

fn assert_ok_json(response: &str) {
    assert!(response.starts_with("HTTP/1.1 200 OK\r\n"), "{response}");
    assert!(response.contains("content-type: application/json\r\n"));
    assert!(response.contains("cache-control: no-store\r\n"));
}

fn assert_error(response: &str, description: &str) {
    assert!(
        response.starts_with("HTTP/1.1 400 Bad Request\r\n"),
        "{response}"
    );
    let body = json_body(response);
    assert_eq!(body["error"], "invalid_request");
    assert_eq!(body["error_description"], description);
}
