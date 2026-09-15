use std::time::{SystemTime, UNIX_EPOCH};

use jsonwebtoken::{Algorithm, EncodingKey, Header, Validation, encode};
use serde_json::{Value, json};

use super::super::server::send_request;

const HOST: &str = "issuer.example.com";
const CONFIGURATION_ID: &str = "UniversityDegreeCredential";
const GRANT_TYPE: &str = "urn:ietf:params:oauth:grant-type:pre-authorized_code";
const RESPONSE_TYPE: &str = "urn:ietf:params:oauth:response-type:pre-authorized_code";
const PROOF_X: &str = "2OOMuJdc5XAbumGYaUtM3ngfBVFhqjeqb0fJ_N3Y7UI";
const PROOF_Y: &str = "Yp8TpPyvA3t9jF01vn7Z6SXYjpKkZOrO1Gg7CkxnMF8";
const PROOF_PRIVATE_KEY: &[u8] = b"-----BEGIN PRIVATE KEY-----\nMIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg9SWS4Y9IULSULCea\nXPaFWOCkkYV/k1RW1NCRhdqo8NGhRANCAATY44y4l1zlcBu6YZhpS0zeeB8FUWGq\nN6pvR8n83djtQmKfE6T8rwN7fYxdNb5+2ekl2I6SpGTqztRoOwpMZzBf\n-----END PRIVATE KEY-----\n";
const OTHER_PRIVATE_KEY: &[u8] = b"-----BEGIN PRIVATE KEY-----\nMIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgVW2Jp8GefPD2+UXt\nbha/i609CuG2sBUhr+ReRUGWptKhRANCAAR9nFOOpv0YEl1qdoEHe49769dxqWQt\nWvq6iQSd17Nm4ihLYZLKTGl3qy/RD0wJx46+TzAkr+D+BtB2Ru1D/Bz7\n-----END PRIVATE KEY-----\n";
const WALLET_BOUND_CLIENT_ID: &str = "wallet_bound_client";
const WALLET_BOUND_REDIRECT_URI: &str = "https://wallet-bound.example.com/callback";

// Branch matrix:
// - discovery endpoint: issuer metadata | authorization-server metadata | JWKS
// - JWKS route: canonical | OpenID compatibility alias; response: success | error,
//   each with Access-Control-Allow-Origin
// - endpoint method: supported | credential OPTIONS preflight | unsupported
// - Host: valid | missing | invalid
// - token representation: form | JSON
// - credential access-token artifact: opaque COSE_Encrypt0
// - pre-authorized_code: valid | missing | invalid | expired
// - authorization response delivery: redirect | QR-code HTML with matching deep link
// - tx_code: valid | omitted | invalid
// - successful token authorization_details: credential configuration | format | type
// - redemption count: first | repeated (equivalent because this stateless profile
//   deliberately permits reuse until expiration)
// - bearer token: valid | missing | malformed | invalid | expired
// - credential request media type: application/json (case-insensitive, parameters
//   allowed) | missing | unsupported
// - credential_identifier: supported | missing | legacy credential_configuration_id | unknown
// - credential proof: absent (access-token subject fallback) | valid JWT proof with configured
//   issuer audience | malformed | invalid signature | Host-derived or unrelated audience |
//   wallet-bound signature
//   matching/mismatching the ID-token public key. A wallet-binding client also
//   rejects a missing code key or proof. A valid proof binds the issued subject
//   and cnf.jwk to its wallet DID and public key.
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
    assert_eq!(
        body["credential_configurations_supported"][CONFIGURATION_ID]["proof_types_supported"]["jwt"]
            ["proof_signing_alg_values_supported"],
        json!([
            "ES256", "ES384", "RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "EdDSA"
        ])
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
fn returns_centralized_signing_jwks() {
    for path in ["/jwks", "/openid/jwks"] {
        let response = get(path);
        let body = json_body(&response);
        let keys = body["keys"].as_array().unwrap();

        assert_ok_json(&response);
        assert!(response.contains("access-control-allow-origin: *\r\n"));
        assert_eq!(keys.len(), 3);
        for artifact in [
            kagome::resources::crypto::SigningArtifact::Credential,
            kagome::resources::crypto::SigningArtifact::IdToken,
            kagome::resources::crypto::SigningArtifact::RequestObject,
        ] {
            assert!(
                keys.iter()
                    .any(|key| key["kid"] == artifact.key_id() && key == &artifact.public_jwk())
            );
        }
    }
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
        &kagome::resources::crypto::SigningArtifact::Credential
            .decoding_key()
            .unwrap(),
        &validation,
    )
    .unwrap()
    .claims;

    assert_eq!(claims["sub"], "username");
}

#[test]
fn renders_pre_authorized_credential_offer_as_qr_code_with_deep_link() {
    let response = authorize_preauthorized_code_for_client(
        "",
        "qr_client",
        "https://qr.example.com/callback",
        None,
        "username=username&password=password",
    );
    let deep_link = super::common::qr_page_deep_link(&response);
    let encoded_offer = deep_link
        .split_once('?')
        .and_then(|(_, query)| {
            query
                .split('&')
                .find_map(|value| value.strip_prefix("credential_offer="))
        })
        .expect("QR deep link should contain a credential offer");
    let offer: Value = serde_json::from_str(&decode_form_value(encoded_offer)).unwrap();

    assert!(deep_link.starts_with("https://qr.example.com/callback?credential_offer="));
    assert_eq!(offer["credential_issuer"], "http://localhost:4000");
    assert!(offer["grants"][GRANT_TYPE]["pre-authorized_code"].is_string());
}

#[test]
fn returns_not_implemented_for_unauthenticated_preauthorized_code_request() {
    let response = send_request(&format!(
        "GET /authorize?response_type={RESPONSE_TYPE}&client_id=client_id&redirect_uri=https%3A%2F%2Fclient.example.com%2Fcallback HTTP/1.1\r\nhost: example.com\r\n\r\n"
    ));

    assert!(response.starts_with("HTTP/1.1 501 Not Implemented\r\n"));
    assert!(response.contains("content-type: text/plain\r\n"));
    assert!(response.ends_with("\r\n\r\nnot implemented"));
    assert!(!response.contains("<form"));
}

#[test]
fn authenticates_public_username_host_client_for_preauthorized_code_request() {
    let response = send_request(&format!(
        "GET /authorize?response_type={RESPONSE_TYPE}&client_id=username%40example.com&redirect_uri=https%3A%2F%2Fclient.example.com%2Fcallback HTTP/1.1\r\nhost: example.com\r\n\r\n"
    ));

    assert!(response.starts_with("HTTP/1.1 302 Found\r\n"));
    assert!(response.contains("location: https://client.example.com/callback?credential_offer="));
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
        &kagome::resources::crypto::SigningArtifact::Credential
            .decoding_key()
            .unwrap(),
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
fn issues_credential_bound_to_wallet_proof_subject_and_key() {
    let access_token = access_token();
    let did = proof_did_key();
    let proof = credential_proof(&did, "http://localhost:4000");
    let response = post_json(
        "/credential",
        Some(&format!("Bearer {access_token}")),
        &credential_body_with_proof(CONFIGURATION_ID, &proof),
    );
    let body = json_body(&response);
    let claims = credential_claims(body["credential"].as_str().unwrap());

    assert_ok_json(&response);
    assert_eq!(claims["sub"], did);
    assert_eq!(claims["credentialSubject"][CONFIGURATION_ID]["id"], did);
    assert_eq!(claims["vc"]["credentialSubject"]["id"], did);
    assert_eq!(claims["cnf"]["jwk"], proof_jwk());
}

#[test]
fn verifies_credential_proof_signature_against_code_id_token_public_key() {
    let access_token = wallet_bound_access_token(&id_token(PROOF_PRIVATE_KEY, proof_jwk()));
    let did = proof_did_key();
    let proof = credential_proof(&did, "http://localhost:4000");
    let response = post_json(
        "/credential",
        Some(&format!("Bearer {access_token}")),
        &credential_body_with_proof(CONFIGURATION_ID, &proof),
    );

    assert_ok_json(&response);
}

#[test]
fn rejects_credential_proof_signature_not_matching_code_id_token_public_key() {
    let access_token = wallet_bound_access_token(&id_token(OTHER_PRIVATE_KEY, other_jwk()));
    let did = proof_did_key();
    let proof = credential_proof(&did, "http://localhost:4000");
    let response = post_json(
        "/credential",
        Some(&format!("Bearer {access_token}")),
        &credential_body_with_proof(CONFIGURATION_ID, &proof),
    );

    assert_credential_error(
        &response,
        "invalid_credential_request",
        "proof jwt signature does not match id_token public key",
    );
}

#[test]
fn requires_credential_proof_for_wallet_bound_client() {
    let access_token = wallet_bound_access_token(&id_token(PROOF_PRIVATE_KEY, proof_jwk()));
    let response = credential_request(Some(&access_token), "application/json", CONFIGURATION_ID);

    assert_credential_error(
        &response,
        "invalid_credential_request",
        "proof is required for wallet binding",
    );
}

#[test]
fn rejects_wallet_bound_authorize_request_without_code_id_token_key() {
    let response = authorize_preauthorized_code_for_client(
        "",
        WALLET_BOUND_CLIENT_ID,
        WALLET_BOUND_REDIRECT_URI,
        None,
        "username=username&password=password",
    );

    assert!(response.starts_with("HTTP/1.1 400 Bad Request\r\n"));
    assert!(response.contains("wallet binding requires a code containing an id_token public key"));
}

#[test]
fn rejects_credential_proof_with_invalid_signature() {
    let access_token = access_token();
    let did = proof_did_key();
    let mut proof = credential_proof(&did, "http://localhost:4000");
    proof.push('x');
    let response = post_json(
        "/credential",
        Some(&format!("Bearer {access_token}")),
        &credential_body_with_proof(CONFIGURATION_ID, &proof),
    );

    assert_credential_error(
        &response,
        "invalid_credential_request",
        "proof jwt signature is invalid",
    );
}

#[test]
fn rejects_credential_proof_with_wrong_audience() {
    let access_token = access_token();
    let did = proof_did_key();
    let proof = credential_proof(&did, "https://attacker.example.com");
    let response = post_json(
        "/credential",
        Some(&format!("Bearer {access_token}")),
        &credential_body_with_proof(CONFIGURATION_ID, &proof),
    );

    assert_credential_error(
        &response,
        "invalid_credential_request",
        "proof jwt audience is invalid",
    );
}

#[test]
fn rejects_credential_proof_with_host_derived_audience() {
    let access_token = access_token();
    let did = proof_did_key();
    let proof = credential_proof(&did, "https://issuer.example.com");
    let response = post_json(
        "/credential",
        Some(&format!("Bearer {access_token}")),
        &credential_body_with_proof(CONFIGURATION_ID, &proof),
    );

    assert_credential_error(
        &response,
        "invalid_credential_request",
        "proof jwt audience is invalid",
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
fn rejects_expired_cose_bearer_token() {
    let response = credential_request(
        Some(&expired_credential_access_token()),
        "application/json",
        CONFIGURATION_ID,
    );

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
        "/openid/jwks",
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

#[test]
fn returns_jwks_errors_with_access_control_allow_origin() {
    for path in ["/jwks", "/openid/jwks"] {
        let response = send_request(&format!("GET {path} HTTP/1.1\r\n\r\n"));

        assert_oauth_error(&response, "invalid_request", "host header is required");
        assert!(response.contains("access-control-allow-origin: *\r\n"));
    }
}

fn credential_offer() -> String {
    get("/credential-offer")
}

fn authorize_preauthorized_code(prefix: &str, body: &str) -> String {
    authorize_preauthorized_code_for_client(
        prefix,
        "client_id",
        "https://client.example.com/callback",
        None,
        body,
    )
}

fn authorize_preauthorized_code_for_client(
    prefix: &str,
    client_id: &str,
    redirect_uri: &str,
    code: Option<&str>,
    body: &str,
) -> String {
    let code = code.map(|code| format!("&code={code}")).unwrap_or_default();
    send_request(&format!(
        "POST /authorize?response_type={prefix}{RESPONSE_TYPE}&client_id={client_id}&redirect_uri={redirect_uri}{code} HTTP/1.1\r\nhost: example.com\r\ncontent-type: application/x-www-form-urlencoded\r\ncontent-length: {}\r\n\r\n{body}",
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
        id_token_public_jwk: None,
        require_wallet_binding: false,
        iat: 1,
        exp: 2,
    };
    let mut bytes = Vec::new();
    ciborium::into_writer(&claims, &mut bytes).unwrap();
    kagome::resources::crypto::encode_cose_encrypt0(
        &bytes,
        kagome::resources::crypto::EncryptedArtifact::PreAuthorizedCode,
    )
    .unwrap()
}

fn expired_credential_access_token() -> String {
    let claims = kagome::resources::credential_access_token::CredentialAccessTokenClaims {
        credential_configuration_id: CONFIGURATION_ID.to_owned(),
        subject: "did:example:alice".to_owned(),
        id_token_public_jwk: None,
        require_wallet_binding: false,
        iat: 1,
        exp: 2,
    };
    let mut bytes = Vec::new();
    ciborium::into_writer(&claims, &mut bytes).unwrap();
    kagome::resources::crypto::encode_cose_encrypt0(
        &bytes,
        kagome::resources::crypto::EncryptedArtifact::CredentialAccessToken,
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

fn wallet_bound_access_token(id_token: &str) -> String {
    let authorization_code = authorization_code_with_id_token(id_token);
    let response = authorize_preauthorized_code_for_client(
        "",
        WALLET_BOUND_CLIENT_ID,
        WALLET_BOUND_REDIRECT_URI,
        Some(&authorization_code),
        "username=username&password=password",
    );
    let code = redirected_credential_offer(&response)["grants"][GRANT_TYPE]["pre-authorized_code"]
        .as_str()
        .unwrap()
        .to_owned();
    let response = token_request(&format!(
        "grant_type={GRANT_TYPE}&pre-authorized_code={code}"
    ));
    json_body(&response)["access_token"]
        .as_str()
        .unwrap()
        .to_owned()
}

struct AuthorizationCodeWithIdToken {
    id_token: String,
    authorization_code: Option<kagome::resources::authorization_code::AuthorizationCode>,
}

impl kagome::resources::authorization_code::Generate for AuthorizationCodeWithIdToken {
    fn previous_authorization_code(&self) -> Option<&str> {
        None
    }

    fn client_id(&self) -> Option<&str> {
        Some(WALLET_BOUND_CLIENT_ID)
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

fn authorization_code_with_id_token(id_token: &str) -> String {
    kagome::resources::authorization_code::generate(AuthorizationCodeWithIdToken {
        id_token: id_token.to_owned(),
        authorization_code: None,
    })
    .unwrap()
    .authorization_code
    .unwrap()
    .value
}

fn id_token(private_key: &[u8], jwk: Value) -> String {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let mut header = Header::new(Algorithm::ES256);
    header.jwk = Some(serde_json::from_value(jwk).unwrap());
    encode(
        &header,
        &json!({"iat": now, "exp": now + 300}),
        &EncodingKey::from_ec_pem(private_key).unwrap(),
    )
    .unwrap()
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

fn credential_body_with_proof(credential_identifier: &str, proof: &str) -> String {
    json!({
        "credential_identifier": credential_identifier,
        "format": "jwt_vc",
        "proof": {
            "proof_type": "jwt",
            "jwt": proof
        }
    })
    .to_string()
}

fn credential_proof(subject: &str, audience: &str) -> String {
    let claims = json!({
        "iss": subject,
        "sub": subject,
        "aud": audience,
        "iat": SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs()
    });
    let mut header = Header::new(Algorithm::ES256);
    header.kid = Some(subject.to_owned());
    encode(
        &header,
        &claims,
        &EncodingKey::from_ec_pem(PROOF_PRIVATE_KEY).unwrap(),
    )
    .unwrap()
}

fn credential_claims(credential: &str) -> Value {
    let mut validation = Validation::new(Algorithm::EdDSA);
    validation.validate_aud = false;
    jsonwebtoken::decode::<Value>(
        credential,
        &kagome::resources::crypto::SigningArtifact::Credential
            .decoding_key()
            .unwrap(),
        &validation,
    )
    .unwrap()
    .claims
}

fn proof_jwk() -> Value {
    json!({"kty": "EC", "crv": "P-256", "x": PROOF_X, "y": PROOF_Y})
}

fn other_jwk() -> Value {
    kagome::resources::crypto::SigningArtifact::RequestObject.public_jwk()
}

fn proof_did_key() -> String {
    let canonical = format!(r#"{{"crv":"P-256","kty":"EC","x":"{PROOF_X}","y":"{PROOF_Y}"}}"#);
    let mut multicodec_key = vec![0xd1, 0xd6, 0x03];
    multicodec_key.extend(canonical.as_bytes());
    format!("did:key:z{}", base58btc(&multicodec_key))
}

fn base58btc(value: &[u8]) -> String {
    let alphabet = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    let mut digits = vec![0_u8];
    for byte in value {
        let mut carry = u32::from(*byte);
        for digit in &mut digits {
            carry += u32::from(*digit) << 8;
            *digit = (carry % 58) as u8;
            carry /= 58;
        }
        while carry > 0 {
            digits.push((carry % 58) as u8);
            carry /= 58;
        }
    }
    let leading_zeroes = value.iter().take_while(|byte| **byte == 0).count();
    let mut encoded = String::from_utf8(vec![b'1'; leading_zeroes]).unwrap();
    encoded.extend(
        digits
            .iter()
            .rev()
            .map(|digit| alphabet[usize::from(*digit)] as char),
    );
    encoded
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
    assert!(body["access_token"].as_str().is_some_and(|token| {
        !token.is_empty()
            && !token.contains('.')
            && base64::Engine::decode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, token)
                .is_ok()
    }));
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
