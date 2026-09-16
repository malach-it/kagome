use std::time::{SystemTime, UNIX_EPOCH};

use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation, decode, encode};
use serde_json::{Value, json};

use super::super::server::send_request;

const HOST: &str = "issuer.example.com";
const CLIENT_ID: &str = "redirect_uri:http://localhost:4000/presentation-response";
const PRESENTATION_REDIRECT_URI: &str = "http://localhost:4000/presentation-response";
const AUTHORIZE_CLIENT_ID: &str = "configured_client";
const AUTHORIZE_REDIRECT_URI: &str = "https://configured.example.com/callback";
const PRESENTATION_DEFINITION_ID: &str = "credential_presentation";
const INPUT_DESCRIPTOR_ID: &str = "credential";
const HOLDER_PRIVATE_KEY: &[u8] = b"-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEINJfaccWsYDZbi2f7pKdaHSEmgf8842Rvoli2GJ94YSk\n-----END PRIVATE KEY-----\n";
const EC_HOLDER_PRIVATE_KEY: &[u8] = b"-----BEGIN PRIVATE KEY-----\nMIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgVW2Jp8GefPD2+UXt\nbha/i609CuG2sBUhr+ReRUGWptKhRANCAAR9nFOOpv0YEl1qdoEHe49769dxqWQt\nWvq6iQSd17Nm4ihLYZLKTGl3qy/RD0wJx46+TzAkr+D+BtB2Ru1D/Bz7\n-----END PRIVATE KEY-----\n";
const ISSUER_PRIVATE_KEY: &[u8] = b"-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEIDt2IW+OSTJfZcs+QLnyHa+IoZthF8Pbf7sBWYsElCKk\n-----END PRIVATE KEY-----\n";

// Branch matrix:
// - authorize response type: vp_token (presentation flow) | another value
//   (OAuth flow, covered by the OAuth authorize matrix) | vp_token combined with
//   another response type (invalid)
// - endpoint method: supported | unsupported
// - common authorize validation: valid client and redirect URI | missing/invalid;
//   optional authorization code and metadata policy absent/valid | invalid
// - client authentication: local presentation proceeds directly | unauthenticated
//   federated client redirects through its upstream server
// - PKCE: absent | valid S256 challenge carried in presentation state | unsupported method
// - wallet binding policy: disabled | enabled with a code ID-token key | enabled
//   without a code ID-token key (invalid)
// - verifier: configured issuer rather than request Host
// - presentation definition scope: exactly one configured identifier selected |
//   missing, unknown, or multiple configured identifiers (invalid). Extra
//   unrelated scope values are intentionally ignored.
// - request Host: configured-issuer host | different host. Both are intentionally
//   equivalent because presentation state uses the configured credential issuer.
// - generated transaction values: fresh nonce/state | generation failure (not
//   reachable with the process RNG and embedded encryption key)
// - request object: signed ES256 JWT redirect with nonce and state omitted from
//   the outer deep link and redirect URI duplicated in the outer query | signing
//   failure (not reachable with the embedded signing key)
// - authorization request delivery: redirect | QR-code HTML with matching deep link
// - response media type: form (case-insensitive, parameters allowed) | missing |
//   unsupported
// - state source: callback query | form body. These sources are intentionally
//   equivalent after parsing and exercise the same validation path.
// - state value: valid | missing | invalid | expired | replayed
// - response kind: vp_token | supported wallet error | unsupported wallet error |
//   neither | both (invalid)
// - response destination: trusted redirect URI with code/error and client state |
//   local HTML error when presentation state or redirect URI cannot be trusted
// - presentation submission representation: definition-bound standard map |
//   credential-bound Boruta wallet map with any non-empty nested identifier.
//   Both are equivalent after validation.
// - presentation submission: valid | missing | malformed | wrong definition |
//   missing id | wrong descriptor | wrong mapping | zero/multiple descriptors.
//   Outer/nested descriptor ID mismatches are intentionally equivalent, as are
//   VP/VC format and path mismatches: each follows the same mapping-error path.
// - VP Token shape: one presentation JWT | malformed
// - presentation JWT algorithm: EdDSA | ECDSA | RSA PKCS#1 | RSA-PSS |
//   symmetric HMAC (invalid). EdDSA and ES256 exercise successful end-to-end
//   verification; all asymmetric variants share the library's algorithm-family
//   path and exact header-algorithm verification.
// - presentation JWT key source: embedded JWK | issuer-bound did:key kid |
//   neither | invalid or unrelated kid. Embedded JWK takes precedence over kid.
// - presentation JWT: valid asymmetric signature | malformed | invalid signature |
//   expired. Its signing key is intentionally independent of credential cnf.
// - code ID-token public key: absent | matching VP signature | mismatching VP
//   signature. Configured wallet binding makes absence invalid.
// - presentation claims profile: standard nested VP with audience and time claims |
//   Boruta top-level VP with issuer/subject, nonce, and definition ID bindings.
// - audience and time claims: absent | present and valid | present and invalid.
//   Missing values intentionally rely on the short-lived encrypted state binding.
// - holder binding: matching audience/nonce/subject/key | mismatch for each
// - presentation contents: VerifiablePresentation with one credential | wrong type |
//   multiple credentials
// - credential: trusted issuer JWT satisfying the selected definition | valid
//   credential that does not satisfy it | malformed/tampered
// A trusted credential with the wrong issuer, type, claims, or holder key is
// unreachable through Kagome's fixed issuer endpoint; tampering is covered as an
// invalid issuer signature.

#[test]
fn returns_presentation_exchange_direct_post_presentation_request() {
    let request = presentation_request();

    assert!(request.response.starts_with(&format!(
        "HTTP/1.1 302 Found\r\nlocation: {AUTHORIZE_REDIRECT_URI}?client_id={}&response_type=vp_token&redirect_uri={}%3Fstate%3D",
        form_encode(CLIENT_ID),
        form_encode(PRESENTATION_REDIRECT_URI)
    )));
    assert!(request.response.contains("cache-control: no-store\r\n"));
    assert_eq!(request.body["client_id"], CLIENT_ID);
    assert_eq!(
        redirect_query_parameter(&request.response, "client_id"),
        request.body["client_id"]
    );
    assert_eq!(
        redirect_query_parameter(&request.response, "response_type"),
        request.body["response_type"]
    );
    assert!(redirect_query_parameter_optional(&request.response, "nonce").is_none());
    assert!(redirect_query_parameter_optional(&request.response, "state").is_none());
    assert_eq!(
        redirect_query_parameter(&request.response, "redirect_uri"),
        request.body["redirect_uri"]
    );
    let presentation_redirect_uri = request.body["redirect_uri"].as_str().unwrap();
    assert!(presentation_redirect_uri.starts_with(&format!("{PRESENTATION_REDIRECT_URI}?state=")));
    assert_eq!(
        percent_decode(presentation_redirect_uri.split_once("?state=").unwrap().1),
        request.body["state"]
    );
    assert!(request.body.get("response_uri").is_none());
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
    assert!(request.body.get("dcql_query").is_none());
    assert_eq!(
        request.body["presentation_definition"]["id"],
        PRESENTATION_DEFINITION_ID
    );
    assert_eq!(
        request.body["presentation_definition"]["input_descriptors"][0]["id"],
        INPUT_DESCRIPTOR_ID
    );
    assert_eq!(
        request.body["presentation_definition"]["input_descriptors"][0]["format"]["jwt_vc"]["alg"]
            [0],
        "EdDSA"
    );
    assert_eq!(
        request.body["presentation_definition"]["input_descriptors"][0]["constraints"]["fields"][0]
            ["filter"]["contains"]["const"],
        "UniversityDegreeCredential"
    );
    assert_eq!(
        request.body["client_metadata"]["vp_formats_supported"]["jwt_vp"]["alg_values"],
        json!([
            "ES256", "ES384", "RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "EdDSA"
        ])
    );

    let header = jsonwebtoken::decode_header(&request.signed_request).unwrap();
    assert_eq!(header.alg, Algorithm::ES256);
    assert_eq!(
        header.kid.as_deref(),
        Some(kagome::resources::crypto::SigningArtifact::RequestObject.key_id())
    );
}

#[test]
fn requires_federated_authentication_before_presentation_request() {
    let response = send_request(
        "GET /authorize?response_type=vp_token&client_id=federated_client&redirect_uri=https%3A%2F%2Fclient.example.com%2Fcallback&scope=credential_presentation HTTP/1.1\r\nhost: issuer.example.com\r\n\r\n",
    );

    assert!(response.starts_with("HTTP/1.1 302 Found\r\n"));
    assert!(response.contains("location: https://identity.example.com/authorize?"));
    assert!(!response.contains("response_type=vp_token"));
}

#[test]
fn selects_presentation_definition_from_scope() {
    let path = format!(
        "/authorize?response_type=vp_token&client_id={AUTHORIZE_CLIENT_ID}&redirect_uri={}&scope=openid%20employee_presentation",
        form_encode(AUTHORIZE_REDIRECT_URI)
    );
    let request = presentation_request_for_path(&path);

    assert_eq!(
        request.body["presentation_definition"]["id"],
        "employee_presentation"
    );
    assert_eq!(
        request.body["presentation_definition"]["input_descriptors"][0]["id"],
        "employee_credential"
    );
    assert_eq!(
        request.body["presentation_definition"]["input_descriptors"][0]["constraints"]["fields"][0]
            ["filter"]["contains"]["const"],
        "EmployeeCredential"
    );
}

#[test]
fn requires_scope_to_select_exactly_one_presentation_definition() {
    for scope in ["", "&scope=credential_presentation%20employee_presentation"] {
        let response = send_request(&format!(
            "GET /authorize?response_type=vp_token&client_id={AUTHORIZE_CLIENT_ID}&redirect_uri={}{} HTTP/1.1\r\nhost: {HOST}\r\n\r\n",
            form_encode(AUTHORIZE_REDIRECT_URI),
            scope
        ));

        assert_authorize_error(
            &response,
            "scope must select exactly one configured presentation definition",
        );
    }
}

#[test]
fn rejects_unauthorized_presentation_scope() {
    let response = send_request(&format!(
        "GET /authorize?response_type=vp_token&client_id={AUTHORIZE_CLIENT_ID}&redirect_uri={}&scope=unknown HTTP/1.1\r\nhost: {HOST}\r\n\r\n",
        form_encode(AUTHORIZE_REDIRECT_URI)
    ));

    assert_authorize_error(&response, "scope is not authorized for client: unknown");
}

#[test]
fn rejects_credential_that_does_not_satisfy_selected_presentation_definition() {
    let path = format!(
        "/authorize?response_type=vp_token&client_id={AUTHORIZE_CLIENT_ID}&redirect_uri={}&state=client-state&scope=employee_presentation",
        form_encode(AUTHORIZE_REDIRECT_URI)
    );
    let request = presentation_request_for_path(&path);
    let credential = issued_credential();
    let claims = presentation_claims(&request, &credential, &PresentationOverrides::default());
    let mut header = Header::new(Algorithm::EdDSA);
    header.jwk = Some(holder_jwk());
    let presentation = encode(
        &header,
        &claims,
        &EncodingKey::from_ed_pem(HOLDER_PRIVATE_KEY).unwrap(),
    )
    .unwrap();
    let submission = presentation_submission(
        "employee_presentation",
        "employee_credential",
        "jwt_vp",
        "$",
        1,
    );
    let response = submit_with_submission(
        &request.state(),
        Some(&presentation),
        Some(&submission),
        None,
        FORM_CONTENT_TYPE,
    );

    assert_error(
        &response,
        "presented credential claims do not satisfy the query",
    );
}

#[test]
fn renders_presentation_request_as_qr_code_with_deep_link() {
    let response = send_request(&format!(
        "GET /authorize?response_type=vp_token&client_id=qr_client&redirect_uri={}&scope=credential_presentation HTTP/1.1\r\nhost: {HOST}\r\n\r\n",
        form_encode("https://qr.example.com/callback")
    ));
    let deep_link = super::common::qr_page_deep_link(&response);

    assert!(deep_link.starts_with("https://qr.example.com/callback?client_id="));
    assert!(deep_link.contains("&response_type=vp_token"));
    assert!(!deep_link.contains("&nonce="));
    assert!(!deep_link.contains("&state="));
    assert!(deep_link.contains("&redirect_uri="));
    assert!(deep_link.contains("&request="));
}

#[test]
fn generates_fresh_nonce_and_state_for_each_request() {
    let first = presentation_request();
    let second = presentation_request();

    assert_ne!(first.body["nonce"], second.body["nonce"]);
    assert_ne!(first.body["state"], second.body["state"]);
    assert_ne!(first.signed_request, second.signed_request);
}

#[test]
fn accepts_presentation_request_with_a_different_request_host() {
    let path = presentation_request_path();
    let response = send_request(&format!(
        "GET {path} HTTP/1.1\r\nhost: attacker.example\r\n\r\n"
    ));

    assert!(response.starts_with("HTTP/1.1 302 Found\r\n"));
}

#[test]
fn carries_s256_pkce_challenge_in_presentation_state() {
    let request = presentation_request_with_suffix(&format!(
        "&code_challenge={}&code_challenge_method=S256",
        "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
    ));
    let plaintext = kagome::resources::crypto::decode_cose_encrypt0(
        &request.state(),
        kagome::resources::crypto::EncryptedArtifact::PresentationState,
        kagome::resources::crypto::CoseEncrypt0Errors {
            invalid_cose: "invalid",
            missing_ciphertext: "invalid",
            missing_nonce: "invalid",
            decryption_failed: "invalid",
        },
    )
    .unwrap();
    let claims: kagome::resources::presentation_state::PresentationStateClaims =
        ciborium::from_reader(plaintext.as_slice()).unwrap();

    assert_eq!(
        claims.code_challenge,
        Some(kagome::resources::pkce::CodeChallenge {
            value: "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM".to_owned(),
        })
    );
}

#[test]
fn applies_s256_only_pkce_validation_to_presentation_request() {
    let path = format!(
        "{}&code_challenge={}&code_challenge_method=plain",
        presentation_request_path(),
        "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
    );
    let response = send_request(&format!("GET {path} HTTP/1.1\r\nhost: {HOST}\r\n\r\n"));

    assert_authorize_error(&response, "code_challenge_method must be S256");
}

#[test]
fn applies_common_client_validation_to_presentation_request() {
    let missing_client = send_request(&format!(
        "GET /authorize?response_type=vp_token&redirect_uri={} HTTP/1.1\r\nhost: {HOST}\r\n\r\n",
        form_encode(AUTHORIZE_REDIRECT_URI)
    ));
    let invalid_redirect = send_request(&format!(
        "GET /authorize?response_type=vp_token&client_id={AUTHORIZE_CLIENT_ID}&redirect_uri={} HTTP/1.1\r\nhost: {HOST}\r\n\r\n",
        form_encode("https://attacker.example/callback")
    ));

    assert_authorize_error(&missing_client, "client_id is required");
    assert_authorize_error(&invalid_redirect, "redirect_uri is invalid");
}

#[test]
fn applies_common_response_type_validation_to_presentation_request() {
    let response = send_request(&format!(
        "GET {}%20code&client_id={AUTHORIZE_CLIENT_ID}&redirect_uri={} HTTP/1.1\r\nhost: {HOST}\r\n\r\n",
        "/authorize?response_type=vp_token",
        form_encode(AUTHORIZE_REDIRECT_URI)
    ));

    assert_authorize_error(&response, "invalid final response type");
}

#[test]
fn applies_common_authorization_code_validation_to_presentation_request() {
    let response = send_request(&format!(
        "GET {}&code=invalid HTTP/1.1\r\nhost: {HOST}\r\n\r\n",
        presentation_request_path()
    ));

    assert_authorize_error(&response, "authorization_code must be a cose_encrypt0");
}

#[test]
fn applies_common_metadata_policy_validation_to_presentation_request() {
    let response = send_request(&format!(
        "GET {}&metadata_policy={} HTTP/1.1\r\nhost: {HOST}\r\n\r\n",
        presentation_request_path(),
        form_encode("not-json")
    ));

    assert_authorize_error(&response, "metadata_policy must be a json string or object");
}

#[test]
fn returns_not_found_for_unsupported_presentation_endpoint_methods() {
    let old_request_endpoint = send_request(&format!(
        "GET /presentation-request HTTP/1.1\r\nhost: {HOST}\r\n\r\n"
    ));
    let unsupported_authorize_method = send_request(&format!(
        "POST {} HTTP/1.1\r\nhost: {HOST}\r\n\r\n",
        presentation_request_path()
    ));
    let response = send_request(&format!(
        "GET /presentation-response HTTP/1.1\r\nhost: {HOST}\r\n\r\n"
    ));

    assert!(old_request_endpoint.starts_with("HTTP/1.1 404 Not Found\r\n"));
    assert!(unsupported_authorize_method.starts_with("HTTP/1.1 404 Not Found\r\n"));
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

    assert_presentation_success(&response);
}

#[test]
fn accepts_presentation_state_from_callback_query() {
    let fixture = presentation_fixture(PresentationOverrides::default());
    let submission = valid_presentation_submission();
    let body = response_body_without_state(Some(&fixture.vp_token), Some(&submission), None);
    let response = post(
        &format!(
            "/presentation-response?state={}",
            form_encode(&fixture.state)
        ),
        FORM_CONTENT_TYPE,
        None,
        &body,
    );

    assert_presentation_success(&response);
}

#[test]
fn accepts_credential_bound_boruta_wallet_presentation_submission() {
    let fixture = presentation_fixture(PresentationOverrides::default());
    let submission = boruta_wallet_presentation_submission();
    let response = submit_with_submission(
        &fixture.state,
        Some(&fixture.vp_token),
        Some(&submission),
        None,
        FORM_CONTENT_TYPE,
    );

    assert_presentation_success(&response);
}

#[test]
fn rejects_empty_credential_bound_nested_descriptor_identifier() {
    let fixture = presentation_fixture(PresentationOverrides::default());
    let mut submission: Value =
        serde_json::from_str(&boruta_wallet_presentation_submission()).unwrap();
    submission["descriptor_map"][0]["path_nested"]["id"] = json!("");
    let response = submit_with_submission(
        &fixture.state,
        Some(&fixture.vp_token),
        Some(&submission.to_string()),
        None,
        FORM_CONTENT_TYPE,
    );

    assert_error(
        &response,
        "presentation_submission descriptor id is invalid",
    );
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

    assert_presentation_success(&response);
}

#[test]
fn rejects_missing_presentation_response_content_type() {
    let fixture = presentation_fixture(PresentationOverrides::default());
    let submission = valid_presentation_submission();
    let body = response_body(
        &fixture.state,
        Some(&fixture.vp_token),
        Some(&submission),
        None,
    );
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
fn returns_html_instead_of_redirecting_to_unregistered_state_redirect_uri() {
    let state = presentation_state_with_redirect_uri("https://attacker.example/callback");
    let response = submit(&state, None, None, FORM_CONTENT_TYPE);

    assert_error(&response, "redirect_uri is invalid");
    assert!(!response.contains("location:"));
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
    let submission = valid_presentation_submission();
    let response = submit_with_submission(
        &request.state(),
        None,
        Some(&submission),
        None,
        FORM_CONTENT_TYPE,
    );

    assert_error(&response, "vp_token is required");
}

#[test]
fn rejects_missing_presentation_submission() {
    let fixture = presentation_fixture(PresentationOverrides::default());
    let response = submit_with_submission(
        &fixture.state,
        Some(&fixture.vp_token),
        None,
        None,
        FORM_CONTENT_TYPE,
    );

    assert_error(&response, "presentation_submission is required");
}

#[test]
fn rejects_malformed_presentation_submission() {
    let fixture = presentation_fixture(PresentationOverrides::default());
    let response = submit_with_submission(
        &fixture.state,
        Some(&fixture.vp_token),
        Some("not-json"),
        None,
        FORM_CONTENT_TYPE,
    );

    assert_error(&response, "presentation_submission must be a JSON object");
}

#[test]
fn rejects_presentation_submission_for_wrong_definition() {
    let fixture = presentation_fixture(PresentationOverrides::default());
    let submission = presentation_submission("other", INPUT_DESCRIPTOR_ID, "jwt_vp", "$", 1);
    let response = submit_with_submission(
        &fixture.state,
        Some(&fixture.vp_token),
        Some(&submission),
        None,
        FORM_CONTENT_TYPE,
    );

    assert_error(
        &response,
        "presentation_submission definition_id is invalid",
    );
}

#[test]
fn rejects_presentation_submission_without_an_id() {
    let fixture = presentation_fixture(PresentationOverrides::default());
    let mut submission: Value = serde_json::from_str(&valid_presentation_submission()).unwrap();
    submission["id"] = json!("");
    let response = submit_with_submission(
        &fixture.state,
        Some(&fixture.vp_token),
        Some(&submission.to_string()),
        None,
        FORM_CONTENT_TYPE,
    );

    assert_error(&response, "presentation_submission id is required");
}

#[test]
fn rejects_presentation_submission_for_wrong_descriptor() {
    let fixture = presentation_fixture(PresentationOverrides::default());
    let submission = presentation_submission(PRESENTATION_DEFINITION_ID, "other", "jwt_vp", "$", 1);
    let response = submit_with_submission(
        &fixture.state,
        Some(&fixture.vp_token),
        Some(&submission),
        None,
        FORM_CONTENT_TYPE,
    );

    assert_error(
        &response,
        "presentation_submission descriptor id is invalid",
    );
}

#[test]
fn rejects_presentation_submission_with_wrong_mapping() {
    let fixture = presentation_fixture(PresentationOverrides::default());
    let submission = presentation_submission(
        PRESENTATION_DEFINITION_ID,
        INPUT_DESCRIPTOR_ID,
        "jwt_vc",
        "$[0]",
        1,
    );
    let response = submit_with_submission(
        &fixture.state,
        Some(&fixture.vp_token),
        Some(&submission),
        None,
        FORM_CONTENT_TYPE,
    );

    assert_error(
        &response,
        "presentation_submission descriptor mapping is invalid",
    );
}

#[test]
fn rejects_presentation_submission_with_multiple_descriptors() {
    let fixture = presentation_fixture(PresentationOverrides::default());
    let submission = presentation_submission(
        PRESENTATION_DEFINITION_ID,
        INPUT_DESCRIPTOR_ID,
        "jwt_vp",
        "$",
        2,
    );
    let response = submit_with_submission(
        &fixture.state,
        Some(&fixture.vp_token),
        Some(&submission),
        None,
        FORM_CONTENT_TYPE,
    );

    assert_error(
        &response,
        "presentation_submission must contain exactly one descriptor",
    );
}

#[test]
fn rejects_presentation_submission_without_a_descriptor() {
    let fixture = presentation_fixture(PresentationOverrides::default());
    let submission = presentation_submission(
        PRESENTATION_DEFINITION_ID,
        INPUT_DESCRIPTOR_ID,
        "jwt_vp",
        "$",
        0,
    );
    let response = submit_with_submission(
        &fixture.state,
        Some(&fixture.vp_token),
        Some(&submission),
        None,
        FORM_CONTENT_TYPE,
    );

    assert_error(
        &response,
        "presentation_submission must contain exactly one descriptor",
    );
}

#[test]
fn rejects_malformed_presentation_jwt() {
    let request = presentation_request();
    let response = submit(&request.state(), Some("invalid"), None, FORM_CONTENT_TYPE);

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

    assert_error(
        &response,
        "vp_token presentation header must include jwk or a did:key kid",
    );
}

#[test]
fn rejects_presentation_with_wrong_algorithm() {
    let request = presentation_request();
    let credential = issued_credential();
    let claims = presentation_claims(&request, &credential, &PresentationOverrides::default());
    let mut header = Header::new(Algorithm::HS512);
    header.jwk = Some(holder_jwk());
    let jwt = encode(&header, &claims, &EncodingKey::from_secret(b"secret")).unwrap();
    let response = submit(&request.state(), Some(&jwt), None, FORM_CONTENT_TYPE);

    assert_error(
        &response,
        "vp_token presentation algorithm must be asymmetric",
    );
}

#[test]
fn accepts_es256_presentation_with_embedded_jwk_before_kid() {
    let request = presentation_request();
    let holder_jwk = ec_holder_jwk();
    let credential = issued_credential();
    let claims = presentation_claims(&request, &credential, &PresentationOverrides::default());
    let mut header = Header::new(Algorithm::ES256);
    header.kid = Some("unrelated-key-id".to_owned());
    header.jwk = Some(holder_jwk);
    let jwt = encode(
        &header,
        &claims,
        &EncodingKey::from_ec_pem(EC_HOLDER_PRIVATE_KEY).unwrap(),
    )
    .unwrap();
    let response = submit(&request.state(), Some(&jwt), None, FORM_CONTENT_TYPE);

    assert_presentation_success(&response);
}

#[test]
fn accepts_standard_presentation_without_audience_or_time_claims() {
    let request = presentation_request();
    let credential = issued_credential();
    let mut claims = presentation_claims(&request, &credential, &PresentationOverrides::default());
    let claims = claims.as_object_mut().unwrap();
    claims.remove("aud");
    claims.remove("iat");
    claims.remove("nbf");
    claims.remove("exp");
    let mut header = Header::new(Algorithm::EdDSA);
    header.jwk = Some(holder_jwk());
    let jwt = encode(
        &header,
        &claims,
        &EncodingKey::from_ed_pem(HOLDER_PRIVATE_KEY).unwrap(),
    )
    .unwrap();
    let response = submit(&request.state(), Some(&jwt), None, FORM_CONTENT_TYPE);

    assert_presentation_success(&response);
}

#[test]
fn accepts_es256_presentation_with_did_key_kid_fallback() {
    let request = presentation_request();
    let did = ec_holder_did_key();
    let credential = issued_credential_for_subject(&did);
    let claims =
        boruta_presentation_claims(&request, &credential, &did, PRESENTATION_DEFINITION_ID);
    let mut header = Header::new(Algorithm::ES256);
    header.kid = Some(did);
    let jwt = encode(
        &header,
        &claims,
        &EncodingKey::from_ec_pem(EC_HOLDER_PRIVATE_KEY).unwrap(),
    )
    .unwrap();
    let submission = boruta_wallet_presentation_submission();
    let response = submit_with_submission(
        &request.state(),
        Some(&jwt),
        Some(&submission),
        None,
        FORM_CONTENT_TYPE,
    );

    assert_presentation_success(&response);
}

#[test]
fn verifies_presentation_kid_and_signature_against_code_id_token_public_key() {
    let code = authorization_code_with_id_token(&ec_id_token());
    let request = presentation_request_with_code(Some(&code));
    let did = ec_holder_did_key();
    let credential = issued_credential_for_subject(&did);
    let claims =
        boruta_presentation_claims(&request, &credential, &did, PRESENTATION_DEFINITION_ID);
    let mut header = Header::new(Algorithm::ES256);
    header.kid = Some(did);
    let jwt = encode(
        &header,
        &claims,
        &EncodingKey::from_ec_pem(EC_HOLDER_PRIVATE_KEY).unwrap(),
    )
    .unwrap();
    let submission = boruta_wallet_presentation_submission();
    let response = submit_with_submission(
        &request.state(),
        Some(&jwt),
        Some(&submission),
        None,
        FORM_CONTENT_TYPE,
    );

    assert_presentation_success(&response);
}

#[test]
fn rejects_wallet_bound_presentation_request_without_code_id_token_key() {
    let response = send_request(
        "GET /authorize?response_type=vp_token&client_id=wallet_bound_client&redirect_uri=https%3A%2F%2Fwallet-bound.example.com%2Fcallback&scope=credential_presentation HTTP/1.1\r\nhost: issuer.example.com\r\n\r\n",
    );

    assert!(response.starts_with("HTTP/1.1 400 Bad Request\r\n"));
    assert!(response.contains("wallet binding requires a code containing an id_token public key"));
}

#[test]
fn accepts_wallet_bound_presentation_request_with_code_id_token_key() {
    let code = authorization_code_with_id_token_for_client(&ec_id_token(), "wallet_bound_client");
    let response = send_request(&format!(
        "GET /authorize?response_type=vp_token&client_id=wallet_bound_client&redirect_uri=https%3A%2F%2Fwallet-bound.example.com%2Fcallback&scope=credential_presentation&code={} HTTP/1.1\r\nhost: issuer.example.com\r\n\r\n",
        form_encode(&code)
    ));

    assert!(response.starts_with("HTTP/1.1 302 Found\r\n"));
    assert!(response.contains("request="));
}

#[test]
fn rejects_presentation_key_different_from_code_id_token_public_key() {
    let code = authorization_code_with_id_token(&ec_id_token());
    let request = presentation_request_with_code(Some(&code));
    let credential = issued_credential();
    let claims = presentation_claims(&request, &credential, &PresentationOverrides::default());
    let mut header = Header::new(Algorithm::EdDSA);
    header.jwk = Some(holder_jwk());
    let jwt = encode(
        &header,
        &claims,
        &EncodingKey::from_ed_pem(HOLDER_PRIVATE_KEY).unwrap(),
    )
    .unwrap();
    let response = submit(&request.state(), Some(&jwt), None, FORM_CONTENT_TYPE);

    assert_error(
        &response,
        "vp_token presentation signature does not match id_token public key",
    );
}

#[test]
fn rejects_boruta_presentation_with_wrong_definition_id() {
    let request = presentation_request();
    let did = ec_holder_did_key();
    let credential = issued_credential_for_subject(&did);
    let claims = boruta_presentation_claims(&request, &credential, &did, "other-definition");
    let mut header = Header::new(Algorithm::ES256);
    header.kid = Some(did);
    let jwt = encode(
        &header,
        &claims,
        &EncodingKey::from_ec_pem(EC_HOLDER_PRIVATE_KEY).unwrap(),
    )
    .unwrap();
    let submission = boruta_wallet_presentation_submission();
    let response = submit_with_submission(
        &request.state(),
        Some(&jwt),
        Some(&submission),
        None,
        FORM_CONTENT_TYPE,
    );

    assert_error(&response, "vp_token presentation definition id is invalid");
}

#[test]
fn rejects_did_key_kid_that_does_not_identify_presentation_issuer() {
    let request = presentation_request();
    let credential = issued_credential();
    let claims = presentation_claims(&request, &credential, &PresentationOverrides::default());
    let mut header = Header::new(Algorithm::ES256);
    header.kid = Some(ec_holder_did_key());
    let jwt = encode(
        &header,
        &claims,
        &EncodingKey::from_ec_pem(EC_HOLDER_PRIVATE_KEY).unwrap(),
    )
    .unwrap();
    let response = submit(&request.state(), Some(&jwt), None, FORM_CONTENT_TYPE);

    assert_error(
        &response,
        "vp_token presentation kid must identify the issuer did:key",
    );
}

#[test]
fn accepts_presentation_key_different_from_credential_confirmation_key() {
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
    let response = submit(&request.state(), Some(&jwt), None, FORM_CONTENT_TYPE);

    assert_presentation_success(&response);
}

#[test]
fn rejects_presentation_with_invalid_signature() {
    let mut fixture = presentation_fixture(PresentationOverrides::default());
    fixture.presentation.push('x');
    fixture.vp_token = fixture.presentation.clone();
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

    assert_error(&response, "vp_token presentation audience is invalid");
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

    assert_presentation_success(&submit(
        &fixture.state,
        Some(&fixture.vp_token),
        None,
        FORM_CONTENT_TYPE,
    ));
    assert_presentation_success(&submit(
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

    assert_wallet_error_redirect(&response, "access_denied", None);
}

#[test]
fn redirects_wallet_error_description_and_client_state() {
    let request = presentation_request();
    let body = format!(
        "{}&error_description={}",
        response_body(&request.state(), None, None, Some("access_denied")),
        form_encode("credential presentation was declined")
    );
    let response = post_form(&body, FORM_CONTENT_TYPE);

    assert_wallet_error_redirect(
        &response,
        "access_denied",
        Some("credential presentation was declined"),
    );
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

#[test]
fn rejects_wallet_error_response_with_presentation_submission() {
    let request = presentation_request();
    let submission = valid_presentation_submission();
    let response = submit_with_submission(
        &request.state(),
        None,
        Some(&submission),
        Some("access_denied"),
        FORM_CONTENT_TYPE,
    );

    assert_error(
        &response,
        "wallet error response must not include presentation_submission",
    );
}

const FORM_CONTENT_TYPE: &str = "application/x-www-form-urlencoded";

struct AuthorizationRequestFixture {
    response: String,
    body: Value,
    signed_request: String,
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
    let vp_token = presentation.clone();

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

fn boruta_presentation_claims(
    request: &AuthorizationRequestFixture,
    credential: &str,
    holder: &str,
    definition_id: &str,
) -> Value {
    json!({
        "iss": holder,
        "sub": holder,
        "metadata_policy": {
            "client_id": {
                "one_of": [holder]
            }
        },
        "id": definition_id,
        "@context": ["https://www.w3.org/2018/credentials/v1"],
        "type": ["VerifiablePresentation"],
        "verifiableCredential": [credential],
        "nonce": request.nonce()
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

fn ec_holder_jwk() -> jsonwebtoken::jwk::Jwk {
    serde_json::from_value(kagome::resources::crypto::SigningArtifact::RequestObject.public_jwk())
        .unwrap()
}

fn ec_holder_did_key() -> String {
    let jwk = kagome::resources::crypto::SigningArtifact::RequestObject.public_jwk();
    let canonical = format!(
        r#"{{"crv":"P-256","kty":"EC","x":"{}","y":"{}"}}"#,
        jwk["x"].as_str().unwrap(),
        jwk["y"].as_str().unwrap()
    );
    let mut multicodec_key = vec![0xd1, 0xd6, 0x03];
    multicodec_key.extend(canonical.as_bytes());
    format!("did:key:z{}", base58btc(&multicodec_key))
}

fn issuer_jwk() -> jsonwebtoken::jwk::Jwk {
    serde_json::from_value(kagome::resources::crypto::SigningArtifact::Credential.public_jwk())
        .unwrap()
}

fn presentation_request() -> AuthorizationRequestFixture {
    presentation_request_with_code(None)
}

fn presentation_request_with_code(code: Option<&str>) -> AuthorizationRequestFixture {
    let mut path = presentation_request_path();
    if let Some(code) = code {
        path.push_str("&code=");
        path.push_str(&form_encode(code));
    }
    presentation_request_for_path(&path)
}

fn presentation_request_with_suffix(suffix: &str) -> AuthorizationRequestFixture {
    presentation_request_for_path(&format!("{}{suffix}", presentation_request_path()))
}

fn presentation_request_for_path(path: &str) -> AuthorizationRequestFixture {
    let response = send_request(&format!("GET {path} HTTP/1.1\r\nhost: {HOST}\r\n\r\n"));
    let signed_request = redirect_query_parameter(&response, "request");
    let request_key: jsonwebtoken::jwk::Jwk = serde_json::from_value(
        kagome::resources::crypto::SigningArtifact::RequestObject.public_jwk(),
    )
    .unwrap();
    let mut validation = Validation::new(Algorithm::ES256);
    validation.set_audience(&[kagome::resources::request_object::SELF_ISSUED_AUDIENCE]);
    let body = decode::<Value>(
        &signed_request,
        &DecodingKey::from_jwk(&request_key).unwrap(),
        &validation,
    )
    .unwrap()
    .claims;

    AuthorizationRequestFixture {
        response,
        body,
        signed_request,
    }
}

struct AuthorizationCodeWithIdToken {
    client_id: String,
    id_token: String,
    id_token_public_jwk: Value,
    authorization_code: Option<kagome::resources::authorization_code::AuthorizationCode>,
}

impl kagome::resources::authorization_code::Generate for AuthorizationCodeWithIdToken {
    fn previous_authorization_code(&self) -> Option<&str> {
        None
    }

    fn client_id(&self) -> Option<&str> {
        Some(&self.client_id)
    }

    fn id_token(&self) -> Option<&str> {
        Some(&self.id_token)
    }

    fn id_token_public_jwk(&self) -> Option<&Value> {
        Some(&self.id_token_public_jwk)
    }

    fn add_authorization_code(
        &mut self,
        authorization_code: kagome::resources::authorization_code::AuthorizationCode,
    ) {
        self.authorization_code = Some(authorization_code);
    }
}

fn authorization_code_with_id_token(id_token: &str) -> String {
    authorization_code_with_id_token_for_client(id_token, AUTHORIZE_CLIENT_ID)
}

fn authorization_code_with_id_token_for_client(id_token: &str, client_id: &str) -> String {
    let id_token_public_jwk = jsonwebtoken::decode_header(id_token)
        .unwrap()
        .jwk
        .map(|jwk| serde_json::to_value(jwk).unwrap())
        .unwrap();
    let request = AuthorizationCodeWithIdToken {
        client_id: client_id.to_owned(),
        id_token: id_token.to_owned(),
        id_token_public_jwk,
        authorization_code: None,
    };
    kagome::resources::authorization_code::generate(request)
        .unwrap()
        .authorization_code
        .unwrap()
        .value
}

fn ec_id_token() -> String {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let claims = json!({"iat": now, "exp": now + 300});
    let mut header = Header::new(Algorithm::ES256);
    header.jwk = Some(ec_holder_jwk());
    encode(
        &header,
        &claims,
        &EncodingKey::from_ec_pem(EC_HOLDER_PRIVATE_KEY).unwrap(),
    )
    .unwrap()
}

fn presentation_request_path() -> String {
    format!(
        "/authorize?response_type=vp_token&client_id={AUTHORIZE_CLIENT_ID}&redirect_uri={}&state=client-state&scope=credential_presentation",
        form_encode(AUTHORIZE_REDIRECT_URI)
    )
}

fn issued_credential() -> String {
    issued_credential_with_proof(None)
}

fn issued_credential_for_subject(subject: &str) -> String {
    let claims = json!({
        "iss": subject,
        "sub": subject,
        "aud": "http://localhost:4000",
        "iat": SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs()
    });
    let mut header = Header::new(Algorithm::ES256);
    header.kid = Some(subject.to_owned());
    let proof = encode(
        &header,
        &claims,
        &EncodingKey::from_ec_pem(EC_HOLDER_PRIVATE_KEY).unwrap(),
    )
    .unwrap();

    issued_credential_with_proof(Some(&proof))
}

fn issued_credential_with_proof(proof: Option<&str>) -> String {
    let grant_type = kagome::resources::pre_authorized_code::GRANT_TYPE;
    let code =
        kagome::resources::pre_authorized_code::generate(PreAuthorizedCodeFixture::default())
            .unwrap()
            .code
            .unwrap();
    let token_body = format!(
        "grant_type={}&pre-authorized_code={}",
        form_encode(grant_type),
        form_encode(&code)
    );
    let token_response = post("/token", FORM_CONTENT_TYPE, None, &token_body);
    let access_token = json_body(&token_response)["access_token"]
        .as_str()
        .unwrap()
        .to_owned();
    let mut credential_body = json!({
        "credential_identifier": "UniversityDegreeCredential"
    });
    if let Some(proof) = proof {
        credential_body["proof"] = json!({"proof_type": "jwt", "jwt": proof});
    }
    let credential_response = post(
        "/credential",
        "application/json",
        Some(&format!("Bearer {access_token}")),
        &credential_body.to_string(),
    );

    json_body(&credential_response)["credential"]
        .as_str()
        .unwrap()
        .to_owned()
}

#[derive(Default)]
struct PreAuthorizedCodeFixture {
    code: Option<String>,
}

impl kagome::resources::pre_authorized_code::Generate for PreAuthorizedCodeFixture {
    fn add_pre_authorized_code(&mut self, pre_authorized_code: String) {
        self.code = Some(pre_authorized_code);
    }
}

fn expired_state() -> String {
    encoded_presentation_state(1, 2, AUTHORIZE_REDIRECT_URI)
}

fn presentation_state_with_redirect_uri(redirect_uri: &str) -> String {
    let iat = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    encoded_presentation_state(iat, iat + 300, redirect_uri)
}

fn encoded_presentation_state(iat: u64, exp: u64, redirect_uri: &str) -> String {
    let presentation_definition =
        kagome::config::Config::global().presentation_definitions[0].clone();
    let claims = kagome::resources::presentation_state::PresentationStateClaims {
        nonce: "expired-nonce".to_owned(),
        client_id: CLIENT_ID.to_owned(),
        verifier: "http://localhost:4000".to_owned(),
        credential_issuer: "http://localhost:4000".to_owned(),
        authorization_client_id: AUTHORIZE_CLIENT_ID.to_owned(),
        authorization_redirect_uri: redirect_uri.to_owned(),
        authorization_state: Some("client-state".to_owned()),
        code_challenge: None,
        id_token_public_jwk: None,
        presentation_definition_identifier: presentation_definition.identifier,
        presentation_definition: presentation_definition.definition,
        presentation_definition_id: PRESENTATION_DEFINITION_ID.to_owned(),
        input_descriptor_id: INPUT_DESCRIPTOR_ID.to_owned(),
        iat,
        exp,
    };
    let mut plaintext = Vec::new();
    ciborium::into_writer(&claims, &mut plaintext).unwrap();
    kagome::resources::crypto::encode_cose_encrypt0(
        &plaintext,
        kagome::resources::crypto::EncryptedArtifact::PresentationState,
    )
    .unwrap()
}

fn submit(state: &str, vp_token: Option<&str>, error: Option<&str>, content_type: &str) -> String {
    let submission = vp_token.map(|_| valid_presentation_submission());
    submit_with_submission(state, vp_token, submission.as_deref(), error, content_type)
}

fn submit_with_submission(
    state: &str,
    vp_token: Option<&str>,
    presentation_submission: Option<&str>,
    error: Option<&str>,
    content_type: &str,
) -> String {
    post_form(
        &response_body(state, vp_token, presentation_submission, error),
        content_type,
    )
}

fn response_body(
    state: &str,
    vp_token: Option<&str>,
    presentation_submission: Option<&str>,
    error: Option<&str>,
) -> String {
    response_parameters(Some(state), vp_token, presentation_submission, error)
}

fn response_body_without_state(
    vp_token: Option<&str>,
    presentation_submission: Option<&str>,
    error: Option<&str>,
) -> String {
    response_parameters(None, vp_token, presentation_submission, error)
}

fn response_parameters(
    state: Option<&str>,
    vp_token: Option<&str>,
    presentation_submission: Option<&str>,
    error: Option<&str>,
) -> String {
    let mut parameters = Vec::new();
    if let Some(state) = state {
        parameters.push(format!("state={}", form_encode(state)));
    }
    if let Some(vp_token) = vp_token {
        parameters.push(format!("vp_token={}", form_encode(vp_token)));
    }
    if let Some(presentation_submission) = presentation_submission {
        parameters.push(format!(
            "presentation_submission={}",
            form_encode(presentation_submission)
        ));
    }
    if let Some(error) = error {
        parameters.push(format!("error={}", form_encode(error)));
    }
    parameters.join("&")
}

fn valid_presentation_submission() -> String {
    presentation_submission(
        PRESENTATION_DEFINITION_ID,
        INPUT_DESCRIPTOR_ID,
        "jwt_vp",
        "$",
        1,
    )
}

fn boruta_wallet_presentation_submission() -> String {
    json!({
        "id": format!("presentation_submission~{PRESENTATION_DEFINITION_ID}"),
        "descriptor_map": [{
            "id": "UniversityDegreeCredential",
            "format": "jwt_vp",
            "path": "$",
            "path_nested": {
                "id": "wallet-defined-identifier",
                "format": "jwt_vc",
                "path": "$.verifiableCredential[0]"
            }
        }]
    })
    .to_string()
}

fn presentation_submission(
    definition_id: &str,
    descriptor_id: &str,
    format: &str,
    path: &str,
    descriptor_count: usize,
) -> String {
    let descriptor = json!({
        "id": descriptor_id,
        "format": format,
        "path": path,
        "path_nested": {
            "id": descriptor_id,
            "format": "jwt_vc",
            "path": "$.vp.verifiableCredential[0]"
        }
    });

    json!({
        "id": "presentation_submission",
        "definition_id": definition_id,
        "descriptor_map": vec![descriptor; descriptor_count]
    })
    .to_string()
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

fn redirect_query_parameter(response: &str, name: &str) -> String {
    redirect_query_parameter_optional(response, name).unwrap()
}

fn redirect_query_parameter_optional(response: &str, name: &str) -> Option<String> {
    let location = response
        .lines()
        .find_map(|line| line.strip_prefix("location: "))
        .unwrap();
    let query = location
        .split_once('?')
        .map(|(_, query)| query)
        .unwrap()
        .split('#')
        .next()
        .unwrap();
    query
        .split('&')
        .find_map(|parameter| {
            parameter
                .split_once('=')
                .filter(|(parameter_name, _)| *parameter_name == name)
                .map(|(_, value)| value)
        })
        .map(percent_decode)
}

fn percent_decode(value: &str) -> String {
    let bytes = value.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' && index + 2 < bytes.len() {
            let high = hex_value(bytes[index + 1]).unwrap();
            let low = hex_value(bytes[index + 2]).unwrap();
            decoded.push(high * 16 + low);
            index += 3;
        } else {
            decoded.push(bytes[index]);
            index += 1;
        }
    }

    String::from_utf8(decoded).unwrap()
}

fn hex_value(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'A'..=b'F' => Some(value - b'A' + 10),
        b'a'..=b'f' => Some(value - b'a' + 10),
        _ => None,
    }
}

fn json_body(response: &str) -> Value {
    serde_json::from_str(response.split_once("\r\n\r\n").unwrap().1).unwrap()
}

fn assert_presentation_success(response: &str) {
    assert!(response.starts_with("HTTP/1.1 302 Found\r\n"), "{response}");
    assert!(
        response.contains(&format!("location: {AUTHORIZE_REDIRECT_URI}?")),
        "{response}"
    );
    assert!(response.contains("cache-control: no-store\r\n"));
    let code = redirect_query_parameter(response, "code");
    let payload = kagome::resources::authorization_code::decode_cose_payload(&code).unwrap();
    assert_eq!(payload.client_id, AUTHORIZE_CLIENT_ID);
    assert!(
        payload
            .username
            .is_some_and(|username| !username.is_empty())
    );
    assert_eq!(redirect_query_parameter(response, "state"), "client-state");
}

fn assert_wallet_error_redirect(response: &str, error: &str, description: Option<&str>) {
    assert!(response.starts_with("HTTP/1.1 302 Found\r\n"), "{response}");
    assert!(response.contains(&format!("location: {AUTHORIZE_REDIRECT_URI}?")));
    assert_eq!(redirect_query_parameter(response, "error"), error);
    if let Some(description) = description {
        assert_eq!(
            redirect_query_parameter(response, "error_description"),
            description
        );
    }
    assert_eq!(redirect_query_parameter(response, "state"), "client-state");
}

fn assert_error(response: &str, description: &str) {
    if response.starts_with("HTTP/1.1 302 Found\r\n") {
        assert!(response.contains(&format!("location: {AUTHORIZE_REDIRECT_URI}?")));
        assert_eq!(
            redirect_query_parameter(response, "error"),
            "invalid_request"
        );
        assert_eq!(
            redirect_query_parameter(response, "error_description"),
            description
        );
        assert_eq!(redirect_query_parameter(response, "state"), "client-state");
        return;
    }

    assert!(
        response.starts_with("HTTP/1.1 400 Bad Request\r\n"),
        "{response}"
    );
    assert!(response.contains("content-type: text/html\r\n"));
    assert!(response.contains("<title>authorization error</title>"));
    assert!(response.contains(&format!("<p role=\"alert\">{description}</p>")));
}

fn assert_authorize_error(response: &str, description: &str) {
    assert!(
        response.starts_with("HTTP/1.1 400 Bad Request\r\n"),
        "{response}"
    );
    assert!(response.contains("content-type: text/html\r\n"));
    assert!(response.contains(&format!("<p role=\"alert\">{description}</p>")));
}
