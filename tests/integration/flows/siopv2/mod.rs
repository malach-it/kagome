use std::time::{SystemTime, UNIX_EPOCH};

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation, decode, encode};
use ring::digest;
use serde_json::{Value, json};

use super::super::server::send_request;

const HOST: &str = "issuer.example.com";
const ISSUER: &str = "http://localhost:4000";
const RESPONSE_URI: &str = "http://localhost:4000/siopv2-response";
const CLIENT_ID: &str = "configured_client";
const CLIENT_REDIRECT_URI: &str = "https://configured.example.com/callback";
const X: &str = "2OOMuJdc5XAbumGYaUtM3ngfBVFhqjeqb0fJ_N3Y7UI";
const Y: &str = "Yp8TpPyvA3t9jF01vn7Z6SXYjpKkZOrO1Gg7CkxnMF8";
const PRIVATE_KEY: &[u8] = b"-----BEGIN PRIVATE KEY-----\nMIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg9SWS4Y9IULSULCea\nXPaFWOCkkYV/k1RW1NCRhdqo8NGhRANCAATY44y4l1zlcBu6YZhpS0zeeB8FUWGq\nN6pvR8n83djtQmKfE6T8rwN7fYxdNb5+2ekl2I6SpGTqztRoOwpMZzBf\n-----END PRIVATE KEY-----\n";

// Branch matrix:
// - endpoint method: supported | unsupported
// - OAuth authorization attributes: valid response type(s), client, redirect URI,
//   client state, and optional code | missing/invalid value for each
// - authorization request error format: every direct failure renders HTML
// - wallet binding policy: SIOPv2 pre-authorized-code continuation carries the
//   validated wallet key through an encrypted authorization code
// - PKCE: absent | valid S256 parameters preserved in state | unsupported method
// - verifier origin: configured issuer | unrelated or missing Host (equivalent)
// - generated values: fresh nonce/state/request object | RNG/signing failure
//   (unreachable with the process RNG and embedded signing key)
// - authorization request delivery: redirect | QR-code HTML with matching deep link
// - authenticated continuation delivery: redirect even when the client enables QR
//   pages; pre-authorized code returns through /authorize | OpenID4VP request
// - response media type: form (case-insensitive, parameters allowed) | missing |
//   unsupported
// - state source: callback query | form body; value valid | missing | invalid |
//   expired; request response type: matches authorization parameters | mismatch
// - response kind: id_token | supported wallet error with or without description |
//   unsupported wallet error | neither | both (invalid)
// - error destination: validated client redirect URI with optional client state |
//   no trusted redirect URI (HTML error)
// - ID Token shape: JWT | malformed; algorithm ES256 | unsupported
// - subject syntax: raw P-256 did:key | Boruta JWK-JCS P-256 did:key |
//   JWK thumbprint P-256 | unsupported | malformed/non-canonical key |
//   subject/key mismatch | kid mismatch
// - claims: issuer equals subject | mismatch; audience and nonce match | mismatch;
//   time claims valid | invalid/expired
// Equivalent valid state sources converge before ID Token validation. Replay is
// deliberately possible until the five-minute stateless state expires.

#[test]
fn returns_signed_direct_post_siop_authorization_request() {
    let fixture = authorization_request();

    assert!(
        fixture.response.starts_with(&format!(
            "HTTP/1.1 302 Found\r\nlocation: {CLIENT_REDIRECT_URI}?"
        )),
        "{}",
        fixture.response
    );
    assert!(fixture.response.contains("cache-control: no-store\r\n"));
    assert_eq!(fixture.body["client_id"], RESPONSE_URI);
    assert_eq!(fixture.body["response_type"], "id_token");
    assert_eq!(fixture.state_claims().response_type, "code");
    assert_eq!(fixture.body["response_mode"], "direct_post");
    assert_eq!(fixture.body["scope"], "openid");
    assert!(
        fixture.body["redirect_uri"]
            .as_str()
            .unwrap()
            .contains("?state=")
    );
    assert!(fixture.body["nonce"].as_str().unwrap().len() >= 32);

    let jwks = json_body(&send_request(&format!(
        "GET /openid/jwks HTTP/1.1\r\nhost: {HOST}\r\n\r\n"
    )));
    let request_key: jsonwebtoken::jwk::Jwk = serde_json::from_value(
        jwks["keys"]
            .as_array()
            .unwrap()
            .iter()
            .find(|key| {
                key["kid"] == kagome::resources::crypto::SigningArtifact::RequestObject.key_id()
            })
            .unwrap()
            .clone(),
    )
    .unwrap();
    let mut validation = Validation::new(Algorithm::ES256);
    validation.set_audience(&[kagome::resources::request_object::SELF_ISSUED_AUDIENCE]);
    let claims = decode::<Value>(
        fixture.body["request"].as_str().unwrap(),
        &DecodingKey::from_jwk(&request_key).unwrap(),
        &validation,
    )
    .unwrap()
    .claims;
    assert_eq!(claims["nonce"], fixture.body["nonce"]);
    assert_eq!(claims["state"], fixture.body["state"]);
    assert_eq!(claims["redirect_uri"], fixture.body["redirect_uri"]);
    assert_eq!(
        claims["client_metadata"]["id_token_signed_response_alg"],
        "ES256"
    );
}

#[test]
fn preserves_s256_pkce_parameters_in_siop_state() {
    let response = send_request(&format!(
        "GET /siopv2-request?response_type=code&client_id={CLIENT_ID}&redirect_uri={}&state=client-state&code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM&code_challenge_method=S256 HTTP/1.1\r\nhost: {HOST}\r\n\r\n",
        form_encode(CLIENT_REDIRECT_URI)
    ));
    let fixture = AuthorizationFixture {
        body: redirect_parameters(&response),
        response,
    };
    let authorization = fixture.state_claims().authorization;

    assert_eq!(
        authorization.code_challenge.as_deref(),
        Some("E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM")
    );
    assert_eq!(authorization.code_challenge_method.as_deref(), Some("S256"));
}

#[test]
fn rejects_non_s256_pkce_method_for_siop_authorization() {
    let response = send_request(&format!(
        "GET /siopv2-request?response_type=code&client_id={CLIENT_ID}&redirect_uri={}&code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM&code_challenge_method=plain HTTP/1.1\r\nhost: {HOST}\r\n\r\n",
        form_encode(CLIENT_REDIRECT_URI)
    ));

    assert_authorization_request_html_error(&response, "code_challenge_method must be S256");
}

#[test]
fn renders_siop_authorization_request_as_qr_code_with_deep_link() {
    let response = send_request(&format!(
        "GET /siopv2-request?response_type=code&client_id=qr_client&redirect_uri={} HTTP/1.1\r\nhost: {HOST}\r\n\r\n",
        form_encode("https://qr.example.com/callback")
    ));
    let deep_link = super::common::qr_page_deep_link(&response);

    assert!(deep_link.starts_with("https://qr.example.com/callback?client_id="));
    assert!(deep_link.contains("&response_type=id_token"));
    assert!(deep_link.contains("&response_mode=direct_post"));
    assert!(deep_link.contains("&request="));
}

#[test]
fn generates_fresh_siop_nonce_state_and_request_object() {
    let first = authorization_request();
    let second = authorization_request();

    assert_ne!(first.body["nonce"], second.body["nonce"]);
    assert_ne!(first.body["state"], second.body["state"]);
    assert_ne!(first.body["request"], second.body["request"]);
}

#[test]
fn uses_configured_issuer_independently_of_host() {
    let path = format!(
        "/siopv2-request?response_type=code&client_id={CLIENT_ID}&redirect_uri={}",
        form_encode(CLIENT_REDIRECT_URI)
    );
    let missing = send_request(&format!("GET {path} HTTP/1.1\r\n\r\n"));
    let invalid = send_request(&format!("GET {path} HTTP/1.1\r\nhost: bad/host\r\n\r\n"));

    for response in [missing, invalid] {
        assert!(response.starts_with(&format!(
            "HTTP/1.1 302 Found\r\nlocation: {CLIENT_REDIRECT_URI}?"
        )));
        assert_eq!(redirect_parameters(&response)["client_id"], RESPONSE_URI);
    }
}

#[test]
fn returns_not_found_for_unsupported_siop_endpoint_methods() {
    let request = send_request(&format!(
        "POST /siopv2-request HTTP/1.1\r\nhost: {HOST}\r\n\r\n"
    ));
    let response = send_request(&format!(
        "GET /siopv2-response HTTP/1.1\r\nhost: {HOST}\r\n\r\n"
    ));

    assert!(request.starts_with("HTTP/1.1 404 Not Found\r\n"));
    assert!(response.starts_with("HTTP/1.1 404 Not Found\r\n"));
}

#[test]
fn accepts_raw_p256_did_key_self_issued_id_token() {
    let fixture = authorization_request();
    let did = did_key();
    let token = id_token(&fixture, &did, &did, None, TokenOverrides::default());
    let response = submit(&fixture, &token, None);

    assert!(
        response.starts_with(
            "HTTP/1.1 302 Found\r\nlocation: https://configured.example.com/callback?code="
        ),
        "{response}"
    );
}

#[test]
fn accepts_boruta_jwk_jcs_did_key_self_issued_id_token() {
    let fixture = authorization_request();
    let did = boruta_did_key();
    assert_eq!(
        did,
        "did:key:z2dmzD81cgPx8Vki7JbuuMmFYrWPgYoytykUZ3eyqht1j9KbnYXXLVm1YkyuJpeXa2mP7D8b1ndzfjMLu2BopfTo6dLfNZz88H2MoXxWn9HSx3Jk4h1RinoMWKAX3aghxZhkDSHCdLWC6uWKdypK9RGqb28ArDqzMNuxWw66ZNZdVaxciY"
    );
    let token = id_token(&fixture, &did, &did, None, TokenOverrides::default());
    let response = submit(&fixture, &token, None);

    assert!(
        response.starts_with(
            "HTTP/1.1 302 Found\r\nlocation: https://configured.example.com/callback?code="
        ),
        "{response}"
    );
}

#[test]
fn rejects_non_canonical_boruta_jwk_jcs_did_key() {
    let fixture = authorization_request();
    let did = non_canonical_boruta_did_key();
    let token = id_token(&fixture, &did, &did, None, TokenOverrides::default());

    assert_error(
        &submit(&fixture, &token, None),
        "id_token did:key contains a non-canonical JWK-JCS key",
    );
}

#[test]
fn accepts_jwk_thumbprint_self_issued_id_token_with_body_state() {
    let fixture = authorization_request();
    let jwk = signing_jwk();
    let subject = format!(
        "urn:ietf:params:oauth:jwk-thumbprint:sha-256:{}",
        jwk_thumbprint()
    );
    let token = id_token(
        &fixture,
        &subject,
        &subject,
        Some(jwk),
        TokenOverrides::default(),
    );
    let body = format!(
        "state={}&id_token={}",
        form_encode(fixture.state()),
        form_encode(&token)
    );
    let response = post(
        "/siopv2-response",
        "application/x-www-form-urlencoded",
        &body,
    );

    assert!(
        response.starts_with(
            "HTTP/1.1 302 Found\r\nlocation: https://configured.example.com/callback?code="
        ),
        "{response}"
    );
}

#[test]
fn requires_valid_oauth_authorization_attributes() {
    let missing = send_request(&format!(
        "GET /siopv2-request HTTP/1.1\r\nhost: {HOST}\r\n\r\n"
    ));
    let invalid_client = send_request(&format!(
        "GET /siopv2-request?response_type=code&client_id=unknown&redirect_uri={} HTTP/1.1\r\nhost: {HOST}\r\n\r\n",
        form_encode(CLIENT_REDIRECT_URI)
    ));
    let invalid_response_type = send_request(&format!(
        "GET /siopv2-request?response_type=unknown&client_id={CLIENT_ID}&redirect_uri={} HTTP/1.1\r\nhost: {HOST}\r\n\r\n",
        form_encode(CLIENT_REDIRECT_URI)
    ));
    let invalid_code = send_request(&format!(
        "GET /siopv2-request?response_type=token&client_id={CLIENT_ID}&redirect_uri={}&code=invalid HTTP/1.1\r\nhost: {HOST}\r\n\r\n",
        form_encode(CLIENT_REDIRECT_URI)
    ));

    assert_authorization_request_html_error(&missing, "response_type must be one of:");
    assert_authorization_request_html_error(&invalid_client, "client_id is invalid");
    assert_authorization_request_html_error(
        &invalid_response_type,
        "response_type must be one of:",
    );
    assert_authorization_request_html_error(
        &invalid_code,
        "authorization_code must be a cose_encrypt0",
    );
}

#[test]
fn renders_html_error_for_invalid_authorization_request_redirect_uri() {
    let response = send_request(&format!(
        "GET /siopv2-request?response_type=code&client_id={CLIENT_ID}&redirect_uri={} HTTP/1.1\r\nhost: {HOST}\r\n\r\n",
        form_encode("https://untrusted.example.com/callback")
    ));

    assert!(response.starts_with("HTTP/1.1 400 Bad Request\r\n"));
    assert!(response.contains("content-type: text/html\r\n"));
    assert!(response.contains("<title>authorization error</title>"));
    assert!(response.contains("<p role=\"alert\">redirect_uri is invalid</p>"));
    assert!(!response.contains("\r\nlocation:"));
}

#[test]
fn uses_siop_request_response_types_for_authorize_continuation() {
    let fixture = authorization_request_with("code token", None);
    let did = did_key();
    let token = id_token(&fixture, &did, &did, None, TokenOverrides::default());
    let response = submit(&fixture, &token, None);

    assert!(
        response.starts_with(
            "HTTP/1.1 302 Found\r\nlocation: https://configured.example.com/callback?code="
        ),
        "{response}"
    );
    assert!(response.contains("#access_token="), "{response}");
}

#[test]
fn redirects_wallet_bound_preauthorized_continuation_to_authorize() {
    let fixture = authorization_request_for_client(
        "urn:ietf:params:oauth:response-type:pre-authorized_code",
        "wallet_bound_client",
        "https://wallet-bound.example.com/callback",
        None,
    );
    let did = did_key();
    let token = id_token(&fixture, &did, &did, None, TokenOverrides::default());
    let response = submit(&fixture, &token, None);

    assert!(
        response.starts_with("HTTP/1.1 302 Found\r\nlocation: /authorize?"),
        "{response}"
    );
    let parameters = redirect_parameters(&response);
    assert_eq!(
        parameters["response_type"],
        "urn:ietf:params:oauth:response-type:pre-authorized_code"
    );
    let code = parameters["code"].as_str().unwrap();
    let payload = kagome::resources::authorization_code::decode_cose_payload(code).unwrap();
    let public_jwk = payload.id_token_public_jwk.unwrap();
    assert_eq!(public_jwk["x"], X);
    assert_eq!(public_jwk["y"], Y);
    assert!(payload.username.is_none());
}

#[test]
fn redirects_qr_client_preauthorized_continuation_to_authorize() {
    let fixture =
        qr_authorization_request("urn:ietf:params:oauth:response-type:pre-authorized_code");
    let did = did_key();
    let token = id_token(&fixture, &did, &did, None, TokenOverrides::default());
    let response = submit(&fixture, &token, None);

    assert!(
        response.starts_with("HTTP/1.1 302 Found\r\nlocation: /authorize?"),
        "{response}"
    );
    let parameters = redirect_parameters(&response);
    assert_eq!(parameters["client_id"], "qr_client");
    assert!(parameters["code"].as_str().is_some());
    assert!(!response.contains("<svg"), "{response}");
}

#[test]
fn redirects_qr_client_openid4vp_request_after_siopv2_response() {
    let fixture = qr_authorization_request("vp_token");
    let did = did_key();
    let token = id_token(&fixture, &did, &did, None, TokenOverrides::default());
    let response = submit(&fixture, &token, None);

    assert!(
        response.starts_with(
            "HTTP/1.1 302 Found\r\nlocation: https://qr.example.com/callback?client_id="
        ),
        "{response}"
    );
    assert!(response.contains("&response_type=vp_token"), "{response}");
    assert!(!response.contains("<svg"), "{response}");
}

#[test]
fn accepts_code_parameter_for_a_following_authorization_request() {
    let first = authorization_request();
    let did = did_key();
    let first_token = id_token(&first, &did, &did, None, TokenOverrides::default());
    let first_response = submit(&first, &first_token, None);
    let location = response_header(&first_response, "location").unwrap();
    let code = location.split_once("?code=").map(|(_, code)| code).unwrap();
    let second = authorization_request_with("token", Some(code));
    let second_token = id_token(&second, &did, &did, None, TokenOverrides::default());
    let second_response = submit(&second, &second_token, None);

    assert!(
        second_response.starts_with(
            "HTTP/1.1 302 Found\r\nlocation: https://configured.example.com/callback#access_token="
        ),
        "{second_response}"
    );
}

#[test]
fn redirects_supported_wallet_error_to_client() {
    let fixture = authorization_request();
    let response = submit_error(
        &fixture,
        "access_denied",
        Some("resource owner denied access"),
    );

    assert!(response.starts_with(&format!(
        "HTTP/1.1 302 Found\r\nlocation: {CLIENT_REDIRECT_URI}?"
    )));
    let parameters = redirect_parameters(&response);
    assert_eq!(parameters["error"], "access_denied");
    assert_eq!(
        parameters["error_description"],
        "resource owner denied access"
    );
    assert_eq!(parameters["state"], "client-state");
}

#[test]
fn omits_missing_wallet_error_description_from_redirect() {
    let fixture = authorization_request();
    let response = submit_error(&fixture, "user_cancelled", None);
    let parameters = redirect_parameters(&response);

    assert_eq!(parameters["error"], "user_cancelled");
    assert!(parameters.get("error_description").is_none());
    assert_eq!(parameters["state"], "client-state");
}

#[test]
fn rejects_invalid_encoding_state_and_response_shape() {
    let fixture = authorization_request();
    let token = id_token(
        &fixture,
        &did_key(),
        &did_key(),
        None,
        TokenOverrides::default(),
    );
    let json_response = post(
        &fixture.callback_path(),
        "application/json",
        &json!({"id_token": token}).to_string(),
    );
    let missing_state = post(
        "/siopv2-response",
        "application/x-www-form-urlencoded",
        "id_token=value",
    );
    let invalid_state = post(
        "/siopv2-response?state=invalid",
        "application/x-www-form-urlencoded",
        "id_token=value",
    );
    let neither = submit(&fixture, "", None);
    let both = submit(&fixture, "value", Some("access_denied"));
    let unsupported_error = submit(&fixture, "", Some("server_error"));

    assert_error(
        &json_response,
        "siop response content-type must be application/x-www-form-urlencoded",
    );
    assert_html_error(&missing_state, "state is required");
    assert_html_error(&invalid_state, "state is invalid or expired");
    assert_error(&neither, "id_token is required");
    assert_error(&both, "wallet error response must not include id_token");
    assert_error(&unsupported_error, "wallet error is unsupported");
}

#[test]
fn rejects_expired_siop_state() {
    let claims = kagome::resources::siopv2_state::SiopStateClaims {
        nonce: "expired-nonce".to_owned(),
        verifier: ISSUER.to_owned(),
        response_type: "id_token".to_owned(),
        authorization: kagome::resources::siopv2_state::SiopAuthorizationParameters {
            response_type: Some("code".to_owned()),
            client_id: Some(CLIENT_ID.to_owned()),
            redirect_uri: Some(CLIENT_REDIRECT_URI.to_owned()),
            state: Some("client-state".to_owned()),
            authorization_code: None,
            metadata_policy: None,
            code_challenge: None,
            code_challenge_method: None,
        },
        iat: 1,
        exp: 2,
    };
    let mut plaintext = Vec::new();
    ciborium::into_writer(&claims, &mut plaintext).unwrap();
    let state = kagome::resources::crypto::encode_cose_encrypt0(
        &plaintext,
        kagome::resources::crypto::EncryptedArtifact::Siopv2State,
    )
    .unwrap();
    let response = post(
        &format!("/siopv2-response?state={state}"),
        "application/x-www-form-urlencoded",
        "id_token=value",
    );

    assert_html_error(&response, "state is invalid or expired");
}

#[test]
fn rejects_siop_state_bound_to_a_different_issuer() {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let claims = kagome::resources::siopv2_state::SiopStateClaims {
        nonce: "issuer-bound-nonce".to_owned(),
        verifier: "https://other.example.com".to_owned(),
        response_type: "id_token".to_owned(),
        authorization: kagome::resources::siopv2_state::SiopAuthorizationParameters {
            response_type: Some("code".to_owned()),
            client_id: Some(CLIENT_ID.to_owned()),
            redirect_uri: Some(CLIENT_REDIRECT_URI.to_owned()),
            state: None,
            authorization_code: None,
            metadata_policy: None,
            code_challenge: None,
            code_challenge_method: None,
        },
        iat: now,
        exp: now + kagome::resources::siopv2_state::TTL_SECONDS,
    };
    let mut plaintext = Vec::new();
    ciborium::into_writer(&claims, &mut plaintext).unwrap();
    let state = kagome::resources::crypto::encode_cose_encrypt0(
        &plaintext,
        kagome::resources::crypto::EncryptedArtifact::Siopv2State,
    )
    .unwrap();
    let response = post(
        &format!("/siopv2-response?state={state}"),
        "application/x-www-form-urlencoded",
        "id_token=value",
    );

    assert_html_error(&response, "state is invalid or expired");
}

#[test]
fn rejects_mismatched_request_response_type_in_state() {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let claims = kagome::resources::siopv2_state::SiopStateClaims {
        nonce: "response-type-bound-nonce".to_owned(),
        verifier: ISSUER.to_owned(),
        response_type: "vp_token".to_owned(),
        authorization: kagome::resources::siopv2_state::SiopAuthorizationParameters {
            response_type: Some("code".to_owned()),
            client_id: Some(CLIENT_ID.to_owned()),
            redirect_uri: Some(CLIENT_REDIRECT_URI.to_owned()),
            state: None,
            authorization_code: None,
            metadata_policy: None,
            code_challenge: None,
            code_challenge_method: None,
        },
        iat: now,
        exp: now + kagome::resources::siopv2_state::TTL_SECONDS,
    };
    let mut plaintext = Vec::new();
    ciborium::into_writer(&claims, &mut plaintext).unwrap();
    let state = kagome::resources::crypto::encode_cose_encrypt0(
        &plaintext,
        kagome::resources::crypto::EncryptedArtifact::Siopv2State,
    )
    .unwrap();
    let response = post(
        &format!("/siopv2-response?state={state}"),
        "application/x-www-form-urlencoded",
        "id_token=value",
    );

    assert_html_error(&response, "state is invalid or expired");
}

#[test]
fn rejects_malformed_or_wrong_algorithm_id_token() {
    let fixture = authorization_request();
    let malformed = submit(&fixture, "not-a-jwt", None);
    let claims = token_claims(
        &fixture,
        &did_key(),
        &did_key(),
        None,
        TokenOverrides::default(),
    );
    let wrong_algorithm = encode(
        &Header::new(Algorithm::HS256),
        &claims,
        &EncodingKey::from_secret(b"secret"),
    )
    .unwrap();
    let wrong_algorithm = submit(&fixture, &wrong_algorithm, None);

    assert_error(&malformed, "id_token must be a jwt");
    assert_error(&wrong_algorithm, "id_token algorithm must be ES256");
}

#[test]
fn rejects_id_token_claim_mismatches() {
    let fixture = authorization_request();
    let did = did_key();
    let issuer = id_token(
        &fixture,
        &did,
        "did:key:zDifferent",
        None,
        TokenOverrides::default(),
    );
    let audience = id_token(
        &fixture,
        &did,
        &did,
        None,
        TokenOverrides {
            audience: Some("https://attacker.example/callback"),
            ..Default::default()
        },
    );
    let nonce = id_token(
        &fixture,
        &did,
        &did,
        None,
        TokenOverrides {
            nonce: Some("wrong-nonce"),
            ..Default::default()
        },
    );

    assert_error(
        &submit(&fixture, &issuer, None),
        "id_token issuer must equal subject",
    );
    assert_error(
        &submit(&fixture, &audience, None),
        "id_token audience is invalid",
    );
    assert_error(&submit(&fixture, &nonce, None), "id_token nonce is invalid");
}

#[test]
fn rejects_subject_key_and_time_mismatches() {
    let fixture = authorization_request();
    let invalid_thumbprint = format!("urn:ietf:params:oauth:jwk-thumbprint:sha-256:{}", "invalid");
    let subject = id_token(
        &fixture,
        &invalid_thumbprint,
        &invalid_thumbprint,
        Some(signing_jwk()),
        TokenOverrides::default(),
    );
    let did = did_key();
    let expired = id_token(
        &fixture,
        &did,
        &did,
        None,
        TokenOverrides {
            expired: true,
            ..Default::default()
        },
    );

    assert_error(
        &submit(&fixture, &subject, None),
        "id_token subject does not match sub_jwk",
    );
    assert_error(
        &submit(&fixture, &expired, None),
        "id_token is invalid or expired",
    );
}

struct AuthorizationFixture {
    response: String,
    body: Value,
}

impl AuthorizationFixture {
    fn state(&self) -> &str {
        self.body["state"].as_str().unwrap()
    }

    fn callback_path(&self) -> String {
        let redirect_uri = self.body["redirect_uri"].as_str().unwrap();
        let authority_and_path = redirect_uri.split_once("://").unwrap().1;
        let path_start = authority_and_path.find('/').unwrap();

        authority_and_path[path_start..].to_owned()
    }

    fn state_claims(&self) -> kagome::resources::siopv2_state::SiopStateClaims {
        let plaintext = kagome::resources::crypto::decode_cose_encrypt0(
            self.state(),
            kagome::resources::crypto::EncryptedArtifact::Siopv2State,
            kagome::resources::crypto::CoseEncrypt0Errors {
                invalid_cose: "invalid state",
                missing_ciphertext: "invalid state",
                missing_nonce: "invalid state",
                decryption_failed: "invalid state",
            },
        )
        .unwrap();
        ciborium::from_reader(plaintext.as_slice()).unwrap()
    }
}

#[derive(Default)]
struct TokenOverrides<'a> {
    audience: Option<&'a str>,
    nonce: Option<&'a str>,
    expired: bool,
}

fn authorization_request() -> AuthorizationFixture {
    authorization_request_with("code", None)
}

fn authorization_request_with(response_type: &str, code: Option<&str>) -> AuthorizationFixture {
    authorization_request_for_client(response_type, CLIENT_ID, CLIENT_REDIRECT_URI, code)
}

fn authorization_request_for_client(
    response_type: &str,
    client_id: &str,
    redirect_uri: &str,
    code: Option<&str>,
) -> AuthorizationFixture {
    let code = code
        .map(|code| format!("&code={}", form_encode(code)))
        .unwrap_or_default();
    let response = send_request(&format!(
        "GET /siopv2-request?response_type={}&client_id={client_id}&redirect_uri={}&state=client-state{code} HTTP/1.1\r\nhost: {HOST}\r\n\r\n",
        form_encode(response_type),
        form_encode(redirect_uri),
    ));
    let body = redirect_parameters(&response);
    AuthorizationFixture { response, body }
}

fn qr_authorization_request(response_type: &str) -> AuthorizationFixture {
    let response = send_request(&format!(
        "GET /siopv2-request?response_type={}&client_id=qr_client&redirect_uri={}&state=client-state HTTP/1.1\r\nhost: {HOST}\r\n\r\n",
        form_encode(response_type),
        form_encode("https://qr.example.com/callback"),
    ));
    let deep_link = super::common::qr_page_deep_link(&response);
    let body = uri_parameters(&deep_link);

    AuthorizationFixture { response, body }
}

fn response_header<'a>(response: &'a str, name: &str) -> Option<&'a str> {
    response.lines().find_map(|line| {
        let (header_name, value) = line.split_once(':')?;
        header_name
            .eq_ignore_ascii_case(name)
            .then_some(value.trim())
    })
}

fn redirect_parameters(response: &str) -> Value {
    let location = response_header(response, "location").unwrap();
    uri_parameters(location)
}

fn uri_parameters(uri: &str) -> Value {
    let query = uri.split_once('?').unwrap().1;
    let query = query.split_once('#').map_or(query, |(query, _)| query);
    let parameters = query
        .split('&')
        .filter_map(|parameter| parameter.split_once('='))
        .map(|(name, value)| (decode_form(name), Value::String(decode_form(value))))
        .collect();

    Value::Object(parameters)
}

fn decode_form(value: &str) -> String {
    let bytes = value.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        match bytes[index] {
            b'+' => decoded.push(b' '),
            b'%' if index + 2 < bytes.len() => {
                let high = hex(bytes[index + 1]);
                let low = hex(bytes[index + 2]);
                if let (Some(high), Some(low)) = (high, low) {
                    decoded.push(high * 16 + low);
                    index += 2;
                } else {
                    decoded.push(bytes[index]);
                }
            }
            byte => decoded.push(byte),
        }
        index += 1;
    }

    String::from_utf8(decoded).unwrap()
}

fn hex(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn id_token(
    fixture: &AuthorizationFixture,
    subject: &str,
    issuer: &str,
    sub_jwk: Option<Value>,
    overrides: TokenOverrides<'_>,
) -> String {
    let claims = token_claims(fixture, subject, issuer, sub_jwk, overrides);
    let mut header = Header::new(Algorithm::ES256);
    if subject.starts_with("did:key:") {
        header.kid = Some(subject.to_owned());
    }
    encode(
        &header,
        &claims,
        &EncodingKey::from_ec_pem(PRIVATE_KEY).unwrap(),
    )
    .unwrap()
}

fn token_claims(
    fixture: &AuthorizationFixture,
    subject: &str,
    issuer: &str,
    sub_jwk: Option<Value>,
    overrides: TokenOverrides<'_>,
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
    let mut claims = json!({
        "iss": issuer,
        "sub": subject,
        "aud": overrides.audience.unwrap_or(fixture.body["redirect_uri"].as_str().unwrap()),
        "nonce": overrides.nonce.unwrap_or(fixture.body["nonce"].as_str().unwrap()),
        "iat": iat,
        "exp": exp,
    });
    if let Some(sub_jwk) = sub_jwk {
        claims["sub_jwk"] = sub_jwk;
    }
    claims
}

fn signing_jwk() -> Value {
    json!({"kty": "EC", "crv": "P-256", "x": X, "y": Y})
}

fn jwk_thumbprint() -> String {
    let canonical = format!(r#"{{"crv":"P-256","kty":"EC","x":"{X}","y":"{Y}"}}"#);
    URL_SAFE_NO_PAD.encode(digest::digest(&digest::SHA256, canonical.as_bytes()))
}

fn did_key() -> String {
    let mut multicodec_key = vec![0x80, 0x24, 0x03];
    multicodec_key.extend(URL_SAFE_NO_PAD.decode(X).unwrap());
    format!("did:key:z{}", base58btc(&multicodec_key))
}

fn boruta_did_key() -> String {
    let canonical = format!(r#"{{"crv":"P-256","kty":"EC","x":"{X}","y":"{Y}"}}"#);
    jwk_jcs_did_key(&canonical)
}

fn non_canonical_boruta_did_key() -> String {
    let non_canonical = format!(r#"{{"kty":"EC","crv":"P-256","x":"{X}","y":"{Y}"}}"#);
    jwk_jcs_did_key(&non_canonical)
}

fn jwk_jcs_did_key(jwk: &str) -> String {
    let mut multicodec_key = vec![0xd1, 0xd6, 0x03];
    multicodec_key.extend(jwk.as_bytes());
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
    value
        .iter()
        .take_while(|byte| **byte == 0)
        .map(|_| '1')
        .chain(
            digits
                .iter()
                .rev()
                .map(|digit| alphabet[*digit as usize] as char),
        )
        .collect()
}

fn submit(fixture: &AuthorizationFixture, id_token: &str, error: Option<&str>) -> String {
    let mut parameters = Vec::new();
    if !id_token.is_empty() {
        parameters.push(format!("id_token={}", form_encode(id_token)));
    }
    if let Some(error) = error {
        parameters.push(format!("error={}", form_encode(error)));
    }
    post(
        &fixture.callback_path(),
        "application/x-www-form-urlencoded",
        &parameters.join("&"),
    )
}

fn submit_error(
    fixture: &AuthorizationFixture,
    error: &str,
    error_description: Option<&str>,
) -> String {
    let mut body = format!("error={}", form_encode(error));
    if let Some(error_description) = error_description {
        body.push_str("&error_description=");
        body.push_str(&form_encode(error_description));
    }
    post(
        &fixture.callback_path(),
        "application/x-www-form-urlencoded",
        &body,
    )
}

fn post(path: &str, content_type: &str, body: &str) -> String {
    send_request(&format!(
        "POST {path} HTTP/1.1\r\nhost: {HOST}\r\ncontent-type: {content_type}\r\ncontent-length: {}\r\n\r\n{body}",
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

fn assert_authorization_request_html_error(response: &str, description: &str) {
    assert!(
        response.starts_with("HTTP/1.1 400 Bad Request\r\n"),
        "{response}"
    );
    assert!(response.contains("content-type: text/html\r\n"));
    assert!(response.contains("<title>authorization error</title>"));
    assert!(response.contains(description));
    assert!(!response.contains("\r\nlocation:"));
}

fn assert_error(response: &str, description: &str) {
    assert!(
        response.starts_with(&format!(
            "HTTP/1.1 302 Found\r\nlocation: {CLIENT_REDIRECT_URI}?"
        )),
        "{response}"
    );
    let parameters = redirect_parameters(response);
    assert_eq!(parameters["error"], "invalid_request");
    assert_eq!(parameters["error_description"], description);
    assert_eq!(parameters["state"], "client-state");
}

fn assert_html_error(response: &str, description: &str) {
    assert!(
        response.starts_with("HTTP/1.1 400 Bad Request\r\n"),
        "{response}"
    );
    assert!(response.contains("content-type: text/html\r\n"));
    assert!(response.contains(&format!("<p role=\"alert\">{description}</p>")));
}
