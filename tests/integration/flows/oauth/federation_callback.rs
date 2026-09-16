use super::*;

// Branch matrix:
// - method: GET | unsupported
// - authenticated state: valid | missing | invalid
// - restored scope: omitted | authorized (unauthorized values cannot enter authenticated state)
// - presentation continuation: authenticated owner proceeds without a second
//   upstream federation redirect
// - authorization response: code | upstream error | code and error | neither
// - values: non-empty | empty
// - token endpoint: valid token | rejected request | malformed response
// - identity endpoint: multiple valid string claims | rejected request |
//   malformed response | missing or non-string claim
// - resource owner identifier: username | sub fallback | missing
// - artifact inclusion: claim selected for ID token only | credential only | both
// - wallet delivery: QR client with a valid ID-token code redirects directly |
//   missing ID-token code fails wallet binding
// - identity error response: error_description | message | error | HTTP status fallback
// - error destination: validated redirect URI with error, description, and optional
//   client state | local JSON error when callback state is missing or invalid
// The upstream-error cases cover both explicit and fallback descriptions.
// Missing and non-string identity claims intentionally share a validation path and response.

#[test]
fn populates_resource_owner_from_federated_identity() {
    let response = send_callback_request("code=federated-code");

    assert!(response.starts_with("HTTP/1.1 302 Found\r\n"));
    assert!(response.contains("location: https://client.example.com/callback?code="));
    assert!(!response.contains("federated-code"));
    let payload = kagome::resources::authorization_code::decode_cose_payload(
        &authorization_code_from_response(&response),
    )
    .expect("downstream authorization code should decode");
    assert_eq!(payload.username.as_deref(), Some("federated-user"));
}

#[test]
fn accepts_authorized_scope_restored_from_federation_state() {
    let state = federation_state_for(
        "response_type=code&client_id=federated_client&redirect_uri=https%3A%2F%2Fclient.example.com%2Fcallback&scope=openid%20profile",
    );
    let response = send_request(&format!(
        "GET /federation_callback?code=federated-code&state={state} HTTP/1.1\r\nhost: example.com\r\n\r\n"
    ));

    assert!(response.starts_with("HTTP/1.1 302 Found\r\n"));
    assert!(response.contains("location: https://client.example.com/callback?code="));
}

#[test]
fn continues_authenticated_presentation_without_repeating_federation() {
    let state = federation_state_for(
        "response_type=vp_token&client_id=federated_client&redirect_uri=https%3A%2F%2Fclient.example.com%2Fcallback&scope=credential_presentation",
    );
    let response = send_request(&format!(
        "GET /federation_callback?code=federated-code&state={state} HTTP/1.1\r\nhost: example.com\r\n\r\n"
    ));

    assert!(response.starts_with("HTTP/1.1 302 Found\r\n"));
    assert!(response.contains("location: https://client.example.com/callback?"));
    assert!(response.contains("response_type=vp_token"));
    assert!(!response.contains("identity.example.com/authorize"));
}

#[test]
fn signs_federated_resource_owner_profile_in_id_token() {
    let state = federation_state_for(
        "response_type=id_token&client_id=federated_client&redirect_uri=https%3A%2F%2Fclient.example.com%2Fcallback",
    );
    let response = send_request(&format!(
        "GET /federation_callback?code=federated-code&state={state} HTTP/1.1\r\nhost: example.com\r\n\r\n"
    ));
    let id_token = response
        .lines()
        .find_map(|line| line.strip_prefix("location: "))
        .and_then(|location| location.split_once('#'))
        .map(|(_, fragment)| fragment)
        .and_then(|fragment| {
            fragment
                .split('&')
                .filter_map(|parameter| parameter.split_once('='))
                .find_map(|(name, value)| (name == "id_token").then(|| decode_form_value(value)))
        })
        .expect("federated response should contain an id token");
    let mut validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::EdDSA);
    validation.validate_aud = false;
    let payload = jsonwebtoken::decode::<kagome::resources::id_token::IdTokenJwtPayload>(
        &id_token,
        &kagome::resources::crypto::SigningArtifact::IdToken
            .decoding_key()
            .expect("ID token decoding key should load"),
        &validation,
    )
    .expect("federated ID token should have a valid signature")
    .claims;

    assert_eq!(payload.username, "federated-user");
    assert_eq!(payload.profile["username"], "federated-user");
    assert_eq!(payload.profile["sub"], "ignored-user");
    assert!(!payload.profile.contains_key("display_name"));
}

#[test]
fn includes_selected_federated_attributes_in_credential_subject() {
    const GRANT_TYPE: &str = "urn:ietf:params:oauth:grant-type:pre-authorized_code";
    const CONFIGURATION_ID: &str = "UniversityDegreeCredential";
    const SECOND_CONFIGURATION_ID: &str = "EmployeeCredential";
    let state = federation_state_for(
        "response_type=urn%3Aietf%3Aparams%3Aoauth%3Aresponse-type%3Apre-authorized_code&client_id=federated_client&redirect_uri=https%3A%2F%2Fclient.example.com%2Fcallback",
    );
    let callback = send_request(&format!(
        "GET /federation_callback?code=federated-code&state={state} HTTP/1.1\r\nhost: example.com\r\n\r\n"
    ));
    let offer = redirect_parameter(&callback, "credential_offer");
    let offer: serde_json::Value = serde_json::from_str(&offer).unwrap();
    let pre_authorized_code = offer["grants"][GRANT_TYPE]["pre-authorized_code"]
        .as_str()
        .unwrap();
    let token_body =
        format!("grant_type={GRANT_TYPE}&pre-authorized_code={pre_authorized_code}&tx_code=493536");
    let token_response = send_request(&format!(
        "POST /token HTTP/1.1\r\nhost: example.com\r\ncontent-type: application/x-www-form-urlencoded\r\ncontent-length: {}\r\n\r\n{token_body}",
        token_body.len()
    ));
    let access_token = json_response_body(&token_response)["access_token"]
        .as_str()
        .unwrap()
        .to_owned();
    let credential_body =
        serde_json::json!({"credential_identifier": CONFIGURATION_ID}).to_string();
    let credential_response = send_request(&format!(
        "POST /credential HTTP/1.1\r\nhost: example.com\r\ncontent-type: application/json\r\nauthorization: Bearer {access_token}\r\ncontent-length: {}\r\n\r\n{credential_body}",
        credential_body.len()
    ));
    let credential = json_response_body(&credential_response)["credential"]
        .as_str()
        .unwrap()
        .to_owned();
    let mut validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::EdDSA);
    validation.validate_aud = false;
    let claims = jsonwebtoken::decode::<serde_json::Value>(
        &credential,
        &kagome::resources::crypto::SigningArtifact::Credential
            .decoding_key()
            .unwrap(),
        &validation,
    )
    .unwrap()
    .claims;

    for subject in [
        &claims["credentialSubject"][CONFIGURATION_ID],
        &claims["vc"]["credentialSubject"],
    ] {
        assert_eq!(subject["username"], "federated-user");
        assert_eq!(subject["sub"], "ignored-user");
        assert!(subject.get("display_name").is_none());
    }

    let credential_body =
        serde_json::json!({"credential_identifier": SECOND_CONFIGURATION_ID}).to_string();
    let credential_response = send_request(&format!(
        "POST /credential HTTP/1.1\r\nhost: example.com\r\ncontent-type: application/json\r\nauthorization: Bearer {access_token}\r\ncontent-length: {}\r\n\r\n{credential_body}",
        credential_body.len()
    ));
    let employee_credential = json_response_body(&credential_response)["credential"]
        .as_str()
        .unwrap()
        .to_owned();
    let employee_claims = jsonwebtoken::decode::<serde_json::Value>(
        &employee_credential,
        &kagome::resources::crypto::SigningArtifact::Credential
            .decoding_key()
            .unwrap(),
        &validation,
    )
    .unwrap()
    .claims;

    for subject in [
        &employee_claims["credentialSubject"][SECOND_CONFIGURATION_ID],
        &employee_claims["vc"]["credentialSubject"],
    ] {
        assert_eq!(subject["display_name"], "federated-user");
        assert_eq!(subject["username"], "federated-user");
        assert!(subject.get("sub").is_none());
    }
}

#[test]
fn restores_parsed_request_attributes_for_implicit_authorize_continuation() {
    let state = federation_state_for(
        "response_type=token&client_id=federated_client&redirect_uri=https%3A%2F%2Fclient.example.com%2Fcallback&state=client%20state",
    );
    let response = send_request(&format!(
        "GET /federation_callback?code=federated-code&state={state} HTTP/1.1\r\nhost: example.com\r\n\r\n"
    ));

    assert!(response.starts_with("HTTP/1.1 302 Found\r\n"));
    assert!(response.contains("location: https://client.example.com/callback#access_token="));
    assert!(response.contains("&state=client%20state\r\n"));
    assert!(!response.contains("federated-code"));
}

#[test]
fn returns_credential_offer_for_federated_preauthorized_code_request() {
    let state = federation_state_for(
        "response_type=urn%3Aietf%3Aparams%3Aoauth%3Aresponse-type%3Apre-authorized_code&client_id=federated_client&redirect_uri=https%3A%2F%2Fclient.example.com%2Fcallback",
    );
    let response = send_request(&format!(
        "GET /federation_callback?code=federated-code&state={state} HTTP/1.1\r\nhost: example.com\r\n\r\n"
    ));

    assert!(response.starts_with("HTTP/1.1 302 Found\r\n"));
    assert!(response.contains("location: https://client.example.com/callback?credential_offer="));
    assert!(!response.contains("federated-code"));
}

#[test]
fn redirects_qr_federation_callback_with_valid_id_token_code() {
    let authorization_code = authorization_code_for_client_id("federated_qr_client");
    let state = federation_state_for(&format!(
        "response_type=urn%3Aietf%3Aparams%3Aoauth%3Aresponse-type%3Apre-authorized_code&client_id=federated_qr_client&redirect_uri=https%3A%2F%2Ffederated-qr.example.com%2Fcallback&code={authorization_code}",
    ));
    let response = send_request(&format!(
        "GET /federation_callback?code=federated-code&state={state} HTTP/1.1\r\nhost: example.com\r\n\r\n"
    ));

    assert!(response.starts_with("HTTP/1.1 302 Found\r\n"), "{response}");
    assert!(
        response.contains("location: https://federated-qr.example.com/callback?credential_offer="),
        "{response}"
    );
    assert!(!response.contains("<svg"), "{response}");
}

#[test]
fn rejects_qr_federation_callback_without_id_token_code() {
    let state = federation_state_for(
        "response_type=urn%3Aietf%3Aparams%3Aoauth%3Aresponse-type%3Apre-authorized_code&client_id=federated_qr_client&redirect_uri=https%3A%2F%2Ffederated-qr.example.com%2Fcallback",
    );
    let response = send_request(&format!(
        "GET /federation_callback?code=federated-code&state={state} HTTP/1.1\r\nhost: example.com\r\n\r\n"
    ));

    assert!(response.starts_with("HTTP/1.1 302 Found\r\n"), "{response}");
    assert!(response.contains("error=invalid_request"), "{response}");
    assert!(
        response.contains(
            "error_description=wallet%20binding%20requires%20a%20code%20containing%20an%20id_token%20public%20key"
        ),
        "{response}"
    );
}

#[test]
fn rejects_federation_callback_when_token_request_fails() {
    let response = send_callback_request("code=rejected-code");

    assert_callback_error(&response, "invalid_grant", "federated token request failed");
}

#[test]
fn rejects_invalid_federated_token_response() {
    let response = send_callback_request("code=malformed-token");

    assert_callback_error(
        &response,
        "invalid_grant",
        "federated token response is invalid",
    );
}

#[test]
fn rejects_empty_federated_access_token() {
    let response = send_callback_request("code=empty-token");

    assert_callback_error(
        &response,
        "invalid_grant",
        "federated token response is invalid",
    );
}

#[test]
fn rejects_failed_federated_identity_request() {
    let response = send_callback_request("code=identity-rejected");

    assert_callback_error(
        &response,
        "invalid_grant",
        "federated identity request failed: federated access token expired",
    );
}

#[test]
fn returns_federated_identity_error_code() {
    let response = send_callback_request("code=identity-error-code");

    assert_callback_error(
        &response,
        "invalid_grant",
        "federated identity request failed: insufficient_scope",
    );
}

#[test]
fn returns_federated_identity_message() {
    let response = send_callback_request("code=identity-message");

    assert_callback_error(
        &response,
        "invalid_grant",
        "federated identity request failed: profile unavailable",
    );
}

#[test]
fn returns_federated_identity_http_status_without_message() {
    let response = send_callback_request("code=identity-no-message");

    assert_callback_error(
        &response,
        "invalid_grant",
        "federated identity request failed: HTTP 502",
    );
}

#[test]
fn rejects_invalid_federated_identity_response() {
    let response = send_callback_request("code=identity-malformed");

    assert_callback_error(
        &response,
        "invalid_grant",
        "federated identity response is invalid",
    );
}

#[test]
fn rejects_missing_federated_identity_claim() {
    let response = send_callback_request("code=identity-missing-claim");

    assert_callback_error(
        &response,
        "invalid_grant",
        "federated identity claim is missing or invalid",
    );
}

#[test]
fn rejects_missing_later_claim_from_federated_identity_endpoint() {
    let response = send_callback_request("code=identity-missing-second-claim");

    assert_callback_error(
        &response,
        "invalid_grant",
        "federated identity claim is missing or invalid",
    );
}

#[test]
fn rejects_non_string_federated_identity_claim() {
    let response = send_callback_request("code=identity-non-string");

    assert_callback_error(
        &response,
        "invalid_grant",
        "federated identity claim is missing or invalid",
    );
}

#[test]
fn returns_oauth_error_for_federation_callback_error() {
    let response = send_callback_request(
        "error=access_denied&error_description=resource%20owner%20denied%20access",
    );

    assert_callback_error(
        &response,
        "invalid_grant",
        "federated server returned an error: resource owner denied access",
    );
}

#[test]
fn uses_error_code_when_federation_callback_description_is_missing() {
    let response = send_callback_request("error=access_denied");

    assert_callback_error(
        &response,
        "invalid_grant",
        "federated server returned an error: access_denied",
    );
}

#[test]
fn rejects_federation_callback_with_code_and_error() {
    let response = send_callback_request("code=federated-code&error=access_denied");

    assert_callback_error(
        &response,
        "invalid_request",
        "federation callback must not include both code and error",
    );
}

#[test]
fn rejects_federation_callback_without_authorization_response() {
    let response = send_callback_request("");

    assert_callback_error(
        &response,
        "invalid_request",
        "federation callback requires code or error",
    );
}

#[test]
fn rejects_federation_callback_with_empty_code() {
    let response = send_callback_request("code=");

    assert_callback_error(
        &response,
        "invalid_request",
        "federation callback code must not be empty",
    );
}

#[test]
fn rejects_federation_callback_with_empty_error() {
    let response = send_callback_request("error=");

    assert_callback_error(
        &response,
        "invalid_request",
        "federation callback error must not be empty",
    );
}

#[test]
fn redirects_federation_callback_error_with_client_state() {
    let state = federation_state_for(
        "response_type=code&client_id=federated_client&redirect_uri=https%3A%2F%2Fclient.example.com%2Fcallback&state=client%20state",
    );
    let response = send_request(&format!(
        "GET /federation_callback?error=access_denied&state={state} HTTP/1.1\r\nhost: example.com\r\n\r\n"
    ));
    let parameters = callback_error_parameters(&response);

    assert_eq!(
        parameters.get("state").map(String::as_str),
        Some("client state")
    );
}

#[test]
fn rejects_federation_callback_without_state() {
    let response = send_request(
        "GET /federation_callback?code=federated-code HTTP/1.1\r\nhost: example.com\r\n\r\n",
    );

    assert!(response.starts_with("HTTP/1.1 400 Bad Request\r\n"));
    assert!(response.contains("\"error\":\"invalid_request\""));
    assert!(response.contains("federation callback state is invalid or expired"));
}

#[test]
fn rejects_federation_callback_with_invalid_state() {
    let response = send_request(
        "GET /federation_callback?code=federated-code&state=invalid HTTP/1.1\r\nhost: example.com\r\n\r\n",
    );

    assert!(response.starts_with("HTTP/1.1 400 Bad Request\r\n"));
    assert!(response.contains("\"error\":\"invalid_request\""));
    assert!(response.contains("federation callback state is invalid or expired"));
}

#[test]
fn returns_not_found_for_federation_callback_post() {
    let response = send_request(
        "POST /federation_callback HTTP/1.1\r\nhost: example.com\r\ncontent-length: 0\r\n\r\n",
    );

    assert!(response.starts_with("HTTP/1.1 404 Not Found\r\n"));
}

fn send_callback_request(query: &str) -> String {
    let state = federation_state();
    let separator = if query.is_empty() { "" } else { "&" };

    send_request(&format!(
        "GET /federation_callback?{query}{separator}state={state} HTTP/1.1\r\nhost: example.com\r\n\r\n"
    ))
}

fn federation_state() -> String {
    federation_state_for(
        "response_type=code&client_id=federated_client&redirect_uri=https%3A%2F%2Fclient.example.com%2Fcallback",
    )
}

fn federation_state_for(authorize_query: &str) -> String {
    let response = send_request(&format!(
        "GET /authorize?{authorize_query} HTTP/1.1\r\nhost: example.com\r\n\r\n"
    ));
    let location = response
        .lines()
        .find_map(|line| line.strip_prefix("location: "))
        .expect("federated authorization response should contain a location");

    location
        .split_once('?')
        .expect("federated authorization location should contain a query")
        .1
        .split('&')
        .find_map(|parameter| parameter.strip_prefix("state="))
        .expect("federated authorization location should contain state")
        .to_owned()
}

fn authorization_code_from_response(response: &str) -> String {
    response
        .lines()
        .find_map(|line| line.strip_prefix("location: "))
        .and_then(|location| location.split_once('?'))
        .map(|(_, query)| query)
        .and_then(|query| {
            query
                .split('&')
                .find_map(|value| value.strip_prefix("code="))
        })
        .expect("downstream authorization response should contain a code")
        .to_owned()
}

fn redirect_parameter(response: &str, name: &str) -> String {
    response
        .lines()
        .find_map(|line| line.strip_prefix("location: "))
        .and_then(|location| location.split_once('?'))
        .map(|(_, query)| query)
        .and_then(|query| {
            query.split('&').find_map(|parameter| {
                parameter
                    .split_once('=')
                    .filter(|(parameter_name, _)| *parameter_name == name)
                    .map(|(_, value)| decode_form_value(value))
            })
        })
        .expect("redirect response should contain parameter")
}

fn json_response_body(response: &str) -> serde_json::Value {
    serde_json::from_str(response.split_once("\r\n\r\n").unwrap().1).unwrap()
}

fn assert_callback_error(response: &str, error: &str, description: &str) {
    let parameters = callback_error_parameters(response);

    assert_eq!(parameters.get("error").map(String::as_str), Some(error));
    assert_eq!(
        parameters.get("error_description").map(String::as_str),
        Some(description)
    );
    assert!(!parameters.contains_key("state"));
}

fn callback_error_parameters(response: &str) -> std::collections::BTreeMap<String, String> {
    assert!(response.starts_with("HTTP/1.1 302 Found\r\n"), "{response}");
    let location = response
        .lines()
        .find_map(|line| line.strip_prefix("location: "))
        .expect("callback error response should contain a location");
    assert!(location.starts_with("https://client.example.com/callback?"));

    location
        .split_once('?')
        .unwrap()
        .1
        .split('&')
        .filter_map(|parameter| parameter.split_once('='))
        .map(|(name, value)| (decode_form_value(name), decode_form_value(value)))
        .collect()
}

fn decode_form_value(value: &str) -> String {
    let bytes = value.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
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
