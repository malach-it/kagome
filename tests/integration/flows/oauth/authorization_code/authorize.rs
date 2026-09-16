use super::super::*;

// Branch matrix:
// - method: GET | POST | unsupported
// - response_type: code | token | id_token | standalone pre-authorized_code |
//   supported hybrid combinations | chained code | missing | unsupported | invalid ordering
// - resource owner: form credentials | client_id credentials | missing | invalid
// - client_id: local | second local | federated | public username@host |
//   resource-owner form | missing | unconfigured
// - client response policy: all requested types supported | one requested type unsupported
// - scope: omitted | authorized | unauthorized
// - redirect_uri: matching first URI | matching alternate URI | another client's URI |
//   missing | invalid
// - metadata policy: missing | valid string | valid username superset | invalid |
//   username mismatch
// - PKCE when response_type contains code: valid S256 | absent | missing challenge |
//   missing method | unsupported method | malformed challenge
// - authorization-code chain depth: below maximum | exactly maximum | exceeding maximum
// - authorization-code redemption: first generated response succeeds | repeated response
//   generation is rejected by the process-local replay store
// - client state: absent | exact value returned in query for code and error responses |
//   exact value returned in the fragment for implicit and hybrid responses. A state supplied
//   with an untrusted redirect URI is intentionally not returned.
// - generated artifacts: COSE_Encrypt0 code/access token | EdDSA ID token
// - federation: configured redirect | local authentication not implemented
//   Federated clients ignore local credentials until the upstream authenticates them.
// Authorization errors without state render as HTML. Errors with state redirect only when the
// client and redirect URI can be independently trusted. Public client response representations
// are covered here for code, by implicit tests for token, and by OID4VCI tests for
// pre-authorized_code.

#[test]
fn redirects_authorize_get_request_to_federated_server() {
    let response = send_authorize_request(&format!(
        "response_type=code&client_id=federated_client&redirect_uri={}",
        valid_redirect_uri()
    ));

    assert_federated_authorize_redirect(&response);
}

#[test]
fn requires_federation_even_when_get_request_contains_local_credentials() {
    let response = send_authorize_request(&format!(
        "response_type=code&client_id=federated_client&redirect_uri={}&username=username&password=password",
        valid_redirect_uri()
    ));

    assert_federated_authorize_redirect(&response);
}

#[test]
fn accepts_authorized_scope_for_authorize_get_request() {
    let response = send_authorize_request(&format!(
        "response_type=code&client_id=federated_client&redirect_uri={}&scope=openid%20profile",
        valid_redirect_uri()
    ));

    assert_federated_authorize_redirect(&response);
}

#[test]
fn rejects_unauthorized_scope_for_authorize_get_and_post_requests() {
    let query = format!(
        "response_type=code&client_id=client_id&redirect_uri={}&scope=admin",
        valid_redirect_uri()
    );

    for response in [
        send_authorize_request(&query),
        send_post_authorize_request(&query),
    ] {
        assert!(response.starts_with("HTTP/1.1 400 Bad Request\r\n"));
        assert!(
            response.contains("<p role=\"alert\">scope is not authorized for client: admin</p>")
        );
    }
}

#[test]
fn rejects_authorize_post_request_for_federated_client() {
    let response = send_post_authorize_request(&format!(
        "response_type=code&client_id=federated_client&redirect_uri={}",
        valid_redirect_uri()
    ));

    assert!(response.starts_with("HTTP/1.1 400 Bad Request\r\n"));
    assert!(response.contains("content-type: text/html\r\n"));
    assert!(
        response
            .contains("<p role=\"alert\">POST /authorize is disabled for federated clients</p>")
    );
}

#[test]
fn returns_not_implemented_for_authorize_get_request_with_metadata_policy() {
    let response = send_authorize_request(&format!(
        "response_type=code&client_id=client_id&redirect_uri={}&metadata_policy=%22profile%22",
        valid_redirect_uri()
    ));

    assert_not_implemented(&response);
}

#[test]
fn returns_not_implemented_for_authorize_get_request_with_metadata_policy_username_superset() {
    let first_response = send_post_authorize_request(&format!(
        "response_type=code+code&client_id=client_id&redirect_uri={}",
        valid_redirect_uri()
    ));
    let next_query = authorize_redirect_query(&first_response)
        .expect("first authorize redirect should include query");
    let response = send_authorize_request(&format!(
        "{next_query}&metadata_policy=%7B%22username%22%3A%7B%22superset_of%22%3A%5B%22username%22%5D%7D%7D"
    ));

    assert_not_implemented(&response);
}

#[test]
fn redirects_to_client_redirect_uri_for_post_authorize_code_response_type() {
    let response = send_post_authorize_request(&format!(
        "response_type=code&client_id=client_id&redirect_uri={}",
        valid_redirect_uri()
    ));

    assert!(response.starts_with("HTTP/1.1 302 Found\r\n"));
    assert!(response.contains("location: https://client.example.com/callback?code="));
    assert!(response.contains("content-length: 0\r\n"));
    assert!(response.contains("connection: close\r\n"));
}

#[test]
fn returns_exact_state_for_every_successful_authorization_response_type() {
    const STATE: &str = "opaque+state &=/%";
    const ENCODED_STATE: &str = "opaque%2Bstate%20%26%3D%2F%25";

    for response_type in [
        "code",
        "token",
        "id_token",
        "code+token",
        "code+id_token",
        "id_token+token",
        "code+id_token+token",
    ] {
        let response = send_post_authorize_request(&format!(
            "response_type={response_type}&client_id=client_id&redirect_uri={}&state={ENCODED_STATE}",
            valid_redirect_uri()
        ));
        let returned_state = if response_type == "code" {
            redirect_query_parameter(&response, "state")
        } else {
            redirect_fragment_parameter(&response, "state")
        };

        assert!(response.starts_with("HTTP/1.1 302 Found\r\n"), "{response}");
        assert_eq!(returned_state.as_deref(), Some(STATE), "{response_type}");
    }
}

#[test]
fn returns_exact_state_in_trusted_authorization_error_response() {
    let response = send_authorize_request(&format!(
        "response_type=unsupported&client_id=client_id&redirect_uri={}&state=opaque%2Bstate%20%26%3D%2F%25",
        valid_redirect_uri()
    ));

    assert!(response.starts_with("HTTP/1.1 302 Found\r\n"));
    assert_eq!(
        redirect_query_parameter(&response, "state").as_deref(),
        Some("opaque+state &=/%")
    );
    assert_eq!(
        redirect_query_parameter(&response, "error").as_deref(),
        Some("unsupported_response_type")
    );
}

#[test]
fn does_not_return_state_to_untrusted_authorization_error_redirect_uri() {
    let response = send_authorize_request(
        "response_type=unsupported&client_id=client_id&redirect_uri=https%3A%2F%2Fattacker.example%2Fcallback&state=opaque%2Bstate",
    );

    assert_authorize_html_error(&response, "response_type must be one of:");
    assert!(!response.contains("opaque+state"));
}

#[test]
fn redirects_to_alternate_uri_for_second_configured_client() {
    let response = send_post_authorize_request(
        "response_type=code&client_id=configured_client&redirect_uri=https%3A%2F%2Fconfigured.example.com%2Falternate",
    );

    assert!(response.starts_with("HTTP/1.1 302 Found\r\n"));
    assert!(response.contains("location: https://configured.example.com/alternate?code="));
}

#[test]
fn accepts_response_type_supported_by_client() {
    let response = send_post_authorize_request(
        "response_type=code&client_id=restricted_client&redirect_uri=https%3A%2F%2Frestricted.example.com%2Fcallback",
    );

    assert!(response.starts_with("HTTP/1.1 302 Found\r\n"));
    assert!(response.contains("location: https://restricted.example.com/callback?code="));
}

#[test]
fn rejects_response_type_not_supported_by_client() {
    let response = send_authorize_request(
        "response_type=token&client_id=restricted_client&redirect_uri=https%3A%2F%2Frestricted.example.com%2Fcallback",
    );

    assert!(response.starts_with("HTTP/1.1 400 Bad Request\r\n"));
    assert!(response.contains("content-type: text/html\r\n"));
    assert!(response.contains("<p role=\"alert\">client does not support response_type token</p>"));
}

#[test]
fn rejects_hybrid_response_when_one_type_is_not_supported_by_client() {
    let response = send_authorize_request(
        "response_type=code+token&client_id=restricted_client&redirect_uri=https%3A%2F%2Frestricted.example.com%2Fcallback",
    );

    assert!(response.starts_with("HTTP/1.1 400 Bad Request\r\n"));
    assert!(response.contains("content-type: text/html\r\n"));
    assert!(response.contains("<p role=\"alert\">client does not support response_type token</p>"));
}

#[test]
fn redirects_to_client_redirect_uri_with_id_token_for_post_authorize_id_token_response_type() {
    let response = send_post_authorize_request(&format!(
        "response_type=id_token&client_id=client_id&redirect_uri={}",
        valid_redirect_uri()
    ));
    let id_token = redirect_fragment_parameter(&response, "id_token")
        .expect("redirect should include id token");
    let expires_in =
        redirect_fragment_parameter(&response, "expires_in").expect("redirect should include ttl");
    let payload = decode_id_token_payload(&id_token);

    assert!(response.starts_with("HTTP/1.1 302 Found\r\n"));
    assert!(response.contains("location: https://client.example.com/callback#id_token="));
    assert_eq!(expires_in, "3600");
    assert_eq!(payload.iss, "http://localhost:4000");
    assert_eq!(payload.sub, "username");
    assert_eq!(payload.aud, "client_id");
    assert_eq!(payload.client_id, "client_id");
    assert_eq!(payload.username, "username");
    assert_eq!(payload.profile["username"], "username");
}

#[test]
fn redirects_to_client_redirect_uri_with_id_token_for_client_id_resource_owner_credentials() {
    let response = send_authorize_request(&format!(
        "response_type=id_token&client_id=other_username%3Aother_password%40example.com&redirect_uri={}",
        valid_redirect_uri()
    ));
    let id_token = redirect_fragment_parameter(&response, "id_token")
        .expect("redirect should include id token");
    let payload = decode_id_token_payload(&id_token);

    assert!(response.starts_with("HTTP/1.1 302 Found\r\n"));
    assert!(response.contains("location: https://client.example.com/callback#id_token="));
    assert_eq!(payload.client_id, "other_username@example.com");
    assert_eq!(payload.username, "other_username");
    assert_eq!(payload.profile["username"], "other_username");
}

#[test]
fn redirects_to_client_redirect_uri_with_id_token_and_access_token_for_post_authorize_id_token_token_response_type()
 {
    let response = send_post_authorize_request(&format!(
        "response_type=id_token+token&client_id=client_id&redirect_uri={}",
        valid_redirect_uri()
    ));
    let id_token = redirect_fragment_parameter(&response, "id_token")
        .expect("redirect should include id token");
    let access_token = redirect_fragment_parameter(&response, "access_token")
        .expect("redirect should include token");
    let expires_in =
        redirect_fragment_parameter(&response, "expires_in").expect("redirect should include ttl");
    let id_token_payload = decode_id_token_payload(&id_token);
    let access_token_payload = decode_access_token_payload(&access_token);

    assert!(response.starts_with("HTTP/1.1 302 Found\r\n"));
    assert!(response.contains("location: https://client.example.com/callback#id_token="));
    assert!(response.contains("&access_token="));
    assert_eq!(expires_in, "3600");
    assert_eq!(id_token_payload.client_id, "client_id");
    assert_eq!(id_token_payload.username, "username");
    assert_eq!(access_token_payload.client_id, "client_id");
}

#[test]
fn redirects_to_client_redirect_uri_with_code_and_access_token_for_post_authorize_code_token_response_type()
 {
    let response = send_post_authorize_request(&format!(
        "response_type=code+token&client_id=client_id&redirect_uri={}",
        valid_redirect_uri()
    ));
    let _code = redirect_code(&response).expect("redirect should include code");
    let access_token = redirect_fragment_parameter(&response, "access_token")
        .expect("redirect should include token");
    let expires_in =
        redirect_fragment_parameter(&response, "expires_in").expect("redirect should include ttl");
    let token_payload = decode_access_token_payload(&access_token);

    assert!(response.starts_with("HTTP/1.1 302 Found\r\n"));
    assert!(response.contains("location: https://client.example.com/callback?code="));
    assert!(response.contains("#access_token="));
    assert_eq!(expires_in, "3600");
    assert_eq!(token_payload.client_id, "client_id");
}

#[test]
fn redirects_to_client_redirect_uri_with_code_and_id_token_for_post_authorize_code_id_token_response_type()
 {
    let response = send_post_authorize_request(&format!(
        "response_type=code+id_token&client_id=client_id&redirect_uri={}",
        valid_redirect_uri()
    ));
    let _code = redirect_code(&response).expect("redirect should include code");
    let id_token = redirect_fragment_parameter(&response, "id_token")
        .expect("redirect should include id token");
    let token_payload = decode_id_token_payload(&id_token);

    assert!(response.starts_with("HTTP/1.1 302 Found\r\n"));
    assert!(response.contains("location: https://client.example.com/callback?code="));
    assert!(response.contains("#id_token="));
    assert_eq!(token_payload.client_id, "client_id");
    assert_eq!(token_payload.username, "username");
}

#[test]
fn redirects_to_client_redirect_uri_with_code_id_token_and_access_token_for_post_authorize_code_id_token_token_response_type()
 {
    let response = send_post_authorize_request(&format!(
        "response_type=code+id_token+token&client_id=client_id&redirect_uri={}",
        valid_redirect_uri()
    ));
    let _code = redirect_code(&response).expect("redirect should include code");
    let id_token = redirect_fragment_parameter(&response, "id_token")
        .expect("redirect should include id token");
    let access_token = redirect_fragment_parameter(&response, "access_token")
        .expect("redirect should include token");
    let id_token_payload = decode_id_token_payload(&id_token);
    let access_token_payload = decode_access_token_payload(&access_token);

    assert!(response.starts_with("HTTP/1.1 302 Found\r\n"));
    assert!(response.contains("location: https://client.example.com/callback?code="));
    assert!(response.contains("#access_token="));
    assert!(response.contains("&id_token="));
    assert_eq!(id_token_payload.client_id, "client_id");
    assert_eq!(id_token_payload.username, "username");
    assert_eq!(access_token_payload.client_id, "client_id");
}

#[test]
fn redirects_to_client_redirect_uri_with_code_and_access_token_for_get_authorize_code_token_response_type_with_client_id_resource_owner_credentials()
 {
    let response = send_authorize_request(&format!(
        "response_type=code+token&client_id=other_username%3Aother_password%40example.com&redirect_uri={}",
        valid_redirect_uri()
    ));
    let _code = redirect_code(&response).expect("redirect should include code");
    let access_token = redirect_fragment_parameter(&response, "access_token")
        .expect("redirect should include token");
    let token_payload = decode_access_token_payload(&access_token);

    assert!(response.starts_with("HTTP/1.1 302 Found\r\n"));
    assert!(response.contains("location: https://client.example.com/callback?code="));
    assert!(response.contains("#access_token="));
    assert_eq!(token_payload.client_id, "other_username@example.com");
}

#[test]
fn redirects_to_client_redirect_uri_with_code_and_id_token_for_get_authorize_code_id_token_response_type_with_client_id_resource_owner_credentials()
 {
    let response = send_authorize_request(&format!(
        "response_type=code+id_token&client_id=other_username%3Aother_password%40example.com&redirect_uri={}",
        valid_redirect_uri()
    ));
    let _code = redirect_code(&response).expect("redirect should include code");
    let id_token = redirect_fragment_parameter(&response, "id_token")
        .expect("redirect should include id token");
    let token_payload = decode_id_token_payload(&id_token);

    assert!(response.starts_with("HTTP/1.1 302 Found\r\n"));
    assert!(response.contains("location: https://client.example.com/callback?code="));
    assert!(response.contains("#id_token="));
    assert_eq!(token_payload.client_id, "other_username@example.com");
    assert_eq!(token_payload.username, "other_username");
}

#[test]
fn public_client_uses_hybrid_id_token_and_code_to_start_code_chain_without_secret() {
    let authorize_response = send_authorize_request(&format!(
        "response_type=code+id_token&client_id=other_username%3Aother_password%40example.com&redirect_uri={}&scope=openid",
        valid_redirect_uri()
    ));
    let code = redirect_code(&authorize_response).expect("hybrid response should include code");
    let id_token = redirect_fragment_parameter(&authorize_response, "id_token")
        .expect("hybrid response should include id_token");
    let response = send_form_token_request(&format!(
        "client_id=other_username%40example.com&grant_type=code_chain&id_token={}&authorization_code={}&scope=openid",
        encode_form_value(&id_token),
        encode_form_value(&code)
    ));

    assert!(response.starts_with("HTTP/1.1 200 OK\r\n"));
    assert!(response.contains("\"authorization_code\":\""));
}

#[test]
fn redirects_to_client_redirect_uri_with_code_id_token_and_access_token_for_get_authorize_code_id_token_token_response_type_with_client_id_resource_owner_credentials()
 {
    let response = send_authorize_request(&format!(
        "response_type=code+id_token+token&client_id=other_username%3Aother_password%40example.com&redirect_uri={}",
        valid_redirect_uri()
    ));
    let _code = redirect_code(&response).expect("redirect should include code");
    let id_token = redirect_fragment_parameter(&response, "id_token")
        .expect("redirect should include id token");
    let access_token = redirect_fragment_parameter(&response, "access_token")
        .expect("redirect should include token");
    let id_token_payload = decode_id_token_payload(&id_token);
    let access_token_payload = decode_access_token_payload(&access_token);

    assert!(response.starts_with("HTTP/1.1 302 Found\r\n"));
    assert!(response.contains("location: https://client.example.com/callback?code="));
    assert!(response.contains("#access_token="));
    assert!(response.contains("&id_token="));
    assert_eq!(id_token_payload.client_id, "other_username@example.com");
    assert_eq!(id_token_payload.username, "other_username");
    assert_eq!(access_token_payload.client_id, "other_username@example.com");
}

#[test]
fn redirects_to_client_redirect_uri_with_id_token_and_access_token_for_get_authorize_id_token_token_response_type_with_client_id_resource_owner_credentials()
 {
    let response = send_authorize_request(&format!(
        "response_type=id_token+token&client_id=other_username%3Aother_password%40example.com&redirect_uri={}",
        valid_redirect_uri()
    ));
    let id_token = redirect_fragment_parameter(&response, "id_token")
        .expect("redirect should include id token");
    let access_token = redirect_fragment_parameter(&response, "access_token")
        .expect("redirect should include token");
    let id_token_payload = decode_id_token_payload(&id_token);
    let access_token_payload = decode_access_token_payload(&access_token);

    assert!(response.starts_with("HTTP/1.1 302 Found\r\n"));
    assert!(response.contains("location: https://client.example.com/callback#id_token="));
    assert!(response.contains("&access_token="));
    assert_eq!(id_token_payload.client_id, "other_username@example.com");
    assert_eq!(id_token_payload.username, "other_username");
    assert_eq!(access_token_payload.client_id, "other_username@example.com");
}

#[test]
fn redirects_to_client_redirect_uri_for_other_resource_owner() {
    let response = send_post_authorize_request_with_body(
        &format!(
            "response_type=code&client_id=client_id&redirect_uri={}",
            valid_redirect_uri()
        ),
        "username=other_username&password=other_password",
    );
    let code = redirect_code(&response).expect("authorize redirect should include code");

    assert!(response.starts_with("HTTP/1.1 302 Found\r\n"));
    assert!(response.contains("location: https://client.example.com/callback?code="));
    assert!(!code.is_empty());
}

#[test]
fn authenticates_resource_owner_from_client_id_credentials() {
    let second_response = send_post_authorize_request_with_body(
        &format!(
            "response_type=code&client_id=other_username%3Aother_password%40example.com&redirect_uri={}",
            valid_redirect_uri()
        ),
        "",
    );
    let code = redirect_code(&second_response).expect("final redirect should include code");

    assert!(second_response.starts_with("HTTP/1.1 302 Found\r\n"));
    assert!(second_response.contains("location: https://client.example.com/callback?code="));
    assert!(!code.is_empty());
}

#[test]
fn redirects_back_to_authorize_for_intermediate_code_response_type() {
    let response = send_post_authorize_request(&format!(
        "response_type=code+code&client_id=client_id&redirect_uri={}",
        valid_redirect_uri()
    ));

    assert!(response.starts_with("HTTP/1.1 302 Found\r\n"));
    assert!(response.contains("location: /authorize?"));
    assert!(response.contains("response_type=code"));
    assert!(response.contains("client_id=client_id"));
    assert!(response.contains("redirect_uri=https%3A%2F%2Fclient.example.com%2Fcallback"));
    assert!(response.contains("code="));
    assert!(response.contains("content-length: 0\r\n"));
}

#[test]
fn returns_not_implemented_for_authorize_get_request_with_code() {
    let first_response = send_post_authorize_request(&format!(
        "response_type=code+code&client_id=client_id&redirect_uri={}",
        valid_redirect_uri()
    ));
    let next_query = authorize_redirect_query(&first_response)
        .expect("first authorize redirect should include query");
    let response = send_authorize_request(&next_query);

    assert_not_implemented(&response);
}

#[test]
fn redirects_for_authorize_get_request_with_client_id_resource_owner_credentials() {
    let response = send_authorize_request(&format!(
        "response_type=code&client_id=other_username%3Aother_password%40example.com&redirect_uri={}",
        valid_redirect_uri()
    ));
    let code = redirect_code(&response).expect("authorize redirect should include code");

    assert!(response.starts_with("HTTP/1.1 302 Found\r\n"));
    assert!(response.contains("location: https://client.example.com/callback?code="));
    assert!(!code.is_empty());
}

#[test]
fn redirects_for_initial_authorize_get_request_with_client_id_resource_owner_credentials() {
    let response = send_authorize_request(&format!(
        "response_type=code&client_id=other_username%3Aother_password%40example.com&redirect_uri={}",
        valid_redirect_uri()
    ));
    let code = redirect_code(&response).expect("authorize redirect should include code");

    assert!(response.starts_with("HTTP/1.1 302 Found\r\n"));
    assert!(response.contains("location: https://client.example.com/callback?code="));
    assert!(!code.is_empty());
}

#[test]
fn returns_not_implemented_for_authorize_get_request_with_missing_client_id_resource_owner_password()
 {
    let response = send_authorize_request(&format!(
        "response_type=code&client_id=other_username%3A%40example.com&redirect_uri={}",
        valid_redirect_uri()
    ));

    assert_not_implemented(&response);
}

#[test]
fn authenticates_authorize_get_request_with_public_username_host_client_id() {
    let response = send_request(&format!(
        "GET /authorize?response_type=code&client_id=username%40example.com&redirect_uri={}&code_challenge={PKCE_CHALLENGE}&code_challenge_method=S256 HTTP/1.1\r\nhost: example.com\r\n\r\n",
        valid_redirect_uri()
    ));
    let code = redirect_code(&response).expect("public client response should include code");
    let payload = kagome::resources::authorization_code::decode_cose_payload(&code)
        .expect("public client authorization code should decrypt");

    assert!(response.starts_with("HTTP/1.1 302 Found\r\n"));
    assert_eq!(payload.client_id, "username@example.com");
    assert_eq!(payload.username.as_deref(), Some("username"));
}

#[test]
fn rejects_public_username_host_client_id_with_another_clients_redirect_uri() {
    let response = send_request(
        "GET /authorize?response_type=code&client_id=username%40example.com&redirect_uri=https%3A%2F%2Fconfigured.example.com%2Fcallback HTTP/1.1\r\nhost: example.com\r\n\r\n",
    );

    assert!(response.starts_with("HTTP/1.1 400 Bad Request\r\n"));
    assert!(response.contains("<p role=\"alert\">redirect_uri is invalid</p>"));
}

#[test]
fn rejects_username_host_client_id_without_matching_public_configuration() {
    let response = send_request(&format!(
        "GET /authorize?response_type=code&client_id=username%40other.example.com&redirect_uri={} HTTP/1.1\r\nhost: other.example.com\r\n\r\n",
        valid_redirect_uri()
    ));

    assert!(response.starts_with("HTTP/1.1 400 Bad Request\r\n"));
    assert!(response.contains("<p role=\"alert\">client_id is invalid</p>"));
}

#[test]
fn redirects_for_authorize_post_request_with_matching_username_host_client_id() {
    let response = send_post_authorize_request_with_body(
        &format!(
            "response_type=code&client_id=username%40example.com&redirect_uri={}",
            valid_redirect_uri()
        ),
        "username=username&password=password",
    );
    let code = redirect_code(&response).expect("authorize redirect should include code");

    assert!(response.starts_with("HTTP/1.1 302 Found\r\n"));
    assert!(response.contains("location: https://client.example.com/callback?code="));
    assert!(!code.is_empty());
}

#[test]
fn redirects_for_authorize_post_request_with_client_id_username_over_body_username() {
    let response = send_post_authorize_request_with_body(
        &format!(
            "response_type=code&client_id=username%40example.com&redirect_uri={}",
            valid_redirect_uri()
        ),
        "username=other_username&password=password",
    );
    let code = redirect_code(&response).expect("authorize redirect should include code");

    assert!(response.starts_with("HTTP/1.1 302 Found\r\n"));
    assert!(response.contains("location: https://client.example.com/callback?code="));
    assert!(!code.is_empty());
}

#[test]
fn returns_oauth_error_for_invalid_authorize_get_code() {
    let response = send_authorize_request(&format!(
        "response_type=code&client_id=client_id&redirect_uri={}&code=app",
        valid_redirect_uri()
    ));

    assert!(response.starts_with("HTTP/1.1 400 Bad Request\r\n"));
    assert!(response.contains("content-type: text/html\r\n"));
    assert!(response.contains("<title>authorization error</title>"));
    assert!(response.contains("<p role=\"alert\">authorization_code must be a cose_encrypt0</p>"));
    assert!(!response.contains("<form"));
}

#[test]
fn returns_oauth_error_for_authorize_get_client_id_resource_owner_credentials() {
    let response = send_authorize_request(&format!(
        "response_type=code&client_id=other_username%3Aapp%40example.com&redirect_uri={}",
        valid_redirect_uri()
    ));

    assert_authorize_html_error(&response, "username or password is invalid");
}

#[test]
fn renders_html_error_for_missing_response_type_with_client_id_resource_owner_credentials() {
    let response = send_authorize_request(&format!(
        "client_id=other_username%3Aother_password%40example.com&redirect_uri={}",
        valid_redirect_uri()
    ));

    assert_authorize_html_error(&response, "response_type must be one of:");
}

#[test]
fn renders_html_error_for_invalid_final_response_type_with_client_id_resource_owner_credentials() {
    let response = send_authorize_request(&format!(
        "response_type=id_token+code&client_id=other_username%3Aother_password%40example.com&redirect_uri={}",
        valid_redirect_uri()
    ));

    assert_authorize_html_error(&response, "invalid final response type");
}

#[test]
fn renders_html_error_for_invalid_redirect_uri_with_client_id_resource_owner_credentials() {
    let response = send_authorize_request(
        "response_type=code&client_id=other_username%3Aother_password%40example.com&redirect_uri=https%3A%2F%2Fapp.example.com%2Fcallback",
    );

    assert!(response.starts_with("HTTP/1.1 400 Bad Request\r\n"));
    assert!(response.contains("content-type: text/html\r\n"));
    assert!(response.contains("<p role=\"alert\">redirect_uri is invalid</p>"));
    assert!(!response.contains("location:"));
}

#[test]
fn renders_html_error_for_query_format_with_untrusted_redirect_uri() {
    let response = send_authorize_request(
        "response_type=app&client_id=client_id&redirect_uri=https%3A%2F%2Fattacker.example.com%2Fcallback&format=query",
    );

    assert!(response.starts_with("HTTP/1.1 400 Bad Request\r\n"));
    assert!(response.contains("content-type: text/html\r\n"));
    assert!(response.contains("<p role=\"alert\">response_type must be one of:"));
    assert!(!response.contains("location:"));
}

#[test]
fn renders_html_error_for_authorize_get_client_id_resource_owner_username() {
    let response = send_authorize_request(&format!(
        "response_type=code&client_id=app%3Apassword%40example.com&redirect_uri={}",
        valid_redirect_uri()
    ));

    assert_authorize_html_error(&response, "username or password is invalid");
}

#[test]
fn redirects_to_client_redirect_uri_for_last_code_response_type() {
    let first_response = send_post_authorize_request(&format!(
        "response_type=code+code&client_id=client_id&redirect_uri={}",
        valid_redirect_uri()
    ));
    let next_query = authorize_redirect_query(&first_response)
        .expect("first authorize redirect should include query");
    let previous_code = query_parameter(&next_query, "code").expect("redirect should include code");
    let second_response = send_post_authorize_request(&next_query);
    let code = redirect_code(&second_response).expect("final redirect should include code");

    assert!(second_response.starts_with("HTTP/1.1 302 Found\r\n"));
    assert!(second_response.contains("location: https://client.example.com/callback?code="));
    assert!(!previous_code.is_empty());
    assert!(!code.is_empty());
}

#[test]
fn rejects_repeated_authorization_response_generation_from_the_same_code() {
    let first_response = send_post_authorize_request(&format!(
        "response_type=code+code&client_id=client_id&redirect_uri={}",
        valid_redirect_uri()
    ));
    let next_query = authorize_redirect_query(&first_response)
        .expect("first authorize redirect should include query");

    let success = send_post_authorize_request(&next_query);
    let replay = send_post_authorize_request(&next_query);

    assert!(success.starts_with("HTTP/1.1 302 Found\r\n"), "{success}");
    assert!(success.contains("location: https://client.example.com/callback?code="));
    assert!(
        replay.starts_with("HTTP/1.1 400 Bad Request\r\n"),
        "{replay}"
    );
    assert!(replay.contains("authorization_code has already been used"));
}

#[test]
fn redirects_back_to_authorize_until_final_code_response_type() {
    let first_response = send_post_authorize_request(&format!(
        "response_type=code+code+code&client_id=client_id&redirect_uri={}",
        valid_redirect_uri()
    ));
    let second_query = authorize_redirect_query(&first_response)
        .expect("first authorize redirect should include query");
    let first_code = query_parameter(&second_query, "code").expect("redirect should include code");

    assert!(second_query.contains("response_type=code%20code"));

    let second_response = send_post_authorize_request(&second_query);
    let third_query = authorize_redirect_query(&second_response)
        .expect("second authorize redirect should include query");
    let second_code = query_parameter(&third_query, "code").expect("redirect should include code");

    assert!(third_query.contains("response_type=code"));
    assert!(!first_code.is_empty());
    assert!(!second_code.is_empty());

    let third_response = send_post_authorize_request(&third_query);
    let final_code = redirect_code(&third_response).expect("final redirect should include code");

    assert!(third_response.starts_with("HTTP/1.1 302 Found\r\n"));
    assert!(third_response.contains("location: https://client.example.com/callback?code="));
    assert!(!final_code.is_empty());
}

#[test]
fn accepts_authorization_code_chain_at_maximum_depth() {
    let maximum_depth = kagome::config::DEFAULT_AUTHORIZATION_CODE_CHAIN_MAX_DEPTH;
    let response_type = vec!["code"; maximum_depth].join("+");
    let mut response = send_post_authorize_request(&format!(
        "response_type={response_type}&client_id=client_id&redirect_uri={}",
        valid_redirect_uri()
    ));

    for _ in 1..maximum_depth {
        let next_query = authorize_redirect_query(&response)
            .expect("non-final code should redirect back to authorize");
        response = send_post_authorize_request(&next_query);
    }

    assert!(response.starts_with("HTTP/1.1 302 Found\r\n"));
    assert!(response.contains("location: https://client.example.com/callback?code="));
    assert!(authorize_redirect_query(&response).is_none());
}

#[test]
fn rejects_authorization_code_chain_exceeding_maximum_depth() {
    let maximum_depth = kagome::config::DEFAULT_AUTHORIZATION_CODE_CHAIN_MAX_DEPTH;
    let response_type = vec!["code"; maximum_depth + 1].join("+");
    let mut response = send_post_authorize_request(&format!(
        "response_type={response_type}&client_id=client_id&redirect_uri={}",
        valid_redirect_uri()
    ));

    for _ in 1..=maximum_depth {
        let next_query = authorize_redirect_query(&response)
            .expect("code chain should continue until the maximum depth is exceeded");
        response = send_post_authorize_request(&next_query);
    }

    assert!(response.starts_with("HTTP/1.1 400 Bad Request\r\n"));
    assert!(response.contains("content-type: text/html\r\n"));
    assert!(
        response.contains("<p role=\"alert\">authorization_code chain exceeds maximum depth</p>")
    );
}

#[test]
fn returns_authorization_code_for_valid_authorize_request() {
    let response = send_post_authorize_request(&format!(
        "response_type=code&client_id=client_id&redirect_uri={}",
        valid_redirect_uri()
    ));
    let code = redirect_code(&response).expect("authorize redirect should include code");
    assert!(!code.is_empty());
}

#[test]
fn binds_s256_pkce_challenge_to_authorization_code() {
    let response = send_post_authorize_request(&format!(
        "response_type=code&client_id=client_id&redirect_uri={}&code_challenge={PKCE_CHALLENGE}&code_challenge_method=S256",
        valid_redirect_uri()
    ));
    let code = redirect_code(&response).expect("authorize redirect should include code");
    let payload = kagome::resources::authorization_code::decode_cose_payload(&code).unwrap();

    assert_eq!(
        payload.code_challenge,
        Some(kagome::resources::pkce::CodeChallenge {
            value: PKCE_CHALLENGE.to_owned(),
        })
    );
}

#[test]
fn rejects_code_response_type_without_pkce() {
    let response = send_post_authorize_request_without_default_pkce(&format!(
        "response_type=code&client_id=client_id&redirect_uri={}",
        valid_redirect_uri()
    ));

    assert!(response.starts_with("HTTP/1.1 400 Bad Request\r\n"));
    assert!(response.contains("code_challenge is required"));
}

#[test]
fn rejects_pkce_challenge_without_s256_method() {
    let response = send_post_authorize_request(&format!(
        "response_type=code&client_id=client_id&redirect_uri={}&code_challenge={PKCE_CHALLENGE}",
        valid_redirect_uri()
    ));

    assert!(response.starts_with("HTTP/1.1 400 Bad Request\r\n"));
    assert!(response.contains("code_challenge_method must be S256"));
}

#[test]
fn rejects_plain_pkce_method() {
    let response = send_post_authorize_request(&format!(
        "response_type=code&client_id=client_id&redirect_uri={}&code_challenge={PKCE_CHALLENGE}&code_challenge_method=plain",
        valid_redirect_uri()
    ));

    assert!(response.starts_with("HTTP/1.1 400 Bad Request\r\n"));
    assert!(response.contains("code_challenge_method must be S256"));
}

#[test]
fn rejects_pkce_method_without_challenge() {
    let response = send_post_authorize_request(&format!(
        "response_type=code&client_id=client_id&redirect_uri={}&code_challenge_method=S256",
        valid_redirect_uri()
    ));

    assert!(response.starts_with("HTTP/1.1 400 Bad Request\r\n"));
    assert!(response.contains("code_challenge is required when code_challenge_method is provided"));
}

#[test]
fn rejects_malformed_s256_code_challenge() {
    let response = send_post_authorize_request(&format!(
        "response_type=code&client_id=client_id&redirect_uri={}&code_challenge=short&code_challenge_method=S256",
        valid_redirect_uri()
    ));

    assert!(response.starts_with("HTTP/1.1 400 Bad Request\r\n"));
    assert!(response.contains("code_challenge is invalid"));
}

#[test]
fn returns_oauth_error_for_missing_authorize_response_type() {
    let response = send_post_authorize_request(&format!(
        "client_id=client_id&redirect_uri={}",
        valid_redirect_uri()
    ));

    assert!(response.starts_with("HTTP/1.1 400 Bad Request\r\n"));
    assert!(response.contains("content-type: text/html\r\n"));
    assert!(response.contains("<title>authorization error</title>"));
    assert!(
        response
            .contains("<p role=\"alert\">response_type must be one of: code, token, id_token, vp_token, urn:ietf:params:oauth:response-type:pre-authorized_code</p>")
    );
    assert!(!response.contains("<form"));
}

#[test]
fn renders_html_error_for_query_format_with_trusted_redirect_uri() {
    let response = send_post_authorize_request(&format!(
        "client_id=client_id&redirect_uri={}&format=query",
        valid_redirect_uri()
    ));

    assert_authorize_html_error(&response, "response_type must be one of:");
}

#[test]
fn returns_oauth_error_for_unsupported_authorize_response_type() {
    let response = send_post_authorize_request(&format!(
        "response_type=app&client_id=client_id&redirect_uri={}",
        valid_redirect_uri()
    ));

    assert!(response.starts_with("HTTP/1.1 400 Bad Request\r\n"));
    assert!(response.contains("content-type: text/html\r\n"));
    assert!(
        response
            .contains("<p role=\"alert\">response_type must be one of: code, token, id_token, vp_token, urn:ietf:params:oauth:response-type:pre-authorized_code</p>")
    );
}

#[test]
fn returns_oauth_error_when_token_authorize_response_type_is_not_final() {
    let response = send_post_authorize_request(&format!(
        "response_type=token+code&client_id=client_id&redirect_uri={}",
        valid_redirect_uri()
    ));

    assert!(response.starts_with("HTTP/1.1 400 Bad Request\r\n"));
    assert!(response.contains("content-type: text/html\r\n"));
    assert!(response.contains("<p role=\"alert\">invalid final response type</p>"));
}

#[test]
fn returns_oauth_error_when_token_authorize_response_type_is_in_middle_of_chain() {
    let response = send_post_authorize_request(&format!(
        "response_type=code+token+code&client_id=client_id&redirect_uri={}",
        valid_redirect_uri()
    ));

    assert!(response.starts_with("HTTP/1.1 400 Bad Request\r\n"));
    assert!(response.contains("content-type: text/html\r\n"));
    assert!(response.contains("<p role=\"alert\">invalid final response type</p>"));
}

#[test]
fn returns_oauth_error_when_id_token_authorize_response_type_is_not_final() {
    let response = send_post_authorize_request(&format!(
        "response_type=id_token+code&client_id=client_id&redirect_uri={}",
        valid_redirect_uri()
    ));

    assert!(response.starts_with("HTTP/1.1 400 Bad Request\r\n"));
    assert!(response.contains("content-type: text/html\r\n"));
    assert!(response.contains("<p role=\"alert\">invalid final response type</p>"));
}

#[test]
fn returns_oauth_error_for_invalid_authorize_metadata_policy() {
    let response = send_post_authorize_request(&format!(
        "response_type=code&client_id=client_id&redirect_uri={}&metadata_policy=%7B%7D",
        valid_redirect_uri()
    ));

    assert!(response.starts_with("HTTP/1.1 400 Bad Request\r\n"));
    assert!(response.contains("content-type: text/html\r\n"));
    assert!(response.contains("<title>authorization error</title>"));
    assert!(
        response.contains("<p role=\"alert\">metadata_policy must be a json string or object</p>")
    );
    assert!(!response.contains("<form"));
}

#[test]
fn returns_oauth_error_for_authorize_metadata_policy_username_superset_mismatch() {
    let first_response = send_post_authorize_request(&format!(
        "response_type=code+code&client_id=client_id&redirect_uri={}",
        valid_redirect_uri()
    ));
    let next_query = authorize_redirect_query(&first_response)
        .expect("first authorize redirect should include query");
    let response = send_post_authorize_request(&format!(
        "{next_query}&metadata_policy=%7B%22username%22%3A%7B%22superset_of%22%3A%5B%22admin%22%5D%7D%7D"
    ));

    assert!(response.starts_with("HTTP/1.1 400 Bad Request\r\n"));
    assert!(response.contains("content-type: text/html\r\n"));
    assert!(response.contains(
        "<p role=\"alert\">metadata_policy username superset_of must be contained in authorization_code chain usernames</p>"
    ));
}

#[test]
fn returns_oauth_error_for_missing_authorize_client_id() {
    let response = send_post_authorize_request("response_type=code");

    assert!(response.starts_with("HTTP/1.1 400 Bad Request\r\n"));
    assert!(response.contains("content-type: text/html\r\n"));
    assert!(response.contains("<p role=\"alert\">client_id is required</p>"));
}

#[test]
fn returns_oauth_error_for_invalid_authorize_client_id() {
    let response = send_post_authorize_request(&format!(
        "response_type=code&client_id=app&redirect_uri={}",
        valid_redirect_uri()
    ));

    assert!(response.starts_with("HTTP/1.1 400 Bad Request\r\n"));
    assert!(response.contains("content-type: text/html\r\n"));
    assert!(response.contains("<p role=\"alert\">client_id is invalid</p>"));
}

#[test]
fn returns_authorization_code_after_resource_owner_authentication() {
    let response = send_post_authorize_request(&format!(
        "response_type=code&client_id=client_id&redirect_uri={}",
        valid_redirect_uri()
    ));
    let code = redirect_code(&response).expect("authorize redirect should include code");
    assert!(!code.is_empty());
}

#[test]
fn returns_not_found_for_unsupported_authorize_method() {
    let response =
        send_request("PUT /authorize HTTP/1.1\r\nhost: example.com\r\ncontent-length: 0\r\n\r\n");

    assert!(response.starts_with("HTTP/1.1 404 Not Found\r\n"));
}

#[test]
fn returns_oauth_error_for_missing_authorize_redirect_uri() {
    let response = send_post_authorize_request("response_type=code&client_id=client_id");

    assert!(response.starts_with("HTTP/1.1 400 Bad Request\r\n"));
    assert!(response.contains("content-type: text/html\r\n"));
    assert!(response.contains("<p role=\"alert\">redirect_uri is required</p>"));
}

#[test]
fn returns_oauth_error_for_invalid_authorize_redirect_uri() {
    let response = send_post_authorize_request(
        "response_type=code&client_id=client_id&redirect_uri=https%3A%2F%2Fapp.example.com%2Fcallback",
    );

    assert!(response.starts_with("HTTP/1.1 400 Bad Request\r\n"));
    assert!(response.contains("content-type: text/html\r\n"));
    assert!(response.contains("<p role=\"alert\">redirect_uri is invalid</p>"));
}

#[test]
fn returns_oauth_error_for_redirect_uri_registered_to_another_client() {
    let response = send_post_authorize_request(
        "response_type=code&client_id=client_id&redirect_uri=https%3A%2F%2Fconfigured.example.com%2Fcallback",
    );

    assert!(response.starts_with("HTTP/1.1 400 Bad Request\r\n"));
    assert!(response.contains("content-type: text/html\r\n"));
    assert!(response.contains("<p role=\"alert\">redirect_uri is invalid</p>"));
}

#[test]
fn returns_uniform_error_for_missing_authorize_username() {
    let response = send_post_authorize_request_with_body(
        &format!(
            "response_type=code&client_id=client_id&redirect_uri={}",
            valid_redirect_uri()
        ),
        "password=password",
    );

    assert!(response.starts_with("HTTP/1.1 400 Bad Request\r\n"));
    assert!(response.contains("content-type: text/html\r\n"));
    assert!(response.contains("<p role=\"alert\">username or password is invalid</p>"));
}

#[test]
fn returns_uniform_error_for_invalid_authorize_username() {
    let response = send_post_authorize_request_with_body(
        &format!(
            "response_type=code&client_id=client_id&redirect_uri={}",
            valid_redirect_uri()
        ),
        "username=app&password=password",
    );

    assert!(response.starts_with("HTTP/1.1 400 Bad Request\r\n"));
    assert!(response.contains("content-type: text/html\r\n"));
    assert!(response.contains("<p role=\"alert\">username or password is invalid</p>"));
}

#[test]
fn returns_uniform_error_for_missing_authorize_password() {
    let response = send_post_authorize_request_with_body(
        &format!(
            "response_type=code&client_id=client_id&redirect_uri={}",
            valid_redirect_uri()
        ),
        "username=username",
    );

    assert!(response.starts_with("HTTP/1.1 400 Bad Request\r\n"));
    assert!(response.contains("content-type: text/html\r\n"));
    assert!(response.contains("<p role=\"alert\">username or password is invalid</p>"));
}

#[test]
fn returns_uniform_error_for_invalid_authorize_password() {
    let response = send_post_authorize_request_with_body(
        &format!(
            "response_type=code&client_id=client_id&redirect_uri={}",
            valid_redirect_uri()
        ),
        "username=username&password=app",
    );

    assert!(response.starts_with("HTTP/1.1 400 Bad Request\r\n"));
    assert!(response.contains("content-type: text/html\r\n"));
    assert!(response.contains("<p role=\"alert\">username or password is invalid</p>"));
}

fn send_authorize_request(query: &str) -> String {
    let query = with_default_pkce(query);
    send_request(&format!(
        "GET /authorize?{query} HTTP/1.1\r\nhost: example.com\r\n\r\n"
    ))
}

fn assert_not_implemented(response: &str) {
    assert!(response.starts_with("HTTP/1.1 501 Not Implemented\r\n"));
    assert!(response.contains("content-type: text/plain\r\n"));
    assert!(response.ends_with("\r\n\r\nnot implemented"));
    assert!(!response.contains("<form"));
}

fn assert_federated_authorize_redirect(response: &str) {
    assert!(response.starts_with("HTTP/1.1 302 Found\r\n"));
    assert!(response.contains(
        "location: https://identity.example.com/authorize?response_type=code&client_id=kagome&redirect_uri=http%3A%2F%2Flocalhost%3A4000%2Ffederation_callback&state="
    ));
    assert!(response.contains("content-length: 0\r\n"));
    assert!(response.contains("connection: close\r\n"));
    assert!(!response.contains("<form"));
}

fn send_post_authorize_request(query: &str) -> String {
    send_post_authorize_request_with_body(query, "username=username&password=password")
}

fn send_post_authorize_request_with_body(query: &str, body: &str) -> String {
    let query = with_default_pkce(query);
    send_post_authorize_request_with_body_and_query(&query, body)
}

fn send_post_authorize_request_without_default_pkce(query: &str) -> String {
    send_post_authorize_request_with_body_and_query(query, "username=username&password=password")
}

fn send_post_authorize_request_with_body_and_query(query: &str, body: &str) -> String {
    send_request(&format!(
        "POST /authorize?{query} HTTP/1.1\r\nhost: example.com\r\ncontent-type: application/x-www-form-urlencoded\r\ncontent-length: {}\r\n\r\n{}",
        body.len(),
        body
    ))
}

fn with_default_pkce(query: &str) -> String {
    let response_type_contains_code = query
        .split('&')
        .find_map(|parameter| parameter.strip_prefix("response_type="))
        .map(|value| value.replace("%20", " ").replace('+', " "))
        .is_some_and(|value| value.split_whitespace().any(|value| value == "code"));
    let has_pkce_parameter = query.split('&').any(|parameter| {
        parameter.starts_with("code_challenge=") || parameter.starts_with("code_challenge_method=")
    });

    if response_type_contains_code && !has_pkce_parameter {
        format!("{query}&code_challenge={PKCE_CHALLENGE}&code_challenge_method=S256")
    } else {
        query.to_owned()
    }
}

fn redirect_code(response: &str) -> Option<String> {
    let location = response
        .lines()
        .find_map(|line| line.strip_prefix("location: "))?;
    let (_, query) = location.split_once('?')?;
    let query = query.split('#').next()?;
    let encoded_code = query
        .split('&')
        .find_map(|parameter| parameter.strip_prefix("code="))?;

    Some(decode_form_value(encoded_code))
}

fn redirect_query_parameter(response: &str, name: &str) -> Option<String> {
    let location = response
        .lines()
        .find_map(|line| line.strip_prefix("location: "))?;
    let (_, query) = location.split_once('?')?;

    query_parameter(query.split('#').next()?, name)
}

fn redirect_fragment_parameter(response: &str, name: &str) -> Option<String> {
    let location = response
        .lines()
        .find_map(|line| line.strip_prefix("location: "))?;
    let (_, fragment) = location.split_once('#')?;

    query_parameter(fragment, name)
}

fn encode_form_value(value: &str) -> String {
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

fn decode_access_token_payload(
    access_token: &str,
) -> kagome::resources::access_token::AccessTokenClaims {
    kagome::resources::access_token::decode_cose_payload(access_token).unwrap()
}

fn decode_id_token_payload(id_token: &str) -> IdTokenPayload {
    let mut validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::EdDSA);
    validation.validate_aud = false;
    jsonwebtoken::decode(
        id_token,
        &kagome::resources::crypto::SigningArtifact::IdToken
            .decoding_key()
            .unwrap(),
        &validation,
    )
    .expect("ID token should have a valid centralized EdDSA signature")
    .claims
}

#[derive(serde::Deserialize)]
struct IdTokenPayload {
    iss: String,
    sub: String,
    aud: String,
    client_id: String,
    username: String,
    profile: std::collections::BTreeMap<String, String>,
}

fn authorize_redirect_query(response: &str) -> Option<String> {
    let location = response
        .lines()
        .find_map(|line| line.strip_prefix("location: "))?;
    location.strip_prefix("/authorize?").map(str::to_owned)
}

fn query_parameter(query: &str, name: &str) -> Option<String> {
    query.split('&').find_map(|parameter| {
        let (parameter_name, value) = parameter.split_once('=')?;

        if parameter_name == name {
            Some(decode_form_value(value))
        } else {
            None
        }
    })
}

fn valid_redirect_uri() -> &'static str {
    "https%3A%2F%2Fclient.example.com%2Fcallback"
}

fn assert_authorize_html_error(response: &str, description: &str) {
    assert!(response.starts_with("HTTP/1.1 400 Bad Request\r\n"));
    assert!(response.contains("content-type: text/html\r\n"));
    assert!(response.contains("<title>authorization error</title>"));
    assert!(response.contains(description));
    assert!(!response.contains("\r\nlocation:"));
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
