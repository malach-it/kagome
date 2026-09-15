use base64::Engine;
use serde::de::DeserializeOwned;

use super::super::*;

// Branch matrix:
// - method: GET | POST | unsupported
// - response_type: code | token | id_token | standalone pre-authorized_code |
//   supported hybrid combinations | chained code | missing | unsupported | invalid ordering
// - resource owner: form credentials | client_id credentials | missing | invalid
// - client_id: local | second local | federated | resource-owner form | missing |
//   unconfigured
// - redirect_uri: matching first URI | matching alternate URI | another client's URI |
//   missing | invalid
// - metadata policy: missing | valid string | valid username superset | invalid |
//   username mismatch
// - federation: configured redirect | local login fallback (resource-level coverage)
// Error rendering is covered for login-page and redirect response formats.

#[test]
fn redirects_authorize_get_request_to_federated_server() {
    let response = send_authorize_request(&format!(
        "response_type=code&client_id=federated_client&redirect_uri={}",
        valid_redirect_uri()
    ));

    assert_federated_authorize_redirect(&response);
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
fn returns_login_page_for_authorize_get_request_with_metadata_policy() {
    let response = send_authorize_request(&format!(
        "response_type=code&client_id=client_id&redirect_uri={}&metadata_policy=%22profile%22",
        valid_redirect_uri()
    ));

    assert!(response.starts_with("HTTP/1.1 200 OK\r\n"));
    assert!(response.contains("content-type: text/html\r\n"));
    assert!(response.contains("<form method=\"post\" action=\"/authorize?"));
    assert!(response.contains("metadata_policy=%22profile%22"));
}

#[test]
fn returns_login_page_for_authorize_get_request_with_metadata_policy_username_superset() {
    let first_response = send_post_authorize_request(&format!(
        "response_type=code+code&client_id=client_id&redirect_uri={}",
        valid_redirect_uri()
    ));
    let next_query = authorize_redirect_query(&first_response)
        .expect("first authorize redirect should include query");
    let response = send_authorize_request(&format!(
        "{next_query}&metadata_policy=%7B%22username%22%3A%7B%22superset_of%22%3A%5B%22username%22%5D%7D%7D"
    ));

    assert!(response.starts_with("HTTP/1.1 200 OK\r\n"));
    assert!(response.contains("content-type: text/html\r\n"));
    assert!(response.contains(
        "metadata_policy=%7B%22username%22%3A%7B%22superset_of%22%3A%5B%22username%22%5D%7D%7D"
    ));
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
fn redirects_to_alternate_uri_for_second_configured_client() {
    let response = send_post_authorize_request(
        "response_type=code&client_id=configured_client&redirect_uri=https%3A%2F%2Fconfigured.example.com%2Falternate",
    );

    assert!(response.starts_with("HTTP/1.1 302 Found\r\n"));
    assert!(response.contains("location: https://configured.example.com/alternate?code="));
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
    assert_eq!(payload.client_id, "client_id");
    assert_eq!(payload.username, "username");
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
fn returns_login_page_for_authorize_get_request_with_code() {
    let first_response = send_post_authorize_request(&format!(
        "response_type=code+code&client_id=client_id&redirect_uri={}",
        valid_redirect_uri()
    ));
    let next_query = authorize_redirect_query(&first_response)
        .expect("first authorize redirect should include query");
    let response = send_authorize_request(&next_query);

    assert!(response.starts_with("HTTP/1.1 200 OK\r\n"));
    assert!(response.contains("content-type: text/html\r\n"));
    assert!(response.contains("<title>kagome login</title>"));
    assert!(response.contains("<form method=\"post\" action=\"/authorize?"));
    assert!(response.contains("code="));
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
fn returns_login_page_for_authorize_get_request_with_missing_client_id_resource_owner_password() {
    let response = send_authorize_request(&format!(
        "response_type=code&client_id=other_username%3A%40example.com&redirect_uri={}",
        valid_redirect_uri()
    ));

    assert!(response.starts_with("HTTP/1.1 200 OK\r\n"));
    assert!(response.contains("content-type: text/html\r\n"));
    assert!(response.contains("<title>kagome login</title>"));
    assert!(!response.contains("<p role=\"alert\">password is required</p>"));
}

#[test]
fn returns_login_page_for_authorize_get_request_with_username_host_client_id() {
    let response = send_request(&format!(
        "GET /authorize?response_type=code&client_id=username%40localhost%3A4000&redirect_uri={} HTTP/1.1\r\nhost: localhost:4000\r\n\r\n",
        valid_redirect_uri()
    ));

    assert!(response.starts_with("HTTP/1.1 200 OK\r\n"));
    assert!(response.contains("content-type: text/html\r\n"));
    assert!(response.contains("<title>kagome login</title>"));
    assert!(
        response
            .contains("name=\"username\" autocomplete=\"username\" value=\"username\" disabled")
    );
    assert!(response.contains("type=\"hidden\" name=\"username\" value=\"username\""));
    assert!(!response.contains("client_id is invalid"));
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
    assert!(response.contains("<p role=\"alert\">authorization_code must be a cose_encrypt0</p>"));
    assert!(response.contains("<form method=\"post\" action=\"/authorize?"));
    assert!(response.contains("code=app"));
}

#[test]
fn returns_oauth_error_for_authorize_get_client_id_resource_owner_credentials() {
    let response = send_authorize_request(&format!(
        "response_type=code&client_id=other_username%3Aapp%40example.com&redirect_uri={}",
        valid_redirect_uri()
    ));

    assert!(response.starts_with("HTTP/1.1 302 Found\r\n"));
    assert!(response.contains(
        "location: https://client.example.com/callback?error=invalid_grant&error_description=password%20is%20invalid\r\n"
    ));
    assert!(response.contains("content-length: 0\r\n"));
    assert!(response.contains("connection: close\r\n"));
}

#[test]
fn redirects_oauth_error_for_missing_response_type_with_client_id_resource_owner_credentials() {
    let response = send_authorize_request(&format!(
        "client_id=other_username%3Aother_password%40example.com&redirect_uri={}",
        valid_redirect_uri()
    ));

    assert!(response.starts_with("HTTP/1.1 302 Found\r\n"));
    assert!(response.contains(
        "location: https://client.example.com/callback?error=unsupported_response_type&error_description=response_type%20must%20be%20one%20of%3A%20code%2C%20token%2C%20id_token%2C%20vp_token%2C%20urn%3Aietf%3Aparams%3Aoauth%3Aresponse-type%3Apre-authorized_code\r\n"
    ));
    assert!(response.contains("content-length: 0\r\n"));
    assert!(response.contains("connection: close\r\n"));
}

#[test]
fn redirects_oauth_error_for_invalid_final_response_type_with_client_id_resource_owner_credentials()
{
    let response = send_authorize_request(&format!(
        "response_type=id_token+code&client_id=other_username%3Aother_password%40example.com&redirect_uri={}",
        valid_redirect_uri()
    ));

    assert!(response.starts_with("HTTP/1.1 302 Found\r\n"));
    assert!(response.contains(
        "location: https://client.example.com/callback?error=invalid_final_response_type&error_description=invalid%20final%20response%20type\r\n"
    ));
    assert!(response.contains("content-length: 0\r\n"));
    assert!(response.contains("connection: close\r\n"));
}

#[test]
fn redirects_oauth_error_for_invalid_redirect_uri_with_client_id_resource_owner_credentials() {
    let response = send_authorize_request(
        "response_type=code&client_id=other_username%3Aother_password%40example.com&redirect_uri=https%3A%2F%2Fapp.example.com%2Fcallback",
    );

    assert!(response.starts_with("HTTP/1.1 302 Found\r\n"));
    assert!(response.contains(
        "location: https://app.example.com/callback?error=invalid_request&error_description=redirect_uri%20is%20invalid\r\n"
    ));
    assert!(response.contains("content-length: 0\r\n"));
    assert!(response.contains("connection: close\r\n"));
}

#[test]
fn redirects_oauth_error_for_authorize_get_client_id_resource_owner_username() {
    let response = send_authorize_request(&format!(
        "response_type=code&client_id=app%3Apassword%40example.com&redirect_uri={}",
        valid_redirect_uri()
    ));

    assert!(response.starts_with("HTTP/1.1 302 Found\r\n"));
    assert!(response.contains(
        "location: https://client.example.com/callback?error=invalid_grant&error_description=username%20must%20be%20one%20of%3A%20username%2C%20other_username\r\n"
    ));
    assert!(response.contains("content-length: 0\r\n"));
    assert!(response.contains("connection: close\r\n"));
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
fn returns_authorization_code_for_valid_authorize_request() {
    let response = send_post_authorize_request(&format!(
        "response_type=code&client_id=client_id&redirect_uri={}",
        valid_redirect_uri()
    ));
    let code = redirect_code(&response).expect("authorize redirect should include code");
    assert!(!code.is_empty());
}

#[test]
fn returns_oauth_error_for_missing_authorize_response_type() {
    let response = send_post_authorize_request(&format!(
        "client_id=client_id&redirect_uri={}",
        valid_redirect_uri()
    ));

    assert!(response.starts_with("HTTP/1.1 400 Bad Request\r\n"));
    assert!(response.contains("content-type: text/html\r\n"));
    assert!(response.contains("<title>kagome login</title>"));
    assert!(
        response
            .contains("<p role=\"alert\">response_type must be one of: code, token, id_token, vp_token, urn:ietf:params:oauth:response-type:pre-authorized_code</p>")
    );
    assert!(response.contains("<form method=\"post\" action=\"/authorize?"));
    assert!(response.contains("client_id=client_id"));
    assert!(response.contains("redirect_uri=https%3A%2F%2Fclient.example.com%2Fcallback"));
}

#[test]
fn redirects_oauth_error_to_request_redirect_uri_for_query_format() {
    let response = send_post_authorize_request(&format!(
        "client_id=client_id&redirect_uri={}&format=query",
        valid_redirect_uri()
    ));

    assert!(response.starts_with("HTTP/1.1 302 Found\r\n"));
    assert!(response.contains(
        "location: https://client.example.com/callback?error=unsupported_response_type&error_description=response_type%20must%20be%20one%20of%3A%20code%2C%20token%2C%20id_token%2C%20vp_token%2C%20urn%3Aietf%3Aparams%3Aoauth%3Aresponse-type%3Apre-authorized_code\r\n"
    ));
    assert!(response.contains("content-length: 0\r\n"));
    assert!(response.contains("connection: close\r\n"));
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
    assert!(
        response.contains("<p role=\"alert\">metadata_policy must be a json string or object</p>")
    );
    assert!(response.contains("metadata_policy=%7B%7D"));
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
fn returns_oauth_error_for_missing_authorize_username() {
    let response = send_post_authorize_request_with_body(
        &format!(
            "response_type=code&client_id=client_id&redirect_uri={}",
            valid_redirect_uri()
        ),
        "password=password",
    );

    assert!(response.starts_with("HTTP/1.1 400 Bad Request\r\n"));
    assert!(response.contains("content-type: text/html\r\n"));
    assert!(response.contains("<p role=\"alert\">username is required</p>"));
}

#[test]
fn returns_oauth_error_for_invalid_authorize_username() {
    let response = send_post_authorize_request_with_body(
        &format!(
            "response_type=code&client_id=client_id&redirect_uri={}",
            valid_redirect_uri()
        ),
        "username=app&password=password",
    );

    assert!(response.starts_with("HTTP/1.1 400 Bad Request\r\n"));
    assert!(response.contains("content-type: text/html\r\n"));
    assert!(
        response
            .contains("<p role=\"alert\">username must be one of: username, other_username</p>")
    );
}

#[test]
fn returns_oauth_error_for_missing_authorize_password() {
    let response = send_post_authorize_request_with_body(
        &format!(
            "response_type=code&client_id=client_id&redirect_uri={}",
            valid_redirect_uri()
        ),
        "username=username",
    );

    assert!(response.starts_with("HTTP/1.1 400 Bad Request\r\n"));
    assert!(response.contains("content-type: text/html\r\n"));
    assert!(response.contains("<p role=\"alert\">password is required</p>"));
}

#[test]
fn returns_oauth_error_for_invalid_authorize_password() {
    let response = send_post_authorize_request_with_body(
        &format!(
            "response_type=code&client_id=client_id&redirect_uri={}",
            valid_redirect_uri()
        ),
        "username=username&password=app",
    );

    assert!(response.starts_with("HTTP/1.1 400 Bad Request\r\n"));
    assert!(response.contains("content-type: text/html\r\n"));
    assert!(response.contains("<p role=\"alert\">password is invalid</p>"));
}

fn send_authorize_request(query: &str) -> String {
    send_request(&format!(
        "GET /authorize?{query} HTTP/1.1\r\nhost: example.com\r\n\r\n"
    ))
}

fn assert_federated_authorize_redirect(response: &str) {
    assert!(response.starts_with("HTTP/1.1 302 Found\r\n"));
    assert!(response.contains(
        "location: https://identity.example.com/authorize?response_type=code&client_id=kagome&redirect_uri=http%3A%2F%2Flocalhost%3A4000%2Ffederation_callback&state="
    ));
    assert!(response.contains("content-length: 0\r\n"));
    assert!(response.contains("connection: close\r\n"));
    assert!(!response.contains("<title>kagome login</title>"));
}

fn send_post_authorize_request(query: &str) -> String {
    send_post_authorize_request_with_body(query, "username=username&password=password")
}

fn send_post_authorize_request_with_body(query: &str, body: &str) -> String {
    send_request(&format!(
        "POST /authorize?{query} HTTP/1.1\r\nhost: example.com\r\ncontent-type: application/x-www-form-urlencoded\r\ncontent-length: {}\r\n\r\n{}",
        body.len(),
        body
    ))
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

fn redirect_fragment_parameter(response: &str, name: &str) -> Option<String> {
    let location = response
        .lines()
        .find_map(|line| line.strip_prefix("location: "))?;
    let (_, fragment) = location.split_once('#')?;

    query_parameter(fragment, name)
}

fn decode_access_token_payload(access_token: &str) -> AccessTokenPayload {
    decode_jwt_payload(access_token)
}

fn decode_id_token_payload(id_token: &str) -> IdTokenPayload {
    decode_jwt_payload(id_token)
}

fn decode_jwt_payload<T: DeserializeOwned>(token: &str) -> T {
    let encoded_payload = token
        .split('.')
        .nth(1)
        .expect("token response should contain a JWT payload");
    let payload = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(encoded_payload)
        .expect("JWT payload should use base64url encoding");

    serde_json::from_slice(&payload).expect("JWT payload should contain JSON")
}

#[derive(serde::Deserialize)]
struct AccessTokenPayload {
    client_id: String,
}

#[derive(serde::Deserialize)]
struct IdTokenPayload {
    client_id: String,
    username: String,
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
