use super::server::send_request;

#[test]
fn returns_login_page_for_authorize_get_request() {
    let response = send_authorize_request(&format!(
        "response_type=code&client_id=client_id&redirect_uri={}",
        valid_redirect_uri()
    ));

    assert!(response.starts_with("HTTP/1.1 200 OK\r\n"));
    assert!(response.contains("content-type: text/html\r\n"));
    assert!(response.contains("connection: close\r\n"));
    assert!(response.contains("<title>kagome login</title>"));
    assert!(response.contains("<form method=\"post\" action=\"/authorize?"));
    assert!(response.contains("response_type=code"));
    assert!(response.contains("client_id=client_id"));
    assert!(response.contains("redirect_uri=https%3A%2F%2Fclient.example.com%2Fcallback"));
    assert!(response.contains("name=\"username\""));
    assert!(response.contains("name=\"password\""));
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
fn redirects_to_client_redirect_uri_for_other_resource_owner() {
    let response = send_post_authorize_request_with_body(
        &format!(
            "response_type=code&client_id=client_id&redirect_uri={}",
            valid_redirect_uri()
        ),
        "username=other_username&password=other_password",
    );
    let code = redirect_code(&response).expect("authorize redirect should include code");
    let payload = kagome::resources::authorization_code::decode_cose_payload(&code).unwrap();

    assert!(response.starts_with("HTTP/1.1 302 Found\r\n"));
    assert!(response.contains("location: https://client.example.com/callback?code="));
    assert_eq!(payload.username, Some("other_username".to_owned()));
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
    let payload = kagome::resources::authorization_code::decode_cose_payload(&code).unwrap();

    assert!(second_response.starts_with("HTTP/1.1 302 Found\r\n"));
    assert!(second_response.contains("location: https://client.example.com/callback?code="));
    assert_eq!(payload.client_id, "other_username@example.com");
    assert_eq!(payload.username, Some("other_username".to_owned()));
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
    assert!(response.contains("authorization_code="));
    assert!(response.contains("content-length: 0\r\n"));
}

#[test]
fn returns_login_page_for_authorize_get_request_with_authorization_code() {
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
    assert!(response.contains("authorization_code="));
}

#[test]
fn redirects_for_authorize_get_request_with_client_id_resource_owner_credentials() {
    let response = send_authorize_request(&format!(
        "response_type=code&client_id=other_username%3Aother_password%40example.com&redirect_uri={}",
        valid_redirect_uri()
    ));
    let code = redirect_code(&response).expect("authorize redirect should include code");
    let payload = kagome::resources::authorization_code::decode_cose_payload(&code).unwrap();

    assert!(response.starts_with("HTTP/1.1 302 Found\r\n"));
    assert!(response.contains("location: https://client.example.com/callback?code="));
    assert_eq!(payload.client_id, "other_username@example.com");
    assert_eq!(payload.username, Some("other_username".to_owned()));
}

#[test]
fn redirects_for_initial_authorize_get_request_with_client_id_resource_owner_credentials() {
    let response = send_authorize_request(&format!(
        "response_type=code&client_id=other_username%3Aother_password%40example.com&redirect_uri={}",
        valid_redirect_uri()
    ));
    let code = redirect_code(&response).expect("authorize redirect should include code");
    let payload = kagome::resources::authorization_code::decode_cose_payload(&code).unwrap();

    assert!(response.starts_with("HTTP/1.1 302 Found\r\n"));
    assert!(response.contains("location: https://client.example.com/callback?code="));
    assert_eq!(payload.client_id, "other_username@example.com");
    assert_eq!(payload.username, Some("other_username".to_owned()));
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
    let payload = kagome::resources::authorization_code::decode_cose_payload(&code).unwrap();

    assert!(response.starts_with("HTTP/1.1 302 Found\r\n"));
    assert!(response.contains("location: https://client.example.com/callback?code="));
    assert_eq!(payload.client_id, "username@example.com");
    assert_eq!(payload.username, Some("username".to_owned()));
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
    let payload = kagome::resources::authorization_code::decode_cose_payload(&code).unwrap();

    assert!(response.starts_with("HTTP/1.1 302 Found\r\n"));
    assert!(response.contains("location: https://client.example.com/callback?code="));
    assert_eq!(payload.client_id, "username@example.com");
    assert_eq!(payload.username, Some("username".to_owned()));
}

#[test]
fn returns_oauth_error_for_invalid_authorize_get_authorization_code() {
    let response = send_authorize_request(&format!(
        "response_type=code&client_id=client_id&redirect_uri={}&authorization_code=app",
        valid_redirect_uri()
    ));

    assert!(response.starts_with("HTTP/1.1 400 Bad Request\r\n"));
    assert!(response.contains("content-type: text/html\r\n"));
    assert!(response.contains("<p role=\"alert\">authorization_code must be a cose_encrypt0</p>"));
    assert!(response.contains("<form method=\"post\" action=\"/authorize?"));
    assert!(response.contains("authorization_code=app"));
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
        "location: https://client.example.com/callback?error=unsupported_response_type&error_description=response_type%20must%20be%20one%20of%3A%20code\r\n"
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
        "location: https://app.example.com/callback?error=invalid_request&error_description=redirect_uri%20must%20be%3A%20https%3A%2F%2Fclient.example.com%2Fcallback\r\n"
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
    let previous_code =
        query_parameter(&next_query, "authorization_code").expect("redirect should include code");
    let second_response = send_post_authorize_request(&next_query);
    let code = redirect_code(&second_response).expect("final redirect should include code");
    let payload = kagome::resources::authorization_code::decode_cose_payload(&code).unwrap();

    assert!(second_response.starts_with("HTTP/1.1 302 Found\r\n"));
    assert!(second_response.contains("location: https://client.example.com/callback?code="));
    assert_eq!(payload.client_id, "client_id");
    assert_eq!(payload.previous_code, Some(previous_code));
}

#[test]
fn redirects_back_to_authorize_until_final_code_response_type() {
    let first_response = send_post_authorize_request(&format!(
        "response_type=code+code+code&client_id=client_id&redirect_uri={}",
        valid_redirect_uri()
    ));
    let second_query = authorize_redirect_query(&first_response)
        .expect("first authorize redirect should include query");
    let first_code =
        query_parameter(&second_query, "authorization_code").expect("redirect should include code");

    assert!(second_query.contains("response_type=code%20code"));

    let second_response = send_post_authorize_request(&second_query);
    let third_query = authorize_redirect_query(&second_response)
        .expect("second authorize redirect should include query");
    let second_code =
        query_parameter(&third_query, "authorization_code").expect("redirect should include code");
    let second_payload =
        kagome::resources::authorization_code::decode_cose_payload(&second_code).unwrap();

    assert!(third_query.contains("response_type=code"));
    assert_eq!(second_payload.previous_code, Some(first_code));

    let third_response = send_post_authorize_request(&third_query);
    let final_code = redirect_code(&third_response).expect("final redirect should include code");
    let final_payload =
        kagome::resources::authorization_code::decode_cose_payload(&final_code).unwrap();

    assert!(third_response.starts_with("HTTP/1.1 302 Found\r\n"));
    assert!(third_response.contains("location: https://client.example.com/callback?code="));
    assert_eq!(final_payload.client_id, "client_id");
    assert_eq!(final_payload.username, Some("username".to_owned()));
    assert_eq!(final_payload.previous_code, Some(second_code));
}

#[test]
fn returns_encrypted_code_containing_authorize_request_claims() {
    let response = send_post_authorize_request(&format!(
        "response_type=code&client_id=client_id&redirect_uri={}",
        valid_redirect_uri()
    ));
    let code = redirect_code(&response).expect("authorize redirect should include code");
    let payload = kagome::resources::authorization_code::decode_cose_payload(&code).unwrap();

    assert_eq!(payload.client_id, "client_id");
    assert_eq!(payload.id_token, None);
    assert_eq!(payload.username, Some("username".to_owned()));
    assert_eq!(payload.previous_code, None);
    assert_eq!(
        payload.exp,
        payload.iat + kagome::resources::authorization_code::AUTHORIZATION_CODE_TTL_SECONDS
    );
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
    assert!(response.contains("<p role=\"alert\">response_type must be one of: code</p>"));
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
        "location: https://client.example.com/callback?error=unsupported_response_type&error_description=response_type%20must%20be%20one%20of%3A%20code\r\n"
    ));
    assert!(response.contains("content-length: 0\r\n"));
    assert!(response.contains("connection: close\r\n"));
}

#[test]
fn returns_oauth_error_for_unsupported_authorize_response_type() {
    let response = send_post_authorize_request(&format!(
        "response_type=token&client_id=client_id&redirect_uri={}",
        valid_redirect_uri()
    ));

    assert!(response.starts_with("HTTP/1.1 400 Bad Request\r\n"));
    assert!(response.contains("content-type: text/html\r\n"));
    assert!(response.contains("<p role=\"alert\">response_type must be one of: code</p>"));
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
fn returns_encrypted_code_without_id_token_for_authenticate_request() {
    let response = send_post_authorize_request(&format!(
        "response_type=code&client_id=client_id&redirect_uri={}",
        valid_redirect_uri()
    ));
    let code = redirect_code(&response).expect("authorize redirect should include code");
    let payload = kagome::resources::authorization_code::decode_cose_payload(&code).unwrap();

    assert_eq!(payload.client_id, "client_id");
    assert_eq!(payload.id_token, None);
    assert_eq!(payload.username, Some("username".to_owned()));
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
    assert!(response.contains(
        "<p role=\"alert\">redirect_uri must be: https://client.example.com/callback</p>"
    ));
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
    let encoded_code = query
        .split('&')
        .find_map(|parameter| parameter.strip_prefix("code="))?;

    Some(decode_form_value(encoded_code))
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
