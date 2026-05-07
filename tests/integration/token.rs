use super::server::send_request;

#[test]
fn returns_token_response_for_form_client_credentials_grant_type() {
    let response = send_request(
        "POST /token HTTP/1.1\r\nhost: example.com\r\ncontent-type: application/x-www-form-urlencoded\r\ncontent-length: 77\r\n\r\nclient_id=client_id&client_secret=client_secret&grant_type=client_credentials",
    );

    assert!(response.starts_with("HTTP/1.1 200 OK\r\n"));
    assert!(response.contains("content-type: application/json\r\n"));
    assert!(response.contains("connection: close\r\n"));
    assert!(response.contains("\"token_type\":\"bearer\""));
    assert!(response.contains("\"access_token\":\""));
    assert!(response.contains("\"expires_in\":3600"));
    assert!(!response.contains("\"client_id\""));
    assert!(!response.contains("\"client_secret\""));
    assert!(!response.contains("\"grant_type\""));
}

#[test]
fn returns_token_response_for_json_client_credentials_grant_type() {
    let response = send_request(
        "POST /token HTTP/1.1\r\nhost: example.com\r\ncontent-type: application/json\r\ncontent-length: 91\r\n\r\n{\"client_id\":\"client_id\",\"client_secret\":\"client_secret\",\"grant_type\":\"client_credentials\"}",
    );

    assert!(response.starts_with("HTTP/1.1 200 OK\r\n"));
    assert!(response.contains("content-type: application/json\r\n"));
    assert!(response.contains("connection: close\r\n"));
    assert!(response.contains("\"token_type\":\"bearer\""));
    assert!(response.contains("\"access_token\":\""));
    assert!(response.contains("\"expires_in\":3600"));
    assert!(!response.contains("\"client_id\""));
    assert!(!response.contains("\"client_secret\""));
    assert!(!response.contains("\"grant_type\""));
}

#[test]
fn returns_oauth_error_for_unsupported_form_grant_type() {
    let response = send_request(
        "POST /token HTTP/1.1\r\nhost: example.com\r\ncontent-type: application/x-www-form-urlencoded\r\ncontent-length: 67\r\n\r\nclient_id=client_id&client_secret=client_secret&grant_type=password",
    );

    assert_unsupported_grant_type_response(&response);
}

#[test]
fn returns_oauth_error_for_unsupported_json_grant_type() {
    let response = send_request(
        "POST /token HTTP/1.1\r\nhost: example.com\r\ncontent-type: application/json\r\ncontent-length: 81\r\n\r\n{\"client_id\":\"client_id\",\"client_secret\":\"client_secret\",\"grant_type\":\"password\"}",
    );

    assert_unsupported_grant_type_response(&response);
}

#[test]
fn returns_oauth_error_for_missing_grant_type() {
    let response = send_request(
        "POST /token HTTP/1.1\r\nhost: example.com\r\ncontent-type: application/x-www-form-urlencoded\r\ncontent-length: 47\r\n\r\nclient_id=client_id&client_secret=client_secret",
    );

    assert_unsupported_grant_type_response(&response);
}

#[test]
fn returns_oauth_error_for_missing_client_id() {
    let response = send_request(
        "POST /token HTTP/1.1\r\nhost: example.com\r\ncontent-type: application/x-www-form-urlencoded\r\ncontent-length: 57\r\n\r\nclient_secret=client_secret&grant_type=client_credentials",
    );

    assert_missing_client_id_response(&response);
}

#[test]
fn returns_oauth_error_for_invalid_client_id() {
    let response = send_request(
        "POST /token HTTP/1.1\r\nhost: example.com\r\ncontent-type: application/x-www-form-urlencoded\r\ncontent-length: 71\r\n\r\nclient_id=app&client_secret=client_secret&grant_type=client_credentials",
    );

    assert_invalid_client_id_response(&response);
}

#[test]
fn returns_oauth_error_for_missing_client_secret() {
    let response = send_request(
        "POST /token HTTP/1.1\r\nhost: example.com\r\ncontent-type: application/x-www-form-urlencoded\r\ncontent-length: 49\r\n\r\nclient_id=client_id&grant_type=client_credentials",
    );

    assert_missing_client_secret_response(&response);
}

#[test]
fn returns_oauth_error_for_invalid_client_secret() {
    let response = send_request(
        "POST /token HTTP/1.1\r\nhost: example.com\r\ncontent-type: application/x-www-form-urlencoded\r\ncontent-length: 67\r\n\r\nclient_id=client_id&client_secret=app&grant_type=client_credentials",
    );

    assert_invalid_client_secret_response(&response);
}

#[test]
fn returns_not_found_for_non_post_token_request() {
    let response = send_request("GET /token HTTP/1.1\r\nhost: example.com\r\n\r\n");

    assert!(response.starts_with("HTTP/1.1 404 Not Found\r\n"));
    assert!(response.contains("content-type: text/plain\r\n"));
    assert!(response.contains("connection: close\r\n"));
    assert!(response.ends_with("not found"));
}

fn assert_unsupported_grant_type_response(response: &str) {
    assert!(response.starts_with("HTTP/1.1 400 Bad Request\r\n"));
    assert!(response.contains("content-type: application/json\r\n"));
    assert!(response.contains("connection: close\r\n"));
    assert!(response.contains("\"error\":\"unsupported_grant_type\""));
    assert!(
        response
            .contains("\"error_description\":\"grant_type must be one of: client_credentials\"")
    );
}

fn assert_invalid_client_id_response(response: &str) {
    assert!(response.starts_with("HTTP/1.1 400 Bad Request\r\n"));
    assert!(response.contains("content-type: application/json\r\n"));
    assert!(response.contains("connection: close\r\n"));
    assert!(response.contains("\"error\":\"invalid_client\""));
    assert!(response.contains("\"error_description\":\"client_id must be: client_id\""));
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
    assert!(response.contains("\"error_description\":\"client_secret must be: client_secret\""));
}

fn assert_missing_client_secret_response(response: &str) {
    assert!(response.starts_with("HTTP/1.1 400 Bad Request\r\n"));
    assert!(response.contains("content-type: application/json\r\n"));
    assert!(response.contains("connection: close\r\n"));
    assert!(response.contains("\"error\":\"invalid_client\""));
    assert!(response.contains("\"error_description\":\"client_secret is required\""));
}
