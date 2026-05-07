#[test]
fn returns_unsupported_grant_type_oauth_response() {
    let response =
        kagome::errors::OAuthError::unsupported_grant_type(&["client_credentials"]).to_response();

    assert!(response.starts_with("HTTP/1.1 400 Bad Request\r\n"));
    assert!(response.contains("content-type: application/json\r\n"));
    assert!(response.contains("connection: close\r\n"));
    assert!(response.contains("\"error\":\"unsupported_grant_type\""));
    assert!(
        response
            .contains("\"error_description\":\"grant_type must be one of: client_credentials\"")
    );
}

#[test]
fn returns_invalid_token_response_oauth_response() {
    let response =
        kagome::errors::OAuthError::invalid_token_response("token response requires grant_type")
            .to_response();

    assert!(response.starts_with("HTTP/1.1 400 Bad Request\r\n"));
    assert!(response.contains("content-type: application/json\r\n"));
    assert!(response.contains("connection: close\r\n"));
    assert!(response.contains("\"error\":\"invalid_token_response\""));
    assert!(response.contains("\"error_description\":\"token response requires grant_type\""));
}

#[test]
fn returns_invalid_client_id_oauth_response() {
    let response = kagome::errors::OAuthError::invalid_client_id("client_id").to_response();

    assert!(response.starts_with("HTTP/1.1 400 Bad Request\r\n"));
    assert!(response.contains("content-type: application/json\r\n"));
    assert!(response.contains("connection: close\r\n"));
    assert!(response.contains("\"error\":\"invalid_client\""));
    assert!(response.contains("\"error_description\":\"client_id must be: client_id\""));
}

#[test]
fn returns_missing_client_id_oauth_response() {
    let response = kagome::errors::OAuthError::missing_client_id().to_response();

    assert!(response.starts_with("HTTP/1.1 400 Bad Request\r\n"));
    assert!(response.contains("content-type: application/json\r\n"));
    assert!(response.contains("connection: close\r\n"));
    assert!(response.contains("\"error\":\"invalid_client\""));
    assert!(response.contains("\"error_description\":\"client_id is required\""));
}

#[test]
fn returns_invalid_client_secret_oauth_response() {
    let response = kagome::errors::OAuthError::invalid_client_secret("client_secret").to_response();

    assert!(response.starts_with("HTTP/1.1 400 Bad Request\r\n"));
    assert!(response.contains("content-type: application/json\r\n"));
    assert!(response.contains("connection: close\r\n"));
    assert!(response.contains("\"error\":\"invalid_client\""));
    assert!(response.contains("\"error_description\":\"client_secret must be: client_secret\""));
}

#[test]
fn returns_missing_client_secret_oauth_response() {
    let response = kagome::errors::OAuthError::missing_client_secret().to_response();

    assert!(response.starts_with("HTTP/1.1 400 Bad Request\r\n"));
    assert!(response.contains("content-type: application/json\r\n"));
    assert!(response.contains("connection: close\r\n"));
    assert!(response.contains("\"error\":\"invalid_client\""));
    assert!(response.contains("\"error_description\":\"client_secret is required\""));
}

#[test]
fn escapes_oauth_error_response_json() {
    let response = kagome::errors::OAuthError {
        error: "invalid_grant".to_owned(),
        error_description: "line one\nline \"two\"".to_owned(),
    }
    .to_response();

    assert!(response.contains("\"error\":\"invalid_grant\""));
    assert!(response.contains("\"error_description\":\"line one\\nline \\\"two\\\"\""));
}

#[test]
fn implements_native_rust_error() {
    let error = kagome::errors::OAuthError::unsupported_grant_type(&["client_credentials"]);
    let native_error: &dyn std::error::Error = &error;

    assert_eq!(
        native_error.to_string(),
        "unsupported_grant_type: grant_type must be one of: client_credentials"
    );
}
