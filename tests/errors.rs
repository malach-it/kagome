#[test]
fn returns_unsupported_grant_type_oauth_response() {
    let response = kagome::errors::OAuthError::unsupported_grant_type(&[
        "client_credentials",
        "code_chain",
        "authorization_code",
    ])
    .to_response();

    assert!(response.starts_with("HTTP/1.1 400 Bad Request\r\n"));
    assert!(response.contains("content-type: application/json\r\n"));
    assert!(response.contains("connection: close\r\n"));
    assert!(response.contains("\"error\":\"unsupported_grant_type\""));
    assert!(response.contains(
        "\"error_description\":\"grant_type must be one of: client_credentials, code_chain, authorization_code\""
    ));
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
    let response = kagome::errors::OAuthError::invalid_client_id().to_response();

    assert!(response.starts_with("HTTP/1.1 400 Bad Request\r\n"));
    assert!(response.contains("content-type: application/json\r\n"));
    assert!(response.contains("connection: close\r\n"));
    assert!(response.contains("\"error\":\"invalid_client\""));
    assert!(response.contains("\"error_description\":\"client_id is invalid\""));
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
fn returns_invalid_id_token_oauth_response() {
    let response =
        kagome::errors::OAuthError::invalid_id_token("id_token is expired").to_response();

    assert!(response.starts_with("HTTP/1.1 400 Bad Request\r\n"));
    assert!(response.contains("content-type: application/json\r\n"));
    assert!(response.contains("connection: close\r\n"));
    assert!(response.contains("\"error\":\"invalid_grant\""));
    assert!(response.contains("\"error_description\":\"id_token is expired\""));
}

#[test]
fn returns_missing_id_token_oauth_response() {
    let response = kagome::errors::OAuthError::missing_id_token().to_response();

    assert!(response.starts_with("HTTP/1.1 400 Bad Request\r\n"));
    assert!(response.contains("content-type: application/json\r\n"));
    assert!(response.contains("connection: close\r\n"));
    assert!(response.contains("\"error\":\"invalid_grant\""));
    assert!(response.contains("\"error_description\":\"id_token is required\""));
}

#[test]
fn escapes_oauth_error_response_json() {
    let response = kagome::errors::OAuthError {
        error: "invalid_grant".to_owned(),
        error_description: "line one\nline \"two\"".to_owned(),
        format: kagome::errors::OAuthError::DEFAULT_FORMAT.to_owned(),
        kind: kagome::errors::OAuthErrorCode::InvalidPassword,
    }
    .to_response();

    assert!(response.contains("\"error\":\"invalid_grant\""));
    assert!(response.contains("\"error_description\":\"line one\\nline \\\"two\\\"\""));
}

#[test]
fn uses_custom_oauth_error_response_format() {
    let response = kagome::errors::OAuthError::invalid_client_id()
        .with_format("application/oauth-authz-req+jwt")
        .to_response();

    assert!(response.starts_with("HTTP/1.1 400 Bad Request\r\n"));
    assert!(response.contains("content-type: application/oauth-authz-req+jwt\r\n"));
    assert!(response.contains("\"error\":\"invalid_client\""));
}

#[test]
fn uses_login_oauth_error_response_format() {
    let response = kagome::errors::OAuthError::invalid_token_response("<invalid> token")
        .with_format("login")
        .to_response();

    assert!(response.starts_with("HTTP/1.1 400 Bad Request\r\n"));
    assert!(response.contains("content-type: text/html\r\n"));
    assert!(response.contains("<title>kagome login</title>"));
    assert!(response.contains("<p role=\"alert\">&lt;invalid&gt; token</p>"));
    assert!(response.contains("<form method=\"post\" action=\"/authorize\">"));
    assert!(response.contains("name=\"username\""));
    assert!(response.contains("name=\"password\""));
}

#[test]
fn implements_native_rust_error() {
    let error = kagome::errors::OAuthError::unsupported_grant_type(&[
        "client_credentials",
        "code_chain",
        "authorization_code",
    ]);
    let native_error: &dyn std::error::Error = &error;

    assert_eq!(
        native_error.to_string(),
        "unsupported_grant_type: grant_type must be one of: client_credentials, code_chain, authorization_code"
    );
}
