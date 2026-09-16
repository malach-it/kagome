use std::{
    io::{self, BufRead, BufReader, Read, Write},
    net::{TcpListener, TcpStream},
    sync::OnceLock,
    thread,
    time::Duration,
};

static SERVER_ADDRESS: OnceLock<String> = OnceLock::new();

pub fn send_request(request: &str) -> String {
    let mut stream =
        TcpStream::connect(server_address()).expect("failed to connect to kagome server");
    let mut reader = BufReader::new(
        stream
            .try_clone()
            .expect("failed to clone kagome connection"),
    );

    stream
        .write_all(request.as_bytes())
        .expect("failed to write request");

    read_response(&mut reader)
}

pub fn send_persistent_requests(requests: &[&str]) -> Vec<String> {
    let mut stream =
        TcpStream::connect(server_address()).expect("failed to connect to kagome server");
    let mut reader = BufReader::new(
        stream
            .try_clone()
            .expect("failed to clone kagome connection"),
    );

    requests
        .iter()
        .map(|request| {
            stream
                .write_all(request.as_bytes())
                .expect("failed to write request");

            read_response(&mut reader)
        })
        .collect()
}

#[test]
fn keeps_connection_alive_when_requested() {
    let responses = send_persistent_requests(&[
        "GET /echo HTTP/1.1\r\nhost: example.com\r\nconnection: keep-alive\r\n\r\n",
        "GET /echo HTTP/1.1\r\nhost: example.com\r\nconnection: keep-alive\r\n\r\n",
    ]);

    assert_eq!(responses.len(), 2);
    assert!(responses[0].contains("\"method\":\"GET\""));
    assert!(responses[0].contains("\"path\":\"/echo\""));
    assert!(responses[0].contains("connection: keep-alive\r\n"));
    assert!(responses[0].contains("{\"name\":\"connection\",\"value\":\"keep-alive\"}"));
    assert!(responses[0].ends_with("\"body\":\"\"}"));
    assert!(responses[1].contains("\"method\":\"GET\""));
    assert!(responses[1].contains("\"path\":\"/echo\""));
    assert!(responses[1].contains("connection: keep-alive\r\n"));
    assert!(responses[1].contains("{\"name\":\"connection\",\"value\":\"keep-alive\"}"));
    assert!(responses[1].ends_with("\"body\":\"\"}"));
}

#[test]
fn closes_connection_by_default() {
    let response = send_request("GET /echo HTTP/1.1\r\nhost: example.com\r\n\r\n");

    assert!(response.contains("connection: close\r\n"));
}

#[test]
fn closes_connection_when_requested() {
    let response =
        send_request("GET /echo HTTP/1.1\r\nhost: example.com\r\nconnection: close\r\n\r\n");

    assert!(response.contains("connection: close\r\n"));
    assert!(response.contains("{\"name\":\"connection\",\"value\":\"close\"}"));
}

#[test]
fn returns_not_found_for_unknown_path() {
    let response = send_request("GET /missing HTTP/1.1\r\nhost: example.com\r\n\r\n");

    assert!(response.starts_with("HTTP/1.1 404 Not Found\r\n"));
    assert!(response.contains("content-type: text/plain\r\n"));
    assert!(response.contains("connection: close\r\n"));
    assert!(response.ends_with("not found"));
}

#[test]
fn routes_echo_for_any_http_method() {
    let response =
        send_request("POST /echo HTTP/1.1\r\nhost: example.com\r\ncontent-length: 5\r\n\r\nhello");

    assert!(response.starts_with("HTTP/1.1 200 OK\r\n"));
    assert!(response.contains("connection: close\r\n"));
    assert!(response.contains("\"method\":\"POST\""));
    assert!(response.contains("\"path\":\"/echo\""));
    assert!(response.ends_with("\"body\":\"hello\"}"));
}

#[test]
fn rejects_request_body_larger_than_one_mebibyte() {
    let body = "a".repeat(kagome::http_server::MAX_ECHO_REQUEST_BODY_BYTES + 1);
    let response = send_request(&format!(
        "POST /echo HTTP/1.1\r\nhost: example.com\r\ncontent-length: {}\r\n\r\n{body}",
        body.len()
    ));

    assert!(response.starts_with("HTTP/1.1 413 Payload Too Large\r\n"));
    assert!(response.ends_with("request body exceeds 1048576 bytes"));
}

#[test]
fn rejects_protocol_body_larger_than_256_kibibytes() {
    let body = "a".repeat(kagome::http_server::MAX_PROTOCOL_REQUEST_BODY_BYTES + 1);
    let response = send_request(&format!(
        "POST /token HTTP/1.1\r\nhost: example.com\r\ncontent-type: application/x-www-form-urlencoded\r\ncontent-length: {}\r\n\r\n{body}",
        body.len()
    ));

    assert!(response.starts_with("HTTP/1.1 413 Payload Too Large\r\n"));
    assert!(response.ends_with("request body exceeds 262144 bytes"));
}

#[test]
fn permits_larger_presentation_response_within_global_limit() {
    let body = "a".repeat(kagome::http_server::MAX_PROTOCOL_REQUEST_BODY_BYTES + 1);
    let response = send_request(&format!(
        "POST /presentation-response HTTP/1.1\r\nhost: example.com\r\ncontent-type: application/x-www-form-urlencoded\r\ncontent-length: {}\r\n\r\n{body}",
        body.len()
    ));

    assert!(!response.starts_with("HTTP/1.1 413 Payload Too Large\r\n"));
}

#[test]
fn rejects_presentation_response_larger_than_ten_mebibytes() {
    let body = "a".repeat(kagome::http_server::MAX_REQUEST_BODY_BYTES + 1);
    let response = send_request(&format!(
        "POST /presentation-response HTTP/1.1\r\nhost: example.com\r\ncontent-type: application/x-www-form-urlencoded\r\ncontent-length: {}\r\n\r\n{body}",
        body.len()
    ));

    assert!(response.starts_with("HTTP/1.1 413 Payload Too Large\r\n"));
    assert!(response.ends_with("request body exceeds 10485760 bytes"));
}

#[test]
fn permits_larger_credential_request_within_ten_mebibyte_limit() {
    let body = "a".repeat(kagome::http_server::MAX_PROTOCOL_REQUEST_BODY_BYTES + 1);
    let response = send_request(&format!(
        "POST /credential HTTP/1.1\r\nhost: example.com\r\ncontent-type: application/json\r\ncontent-length: {}\r\n\r\n{body}",
        body.len()
    ));

    assert!(!response.starts_with("HTTP/1.1 413 Payload Too Large\r\n"));
}

#[test]
fn rejects_credential_request_larger_than_ten_mebibytes() {
    let body = "a".repeat(kagome::http_server::MAX_REQUEST_BODY_BYTES + 1);
    let response = send_request(&format!(
        "POST /credential HTTP/1.1\r\nhost: example.com\r\ncontent-type: application/json\r\ncontent-length: {}\r\n\r\n{body}",
        body.len()
    ));

    assert!(response.starts_with("HTTP/1.1 413 Payload Too Large\r\n"));
    assert!(response.ends_with("request body exceeds 10485760 bytes"));
}

#[test]
fn rejects_more_than_64_request_headers() {
    let headers = (0..kagome::http_server::MAX_REQUEST_HEADERS)
        .map(|index| format!("x-test-{index}: value\r\n"))
        .collect::<String>();
    let response = send_request(&format!(
        "GET /echo HTTP/1.1\r\nhost: example.com\r\n{headers}\r\n"
    ));

    assert!(
        response.starts_with("HTTP/1.1 431 Request Header Fields Too Large\r\n"),
        "{response}"
    );
}

#[test]
fn rejects_headers_exceeding_32_kibibytes() {
    let value = "a".repeat(kagome::http_server::MAX_HEADER_BYTES);
    let response = send_request(&format!(
        "GET /echo HTTP/1.1\r\nhost: example.com\r\nx-large: {value}\r\n\r\n"
    ));

    assert!(
        response.starts_with("HTTP/1.1 431 Request Header Fields Too Large\r\n"),
        "{response}"
    );
}

#[test]
fn closes_connection_when_header_read_times_out() {
    let address = start_server_with_limits(kagome::http_server::ServerLimits {
        header_read_timeout: Duration::from_millis(50),
        ..Default::default()
    });
    let mut stream = TcpStream::connect(address).expect("failed to connect to limited server");
    stream
        .set_read_timeout(Some(Duration::from_secs(1)))
        .expect("failed to set client read timeout");
    stream
        .write_all(b"GET /echo HTTP/1.1\r\nhost:")
        .expect("failed to write partial headers");

    let mut response = Vec::new();
    let result = stream.read_to_end(&mut response);

    assert!(
        result.is_ok()
            || result.as_ref().is_err_and(|error| {
                matches!(
                    error.kind(),
                    io::ErrorKind::ConnectionReset | io::ErrorKind::UnexpectedEof
                )
            }),
        "{result:?}"
    );
    assert!(
        response.is_empty() || response.starts_with(b"HTTP/1.1 408 Request Timeout\r\n"),
        "{}",
        String::from_utf8_lossy(&response)
    );
}

#[test]
fn times_out_incomplete_request_body() {
    let address = start_server_with_limits(kagome::http_server::ServerLimits {
        request_body_timeout: Duration::from_millis(50),
        ..Default::default()
    });
    let mut stream = TcpStream::connect(address).expect("failed to connect to limited server");
    let mut reader = BufReader::new(stream.try_clone().expect("failed to clone connection"));
    stream
        .write_all(b"POST /echo HTTP/1.1\r\nhost: example.com\r\ncontent-length: 5\r\n\r\na")
        .expect("failed to write partial request");

    let response = read_response(&mut reader);

    assert!(response.starts_with("HTTP/1.1 408 Request Timeout\r\n"));
    assert!(response.ends_with("request body timed out"));
}

#[test]
fn rejects_request_when_concurrency_is_exhausted() {
    let address = start_server_with_limits(kagome::http_server::ServerLimits {
        max_concurrent_connections: 2,
        max_concurrent_requests: 1,
        request_body_timeout: Duration::from_secs(1),
        ..Default::default()
    });
    let mut blocked = TcpStream::connect(&address).expect("failed to connect blocking request");
    blocked
        .write_all(b"POST /echo HTTP/1.1\r\nhost: example.com\r\ncontent-length: 5\r\n\r\na")
        .expect("failed to write blocking request");
    thread::sleep(Duration::from_millis(25));

    let mut rejected = TcpStream::connect(address).expect("failed to connect rejected request");
    let mut reader = BufReader::new(rejected.try_clone().expect("failed to clone connection"));
    rejected
        .write_all(b"GET /echo HTTP/1.1\r\nhost: example.com\r\n\r\n")
        .expect("failed to write rejected request");
    let response = read_response(&mut reader);

    assert!(response.starts_with("HTTP/1.1 503 Service Unavailable\r\n"));
    assert!(response.ends_with("request concurrency limit reached"));
}

#[test]
fn rejects_conflicting_content_length_headers() {
    let response = send_request(
        "POST /echo HTTP/1.1\r\nhost: example.com\r\ncontent-length: 1\r\ncontent-length: 2\r\n\r\nxx",
    );

    assert!(
        response.starts_with("HTTP/1.1 400 Bad Request\r\n"),
        "{response}"
    );
}

#[test]
fn normalizes_transfer_encoding_with_content_length() {
    let response = send_request(
        "POST /echo HTTP/1.1\r\nhost: example.com\r\ntransfer-encoding: chunked\r\ncontent-length: 4\r\n\r\n0\r\n\r\n",
    );

    assert!(response.starts_with("HTTP/1.1 200 OK\r\n"), "{response}");
    assert!(response.contains("\"name\":\"transfer-encoding\",\"value\":\"chunked\""));
    assert!(!response.contains("\"name\":\"content-length\""));
    assert!(response.ends_with("\"body\":\"\"}"));
}

fn read_response(reader: &mut BufReader<TcpStream>) -> String {
    let mut response = String::new();
    let mut content_length = 0;

    loop {
        let mut line = String::new();
        reader
            .read_line(&mut line)
            .expect("failed to read response header");

        if let Some((name, value)) = line.split_once(':')
            && name.eq_ignore_ascii_case("content-length")
        {
            content_length = value.trim().parse().unwrap_or_default();
        }

        let is_end_of_headers = line == "\r\n" || line == "\n";
        response.push_str(&line);

        if is_end_of_headers {
            break;
        }
    }

    let mut body = vec![0; content_length];
    reader
        .read_exact(&mut body)
        .expect("failed to read response body");
    response.push_str(&String::from_utf8_lossy(&body));

    response
}

fn server_address() -> &'static str {
    SERVER_ADDRESS.get_or_init(start_server)
}

fn start_server() -> String {
    let manifest_directory = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let crypto_path = manifest_directory.join("tests/fixtures/kagome.crypto.yaml");
    let password_path = manifest_directory.join("kagome.htpasswd.example");
    let config_path = std::env::temp_dir().join(format!(
        "kagome-integration-config-{}.yaml",
        std::process::id()
    ));
    let config_yaml = include_str!("../../kagome.example.yaml")
        .replace(
            "key_file: kagome.crypto.yaml",
            &format!("key_file: {}", crypto_path.display()),
        )
        .replace(
            "password_file: kagome.htpasswd.example",
            &format!("password_file: {}", password_path.display()),
        );
    std::fs::write(&config_path, config_yaml).expect("integration configuration should be written");
    let mut config = kagome::config::Config::load_from_path(&config_path)
        .expect("example configuration should load");
    let _ = std::fs::remove_file(config_path);
    config.clients[0].public = Some("example.com".to_owned());
    config.credentials.push(kagome::config::CredentialConfig {
        credential_configuration_id: "EmployeeCredential".to_owned(),
        name: "Employee Credential".to_owned(),
        vct: "https://credentials.example.com/employee".to_owned(),
        credential_types: vec!["EmployeeCredential".to_owned()],
    });
    config
        .presentation_definitions
        .push(kagome::config::PresentationDefinitionConfig {
            identifier: "employee_presentation".to_owned(),
            definition: serde_json::json!({
                "id": "employee_presentation",
                "input_descriptors": [{
                    "id": "employee_credential",
                    "format": {"jwt_vc": {"alg": ["EdDSA"]}},
                    "constraints": {"fields": [{
                        "path": ["$.vc.type"],
                        "filter": {
                            "type": "array",
                            "contains": {"const": "EmployeeCredential"}
                        }
                    }]}
                }]
            }),
        });
    let password_file = config.clients[0].password_file.clone();
    let qr_password_file = password_file.clone();
    let restricted_password_file = password_file.clone();
    let mut federated_server = config.clients[0]
        .federated_server
        .take()
        .expect("example client should configure federation");
    let (token_endpoint, identity_endpoint) = start_federated_server();
    federated_server.token_endpoint = token_endpoint;
    federated_server.endpoints[0].endpoint = identity_endpoint;
    federated_server.endpoints[0].claims[0].target = "sub".to_owned();
    federated_server.endpoints[0].claims[0].id_token = true;
    federated_server.endpoints[0]
        .claims
        .push(kagome::config::FederatedIdentityClaimConfig {
            claim: "profile.username".to_owned(),
            target: "username".to_owned(),
            id_token: true,
            credential: vec![
                "UniversityDegreeCredential".to_owned(),
                "EmployeeCredential".to_owned(),
            ],
        });
    let federated_qr_server = federated_server.clone();
    federated_server.endpoints[0]
        .claims
        .push(kagome::config::FederatedIdentityClaimConfig {
            claim: "profile.username".to_owned(),
            target: "display_name".to_owned(),
            id_token: false,
            credential: vec!["EmployeeCredential".to_owned()],
        });
    config.clients.push(kagome::config::ClientConfig {
        client_id: "configured_client".to_owned(),
        public: None,
        client_secret: "configured_secret".to_owned(),
        password_file: password_file.clone(),
        redirect_uris: vec![
            "https://configured.example.com/callback".to_owned(),
            "https://configured.example.com/alternate".to_owned(),
        ],
        supported_grant_types: kagome::resources::grant_type::GrantType::ALL.to_vec(),
        supported_response_types: kagome::resources::response_type::ResponseType::ALL.to_vec(),
        scopes: integration_scopes(),
        require_wallet_binding: false,
        qr_code: false,
        federated_server: None,
    });
    config.clients.push(kagome::config::ClientConfig {
        client_id: "federated_client".to_owned(),
        public: None,
        client_secret: "federated_secret".to_owned(),
        password_file: None,
        redirect_uris: vec!["https://client.example.com/callback".to_owned()],
        supported_grant_types: kagome::resources::grant_type::GrantType::ALL.to_vec(),
        supported_response_types: kagome::resources::response_type::ResponseType::ALL.to_vec(),
        scopes: integration_scopes(),
        require_wallet_binding: false,
        qr_code: false,
        federated_server: Some(federated_server),
    });
    config.clients.push(kagome::config::ClientConfig {
        client_id: "federated_qr_client".to_owned(),
        public: None,
        client_secret: "federated_qr_secret".to_owned(),
        password_file: None,
        redirect_uris: vec!["https://federated-qr.example.com/callback".to_owned()],
        supported_grant_types: kagome::resources::grant_type::GrantType::ALL.to_vec(),
        supported_response_types: kagome::resources::response_type::ResponseType::ALL.to_vec(),
        scopes: integration_scopes(),
        require_wallet_binding: true,
        qr_code: true,
        federated_server: Some(federated_qr_server),
    });
    config.clients.push(kagome::config::ClientConfig {
        client_id: "restricted_client".to_owned(),
        public: None,
        client_secret: "restricted_secret".to_owned(),
        password_file: restricted_password_file,
        redirect_uris: vec!["https://restricted.example.com/callback".to_owned()],
        supported_grant_types: vec![kagome::resources::grant_type::GrantType::AuthorizationCode],
        supported_response_types: vec![kagome::resources::response_type::ResponseType::Code],
        scopes: vec!["openid".to_owned()],
        require_wallet_binding: false,
        qr_code: false,
        federated_server: None,
    });
    config.clients.push(kagome::config::ClientConfig {
        client_id: "wallet_bound_client".to_owned(),
        public: None,
        client_secret: "wallet_bound_secret".to_owned(),
        password_file,
        redirect_uris: vec!["https://wallet-bound.example.com/callback".to_owned()],
        supported_grant_types: kagome::resources::grant_type::GrantType::ALL.to_vec(),
        supported_response_types: kagome::resources::response_type::ResponseType::ALL.to_vec(),
        scopes: integration_scopes(),
        require_wallet_binding: true,
        qr_code: false,
        federated_server: None,
    });
    config.clients.push(kagome::config::ClientConfig {
        client_id: "qr_client".to_owned(),
        public: None,
        client_secret: "qr_secret".to_owned(),
        password_file: qr_password_file,
        redirect_uris: vec!["https://qr.example.com/callback".to_owned()],
        supported_grant_types: kagome::resources::grant_type::GrantType::ALL.to_vec(),
        supported_response_types: kagome::resources::response_type::ResponseType::ALL.to_vec(),
        scopes: integration_scopes(),
        require_wallet_binding: false,
        qr_code: true,
        federated_server: None,
    });
    kagome::config::Config::set_global(config)
        .expect("integration configuration should initialize");
    let listener = TcpListener::bind("127.0.0.1:0").expect("failed to bind kagome server");
    let address = listener
        .local_addr()
        .expect("failed to read kagome server address")
        .to_string();

    thread::spawn(move || {
        kagome::http_server::serve_listener_with_workers(listener, 2)
            .expect("kagome server failed");
    });

    address
}

fn start_server_with_limits(limits: kagome::http_server::ServerLimits) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").expect("failed to bind limited server");
    let address = listener
        .local_addr()
        .expect("failed to read limited server address")
        .to_string();

    thread::spawn(move || {
        kagome::http_server::serve_listener_with_workers_and_limits(listener, 1, limits)
            .expect("limited kagome server failed");
    });

    address
}

fn integration_scopes() -> Vec<String> {
    [
        "openid",
        "profile",
        "credential_presentation",
        "employee_presentation",
    ]
    .map(str::to_owned)
    .to_vec()
}

fn start_federated_server() -> (String, String) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("failed to bind federated server");
    let address = listener
        .local_addr()
        .expect("failed to read federated token server address");

    thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(stream) = stream else { continue };
            thread::spawn(move || respond_to_federated_request(stream));
        }
    });

    (
        format!("http://{address}/token"),
        format!("http://{address}/userinfo"),
    )
}

fn respond_to_federated_request(mut stream: TcpStream) {
    let mut reader = BufReader::new(
        stream
            .try_clone()
            .expect("failed to clone federated token connection"),
    );
    let mut request_line = String::new();
    reader
        .read_line(&mut request_line)
        .expect("failed to read federated request line");
    let path = request_line.split_whitespace().nth(1).unwrap_or_default();
    let mut content_length = 0;
    let mut authorization = None;

    loop {
        let mut line = String::new();
        reader
            .read_line(&mut line)
            .expect("failed to read federated token request header");
        if let Some((name, value)) = line.split_once(':')
            && name.eq_ignore_ascii_case("content-length")
        {
            content_length = value.trim().parse().unwrap_or_default();
        }
        if let Some((name, value)) = line.split_once(':')
            && name.eq_ignore_ascii_case("authorization")
        {
            authorization = Some(value.trim().to_owned());
        }
        if line == "\r\n" || line == "\n" {
            break;
        }
    }

    let mut body = vec![0; content_length];
    reader
        .read_exact(&mut body)
        .expect("failed to read federated token request body");
    let parameters = String::from_utf8_lossy(&body);
    let (status, response_body) = if path == "/userinfo" {
        match authorization.as_deref() {
            Some("Bearer upstream-access-token") => (
                "200 OK",
                r#"{"sub":"ignored-user","profile":{"username":"federated-user"}}"#,
            ),
            Some("Bearer identity-malformed-token") => ("200 OK", "not-json"),
            Some("Bearer identity-oversized-token") => ("200 OK", "oversized"),
            Some("Bearer identity-wrong-content-type-token") => (
                "200 OK",
                r#"{"sub":"ignored-user","profile":{"username":"federated-user"}}"#,
            ),
            Some("Bearer identity-missing-claim-token") => ("200 OK", "{}"),
            Some("Bearer identity-missing-second-claim-token") => {
                ("200 OK", r#"{"sub":"federated-user"}"#)
            }
            Some("Bearer identity-non-string-token") => ("200 OK", r#"{"sub":123}"#),
            Some("Bearer identity-error-code-token") => {
                ("403 Forbidden", r#"{"error":"insufficient_scope"}"#)
            }
            Some("Bearer identity-message-token") => (
                "503 Service Unavailable",
                r#"{"message":"profile unavailable"}"#,
            ),
            Some("Bearer identity-no-message-token") => {
                ("502 Bad Gateway", r#"{"detail":"upstream unavailable"}"#)
            }
            _ => (
                "400 Bad Request",
                r#"{"error":"invalid_token","error_description":"federated access token expired"}"#,
            ),
        }
    } else if parameters.contains("code=oversized-token") {
        ("200 OK", "oversized")
    } else if parameters.contains("code=token-wrong-content-type") {
        ("200 OK", r#"{"access_token":"upstream-access-token"}"#)
    } else if parameters.contains("code=malformed-token") {
        ("200 OK", "not-json")
    } else if parameters.contains("code=empty-token") {
        ("200 OK", r#"{"access_token":""}"#)
    } else if parameters.contains("code=identity-rejected") {
        ("200 OK", r#"{"access_token":"identity-rejected-token"}"#)
    } else if parameters.contains("code=identity-malformed") {
        ("200 OK", r#"{"access_token":"identity-malformed-token"}"#)
    } else if parameters.contains("code=identity-oversized") {
        ("200 OK", r#"{"access_token":"identity-oversized-token"}"#)
    } else if parameters.contains("code=identity-wrong-content-type") {
        (
            "200 OK",
            r#"{"access_token":"identity-wrong-content-type-token"}"#,
        )
    } else if parameters.contains("code=identity-missing-claim") {
        (
            "200 OK",
            r#"{"access_token":"identity-missing-claim-token"}"#,
        )
    } else if parameters.contains("code=identity-missing-second-claim") {
        (
            "200 OK",
            r#"{"access_token":"identity-missing-second-claim-token"}"#,
        )
    } else if parameters.contains("code=identity-non-string") {
        ("200 OK", r#"{"access_token":"identity-non-string-token"}"#)
    } else if parameters.contains("code=identity-error-code") {
        ("200 OK", r#"{"access_token":"identity-error-code-token"}"#)
    } else if parameters.contains("code=identity-message") {
        ("200 OK", r#"{"access_token":"identity-message-token"}"#)
    } else if parameters.contains("code=identity-no-message") {
        ("200 OK", r#"{"access_token":"identity-no-message-token"}"#)
    } else if parameters.contains("code=federated-code")
        && parameters.contains("grant_type=authorization_code")
        && parameters.contains("client_id=kagome")
        && parameters.contains("client_secret=federated_client_secret")
        && parameters.contains("redirect_uri=http%3A%2F%2Flocalhost%3A4000%2Ffederation_callback")
    {
        (
            "200 OK",
            r#"{"access_token":"upstream-access-token","token_type":"bearer","expires_in":3600}"#,
        )
    } else {
        ("400 Bad Request", r#"{"error":"invalid_grant"}"#)
    };
    let response_body = if response_body == "oversized" {
        format!(r#"{{"access_token":"{}"}}"#, "x".repeat(70 * 1024))
    } else {
        response_body.to_owned()
    };
    let content_type = if parameters.contains("code=token-wrong-content-type")
        || authorization.as_deref() == Some("Bearer identity-wrong-content-type-token")
    {
        "text/plain"
    } else {
        "application/json"
    };
    let response = format!(
        "HTTP/1.1 {status}\r\ncontent-type: {content_type}\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{response_body}",
        response_body.len()
    );
    stream
        .write_all(response.as_bytes())
        .expect("failed to write federated token response");
}
