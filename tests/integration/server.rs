use std::{
    io::{BufRead, BufReader, Read, Write},
    net::{TcpListener, TcpStream},
    sync::OnceLock,
    thread,
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
    let config_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("kagome.example.yaml");
    let mut config = kagome::config::Config::load_from_path(config_path)
        .expect("example configuration should load");
    config.clients[0].public = Some("example.com".to_owned());
    let mut federated_server = config.clients[0]
        .federated_server
        .take()
        .expect("example client should configure federation");
    let (token_endpoint, identity_endpoint) = start_federated_server();
    federated_server.token_endpoint = token_endpoint;
    federated_server.endpoints[0].endpoint = identity_endpoint;
    config.clients.push(kagome::config::ClientConfig {
        client_id: "configured_client".to_owned(),
        public: None,
        client_secret: "configured_secret".to_owned(),
        redirect_uris: vec![
            "https://configured.example.com/callback".to_owned(),
            "https://configured.example.com/alternate".to_owned(),
        ],
        require_wallet_binding: false,
        federated_server: None,
    });
    config.clients.push(kagome::config::ClientConfig {
        client_id: "federated_client".to_owned(),
        public: None,
        client_secret: "federated_secret".to_owned(),
        redirect_uris: vec!["https://client.example.com/callback".to_owned()],
        require_wallet_binding: false,
        federated_server: Some(federated_server),
    });
    config.clients.push(kagome::config::ClientConfig {
        client_id: "wallet_bound_client".to_owned(),
        public: None,
        client_secret: "wallet_bound_secret".to_owned(),
        redirect_uris: vec!["https://wallet-bound.example.com/callback".to_owned()],
        require_wallet_binding: true,
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
            Some("Bearer upstream-access-token") => ("200 OK", r#"{"sub":"federated-user"}"#),
            Some("Bearer identity-malformed-token") => ("200 OK", "not-json"),
            Some("Bearer identity-missing-claim-token") => ("200 OK", "{}"),
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
    } else if parameters.contains("code=malformed-token") {
        ("200 OK", "not-json")
    } else if parameters.contains("code=empty-token") {
        ("200 OK", r#"{"access_token":""}"#)
    } else if parameters.contains("code=identity-rejected") {
        ("200 OK", r#"{"access_token":"identity-rejected-token"}"#)
    } else if parameters.contains("code=identity-malformed") {
        ("200 OK", r#"{"access_token":"identity-malformed-token"}"#)
    } else if parameters.contains("code=identity-missing-claim") {
        (
            "200 OK",
            r#"{"access_token":"identity-missing-claim-token"}"#,
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
    let response = format!(
        "HTTP/1.1 {status}\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{response_body}",
        response_body.len()
    );
    stream
        .write_all(response.as_bytes())
        .expect("failed to write federated token response");
}
