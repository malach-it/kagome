#[test]
fn echoes_http_request_parts() {
    let response = kagome::handlers::echo::handle(
        "POST /echo HTTP/1.1\r\nhost: example.com\r\ncontent-type: text/plain\r\n\r\nhello",
    );

    assert!(response.starts_with("HTTP/1.1 200 OK\r\n"));
    assert!(response.contains("content-type: application/json\r\n"));
    assert!(response.contains("connection: close\r\n"));
    assert!(response.contains("\"method\":\"POST\""));
    assert!(response.contains("\"protocol\":\"HTTP/1.1\""));
    assert!(response.contains("{\"name\":\"host\",\"value\":\"example.com\"}"));
    assert!(response.contains("{\"name\":\"content-type\",\"value\":\"text/plain\"}"));
    assert!(response.ends_with("\"body\":\"hello\"}"));
}
