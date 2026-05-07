use super::server::send_request;

#[test]
fn server_echoes_post_request() {
    let response = send_request(
        "POST /echo HTTP/1.1\r\nhost: example.com\r\ncontent-type: text/plain\r\ncontent-length: 5\r\n\r\nhello",
    );

    assert!(response.starts_with("HTTP/1.1 200 OK\r\n"));
    assert!(response.contains("content-type: application/json\r\n"));
    assert!(response.contains("\"method\":\"POST\""));
    assert!(response.contains("\"protocol\":\"HTTP/1.1\""));
    assert!(response.contains("{\"name\":\"host\",\"value\":\"example.com\"}"));
    assert!(response.contains("{\"name\":\"content-type\",\"value\":\"text/plain\"}"));
    assert!(response.contains("{\"name\":\"content-length\",\"value\":\"5\"}"));
    assert!(response.ends_with("\"body\":\"hello\"}"));
}

#[test]
fn server_echoes_request_without_body() {
    let response = send_request("GET /echo HTTP/1.1\r\nhost: example.com\r\n\r\n");

    assert!(response.starts_with("HTTP/1.1 200 OK\r\n"));
    assert!(response.contains("\"method\":\"GET\""));
    assert!(response.contains("\"protocol\":\"HTTP/1.1\""));
    assert!(response.contains("{\"name\":\"host\",\"value\":\"example.com\"}"));
    assert!(response.ends_with("\"body\":\"\"}"));
}
