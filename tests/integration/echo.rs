use super::server::send_request;

#[test]
fn server_echoes_get_request() {
    let response =
        send_request("GET /echo HTTP/1.1\r\nhost: example.com\r\ncontent-type: text/plain\r\n\r\n");

    assert!(response.starts_with("HTTP/1.1 200 OK\r\n"));
    assert!(response.contains("content-type: application/json\r\n"));
    assert!(response.contains("connection: close\r\n"));
    assert!(response.contains("\"method\":\"GET\""));
    assert!(response.contains("\"path\":\"/echo\""));
    assert!(response.contains("\"protocol\":\"HTTP/1.1\""));
    assert!(response.contains("{\"name\":\"host\",\"value\":\"example.com\"}"));
    assert!(response.contains("{\"name\":\"content-type\",\"value\":\"text/plain\"}"));
    assert!(response.contains("\"grant_type\":null"));
    assert!(response.ends_with("\"body\":\"\"}"));
}

#[test]
fn server_echoes_request_without_body() {
    let response = send_request("GET /echo HTTP/1.1\r\nhost: example.com\r\n\r\n");

    assert!(response.starts_with("HTTP/1.1 200 OK\r\n"));
    assert!(response.contains("connection: close\r\n"));
    assert!(response.contains("\"method\":\"GET\""));
    assert!(response.contains("\"path\":\"/echo\""));
    assert!(response.contains("\"protocol\":\"HTTP/1.1\""));
    assert!(response.contains("{\"name\":\"host\",\"value\":\"example.com\"}"));
    assert!(response.contains("\"grant_type\":null"));
    assert!(response.ends_with("\"body\":\"\"}"));
}

#[test]
fn server_echoes_post_grant_type() {
    let response = send_request(
        "POST /echo HTTP/1.1\r\nhost: example.com\r\ncontent-type: application/x-www-form-urlencoded\r\ncontent-length: 29\r\n\r\ngrant_type=client_credentials",
    );

    assert!(response.starts_with("HTTP/1.1 200 OK\r\n"));
    assert!(response.contains("connection: close\r\n"));
    assert!(response.contains("\"method\":\"POST\""));
    assert!(response.contains("\"path\":\"/echo\""));
    assert!(response.contains("\"grant_type\":\"client_credentials\""));
    assert!(response.ends_with("\"body\":\"grant_type=client_credentials\"}"));
}

#[test]
fn server_echoes_json_post_grant_type() {
    let response = send_request(
        "POST /echo HTTP/1.1\r\nhost: example.com\r\ncontent-type: application/json\r\ncontent-length: 35\r\n\r\n{\"grant_type\":\"client_credentials\"}",
    );

    assert!(response.starts_with("HTTP/1.1 200 OK\r\n"));
    assert!(response.contains("connection: close\r\n"));
    assert!(response.contains("\"method\":\"POST\""));
    assert!(response.contains("\"path\":\"/echo\""));
    assert!(response.contains("\"grant_type\":\"client_credentials\""));
    assert!(response.ends_with("\"body\":\"{\\\"grant_type\\\":\\\"client_credentials\\\"}\"}"));
}
