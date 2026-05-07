#[test]
fn echoes_http_request_parts() {
    let request = kagome::unit::KagomeRequest {
        method: "POST".to_owned(),
        path: "/echo".to_owned(),
        protocol: "HTTP/1.1".to_owned(),
        headers: vec![
            kagome::unit::HttpHeader {
                name: "host".to_owned(),
                value: "example.com".to_owned(),
            },
            kagome::unit::HttpHeader {
                name: "content-type".to_owned(),
                value: "text/plain".to_owned(),
            },
        ],
        body: "hello".to_owned(),
    };
    let response = kagome::handlers::echo::handle(&request);

    assert!(response.starts_with("HTTP/1.1 200 OK\r\n"));
    assert!(response.contains("content-type: application/json\r\n"));
    assert!(response.contains("connection: close\r\n"));
    assert!(response.contains("\"method\":\"POST\""));
    assert!(response.contains("\"path\":\"/echo\""));
    assert!(response.contains("\"protocol\":\"HTTP/1.1\""));
    assert!(response.contains("{\"name\":\"host\",\"value\":\"example.com\"}"));
    assert!(response.contains("{\"name\":\"content-type\",\"value\":\"text/plain\"}"));
    assert!(response.ends_with("\"body\":\"hello\"}"));
}
