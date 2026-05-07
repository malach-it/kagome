use kagome::unit::{HttpHeader, KagomeRequest, parse_request, to_json};

#[test]
fn parses_crlf_request_protocol_headers_and_body() {
    let request = parse_request(
        "POST /echo HTTP/1.1\r\nhost: example.com\r\ncontent-type: text/plain\r\n\r\nhello",
    );

    assert_eq!(request.method, "POST");
    assert_eq!(request.path, "/echo");
    assert_eq!(request.protocol, "HTTP/1.1");
    assert_eq!(request.body, "hello");
    assert_eq!(request.headers.len(), 2);
    assert_eq!(request.headers[0].name, "host");
    assert_eq!(request.headers[0].value, "example.com");
    assert_eq!(request.headers[1].name, "content-type");
    assert_eq!(request.headers[1].value, "text/plain");
}

#[test]
fn parses_lf_request_body_separator() {
    let request = parse_request("GET /echo HTTP/2\naccept: application/json\n\nhello");

    assert_eq!(request.method, "GET");
    assert_eq!(request.path, "/echo");
    assert_eq!(request.protocol, "HTTP/2");
    assert_eq!(request.body, "hello");
    assert_eq!(request.headers.len(), 1);
    assert_eq!(request.headers[0].name, "accept");
    assert_eq!(request.headers[0].value, "application/json");
}

#[test]
fn trims_header_names_and_values() {
    let request = parse_request("GET /echo HTTP/1.1\r\nhost :  example.com  \r\n\r\n");

    assert_eq!(request.headers.len(), 1);
    assert_eq!(request.headers[0].name, "host");
    assert_eq!(request.headers[0].value, "example.com");
}

#[test]
fn defaults_protocol_when_request_line_is_invalid() {
    let request = parse_request("invalid-request-line\r\nhost: example.com\r\n\r\nhello");

    assert_eq!(request.method, "invalid-request-line");
    assert_eq!(request.path, "");
    assert_eq!(request.protocol, "");
    assert_eq!(request.body, "hello");
    assert_eq!(request.headers.len(), 1);
    assert_eq!(request.headers[0].name, "host");
    assert_eq!(request.headers[0].value, "example.com");
}

#[test]
fn ignores_header_lines_without_colons() {
    let request =
        parse_request("GET /echo HTTP/1.1\r\nmalformed-header\r\nhost: example.com\r\n\r\n");

    assert_eq!(request.headers.len(), 1);
    assert_eq!(request.headers[0].name, "host");
    assert_eq!(request.headers[0].value, "example.com");
}

#[test]
fn handles_empty_request() {
    let request = parse_request("");

    assert_eq!(request.method, "");
    assert_eq!(request.path, "");
    assert_eq!(request.protocol, "");
    assert!(request.headers.is_empty());
    assert_eq!(request.body, "");
}

#[test]
fn converts_request_to_json() {
    let request = KagomeRequest {
        method: "POST".to_owned(),
        path: "/echo".to_owned(),
        protocol: "HTTP/1.1".to_owned(),
        headers: vec![HttpHeader {
            name: "x-message".to_owned(),
            value: "hello \"kagome\"".to_owned(),
        }],
        body: "line one\nline two".to_owned(),
    };

    assert_eq!(
        to_json(&request),
        "{\"method\":\"POST\",\"path\":\"/echo\",\"protocol\":\"HTTP/1.1\",\"headers\":[{\"name\":\"x-message\",\"value\":\"hello \\\"kagome\\\"\"}],\"body\":\"line one\\nline two\"}"
    );
}

#[test]
fn escapes_control_characters_in_json() {
    let request = KagomeRequest {
        method: "POST".to_owned(),
        path: "/echo".to_owned(),
        protocol: "HTTP/1.1".to_owned(),
        headers: vec![HttpHeader {
            name: "x-tab".to_owned(),
            value: "a\tb".to_owned(),
        }],
        body: "carriage\rreturn".to_owned(),
    };

    assert_eq!(
        to_json(&request),
        "{\"method\":\"POST\",\"path\":\"/echo\",\"protocol\":\"HTTP/1.1\",\"headers\":[{\"name\":\"x-tab\",\"value\":\"a\\tb\"}],\"body\":\"carriage\\rreturn\"}"
    );
}
