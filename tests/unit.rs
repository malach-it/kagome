use kagome::unit::{
    HttpHeader, KagomeRequest, parse_query_parameter, parse_request, parse_request_parameter,
    to_json,
};

#[test]
fn parses_crlf_request_protocol_headers_and_body() {
    let request = parse_request(
        "POST /echo HTTP/1.1\r\nhost: example.com\r\ncontent-type: text/plain\r\n\r\nhello",
    );

    assert_eq!(request.method, "POST");
    assert_eq!(request.path, "/echo");
    assert_eq!(request.protocol, "HTTP/1.1");
    assert_eq!(request.body, "hello");
    assert_eq!(parse_request_parameter(&request, "client_id"), None);
    assert_eq!(parse_request_parameter(&request, "client_secret"), None);
    assert_eq!(parse_request_parameter(&request, "grant_type"), None);
    assert_eq!(parse_request_parameter(&request, "id_token"), None);
    assert_eq!(
        parse_request_parameter(&request, "authorization_code"),
        None
    );
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
    assert_eq!(parse_request_parameter(&request, "client_id"), None);
    assert_eq!(parse_request_parameter(&request, "client_secret"), None);
    assert_eq!(parse_request_parameter(&request, "grant_type"), None);
    assert_eq!(parse_request_parameter(&request, "id_token"), None);
    assert_eq!(
        parse_request_parameter(&request, "authorization_code"),
        None
    );
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
    assert_eq!(parse_request_parameter(&request, "client_id"), None);
    assert_eq!(parse_request_parameter(&request, "client_secret"), None);
    assert_eq!(parse_request_parameter(&request, "grant_type"), None);
    assert_eq!(parse_request_parameter(&request, "id_token"), None);
    assert_eq!(
        parse_request_parameter(&request, "authorization_code"),
        None
    );
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
    assert_eq!(parse_request_parameter(&request, "client_id"), None);
    assert_eq!(parse_request_parameter(&request, "client_secret"), None);
    assert_eq!(parse_request_parameter(&request, "grant_type"), None);
    assert_eq!(parse_request_parameter(&request, "id_token"), None);
    assert_eq!(
        parse_request_parameter(&request, "authorization_code"),
        None
    );
    assert_eq!(request.body, "");
}

#[test]
fn parses_client_id_from_post_body_parameter() {
    let request = parse_request(
        "POST /echo HTTP/1.1\r\ncontent-type: application/x-www-form-urlencoded\r\n\r\nclient_id=client_id&grant_type=client_credentials",
    );

    assert_eq!(
        parse_request_parameter(&request, "client_id"),
        Some("client_id".to_owned())
    );
}

#[test]
fn parses_query_parameter() {
    let request = parse_request(
        "GET /authorize?response_type=code&client_id=client_id&id_token=id.jwt.token HTTP/1.1\r\n\r\n",
    );

    assert_eq!(request.path, "/authorize");
    assert_eq!(
        request.query_params,
        vec![
            ("response_type".to_owned(), "code".to_owned()),
            ("client_id".to_owned(), "client_id".to_owned()),
            ("id_token".to_owned(), "id.jwt.token".to_owned()),
        ]
    );
    assert_eq!(
        parse_query_parameter(&request, "response_type"),
        Some("code".to_owned())
    );
    assert_eq!(
        parse_query_parameter(&request, "client_id"),
        Some("client_id".to_owned())
    );
    assert_eq!(
        parse_query_parameter(&request, "id_token"),
        Some("id.jwt.token".to_owned())
    );
}

#[test]
fn decodes_query_parameter_form_value() {
    let request = parse_request(
        "GET /authorize?response_type=code&client_id=client+id&id_token=id%2Ejwt%2Etoken HTTP/1.1\r\n\r\n",
    );

    assert_eq!(
        parse_query_parameter(&request, "client_id"),
        Some("client id".to_owned())
    );
    assert_eq!(
        parse_query_parameter(&request, "id_token"),
        Some("id.jwt.token".to_owned())
    );
}

#[test]
fn parses_client_id_from_json_post_body() {
    let request = parse_request(
        "POST /echo HTTP/1.1\r\ncontent-type: application/json\r\n\r\n{\"client_id\":\"client_id\",\"grant_type\":\"client_credentials\"}",
    );

    assert_eq!(
        parse_request_parameter(&request, "client_id"),
        Some("client_id".to_owned())
    );
}

#[test]
fn parses_client_secret_from_post_body_parameter() {
    let request = parse_request(
        "POST /echo HTTP/1.1\r\ncontent-type: application/x-www-form-urlencoded\r\n\r\nclient_id=client_id&client_secret=client_secret&grant_type=client_credentials",
    );

    assert_eq!(
        parse_request_parameter(&request, "client_secret"),
        Some("client_secret".to_owned())
    );
}

#[test]
fn parses_client_secret_from_json_post_body() {
    let request = parse_request(
        "POST /echo HTTP/1.1\r\ncontent-type: application/json\r\n\r\n{\"client_id\":\"client_id\",\"client_secret\":\"client_secret\",\"grant_type\":\"client_credentials\"}",
    );

    assert_eq!(
        parse_request_parameter(&request, "client_secret"),
        Some("client_secret".to_owned())
    );
}

#[test]
fn parses_grant_type_from_post_body_parameter() {
    let request = parse_request(
        "POST /echo HTTP/1.1\r\ncontent-type: application/x-www-form-urlencoded\r\n\r\nclient_id=kagome&grant_type=client_credentials",
    );

    assert_eq!(
        parse_request_parameter(&request, "grant_type"),
        Some("client_credentials".to_owned())
    );
}

#[test]
fn parses_id_token_from_post_body_parameter() {
    let request = parse_request(
        "POST /echo HTTP/1.1\r\ncontent-type: application/x-www-form-urlencoded\r\n\r\nid_token=id.jwt.token&grant_type=code_chain",
    );

    assert_eq!(
        parse_request_parameter(&request, "id_token"),
        Some("id.jwt.token".to_owned())
    );
}

#[test]
fn parses_id_token_from_json_post_body() {
    let request = parse_request(
        "POST /echo HTTP/1.1\r\ncontent-type: application/json\r\n\r\n{\"id_token\":\"id.jwt.token\",\"grant_type\":\"code_chain\"}",
    );

    assert_eq!(
        parse_request_parameter(&request, "id_token"),
        Some("id.jwt.token".to_owned())
    );
}

#[test]
fn parses_authorization_code_from_post_body_parameter() {
    let request = parse_request(
        "POST /echo HTTP/1.1\r\ncontent-type: application/x-www-form-urlencoded\r\n\r\nauthorization_code=auth.cose.code&grant_type=code_chain",
    );

    assert_eq!(
        parse_request_parameter(&request, "authorization_code"),
        Some("auth.cose.code".to_owned())
    );
}

#[test]
fn parses_authorization_code_from_json_post_body() {
    let request = parse_request(
        "POST /echo HTTP/1.1\r\ncontent-type: application/json\r\n\r\n{\"authorization_code\":\"auth.cose.code\",\"grant_type\":\"code_chain\"}",
    );

    assert_eq!(
        parse_request_parameter(&request, "authorization_code"),
        Some("auth.cose.code".to_owned())
    );
}

#[test]
fn decodes_grant_type_form_value() {
    let request = parse_request(
        "POST /echo HTTP/1.1\r\ncontent-type: application/x-www-form-urlencoded\r\n\r\ngrant_type=urn%3Aexample+grant",
    );

    assert_eq!(
        parse_request_parameter(&request, "grant_type"),
        Some("urn:example grant".to_owned())
    );
}

#[test]
fn keeps_malformed_percent_encoding_in_grant_type() {
    let request = parse_request(
        "POST /echo HTTP/1.1\r\ncontent-type: application/x-www-form-urlencoded\r\n\r\ngrant_type=client%zz",
    );

    assert_eq!(
        parse_request_parameter(&request, "grant_type"),
        Some("client%zz".to_owned())
    );
}

#[test]
fn keeps_empty_grant_type_from_post_body_parameter() {
    let request = parse_request(
        "POST /echo HTTP/1.1\r\ncontent-type: application/x-www-form-urlencoded\r\n\r\ngrant_type=",
    );

    assert_eq!(
        parse_request_parameter(&request, "grant_type"),
        Some("".to_owned())
    );
}

#[test]
fn ignores_grant_type_for_non_post_requests() {
    let request = parse_request("GET /echo HTTP/1.1\r\n\r\ngrant_type=client_credentials");

    assert_eq!(parse_request_parameter(&request, "grant_type"), None);
}

#[test]
fn ignores_id_token_for_non_post_requests() {
    let request = parse_request("GET /echo HTTP/1.1\r\n\r\nid_token=id.jwt.token");

    assert_eq!(parse_request_parameter(&request, "id_token"), None);
}

#[test]
fn ignores_authorization_code_for_non_post_requests() {
    let request = parse_request("GET /echo HTTP/1.1\r\n\r\nauthorization_code=auth.cose.code");

    assert_eq!(
        parse_request_parameter(&request, "authorization_code"),
        None
    );
}

#[test]
fn ignores_missing_grant_type_body_parameter() {
    let request = parse_request(
        "POST /echo HTTP/1.1\r\ncontent-type: application/x-www-form-urlencoded\r\n\r\nclient_id=kagome",
    );

    assert_eq!(parse_request_parameter(&request, "grant_type"), None);
}

#[test]
fn parses_grant_type_from_json_post_body() {
    let request = parse_request(
        "POST /echo HTTP/1.1\r\ncontent-type: application/json\r\n\r\n{\"client_id\":\"kagome\",\"grant_type\":\"client_credentials\"}",
    );

    assert_eq!(
        parse_request_parameter(&request, "grant_type"),
        Some("client_credentials".to_owned())
    );
}

#[test]
fn parses_grant_type_from_json_with_content_type_parameters() {
    let request = parse_request(
        "POST /echo HTTP/1.1\r\ncontent-type: application/json; charset=utf-8\r\n\r\n{\"grant_type\":\"client_credentials\"}",
    );

    assert_eq!(
        parse_request_parameter(&request, "grant_type"),
        Some("client_credentials".to_owned())
    );
}

#[test]
fn decodes_escaped_json_grant_type() {
    let request = parse_request(
        "POST /echo HTTP/1.1\r\ncontent-type: application/json\r\n\r\n{\"grant_type\":\"urn:\\/example\\ngrant\"}",
    );

    assert_eq!(
        parse_request_parameter(&request, "grant_type"),
        Some("urn:/example\ngrant".to_owned())
    );
}

#[test]
fn ignores_json_grant_type_when_value_is_not_string() {
    let request = parse_request(
        "POST /echo HTTP/1.1\r\ncontent-type: application/json\r\n\r\n{\"grant_type\":123}",
    );

    assert_eq!(parse_request_parameter(&request, "grant_type"), None);
}

#[test]
fn ignores_grant_type_for_unsupported_content_type() {
    let request = parse_request(
        "POST /echo HTTP/1.1\r\ncontent-type: text/plain\r\n\r\ngrant_type=client_credentials",
    );

    assert_eq!(parse_request_parameter(&request, "grant_type"), None);
}

#[test]
fn ignores_id_token_for_unsupported_content_type() {
    let request = parse_request(
        "POST /echo HTTP/1.1\r\ncontent-type: text/plain\r\n\r\nid_token=id.jwt.token",
    );

    assert_eq!(parse_request_parameter(&request, "id_token"), None);
}

#[test]
fn ignores_authorization_code_for_unsupported_content_type() {
    let request = parse_request(
        "POST /echo HTTP/1.1\r\ncontent-type: text/plain\r\n\r\nauthorization_code=auth.cose.code",
    );

    assert_eq!(
        parse_request_parameter(&request, "authorization_code"),
        None
    );
}

#[test]
fn ignores_grant_type_when_content_type_is_missing() {
    let request = parse_request("POST /echo HTTP/1.1\r\n\r\ngrant_type=client_credentials");

    assert_eq!(parse_request_parameter(&request, "grant_type"), None);
}

#[test]
fn ignores_id_token_when_content_type_is_missing() {
    let request = parse_request("POST /echo HTTP/1.1\r\n\r\nid_token=id.jwt.token");

    assert_eq!(parse_request_parameter(&request, "id_token"), None);
}

#[test]
fn ignores_authorization_code_when_content_type_is_missing() {
    let request = parse_request("POST /echo HTTP/1.1\r\n\r\nauthorization_code=auth.cose.code");

    assert_eq!(
        parse_request_parameter(&request, "authorization_code"),
        None
    );
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
        query_params: vec![("trace".to_owned(), "hello \"query\"".to_owned())],
        body: "line one\nline two".to_owned(),
    };

    assert_eq!(
        to_json(&request),
        "{\"method\":\"POST\",\"path\":\"/echo\",\"protocol\":\"HTTP/1.1\",\"headers\":[{\"name\":\"x-message\",\"value\":\"hello \\\"kagome\\\"\"}],\"query_params\":[{\"name\":\"trace\",\"value\":\"hello \\\"query\\\"\"}],\"body\":\"line one\\nline two\"}"
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
        query_params: Vec::new(),
        body: "carriage\rreturn".to_owned(),
    };

    assert_eq!(
        to_json(&request),
        "{\"method\":\"POST\",\"path\":\"/echo\",\"protocol\":\"HTTP/1.1\",\"headers\":[{\"name\":\"x-tab\",\"value\":\"a\\tb\"}],\"query_params\":[],\"body\":\"carriage\\rreturn\"}"
    );
}
