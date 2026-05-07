use crate::unit;

pub fn handle(request: &str) -> String {
    let parsed_request = unit::parse_request(request);
    let response_body = unit::to_json(&parsed_request);

    format!(
        "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
        response_body.len(),
        response_body
    )
}
