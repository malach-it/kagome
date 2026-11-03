use crate::unit::{self, KagomeRequest};

/// Handle `/echo` by returning the parsed request as JSON in an HTTP 200 response.
///
/// The body uses the shared request serializer, including request headers and body.
pub fn handle_echo(request: &KagomeRequest) -> String {
    let response_body = unit::to_json(request);

    format!(
        "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
        response_body.len(),
        response_body
    )
}
