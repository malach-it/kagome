use crate::unit::{self, KagomeRequest};

pub fn handle(request: &KagomeRequest) -> String {
    let response_body = unit::to_json(request);

    format!(
        "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
        response_body.len(),
        response_body
    )
}
