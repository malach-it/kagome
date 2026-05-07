use crate::unit::KagomeRequest;

pub fn route_raw_request(request: &str) -> String {
    let request = crate::unit::parse_request(request);

    route_request(&request)
}

pub fn route_request(request: &KagomeRequest) -> String {
    if request.method.eq_ignore_ascii_case("POST") && request.path == "/token" {
        return crate::handlers::token::handle(request);
    }

    if request.path == "/echo" {
        return crate::handlers::echo::handle(request);
    }

    not_found_response()
}

fn not_found_response() -> String {
    let body = "not found";

    format!(
        "HTTP/1.1 404 Not Found\r\ncontent-type: text/plain\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
        body.len(),
        body
    )
}
