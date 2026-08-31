use std::path::Path;

use crate::{ca, unit::KagomeRequest};

pub fn route_raw_request(request: &str) -> String {
    let request = crate::unit::parse_request(request);

    route_request(&request)
}

pub fn route_request(request: &KagomeRequest) -> String {
    route_request_with_ca_key_path(request, ca::ca_key_path_from_environment())
}

pub fn route_request_with_ca_key_path(
    request: &KagomeRequest,
    ca_key_path: impl AsRef<Path>,
) -> String {
    if request.path == "/authorize" {
        return crate::handlers::authorize::handle(request);
    }

    if request.method.eq_ignore_ascii_case("GET")
        && request.path == ca::SSH_CERTIFICATE_AUTHORITY_PATH
    {
        return ssh_certificate_authority_response(ca_key_path);
    }

    if request.method.eq_ignore_ascii_case("POST") && request.path == "/token" {
        return crate::handlers::token::handle(request);
    }

    if request.path == "/echo" {
        return crate::handlers::echo::handle(request);
    }

    not_found_response()
}

fn ssh_certificate_authority_response(ca_key_path: impl AsRef<Path>) -> String {
    let Ok(body) = ca::read_public_key(ca_key_path) else {
        return not_found_response();
    };

    format!(
        "HTTP/1.1 200 OK\r\ncontent-type: text/plain\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
        body.len(),
        body
    )
}

fn not_found_response() -> String {
    let body = "not found";

    format!(
        "HTTP/1.1 404 Not Found\r\ncontent-type: text/plain\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
        body.len(),
        body
    )
}
