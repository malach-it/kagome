use crate::unit::KagomeRequest;

pub fn route_raw_request(request: &str) -> String {
    let request = crate::unit::parse_request(request);

    route_request(&request)
}

pub fn route_request(request: &KagomeRequest) -> String {
    if request.path == "/authorize" {
        return crate::handlers::authorize::handle_authorize(request);
    }

    if request.path == "/federation_callback" {
        return crate::handlers::federation_callback::handle_federation_callback(request);
    }

    if request.method.eq_ignore_ascii_case("POST") && request.path == "/token" {
        return crate::handlers::token::handle_token(request);
    }

    if request.method.eq_ignore_ascii_case("GET")
        && request.path == "/.well-known/openid-credential-issuer"
    {
        return crate::handlers::oid4vci::credential_issuer_metadata::handle_credential_issuer_metadata(request);
    }

    if request.method.eq_ignore_ascii_case("GET")
        && request.path == "/.well-known/oauth-authorization-server"
    {
        return crate::handlers::oid4vci::authorization_server_metadata::handle_authorization_server_metadata(request);
    }

    if request.method.eq_ignore_ascii_case("GET") && request.path == "/credential-offer" {
        return crate::handlers::oid4vci::credential_offer::handle_credential_offer(request);
    }

    if request.method.eq_ignore_ascii_case("GET") && request.path == "/jwks" {
        return crate::handlers::oid4vci::jwks::handle_jwks(request);
    }

    if request.method.eq_ignore_ascii_case("POST") && request.path == "/credential" {
        return crate::handlers::oid4vci::credential::handle_credential(request);
    }

    if request.method.eq_ignore_ascii_case("GET") && request.path == "/presentation-request" {
        return crate::handlers::oid4vp::presentation_request::handle_presentation_request(request);
    }

    if request.method.eq_ignore_ascii_case("POST") && request.path == "/presentation-response" {
        return crate::handlers::oid4vp::presentation_response::handle_presentation_response(
            request,
        );
    }

    if request.path == "/echo" {
        return crate::handlers::echo::handle_echo(request);
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
