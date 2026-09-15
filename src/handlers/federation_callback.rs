use crate::{
    errors::OAuthError,
    handlers::{
        authorize,
        responses::{log_timestamp, logged_response},
    },
    requests::{AuthorizeLoginRequest, FederationCallbackRequest},
    resources::federated_server,
    unit::KagomeRequest,
};

pub fn handle_federation_callback(request: &KagomeRequest) -> String {
    match request.method.to_ascii_uppercase().as_str() {
        "GET" => handle_authorization_response(request),
        _ => not_found_response(),
    }
}

fn handle_authorization_response(request: &KagomeRequest) -> String {
    match federated_server::validate_callback(FederationCallbackRequest::from_request(request))
        .and_then(|callback| AuthorizeLoginRequest::from_state(callback, request))
        .and_then(authorize::continue_federated_authorize)
        .and_then(logged_response)
    {
        Ok(response) => response,
        Err(error) => {
            log_federation_callback_failure(&error);
            error.to_response()
        }
    }
}

fn log_federation_callback_failure(error: &OAuthError) {
    eprintln!(
        "timestamp={} federation_callback_handler failure error={} error_description={}",
        log_timestamp(),
        error.error,
        error.error_description
    );
}

fn not_found_response() -> String {
    let body = "not found";

    format!(
        "HTTP/1.1 404 Not Found\r\ncontent-type: text/plain\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
        body.len(),
        body
    )
}
