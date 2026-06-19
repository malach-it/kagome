use crate::{
    errors::OAuthError,
    resources::{authorization_code, client_credentials, resource_owner, response_type},
    unit::KagomeRequest,
};

use super::responses::{log_timestamp, logged_response, login_error_response};

pub use crate::requests::{AuthorizeCodeRequest, AuthorizeLoginRequest};

pub fn handle(request: &KagomeRequest) -> String {
    match request.method.to_ascii_uppercase().as_str() {
        "GET" => handle_authorize(request),
        "POST" => handle_authenticate(request),
        _ => not_found_response(),
    }
}

fn handle_authorize(request: &KagomeRequest) -> String {
    match authorize(AuthorizeLoginRequest::from_request(request))
        .and_then(authorization_code::validate_optional)
        .and_then(logged_response)
    {
        Ok(response) => response,
        Err(error) => {
            log_authorize_failure(&error);
            login_error_response(&request.query_params, &error)
        }
    }
}

fn handle_authenticate(request: &KagomeRequest) -> String {
    match authorize(AuthorizeCodeRequest::from_request(request))
        .and_then(authorization_code::validate_optional)
        .and_then(resource_owner::validate)
        .and_then(authorization_code::generate)
        .and_then(logged_response)
    {
        Ok(response) => response,
        Err(error) => {
            log_authorize_failure(&error);
            login_error_response(&request.query_params, &error)
        }
    }
}

fn authorize<T>(authorize_request: T) -> Result<T, OAuthError>
where
    T: response_type::Validate + client_credentials::Validate,
{
    response_type::validate(authorize_request).and_then(client_credentials::validate)
}

fn log_authorize_failure(error: &OAuthError) {
    eprintln!(
        "timestamp={} authorize_handler failure error={} error_description={}",
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
