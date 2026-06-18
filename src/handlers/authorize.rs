use crate::{
    errors::OAuthError,
    resources::{authorization_code, client_credentials, id_token, response_type},
    unit::KagomeRequest,
};

use super::responses::{log_timestamp, logged_response};

pub use crate::requests::AuthorizeCodeRequest;

pub fn handle(request: &KagomeRequest) -> String {
    match authorize(AuthorizeCodeRequest::from_request(request)).and_then(logged_response) {
        Ok(response) => response,
        Err(error) => {
            log_authorize_failure(&error);
            error.to_response()
        }
    }
}

fn authorize(authorize_request: AuthorizeCodeRequest) -> Result<AuthorizeCodeRequest, OAuthError> {
    response_type::validate(authorize_request)
        .and_then(client_credentials::validate)
        .and_then(id_token::validate)
        .and_then(authorization_code::generate)
}

fn log_authorize_failure(error: &OAuthError) {
    eprintln!(
        "timestamp={} authorize_handler failure error={} error_description={}",
        log_timestamp(),
        error.error,
        error.error_description
    );
}
