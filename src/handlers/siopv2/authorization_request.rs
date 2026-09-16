use crate::{
    errors::OAuthError,
    handlers::authorize,
    handlers::responses::{log_timestamp, logged_response, oauth_error_html_response},
    requests::{AuthorizeLoginRequest, SiopAuthorizationRequest},
    resources::{siopv2_request, siopv2_state},
    unit::KagomeRequest,
};

pub fn handle_siop_authorization_request(request: &KagomeRequest) -> String {
    match authorize::validate_siop_authorize(AuthorizeLoginRequest::from_request(request))
        .map(SiopAuthorizationRequest::from_authorize)
        .and_then(siopv2_state::generate)
        .and_then(siopv2_request::generate)
        .and_then(logged_response)
    {
        Ok(response) => response,
        Err(error) => {
            log_siopv2_request_failure(&error);
            oauth_error_html_response(&error.error, Some(&error.error_description))
        }
    }
}

fn log_siopv2_request_failure(error: &OAuthError) {
    eprintln!("{}", siopv2_request_failure_log(error));
}

fn siopv2_request_failure_log(error: &OAuthError) -> String {
    format!(
        "timestamp={} siopv2_request_handler failure error={} error_description={}",
        log_timestamp(),
        error.error,
        error.error_description
    )
}

#[cfg(test)]
mod tests {
    use super::siopv2_request_failure_log;
    use crate::errors::OAuthError;

    #[test]
    fn formats_siopv2_request_failure_log() {
        let log = siopv2_request_failure_log(&OAuthError::invalid_request(
            "code_challenge_method must be S256",
        ));

        assert!(log.contains("siopv2_request_handler failure"));
        assert!(log.contains("error=invalid_request"));
        assert!(log.contains("error_description=code_challenge_method must be S256"));
    }
}
