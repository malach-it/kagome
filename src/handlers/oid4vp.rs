use crate::{
    requests::{PresentationAuthorizationRequest, PresentationResponseRequest},
    resources::{presentation_state, presentation_submission, verifiable_presentation, verifier},
    unit::KagomeRequest,
};

use super::responses::{logged_response, oid4vp_error_response};

pub fn presentation_request(request: &KagomeRequest) -> String {
    match verifier::validate(PresentationAuthorizationRequest::from_request(request))
        .and_then(presentation_state::generate)
        .and_then(logged_response)
    {
        Ok(response) => response,
        Err(error) => oid4vp_error_response(&error),
    }
}

pub fn presentation_response(request: &KagomeRequest) -> String {
    let result = presentation_submission::validate_encoding(
        PresentationResponseRequest::from_request(request),
    )
    .and_then(presentation_state::validate)
    .and_then(|request| {
        if request.error.is_some() {
            presentation_submission::validate_wallet_error(request)
        } else {
            verifiable_presentation::validate(request)
        }
    })
    .and_then(logged_response);

    match result {
        Ok(response) => response,
        Err(error) => oid4vp_error_response(&error),
    }
}
