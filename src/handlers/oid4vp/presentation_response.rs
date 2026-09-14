use crate::{
    handlers::responses::{logged_response, oid4vp_error_response},
    requests::PresentationResponseRequest,
    resources::{presentation_state, presentation_submission, verifiable_presentation},
    unit::KagomeRequest,
};

pub fn handle_presentation_response(request: &KagomeRequest) -> String {
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
