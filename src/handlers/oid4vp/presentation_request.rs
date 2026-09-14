use crate::{
    handlers::responses::{logged_response, oid4vp_error_response},
    requests::PresentationAuthorizationRequest,
    resources::{presentation_state, verifier},
    unit::KagomeRequest,
};

pub fn handle_presentation_request(request: &KagomeRequest) -> String {
    match verifier::validate(PresentationAuthorizationRequest::from_request(request))
        .and_then(presentation_state::generate)
        .and_then(logged_response)
    {
        Ok(response) => response,
        Err(error) => oid4vp_error_response(&error),
    }
}
