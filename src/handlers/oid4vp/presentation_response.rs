use crate::{
    handlers::responses::{
        authorization_error_redirect_response, logged_response, oid4vp_error_response,
    },
    requests::PresentationResponseRequest,
    resources::{
        authorization_code, presentation_state, presentation_submission, verifiable_presentation,
    },
    unit::KagomeRequest,
};

pub fn handle_presentation_response(request: &KagomeRequest) -> String {
    let validated_state = presentation_submission::validate_encoding(
        PresentationResponseRequest::from_request(request),
    )
    .and_then(presentation_state::validate);

    let request = match validated_state {
        Ok(request) => request,
        Err(error) => return oid4vp_error_response(&error),
    };
    let destination = request.response.state_claims.as_ref().map(|state| {
        (
            state.authorization_redirect_uri.clone(),
            state.authorization_state.clone(),
        )
    });
    let result = if request.error.is_some() {
        presentation_submission::validate_wallet_error(request)
    } else {
        presentation_submission::validate(request)
            .and_then(verifiable_presentation::validate)
            .and_then(authorization_code::generate)
    }
    .and_then(logged_response);

    match result {
        Ok(response) => response,
        Err(error) => match destination {
            Some((redirect_uri, state)) => authorization_error_redirect_response(
                &redirect_uri,
                &error.error,
                Some(&error.error_description),
                state.as_deref(),
            ),
            None => oid4vp_error_response(&error),
        },
    }
}
