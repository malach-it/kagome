use crate::{
    handlers::responses::{
        authorization_error_redirect_response, logged_response, oauth_error_html_response,
    },
    requests::PresentationResponseRequest,
    resources::{
        authorization_code, client_credentials, presentation_state, presentation_submission,
        verifiable_presentation,
    },
    unit::KagomeRequest,
};

/// Handle `POST /presentation-response` from a presentation wallet.
///
/// Validates submission encoding, encrypted state, and client credentials before
/// retaining authorization redirect context. Wallet errors are validated and
/// consume state; successful submissions additionally validate the presentation
/// and generate an authorization code.
///
/// Returns the logged response on success. Early errors produce HTML OAuth errors;
/// later errors use the authorization redirect when trusted context is available.
pub fn handle_presentation_response(request: &KagomeRequest) -> String {
    let validated_state = presentation_submission::validate_encoding(
        PresentationResponseRequest::from_request(request),
    )
    .and_then(presentation_state::validate)
    .and_then(client_credentials::validate);

    let request = match validated_state {
        Ok(request) => request,
        Err(error) => {
            return oauth_error_html_response(None, &error.error, Some(&error.error_description));
        }
    };
    let destination = request
        .response
        .authorization_redirect_uri
        .as_ref()
        .zip(request.response.state_claims.as_ref())
        .map(|(redirect_uri, state)| (redirect_uri.clone(), state.authorization_state.clone()));
    let result = if request.error.is_some() {
        presentation_submission::validate_wallet_error(request)
            .and_then(presentation_state::consume)
    } else {
        presentation_submission::validate(request)
            .and_then(verifiable_presentation::validate)
            .and_then(presentation_state::consume)
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
            None => oauth_error_html_response(None, &error.error, Some(&error.error_description)),
        },
    }
}
