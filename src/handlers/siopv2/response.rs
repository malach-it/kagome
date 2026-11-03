use crate::{
    handlers::{
        authorize,
        responses::{logged_response, oauth_error_html_response, siopv2_error_redirect_response},
    },
    requests::{AuthorizeLoginRequest, SiopResponseRequest},
    resources::{self_issued_id_token, siopv2_state},
    unit::KagomeRequest,
};

/// Handle `POST /siopv2-response` and resume authorization after wallet sign-in.
///
/// Validates encrypted state before retaining trusted error context, then checks
/// response encoding. Wallet errors are validated and consume state; successful
/// responses validate the self-issued ID token, consume state, and continue
/// authorization with the restored identity.
///
/// Returns the logged response on success. Errors use a SIOPv2 error redirect
/// when trusted context exists, or an HTML OAuth error otherwise.
pub fn handle_siop_response(request: &KagomeRequest) -> String {
    let response = match siopv2_state::validate(SiopResponseRequest::from_request(request)) {
        Ok(response) => response,
        Err(error) => {
            return oauth_error_html_response(None, &error.error, Some(&error.error_description));
        }
    };
    let error_context = response.error_context();
    let result = match self_issued_id_token::validate_encoding(response) {
        Ok(response) if response.error.is_some() => {
            self_issued_id_token::validate_wallet_error(response)
                .and_then(siopv2_state::consume)
                .and_then(logged_response)
        }
        Ok(response) => self_issued_id_token::validate(response)
            .and_then(siopv2_state::consume)
            .and_then(|response| AuthorizeLoginRequest::from_siop(response, request))
            .and_then(authorize::continue_siop_authorize)
            .and_then(logged_response),
        Err(error) => Err(error),
    };

    match result {
        Ok(response) => response,
        Err(error) => match error_context {
            Some(context) => siopv2_error_redirect_response(
                &context.redirect_uri,
                &error.error,
                Some(&error.error_description),
                context.state.as_deref(),
            ),
            None => oauth_error_html_response(None, &error.error, Some(&error.error_description)),
        },
    }
}
