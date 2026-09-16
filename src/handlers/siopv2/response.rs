use crate::{
    handlers::{
        authorize,
        responses::{logged_response, oauth_error_html_response, siopv2_error_redirect_response},
    },
    requests::{AuthorizeLoginRequest, SiopResponseRequest},
    resources::{self_issued_id_token, siopv2_state},
    unit::KagomeRequest,
};

pub fn handle_siop_response(request: &KagomeRequest) -> String {
    let error_context = siopv2_state::validate(SiopResponseRequest::from_request(request))
        .ok()
        .and_then(|request| request.response.state_claims)
        .and_then(|state| Some((state.authorization.redirect_uri?, state.authorization.state)));
    let validated =
        self_issued_id_token::validate_encoding(SiopResponseRequest::from_request(request))
            .and_then(siopv2_state::validate);
    let result = match validated {
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
            Some((redirect_uri, state)) => siopv2_error_redirect_response(
                &redirect_uri,
                &error.error,
                Some(&error.error_description),
                state.as_deref(),
            ),
            None => oauth_error_html_response(None, &error.error, Some(&error.error_description)),
        },
    }
}
