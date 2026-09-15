use crate::{
    handlers::authorize,
    handlers::responses::{logged_response, oid4vp_error_response},
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
        Err(error) => oid4vp_error_response(&error),
    }
}
