use crate::{
    handlers::responses::{oauth_error_html_response, wallet_authorization_redirect_response},
    resources::wallet_authorization,
    unit::{KagomeRequest, parse_query_parameter},
};

pub fn handle_wallet_authorization(request: &KagomeRequest) -> String {
    match wallet_authorization::resolve(parse_query_parameter(request, "id").as_deref()) {
        Ok(uri) => wallet_authorization_redirect_response(&uri),
        Err(error) => oauth_error_html_response(&error.error, Some(&error.error_description)),
    }
}
