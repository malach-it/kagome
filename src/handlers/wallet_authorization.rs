use crate::{
    handlers::responses::{oauth_error_html_response, wallet_authorization_redirect_response},
    resources::wallet_authorization,
    unit::{KagomeRequest, parse_query_parameter},
};

/// Handle `GET /wallet-authorization` by resolving the query parameter `id`.
///
/// Returns a redirect to the resolved wallet authorization URI, or an HTML OAuth
/// error response when resolution fails.
pub fn handle_wallet_authorization(request: &KagomeRequest) -> String {
    match wallet_authorization::resolve(parse_query_parameter(request, "id").as_deref()) {
        Ok(uri) => wallet_authorization_redirect_response(&uri),
        Err(error) => oauth_error_html_response(None, &error.error, Some(&error.error_description)),
    }
}
