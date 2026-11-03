use crate::{
    errors::OAuthError,
    handlers::{
        authorize,
        responses::{log_timestamp, logged_response, query_error_response},
    },
    requests::{AuthorizeLoginRequest, FederationCallbackRequest},
    resources::federated_server,
    unit::KagomeRequest,
};

/// Handle `GET /federation_callback` and resume the original authorization flow.
///
/// Validates callback state before retaining its redirect context, validates the
/// callback shape, consumes state, and validates the upstream response before
/// continuing authorization. Failures are logged and returned as query error
/// redirects when trusted context exists, or direct OAuth errors otherwise.
/// Other methods return HTTP 404.
pub fn handle_federation_callback(request: &KagomeRequest) -> String {
    match request.method.to_ascii_uppercase().as_str() {
        "GET" => handle_authorization_response(request),
        _ => not_found_response(),
    }
}

fn handle_authorization_response(request: &KagomeRequest) -> String {
    let callback = match federated_server::validate_callback_state(
        FederationCallbackRequest::from_request(request),
    ) {
        Ok(callback) => callback,
        Err(error) => return federation_callback_error_response(error, None),
    };
    let error_redirect = callback
        .response
        .federation_state
        .as_ref()
        .and_then(|state| {
            state
                .request_parameters
                .redirect_uri
                .as_deref()
                .map(|redirect_uri| {
                    (
                        redirect_uri.to_owned(),
                        state.request_parameters.state.clone(),
                    )
                })
        });

    match federated_server::validate_callback_shape(callback)
        .and_then(federated_server::consume_callback_state)
        .and_then(federated_server::validate_callback)
        .and_then(|callback| AuthorizeLoginRequest::from_state(callback, request))
        .and_then(authorize::continue_federated_authorize)
        .and_then(logged_response)
    {
        Ok(response) => response,
        Err(error) => federation_callback_error_response(error, error_redirect),
    }
}

fn federation_callback_error_response(
    error: OAuthError,
    redirect: Option<(String, Option<String>)>,
) -> String {
    log_federation_callback_failure(&error);
    match redirect {
        Some((redirect_uri, state)) => {
            query_error_response(&redirect_uri, &error, state.as_deref())
        }
        None => error.to_response(),
    }
}

fn log_federation_callback_failure(error: &OAuthError) {
    eprintln!(
        "timestamp={} federation_callback_handler failure error={} error_description={}",
        log_timestamp(),
        error.error,
        error.error_description
    );
}

fn not_found_response() -> String {
    let body = "not found";

    format!(
        "HTTP/1.1 404 Not Found\r\ncontent-type: text/plain\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
        body.len(),
        body
    )
}
