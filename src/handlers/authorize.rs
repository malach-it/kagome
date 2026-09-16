use crate::{
    errors::OAuthError,
    resources::{
        access_token, authorization_code, client_credentials, credential_issuer, federated_server,
        id_token, metadata_policy, pkce, pre_authorized_code, presentation_definition,
        presentation_request, presentation_state, resource_owner,
        response_type::{self, ResponseType},
        scope, verifier,
    },
    unit::KagomeRequest,
};

use super::responses::{log_timestamp, logged_response, oauth_error_html_response};

pub use crate::requests::{AuthorizeCodeRequest, AuthorizeLoginRequest};

pub fn handle_authorize(request: &KagomeRequest) -> String {
    if !request.method.eq_ignore_ascii_case("GET") && is_oid4vp_authorization_request(request) {
        return not_found_response();
    }

    match request.method.to_ascii_uppercase().as_str() {
        "GET" => handle_authorization_request(request),
        "POST" => handle_authentication(request),
        _ => not_found_response(),
    }
}

fn is_oid4vp_authorization_request(request: &KagomeRequest) -> bool {
    request
        .query_params
        .iter()
        .any(|(name, value)| name == "response_type" && value == "vp_token")
}

fn handle_authorization_request(request: &KagomeRequest) -> String {
    match validate_authorize(AuthorizeLoginRequest::from_request(request))
        .and_then(pkce::validate)
        .and_then(authorization_code::validate_optional)
        .and_then(metadata_policy::validate)
        .and_then(validate_optional_local_resource_owner)
        .and_then(select_authorization_request_flow)
        .and_then(logged_response)
    {
        Ok(response) => response,
        Err(error) => {
            log_authorize_failure(&error);
            authorize_error_response(error)
        }
    }
}

fn validate_optional_local_resource_owner(
    authorize_request: AuthorizeLoginRequest<'_>,
) -> Result<AuthorizeLoginRequest<'_>, OAuthError> {
    let authenticated = authorize_request.has_resource_owner();
    let federated = federated_server::configuration(&authorize_request).is_some();
    let presentation = matches!(
        authorize_request.response.response_types.as_slice(),
        [ResponseType::VpToken]
    );

    match (authenticated, federated, presentation) {
        (false, false, false) => resource_owner::validate_optional(authorize_request),
        _ => Ok(authorize_request),
    }
}

fn select_authorization_request_flow(
    authorize_request: AuthorizeLoginRequest<'_>,
) -> Result<AuthorizeLoginRequest<'_>, OAuthError> {
    match authorization_request_flow(&authorize_request) {
        AuthorizationRequestFlow::Generate => generate_login_response(authorize_request),
        AuthorizationRequestFlow::Federate => federated_server::authorize(authorize_request),
        AuthorizationRequestFlow::AwaitAuthentication => Ok(authorize_request),
    }
}

enum AuthorizationRequestFlow {
    Generate,
    Federate,
    AwaitAuthentication,
}

fn authorization_request_flow(
    authorize_request: &AuthorizeLoginRequest<'_>,
) -> AuthorizationRequestFlow {
    let authenticated = authorize_request.has_resource_owner();
    let federated = federated_server::configuration(authorize_request).is_some()
        && authorize_request.response.federated_access_token.is_none();
    let presentation = matches!(
        authorize_request.response.response_types.as_slice(),
        [ResponseType::VpToken]
    );

    match (authenticated, federated, presentation) {
        (true, _, _) | (false, false, true) => AuthorizationRequestFlow::Generate,
        (false, true, _) => AuthorizationRequestFlow::Federate,
        (false, false, false) => AuthorizationRequestFlow::AwaitAuthentication,
    }
}

fn handle_authentication(request: &KagomeRequest) -> String {
    match validate_authorize(AuthorizeCodeRequest::from_request(request))
        .and_then(pkce::validate)
        .and_then(authorization_code::validate_optional)
        .and_then(metadata_policy::validate)
        .and_then(resource_owner::validate)
        .and_then(generate_code_response)
        .and_then(logged_response)
    {
        Ok(response) => response,
        Err(error) => {
            log_authorize_failure(&error);
            authorize_error_response(error)
        }
    }
}

fn validate_authorize<T>(authorize_request: T) -> Result<T, OAuthError>
where
    T: response_type::Validate + client_credentials::Validate + scope::Validate,
{
    response_type::validate(authorize_request)
        .and_then(client_credentials::validate)
        .and_then(scope::validate)
}

pub fn validate_siop_authorize(
    authorize_request: AuthorizeLoginRequest<'_>,
) -> Result<AuthorizeLoginRequest<'_>, OAuthError> {
    validate_authorize(authorize_request)
        .and_then(pkce::validate)
        .and_then(authorization_code::validate_optional)
        .and_then(metadata_policy::validate)
}

pub fn continue_federated_authorize(
    authorize_request: AuthorizeLoginRequest<'_>,
) -> Result<AuthorizeLoginRequest<'_>, OAuthError> {
    validate_authorize(authorize_request)
        .and_then(pkce::validate)
        .and_then(authorization_code::validate_optional)
        .and_then(metadata_policy::validate)
        .and_then(federated_server::request_access_token)
        .and_then(federated_server::fetch_identity)
        .and_then(select_authorization_request_flow)
}

pub fn continue_siop_authorize(
    authorize_request: AuthorizeLoginRequest<'_>,
) -> Result<AuthorizeLoginRequest<'_>, OAuthError> {
    validate_siop_authorize(authorize_request).and_then(|authorize_request| {
        match (
            federated_server::configuration(&authorize_request).is_some(),
            authorize_request.is_siop_pre_authorized_code_continuation(),
        ) {
            (true, _) => authorization_code::generate(authorize_request)
                .and_then(federated_server::authorize),
            (false, true) => authorization_code::generate(authorize_request),
            (false, false) => generate_login_response(authorize_request),
        }
    })
}

fn generate_login_response(
    authorize_request: AuthorizeLoginRequest<'_>,
) -> Result<AuthorizeLoginRequest<'_>, OAuthError> {
    let is_authenticated = authorize_request.response.authenticated;

    match authorize_request.response.response_types.as_slice() {
        [ResponseType::PreAuthorizedCode] if is_authenticated => {
            pre_authorized_code::generate(authorize_request)
        }
        [ResponseType::PreAuthorizedCode] => Err(OAuthError::unauthenticated()),
        [
            ResponseType::Code,
            ResponseType::IdToken,
            ResponseType::Token,
        ] if is_authenticated => authorization_code::generate(authorize_request)
            .and_then(id_token::generate)
            .and_then(access_token::generate),
        [ResponseType::Code, ResponseType::Token] if is_authenticated => {
            authorization_code::generate(authorize_request).and_then(access_token::generate)
        }
        [ResponseType::Code, ResponseType::IdToken] if is_authenticated => {
            authorization_code::generate(authorize_request).and_then(id_token::generate)
        }
        [ResponseType::IdToken, ResponseType::Token] if is_authenticated => {
            id_token::generate(authorize_request).and_then(access_token::generate)
        }
        [ResponseType::IdToken, ResponseType::Token] => Err(OAuthError::unauthenticated()),
        [ResponseType::Token] if is_authenticated => access_token::generate(authorize_request),
        [ResponseType::Token] => Err(OAuthError::unauthenticated()),
        [ResponseType::IdToken] if is_authenticated => id_token::generate(authorize_request),
        [ResponseType::IdToken] => Err(OAuthError::unauthenticated()),
        [ResponseType::VpToken] => verifier::validate(authorize_request)
            .and_then(credential_issuer::validate)
            .and_then(presentation_definition::select)
            .and_then(presentation_state::generate)
            .and_then(presentation_request::generate),
        [ResponseType::Code, ..] => authorization_code::generate(authorize_request),
        [] => Err(OAuthError::unsupported_response_type(
            &response_type::SUPPORTED_RESPONSE_TYPES,
        )),
        [ResponseType::IdToken, ..]
        | [ResponseType::PreAuthorizedCode, ..]
        | [ResponseType::Token, ..]
        | [ResponseType::VpToken, ..] => Err(OAuthError::unsupported_response_type(
            &response_type::SUPPORTED_RESPONSE_TYPES,
        )),
    }
}

fn generate_code_response(
    authorize_request: AuthorizeCodeRequest<'_>,
) -> Result<AuthorizeCodeRequest<'_>, OAuthError> {
    let is_authenticated = authorize_request.response.authenticated;

    match authorize_request.response.response_types.as_slice() {
        [ResponseType::PreAuthorizedCode] if is_authenticated => {
            pre_authorized_code::generate(authorize_request)
        }
        [ResponseType::PreAuthorizedCode] => Err(OAuthError::unauthenticated()),
        [
            ResponseType::Code,
            ResponseType::IdToken,
            ResponseType::Token,
        ] if is_authenticated => authorization_code::generate(authorize_request)
            .and_then(id_token::generate)
            .and_then(access_token::generate),
        [ResponseType::Code, ResponseType::Token] if is_authenticated => {
            authorization_code::generate(authorize_request).and_then(access_token::generate)
        }
        [ResponseType::Code, ResponseType::IdToken] if is_authenticated => {
            authorization_code::generate(authorize_request).and_then(id_token::generate)
        }
        [ResponseType::IdToken, ResponseType::Token] if is_authenticated => {
            id_token::generate(authorize_request).and_then(access_token::generate)
        }
        [ResponseType::IdToken, ResponseType::Token] => Err(OAuthError::unauthenticated()),
        [ResponseType::Token] if is_authenticated => access_token::generate(authorize_request),
        [ResponseType::Token] => Err(OAuthError::unauthenticated()),
        [ResponseType::IdToken] if is_authenticated => id_token::generate(authorize_request),
        [ResponseType::IdToken] => Err(OAuthError::unauthenticated()),
        [ResponseType::Code, ..] => authorization_code::generate(authorize_request),
        [] => Err(OAuthError::unsupported_response_type(
            &response_type::SUPPORTED_RESPONSE_TYPES,
        )),
        [ResponseType::IdToken, ..]
        | [ResponseType::PreAuthorizedCode, ..]
        | [ResponseType::Token, ..]
        | [ResponseType::VpToken, ..] => Err(OAuthError::unsupported_response_type(
            &response_type::SUPPORTED_RESPONSE_TYPES,
        )),
    }
}

fn log_authorize_failure(error: &OAuthError) {
    eprintln!(
        "timestamp={} authorize_handler failure error={} error_description={}",
        log_timestamp(),
        error.error,
        error.error_description
    );
}

fn authorize_error_response(error: OAuthError) -> String {
    oauth_error_html_response(&error.error, Some(&error.error_description))
}

fn not_found_response() -> String {
    let body = "not found";

    format!(
        "HTTP/1.1 404 Not Found\r\ncontent-type: text/plain\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
        body.len(),
        body
    )
}
