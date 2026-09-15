use crate::{
    errors::OAuthError,
    resources::{
        access_token, authorization_code, client_credentials, credential_issuer, federated_server,
        id_token, metadata_policy, pre_authorized_code, presentation_request, presentation_state,
        resource_owner,
        response_type::{self, ResponseType},
        verifier,
    },
    unit::KagomeRequest,
};

use super::responses::{authorize_error_http_response, log_timestamp, logged_response};

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
    let authorize_request = validate_authorize(AuthorizeLoginRequest::from_request(request))
        .and_then(authorization_code::validate_optional)
        .and_then(metadata_policy::validate);

    if authorize_request.as_ref().is_ok_and(|request| {
        matches!(
            request.response.response_types.as_slice(),
            [ResponseType::VpToken]
        )
    }) {
        return match authorize_request
            .and_then(generate_login_response)
            .and_then(logged_response)
        {
            Ok(response) => response,
            Err(error) => {
                log_authorize_failure(&error);
                authorize_error_response(request, error)
            }
        };
    }

    match authorize_request.and_then(resource_owner::validate_optional) {
        Ok(authorize_request) if authorize_request.has_resource_owner() => {
            match generate_login_response(authorize_request).and_then(logged_response) {
                Ok(response) => response,
                Err(error) => {
                    log_authorize_failure(&error);
                    authorize_error_response(request, error)
                }
            }
        }
        Ok(authorize_request) => match federated_server::configuration(&authorize_request) {
            Some(_) => federated_server::authorize(authorize_request).and_then(logged_response),
            None => logged_response(authorize_request),
        }
        .unwrap_or_else(|error| {
            log_authorize_failure(&error);
            authorize_error_response(request, error)
        }),
        Err(error) => {
            log_authorize_failure(&error);
            authorize_error_response(request, error)
        }
    }
}

fn handle_authentication(request: &KagomeRequest) -> String {
    match validate_authorize(AuthorizeCodeRequest::from_request(request))
        .and_then(authorization_code::validate_optional)
        .and_then(metadata_policy::validate)
        .and_then(resource_owner::validate)
        .and_then(generate_code_response)
        .and_then(logged_response)
    {
        Ok(response) => response,
        Err(error) => {
            log_authorize_failure(&error);
            authorize_error_response(request, error)
        }
    }
}

fn validate_authorize<T>(authorize_request: T) -> Result<T, OAuthError>
where
    T: response_type::Validate + client_credentials::Validate,
{
    response_type::validate(authorize_request).and_then(client_credentials::validate)
}

pub fn validate_siop_authorize(
    authorize_request: AuthorizeLoginRequest<'_>,
) -> Result<AuthorizeLoginRequest<'_>, OAuthError> {
    validate_authorize(authorize_request)
        .and_then(authorization_code::validate_optional)
        .and_then(metadata_policy::validate)
}

pub fn continue_federated_authorize(
    authorize_request: AuthorizeLoginRequest<'_>,
) -> Result<AuthorizeLoginRequest<'_>, OAuthError> {
    validate_authorize(authorize_request)
        .and_then(authorization_code::validate_optional)
        .and_then(metadata_policy::validate)
        .and_then(federated_server::request_access_token)
        .and_then(federated_server::fetch_identity)
        .and_then(generate_login_response)
}

pub fn continue_siop_authorize(
    authorize_request: AuthorizeLoginRequest<'_>,
) -> Result<AuthorizeLoginRequest<'_>, OAuthError> {
    validate_siop_authorize(authorize_request).and_then(generate_login_response)
}

fn generate_login_response(
    authorize_request: AuthorizeLoginRequest<'_>,
) -> Result<AuthorizeLoginRequest<'_>, OAuthError> {
    let is_authenticated = authorize_request.response.username.is_some()
        || authorize_request.response.federated_access_token.is_some();

    match authorize_request.response.response_types.as_slice() {
        [ResponseType::PreAuthorizedCode] if is_authenticated => {
            pre_authorized_code::generate(authorize_request)
        }
        [ResponseType::PreAuthorizedCode] => Err(OAuthError::missing_username()),
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
        [ResponseType::IdToken, ResponseType::Token] => Err(OAuthError::missing_username()),
        [ResponseType::Token] if is_authenticated => access_token::generate(authorize_request),
        [ResponseType::Token] => Err(OAuthError::missing_username()),
        [ResponseType::IdToken] if is_authenticated => id_token::generate(authorize_request),
        [ResponseType::IdToken] => Err(OAuthError::missing_username()),
        [ResponseType::VpToken] => verifier::validate(authorize_request)
            .and_then(credential_issuer::validate)
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
    let is_authenticated = authorize_request.response.username.is_some();

    match authorize_request.response.response_types.as_slice() {
        [ResponseType::PreAuthorizedCode] if is_authenticated => {
            pre_authorized_code::generate(authorize_request)
        }
        [ResponseType::PreAuthorizedCode] => Err(OAuthError::missing_username()),
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
        [ResponseType::IdToken, ResponseType::Token] => Err(OAuthError::missing_username()),
        [ResponseType::Token] if is_authenticated => access_token::generate(authorize_request),
        [ResponseType::Token] => Err(OAuthError::missing_username()),
        [ResponseType::IdToken] if is_authenticated => id_token::generate(authorize_request),
        [ResponseType::IdToken] => Err(OAuthError::missing_username()),
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

fn authorize_error_response(request: &KagomeRequest, mut error: OAuthError) -> String {
    if request
        .query_params
        .iter()
        .find(|(name, _)| name == "client_id")
        .is_some_and(|(_, client_id)| {
            client_credentials::client_id_resource_owner_credentials(client_id)
        })
    {
        error = error.with_format("query");
    }

    authorize_error_http_response(&request.query_params, &error)
}

fn not_found_response() -> String {
    let body = "not found";

    format!(
        "HTTP/1.1 404 Not Found\r\ncontent-type: text/plain\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
        body.len(),
        body
    )
}
