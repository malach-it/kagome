use crate::{
    errors::OAuthError,
    resources::{
        access_token, authorization_code, client_credentials, federated_server, id_token,
        metadata_policy, resource_owner,
        response_type::{self, ResponseType},
    },
    unit::KagomeRequest,
};

use super::responses::{log_timestamp, logged_response, login_error_response};

pub use crate::requests::{AuthorizeCodeRequest, AuthorizeLoginRequest};

pub fn handle_authorize(request: &KagomeRequest) -> String {
    match request.method.to_ascii_uppercase().as_str() {
        "GET" => handle_authorization_request(request),
        "POST" => handle_authentication(request),
        _ => not_found_response(),
    }
}

fn handle_authorization_request(request: &KagomeRequest) -> String {
    let authorize_request = validate_authorize(AuthorizeLoginRequest::from_request(request))
        .and_then(authorization_code::validate_optional)
        .and_then(metadata_policy::validate);

    match authorize_request.and_then(resource_owner::validate_optional) {
        Ok(authorize_request) if authorize_request.has_resource_owner() => {
            match generate_response(authorize_request).and_then(logged_response) {
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
        .and_then(generate_response)
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

trait GenerateAuthorizeResponse {
    fn response_types(&self) -> &[ResponseType];
    fn is_authenticated(&self) -> bool;
}

impl GenerateAuthorizeResponse for AuthorizeLoginRequest<'_> {
    fn response_types(&self) -> &[ResponseType] {
        &self.response.response_types
    }

    fn is_authenticated(&self) -> bool {
        self.response.username.is_some() || self.response.federated_access_token.is_some()
    }
}

impl GenerateAuthorizeResponse for AuthorizeCodeRequest<'_> {
    fn response_types(&self) -> &[ResponseType] {
        &self.response.response_types
    }

    fn is_authenticated(&self) -> bool {
        self.response.username.is_some()
    }
}

pub fn continue_federated_authorize(
    authorize_request: AuthorizeLoginRequest<'_>,
) -> Result<AuthorizeLoginRequest<'_>, OAuthError> {
    validate_authorize(authorize_request)
        .and_then(authorization_code::validate_optional)
        .and_then(metadata_policy::validate)
        .and_then(federated_server::request_access_token)
        .and_then(federated_server::fetch_identity)
        .and_then(generate_response)
}

fn generate_response<T>(authorize_request: T) -> Result<T, OAuthError>
where
    T: GenerateAuthorizeResponse
        + access_token::Generate
        + authorization_code::Generate
        + id_token::Generate,
{
    match authorize_request.response_types() {
        [
            ResponseType::Code,
            ResponseType::IdToken,
            ResponseType::Token,
        ] if authorize_request.is_authenticated() => {
            authorization_code::generate(authorize_request)
                .and_then(id_token::generate)
                .and_then(access_token::generate)
        }
        [ResponseType::Code, ResponseType::Token] if authorize_request.is_authenticated() => {
            authorization_code::generate(authorize_request).and_then(access_token::generate)
        }
        [ResponseType::Code, ResponseType::IdToken] if authorize_request.is_authenticated() => {
            authorization_code::generate(authorize_request).and_then(id_token::generate)
        }
        [ResponseType::IdToken, ResponseType::Token] if authorize_request.is_authenticated() => {
            id_token::generate(authorize_request).and_then(access_token::generate)
        }
        [ResponseType::IdToken, ResponseType::Token] => Err(OAuthError::missing_username()),
        [ResponseType::Token] if authorize_request.is_authenticated() => {
            access_token::generate(authorize_request)
        }
        [ResponseType::Token] => Err(OAuthError::missing_username()),
        [ResponseType::IdToken] if authorize_request.is_authenticated() => {
            id_token::generate(authorize_request)
        }
        [ResponseType::IdToken] => Err(OAuthError::missing_username()),
        [ResponseType::Code, ..] => authorization_code::generate(authorize_request),
        [] => Err(OAuthError::unsupported_response_type(
            &response_type::SUPPORTED_RESPONSE_TYPES,
        )),
        [ResponseType::IdToken, ..] | [ResponseType::Token, ..] => Err(
            OAuthError::unsupported_response_type(&response_type::SUPPORTED_RESPONSE_TYPES),
        ),
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

    login_error_response(&request.query_params, &error)
}

fn not_found_response() -> String {
    let body = "not found";

    format!(
        "HTTP/1.1 404 Not Found\r\ncontent-type: text/plain\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
        body.len(),
        body
    )
}
