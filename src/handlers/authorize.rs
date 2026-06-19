use crate::{
    errors::OAuthError,
    resources::{
        access_token, authorization_code, client_credentials, id_token, metadata_policy,
        resource_owner,
        response_type::{self, ResponseType},
        ssh_keys,
    },
    unit::KagomeRequest,
};

use super::responses::{log_timestamp, logged_response, login_error_response};

pub use crate::requests::{AuthorizeCodeRequest, AuthorizeLoginRequest};

pub fn handle(request: &KagomeRequest) -> String {
    match request.method.to_ascii_uppercase().as_str() {
        "GET" => handle_authorize(request),
        "POST" => handle_authenticate(request),
        _ => not_found_response(),
    }
}

fn handle_authorize(request: &KagomeRequest) -> String {
    let authorize_request = authorize(AuthorizeLoginRequest::from_request(request))
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
        Ok(authorize_request) => match logged_response(authorize_request) {
            Ok(response) => response,
            Err(error) => {
                log_authorize_failure(&error);
                authorize_error_response(request, error)
            }
        },
        Err(error) => {
            log_authorize_failure(&error);
            authorize_error_response(request, error)
        }
    }
}

fn handle_authenticate(request: &KagomeRequest) -> String {
    match authorize(AuthorizeCodeRequest::from_request(request))
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

fn authorize<T>(authorize_request: T) -> Result<T, OAuthError>
where
    T: response_type::Validate + client_credentials::Validate,
{
    response_type::validate(authorize_request).and_then(client_credentials::validate)
}

trait GenerateAuthorizeResponse {
    fn response_types(&self) -> &[ResponseType];
    fn has_valid_resource_owner(&self) -> bool;
}

impl GenerateAuthorizeResponse for AuthorizeLoginRequest<'_> {
    fn response_types(&self) -> &[ResponseType] {
        &self.response.response_types
    }

    fn has_valid_resource_owner(&self) -> bool {
        self.response.username.is_some()
    }
}

impl GenerateAuthorizeResponse for AuthorizeCodeRequest<'_> {
    fn response_types(&self) -> &[ResponseType] {
        &self.response.response_types
    }

    fn has_valid_resource_owner(&self) -> bool {
        self.response.username.is_some()
    }
}

fn generate_response<T>(authorize_request: T) -> Result<T, OAuthError>
where
    T: GenerateAuthorizeResponse
        + access_token::Generate
        + authorization_code::Generate
        + id_token::Generate
        + ssh_keys::Generate,
{
    match authorize_request.response_types() {
        [
            ResponseType::Code,
            ResponseType::IdToken,
            ResponseType::Token,
        ] if authorize_request.has_valid_resource_owner() => {
            authorization_code::generate(authorize_request)
                .and_then(id_token::generate)
                .and_then(access_token::generate)
        }
        [ResponseType::Code, ResponseType::Token]
            if authorize_request.has_valid_resource_owner() =>
        {
            authorization_code::generate(authorize_request).and_then(access_token::generate)
        }
        [ResponseType::Code, ResponseType::IdToken]
            if authorize_request.has_valid_resource_owner() =>
        {
            authorization_code::generate(authorize_request).and_then(id_token::generate)
        }
        [ResponseType::Code, ResponseType::SshKeys]
            if authorize_request.has_valid_resource_owner() =>
        {
            authorization_code::generate(authorize_request).and_then(ssh_keys::generate)
        }
        [ResponseType::IdToken, ResponseType::Token]
            if authorize_request.has_valid_resource_owner() =>
        {
            id_token::generate(authorize_request).and_then(access_token::generate)
        }
        [ResponseType::IdToken, ResponseType::Token] => Err(OAuthError::missing_username()),
        [ResponseType::Token] if authorize_request.has_valid_resource_owner() => {
            access_token::generate(authorize_request)
        }
        [ResponseType::Token] => Err(OAuthError::missing_username()),
        [ResponseType::IdToken] if authorize_request.has_valid_resource_owner() => {
            id_token::generate(authorize_request)
        }
        [ResponseType::IdToken] => Err(OAuthError::missing_username()),
        [ResponseType::SshKeys] if authorize_request.has_valid_resource_owner() => {
            ssh_keys::generate(authorize_request)
        }
        [ResponseType::SshKeys] => Err(OAuthError::missing_username()),
        [ResponseType::Code, ..] => authorization_code::generate(authorize_request),
        [] => Err(OAuthError::unsupported_response_type(
            &response_type::SUPPORTED_RESPONSE_TYPES,
        )),
        [ResponseType::IdToken, ..] | [ResponseType::SshKeys, ..] | [ResponseType::Token, ..] => {
            Err(OAuthError::unsupported_response_type(
                &response_type::SUPPORTED_RESPONSE_TYPES,
            ))
        }
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
