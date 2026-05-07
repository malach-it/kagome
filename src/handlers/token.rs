use crate::{
    errors::OAuthError,
    resources::{
        access_token, client_id, client_secret,
        grant_type::{self, GrantType},
        id_token,
    },
    unit::KagomeRequest,
};

pub use super::requests::{
    AuthorizationCodeRequest, ClientCredentialsRequest, CodeChainRequest, GrantTypeRequest,
    GrantTypeResponse,
};

pub fn handle(request: &KagomeRequest) -> String {
    match grant_type::validate(GrantTypeRequest::from_request(request), request)
        .and_then(|token_request| handle_validated_grant_type(token_request, request))
    {
        Ok(response) => response,
        Err(error) => error.to_response(),
    }
}

fn handle_validated_grant_type(
    token_request: GrantTypeRequest,
    request: &KagomeRequest,
) -> Result<String, OAuthError> {
    let grant_type = token_request
        .response
        .grant_type
        .ok_or_else(|| OAuthError::invalid_token_response("token response requires grant_type"))?;

    match grant_type {
        GrantType::AuthorizationCode => authorization_code(
            AuthorizationCodeRequest::from_grant_type_response(token_request, request),
            request,
        ),
        GrantType::ClientCredentials => client_credentials(
            ClientCredentialsRequest::from_grant_type_response(token_request, request),
            request,
        ),
        GrantType::CodeChain => code_chain(
            CodeChainRequest::from_grant_type_response(token_request, request),
            request,
        ),
    }
}

fn authorization_code(
    token_request: AuthorizationCodeRequest,
    request: &KagomeRequest,
) -> Result<String, OAuthError> {
    use crate::resources::authorization_code;

    client_id::validate(token_request, request)
        .and_then(|token_request| client_secret::validate(token_request, request))
        .and_then(|token_request| authorization_code::validate(token_request, request))
        .and_then(|token_request| access_token::generate(token_request, request))
        .and_then(|token_request| token_request.to_response())
}

fn client_credentials(
    token_request: ClientCredentialsRequest,
    request: &KagomeRequest,
) -> Result<String, OAuthError> {
    client_id::validate(token_request, request)
        .and_then(|token_request| client_secret::validate(token_request, request))
        .and_then(|token_request| access_token::generate(token_request, request))
        .and_then(|token_request| token_request.to_response())
}

fn code_chain(
    token_request: CodeChainRequest,
    request: &KagomeRequest,
) -> Result<String, OAuthError> {
    use crate::resources::authorization_code;

    client_id::validate(token_request, request)
        .and_then(|token_request| client_secret::validate(token_request, request))
        .and_then(|token_request| id_token::validate(token_request, request))
        .and_then(|token_request| authorization_code::validate_optional(token_request, request))
        .and_then(|token_request| authorization_code::generate(token_request, request))
        .and_then(|token_request| token_request.to_response())
}
