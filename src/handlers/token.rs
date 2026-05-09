use crate::{
    errors::OAuthError,
    resources::{
        access_token, client_credentials,
        grant_type::{self, GrantType},
        id_token,
    },
    unit::KagomeRequest,
};

pub use super::requests::{
    AuthorizationCodeRequest, ClientCredentialsRequest, CodeChainRequest, ContinueCodeChainRequest,
    GrantTypeRequest, GrantTypeResponse, NewCodeChainRequest,
};

pub fn handle(request: &KagomeRequest) -> String {
    match grant_type::validate(GrantTypeRequest::from_request(request))
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
        ),
        GrantType::ClientCredentials => client_credentials(
            ClientCredentialsRequest::from_grant_type_response(token_request, request),
        ),
        GrantType::CodeChain => code_chain(CodeChainRequest::from_grant_type_response(
            token_request,
            request,
        )),
    }
}

fn authorization_code(token_request: AuthorizationCodeRequest) -> Result<String, OAuthError> {
    use crate::resources::authorization_code;

    client_credentials::validate(token_request)
        .and_then(authorization_code::validate)
        .and_then(access_token::generate)
        .and_then(|token_request| token_request.to_response())
}

fn client_credentials(token_request: ClientCredentialsRequest) -> Result<String, OAuthError> {
    client_credentials::validate(token_request)
        .and_then(access_token::generate)
        .and_then(|token_request| token_request.to_response())
}

fn code_chain(token_request: CodeChainRequest) -> Result<String, OAuthError> {
    use crate::resources::authorization_code;

    let token_request = client_credentials::validate(token_request)
        .and_then(authorization_code::validate_optional)?;

    match token_request.authorization_code() {
        None => new_code_chain(NewCodeChainRequest::from_code_chain_request(token_request)),
        Some(_) => continue_code_chain(ContinueCodeChainRequest::from_code_chain_request(
            token_request,
        )),
    }
}

fn new_code_chain(token_request: NewCodeChainRequest) -> Result<String, OAuthError> {
    use crate::resources::authorization_code;

    id_token::validate(token_request)
        .and_then(authorization_code::generate)
        .and_then(|token_request| token_request.to_response())
}

fn continue_code_chain(token_request: ContinueCodeChainRequest) -> Result<String, OAuthError> {
    use crate::resources::authorization_code;

    id_token::validate(token_request)
        .and_then(authorization_code::generate)
        .and_then(|token_request| token_request.to_response())
}
