use crate::{
    errors::OAuthError,
    resources::{
        access_token, client_credentials,
        grant_type::{self, GrantType},
        id_token,
    },
    unit::KagomeRequest,
};

pub use crate::requests::{
    AuthorizationCodeRequest, ClientCredentialsRequest, CodeChainAuthorizationCodeRequest,
    CodeChainRequest, GrantTypeRequest, GrantTypeResponse,
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
    match token_request.grant_types() {
        [GrantType::AuthorizationCode, ..] => authorization_code(
            AuthorizationCodeRequest::from_grant_type_response(&token_request, request),
        )
        .and_then(|token_request| token_request.to_response()),
        [GrantType::ClientCredentials, ..] => client_credentials(
            ClientCredentialsRequest::from_grant_type_response(&token_request, request),
        )
        .and_then(|token_request| token_request.to_response()),
        [GrantType::CodeChain, GrantType::AuthorizationCode, ..] => code_chain_authorization_code(
            CodeChainRequest::from_grant_type_response(&token_request, request),
            AuthorizationCodeRequest::from_grant_type_response(&token_request, request),
        )
        .and_then(|token_request| token_request.to_response()),
        [GrantType::CodeChain, ..] => code_chain(CodeChainRequest::from_grant_type_response(
            &token_request,
            request,
        ))
        .and_then(|token_request| token_request.to_response()),
        [] => Err(OAuthError::invalid_token_response(
            "token response requires grant_type",
        )),
    }
}

fn authorization_code(
    token_request: AuthorizationCodeRequest,
) -> Result<AuthorizationCodeRequest, OAuthError> {
    use crate::resources::authorization_code;

    client_credentials::validate(token_request)
        .and_then(authorization_code::validate)
        .and_then(access_token::generate)
}

fn code_chain(token_request: CodeChainRequest) -> Result<CodeChainRequest, OAuthError> {
    use crate::resources::authorization_code;

    client_credentials::validate(token_request)
        .and_then(authorization_code::validate_optional)
        .and_then(id_token::validate)
        .and_then(authorization_code::generate)
}

fn code_chain_authorization_code<'a>(
    code_chain_request: CodeChainRequest<'a>,
    authorization_code_request: AuthorizationCodeRequest<'a>,
) -> Result<CodeChainAuthorizationCodeRequest<'a>, OAuthError> {
    let code_chain_result = code_chain(code_chain_request)?;
    let authorization_code_result = authorization_code(authorization_code_request)?;

    Ok(CodeChainAuthorizationCodeRequest::from_requests(
        code_chain_result,
        authorization_code_result,
    ))
}

fn client_credentials(
    token_request: ClientCredentialsRequest,
) -> Result<ClientCredentialsRequest, OAuthError> {
    client_credentials::validate(token_request).and_then(access_token::generate)
}
