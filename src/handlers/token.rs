use crate::{
    errors::OAuthError,
    resources::{
        access_token, authorization_code, client_id, client_secret,
        grant_type::{self, GrantType},
        id_token,
    },
    unit::KagomeRequest,
};

pub use super::responses::{ClientCredentialsResponse, CodeChainResponse, GrantTypeResponse};

pub fn handle(request: &KagomeRequest) -> String {
    match grant_type::validate(GrantTypeResponse::empty(), request)
        .and_then(|token_response| handle_validated_grant_type(token_response, request))
    {
        Ok(response) => response,
        Err(error) => error.to_response(),
    }
}

fn handle_validated_grant_type(
    token_response: GrantTypeResponse,
    request: &KagomeRequest,
) -> Result<String, OAuthError> {
    let grant_type = token_response
        .grant_type
        .ok_or_else(|| OAuthError::invalid_token_response("token response requires grant_type"))?;

    match grant_type {
        GrantType::ClientCredentials => {
            client_credentials(ClientCredentialsResponse::from(token_response), request)
        }
        GrantType::CodeChain => code_chain(CodeChainResponse::from(token_response), request),
    }
}

fn client_credentials(
    token_response: ClientCredentialsResponse,
    request: &KagomeRequest,
) -> Result<String, OAuthError> {
    client_id::validate(token_response, request)
        .and_then(|token_response| client_secret::validate(token_response, request))
        .and_then(|token_response| access_token::generate(token_response, request))
        .and_then(|token_response| token_response.to_response())
}

fn code_chain(
    token_response: CodeChainResponse,
    request: &KagomeRequest,
) -> Result<String, OAuthError> {
    client_id::validate(token_response, request)
        .and_then(|token_response| client_secret::validate(token_response, request))
        .and_then(|token_response| id_token::validate(token_response, request))
        .and_then(|token_response| authorization_code::validate(token_response, request))
        .and_then(|token_response| authorization_code::generate(token_response, request))
        .and_then(|token_response| token_response.to_response())
}
