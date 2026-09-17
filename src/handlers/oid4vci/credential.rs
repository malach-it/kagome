use crate::{
    requests::CredentialRequest,
    resources::{
        credential_access_token, credential_issuer, credential_proof, verifiable_credential,
    },
    unit::KagomeRequest,
};

use crate::handlers::responses::{cors_response, credential_error_response, logged_response};

pub fn handle_credential(request: &KagomeRequest) -> String {
    let response = match credential_issuer::validate(CredentialRequest::from_request(request))
        .and_then(credential_access_token::validate)
        .and_then(credential_issuer::validate_configuration)
        .and_then(credential_proof::validate)
        .and_then(credential_access_token::consume_nonce)
        .and_then(verifiable_credential::generate)
        .and_then(logged_response)
    {
        Ok(response) => response,
        Err(error) => credential_error_response(&error),
    };

    cors_response(request, response)
}
