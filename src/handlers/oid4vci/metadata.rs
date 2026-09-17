use crate::{
    errors::OAuthError,
    handlers::responses::{cors_response, oid4vci_json_response},
    requests::IssuerRequest,
    resources::credential_issuer,
    unit::KagomeRequest,
};

pub(super) fn issuer_response(
    request: &KagomeRequest,
    body: impl FnOnce(&str) -> serde_json::Value,
) -> String {
    let response = match credential_issuer::validate(IssuerRequest::from_request(request))
        .and_then(|request| metadata_response(request, body))
    {
        Ok(response) => response,
        Err(error) => error.to_response(),
    };

    cors_response(request, response)
}

fn metadata_response(
    request: IssuerRequest,
    body: impl FnOnce(&str) -> serde_json::Value,
) -> Result<String, OAuthError> {
    Ok(oid4vci_json_response(
        &body(request.credential_issuer()?).to_string(),
    ))
}
