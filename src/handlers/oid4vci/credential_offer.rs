use crate::{
    requests::CredentialOfferRequest,
    resources::{credential_issuer, pre_authorized_code},
    unit::KagomeRequest,
};

use crate::handlers::responses::logged_response;

pub fn handle_credential_offer(request: &KagomeRequest) -> String {
    match credential_issuer::validate(CredentialOfferRequest::from_request(request))
        .and_then(pre_authorized_code::generate)
        .and_then(logged_response)
    {
        Ok(response) => response,
        Err(error) => error.to_response(),
    }
}
