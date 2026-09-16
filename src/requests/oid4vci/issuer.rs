use crate::{errors::OAuthError, resources::credential_issuer, unit::KagomeRequest};

#[derive(Debug)]
pub struct IssuerRequest {
    pub response: IssuerResponse,
}

#[derive(Debug, Default)]
pub struct IssuerResponse {
    pub credential_issuer: Option<String>,
}

impl IssuerRequest {
    pub fn from_request(_request: &KagomeRequest) -> Self {
        Self {
            response: IssuerResponse::default(),
        }
    }

    pub fn credential_issuer(&self) -> Result<&str, OAuthError> {
        self.response
            .credential_issuer
            .as_deref()
            .ok_or_else(|| OAuthError::invalid_token_response("credential issuer is required"))
    }
}

impl credential_issuer::Validate for IssuerRequest {
    fn add_credential_issuer(&mut self, credential_issuer: String) {
        self.response.credential_issuer = Some(credential_issuer);
    }
}
