use crate::{
    errors::OAuthError,
    resources::credential_issuer,
    unit::{KagomeRequest, request_header},
};

#[derive(Debug)]
pub struct IssuerRequest<'a> {
    pub request: &'a KagomeRequest,
    pub host: Option<String>,
    pub response: IssuerResponse,
}

#[derive(Debug, Default)]
pub struct IssuerResponse {
    pub credential_issuer: Option<String>,
}

impl<'a> IssuerRequest<'a> {
    pub fn from_request(request: &'a KagomeRequest) -> Self {
        Self {
            request,
            host: request_header(request, "host"),
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

impl credential_issuer::Validate for IssuerRequest<'_> {
    fn request_host(&self) -> Option<&str> {
        self.host.as_deref()
    }

    fn add_credential_issuer(&mut self, credential_issuer: String) {
        self.response.credential_issuer = Some(credential_issuer);
    }
}
