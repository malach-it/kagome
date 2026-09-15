use crate::{
    errors::OAuthError,
    handlers::responses::oid4vci_json_response,
    resources::{
        credential_issuer::{self, CREDENTIAL_CONFIGURATION_ID},
        pre_authorized_code,
    },
    unit::{KagomeRequest, request_header},
};

#[derive(Debug)]
pub struct CredentialOfferRequest<'a> {
    pub request: &'a KagomeRequest,
    pub host: Option<String>,
    pub response: CredentialOfferResponse,
}

#[derive(Debug, Default)]
pub struct CredentialOfferResponse {
    pub credential_issuer: Option<String>,
    pub pre_authorized_code: Option<String>,
}

impl<'a> CredentialOfferRequest<'a> {
    pub fn from_request(request: &'a KagomeRequest) -> Self {
        Self {
            request,
            host: request_header(request, "host"),
            response: CredentialOfferResponse::default(),
        }
    }

    pub fn to_response(&self) -> Result<String, OAuthError> {
        let credential_issuer =
            self.response.credential_issuer.as_deref().ok_or_else(|| {
                OAuthError::invalid_token_response("credential issuer is required")
            })?;
        let pre_authorized_code = self
            .response
            .pre_authorized_code
            .as_deref()
            .ok_or_else(|| OAuthError::invalid_token_response("pre-authorized_code is required"))?;
        let response_body = serde_json::json!({
            "credential_issuer": credential_issuer,
            "credential_configuration_ids": [CREDENTIAL_CONFIGURATION_ID],
            "grants": {
                pre_authorized_code::GRANT_TYPE: {
                    "pre-authorized_code": pre_authorized_code
                }
            }
        })
        .to_string();

        Ok(oid4vci_json_response(&response_body))
    }
}

impl credential_issuer::Validate for CredentialOfferRequest<'_> {
    fn request_host(&self) -> Option<&str> {
        self.host.as_deref()
    }

    fn add_credential_issuer(&mut self, credential_issuer: String) {
        self.response.credential_issuer = Some(credential_issuer);
    }
}

impl pre_authorized_code::Generate for CredentialOfferRequest<'_> {
    fn add_pre_authorized_code(&mut self, pre_authorized_code: String) {
        self.response.pre_authorized_code = Some(pre_authorized_code);
    }
}
