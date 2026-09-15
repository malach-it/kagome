use crate::{
    errors::OAuthError,
    handlers::responses::oid4vci_json_response,
    resources::{
        credential_access_token::{self, CredentialAccessToken},
        pre_authorized_code::{self, PreAuthorizedCodeClaims},
    },
    unit::{KagomeRequest, parse_request_parameter},
};

#[derive(Debug)]
pub struct PreAuthorizedCodeRequest<'a> {
    pub request: &'a KagomeRequest,
    pub pre_authorized_code: Option<String>,
    pub tx_code: Option<String>,
    pub response: PreAuthorizedCodeResponse,
}

#[derive(Debug, Default)]
pub struct PreAuthorizedCodeResponse {
    pub credential_configuration_id: Option<String>,
    pub subject: Option<String>,
    pub access_token: Option<CredentialAccessToken>,
}

impl<'a> PreAuthorizedCodeRequest<'a> {
    pub fn from_request(request: &'a KagomeRequest) -> Self {
        Self {
            request,
            pre_authorized_code: parse_request_parameter(request, "pre-authorized_code"),
            tx_code: parse_request_parameter(request, "tx_code"),
            response: PreAuthorizedCodeResponse::default(),
        }
    }

    pub fn to_response(&self) -> Result<String, OAuthError> {
        let access_token = self.response.access_token.as_ref().ok_or_else(|| {
            OAuthError::invalid_token_response("token response requires access_token")
        })?;
        let credential_configuration_id = self
            .response
            .credential_configuration_id
            .as_deref()
            .ok_or_else(|| {
                OAuthError::invalid_token_response(
                    "token response requires credential configuration",
                )
            })?;
        let response_body = serde_json::json!({
            "access_token": access_token.value,
            "token_type": "Bearer",
            "expires_in": access_token.expires_in,
            "authorization_details": [{
                "type": "openid_credential",
                "format": crate::resources::credential_issuer::CREDENTIAL_FORMAT,
                "credential_configuration_id": credential_configuration_id,
            }],
        })
        .to_string();

        Ok(oid4vci_json_response(&response_body))
    }
}

impl pre_authorized_code::Validate for PreAuthorizedCodeRequest<'_> {
    fn request_pre_authorized_code(&self) -> Option<&str> {
        self.pre_authorized_code.as_deref()
    }

    fn request_tx_code(&self) -> Option<&str> {
        self.tx_code.as_deref()
    }

    fn add_pre_authorized_code_claims(&mut self, claims: PreAuthorizedCodeClaims) {
        self.response.credential_configuration_id = Some(claims.credential_configuration_id);
        self.response.subject = Some(claims.subject);
    }
}

impl credential_access_token::Generate for PreAuthorizedCodeRequest<'_> {
    fn credential_configuration_id(&self) -> Option<&str> {
        self.response.credential_configuration_id.as_deref()
    }

    fn subject(&self) -> Option<&str> {
        self.response.subject.as_deref()
    }

    fn add_credential_access_token(&mut self, access_token: CredentialAccessToken) {
        self.response.access_token = Some(access_token);
    }
}
