use crate::{
    errors::OAuthError,
    handlers::responses::oid4vci_json_response,
    resources::{
        credential_access_token::{self, CredentialAccessToken},
        pre_authorized_code::{self, PreAuthorizedCodeClaims},
        resource_owner::CredentialProfiles,
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
    pub credential_configuration_ids: Vec<String>,
    pub subject: Option<String>,
    pub credential_profile: CredentialProfiles,
    pub id_token_public_jwk: Option<serde_json::Value>,
    pub require_wallet_binding: bool,
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
        if self.response.credential_configuration_ids.is_empty() {
            return Err(OAuthError::invalid_token_response(
                "token response requires credential configuration",
            ));
        }
        let authorization_details: Vec<_> = self
            .response
            .credential_configuration_ids
            .iter()
            .map(|credential_configuration_id| {
                serde_json::json!({
                    "type": "openid_credential",
                    "format": crate::resources::credential_issuer::CREDENTIAL_FORMAT,
                    "credential_configuration_id": credential_configuration_id,
                })
            })
            .collect();
        let response_body = serde_json::json!({
            "access_token": access_token.value,
            "token_type": "Bearer",
            "expires_in": access_token.expires_in,
            "authorization_details": authorization_details,
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
        self.response.credential_configuration_ids = claims.credential_configuration_ids;
        self.response.subject = Some(claims.subject);
        self.response.credential_profile = claims.credential_profile;
        self.response.id_token_public_jwk = claims.id_token_public_jwk;
        self.response.require_wallet_binding = claims.require_wallet_binding;
    }
}

impl credential_access_token::Generate for PreAuthorizedCodeRequest<'_> {
    fn credential_configuration_ids(&self) -> &[String] {
        &self.response.credential_configuration_ids
    }

    fn subject(&self) -> Option<&str> {
        self.response.subject.as_deref()
    }

    fn credential_profile(&self) -> Option<&CredentialProfiles> {
        Some(&self.response.credential_profile)
    }

    fn id_token_public_jwk(&self) -> Option<&serde_json::Value> {
        self.response.id_token_public_jwk.as_ref()
    }

    fn require_wallet_binding(&self) -> bool {
        self.response.require_wallet_binding
    }

    fn add_credential_access_token(&mut self, access_token: CredentialAccessToken) {
        self.response.access_token = Some(access_token);
    }
}
