use crate::{
    errors::OAuthError,
    handlers::responses::oid4vci_json_response,
    resources::{
        credential_access_token::{self, CredentialAccessTokenClaims},
        credential_issuer,
        verifiable_credential::{self, VerifiableCredential},
    },
    unit::{KagomeRequest, parse_request_parameter, request_header},
};

#[derive(Debug)]
pub struct CredentialRequest<'a> {
    pub request: &'a KagomeRequest,
    pub host: Option<String>,
    pub access_token: Option<String>,
    pub content_type: Option<String>,
    pub credential_identifier: Option<String>,
    pub response: CredentialResponse,
}

#[derive(Debug, Default)]
pub struct CredentialResponse {
    pub credential_issuer: Option<String>,
    pub authorized_credential_configuration_id: Option<String>,
    pub credential_configuration_id: Option<String>,
    pub subject: Option<String>,
    pub credential: Option<VerifiableCredential>,
}

impl<'a> CredentialRequest<'a> {
    pub fn from_request(request: &'a KagomeRequest) -> Self {
        Self {
            request,
            host: request_header(request, "host"),
            access_token: bearer_token(request_header(request, "authorization").as_deref()),
            content_type: request_header(request, "content-type"),
            credential_identifier: parse_request_parameter(request, "credential_identifier"),
            response: CredentialResponse::default(),
        }
    }

    pub fn to_response(&self) -> Result<String, OAuthError> {
        let credential = self.response.credential.as_ref().ok_or_else(|| {
            OAuthError::invalid_token_response("credential response requires credential")
        })?;
        let response_body = serde_json::json!({
            "format": credential_issuer::CREDENTIAL_FORMAT,
            "credential": credential.value,
        })
        .to_string();

        Ok(oid4vci_json_response(&response_body))
    }
}

impl credential_issuer::Validate for CredentialRequest<'_> {
    fn request_host(&self) -> Option<&str> {
        self.host.as_deref()
    }

    fn add_credential_issuer(&mut self, credential_issuer: String) {
        self.response.credential_issuer = Some(credential_issuer);
    }
}

impl credential_access_token::Validate for CredentialRequest<'_> {
    fn request_access_token(&self) -> Option<&str> {
        self.access_token.as_deref()
    }

    fn add_credential_access_token_claims(&mut self, claims: CredentialAccessTokenClaims) {
        self.response.authorized_credential_configuration_id =
            Some(claims.credential_configuration_id);
        self.response.subject = Some(claims.subject);
    }
}

impl credential_issuer::ValidateConfiguration for CredentialRequest<'_> {
    fn request_content_type(&self) -> Option<&str> {
        self.content_type.as_deref()
    }

    fn request_credential_identifier(&self) -> Option<&str> {
        self.credential_identifier.as_deref()
    }

    fn authorized_credential_configuration_id(&self) -> Option<&str> {
        self.response
            .authorized_credential_configuration_id
            .as_deref()
    }

    fn add_credential_configuration(&mut self, credential_configuration_id: String) {
        self.response.credential_configuration_id = Some(credential_configuration_id);
    }
}

impl verifiable_credential::Generate for CredentialRequest<'_> {
    fn credential_issuer(&self) -> Option<&str> {
        self.response.credential_issuer.as_deref()
    }

    fn subject(&self) -> Option<&str> {
        self.response.subject.as_deref()
    }

    fn add_verifiable_credential(&mut self, credential: VerifiableCredential) {
        self.response.credential = Some(credential);
    }
}

fn bearer_token(authorization: Option<&str>) -> Option<String> {
    let (scheme, token) = authorization?.split_once(' ')?;
    (scheme.eq_ignore_ascii_case("bearer") && !token.is_empty()).then(|| token.to_owned())
}
