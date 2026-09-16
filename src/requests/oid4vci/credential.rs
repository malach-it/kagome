use crate::{
    config::{Config, CredentialConfig},
    errors::OAuthError,
    handlers::responses::oid4vci_json_response,
    resources::{
        credential_access_token::{self, CredentialAccessTokenClaims},
        credential_issuer, credential_proof,
        resource_owner::{CredentialProfiles, ResourceOwnerProfile},
        verifiable_credential::{self, VerifiableCredential},
    },
    unit::{KagomeRequest, parse_request_json_parameter, parse_request_parameter, request_header},
};

#[derive(Debug)]
pub struct CredentialRequest<'a> {
    pub request: &'a KagomeRequest,
    pub access_token: Option<String>,
    pub content_type: Option<String>,
    pub credential_identifier: Option<String>,
    pub proof: Option<serde_json::Value>,
    pub response: CredentialResponse,
}

#[derive(Debug, Default)]
pub struct CredentialResponse {
    pub credential_issuer: Option<String>,
    pub authorized_credential_configuration_ids: Vec<String>,
    pub credential_configuration: Option<CredentialConfig>,
    pub subject: Option<String>,
    pub credential_profile: CredentialProfiles,
    pub holder_jwk: Option<serde_json::Value>,
    pub id_token_public_jwk: Option<serde_json::Value>,
    pub require_wallet_binding: bool,
    pub c_nonce: Option<String>,
    pub credential: Option<VerifiableCredential>,
}

impl<'a> CredentialRequest<'a> {
    pub fn from_request(request: &'a KagomeRequest) -> Self {
        Self {
            request,
            access_token: bearer_token(request_header(request, "authorization").as_deref()),
            content_type: request_header(request, "content-type"),
            credential_identifier: parse_request_parameter(request, "credential_identifier"),
            proof: parse_request_json_parameter(request, "proof"),
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
    fn add_credential_issuer(&mut self, credential_issuer: String) {
        self.response.credential_issuer = Some(credential_issuer);
    }
}

impl credential_access_token::Validate for CredentialRequest<'_> {
    fn request_access_token(&self) -> Option<&str> {
        self.access_token.as_deref()
    }

    fn add_credential_access_token_claims(&mut self, claims: CredentialAccessTokenClaims) {
        self.response.authorized_credential_configuration_ids = claims.credential_configuration_ids;
        self.response.subject = Some(claims.subject);
        self.response.credential_profile = claims.credential_profile;
        self.response.id_token_public_jwk = claims.id_token_public_jwk;
        self.response.require_wallet_binding = claims.require_wallet_binding;
        self.response.c_nonce = Some(claims.c_nonce);
    }
}

impl credential_issuer::ValidateConfiguration for CredentialRequest<'_> {
    fn request_content_type(&self) -> Option<&str> {
        self.content_type.as_deref()
    }

    fn request_credential_identifier(&self) -> Option<&str> {
        self.credential_identifier.as_deref()
    }

    fn authorized_credential_configuration_ids(&self) -> &[String] {
        &self.response.authorized_credential_configuration_ids
    }

    fn add_credential_configuration(&mut self, credential: CredentialConfig) {
        self.response.credential_configuration = Some(credential);
    }
}

impl verifiable_credential::Generate for CredentialRequest<'_> {
    fn credential_configuration(&self) -> Option<&CredentialConfig> {
        self.response.credential_configuration.as_ref()
    }
    fn credential_issuer(&self) -> Option<&str> {
        self.response.credential_issuer.as_deref()
    }

    fn subject(&self) -> Option<&str> {
        self.response.subject.as_deref()
    }

    fn credential_profile(&self) -> Option<&ResourceOwnerProfile> {
        let credential_configuration_id = &self
            .response
            .credential_configuration
            .as_ref()?
            .credential_configuration_id;
        self.response
            .credential_profile
            .get(credential_configuration_id)
    }

    fn holder_jwk(&self) -> Option<&serde_json::Value> {
        self.response.holder_jwk.as_ref()
    }

    fn add_verifiable_credential(&mut self, credential: VerifiableCredential) {
        self.response.credential = Some(credential);
    }
}

impl credential_proof::Validate for CredentialRequest<'_> {
    fn request_proof(&self) -> Option<&serde_json::Value> {
        self.proof.as_ref()
    }

    fn proof_audience(&self) -> Option<&str> {
        Some(&Config::global().server.issuer)
    }

    fn id_token_public_jwk(&self) -> Option<&serde_json::Value> {
        self.response.id_token_public_jwk.as_ref()
    }

    fn credential_nonce(&self) -> Option<&str> {
        self.response.c_nonce.as_deref()
    }

    fn add_validated_credential_proof(
        &mut self,
        proof: credential_proof::ValidatedCredentialProof,
    ) {
        self.response.subject = Some(proof.subject);
        self.response.holder_jwk = Some(proof.jwk);
    }
}

fn bearer_token(authorization: Option<&str>) -> Option<String> {
    let (scheme, token) = authorization?.split_once(' ')?;
    (scheme.eq_ignore_ascii_case("bearer") && !token.is_empty()).then(|| token.to_owned())
}
