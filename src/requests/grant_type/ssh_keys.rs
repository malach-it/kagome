use crate::{
    errors::OAuthError,
    handlers::responses::{cose_response, ssh_keys_response, ssh_keys_response_body},
    resources::{
        authorization_code, client_credentials, crypto,
        grant_type::{self, GrantType},
        ssh_keys::{self, SshKeys},
    },
    unit::{KagomeRequest, parse_request_parameter},
};

use super::GrantTypeRequest;

#[derive(Debug)]
pub struct SshKeysRequest<'a> {
    pub response: SshKeysResponse,
    pub request: &'a KagomeRequest,
    pub code: Option<String>,
    pub client_id: Option<String>,
    pub client_secret: Option<String>,
    pub client_encryption_key: Option<String>,
    pub client_encryption_alg: Option<String>,
    pub grant_type: Option<String>,
}

#[derive(Debug)]
pub struct SshKeysResponse {
    pub ssh_keys: Option<SshKeys>,
    pub authorization_code: Option<String>,
    pub client_id: Option<String>,
    pub client_secret: Option<String>,
    pub grant_type: Option<GrantType>,
    pub username: Option<String>,
}

impl<'a> SshKeysRequest<'a> {
    pub fn from_grant_type_response(
        response: &GrantTypeRequest<'a>,
        request: &'a KagomeRequest,
    ) -> Self {
        Self {
            response: SshKeysResponse::empty(),
            request,
            code: parse_request_parameter(request, "code"),
            client_id: parse_request_parameter(request, "client_id"),
            client_secret: parse_request_parameter(request, "client_secret"),
            client_encryption_key: parse_request_parameter(request, "client_encryption_key"),
            client_encryption_alg: parse_request_parameter(request, "client_encryption_alg"),
            grant_type: response
                .response
                .grant_type
                .map(|grant_type| grant_type.as_str().to_owned()),
        }
    }

    pub fn add_credentials_from_authorization_code(mut self) -> Result<Self, OAuthError> {
        let authorization_code = self
            .response
            .authorization_code
            .as_deref()
            .ok_or_else(OAuthError::missing_authorization_code)?;
        let payload = authorization_code::decode_cose_payload(authorization_code)?;

        self.response.client_id = Some(payload.client_id);
        self.response.username = Some(payload.username.ok_or_else(OAuthError::missing_username)?);

        Ok(self)
    }

    pub fn to_response(&self) -> Result<String, OAuthError> {
        let ssh_keys = self.response.ssh_keys.as_ref().ok_or_else(|| {
            OAuthError::invalid_token_response("token response requires ssh_keys")
        })?;

        if let Some(client_encryption_key) = self.client_encryption_key.as_deref() {
            validate_client_encryption_alg(self.client_encryption_alg.as_deref())?;

            return Ok(cose_response(&crypto::encode_cose_encrypt0(
                ssh_keys_response_body(ssh_keys).as_bytes(),
                client_encryption_key,
                SSH_KEYS_RESPONSE_EXTERNAL_AAD,
            )?));
        }

        Ok(ssh_keys_response(ssh_keys))
    }
}

const SSH_KEYS_RESPONSE_EXTERNAL_AAD: &[u8] = b"kagome ssh_keys token response";
const CLIENT_ENCRYPTION_ALG_A256GCM: &str = "A256GCM";

fn validate_client_encryption_alg(client_encryption_alg: Option<&str>) -> Result<(), OAuthError> {
    match client_encryption_alg {
        Some(CLIENT_ENCRYPTION_ALG_A256GCM) => Ok(()),
        _ => Err(OAuthError::invalid_token_response(format!(
            "client_encryption_alg must be {CLIENT_ENCRYPTION_ALG_A256GCM}"
        ))),
    }
}

impl SshKeysResponse {
    fn empty() -> Self {
        Self {
            ssh_keys: None,
            authorization_code: None,
            client_id: None,
            client_secret: None,
            grant_type: None,
            username: None,
        }
    }
}

impl<'a> grant_type::Validate for SshKeysRequest<'a> {
    fn request_grant_type(&self) -> Option<&str> {
        self.grant_type.as_deref()
    }

    fn add_grant_type(&mut self, grant_type: &GrantType) {
        self.response.grant_type = Some(*grant_type);
    }
}

impl<'a> client_credentials::Validate for SshKeysRequest<'a> {
    fn request_client_id(&self) -> Option<&str> {
        self.client_id.as_deref()
    }

    fn valid_client_id(&self, client_id: &str) -> bool {
        client_id == client_credentials::CLIENT_ID
            || client_id == client_credentials::USERNAME_LOCALHOST_CLIENT_ID
            || self
                .code
                .as_deref()
                .and_then(|code| authorization_code::decode_cose_payload(code).ok())
                .is_some_and(|payload| payload.client_id == client_id)
    }

    fn request_client_secret(&self) -> Option<&str> {
        self.client_secret.as_deref()
    }

    fn add_client_credentials(
        &mut self,
        client_credentials: client_credentials::ClientCredentials,
    ) {
        self.response.client_id = Some(client_credentials.client_id);
        self.response.client_secret = client_credentials.client_secret;
    }
}

impl<'a> authorization_code::Validate for SshKeysRequest<'a> {
    fn request_authorization_code(&self) -> Option<&str> {
        self.code.as_deref()
    }

    fn client_id(&self) -> Option<&str> {
        self.response.client_id.as_deref()
    }

    fn add_authorization_code(&mut self, authorization_code: &str) {
        self.response.authorization_code = Some(authorization_code.to_owned());
    }
}

impl<'a> ssh_keys::Generate for SshKeysRequest<'a> {
    fn client_id(&self) -> Option<&str> {
        self.response.client_id.as_deref()
    }

    fn username(&self) -> Option<&str> {
        self.response.username.as_deref()
    }

    fn add_ssh_keys(&mut self, ssh_keys: SshKeys) {
        self.response.ssh_keys = Some(ssh_keys);
    }
}
