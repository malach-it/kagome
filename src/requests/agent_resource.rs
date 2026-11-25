use std::collections::BTreeMap;

use axum::http::Uri;

use crate::{
    errors::OAuthError,
    handlers::responses::{
        ResponseLog, agent_resource_response, agent_ssh_response, log_agent_resource_success,
    },
    resources::{
        agent_ssh::{Register, SSH_SCOPE_HEADER, SshAction},
        agent_token::VerifiedAgentToken,
        http_signature::{SIGNATURE_KEY_HEADER, Validate, VerifiedSignatureKey, VerifyMessage},
    },
    unit::KagomeRequest,
};

pub struct AgentResourceRequest<'a> {
    method: &'a str,
    path: &'a str,
    target_authority: Option<&'a str>,
    target_scheme: Option<&'a str>,
    fields: BTreeMap<String, Vec<&'a str>>,
    pub response: AgentResourceResponse,
}

#[derive(Default)]
pub struct AgentResourceResponse {
    verified_keys: Vec<VerifiedSignatureKey>,
    authenticated_key: Option<(usize, u64)>,
    ssh_action: Option<SshAction>,
}

impl<'a> AgentResourceRequest<'a> {
    pub fn from_request(request: &'a KagomeRequest, target: Option<&'a Uri>) -> Self {
        let mut fields = BTreeMap::<_, Vec<_>>::new();
        for header in &request.headers {
            fields
                .entry(header.name.to_ascii_lowercase())
                .or_default()
                .push(header.value.as_str());
        }

        Self {
            method: &request.method,
            path: &request.path,
            target_authority: target.and_then(Uri::authority).map(|value| value.as_str()),
            target_scheme: target.and_then(Uri::scheme_str),
            fields,
            response: AgentResourceResponse::default(),
        }
    }
}

impl Validate for AgentResourceRequest<'_> {
    fn signature_key_fields(&self) -> &[&str] {
        self.field_lines(SIGNATURE_KEY_HEADER)
    }

    fn add_verified_signature_keys(&mut self, keys: Vec<VerifiedSignatureKey>) {
        self.response.verified_keys = keys;
    }
}

impl VerifyMessage for AgentResourceRequest<'_> {
    fn method(&self) -> &str {
        self.method
    }

    fn path(&self) -> &str {
        self.path
    }

    fn target_authority(&self) -> Option<&str> {
        self.target_authority
    }

    fn target_scheme(&self) -> Option<&str> {
        self.target_scheme
    }

    fn field_lines(&self, name: &str) -> &[&str] {
        self.fields.get(name).map_or(&[], Vec::as_slice)
    }

    fn verified_signature_keys(&self) -> &[VerifiedSignatureKey] {
        &self.response.verified_keys
    }

    fn set_authenticated_agent(&mut self, key_index: usize, signature_created: u64) {
        self.response.authenticated_key = Some((key_index, signature_created));
    }

    fn additional_required_components(&self) -> &[&str] {
        if self.method == "POST" && !self.field_lines(SSH_SCOPE_HEADER).is_empty() {
            &[SSH_SCOPE_HEADER]
        } else {
            &[]
        }
    }
}

impl Register for AgentResourceRequest<'_> {
    fn ssh_scope_fields(&self) -> &[&str] {
        self.field_lines(SSH_SCOPE_HEADER)
    }

    fn authenticated_agent(&self) -> Option<(&VerifiedAgentToken, u64)> {
        let (index, created) = self.response.authenticated_key?;
        let key = self.response.verified_keys.get(index)?;
        Some((&key.agent_token, created))
    }

    fn set_ssh_action(&mut self, action: SshAction) {
        self.response.ssh_action = Some(action);
    }
}

impl ResponseLog for AgentResourceRequest<'_> {
    fn to_http_response(&self) -> Result<String, OAuthError> {
        self.authenticated_agent()
            .ok_or_else(|| OAuthError::invalid_token_response("authenticated agent is missing"))?;
        match self.method {
            "GET" => Ok(agent_resource_response()),
            "POST" => agent_ssh_response(
                self.response
                    .ssh_action
                    .as_ref()
                    .ok_or_else(|| OAuthError::invalid_token_response("SSH action is missing"))?,
            ),
            _ => Err(OAuthError::invalid_token_response(
                "agent resource method is invalid",
            )),
        }
    }

    fn log_success(&self) {
        if let Some((agent, _)) = self.authenticated_agent() {
            log_agent_resource_success(agent, self.response.ssh_action.as_ref());
        }
    }
}
