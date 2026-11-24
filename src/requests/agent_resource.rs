use std::collections::BTreeMap;

use axum::http::Uri;

use crate::{
    errors::OAuthError,
    handlers::responses::{ResponseLog, agent_resource_response},
    resources::http_signature::{
        SIGNATURE_KEY_HEADER, Validate, VerifiedSignatureKey, VerifyMessage,
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
    authenticated_key_index: Option<usize>,
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

    fn set_authenticated_agent(&mut self, key_index: usize) {
        self.response.authenticated_key_index = Some(key_index);
    }
}

impl ResponseLog for AgentResourceRequest<'_> {
    fn to_http_response(&self) -> Result<String, OAuthError> {
        self.response
            .authenticated_key_index
            .and_then(|index| self.response.verified_keys.get(index))
            .ok_or_else(|| OAuthError::invalid_token_response("authenticated agent is missing"))?;
        Ok(agent_resource_response())
    }

    fn log_success(&self) {
        eprintln!("Agent resource request authenticated");
    }
}
