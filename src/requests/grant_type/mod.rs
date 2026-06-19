use crate::{
    resources::grant_type::{self, GrantType},
    unit::{KagomeRequest, parse_request_parameter},
};

mod authorization_code;
mod client_credentials;
mod code_chain;
mod ssh_keys;

pub use authorization_code::{AuthorizationCodeRequest, AuthorizationCodeResponse};
pub use client_credentials::{ClientCredentialsRequest, ClientCredentialsResponse};
pub use code_chain::{
    CodeChainAuthorizationCodeRequest, CodeChainAuthorizationCodeResponse, CodeChainRequest,
    CodeChainResponse,
};
pub use ssh_keys::{SshKeysRequest, SshKeysResponse};

#[derive(Debug)]
pub struct GrantTypeRequest<'a> {
    pub response: GrantTypeResponse,
    pub request: &'a KagomeRequest,
    pub grant_type: Option<String>,
    pub grant_types: Vec<GrantType>,
}

#[derive(Debug)]
pub struct GrantTypeResponse {
    pub grant_type: Option<GrantType>,
    pub grant_types: Vec<GrantType>,
}

impl<'a> GrantTypeRequest<'a> {
    pub fn from_request(request: &'a KagomeRequest) -> Self {
        let grant_type = parse_request_parameter(request, "grant_type");

        Self {
            response: GrantTypeResponse::empty(),
            request,
            grant_types: grant_type
                .as_deref()
                .map(parse_grant_types)
                .unwrap_or_default(),
            grant_type,
        }
    }

    pub fn grant_types(&self) -> &[GrantType] {
        &self.grant_types
    }
}

impl GrantTypeResponse {
    pub fn empty() -> Self {
        Self {
            grant_type: None,
            grant_types: Vec::new(),
        }
    }
}

impl<'a> grant_type::Validate for GrantTypeRequest<'a> {
    fn request_grant_type(&self) -> Option<&str> {
        self.grant_type
            .as_deref()
            .and_then(|grant_type| grant_type.split_whitespace().next())
    }

    fn add_grant_type(&mut self, grant_type: &GrantType) {
        self.response.grant_type = Some(*grant_type);
        self.response.grant_types = self.grant_types.clone();
    }
}

fn parse_grant_types(grant_type: &str) -> Vec<GrantType> {
    grant_type
        .split_whitespace()
        .map_while(|grant_type| match grant_type {
            "authorization_code" => Some(GrantType::AuthorizationCode),
            "client_credentials" => Some(GrantType::ClientCredentials),
            "code_chain" => Some(GrantType::CodeChain),
            "ssh_keys" => Some(GrantType::SshKeys),
            _ => None,
        })
        .collect()
}
