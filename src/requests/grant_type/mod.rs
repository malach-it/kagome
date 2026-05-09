use crate::{
    resources::grant_type::{self, GrantType},
    unit::{KagomeRequest, parse_request_parameter},
};

mod authorization_code;
mod client_credentials;
mod code_chain;

pub use authorization_code::{AuthorizationCodeRequest, AuthorizationCodeResponse};
pub use client_credentials::{ClientCredentialsRequest, ClientCredentialsResponse};
pub use code_chain::{
    CodeChainRequest, CodeChainResponse, ContinueCodeChainRequest, ContinueCodeChainResponse,
    NewCodeChainRequest, NewCodeChainResponse,
};

#[derive(Debug)]
pub struct GrantTypeRequest<'a> {
    pub response: GrantTypeResponse,
    pub request: &'a KagomeRequest,
    pub grant_type: Option<GrantType>,
}

#[derive(Debug)]
pub struct GrantTypeResponse {
    pub grant_type: Option<GrantType>,
}

impl<'a> GrantTypeRequest<'a> {
    pub fn from_request(request: &'a KagomeRequest) -> Self {
        Self {
            response: GrantTypeResponse::empty(),
            request,
            grant_type: parse_request_parameter(request, "grant_type").and_then(|grant_type| {
                match grant_type.as_str() {
                    "authorization_code" => Some(GrantType::AuthorizationCode),
                    "client_credentials" => Some(GrantType::ClientCredentials),
                    "code_chain" => Some(GrantType::CodeChain),
                    _ => None,
                }
            }),
        }
    }
}

impl GrantTypeResponse {
    pub fn empty() -> Self {
        Self { grant_type: None }
    }
}

impl<'a> grant_type::Validate for GrantTypeRequest<'a> {
    fn request_grant_type(&self) -> Option<&str> {
        self.grant_type.map(GrantType::as_str)
    }

    fn add_grant_type(&mut self, grant_type: &GrantType) {
        self.response.grant_type = Some(*grant_type);
    }
}
