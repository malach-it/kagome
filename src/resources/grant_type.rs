use crate::errors::OAuthError;

pub const SUPPORTED_GRANT_TYPES: [&str; 4] = [
    "client_credentials",
    "code_chain",
    "authorization_code",
    "ssh_keys",
];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GrantType {
    AuthorizationCode,
    ClientCredentials,
    CodeChain,
    SshKeys,
}

impl GrantType {
    pub fn as_str(self) -> &'static str {
        match self {
            GrantType::AuthorizationCode => "authorization_code",
            GrantType::ClientCredentials => "client_credentials",
            GrantType::CodeChain => "code_chain",
            GrantType::SshKeys => "ssh_keys",
        }
    }
}

pub trait Validate {
    fn request_grant_type(&self) -> Option<&str> {
        None
    }

    fn add_grant_type(&mut self, grant_type: &GrantType);
}

pub fn validate<T: Validate>(mut token_request: T) -> Result<T, OAuthError> {
    let grant_type = parse(token_request.request_grant_type())?;
    token_request.add_grant_type(&grant_type);

    Ok(token_request)
}

fn parse(grant_type: Option<&str>) -> Result<GrantType, OAuthError> {
    match grant_type.and_then(|grant_type| grant_type.split_whitespace().next()) {
        Some("authorization_code") => Ok(GrantType::AuthorizationCode),
        Some("client_credentials") => Ok(GrantType::ClientCredentials),
        Some("code_chain") => Ok(GrantType::CodeChain),
        Some("ssh_keys") => Ok(GrantType::SshKeys),
        _ => Err(OAuthError::unsupported_grant_type(&SUPPORTED_GRANT_TYPES)),
    }
}
