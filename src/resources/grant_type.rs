use crate::errors::OAuthError;

pub const RESOURCE_OWNER_PASSWORD_CREDENTIALS: &str = "password";

pub const SUPPORTED_GRANT_TYPES: [&str; 5] = [
    "client_credentials",
    RESOURCE_OWNER_PASSWORD_CREDENTIALS,
    "code_chain",
    "authorization_code",
    super::pre_authorized_code::GRANT_TYPE,
];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GrantType {
    AuthorizationCode,
    ClientCredentials,
    CodeChain,
    PreAuthorizedCode,
    ResourceOwnerPasswordCredentials,
}

impl GrantType {
    pub fn as_str(self) -> &'static str {
        match self {
            GrantType::AuthorizationCode => "authorization_code",
            GrantType::ClientCredentials => "client_credentials",
            GrantType::CodeChain => "code_chain",
            GrantType::PreAuthorizedCode => super::pre_authorized_code::GRANT_TYPE,
            GrantType::ResourceOwnerPasswordCredentials => RESOURCE_OWNER_PASSWORD_CREDENTIALS,
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
        Some(RESOURCE_OWNER_PASSWORD_CREDENTIALS) => {
            Ok(GrantType::ResourceOwnerPasswordCredentials)
        }
        Some("code_chain") => Ok(GrantType::CodeChain),
        Some(super::pre_authorized_code::GRANT_TYPE) => Ok(GrantType::PreAuthorizedCode),
        _ => Err(OAuthError::unsupported_grant_type(&SUPPORTED_GRANT_TYPES)),
    }
}
