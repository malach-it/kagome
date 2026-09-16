use crate::errors::OAuthError;
use schemars::JsonSchema;
use serde::Deserialize;

pub const RESOURCE_OWNER_PASSWORD_CREDENTIALS: &str = "password";

pub const SUPPORTED_GRANT_TYPES: [&str; 5] = [
    "client_credentials",
    RESOURCE_OWNER_PASSWORD_CREDENTIALS,
    "code_chain",
    "authorization_code",
    super::pre_authorized_code::GRANT_TYPE,
];

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, JsonSchema, PartialEq)]
pub enum GrantType {
    #[serde(rename = "authorization_code")]
    AuthorizationCode,
    #[serde(rename = "client_credentials")]
    ClientCredentials,
    #[serde(rename = "code_chain")]
    CodeChain,
    #[serde(rename = "implicit")]
    Implicit,
    #[serde(rename = "urn:ietf:params:oauth:grant-type:pre-authorized_code")]
    PreAuthorizedCode,
    #[serde(rename = "password")]
    ResourceOwnerPasswordCredentials,
}

impl GrantType {
    pub const ALL: [Self; 6] = [
        Self::AuthorizationCode,
        Self::ClientCredentials,
        Self::CodeChain,
        Self::Implicit,
        Self::PreAuthorizedCode,
        Self::ResourceOwnerPasswordCredentials,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            GrantType::AuthorizationCode => "authorization_code",
            GrantType::ClientCredentials => "client_credentials",
            GrantType::CodeChain => "code_chain",
            GrantType::Implicit => "implicit",
            GrantType::PreAuthorizedCode => super::pre_authorized_code::GRANT_TYPE,
            GrantType::ResourceOwnerPasswordCredentials => RESOURCE_OWNER_PASSWORD_CREDENTIALS,
        }
    }
}

/// Parses supported space-delimited grant names until the first unsupported value.
///
/// The returned order matches the input. Parsing deliberately stops at the first unknown value,
/// so callers can identify only the supported prefix without producing an error.
pub fn parse_supported(grant_type: &str) -> Vec<GrantType> {
    grant_type
        .split_whitespace()
        .map_while(|grant_type| match grant_type {
            "authorization_code" => Some(GrantType::AuthorizationCode),
            "client_credentials" => Some(GrantType::ClientCredentials),
            RESOURCE_OWNER_PASSWORD_CREDENTIALS => {
                Some(GrantType::ResourceOwnerPasswordCredentials)
            }
            "code_chain" => Some(GrantType::CodeChain),
            super::pre_authorized_code::GRANT_TYPE => Some(GrantType::PreAuthorizedCode),
            _ => None,
        })
        .collect()
}

pub trait Validate {
    fn request_grant_type(&self) -> Option<&str> {
        None
    }

    fn add_grant_type(&mut self, grant_type: &GrantType);
}

/// Selects and stores the supported grant type requested by a token request.
///
/// Exactly one grant type must be provided and is added as typed response state.
///
/// # Errors
///
/// Returns `unsupported_grant_type` when the parameter is absent or its first value is not
/// supported by the token endpoint.
pub fn validate<T: Validate>(mut token_request: T) -> Result<T, OAuthError> {
    let grant_type = parse(token_request.request_grant_type())?;
    token_request.add_grant_type(&grant_type);

    Ok(token_request)
}

fn parse(grant_type: Option<&str>) -> Result<GrantType, OAuthError> {
    let mut values = grant_type.into_iter().flat_map(str::split_whitespace);
    let grant_type = values.next();
    if values.next().is_some() {
        return Err(OAuthError::unsupported_grant_type(&SUPPORTED_GRANT_TYPES));
    }

    match grant_type {
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
