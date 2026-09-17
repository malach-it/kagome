use std::{
    collections::{HashMap, HashSet},
    env,
    error::Error,
    fmt, fs,
    hash::Hash,
    io,
    path::{Path, PathBuf},
    sync::OnceLock,
};

use ring::digest;
use schemars::{JsonSchema, Schema, SchemaGenerator, generate::SchemaSettings};
use serde::{Deserialize, Serialize};

use crate::{
    key_management::{KeyManagementError, KeyManager},
    resources::{grant_type::GrantType, response_type::ResponseType},
};

pub const CONFIG_PATH_ENV_VAR: &str = "KAGOME_CONFIG";
pub const DEFAULT_CONFIG_PATH: &str = "kagome.yaml";
pub const DEFAULT_ACCESS_TOKEN_TTL_SECONDS: u64 = 3600;
pub const DEFAULT_AUTHORIZATION_CODE_TTL_SECONDS: u64 = 600;
pub const DEFAULT_AUTHORIZATION_CODE_CHAIN_MAX_DEPTH: usize = 8;
pub const MAX_AUTHORIZATION_CODE_CHAIN_DEPTH: usize = 32;
pub const DEFAULT_ID_TOKEN_TTL_SECONDS: u64 = 3600;
pub const DEFAULT_PRE_AUTHORIZED_CODE_TTL_SECONDS: u64 = 300;
pub const DEFAULT_FEDERATION_STATE_TTL_SECONDS: u64 = 300;
pub const DEFAULT_PRESENTATION_STATE_TTL_SECONDS: u64 = 300;
pub const DEFAULT_SIOPV2_STATE_TTL_SECONDS: u64 = 300;
pub const DEFAULT_MAX_CONSUMED_ARTIFACTS: usize = 100_000;
pub const DEFAULT_RATE_LIMIT_COUNT: usize = 10;
pub const DEFAULT_RATE_LIMIT_PENALITY_MILLISECONDS: u64 = 500;
pub const DEFAULT_RATE_LIMIT_TIMEOUT_MILLISECONDS: u64 = 5_000;
pub const DEFAULT_RATE_LIMIT_MEMORY_LENGTH: usize = 50;

static CONFIG: OnceLock<Config> = OnceLock::new();

#[derive(Debug, Deserialize, Eq, JsonSchema, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// HTTP server settings.
    pub server: ServerConfig,
    /// External file containing encryption secrets and signing key pairs.
    pub crypto: CryptoConfig,
    /// OAuth token lifetime and authorization-code chain settings.
    #[serde(default)]
    #[schemars(default)]
    pub tokens: TokenTtlsConfig,
    /// Verifiable credential configurations advertised and issued by the server.
    #[serde(default = "default_credential_configurations")]
    #[schemars(default = "default_credential_configurations", length(min = 1))]
    pub credentials: Vec<CredentialConfig>,
    /// Presentation definitions selected by OAuth scope identifiers.
    #[serde(default = "default_presentation_definitions")]
    #[schemars(default = "default_presentation_definitions", length(min = 1))]
    pub presentation_definitions: Vec<PresentationDefinitionConfig>,
    /// OAuth clients accepted by the authorization server.
    #[schemars(length(min = 1))]
    pub clients: Vec<ClientConfig>,
    #[serde(skip)]
    #[schemars(skip)]
    client_password_files: HashMap<PathBuf, ClientPasswordFile>,
    #[serde(skip)]
    #[schemars(skip)]
    key_manager: KeyManager,
}

#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CredentialConfig {
    /// Identifier used in issuer metadata, offers, and credential requests.
    #[schemars(length(min = 1))]
    pub credential_configuration_id: String,
    /// Human-readable credential name advertised in issuer metadata.
    #[schemars(length(min = 1))]
    pub name: String,
    /// Verifiable credential type identifier carried by the credential.
    #[schemars(length(min = 1))]
    pub vct: String,
    /// W3C Verifiable Credential types carried by the credential.
    #[serde(rename = "type")]
    #[schemars(length(min = 1))]
    pub credential_types: Vec<String>,
}

fn default_credential_configurations() -> Vec<CredentialConfig> {
    vec![CredentialConfig {
        credential_configuration_id: "UniversityDegreeCredential".to_owned(),
        name: "University Degree Credential".to_owned(),
        vct: "UniversityDegreeCredential".to_owned(),
        credential_types: vec!["UniversityDegreeCredential".to_owned()],
    }]
}

#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PresentationDefinitionConfig {
    /// OAuth scope value used to select the presentation definition.
    #[schemars(length(min = 1))]
    pub identifier: String,
    /// Presentation Exchange definition sent to the wallet and enforced on response.
    pub definition: serde_json::Value,
}

fn default_presentation_definitions() -> Vec<PresentationDefinitionConfig> {
    vec![PresentationDefinitionConfig {
        identifier: "credential_presentation".to_owned(),
        definition: serde_json::json!({
            "id": "credential_presentation",
            "input_descriptors": [{
                "id": "credential",
                "format": {"jwt_vc": {"alg": ["EdDSA"]}},
                "constraints": {"fields": [{
                    "path": ["$.vc.type"],
                    "filter": {
                        "type": "array",
                        "contains": {"const": "UniversityDegreeCredential"}
                    }
                }, {
                    "path": ["$.vc.credentialSubject.id"]
                }]}
            }]
        }),
    }]
}

impl PresentationDefinitionConfig {
    pub fn definition_id(&self) -> Option<&str> {
        self.definition.get("id")?.as_str()
    }

    pub fn input_descriptor_id(&self) -> Option<&str> {
        self.definition
            .get("input_descriptors")?
            .as_array()?
            .first()?
            .get("id")?
            .as_str()
    }
}

#[derive(Debug, Deserialize, Eq, JsonSchema, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct CryptoConfig {
    /// YAML file loaded once at startup with encryption secrets and signing keys.
    pub key_file: PathBuf,
}

#[derive(Debug, Eq, PartialEq)]
struct ClientPasswordFile {
    contents: String,
    usernames: Vec<String>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, JsonSchema, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct TokenTtlsConfig {
    /// Lifetime of an access token, in seconds.
    #[schemars(range(min = 1))]
    pub access_token_ttl: u64,
    /// Lifetime of an authorization code, in seconds.
    #[schemars(range(min = 1))]
    pub authorization_code_ttl: u64,
    /// Lifetime of an ID token, in seconds.
    #[schemars(range(min = 1))]
    pub id_token_ttl: u64,
    /// Lifetime of a pre-authorized code, in seconds.
    #[serde(default = "default_pre_authorized_code_ttl")]
    #[schemars(default = "default_pre_authorized_code_ttl", range(min = 1))]
    pub pre_authorized_code_ttl: u64,
    /// Lifetime of encrypted federation state, in seconds.
    #[serde(default = "default_federation_state_ttl")]
    #[schemars(default = "default_federation_state_ttl", range(min = 1))]
    pub federation_state_ttl: u64,
    /// Lifetime of encrypted presentation state, in seconds.
    #[serde(default = "default_presentation_state_ttl")]
    #[schemars(default = "default_presentation_state_ttl", range(min = 1))]
    pub presentation_state_ttl: u64,
    /// Lifetime of encrypted SIOPv2 state, in seconds.
    #[serde(default = "default_siopv2_state_ttl")]
    #[schemars(default = "default_siopv2_state_ttl", range(min = 1))]
    pub siopv2_state_ttl: u64,
    /// Maximum number of nested authorization codes accepted in one chain.
    #[serde(default = "default_authorization_code_chain_max_depth")]
    #[schemars(
        default = "default_authorization_code_chain_max_depth",
        range(min = 1, max = 32)
    )]
    pub authorization_code_chain_max_depth: usize,
}

impl Default for TokenTtlsConfig {
    fn default() -> Self {
        Self {
            access_token_ttl: DEFAULT_ACCESS_TOKEN_TTL_SECONDS,
            authorization_code_ttl: DEFAULT_AUTHORIZATION_CODE_TTL_SECONDS,
            id_token_ttl: DEFAULT_ID_TOKEN_TTL_SECONDS,
            pre_authorized_code_ttl: DEFAULT_PRE_AUTHORIZED_CODE_TTL_SECONDS,
            federation_state_ttl: DEFAULT_FEDERATION_STATE_TTL_SECONDS,
            presentation_state_ttl: DEFAULT_PRESENTATION_STATE_TTL_SECONDS,
            siopv2_state_ttl: DEFAULT_SIOPV2_STATE_TTL_SECONDS,
            authorization_code_chain_max_depth: DEFAULT_AUTHORIZATION_CODE_CHAIN_MAX_DEPTH,
        }
    }
}

fn default_authorization_code_chain_max_depth() -> usize {
    DEFAULT_AUTHORIZATION_CODE_CHAIN_MAX_DEPTH
}
fn default_federation_state_ttl() -> u64 {
    DEFAULT_FEDERATION_STATE_TTL_SECONDS
}
fn default_presentation_state_ttl() -> u64 {
    DEFAULT_PRESENTATION_STATE_TTL_SECONDS
}
fn default_siopv2_state_ttl() -> u64 {
    DEFAULT_SIOPV2_STATE_TTL_SECONDS
}
fn default_pre_authorized_code_ttl() -> u64 {
    DEFAULT_PRE_AUTHORIZED_CODE_TTL_SECONDS
}

#[derive(Debug, Deserialize, Eq, JsonSchema, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ServerConfig {
    /// Socket address on which the HTTP server listens.
    #[schemars(length(min = 1))]
    pub address: String,
    /// Public HTTP origin used to construct callback URLs.
    #[schemars(length(min = 1), url)]
    pub issuer: String,
    /// Number of HTTP request worker threads.
    #[schemars(range(min = 1))]
    pub workers: usize,
    /// Enable process-local replay protection for short-lived protocol artifacts.
    #[serde(default)]
    #[schemars(default)]
    pub replay_protection: ReplayProtectionConfig,
    /// Global per-IP request throttling policy.
    #[serde(default)]
    #[schemars(default)]
    pub rate_limit: RateLimitConfig,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, JsonSchema, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct RateLimitConfig {
    /// Target number of requests per configured time unit.
    #[schemars(range(min = 1, max = 100_000))]
    pub count: usize,
    /// Time unit used to group request history.
    pub time_unit: RateLimitTimeUnit,
    /// Delay multiplier, in milliseconds, applied to the historical overload factor.
    #[schemars(range(max = 600_000))]
    pub penality: u64,
    /// Reject requests whose calculated delay reaches this value, in milliseconds.
    #[schemars(range(max = 600_000))]
    pub timeout: u64,
    /// Number of time-unit buckets retained per client IP.
    #[schemars(range(min = 1, max = 10_000))]
    pub memory_length: usize,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            count: DEFAULT_RATE_LIMIT_COUNT,
            time_unit: RateLimitTimeUnit::Second,
            penality: DEFAULT_RATE_LIMIT_PENALITY_MILLISECONDS,
            timeout: DEFAULT_RATE_LIMIT_TIMEOUT_MILLISECONDS,
            memory_length: DEFAULT_RATE_LIMIT_MEMORY_LENGTH,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, JsonSchema, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum RateLimitTimeUnit {
    Millisecond,
    Second,
    Minute,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, JsonSchema, PartialEq)]
#[serde(untagged)]
pub enum ReplayProtectionConfig {
    /// Enables replay protection with the default artifact capacity, or disables it when false.
    Boolean(bool),
    /// Enables replay protection with this maximum number of tracked artifacts.
    Capacity(#[schemars(range(min = 1))] usize),
}

impl Default for ReplayProtectionConfig {
    fn default() -> Self {
        Self::Boolean(true)
    }
}

impl ReplayProtectionConfig {
    pub fn enabled(self) -> bool {
        !matches!(self, Self::Boolean(false))
    }

    pub fn capacity(self) -> usize {
        match self {
            Self::Boolean(_) => DEFAULT_MAX_CONSUMED_ARTIFACTS,
            Self::Capacity(capacity) => capacity,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ClientConfig {
    /// Public identifier of the OAuth client.
    #[schemars(length(min = 1))]
    pub client_id: String,
    /// Host used to resolve dynamic `username@host` client identifiers.
    #[serde(default)]
    #[schemars(length(min = 1))]
    pub public: Option<String>,
    /// Secret used to authenticate the OAuth client at the token endpoint.
    #[schemars(length(min = 1))]
    pub client_secret: String,
    /// Optional nginx-style resource-owner password file.
    #[serde(default)]
    pub password_file: Option<PathBuf>,
    /// Exact redirect URIs accepted for authorization responses.
    #[schemars(length(min = 1), inner(length(min = 1)))]
    pub redirect_uris: Vec<String>,
    /// OAuth grant types this client may use.
    #[serde(default = "empty_supported_grant_types")]
    #[schemars(default = "empty_supported_grant_types")]
    pub supported_grant_types: Vec<GrantType>,
    /// OAuth response types this client may request.
    #[serde(default = "empty_supported_response_types")]
    #[schemars(default = "empty_supported_response_types")]
    pub supported_response_types: Vec<ResponseType>,
    /// OAuth scopes this client may request.
    #[serde(default = "empty_scopes")]
    #[schemars(default = "empty_scopes", inner(length(min = 1)))]
    pub scopes: Vec<String>,
    /// Require wallet proofs and presentations to be bound to the public key
    /// from the ID token carried by the incoming authorization code.
    #[serde(default)]
    #[schemars(default)]
    pub require_wallet_binding: bool,
    /// Render wallet authorization URLs as QR-code HTML instead of redirects.
    #[serde(default)]
    #[schemars(default)]
    pub qr_code: bool,
    /// Upstream OAuth server used to federate identities for this client.
    pub federated_server: Option<FederatedServerConfig>,
}

fn empty_supported_grant_types() -> Vec<GrantType> {
    Vec::new()
}

fn empty_supported_response_types() -> Vec<ResponseType> {
    Vec::new()
}

fn empty_scopes() -> Vec<String> {
    Vec::new()
}

#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct FederatedServerConfig {
    /// Client identifier used to authenticate Kagome to the federated server.
    #[schemars(length(min = 1))]
    pub client_id: String,
    /// Client secret used to authenticate Kagome to the federated server.
    #[schemars(length(min = 1))]
    pub client_secret: String,
    /// Federated server endpoint to which authorization requests are sent.
    #[schemars(length(min = 1), url)]
    pub authorize_endpoint: String,
    /// Federated server endpoint at which authorization codes are exchanged.
    #[schemars(length(min = 1), url)]
    pub token_endpoint: String,
    /// Federated endpoints used to obtain identity claims with the access token.
    #[schemars(length(min = 1))]
    pub endpoints: Vec<FederatedIdentityEndpointConfig>,
}

#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct FederatedIdentityEndpointConfig {
    /// Endpoint called with the federated bearer access token.
    #[schemars(length(min = 1), url)]
    pub endpoint: String,
    /// Claims copied from the endpoint response into resource-owner attributes.
    #[schemars(length(min = 1))]
    pub claims: Vec<FederatedIdentityClaimConfig>,
}

#[derive(Clone, Debug, Deserialize, Eq, JsonSchema, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct FederatedIdentityClaimConfig {
    /// Dot-separated JSON claim path read from the endpoint response.
    #[schemars(length(min = 1))]
    pub claim: String,
    /// Resource-owner attribute populated from the claim.
    #[schemars(length(min = 1))]
    pub target: String,
    /// Include the attribute in generated ID tokens.
    #[serde(default)]
    pub id_token: bool,
    /// Credential configuration identifiers whose subjects include the attribute.
    #[serde(default)]
    pub credential: Vec<String>,
}

impl Config {
    pub fn initialize() -> Result<&'static Self, ConfigError> {
        Self::set_global(Self::load()?)
    }

    pub fn set_global(config: Self) -> Result<&'static Self, ConfigError> {
        CONFIG
            .set(config)
            .map_err(|_| ConfigError::AlreadyInitialized)?;

        Ok(CONFIG
            .get()
            .expect("configuration must be available after initialization"))
    }

    pub fn global() -> &'static Self {
        CONFIG
            .get()
            .expect("configuration must be initialized at startup")
    }

    pub fn token_ttls() -> TokenTtlsConfig {
        CONFIG.get().map(|config| config.tokens).unwrap_or_default()
    }

    pub fn replay_protection_enabled() -> bool {
        CONFIG
            .get()
            .map(|config| config.server.replay_protection.enabled())
            .unwrap_or(true)
    }

    pub fn replay_protection_capacity() -> usize {
        CONFIG
            .get()
            .map(|config| config.server.replay_protection.capacity())
            .unwrap_or(DEFAULT_MAX_CONSUMED_ARTIFACTS)
    }

    /// Returns a startup-safe configuration summary with credentials and key material redacted.
    pub fn redacted_summary(&self) -> String {
        let crypto_sha256 = fs::read(&self.crypto.key_file)
            .map(|contents| {
                digest::digest(&digest::SHA256, &contents)
                    .as_ref()
                    .iter()
                    .map(|byte| format!("{byte:02x}"))
                    .collect::<String>()
            })
            .unwrap_or_else(|_| "unavailable".to_owned());
        let replay_protection = match self.server.replay_protection {
            ReplayProtectionConfig::Boolean(enabled) => serde_json::json!(enabled),
            ReplayProtectionConfig::Capacity(capacity) => serde_json::json!(capacity),
        };
        let clients: Vec<_> = self
            .clients
            .iter()
            .map(|client| {
                serde_json::json!({
                    "client_id": client.client_id,
                    "public": client.public,
                    "redirect_uris": client.redirect_uris,
                    "supported_grant_types": client
                        .supported_grant_types
                        .iter()
                        .map(|grant| format!("{grant:?}"))
                        .collect::<Vec<_>>(),
                    "supported_response_types": client
                        .supported_response_types
                        .iter()
                        .map(|response| format!("{response:?}"))
                        .collect::<Vec<_>>(),
                    "scopes": client.scopes,
                    "require_wallet_binding": client.require_wallet_binding,
                    "qr_code": client.qr_code,
                    "client_secret": "[redacted]",
                    "password_file": client.password_file.as_ref().map(|_| "[redacted]"),
                    "federated_server": client.federated_server.as_ref().map(|_| "[redacted]"),
                })
            })
            .collect();

        serde_yaml_ng::to_string(&serde_json::json!({
            "server": {
                "address": self.server.address,
                "issuer": self.server.issuer,
                "workers": self.server.workers,
                "replay_protection": replay_protection,
                "rate_limit": {
                    "count": self.server.rate_limit.count,
                    "time_unit": format!("{:?}", self.server.rate_limit.time_unit).to_lowercase(),
                    "penality": self.server.rate_limit.penality,
                    "timeout": self.server.rate_limit.timeout,
                    "memory_length": self.server.rate_limit.memory_length,
                },
            },
            "crypto": {
                "key_file": self.crypto.key_file,
                "sha256": crypto_sha256,
                "contents": "[redacted]"
            },
            "tokens": {
                "access_token_ttl": self.tokens.access_token_ttl,
                "authorization_code_ttl": self.tokens.authorization_code_ttl,
                "id_token_ttl": self.tokens.id_token_ttl,
                "pre_authorized_code_ttl": self.tokens.pre_authorized_code_ttl,
                "federation_state_ttl": self.tokens.federation_state_ttl,
                "presentation_state_ttl": self.tokens.presentation_state_ttl,
                "siopv2_state_ttl": self.tokens.siopv2_state_ttl,
                "authorization_code_chain_max_depth": self.tokens.authorization_code_chain_max_depth,
            },
            "credentials": &self.credentials,
            "presentation_definitions": &self.presentation_definitions,
            "clients": clients,
        }))
        .expect("redacted configuration summary must serialize as YAML")
    }

    pub(crate) fn key_manager() -> &'static KeyManager {
        if let Some(config) = CONFIG.get() {
            return &config.key_manager;
        }

        #[cfg(debug_assertions)]
        {
            static TEST_KEYS: OnceLock<KeyManager> = OnceLock::new();
            TEST_KEYS.get_or_init(|| {
                KeyManager::from_yaml(include_str!("../tests/fixtures/kagome.crypto.yaml"))
                    .expect("test crypto key file must be valid")
            })
        }

        #[cfg(not(debug_assertions))]
        panic!("configuration must be initialized at startup")
    }

    pub fn client(&self, client_id: &str) -> Option<&ClientConfig> {
        self.clients
            .iter()
            .find(|client| client.client_id == client_id)
            .or_else(|| {
                let public_host = client_id.split_once('@')?.1;
                self.clients.iter().find(|client| {
                    client
                        .public
                        .as_deref()
                        .is_some_and(|configured| configured.eq_ignore_ascii_case(public_host))
                })
            })
    }

    pub fn credential(&self, credential_configuration_id: &str) -> Option<&CredentialConfig> {
        self.credentials.iter().find(|credential| {
            credential.credential_configuration_id == credential_configuration_id
        })
    }

    pub fn presentation_definition(
        &self,
        identifier: &str,
    ) -> Option<&PresentationDefinitionConfig> {
        self.presentation_definitions
            .iter()
            .find(|presentation| presentation.identifier == identifier)
    }

    pub fn client_password_file(&self, client_id: &str) -> Option<(&str, &[String])> {
        let configured_path = self.client(client_id)?.password_file.as_ref()?;
        self.client_password_files
            .get(configured_path)
            .map(|password_file| {
                (
                    password_file.contents.as_str(),
                    password_file.usernames.as_slice(),
                )
            })
    }

    pub fn json_schema() -> Schema {
        SchemaGenerator::new(SchemaSettings::draft2020_12()).into_root_schema_for::<Self>()
    }

    pub fn load() -> Result<Self, ConfigError> {
        let path = env::var_os(CONFIG_PATH_ENV_VAR)
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from(DEFAULT_CONFIG_PATH));

        Self::load_from_path(path)
    }

    pub fn load_from_path(path: impl AsRef<Path>) -> Result<Self, ConfigError> {
        let path = path.as_ref();
        let yaml = fs::read_to_string(path).map_err(|source| ConfigError::Read {
            path: path.to_owned(),
            source,
        })?;
        let mut config: Self =
            serde_yaml_ng::from_str(&yaml).map_err(|source| ConfigError::Parse {
                path: path.to_owned(),
                source,
            })?;

        config.validate(path)?;
        config.load_key_manager(path)?;
        config.load_client_password_files(path)?;

        Ok(config)
    }

    fn load_key_manager(&mut self, config_path: &Path) -> Result<(), ConfigError> {
        let configured_path = &self.crypto.key_file;
        if configured_path.as_os_str().is_empty() {
            return Err(ConfigError::Validation {
                path: config_path.to_owned(),
                message: "crypto.key_file must not be empty".to_owned(),
            });
        }
        let key_file = resolve_relative_path(config_path, configured_path);
        self.key_manager = KeyManager::load(&key_file).map_err(|error| match error {
            KeyManagementError::Read(source) => ConfigError::CryptoFileRead {
                path: key_file.clone(),
                source,
            },
            KeyManagementError::Parse(source) => ConfigError::CryptoFileParse {
                path: key_file.clone(),
                source,
            },
            KeyManagementError::Validation(message) => ConfigError::Validation {
                path: key_file,
                message,
            },
        })?;

        Ok(())
    }

    fn load_client_password_files(&mut self, config_path: &Path) -> Result<(), ConfigError> {
        for client in &self.clients {
            let Some(configured_path) = client.password_file.as_ref() else {
                continue;
            };
            let password_file = resolve_relative_path(config_path, configured_path);
            let contents = fs::read_to_string(&password_file).map_err(|source| {
                ConfigError::PasswordFileRead {
                    path: password_file.clone(),
                    source,
                }
            })?;
            let password_file_config =
                parse_password_file(&contents).map_err(|message| ConfigError::Validation {
                    path: password_file.clone(),
                    message,
                })?;
            self.client_password_files
                .insert(configured_path.clone(), password_file_config);
        }
        Ok(())
    }

    fn validate(&self, path: &Path) -> Result<(), ConfigError> {
        if self.server.address.trim().is_empty() {
            return Err(ConfigError::Validation {
                path: path.to_owned(),
                message: "server.address must not be empty".to_owned(),
            });
        }

        if !is_http_endpoint(&self.server.issuer) {
            return Err(ConfigError::Validation {
                path: path.to_owned(),
                message: "server.issuer must be an absolute HTTP or HTTPS URL".to_owned(),
            });
        }

        if self.server.workers == 0 {
            return Err(ConfigError::Validation {
                path: path.to_owned(),
                message: "server.workers must be greater than zero".to_owned(),
            });
        }

        let rate_limit = self.server.rate_limit;
        if !(1..=100_000).contains(&rate_limit.count)
            || rate_limit.penality > 600_000
            || rate_limit.timeout > 600_000
            || !(1..=10_000).contains(&rate_limit.memory_length)
        {
            return Err(ConfigError::Validation {
                path: path.to_owned(),
                message: "server.rate_limit values are outside their supported ranges".to_owned(),
            });
        }

        if matches!(
            self.server.replay_protection,
            ReplayProtectionConfig::Capacity(0)
        ) {
            return Err(ConfigError::Validation {
                path: path.to_owned(),
                message: "server.replay_protection capacity must be greater than zero".to_owned(),
            });
        }

        if self.clients.is_empty() {
            return Err(ConfigError::Validation {
                path: path.to_owned(),
                message: "clients must contain at least one client".to_owned(),
            });
        }

        if self.credentials.is_empty() {
            return Err(ConfigError::Validation {
                path: path.to_owned(),
                message: "credentials must contain at least one credential configuration"
                    .to_owned(),
            });
        }
        let mut credential_configuration_ids = HashSet::new();
        for (index, credential) in self.credentials.iter().enumerate() {
            for (field, value) in [
                (
                    "credential_configuration_id",
                    credential.credential_configuration_id.as_str(),
                ),
                ("name", credential.name.as_str()),
                ("vct", credential.vct.as_str()),
            ] {
                if value.trim().is_empty() {
                    return Err(ConfigError::Validation {
                        path: path.to_owned(),
                        message: format!("credentials[{index}].{field} must not be empty"),
                    });
                }
            }
            if credential.credential_types.is_empty()
                || credential
                    .credential_types
                    .iter()
                    .any(|credential_type| credential_type.trim().is_empty())
            {
                return Err(ConfigError::Validation {
                    path: path.to_owned(),
                    message: format!("credentials[{index}].type must contain non-empty values"),
                });
            }
            let mut credential_types = HashSet::new();
            if credential
                .credential_types
                .iter()
                .any(|credential_type| !credential_types.insert(credential_type))
            {
                return Err(ConfigError::Validation {
                    path: path.to_owned(),
                    message: format!("credentials[{index}].type must not contain duplicates"),
                });
            }
            if credential
                .credential_types
                .iter()
                .any(|credential_type| credential_type == "VerifiableCredential")
            {
                return Err(ConfigError::Validation {
                    path: path.to_owned(),
                    message: format!(
                        "credentials[{index}].type must not contain VerifiableCredential because it is added automatically"
                    ),
                });
            }
            if !credential_configuration_ids.insert(credential.credential_configuration_id.as_str())
            {
                return Err(ConfigError::Validation {
                    path: path.to_owned(),
                    message: format!(
                        "credential_configuration_id must be unique: {}",
                        credential.credential_configuration_id
                    ),
                });
            }
        }

        if self.presentation_definitions.is_empty() {
            return Err(ConfigError::Validation {
                path: path.to_owned(),
                message: "presentation_definitions must contain at least one definition".to_owned(),
            });
        }
        let mut presentation_identifiers = HashSet::new();
        let mut presentation_definition_ids = HashSet::new();
        for (index, presentation) in self.presentation_definitions.iter().enumerate() {
            if presentation.identifier.trim().is_empty() {
                return Err(ConfigError::Validation {
                    path: path.to_owned(),
                    message: format!(
                        "presentation_definitions[{index}].identifier must not be empty"
                    ),
                });
            }
            if !presentation_identifiers.insert(presentation.identifier.as_str()) {
                return Err(ConfigError::Validation {
                    path: path.to_owned(),
                    message: format!(
                        "presentation definition identifier must be unique: {}",
                        presentation.identifier
                    ),
                });
            }
            let definition_id = presentation
                .definition_id()
                .filter(|id| !id.trim().is_empty());
            let Some(definition_id) = definition_id else {
                return Err(ConfigError::Validation {
                    path: path.to_owned(),
                    message: format!(
                        "presentation_definitions[{index}].definition.id must be a non-empty string"
                    ),
                });
            };
            if !presentation_definition_ids.insert(definition_id) {
                return Err(ConfigError::Validation {
                    path: path.to_owned(),
                    message: format!("presentation definition id must be unique: {definition_id}"),
                });
            }
            let input_descriptors = presentation
                .definition
                .get("input_descriptors")
                .and_then(serde_json::Value::as_array);
            let Some([input_descriptor]) = input_descriptors.map(Vec::as_slice) else {
                return Err(ConfigError::Validation {
                    path: path.to_owned(),
                    message: format!(
                        "presentation_definitions[{index}].definition.input_descriptors must contain exactly one descriptor"
                    ),
                });
            };
            if input_descriptor
                .get("id")
                .and_then(serde_json::Value::as_str)
                .is_none_or(|id| id.trim().is_empty())
            {
                return Err(ConfigError::Validation {
                    path: path.to_owned(),
                    message: format!(
                        "presentation_definitions[{index}].definition.input_descriptors[0].id must be a non-empty string"
                    ),
                });
            }
        }

        for (field, ttl) in [
            ("access_token_ttl", self.tokens.access_token_ttl),
            ("authorization_code_ttl", self.tokens.authorization_code_ttl),
            ("id_token_ttl", self.tokens.id_token_ttl),
            (
                "pre_authorized_code_ttl",
                self.tokens.pre_authorized_code_ttl,
            ),
            ("federation_state_ttl", self.tokens.federation_state_ttl),
            ("presentation_state_ttl", self.tokens.presentation_state_ttl),
            ("siopv2_state_ttl", self.tokens.siopv2_state_ttl),
        ] {
            if ttl == 0 {
                return Err(ConfigError::Validation {
                    path: path.to_owned(),
                    message: format!("tokens.{field} must be greater than zero"),
                });
            }
        }

        if !(1..=MAX_AUTHORIZATION_CODE_CHAIN_DEPTH)
            .contains(&self.tokens.authorization_code_chain_max_depth)
        {
            return Err(ConfigError::Validation {
                path: path.to_owned(),
                message: format!(
                    "tokens.authorization_code_chain_max_depth must be between 1 and {MAX_AUTHORIZATION_CODE_CHAIN_DEPTH}"
                ),
            });
        }

        let mut client_ids = HashSet::new();
        let mut public_hosts = HashSet::new();
        for (index, client) in self.clients.iter().enumerate() {
            if client.client_id.trim().is_empty() {
                return Err(ConfigError::Validation {
                    path: path.to_owned(),
                    message: format!("clients[{index}].client_id must not be empty"),
                });
            }
            if !client_ids.insert(client.client_id.as_str()) {
                return Err(ConfigError::Validation {
                    path: path.to_owned(),
                    message: format!("client_id must be unique: {}", client.client_id),
                });
            }
            if client.client_secret.trim().is_empty() {
                return Err(ConfigError::Validation {
                    path: path.to_owned(),
                    message: format!("clients[{index}].client_secret must not be empty"),
                });
            }
            if client
                .password_file
                .as_ref()
                .is_some_and(|password_file| password_file.as_os_str().is_empty())
            {
                return Err(ConfigError::Validation {
                    path: path.to_owned(),
                    message: format!("clients[{index}].password_file must not be empty"),
                });
            }
            if let Some(public) = client.public.as_deref() {
                if !is_host(public) {
                    return Err(ConfigError::Validation {
                        path: path.to_owned(),
                        message: format!("clients[{index}].public must be a valid host"),
                    });
                }
                if !public_hosts.insert(public.to_ascii_lowercase()) {
                    return Err(ConfigError::Validation {
                        path: path.to_owned(),
                        message: format!("public host must be unique: {public}"),
                    });
                }
            }
            if client.redirect_uris.is_empty() {
                return Err(ConfigError::Validation {
                    path: path.to_owned(),
                    message: format!("clients[{index}].redirect_uris must not be empty"),
                });
            }
            validate_client_capabilities(
                path,
                index,
                "supported_grant_types",
                &client.supported_grant_types,
            )?;
            validate_client_capabilities(
                path,
                index,
                "supported_response_types",
                &client.supported_response_types,
            )?;
            validate_client_capabilities(path, index, "scopes", &client.scopes)?;
            if client.scopes.iter().any(|scope| !is_scope_token(scope)) {
                return Err(ConfigError::Validation {
                    path: path.to_owned(),
                    message: format!(
                        "clients[{index}].scopes must contain valid non-empty OAuth scope tokens"
                    ),
                });
            }
            if client
                .redirect_uris
                .iter()
                .any(|redirect_uri| redirect_uri.trim().is_empty())
            {
                return Err(ConfigError::Validation {
                    path: path.to_owned(),
                    message: format!(
                        "clients[{index}].redirect_uris must not contain empty values"
                    ),
                });
            }
            if let Some(federated_server) = &client.federated_server {
                for (field, value) in [
                    ("client_id", federated_server.client_id.as_str()),
                    ("client_secret", federated_server.client_secret.as_str()),
                    (
                        "authorize_endpoint",
                        federated_server.authorize_endpoint.as_str(),
                    ),
                    ("token_endpoint", federated_server.token_endpoint.as_str()),
                ] {
                    if value.trim().is_empty() {
                        return Err(ConfigError::Validation {
                            path: path.to_owned(),
                            message: format!(
                                "clients[{index}].federated_server.{field} must not be empty"
                            ),
                        });
                    }
                }
                for (field, endpoint) in [
                    (
                        "authorize_endpoint",
                        federated_server.authorize_endpoint.as_str(),
                    ),
                    ("token_endpoint", federated_server.token_endpoint.as_str()),
                ] {
                    if !is_http_endpoint(endpoint) {
                        return Err(ConfigError::Validation {
                            path: path.to_owned(),
                            message: format!(
                                "clients[{index}].federated_server.{field} must be an absolute HTTP or HTTPS URL"
                            ),
                        });
                    }
                }
                if federated_server.endpoints.is_empty() {
                    return Err(ConfigError::Validation {
                        path: path.to_owned(),
                        message: format!(
                            "clients[{index}].federated_server.endpoints must not be empty"
                        ),
                    });
                }
                for (endpoint_index, identity_endpoint) in
                    federated_server.endpoints.iter().enumerate()
                {
                    if !is_http_endpoint(&identity_endpoint.endpoint) {
                        return Err(ConfigError::Validation {
                            path: path.to_owned(),
                            message: format!(
                                "clients[{index}].federated_server.endpoints[{endpoint_index}].endpoint must be an absolute HTTP or HTTPS URL"
                            ),
                        });
                    }
                    if identity_endpoint.claims.is_empty() {
                        return Err(ConfigError::Validation {
                            path: path.to_owned(),
                            message: format!(
                                "clients[{index}].federated_server.endpoints[{endpoint_index}].claims must not be empty"
                            ),
                        });
                    }
                    for (claim_index, identity_claim) in identity_endpoint.claims.iter().enumerate()
                    {
                        if identity_claim.claim.trim().is_empty()
                            || identity_claim
                                .claim
                                .split('.')
                                .any(|segment| segment.is_empty())
                        {
                            return Err(ConfigError::Validation {
                                path: path.to_owned(),
                                message: format!(
                                    "clients[{index}].federated_server.endpoints[{endpoint_index}].claims[{claim_index}].claim must be a dot-separated JSON claim path"
                                ),
                            });
                        }
                        if identity_claim.target.trim().is_empty() {
                            return Err(ConfigError::Validation {
                                path: path.to_owned(),
                                message: format!(
                                    "clients[{index}].federated_server.endpoints[{endpoint_index}].claims[{claim_index}].target must not be empty"
                                ),
                            });
                        }
                        let mut claim_credential_ids = HashSet::new();
                        for credential_configuration_id in &identity_claim.credential {
                            if credential_configuration_id.trim().is_empty() {
                                return Err(ConfigError::Validation {
                                    path: path.to_owned(),
                                    message: format!(
                                        "clients[{index}].federated_server.endpoints[{endpoint_index}].claims[{claim_index}].credential must not contain empty values"
                                    ),
                                });
                            }
                            if !claim_credential_ids.insert(credential_configuration_id.as_str()) {
                                return Err(ConfigError::Validation {
                                    path: path.to_owned(),
                                    message: format!(
                                        "clients[{index}].federated_server.endpoints[{endpoint_index}].claims[{claim_index}].credential must not contain duplicate values"
                                    ),
                                });
                            }
                            if !credential_configuration_ids
                                .contains(credential_configuration_id.as_str())
                            {
                                return Err(ConfigError::Validation {
                                    path: path.to_owned(),
                                    message: format!(
                                        "clients[{index}].federated_server.endpoints[{endpoint_index}].claims[{claim_index}].credential references unknown credential configuration: {credential_configuration_id}"
                                    ),
                                });
                            }
                        }
                        if !identity_claim.credential.is_empty() && identity_claim.target == "id" {
                            return Err(ConfigError::Validation {
                                path: path.to_owned(),
                                message: format!(
                                    "clients[{index}].federated_server.endpoints[{endpoint_index}].claims[{claim_index}].target is reserved for credential subjects"
                                ),
                            });
                        }
                    }
                }
            }
        }

        Ok(())
    }
}

fn resolve_relative_path(config_path: &Path, configured_path: &Path) -> PathBuf {
    if configured_path.is_absolute() {
        configured_path.to_owned()
    } else {
        config_path
            .parent()
            .unwrap_or_else(|| Path::new(""))
            .join(configured_path)
    }
}

fn is_http_endpoint(endpoint: &str) -> bool {
    let authority_and_path = endpoint
        .strip_prefix("https://")
        .or_else(|| endpoint.strip_prefix("http://"));

    authority_and_path.is_some_and(|value| {
        value
            .split(['/', '?', '#'])
            .next()
            .is_some_and(|authority| !authority.is_empty())
            && !value
                .chars()
                .any(|character| character.is_ascii_control() || character.is_whitespace())
    })
}

fn is_host(host: &str) -> bool {
    !host.is_empty()
        && host.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b':' | b'[' | b']')
        })
}

fn is_scope_token(scope: &str) -> bool {
    !scope.is_empty()
        && scope.bytes().all(|byte| {
            byte == b'!' || (b'#'..=b'[').contains(&byte) || (b']'..=b'~').contains(&byte)
        })
}

fn validate_client_capabilities<T: Eq + Hash>(
    path: &Path,
    client_index: usize,
    field: &str,
    capabilities: &[T],
) -> Result<(), ConfigError> {
    let mut unique = HashSet::new();
    if capabilities
        .iter()
        .any(|capability| !unique.insert(capability))
    {
        return Err(ConfigError::Validation {
            path: path.to_owned(),
            message: format!("clients[{client_index}].{field} must not contain duplicates"),
        });
    }

    Ok(())
}

fn parse_password_file(contents: &str) -> Result<ClientPasswordFile, String> {
    let mut normalized_contents = String::new();
    let mut usernames = Vec::new();
    let mut unique_usernames = HashSet::new();

    for (index, line) in contents.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        let Some((username, password_and_comment)) = line.split_once(':') else {
            return Err(format!("line {} must contain username:password", index + 1));
        };
        let password = password_and_comment
            .split_once(':')
            .map_or(password_and_comment, |(value, _)| value);
        if username.is_empty() || password.is_empty() {
            return Err(format!(
                "line {} must contain a non-empty username and password",
                index + 1
            ));
        }
        if bcrypt::verify([], password).is_err() {
            return Err(format!(
                "line {} must contain a valid bcrypt password hash",
                index + 1
            ));
        }
        if !unique_usernames.insert(username) {
            return Err(format!("username must be unique: {username}"));
        }
        normalized_contents.push_str(username);
        normalized_contents.push(':');
        normalized_contents.push_str(password);
        normalized_contents.push('\n');
        usernames.push(username.to_owned());
    }

    if usernames.is_empty() {
        return Err("password file must contain at least one credential".to_owned());
    }

    Ok(ClientPasswordFile {
        contents: normalized_contents,
        usernames,
    })
}

#[derive(Debug)]
pub enum ConfigError {
    AlreadyInitialized,
    Read {
        path: PathBuf,
        source: io::Error,
    },
    Parse {
        path: PathBuf,
        source: serde_yaml_ng::Error,
    },
    CryptoFileRead {
        path: PathBuf,
        source: io::Error,
    },
    CryptoFileParse {
        path: PathBuf,
        source: serde_yaml_ng::Error,
    },
    PasswordFileRead {
        path: PathBuf,
        source: io::Error,
    },
    Validation {
        path: PathBuf,
        message: String,
    },
}

impl fmt::Display for ConfigError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AlreadyInitialized => write!(formatter, "configuration is already initialized"),
            Self::Read { path, source } => {
                write!(
                    formatter,
                    "failed to read configuration {}: {source}",
                    path.display()
                )
            }
            Self::Parse { path, source } => {
                write!(
                    formatter,
                    "failed to parse configuration {}: {source}",
                    path.display()
                )
            }
            Self::CryptoFileRead { path, source } => {
                write!(
                    formatter,
                    "failed to read crypto key file {}: {source}",
                    path.display()
                )
            }
            Self::CryptoFileParse { path, source } => {
                write!(
                    formatter,
                    "failed to parse crypto key file {}: {source}",
                    path.display()
                )
            }
            Self::PasswordFileRead { path, source } => {
                write!(
                    formatter,
                    "failed to read resource owner password file {}: {source}",
                    path.display()
                )
            }
            Self::Validation { path, message } => {
                write!(
                    formatter,
                    "invalid configuration {}: {message}",
                    path.display()
                )
            }
        }
    }
}

impl Error for ConfigError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::AlreadyInitialized => None,
            Self::Read { source, .. } => Some(source),
            Self::Parse { source, .. } => Some(source),
            Self::CryptoFileRead { source, .. } => Some(source),
            Self::CryptoFileParse { source, .. } => Some(source),
            Self::PasswordFileRead { source, .. } => Some(source),
            Self::Validation { .. } => None,
        }
    }
}
