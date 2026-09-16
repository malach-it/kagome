use std::{
    collections::{HashMap, HashSet},
    env,
    error::Error,
    fmt, fs, io,
    path::{Path, PathBuf},
    sync::OnceLock,
};

use schemars::{JsonSchema, Schema, SchemaGenerator, generate::SchemaSettings};
use serde::Deserialize;

use crate::key_management::{KeyManagementError, KeyManager};

pub const CONFIG_PATH_ENV_VAR: &str = "KAGOME_CONFIG";
pub const DEFAULT_CONFIG_PATH: &str = "kagome.yaml";
pub const DEFAULT_ACCESS_TOKEN_TTL_SECONDS: u64 = 3600;
pub const DEFAULT_AUTHORIZATION_CODE_TTL_SECONDS: u64 = 600;
pub const DEFAULT_AUTHORIZATION_CODE_CHAIN_MAX_DEPTH: usize = 8;
pub const MAX_AUTHORIZATION_CODE_CHAIN_DEPTH: usize = 32;
pub const DEFAULT_ID_TOKEN_TTL_SECONDS: u64 = 3600;

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
            authorization_code_chain_max_depth: DEFAULT_AUTHORIZATION_CODE_CHAIN_MAX_DEPTH,
        }
    }
}

fn default_authorization_code_chain_max_depth() -> usize {
    DEFAULT_AUTHORIZATION_CODE_CHAIN_MAX_DEPTH
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
    /// Dot-separated JSON claim path read from the endpoint response.
    #[schemars(length(min = 1))]
    pub claim: String,
    /// Authorize request identity field populated from the claim.
    pub target: FederatedIdentityTarget,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, JsonSchema, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum FederatedIdentityTarget {
    Username,
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

        if self.clients.is_empty() {
            return Err(ConfigError::Validation {
                path: path.to_owned(),
                message: "clients must contain at least one client".to_owned(),
            });
        }

        for (field, ttl) in [
            ("access_token_ttl", self.tokens.access_token_ttl),
            ("authorization_code_ttl", self.tokens.authorization_code_ttl),
            ("id_token_ttl", self.tokens.id_token_ttl),
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
                    if identity_endpoint.claim.trim().is_empty()
                        || identity_endpoint
                            .claim
                            .split('.')
                            .any(|segment| segment.is_empty())
                    {
                        return Err(ConfigError::Validation {
                            path: path.to_owned(),
                            message: format!(
                                "clients[{index}].federated_server.endpoints[{endpoint_index}].claim must be a dot-separated JSON claim path"
                            ),
                        });
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
