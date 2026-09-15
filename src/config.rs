use std::{
    env,
    error::Error,
    fmt, fs, io,
    path::{Path, PathBuf},
};

use schemars::{JsonSchema, Schema, SchemaGenerator, generate::SchemaSettings};
use serde::Deserialize;

pub const CONFIG_PATH_ENV_VAR: &str = "KAGOME_CONFIG";
pub const DEFAULT_CONFIG_PATH: &str = "kagome.yaml";

#[derive(Debug, Deserialize, Eq, JsonSchema, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// HTTP server settings.
    pub server: ServerConfig,
}

#[derive(Debug, Deserialize, Eq, JsonSchema, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ServerConfig {
    /// Socket address on which the HTTP server listens.
    #[schemars(length(min = 1))]
    pub address: String,
    /// Number of HTTP request worker threads.
    #[schemars(range(min = 1))]
    pub workers: usize,
}

impl Config {
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
        let config: Self = serde_yaml_ng::from_str(&yaml).map_err(|source| ConfigError::Parse {
            path: path.to_owned(),
            source,
        })?;

        config.validate(path)?;

        Ok(config)
    }

    fn validate(&self, path: &Path) -> Result<(), ConfigError> {
        if self.server.address.trim().is_empty() {
            return Err(ConfigError::Validation {
                path: path.to_owned(),
                message: "server.address must not be empty",
            });
        }

        if self.server.workers == 0 {
            return Err(ConfigError::Validation {
                path: path.to_owned(),
                message: "server.workers must be greater than zero",
            });
        }

        Ok(())
    }
}

#[derive(Debug)]
pub enum ConfigError {
    Read {
        path: PathBuf,
        source: io::Error,
    },
    Parse {
        path: PathBuf,
        source: serde_yaml_ng::Error,
    },
    Validation {
        path: PathBuf,
        message: &'static str,
    },
}

impl fmt::Display for ConfigError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
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
            Self::Read { source, .. } => Some(source),
            Self::Parse { source, .. } => Some(source),
            Self::Validation { .. } => None,
        }
    }
}
