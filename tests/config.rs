use std::{
    fs,
    path::{Path, PathBuf},
    process::Command,
    sync::atomic::{AtomicU64, Ordering},
};

use kagome::config::{CONFIG_PATH_ENV_VAR, Config, ConfigError};

static NEXT_CONFIG_ID: AtomicU64 = AtomicU64::new(0);

#[test]
fn loads_server_configuration_from_yaml() {
    let file = ConfigFile::new("server:\n  address: 127.0.0.1:4100\n  workers: 8\n");

    let config = Config::load_from_path(file.path()).expect("configuration should load");

    assert_eq!(config.server.address, "127.0.0.1:4100");
    assert_eq!(config.server.workers, 8);
}

#[test]
fn example_configuration_matches_server_defaults() {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("kagome.example.yaml");

    let config = Config::load_from_path(path).expect("example configuration should load");

    assert_eq!(config.server.address, "0.0.0.0:4000");
    assert_eq!(config.server.workers, 4);
}

#[test]
fn checked_in_json_schema_matches_configuration_types() {
    let checked_in_schema: serde_json::Value =
        serde_json::from_str(include_str!("../kagome.schema.json"))
            .expect("checked-in configuration schema should contain JSON");
    let generated_schema =
        serde_json::to_value(Config::json_schema()).expect("configuration schema should serialize");

    assert_eq!(checked_in_schema, generated_schema);
}

#[test]
fn json_schema_describes_server_constraints() {
    let schema =
        serde_json::to_value(Config::json_schema()).expect("configuration schema should serialize");
    let server = &schema["$defs"]["ServerConfig"];

    assert_eq!(
        schema["$schema"],
        "https://json-schema.org/draft/2020-12/schema"
    );
    assert_eq!(schema["additionalProperties"], false);
    assert_eq!(server["additionalProperties"], false);
    assert_eq!(server["properties"]["address"]["minLength"], 1);
    assert_eq!(server["properties"]["workers"]["minimum"], 1);
    assert_eq!(
        server["required"],
        serde_json::json!(["address", "workers"])
    );
}

#[test]
fn startup_loads_configuration_selected_by_environment() {
    let file = ConfigFile::new("server: [\n");

    let output = Command::new(env!("CARGO_BIN_EXE_kagome"))
        .env(CONFIG_PATH_ENV_VAR, file.path())
        .output()
        .expect("kagome process should start");
    let error = String::from_utf8(output.stderr).expect("startup error should be UTF-8");

    assert!(!output.status.success());
    assert!(error.contains("failed to parse configuration"));
    assert!(error.contains(&file.path().display().to_string()));
}

#[test]
fn rejects_missing_configuration_file() {
    let path = unique_config_path();

    let error = Config::load_from_path(&path).expect_err("missing configuration should fail");

    assert!(matches!(error, ConfigError::Read { .. }));
    assert!(error.to_string().contains(&path.display().to_string()));
}

#[test]
fn rejects_malformed_yaml_configuration() {
    let file = ConfigFile::new("server: [\n");

    let error = Config::load_from_path(file.path()).expect_err("malformed YAML should fail");

    assert!(matches!(error, ConfigError::Parse { .. }));
}

#[test]
fn rejects_configuration_with_missing_server_field() {
    let file = ConfigFile::new("server:\n  address: 127.0.0.1:4100\n");

    let error = Config::load_from_path(file.path()).expect_err("missing workers should fail");

    assert!(matches!(error, ConfigError::Parse { .. }));
    assert!(error.to_string().contains("missing field `workers`"));
}

#[test]
fn rejects_unknown_configuration_field() {
    let file = ConfigFile::new("server:\n  address: 127.0.0.1:4100\n  workers: 4\n  timeout: 30\n");

    let error = Config::load_from_path(file.path()).expect_err("unknown field should fail");

    assert!(matches!(error, ConfigError::Parse { .. }));
    assert!(error.to_string().contains("unknown field `timeout`"));
}

#[test]
fn rejects_empty_server_address() {
    let file = ConfigFile::new("server:\n  address: \"\"\n  workers: 4\n");

    let error = Config::load_from_path(file.path()).expect_err("empty address should fail");

    assert!(matches!(error, ConfigError::Validation { .. }));
    assert!(
        error
            .to_string()
            .contains("server.address must not be empty")
    );
}

#[test]
fn rejects_zero_server_workers() {
    let file = ConfigFile::new("server:\n  address: 127.0.0.1:4100\n  workers: 0\n");

    let error = Config::load_from_path(file.path()).expect_err("zero workers should fail");

    assert!(matches!(error, ConfigError::Validation { .. }));
    assert!(
        error
            .to_string()
            .contains("server.workers must be greater than zero")
    );
}

struct ConfigFile {
    path: PathBuf,
}

impl ConfigFile {
    fn new(contents: &str) -> Self {
        let path = unique_config_path();
        fs::write(&path, contents).expect("temporary configuration should be written");

        Self { path }
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for ConfigFile {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}

fn unique_config_path() -> PathBuf {
    let id = NEXT_CONFIG_ID.fetch_add(1, Ordering::Relaxed);

    std::env::temp_dir().join(format!("kagome-config-{}-{id}.yaml", std::process::id()))
}
