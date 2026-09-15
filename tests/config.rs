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
    let file = ConfigFile::new(&configuration_yaml(
        "server:\n  issuer: https://kagome.example.com\n  address: 127.0.0.1:4100\n  workers: 8\n",
    ));

    let config = Config::load_from_path(file.path()).expect("configuration should load");

    assert_eq!(config.server.address, "127.0.0.1:4100");
    assert_eq!(config.server.issuer, "https://kagome.example.com");
    assert_eq!(config.server.workers, 8);
    assert_eq!(config.tokens.access_token_ttl, 3600);
    assert_eq!(config.tokens.authorization_code_ttl, 600);
    assert_eq!(config.tokens.id_token_ttl, 3600);
    assert_eq!(config.clients[0].client_id, "client_id");
    assert_eq!(config.clients[0].client_secret, "client_secret");
    assert_eq!(
        config.clients[0].redirect_uris,
        ["https://client.example.com/callback"]
    );
    assert_eq!(config.clients[0].federated_server, None);
    assert!(!config.clients[0].require_wallet_binding);
}

#[test]
fn example_configuration_matches_server_defaults() {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("kagome.example.yaml");

    let config = Config::load_from_path(path).expect("example configuration should load");

    assert_eq!(config.server.address, "0.0.0.0:4000");
    assert_eq!(config.server.issuer, "http://localhost:4000");
    assert_eq!(config.server.workers, 4);
    assert_eq!(config.tokens.access_token_ttl, 3600);
    assert_eq!(config.tokens.authorization_code_ttl, 600);
    assert_eq!(config.tokens.id_token_ttl, 3600);
    assert_eq!(config.clients.len(), 1);
    assert!(!config.clients[0].require_wallet_binding);
    let federated_server = config.clients[0]
        .federated_server
        .as_ref()
        .expect("example configuration should enable federation");
    assert_eq!(federated_server.client_id, "kagome");
    assert_eq!(federated_server.client_secret, "federated_client_secret");
    assert_eq!(
        federated_server.authorize_endpoint,
        "https://identity.example.com/authorize"
    );
    assert_eq!(
        federated_server.token_endpoint,
        "https://identity.example.com/token"
    );
    assert_eq!(federated_server.endpoints.len(), 1);
    assert_eq!(
        federated_server.endpoints[0].endpoint,
        "https://identity.example.com/userinfo"
    );
    assert_eq!(federated_server.endpoints[0].claim, "sub");
    assert_eq!(
        federated_server.endpoints[0].target,
        kagome::config::FederatedIdentityTarget::Username
    );
}

#[test]
fn initializes_global_configuration_only_once() {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("kagome.example.yaml");
    let config = Config::load_from_path(&path).expect("example configuration should load");

    let initialized = Config::set_global(config).expect("global configuration should initialize");

    assert!(std::ptr::eq(initialized, Config::global()));
    assert_eq!(initialized.clients[0].client_id, "client_id");

    let second = Config::load_from_path(path).expect("example configuration should load again");
    let error = Config::set_global(second).expect_err("second initialization should fail");

    assert!(matches!(error, ConfigError::AlreadyInitialized));
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
fn json_schema_describes_configuration_constraints() {
    let schema =
        serde_json::to_value(Config::json_schema()).expect("configuration schema should serialize");
    let server = &schema["$defs"]["ServerConfig"];
    let client = &schema["$defs"]["ClientConfig"];
    let federated_server = &schema["$defs"]["FederatedServerConfig"];
    let identity_endpoint = &schema["$defs"]["FederatedIdentityEndpointConfig"];
    let identity_target = &schema["$defs"]["FederatedIdentityTarget"];
    let token_ttls = &schema["$defs"]["TokenTtlsConfig"];

    assert_eq!(
        schema["$schema"],
        "https://json-schema.org/draft/2020-12/schema"
    );
    assert_eq!(schema["additionalProperties"], false);
    assert_eq!(schema["properties"]["clients"]["minItems"], 1);
    assert_eq!(server["additionalProperties"], false);
    assert_eq!(server["properties"]["address"]["minLength"], 1);
    assert_eq!(server["properties"]["issuer"]["minLength"], 1);
    assert_eq!(server["properties"]["issuer"]["format"], "uri");
    assert_eq!(server["properties"]["workers"]["minimum"], 1);
    assert_eq!(token_ttls["additionalProperties"], false);
    assert_eq!(token_ttls["properties"]["access_token_ttl"]["minimum"], 1);
    assert_eq!(
        token_ttls["properties"]["authorization_code_ttl"]["minimum"],
        1
    );
    assert_eq!(token_ttls["properties"]["id_token_ttl"]["minimum"], 1);
    assert_eq!(
        server["required"],
        serde_json::json!(["address", "issuer", "workers"])
    );
    assert_eq!(client["additionalProperties"], false);
    assert_eq!(client["properties"]["client_id"]["minLength"], 1);
    assert_eq!(client["properties"]["client_secret"]["minLength"], 1);
    assert_eq!(client["properties"]["redirect_uris"]["minItems"], 1);
    assert!(client["properties"]["federated_server"]["anyOf"].is_array());
    assert_eq!(
        client["properties"]["require_wallet_binding"]["default"],
        false
    );
    assert_eq!(
        client["properties"]["redirect_uris"]["items"]["minLength"],
        1
    );
    assert_eq!(
        client["required"],
        serde_json::json!(["client_id", "client_secret", "redirect_uris"])
    );
    assert_eq!(federated_server["additionalProperties"], false);
    assert_eq!(federated_server["properties"]["client_id"]["minLength"], 1);
    assert_eq!(
        federated_server["properties"]["client_secret"]["minLength"],
        1
    );
    assert_eq!(
        federated_server["properties"]["authorize_endpoint"]["minLength"],
        1
    );
    assert_eq!(
        federated_server["properties"]["authorize_endpoint"]["format"],
        "uri"
    );
    assert_eq!(
        federated_server["properties"]["token_endpoint"]["minLength"],
        1
    );
    assert_eq!(
        federated_server["properties"]["token_endpoint"]["format"],
        "uri"
    );
    assert_eq!(federated_server["properties"]["endpoints"]["minItems"], 1);
    assert_eq!(identity_endpoint["additionalProperties"], false);
    assert_eq!(identity_endpoint["properties"]["endpoint"]["minLength"], 1);
    assert_eq!(identity_endpoint["properties"]["endpoint"]["format"], "uri");
    assert_eq!(identity_endpoint["properties"]["claim"]["minLength"], 1);
    assert_eq!(identity_target["enum"], serde_json::json!(["username"]));
    assert_eq!(
        federated_server["required"],
        serde_json::json!([
            "client_id",
            "client_secret",
            "authorize_endpoint",
            "token_endpoint",
            "endpoints"
        ])
    );
}

#[test]
fn loads_per_client_wallet_binding_policy() {
    let file = ConfigFile::new(
        "server:\n  issuer: https://kagome.example.com\n  address: 127.0.0.1:4100\n  workers: 4\nclients:\n  - client_id: client_id\n    client_secret: client_secret\n    redirect_uris: [https://client.example.com/callback]\n    require_wallet_binding: true\n",
    );

    let config = Config::load_from_path(file.path()).expect("wallet binding should load");

    assert!(config.clients[0].require_wallet_binding);
}

#[test]
fn loads_token_ttls_from_yaml() {
    let file = ConfigFile::new(&configuration_yaml(
        "server:\n  issuer: https://kagome.example.com\n  address: 127.0.0.1:4100\n  workers: 4\ntokens:\n  access_token_ttl: 120\n  authorization_code_ttl: 30\n  id_token_ttl: 90\n",
    ));

    let config = Config::load_from_path(file.path()).expect("token TTLs should load");

    assert_eq!(config.tokens.access_token_ttl, 120);
    assert_eq!(config.tokens.authorization_code_ttl, 30);
    assert_eq!(config.tokens.id_token_ttl, 90);
}

#[test]
fn rejects_zero_token_ttls() {
    for field in ["access_token_ttl", "authorization_code_ttl", "id_token_ttl"] {
        let access_token_ttl = if field == "access_token_ttl" { 0 } else { 120 };
        let authorization_code_ttl = if field == "authorization_code_ttl" {
            0
        } else {
            30
        };
        let id_token_ttl = if field == "id_token_ttl" { 0 } else { 90 };
        let file = ConfigFile::new(&configuration_yaml(&format!(
            "server:\n  issuer: https://kagome.example.com\n  address: 127.0.0.1:4100\n  workers: 4\ntokens:\n  access_token_ttl: {access_token_ttl}\n  authorization_code_ttl: {authorization_code_ttl}\n  id_token_ttl: {id_token_ttl}\n"
        )));

        let error = Config::load_from_path(file.path()).expect_err("zero TTL should fail");

        assert!(matches!(error, ConfigError::Validation { .. }));
        assert!(
            error
                .to_string()
                .contains(&format!("tokens.{field} must be greater than zero"))
        );
    }
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
    let file = ConfigFile::new(&configuration_yaml(
        "server:\n  issuer: https://kagome.example.com\n  address: 127.0.0.1:4100\n",
    ));

    let error = Config::load_from_path(file.path()).expect_err("missing workers should fail");

    assert!(matches!(error, ConfigError::Parse { .. }));
    assert!(error.to_string().contains("missing field `workers`"));
}

#[test]
fn rejects_configuration_with_missing_server_issuer() {
    let file = ConfigFile::new(&configuration_yaml(
        "server:\n  address: 127.0.0.1:4100\n  workers: 4\n",
    ));

    let error = Config::load_from_path(file.path()).expect_err("missing issuer should fail");

    assert!(matches!(error, ConfigError::Parse { .. }));
    assert!(error.to_string().contains("missing field `issuer`"));
}

#[test]
fn rejects_unknown_configuration_field() {
    let file = ConfigFile::new(&configuration_yaml(
        "server:\n  issuer: https://kagome.example.com\n  address: 127.0.0.1:4100\n  workers: 4\n  timeout: 30\n",
    ));

    let error = Config::load_from_path(file.path()).expect_err("unknown field should fail");

    assert!(matches!(error, ConfigError::Parse { .. }));
    assert!(error.to_string().contains("unknown field `timeout`"));
}

#[test]
fn rejects_empty_server_address() {
    let file = ConfigFile::new(&configuration_yaml(
        "server:\n  issuer: https://kagome.example.com\n  address: \"\"\n  workers: 4\n",
    ));

    let error = Config::load_from_path(file.path()).expect_err("empty address should fail");

    assert!(matches!(error, ConfigError::Validation { .. }));
    assert!(
        error
            .to_string()
            .contains("server.address must not be empty")
    );
}

#[test]
fn rejects_empty_server_issuer() {
    let file = ConfigFile::new(&configuration_yaml(
        "server:\n  issuer: \"\"\n  address: 127.0.0.1:4100\n  workers: 4\n",
    ));

    let error = Config::load_from_path(file.path()).expect_err("empty issuer should fail");

    assert!(matches!(error, ConfigError::Validation { .. }));
    assert!(
        error
            .to_string()
            .contains("server.issuer must be an absolute HTTP or HTTPS URL")
    );
}

#[test]
fn rejects_non_http_server_issuer() {
    let file = ConfigFile::new(&configuration_yaml(
        "server:\n  issuer: javascript:alert(1)\n  address: 127.0.0.1:4100\n  workers: 4\n",
    ));

    let error = Config::load_from_path(file.path()).expect_err("non-HTTP issuer should fail");

    assert!(matches!(error, ConfigError::Validation { .. }));
    assert!(
        error
            .to_string()
            .contains("server.issuer must be an absolute HTTP or HTTPS URL")
    );
}

#[test]
fn rejects_zero_server_workers() {
    let file = ConfigFile::new(&configuration_yaml(
        "server:\n  issuer: https://kagome.example.com\n  address: 127.0.0.1:4100\n  workers: 0\n",
    ));

    let error = Config::load_from_path(file.path()).expect_err("zero workers should fail");

    assert!(matches!(error, ConfigError::Validation { .. }));
    assert!(
        error
            .to_string()
            .contains("server.workers must be greater than zero")
    );
}

#[test]
fn rejects_empty_client_list() {
    let file = ConfigFile::new(
        "server:\n  issuer: https://kagome.example.com\n  address: 127.0.0.1:4100\n  workers: 4\nclients: []\n",
    );

    let error = Config::load_from_path(file.path()).expect_err("empty clients should fail");

    assert!(matches!(error, ConfigError::Validation { .. }));
    assert!(
        error
            .to_string()
            .contains("clients must contain at least one client")
    );
}

#[test]
fn rejects_duplicate_client_id() {
    let file = ConfigFile::new(
        "server:\n  issuer: https://kagome.example.com\n  address: 127.0.0.1:4100\n  workers: 4\nclients:\n  - client_id: duplicate\n    client_secret: first\n    redirect_uris: [https://first.example.com/callback]\n  - client_id: duplicate\n    client_secret: second\n    redirect_uris: [https://second.example.com/callback]\n",
    );

    let error = Config::load_from_path(file.path()).expect_err("duplicate client_id should fail");

    assert!(matches!(error, ConfigError::Validation { .. }));
    assert!(
        error
            .to_string()
            .contains("client_id must be unique: duplicate")
    );
}

#[test]
fn rejects_empty_client_id() {
    let file = ConfigFile::new(
        "server:\n  issuer: https://kagome.example.com\n  address: 127.0.0.1:4100\n  workers: 4\nclients:\n  - client_id: \"\"\n    client_secret: client_secret\n    redirect_uris: [https://client.example.com/callback]\n",
    );

    let error = Config::load_from_path(file.path()).expect_err("empty client_id should fail");

    assert!(matches!(error, ConfigError::Validation { .. }));
    assert!(
        error
            .to_string()
            .contains("clients[0].client_id must not be empty")
    );
}

#[test]
fn rejects_empty_client_secret() {
    let file = ConfigFile::new(
        "server:\n  issuer: https://kagome.example.com\n  address: 127.0.0.1:4100\n  workers: 4\nclients:\n  - client_id: client_id\n    client_secret: \"\"\n    redirect_uris: [https://client.example.com/callback]\n",
    );

    let error = Config::load_from_path(file.path()).expect_err("empty client_secret should fail");

    assert!(matches!(error, ConfigError::Validation { .. }));
    assert!(
        error
            .to_string()
            .contains("clients[0].client_secret must not be empty")
    );
}

#[test]
fn rejects_empty_client_redirect_uris() {
    let file = ConfigFile::new(
        "server:\n  issuer: https://kagome.example.com\n  address: 127.0.0.1:4100\n  workers: 4\nclients:\n  - client_id: client_id\n    client_secret: client_secret\n    redirect_uris: []\n",
    );

    let error = Config::load_from_path(file.path()).expect_err("empty redirect_uris should fail");

    assert!(matches!(error, ConfigError::Validation { .. }));
    assert!(
        error
            .to_string()
            .contains("clients[0].redirect_uris must not be empty")
    );
}

#[test]
fn rejects_empty_client_redirect_uri() {
    let file = ConfigFile::new(
        "server:\n  issuer: https://kagome.example.com\n  address: 127.0.0.1:4100\n  workers: 4\nclients:\n  - client_id: client_id\n    client_secret: client_secret\n    redirect_uris: [\"\"]\n",
    );

    let error = Config::load_from_path(file.path()).expect_err("empty redirect_uri should fail");

    assert!(matches!(error, ConfigError::Validation { .. }));
    assert!(
        error
            .to_string()
            .contains("clients[0].redirect_uris must not contain empty values")
    );
}

#[test]
fn rejects_empty_federated_server_fields() {
    for field in [
        "client_id",
        "client_secret",
        "authorize_endpoint",
        "token_endpoint",
    ] {
        let client_id = if field == "client_id" { "" } else { "kagome" };
        let client_secret = if field == "client_secret" {
            ""
        } else {
            "federated_client_secret"
        };
        let authorize_endpoint = if field == "authorize_endpoint" {
            ""
        } else {
            "https://identity.example.com/authorize"
        };
        let token_endpoint = if field == "token_endpoint" {
            ""
        } else {
            "https://identity.example.com/token"
        };
        let file = ConfigFile::new(&format!(
            "server:\n  issuer: https://kagome.example.com\n  address: 127.0.0.1:4100\n  workers: 4\nclients:\n  - client_id: client_id\n    client_secret: client_secret\n    redirect_uris:\n      - https://client.example.com/callback\n    federated_server:\n      client_id: \"{client_id}\"\n      client_secret: \"{client_secret}\"\n      authorize_endpoint: \"{authorize_endpoint}\"\n      token_endpoint: \"{token_endpoint}\"\n      endpoints:\n        - endpoint: https://identity.example.com/userinfo\n          claim: sub\n          target: username\n"
        ));

        let error = Config::load_from_path(file.path())
            .expect_err("empty federated server field should fail");

        assert!(matches!(error, ConfigError::Validation { .. }));
        assert!(error.to_string().contains(&format!(
            "clients[0].federated_server.{field} must not be empty"
        )));
    }
}

#[test]
fn rejects_incomplete_federated_server_configuration() {
    let file = ConfigFile::new(
        "server:\n  issuer: https://kagome.example.com\n  address: 127.0.0.1:4100\n  workers: 4\nclients:\n  - client_id: client_id\n    client_secret: client_secret\n    redirect_uris:\n      - https://client.example.com/callback\n    federated_server:\n      client_id: kagome\n      client_secret: federated_client_secret\n      authorize_endpoint: https://identity.example.com/authorize\n      endpoints:\n        - endpoint: https://identity.example.com/userinfo\n          claim: sub\n          target: username\n",
    );

    let error = Config::load_from_path(file.path())
        .expect_err("federated server without token_endpoint should fail");

    assert!(matches!(error, ConfigError::Parse { .. }));
    assert!(error.to_string().contains("missing field `token_endpoint`"));
}

#[test]
fn rejects_non_http_federated_server_endpoint() {
    let file = ConfigFile::new(
        "server:\n  issuer: https://kagome.example.com\n  address: 127.0.0.1:4100\n  workers: 4\nclients:\n  - client_id: client_id\n    client_secret: client_secret\n    redirect_uris:\n      - https://client.example.com/callback\n    federated_server:\n      client_id: kagome\n      client_secret: federated_client_secret\n      authorize_endpoint: javascript:alert(1)\n      token_endpoint: https://identity.example.com/token\n      endpoints:\n        - endpoint: https://identity.example.com/userinfo\n          claim: sub\n          target: username\n",
    );

    let error =
        Config::load_from_path(file.path()).expect_err("non-HTTP federated endpoint should fail");

    assert!(matches!(error, ConfigError::Validation { .. }));
    assert!(error.to_string().contains(
        "clients[0].federated_server.authorize_endpoint must be an absolute HTTP or HTTPS URL"
    ));
}

#[test]
fn rejects_empty_federated_identity_endpoints() {
    let file = ConfigFile::new(&federated_configuration_yaml("endpoints: []"));

    let error = Config::load_from_path(file.path())
        .expect_err("empty federated identity endpoints should fail");

    assert!(matches!(error, ConfigError::Validation { .. }));
    assert!(
        error
            .to_string()
            .contains("clients[0].federated_server.endpoints must not be empty")
    );
}

#[test]
fn rejects_non_http_federated_identity_endpoint() {
    let file = ConfigFile::new(&federated_configuration_yaml(
        "endpoints:\n        - endpoint: javascript:alert(1)\n          claim: sub\n          target: username",
    ));

    let error = Config::load_from_path(file.path())
        .expect_err("non-HTTP federated identity endpoint should fail");

    assert!(matches!(error, ConfigError::Validation { .. }));
    assert!(error.to_string().contains(
        "clients[0].federated_server.endpoints[0].endpoint must be an absolute HTTP or HTTPS URL"
    ));
}

#[test]
fn rejects_invalid_federated_identity_claim_paths() {
    for claim in ["", ".sub", "profile.", "profile..username"] {
        let file = ConfigFile::new(&federated_configuration_yaml(&format!(
            "endpoints:\n        - endpoint: https://identity.example.com/userinfo\n          claim: \"{claim}\"\n          target: username"
        )));

        let error = Config::load_from_path(file.path())
            .expect_err("invalid federated identity claim should fail");

        assert!(matches!(error, ConfigError::Validation { .. }));
        assert!(error.to_string().contains(
            "clients[0].federated_server.endpoints[0].claim must be a dot-separated JSON claim path"
        ));
    }
}

#[test]
fn rejects_unknown_federated_identity_target() {
    let file = ConfigFile::new(&federated_configuration_yaml(
        "endpoints:\n        - endpoint: https://identity.example.com/userinfo\n          claim: sub\n          target: subject",
    ));

    let error = Config::load_from_path(file.path())
        .expect_err("unknown federated identity target should fail");

    assert!(matches!(error, ConfigError::Parse { .. }));
    assert!(error.to_string().contains("unknown variant `subject`"));
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

fn configuration_yaml(server: &str) -> String {
    format!(
        "{server}clients:\n  - client_id: client_id\n    client_secret: client_secret\n    redirect_uris:\n      - https://client.example.com/callback\n"
    )
}

fn federated_configuration_yaml(endpoints: &str) -> String {
    format!(
        "server:\n  issuer: https://kagome.example.com\n  address: 127.0.0.1:4100\n  workers: 4\nclients:\n  - client_id: client_id\n    client_secret: client_secret\n    redirect_uris:\n      - https://client.example.com/callback\n    federated_server:\n      client_id: kagome\n      client_secret: federated_client_secret\n      authorize_endpoint: https://identity.example.com/authorize\n      token_endpoint: https://identity.example.com/token\n      {endpoints}\n"
    )
}
