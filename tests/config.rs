use std::{
    fs,
    path::{Path, PathBuf},
    process::Command,
    sync::atomic::{AtomicU64, Ordering},
};

use kagome::config::{CONFIG_PATH_ENV_VAR, Config, ConfigError};
use kagome::resources::{grant_type::GrantType, response_type::ResponseType};

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
    assert_eq!(
        config.crypto.key_file.file_name().unwrap(),
        file.crypto_file_name()
    );
    assert_eq!(config.tokens.access_token_ttl, 3600);
    assert_eq!(config.tokens.authorization_code_ttl, 600);
    assert_eq!(config.tokens.id_token_ttl, 3600);
    assert_eq!(config.tokens.authorization_code_chain_max_depth, 8);
    assert_eq!(config.clients[0].client_id, "client_id");
    assert_eq!(config.clients[0].public, None);
    assert_eq!(config.clients[0].client_secret, "client_secret");
    assert_eq!(config.clients[0].password_file, None);
    assert!(config.clients[0].supported_grant_types.is_empty());
    assert!(config.clients[0].supported_response_types.is_empty());
    assert_eq!(
        config.clients[0].redirect_uris,
        ["https://client.example.com/callback"]
    );
    assert_eq!(config.clients[0].federated_server, None);
    assert!(!config.clients[0].require_wallet_binding);
    assert!(!config.clients[0].qr_code);
}

#[test]
fn example_configuration_matches_server_defaults() {
    let file = example_configuration_file();

    let config = Config::load_from_path(file.path()).expect("example configuration should load");

    assert_eq!(config.server.address, "0.0.0.0:4000");
    assert_eq!(config.server.issuer, "http://localhost:4000");
    assert_eq!(config.server.workers, 4);
    assert_eq!(config.tokens.access_token_ttl, 3600);
    assert_eq!(config.tokens.authorization_code_ttl, 600);
    assert_eq!(config.tokens.id_token_ttl, 3600);
    assert_eq!(config.tokens.authorization_code_chain_max_depth, 8);
    assert_eq!(config.clients.len(), 1);
    assert_eq!(config.clients[0].supported_grant_types, GrantType::ALL);
    assert_eq!(
        config.clients[0].supported_response_types,
        ResponseType::ALL
    );
    assert_eq!(config.clients[0].public.as_deref(), Some("localhost:4000"));
    assert!(
        config.clients[0]
            .password_file
            .as_ref()
            .is_some_and(|path| path.ends_with("kagome.htpasswd.example"))
    );
    let (_, usernames) = config
        .client_password_file("client_id")
        .expect("example client should load its password file");
    assert_eq!(usernames, ["username", "other_username"]);
    assert!(!config.clients[0].require_wallet_binding);
    assert!(!config.clients[0].qr_code);
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
    assert_eq!(federated_server.endpoints[0].claims.len(), 1);
    assert_eq!(federated_server.endpoints[0].claims[0].claim, "sub");
    assert_eq!(federated_server.endpoints[0].claims[0].target, "sub");
}

#[test]
fn initializes_global_configuration_only_once() {
    let file = example_configuration_file();
    let config = Config::load_from_path(file.path()).expect("example configuration should load");

    let initialized = Config::set_global(config).expect("global configuration should initialize");

    assert!(std::ptr::eq(initialized, Config::global()));
    assert_eq!(initialized.clients[0].client_id, "client_id");

    let second =
        Config::load_from_path(file.path()).expect("example configuration should load again");
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
    let identity_claim = &schema["$defs"]["FederatedIdentityClaimConfig"];
    let identity_endpoint = &schema["$defs"]["FederatedIdentityEndpointConfig"];
    let grant_type = &schema["$defs"]["GrantType"];
    let response_type = &schema["$defs"]["ResponseType"];
    let token_ttls = &schema["$defs"]["TokenTtlsConfig"];
    let crypto = &schema["$defs"]["CryptoConfig"];

    assert_eq!(
        schema["$schema"],
        "https://json-schema.org/draft/2020-12/schema"
    );
    assert_eq!(schema["additionalProperties"], false);
    assert_eq!(schema["properties"]["clients"]["minItems"], 1);
    assert_eq!(crypto["additionalProperties"], false);
    assert_eq!(crypto["required"], serde_json::json!(["key_file"]));
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
        token_ttls["properties"]["authorization_code_chain_max_depth"]["minimum"],
        1
    );
    assert_eq!(
        token_ttls["properties"]["authorization_code_chain_max_depth"]["maximum"],
        32
    );
    assert_eq!(
        server["required"],
        serde_json::json!(["address", "issuer", "workers"])
    );
    assert_eq!(client["additionalProperties"], false);
    assert_eq!(client["properties"]["client_id"]["minLength"], 1);
    assert_eq!(client["properties"]["public"]["minLength"], 1);
    assert_eq!(
        client["properties"]["public"]["type"],
        serde_json::json!(["string", "null"])
    );
    assert_eq!(client["properties"]["client_secret"]["minLength"], 1);
    assert_eq!(
        client["properties"]["password_file"]["type"],
        serde_json::json!(["string", "null"])
    );
    assert_eq!(client["properties"]["redirect_uris"]["minItems"], 1);
    assert_eq!(
        grant_type["enum"],
        serde_json::json!([
            "authorization_code",
            "client_credentials",
            "code_chain",
            "implicit",
            "urn:ietf:params:oauth:grant-type:pre-authorized_code",
            "password"
        ])
    );
    assert_eq!(
        response_type["enum"],
        serde_json::json!([
            "code",
            "id_token",
            "urn:ietf:params:oauth:response-type:pre-authorized_code",
            "token",
            "vp_token"
        ])
    );
    assert!(client["properties"]["federated_server"]["anyOf"].is_array());
    assert_eq!(
        client["properties"]["require_wallet_binding"]["default"],
        false
    );
    assert_eq!(client["properties"]["qr_code"]["default"], false);
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
    assert_eq!(identity_claim["additionalProperties"], false);
    assert_eq!(identity_endpoint["additionalProperties"], false);
    assert_eq!(identity_endpoint["properties"]["claims"]["minItems"], 1);
    assert_eq!(identity_endpoint["properties"]["endpoint"]["minLength"], 1);
    assert_eq!(identity_endpoint["properties"]["endpoint"]["format"], "uri");
    assert_eq!(identity_claim["properties"]["claim"]["minLength"], 1);
    assert_eq!(identity_claim["properties"]["target"]["minLength"], 1);
    assert_eq!(
        identity_claim["required"],
        serde_json::json!(["claim", "target"])
    );
    assert_eq!(
        identity_endpoint["required"],
        serde_json::json!(["endpoint", "claims"])
    );
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
fn loads_per_client_qr_code_policy() {
    let file = ConfigFile::new(
        "server:\n  issuer: https://kagome.example.com\n  address: 127.0.0.1:4100\n  workers: 4\nclients:\n  - client_id: client_id\n    client_secret: client_secret\n    redirect_uris: [https://client.example.com/callback]\n    qr_code: true\n",
    );

    let config = Config::load_from_path(file.path()).expect("QR-code policy should load");

    assert!(config.clients[0].qr_code);
}

#[test]
fn loads_per_client_supported_grant_and_response_types() {
    let file = ConfigFile::new(
        "server:\n  issuer: https://kagome.example.com\n  address: 127.0.0.1:4100\n  workers: 4\nclients:\n  - client_id: client_id\n    client_secret: client_secret\n    redirect_uris: [https://client.example.com/callback]\n    supported_grant_types: [authorization_code, code_chain]\n    supported_response_types: [code, id_token]\n",
    );

    let config = Config::load_from_path(file.path()).expect("client capabilities should load");

    assert_eq!(
        config.clients[0].supported_grant_types,
        [GrantType::AuthorizationCode, GrantType::CodeChain]
    );
    assert_eq!(
        config.clients[0].supported_response_types,
        [ResponseType::Code, ResponseType::IdToken]
    );
}

#[test]
fn rejects_duplicate_client_capabilities() {
    for (field, values) in [
        (
            "supported_grant_types",
            "[authorization_code, authorization_code]",
        ),
        ("supported_response_types", "[code, code]"),
    ] {
        let file = ConfigFile::new(&format!(
            "server:\n  issuer: https://kagome.example.com\n  address: 127.0.0.1:4100\n  workers: 4\nclients:\n  - client_id: client_id\n    client_secret: client_secret\n    redirect_uris: [https://client.example.com/callback]\n    {field}: {values}\n"
        ));

        let error = Config::load_from_path(file.path())
            .expect_err("duplicate client capabilities should fail");

        assert!(matches!(error, ConfigError::Validation { .. }));
        assert!(error.to_string().contains(&format!("clients[0].{field}")));
    }
}

#[test]
fn rejects_unknown_client_capabilities() {
    for (field, value) in [
        ("supported_grant_types", "unknown_grant"),
        ("supported_response_types", "unknown_response"),
    ] {
        let file = ConfigFile::new(&format!(
            "server:\n  issuer: https://kagome.example.com\n  address: 127.0.0.1:4100\n  workers: 4\nclients:\n  - client_id: client_id\n    client_secret: client_secret\n    redirect_uris: [https://client.example.com/callback]\n    {field}: [{value}]\n"
        ));

        let error =
            Config::load_from_path(file.path()).expect_err("unknown client capability should fail");

        assert!(matches!(error, ConfigError::Parse { .. }));
    }
}

#[test]
fn loads_public_client_host() {
    let file = ConfigFile::new(
        "server:\n  issuer: https://kagome.example.com\n  address: 127.0.0.1:4100\n  workers: 4\nclients:\n  - client_id: client_id\n    public: wallet.example.com\n    client_secret: client_secret\n    redirect_uris: [https://wallet.example.com/callback]\n",
    );

    let config = Config::load_from_path(file.path()).expect("public client host should load");

    assert_eq!(
        config.clients[0].public.as_deref(),
        Some("wallet.example.com")
    );
    assert_eq!(
        config
            .client("username@WALLET.EXAMPLE.COM")
            .map(|client| client.client_id.as_str()),
        Some("client_id")
    );
}

#[test]
fn loads_client_password_file_relative_to_configuration() {
    let password_file = PasswordFile::new(
        "# generated fixture\nusername:$2y$05$4MDXTHOjtx8aCJ0k.Y/5leTGaeV.ffFF8jCeeA69BeQ.BvcTZZy06:fixture comment\n",
    );
    let file = ConfigFile::new(&format!(
        "server:\n  issuer: https://kagome.example.com\n  address: 127.0.0.1:4100\n  workers: 4\nclients:\n  - client_id: client_id\n    client_secret: client_secret\n    password_file: {}\n    redirect_uris: [https://client.example.com/callback]\n",
        password_file.file_name()
    ));

    let config = Config::load_from_path(file.path()).expect("client password file should load");
    let (contents, usernames) = config
        .client_password_file("client_id")
        .expect("client password file should be available");

    assert!(contents.starts_with("username:$2y$"));
    assert!(!contents.contains("fixture comment"));
    assert_eq!(usernames, ["username"]);
}

#[test]
fn rejects_missing_client_password_file() {
    let missing = unique_password_path();
    let file = ConfigFile::new(&format!(
        "server:\n  issuer: https://kagome.example.com\n  address: 127.0.0.1:4100\n  workers: 4\nclients:\n  - client_id: client_id\n    client_secret: client_secret\n    password_file: {}\n    redirect_uris: [https://client.example.com/callback]\n",
        missing.display()
    ));

    let error = Config::load_from_path(file.path()).expect_err("missing password file should fail");

    assert!(matches!(error, ConfigError::PasswordFileRead { .. }));
    assert!(error.to_string().contains(&missing.display().to_string()));
}

#[test]
fn rejects_invalid_client_password_files() {
    for contents in [
        "",
        "missing-separator\n",
        ":password\n",
        "username:\n",
        "username:unsupported-hash\n",
    ] {
        let password_file = PasswordFile::new(contents);
        let file = ConfigFile::new(&format!(
            "server:\n  issuer: https://kagome.example.com\n  address: 127.0.0.1:4100\n  workers: 4\nclients:\n  - client_id: client_id\n    client_secret: client_secret\n    password_file: {}\n    redirect_uris: [https://client.example.com/callback]\n",
            password_file.file_name()
        ));

        let error = Config::load_from_path(file.path())
            .expect_err("invalid password file should fail at startup");

        assert!(matches!(error, ConfigError::Validation { .. }));
    }
}

#[test]
fn rejects_duplicate_client_password_file_usernames() {
    let password_file = PasswordFile::new(concat!(
        "username:$2y$05$4MDXTHOjtx8aCJ0k.Y/5leTGaeV.ffFF8jCeeA69BeQ.BvcTZZy06\n",
        "username:$2y$05$ALGmNcEd4nP1.Zq2D7CtHO1cLL01Xxyj6oxDZ5jAVxd5k5dZKS5XO\n",
    ));
    let file = ConfigFile::new(&format!(
        "server:\n  issuer: https://kagome.example.com\n  address: 127.0.0.1:4100\n  workers: 4\nclients:\n  - client_id: client_id\n    client_secret: client_secret\n    password_file: {}\n    redirect_uris: [https://client.example.com/callback]\n",
        password_file.file_name()
    ));

    let error = Config::load_from_path(file.path()).expect_err("duplicate username should fail");

    assert!(matches!(error, ConfigError::Validation { .. }));
    assert!(
        error
            .to_string()
            .contains("username must be unique: username")
    );
}

#[test]
fn rejects_empty_public_client_host() {
    let file = ConfigFile::new(
        "server:\n  issuer: https://kagome.example.com\n  address: 127.0.0.1:4100\n  workers: 4\nclients:\n  - client_id: client_id\n    public: \"\"\n    client_secret: client_secret\n    redirect_uris: [https://wallet.example.com/callback]\n",
    );

    let error = Config::load_from_path(file.path()).expect_err("empty public host should fail");

    assert!(matches!(error, ConfigError::Validation { .. }));
    assert!(
        error
            .to_string()
            .contains("clients[0].public must be a valid host")
    );
}

#[test]
fn rejects_non_host_public_client_values() {
    for public in [
        "https://wallet.example.com",
        "wallet.example.com/path",
        "wallet host",
    ] {
        let file = ConfigFile::new(&format!(
            "server:\n  issuer: https://kagome.example.com\n  address: 127.0.0.1:4100\n  workers: 4\nclients:\n  - client_id: client_id\n    public: \"{public}\"\n    client_secret: client_secret\n    redirect_uris: [https://wallet.example.com/callback]\n"
        ));

        let error =
            Config::load_from_path(file.path()).expect_err("non-host public value should fail");

        assert!(matches!(error, ConfigError::Validation { .. }));
        assert!(
            error
                .to_string()
                .contains("clients[0].public must be a valid host")
        );
    }
}

#[test]
fn rejects_duplicate_public_client_hosts() {
    let file = ConfigFile::new(
        "server:\n  issuer: https://kagome.example.com\n  address: 127.0.0.1:4100\n  workers: 4\nclients:\n  - client_id: first\n    public: wallet.example.com\n    client_secret: first_secret\n    redirect_uris: [https://first.example.com/callback]\n  - client_id: second\n    public: WALLET.EXAMPLE.COM\n    client_secret: second_secret\n    redirect_uris: [https://second.example.com/callback]\n",
    );

    let error = Config::load_from_path(file.path()).expect_err("duplicate public host should fail");

    assert!(matches!(error, ConfigError::Validation { .. }));
    assert!(
        error
            .to_string()
            .contains("public host must be unique: WALLET.EXAMPLE.COM")
    );
}

#[test]
fn loads_token_settings_from_yaml() {
    let file = ConfigFile::new(&configuration_yaml(
        "server:\n  issuer: https://kagome.example.com\n  address: 127.0.0.1:4100\n  workers: 4\ntokens:\n  access_token_ttl: 120\n  authorization_code_ttl: 30\n  id_token_ttl: 90\n  authorization_code_chain_max_depth: 4\n",
    ));

    let config = Config::load_from_path(file.path()).expect("token TTLs should load");

    assert_eq!(config.tokens.access_token_ttl, 120);
    assert_eq!(config.tokens.authorization_code_ttl, 30);
    assert_eq!(config.tokens.id_token_ttl, 90);
    assert_eq!(config.tokens.authorization_code_chain_max_depth, 4);
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
fn rejects_authorization_code_chain_depth_outside_safe_range() {
    for depth in [0, 33] {
        let file = ConfigFile::new(&configuration_yaml(&format!(
            "server:\n  issuer: https://kagome.example.com\n  address: 127.0.0.1:4100\n  workers: 4\ntokens:\n  access_token_ttl: 120\n  authorization_code_ttl: 30\n  id_token_ttl: 90\n  authorization_code_chain_max_depth: {depth}\n"
        )));

        let error = Config::load_from_path(file.path())
            .expect_err("unsafe authorization code chain depth should fail");

        assert!(matches!(error, ConfigError::Validation { .. }));
        assert!(
            error
                .to_string()
                .contains("tokens.authorization_code_chain_max_depth must be between 1 and 32")
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
fn rejects_missing_crypto_key_file() {
    let file = ConfigFile::new(&configuration_yaml(
        "server:\n  issuer: https://kagome.example.com\n  address: 127.0.0.1:4100\n  workers: 4\n",
    ));
    fs::remove_file(&file.crypto_path).unwrap();

    let error = Config::load_from_path(file.path()).expect_err("missing keys should fail");

    assert!(matches!(error, ConfigError::CryptoFileRead { .. }));
    assert!(error.to_string().contains("failed to read crypto key file"));
}

#[test]
fn rejects_malformed_crypto_key_file() {
    let file = ConfigFile::with_crypto(
        &configuration_yaml(
            "server:\n  issuer: https://kagome.example.com\n  address: 127.0.0.1:4100\n  workers: 4\n",
        ),
        "encryption: [\n",
    );

    let error = Config::load_from_path(file.path()).expect_err("malformed keys should fail");

    assert!(matches!(error, ConfigError::CryptoFileParse { .. }));
    assert!(
        error
            .to_string()
            .contains("failed to parse crypto key file")
    );
}

#[test]
fn rejects_empty_or_reused_encryption_secrets() {
    for crypto in [
        include_str!("fixtures/kagome.crypto.yaml").replace(
            "access_token: test_access_token_secret",
            "access_token: \"\"",
        ),
        include_str!("fixtures/kagome.crypto.yaml").replace(
            "authorization_code: test_authorization_code_secret",
            "authorization_code: test_access_token_secret",
        ),
    ] {
        let file = ConfigFile::with_crypto(
            &configuration_yaml(
                "server:\n  issuer: https://kagome.example.com\n  address: 127.0.0.1:4100\n  workers: 4\n",
            ),
            &crypto,
        );

        let error = Config::load_from_path(file.path())
            .expect_err("invalid encryption secrets should fail");

        assert!(matches!(error, ConfigError::Validation { .. }));
    }
}

#[test]
fn rejects_mismatched_signing_key_pair() {
    let crypto = include_str!("fixtures/kagome.crypto.yaml").replace(
        "mbDL1A9YckRdA3AlHpbwDmEYpR9TJV3qQwKQkNbD63g",
        "JCcXzMbE0lrZdP6YlYfGBAv21p8FEUXzdOANLJlhZUY",
    );
    let file = ConfigFile::with_crypto(
        &configuration_yaml(
            "server:\n  issuer: https://kagome.example.com\n  address: 127.0.0.1:4100\n  workers: 4\n",
        ),
        &crypto,
    );

    let error = Config::load_from_path(file.path()).expect_err("mismatched keys should fail");

    assert!(matches!(error, ConfigError::Validation { .. }));
    assert!(
        error
            .to_string()
            .contains("private_key does not match public_jwk")
    );
}

#[test]
fn rejects_private_material_in_public_jwk() {
    let crypto = include_str!("fixtures/kagome.crypto.yaml").replace(
        "      x: mbDL1A9YckRdA3AlHpbwDmEYpR9TJV3qQwKQkNbD63g",
        "      x: mbDL1A9YckRdA3AlHpbwDmEYpR9TJV3qQwKQkNbD63g\n      d: private",
    );
    let file = ConfigFile::with_crypto(
        &configuration_yaml(
            "server:\n  issuer: https://kagome.example.com\n  address: 127.0.0.1:4100\n  workers: 4\n",
        ),
        &crypto,
    );

    let error = Config::load_from_path(file.path()).expect_err("private JWK should fail");

    assert!(matches!(error, ConfigError::Validation { .. }));
    assert!(
        error
            .to_string()
            .contains("public_jwk must not contain private key material")
    );
}

#[test]
fn generates_valid_crypto_file_without_overwriting_it() {
    let generated_path = std::env::temp_dir().join(format!(
        "kagome-generated-crypto-{}-{}.yaml",
        std::process::id(),
        NEXT_CONFIG_ID.fetch_add(1, Ordering::Relaxed)
    ));
    let script = Path::new(env!("CARGO_MANIFEST_DIR")).join("scripts/generate-crypto-config.sh");
    let first = Command::new(&script)
        .arg(&generated_path)
        .output()
        .expect("crypto generator should run");
    assert!(first.status.success());
    let generated = fs::read_to_string(&generated_path).expect("generated keys should be readable");
    let file = ConfigFile::with_crypto(
        &configuration_yaml(
            "server:\n  issuer: https://kagome.example.com\n  address: 127.0.0.1:4100\n  workers: 4\n",
        ),
        &generated,
    );
    Config::load_from_path(file.path()).expect("generated keys should pass startup validation");

    let second = Command::new(&script)
        .arg(&generated_path)
        .output()
        .expect("crypto generator should run again");
    assert!(!second.status.success());
    assert!(
        String::from_utf8(second.stderr)
            .unwrap()
            .contains("refusing to overwrite existing crypto configuration")
    );
    assert_eq!(fs::read_to_string(&generated_path).unwrap(), generated);

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            fs::metadata(&generated_path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }

    fs::remove_file(generated_path).unwrap();
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
            "server:\n  issuer: https://kagome.example.com\n  address: 127.0.0.1:4100\n  workers: 4\nclients:\n  - client_id: client_id\n    client_secret: client_secret\n    redirect_uris:\n      - https://client.example.com/callback\n    federated_server:\n      client_id: \"{client_id}\"\n      client_secret: \"{client_secret}\"\n      authorize_endpoint: \"{authorize_endpoint}\"\n      token_endpoint: \"{token_endpoint}\"\n      endpoints:\n        - endpoint: https://identity.example.com/userinfo\n          claims:\n            - claim: sub\n              target: username\n"
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
        "server:\n  issuer: https://kagome.example.com\n  address: 127.0.0.1:4100\n  workers: 4\nclients:\n  - client_id: client_id\n    client_secret: client_secret\n    redirect_uris:\n      - https://client.example.com/callback\n    federated_server:\n      client_id: kagome\n      client_secret: federated_client_secret\n      authorize_endpoint: https://identity.example.com/authorize\n      endpoints:\n        - endpoint: https://identity.example.com/userinfo\n          claims:\n            - claim: sub\n              target: username\n",
    );

    let error = Config::load_from_path(file.path())
        .expect_err("federated server without token_endpoint should fail");

    assert!(matches!(error, ConfigError::Parse { .. }));
    assert!(error.to_string().contains("missing field `token_endpoint`"));
}

#[test]
fn rejects_non_http_federated_server_endpoint() {
    let file = ConfigFile::new(
        "server:\n  issuer: https://kagome.example.com\n  address: 127.0.0.1:4100\n  workers: 4\nclients:\n  - client_id: client_id\n    client_secret: client_secret\n    redirect_uris:\n      - https://client.example.com/callback\n    federated_server:\n      client_id: kagome\n      client_secret: federated_client_secret\n      authorize_endpoint: javascript:alert(1)\n      token_endpoint: https://identity.example.com/token\n      endpoints:\n        - endpoint: https://identity.example.com/userinfo\n          claims:\n            - claim: sub\n              target: username\n",
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
fn loads_multiple_claims_for_one_federated_identity_endpoint() {
    let file = ConfigFile::new(&federated_configuration_yaml(
        "endpoints:\n        - endpoint: https://identity.example.com/userinfo\n          claims:\n            - claim: sub\n              target: username\n            - claim: profile.username\n              target: display_name",
    ));

    let config = Config::load_from_path(file.path())
        .expect("multiple claims for one identity endpoint should load");
    let claims = &config.clients[0]
        .federated_server
        .as_ref()
        .expect("federated server should load")
        .endpoints[0]
        .claims;

    assert_eq!(claims.len(), 2);
    assert_eq!(claims[0].claim, "sub");
    assert_eq!(claims[1].claim, "profile.username");
    assert_eq!(claims[1].target, "display_name");
}

#[test]
fn rejects_empty_federated_identity_claims() {
    let file = ConfigFile::new(&federated_configuration_yaml(
        "endpoints:\n        - endpoint: https://identity.example.com/userinfo\n          claims: []",
    ));

    let error = Config::load_from_path(file.path())
        .expect_err("empty federated identity claims should fail");

    assert!(matches!(error, ConfigError::Validation { .. }));
    assert!(
        error
            .to_string()
            .contains("clients[0].federated_server.endpoints[0].claims must not be empty")
    );
}

#[test]
fn rejects_non_http_federated_identity_endpoint() {
    let file = ConfigFile::new(&federated_configuration_yaml(
        "endpoints:\n        - endpoint: javascript:alert(1)\n          claims:\n            - claim: sub\n              target: username",
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
            "endpoints:\n        - endpoint: https://identity.example.com/userinfo\n          claims:\n            - claim: \"{claim}\"\n              target: username"
        )));

        let error = Config::load_from_path(file.path())
            .expect_err("invalid federated identity claim should fail");

        assert!(matches!(error, ConfigError::Validation { .. }));
        assert!(error.to_string().contains(
            "clients[0].federated_server.endpoints[0].claims[0].claim must be a dot-separated JSON claim path"
        ));
    }
}

#[test]
fn loads_arbitrary_federated_identity_target() {
    let file = ConfigFile::new(&federated_configuration_yaml(
        "endpoints:\n        - endpoint: https://identity.example.com/userinfo\n          claims:\n            - claim: sub\n              target: subject",
    ));

    let config =
        Config::load_from_path(file.path()).expect("arbitrary identity target should load");

    assert_eq!(
        config.clients[0]
            .federated_server
            .as_ref()
            .unwrap()
            .endpoints[0]
            .claims[0]
            .target,
        "subject"
    );
}

#[test]
fn rejects_empty_federated_identity_target() {
    let file = ConfigFile::new(&federated_configuration_yaml(
        "endpoints:\n        - endpoint: https://identity.example.com/userinfo\n          claims:\n            - claim: sub\n              target: \"\"",
    ));

    let error = Config::load_from_path(file.path())
        .expect_err("empty federated identity target should fail");

    assert!(matches!(error, ConfigError::Validation { .. }));
    assert!(
        error.to_string().contains(
            "clients[0].federated_server.endpoints[0].claims[0].target must not be empty"
        )
    );
}

struct ConfigFile {
    path: PathBuf,
    crypto_path: PathBuf,
}

impl ConfigFile {
    fn new(contents: &str) -> Self {
        Self::with_crypto(contents, include_str!("fixtures/kagome.crypto.yaml"))
    }

    fn with_crypto(contents: &str, crypto_contents: &str) -> Self {
        let path = unique_config_path();
        let crypto_path = path.with_extension("crypto.yaml");
        fs::write(&crypto_path, crypto_contents)
            .expect("temporary crypto key file should be written");
        let contents = format!(
            "crypto:\n  key_file: {}\n{contents}",
            crypto_path.file_name().unwrap().to_string_lossy()
        );
        fs::write(&path, contents).expect("temporary configuration should be written");

        Self { path, crypto_path }
    }

    fn path(&self) -> &Path {
        &self.path
    }

    fn crypto_file_name(&self) -> &std::ffi::OsStr {
        self.crypto_path.file_name().unwrap()
    }
}

impl Drop for ConfigFile {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
        let _ = fs::remove_file(&self.crypto_path);
    }
}

struct PasswordFile {
    path: PathBuf,
}

impl PasswordFile {
    fn new(contents: &str) -> Self {
        let path = unique_password_path();
        fs::write(&path, contents).expect("temporary password file should be written");
        Self { path }
    }

    fn file_name(&self) -> &str {
        self.path.file_name().unwrap().to_str().unwrap()
    }
}

impl Drop for PasswordFile {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}

fn unique_config_path() -> PathBuf {
    let id = NEXT_CONFIG_ID.fetch_add(1, Ordering::Relaxed);

    std::env::temp_dir().join(format!("kagome-config-{}-{id}.yaml", std::process::id()))
}

fn unique_password_path() -> PathBuf {
    let id = NEXT_CONFIG_ID.fetch_add(1, Ordering::Relaxed);

    std::env::temp_dir().join(format!(
        "kagome-passwords-{}-{id}.htpasswd",
        std::process::id()
    ))
}

fn example_configuration_file() -> ConfigFile {
    let password_file = Path::new(env!("CARGO_MANIFEST_DIR")).join("kagome.htpasswd.example");
    let yaml = include_str!("../kagome.example.yaml")
        .replace("crypto:\n  key_file: kagome.crypto.yaml\n", "")
        .replace(
            "password_file: kagome.htpasswd.example",
            &format!("password_file: {}", password_file.display()),
        );

    ConfigFile::new(&yaml)
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
