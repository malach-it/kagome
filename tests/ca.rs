use std::{
    fs,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

use kagome::{
    ca::{DEFAULT_CA_KEY_PATH, SSH_CERTIFICATE_AUTHORITY_PATH, ensure_ca_key_with_keygen},
    router::route_request_with_ca_key_path,
    unit::parse_request,
};

#[test]
fn default_ca_key_path_is_kagome_ca() {
    assert_eq!(DEFAULT_CA_KEY_PATH, "kagome_ca");
}

#[test]
fn skips_existing_ca_key_file() {
    let directory = temp_directory("existing-ca");
    let ca_key_path = directory.join("ca");
    fs::write(&ca_key_path, "existing key").expect("failed to write existing key");

    ensure_ca_key_with_keygen(&ca_key_path, directory.join("missing-keygen"))
        .expect("existing ca key should not invoke ssh-keygen");

    assert_eq!(
        fs::read_to_string(&ca_key_path).expect("failed to read ca key"),
        "existing key"
    );
}

#[test]
fn generates_missing_ca_key_file_with_ssh_keygen() {
    let directory = temp_directory("missing-ca");
    let ca_key_path = directory.join("nested").join("ca");
    let keygen_path = fake_ssh_keygen(&directory);

    ensure_ca_key_with_keygen(&ca_key_path, &keygen_path).expect("failed to generate ca key");

    assert_eq!(
        fs::read_to_string(&ca_key_path).expect("failed to read generated ca key"),
        "generated private key"
    );
    assert_eq!(
        fs::read_to_string(ca_key_path.with_file_name("ca.pub"))
            .expect("failed to read generated public key"),
        "generated public key"
    );
}

#[test]
fn returns_ca_public_key_from_well_known_ssh_certificate_authority_resource() {
    let directory = temp_directory("well-known-ca");
    let ca_key_path = directory.join("ca");
    fs::write(&ca_key_path, "private key").expect("failed to write private key");
    fs::write(ca_key_path.with_file_name("ca.pub"), "public key")
        .expect("failed to write public key");

    let request = parse_request(&format!(
        "GET {SSH_CERTIFICATE_AUTHORITY_PATH} HTTP/1.1\r\nhost: example.com\r\n\r\n"
    ));
    let response = route_request_with_ca_key_path(&request, &ca_key_path);

    assert!(response.starts_with("HTTP/1.1 200 OK\r\n"));
    assert!(response.contains("content-type: text/plain\r\n"));
    assert!(response.contains("content-length: 10\r\n"));
    assert!(response.contains("connection: close\r\n"));
    assert!(response.ends_with("public key"));
}

#[test]
fn returns_not_found_when_ca_public_key_is_missing() {
    let directory = temp_directory("missing-public-ca");
    let ca_key_path = directory.join("ca");
    let request = parse_request(&format!(
        "GET {SSH_CERTIFICATE_AUTHORITY_PATH} HTTP/1.1\r\nhost: example.com\r\n\r\n"
    ));
    let response = route_request_with_ca_key_path(&request, &ca_key_path);

    assert!(response.starts_with("HTTP/1.1 404 Not Found\r\n"));
    assert!(response.ends_with("not found"));
}

fn fake_ssh_keygen(directory: &Path) -> PathBuf {
    let keygen_path = directory.join("ssh-keygen");
    fs::write(
        &keygen_path,
        r#"#!/bin/sh
while [ "$#" -gt 0 ]; do
  if [ "$1" = "-f" ]; then
    shift
    key_path="$1"
  fi
  shift
done
mkdir -p "$(dirname "$key_path")"
printf "generated private key" > "$key_path"
printf "generated public key" > "$key_path.pub"
"#,
    )
    .expect("failed to write fake ssh-keygen");

    let mut permissions = fs::metadata(&keygen_path)
        .expect("failed to read fake ssh-keygen metadata")
        .permissions();
    permissions.set_mode(0o755);
    fs::set_permissions(&keygen_path, permissions)
        .expect("failed to make fake ssh-keygen executable");

    keygen_path
}

fn temp_directory(name: &str) -> PathBuf {
    let mut directory = std::env::temp_dir();
    directory.push(format!(
        "kagome-{name}-{}",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock before unix epoch")
            .as_nanos()
    ));

    fs::create_dir_all(&directory).expect("failed to create temp directory");

    directory
}
