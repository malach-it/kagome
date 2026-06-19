use std::{
    fs, io,
    path::{Path, PathBuf},
    process::Command,
    time::{SystemTime, UNIX_EPOCH},
};

use crate::{ca, errors::OAuthError};

pub const SSH_KEYS_TTL_SECONDS: u64 = 3600;

#[derive(Debug)]
pub struct SshKeys {
    pub private_key: String,
    pub public_key: String,
    pub certificate: String,
    pub expires_in: u64,
}

pub trait Generate {
    fn client_id(&self) -> Option<&str>;
    fn username(&self) -> Option<&str>;
    fn add_ssh_keys(&mut self, ssh_keys: SshKeys);
}

pub fn generate<T: Generate>(mut request: T) -> Result<T, OAuthError> {
    let client_id = request
        .client_id()
        .ok_or_else(OAuthError::missing_client_id)?;
    let username = request
        .username()
        .ok_or_else(OAuthError::missing_username)?;
    let ca_key_path = ca::ca_key_path_from_environment();

    let ssh_keys = generate_with_keygen("ssh-keygen", &ca_key_path, client_id, username)
        .map_err(|_| OAuthError::invalid_token_response("ssh key generation failed"))?;

    request.add_ssh_keys(ssh_keys);

    Ok(request)
}

pub fn generate_with_keygen(
    keygen: impl AsRef<Path>,
    ca_key_path: impl AsRef<Path>,
    client_id: &str,
    username: &str,
) -> io::Result<SshKeys> {
    let keygen = keygen.as_ref();
    let ca_key_path = ca_key_path.as_ref();

    ca::ensure_ca_key_with_keygen(ca_key_path, keygen)?;

    let key_path = temporary_key_path();
    let public_key_path = public_key_path(&key_path);
    let certificate_path = certificate_path(&key_path);

    let generation_result = generate_and_sign_keys(
        keygen,
        ca_key_path,
        &key_path,
        &public_key_path,
        client_id,
        username,
    )
    .and_then(|_| {
        Ok(SshKeys {
            private_key: fs::read_to_string(&key_path)?,
            public_key: fs::read_to_string(&public_key_path)?,
            certificate: fs::read_to_string(&certificate_path)?,
            expires_in: SSH_KEYS_TTL_SECONDS,
        })
    });

    let _ = fs::remove_file(&key_path);
    let _ = fs::remove_file(&public_key_path);
    let _ = fs::remove_file(&certificate_path);

    generation_result
}

fn generate_and_sign_keys(
    keygen: &Path,
    ca_key_path: &Path,
    key_path: &Path,
    public_key_path: &Path,
    client_id: &str,
    username: &str,
) -> io::Result<()> {
    let key_identity = key_identity(client_id, username);

    run_keygen(
        Command::new(keygen)
            .args(["-t", "ed25519", "-N", "", "-C"])
            .arg(&key_identity)
            .arg("-f")
            .arg(key_path),
    )?;

    run_keygen(
        Command::new(keygen)
            .arg("-s")
            .arg(ca_key_path)
            .arg("-I")
            .arg(key_identity)
            .arg("-n")
            .arg(username)
            .arg("-V")
            .arg(format!("+{SSH_KEYS_TTL_SECONDS}s"))
            .arg(public_key_path),
    )
}

fn key_identity(client_id: &str, username: &str) -> String {
    let username_prefix = format!("{username}@");

    if client_id.starts_with(&username_prefix) {
        client_id.to_owned()
    } else {
        format!("{username}@{client_id}")
    }
}

fn run_keygen(command: &mut Command) -> io::Result<()> {
    let output = command.output()?;

    if output.status.success() {
        return Ok(());
    }

    Err(io::Error::other(format!(
        "ssh-keygen failed with status {}: {}",
        output.status,
        String::from_utf8_lossy(&output.stderr).trim()
    )))
}

fn temporary_key_path() -> PathBuf {
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or_default();

    std::env::temp_dir().join(format!("kagome-ssh-key-{}-{unique}", std::process::id()))
}

fn public_key_path(key_path: &Path) -> PathBuf {
    let mut public_key_path = key_path.as_os_str().to_owned();
    public_key_path.push(".pub");

    PathBuf::from(public_key_path)
}

fn certificate_path(key_path: &Path) -> PathBuf {
    let mut certificate_path = key_path.as_os_str().to_owned();
    certificate_path.push("-cert.pub");

    PathBuf::from(certificate_path)
}
