use std::{
    env, fs, io,
    path::{Path, PathBuf},
    process::Command,
};

pub const CA_KEY_PATH_ENV_VAR: &str = "KAGOME_CA_KEY_PATH";
pub const DEFAULT_CA_KEY_PATH: &str = "kagome_ca";
pub const SSH_CERTIFICATE_AUTHORITY_PATH: &str = "/.well-known/ssh-certificate-authority";

pub fn ca_key_path_from_environment() -> PathBuf {
    env::var(CA_KEY_PATH_ENV_VAR)
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from(DEFAULT_CA_KEY_PATH))
}

pub fn ensure_ca_key(path: impl AsRef<Path>) -> io::Result<()> {
    ensure_ca_key_with_keygen(path, "ssh-keygen")
}

pub fn public_key_path(path: impl AsRef<Path>) -> PathBuf {
    let mut public_key_path = path.as_ref().as_os_str().to_owned();
    public_key_path.push(".pub");

    PathBuf::from(public_key_path)
}

pub fn read_public_key(path: impl AsRef<Path>) -> io::Result<String> {
    fs::read_to_string(public_key_path(path))
}

pub fn ensure_ca_key_with_keygen(
    path: impl AsRef<Path>,
    keygen: impl AsRef<Path>,
) -> io::Result<()> {
    let path = path.as_ref();

    if path.exists() {
        return Ok(());
    }

    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        fs::create_dir_all(parent)?;
    }

    let output = Command::new(keygen.as_ref())
        .args(["-t", "ed25519", "-N", "", "-C", "kagome-ca", "-f"])
        .arg(path)
        .output()?;

    if output.status.success() {
        return Ok(());
    }

    Err(io::Error::other(format!(
        "ssh-keygen failed with status {}: {}",
        output.status,
        String::from_utf8_lossy(&output.stderr).trim()
    )))
}
