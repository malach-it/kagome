//! Durable inventory of public keys attested by trusted agent providers.

use std::{
    fs::{self, File, OpenOptions},
    io::{self, BufWriter, Write},
    path::Path,
};

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use ring::rand::{SecureRandom, SystemRandom};
use serde::{Deserialize, Serialize};

use super::{JwkFields, VerifiedAgentToken};

#[derive(Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Registry {
    provider_attested_keys: Vec<AgentKey>,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct AgentKey {
    issuer: String,
    subject: String,
    jwk_thumbprint: String,
    public_jwk: JwkFields,
    first_seen_at: u64,
    last_seen_at: u64,
    latest_token_expires_at: u64,
}

impl Registry {
    fn observe(&mut self, token: &VerifiedAgentToken, now: u64) {
        let existing = self.provider_attested_keys.iter_mut().find(|key| {
            key.issuer == token.issuer
                && key.subject == token.subject
                && key.jwk_thumbprint == token.key_thumbprint
        });
        if let Some(key) = existing {
            key.first_seen_at = key.first_seen_at.min(now);
            key.last_seen_at = key.last_seen_at.max(now);
            key.latest_token_expires_at = key.latest_token_expires_at.max(token.expires_at);
            return;
        }

        let key_members: &[&str] = match token.public_jwk["kty"].as_str() {
            Some("RSA") => &["e", "n"],
            Some("EC") => &["crv", "x", "y"],
            _ => &["crv", "x"],
        };
        self.provider_attested_keys.push(AgentKey {
            issuer: token.issuer.clone(),
            subject: token.subject.clone(),
            jwk_thumbprint: token.key_thumbprint.clone(),
            public_jwk: token
                .public_jwk
                .iter()
                .filter(|(name, _)| {
                    matches!(name.as_str(), "alg" | "kty") || key_members.contains(&name.as_str())
                })
                .map(|(name, value)| (name.clone(), value.clone()))
                .collect(),
            first_seen_at: now,
            last_seen_at: now,
            latest_token_expires_at: token.expires_at,
        });
    }
}

/// Records a batch of already verified provider attestations. Observations for
/// the same issuer, subject, and key update one record. Rotated keys get separate
/// records. The complete batch is published atomically under an exclusive lock.
///
/// # Errors
///
/// Returns an I/O error for a lock, file, or serialization failure. Existing
/// unreadable or malformed data is preserved.
pub(in crate::resources) fn record<'a>(
    path: &Path,
    tokens: impl IntoIterator<Item = &'a VerifiedAgentToken>,
    now: u64,
) -> io::Result<()> {
    let file_name = path
        .file_name()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "registry needs a file name"))?;
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let mut lock_name = file_name.to_owned();
    lock_name.push(".lock");
    let lock = private_file_options()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(parent.join(lock_name))?;
    lock.lock()?;

    let mut registry: Registry = match File::open(path) {
        Ok(file) => serde_json::from_reader(io::BufReader::new(file))?,
        Err(error) if error.kind() == io::ErrorKind::NotFound => Registry::default(),
        Err(error) => return Err(error),
    };
    for token in tokens {
        registry.observe(token, now);
    }

    let mut nonce = [0; 16];
    SystemRandom::new()
        .fill(&mut nonce)
        .map_err(|_| io::Error::other("registry temporary filename randomness unavailable"))?;
    let mut temp_name = file_name.to_owned();
    temp_name.push(format!(".{}.tmp", URL_SAFE_NO_PAD.encode(nonce)));
    let temp = parent.join(temp_name);
    let file = private_file_options()
        .write(true)
        .create_new(true)
        .open(&temp)?;
    let result = (|| {
        let mut writer = BufWriter::new(file);
        serde_json::to_writer_pretty(&mut writer, &registry)?;
        writer.write_all(b"\n")?;
        writer.flush()?;
        writer.get_ref().sync_all()?;
        drop(writer);
        fs::rename(&temp, path)?;
        #[cfg(unix)]
        File::open(parent)?.sync_all()?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(temp);
    }
    result
}

fn private_file_options() -> OpenOptions {
    let mut options = OpenOptions::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options
}
