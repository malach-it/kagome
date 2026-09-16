use std::{
    collections::HashMap,
    sync::{Mutex, OnceLock},
    time::{SystemTime, UNIX_EPOCH},
};

use ring::digest::{SHA256, digest};

const MAX_CONSUMED_ARTIFACTS: usize = 100_000;

static CONSUMED_ARTIFACTS: OnceLock<Mutex<HashMap<[u8; 32], u64>>> = OnceLock::new();

#[derive(Clone, Copy, Debug)]
pub enum Artifact {
    AuthorizationCode,
    FederationState,
    PresentationState,
    PreAuthorizedCode,
    Siopv2State,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConsumeError {
    AlreadyConsumed,
    CapacityExceeded,
    StorageUnavailable,
    TimeUnavailable,
}

/// Atomically marks an authenticated artifact as consumed until its expiration.
///
/// The process-local store follows the wallet-authorization relay pattern: a lazily initialized
/// mutex protects an in-memory map, and expired entries are pruned before insertion. Artifact
/// values are stored only as domain-separated SHA-256 digests. Capacity exhaustion fails closed
/// rather than evicting a live marker and permitting replay.
///
/// # Errors
///
/// Returns [`ConsumeError::AlreadyConsumed`] when the artifact was already accepted,
/// [`ConsumeError::CapacityExceeded`] when the bounded store is full, or a storage/time error when
/// the marker cannot be recorded safely.
pub fn consume(artifact: Artifact, value: &str, expires_at: u64) -> Result<(), ConsumeError> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| ConsumeError::TimeUnavailable)?
        .as_secs();
    let identifier = identifier(artifact, value);
    let mut consumed = consumed_artifacts()
        .lock()
        .map_err(|_| ConsumeError::StorageUnavailable)?;
    consumed.retain(|_, expiration| *expiration > now);

    if consumed.contains_key(&identifier) {
        return Err(ConsumeError::AlreadyConsumed);
    }
    if consumed.len() >= MAX_CONSUMED_ARTIFACTS {
        return Err(ConsumeError::CapacityExceeded);
    }
    consumed.insert(identifier, expires_at);
    Ok(())
}

fn identifier(artifact: Artifact, value: &str) -> [u8; 32] {
    let domain = match artifact {
        Artifact::AuthorizationCode => b"authorization_code".as_slice(),
        Artifact::FederationState => b"federation_state".as_slice(),
        Artifact::PresentationState => b"presentation_state".as_slice(),
        Artifact::PreAuthorizedCode => b"pre-authorized_code".as_slice(),
        Artifact::Siopv2State => b"siopv2_state".as_slice(),
    };
    let mut input = Vec::with_capacity(domain.len() + 1 + value.len());
    input.extend_from_slice(domain);
    input.push(0);
    input.extend_from_slice(value.as_bytes());

    digest(&SHA256, &input)
        .as_ref()
        .try_into()
        .expect("SHA-256 digest must contain 32 bytes")
}

fn consumed_artifacts() -> &'static Mutex<HashMap<[u8; 32], u64>> {
    CONSUMED_ARTIFACTS.get_or_init(|| Mutex::new(HashMap::new()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_an_artifact_once() {
        let value = "single-use-artifact";

        assert_eq!(
            consume(Artifact::AuthorizationCode, value, u64::MAX),
            Ok(())
        );
        assert_eq!(
            consume(Artifact::AuthorizationCode, value, u64::MAX),
            Err(ConsumeError::AlreadyConsumed)
        );
    }

    #[test]
    fn separates_artifact_domains() {
        let value = "domain-separated-artifact";

        assert_eq!(
            consume(Artifact::AuthorizationCode, value, u64::MAX),
            Ok(())
        );
        assert_eq!(consume(Artifact::FederationState, value, u64::MAX), Ok(()));
        assert_eq!(
            consume(Artifact::PresentationState, value, u64::MAX),
            Ok(())
        );
        assert_eq!(
            consume(Artifact::PreAuthorizedCode, value, u64::MAX),
            Ok(())
        );
        assert_eq!(consume(Artifact::Siopv2State, value, u64::MAX), Ok(()));
    }
}
