use serde::Deserialize;

use crate::{errors::OAuthError, resources::authorization_code};

#[derive(Debug, PartialEq, Eq)]
pub enum MetadataPolicy {
    String(String),
    Username { superset_of: Vec<String> },
}

pub trait Validate {
    fn request_metadata_policy(&self) -> Option<&str> {
        None
    }

    fn request_authorization_code(&self) -> Option<&str> {
        None
    }

    fn client_id(&self) -> Option<&str> {
        None
    }

    fn add_metadata_policy(&mut self, _metadata_policy: MetadataPolicy) {}
}

pub fn validate<T: Validate>(mut request: T) -> Result<T, OAuthError> {
    let Some(metadata_policy) = request.request_metadata_policy() else {
        return Ok(request);
    };

    let metadata_policy = parse(metadata_policy)?;
    validate_policy(&metadata_policy, &request)?;

    request.add_metadata_policy(metadata_policy);
    Ok(request)
}

fn parse(metadata_policy: &str) -> Result<MetadataPolicy, OAuthError> {
    match serde_json::from_str::<RawMetadataPolicy>(metadata_policy) {
        Ok(RawMetadataPolicy::String(value)) => Ok(MetadataPolicy::String(value)),
        Ok(RawMetadataPolicy::Object { username }) => Ok(MetadataPolicy::Username {
            superset_of: username.superset_of,
        }),
        Err(_) => Err(OAuthError::invalid_metadata_policy()),
    }
}

fn validate_policy<T: Validate>(
    metadata_policy: &MetadataPolicy,
    request: &T,
) -> Result<(), OAuthError> {
    let MetadataPolicy::Username { superset_of } = metadata_policy else {
        return Ok(());
    };

    let usernames = authorization_code::chain_usernames(
        request.request_authorization_code(),
        request.client_id(),
    )?;

    if !superset_of
        .iter()
        .all(|required_username| usernames.contains(required_username))
    {
        return Err(OAuthError::invalid_metadata_policy_username());
    }

    Ok(())
}

#[derive(Deserialize)]
#[serde(untagged)]
enum RawMetadataPolicy {
    String(String),
    Object { username: RawUsernamePolicy },
}

#[derive(Deserialize)]
struct RawUsernamePolicy {
    superset_of: Vec<String>,
}
