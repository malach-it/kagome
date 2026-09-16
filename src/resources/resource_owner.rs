use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::{
    config::Config,
    errors::{OAuthError, OAuthErrorCode},
};

pub type ResourceOwnerProfile = BTreeMap<String, String>;
pub type CredentialProfiles = BTreeMap<String, ResourceOwnerProfile>;

const DUMMY_PASSWORD_HASH: &str = "$2y$05$4MDXTHOjtx8aCJ0k.Y/5leTGaeV.ffFF8jCeeA69BeQ.BvcTZZy06";

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ResourceOwner {
    pub username: String,
    pub authenticated: bool,
    pub profile: ResourceOwnerProfile,
    pub credential_profile: CredentialProfiles,
}

#[derive(Debug, Default)]
pub struct ResourceOwnerAttributes {
    attributes: ResourceOwnerProfile,
    id_token_profile: ResourceOwnerProfile,
    credential_profile: CredentialProfiles,
}

impl ResourceOwner {
    pub fn from_username(username: String) -> Self {
        let mut profile = ResourceOwnerProfile::new();
        profile.insert("username".to_owned(), username.clone());

        Self {
            username,
            authenticated: true,
            profile,
            credential_profile: CredentialProfiles::new(),
        }
    }

    pub fn from_attributes(attributes: ResourceOwnerAttributes) -> Option<Self> {
        let username = attributes
            .attributes
            .get("username")
            .or_else(|| attributes.attributes.get("sub"))?
            .to_owned();

        Some(Self {
            username,
            authenticated: true,
            profile: attributes.id_token_profile,
            credential_profile: attributes.credential_profile,
        })
    }
}

impl ResourceOwnerAttributes {
    pub fn add(
        &mut self,
        target: &str,
        value: String,
        include_in_id_token: bool,
        credential_configuration_ids: &[String],
    ) {
        self.attributes.insert(target.to_owned(), value.clone());
        if include_in_id_token {
            self.id_token_profile
                .insert(target.to_owned(), value.clone());
        } else {
            self.id_token_profile.remove(target);
        }
        for profile in self.credential_profile.values_mut() {
            profile.remove(target);
        }
        self.credential_profile
            .retain(|_, profile| !profile.is_empty());
        for credential_configuration_id in credential_configuration_ids {
            self.credential_profile
                .entry(credential_configuration_id.clone())
                .or_default()
                .insert(target.to_owned(), value.clone());
        }
    }
}

pub trait Populate {
    fn add_resource_owner(&mut self, resource_owner: ResourceOwner);
}

pub trait Validate: Populate {
    fn client_id(&self) -> Option<&str>;
    fn request_username(&self) -> Option<&str>;
    fn request_password(&self) -> Option<&str>;
    fn client_id_username(&self) -> Option<&str> {
        None
    }
}

/// Requires valid local resource-owner credentials and populates authenticated owner state.
///
/// Resolves the username from client-bound identity or request credentials, verifies it against
/// the client's password file, and adds a resource owner with `authenticated` set to `true`.
///
/// # Errors
///
/// Returns `unauthenticated` when no credentials are supplied, or the applicable client or
/// uniform username-or-password OAuth error. Invalid and incomplete credential attempts perform
/// one bcrypt verification and do not expose configured usernames.
pub fn validate<T: Validate>(mut request: T) -> Result<T, OAuthError> {
    let Some(resource_owner) = validate_resource_owner(&request)? else {
        return Err(OAuthError::unauthenticated());
    };

    request.add_resource_owner(resource_owner);
    Ok(request)
}

/// Populates a local owner when credentials are complete while allowing their absence.
///
/// A request with no credentials, or with a recognized username but no password, remains
/// unchanged and unauthenticated. Complete valid credentials add the same authenticated resource
/// owner as [`validate`]. Supplied invalid credentials are never ignored.
///
/// # Errors
///
/// Returns client, username, or invalid-password errors for supplied credentials that fail
/// validation; missing credentials and a missing password are accepted.
pub fn validate_optional<T: Validate>(mut request: T) -> Result<T, OAuthError> {
    let resource_owner = match validate_resource_owner(&request) {
        Ok(resource_owner) => resource_owner,
        Err(error) if error.kind == OAuthErrorCode::MissingPassword => None,
        Err(error) => return Err(error),
    };

    let Some(resource_owner) = resource_owner else {
        return Ok(request);
    };

    request.add_resource_owner(resource_owner);
    Ok(request)
}

fn validate_resource_owner<T: Validate>(request: &T) -> Result<Option<ResourceOwner>, OAuthError> {
    if request.client_id_username().is_none()
        && request.request_username().is_none()
        && request.request_password().is_none()
    {
        return Ok(None);
    }

    let client_id = request
        .client_id()
        .ok_or_else(OAuthError::invalid_client_id)?;
    let username = request
        .client_id_username()
        .or_else(|| request.request_username());
    let password = request.request_password();
    let passwords = Config::global()
        .client_password_file(client_id)
        .map(|(passwords, _)| passwords);
    let configured_hash = passwords
        .and_then(|passwords| username.and_then(|username| password_hash(passwords, username)));
    let comparison_hash = configured_hash
        .or_else(|| passwords.and_then(first_password_hash))
        .unwrap_or(DUMMY_PASSWORD_HASH);
    let password_matches =
        bcrypt::verify(password.unwrap_or_default(), comparison_hash).unwrap_or(false);

    let Some(username) = username else {
        return Err(OAuthError::invalid_username());
    };
    if password.is_none() {
        return Err(OAuthError::missing_password());
    }
    if configured_hash.is_none() || !password_matches {
        return Err(OAuthError::invalid_password());
    }

    Ok(Some(ResourceOwner::from_username(username.to_owned())))
}

#[cfg(test)]
fn verify_password(passwords: &str, username: &str, password: &str) -> bool {
    password_hash(passwords, username)
        .is_some_and(|password_hash| bcrypt::verify(password, password_hash).unwrap_or(false))
}

fn password_hash<'a>(passwords: &'a str, username: &str) -> Option<&'a str> {
    passwords.lines().find_map(|line| {
        let (configured_username, password_hash) = line.split_once(':')?;
        (configured_username == username).then_some(password_hash)
    })
}

fn first_password_hash(passwords: &str) -> Option<&str> {
    passwords
        .lines()
        .find_map(|line| line.split_once(':').map(|(_, password_hash)| password_hash))
}

/// Reports whether a username appears in the client's configured password file.
///
/// Returns `false` when the client has no password-file configuration. No password hash is read or
/// verified by this lookup.
pub fn configured_username(client_id: &str, username: &str) -> bool {
    Config::global()
        .client_password_file(client_id)
        .is_some_and(|(_, usernames)| usernames.iter().any(|configured| configured == username))
}

#[cfg(test)]
mod tests {
    use super::{ResourceOwner, ResourceOwnerAttributes, verify_password};

    const PASSWORDS: &str = concat!(
        "# password: password\n",
        "username:$2y$05$4MDXTHOjtx8aCJ0k.Y/5leTGaeV.ffFF8jCeeA69BeQ.BvcTZZy06\n",
        "malformed\n",
        "broken:invalid-hash\n",
    );

    #[test]
    fn verifies_nginx_bcrypt_password_entry() {
        assert!(verify_password(PASSWORDS, "username", "password"));
    }

    #[test]
    fn rejects_wrong_password_unknown_user_and_malformed_hash() {
        assert!(!verify_password(PASSWORDS, "username", "wrong"));
        assert!(!verify_password(PASSWORDS, "unknown", "password"));
        assert!(!verify_password(PASSWORDS, "broken", "password"));
    }

    #[test]
    fn builds_resource_owner_from_attributes() {
        let mut attributes = ResourceOwnerAttributes::default();
        attributes.add("username", "username".to_owned(), true, &[]);
        attributes.add(
            "display_name",
            "display name".to_owned(),
            false,
            &["EmployeeCredential".to_owned()],
        );
        let resource_owner = ResourceOwner::from_attributes(attributes)
            .expect("resource owner attributes should be complete");

        assert_eq!(resource_owner.username, "username");
        assert!(resource_owner.authenticated);
        assert_eq!(resource_owner.profile["username"], "username");
        assert!(!resource_owner.profile.contains_key("display_name"));
        assert_eq!(
            resource_owner.credential_profile["EmployeeCredential"]["display_name"],
            "display name"
        );
        assert!(!resource_owner.credential_profile["EmployeeCredential"].contains_key("username"));
    }

    #[test]
    fn rejects_resource_owner_attributes_without_identifier() {
        assert!(ResourceOwner::from_attributes(ResourceOwnerAttributes::default()).is_none());
    }

    #[test]
    fn uses_last_artifact_selection_for_duplicate_attributes() {
        let mut attributes = ResourceOwnerAttributes::default();
        attributes.add(
            "username",
            "first".to_owned(),
            true,
            &["EmployeeCredential".to_owned()],
        );
        attributes.add("username", "second".to_owned(), false, &[]);
        let resource_owner = ResourceOwner::from_attributes(attributes)
            .expect("resource owner attributes should be complete");

        assert_eq!(resource_owner.username, "second");
        assert!(resource_owner.profile.is_empty());
        assert!(resource_owner.credential_profile.is_empty());
    }

    #[test]
    fn uses_subject_as_resource_owner_username_fallback() {
        let resource_owner = ResourceOwner::from_attributes(ResourceOwnerAttributes {
            attributes: [("sub".to_owned(), "subject".to_owned())]
                .into_iter()
                .collect(),
            ..ResourceOwnerAttributes::default()
        })
        .expect("subject should identify the resource owner");

        assert_eq!(resource_owner.username, "subject");
        assert!(resource_owner.authenticated);
        assert!(resource_owner.profile.is_empty());
        assert!(resource_owner.credential_profile.is_empty());
    }
}
