//! Short-lived SSH command registration for an authenticated agent.

use std::{
    collections::HashSet,
    fs::{self, OpenOptions},
    io::{self, Write},
    net::IpAddr,
    path::Path,
};

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use ring::rand::{SecureRandom, SystemRandom};
use serde::Serialize;

use super::agent_token::{VerifiedAgentToken, agent_domain, valid_server_identifier};
use crate::{
    config::{AgentSshConfig, AgentSshScopes, Config, is_scope_token},
    errors::OAuthError,
};

mod command;
pub use command::run_registered_command;
use command::{CommandGrant, decode_grants, encode_grants};

const GRANT_LIFETIME: u64 = 60;
const MAX_REGISTRATIONS: usize = 1024;
const MAX_AUTHORIZED_KEY_LINE: usize = 4200;
const MANAGED_PREFIX: &str = "restrict,command=\"/usr/local/bin/kagome-ssh-resource ";
const MANAGED_TAG: &str = " kagome-agent-ssh";
pub const SSH_SCOPE_HEADER: &str = "ssh-scope";

#[derive(Serialize)]
pub struct SshAction {
    action: &'static str,
    host: String,
    port: u16,
    user: &'static str,
    pub(crate) scope: String,
    commands: Vec<String>,
    pub(crate) expires_at: u64,
}

pub trait Register {
    fn ssh_scope_fields(&self) -> &[&str];
    fn authenticated_agent(&self) -> Option<(&VerifiedAgentToken, u64)>;
    fn set_ssh_action(&mut self, action: SshAction);
}

/// Validates the SSH handoff settings before startup. Requires a trusted issuer,
/// an exact agent subject, a client-visible endpoint, and absolute local paths.
/// Returns an error naming the invalid setting without changing configuration.
pub(crate) fn validate_config(
    config: &AgentSshConfig,
    issuers: &HashSet<&String>,
) -> Result<(), &'static str> {
    if !issuers.contains(&config.issuer) {
        return Err("issuer must name a configured agent provider");
    }
    if agent_domain(&config.subject).is_none() {
        return Err("subject must be an AAuth agent identifier");
    }
    if config.host.parse::<IpAddr>().is_err()
        && !valid_server_identifier(&format!("https://{}", config.host))
    {
        return Err("host must be a DNS hostname or IP address");
    }
    if config.port == 0 {
        return Err("port must be nonzero");
    }
    match &config.scopes {
        AgentSshScopes::Grouped(scopes) => {
            if config.executable.is_some() || !config.commands.is_empty() {
                return Err(
                    "scopes with command lists cannot be combined with executable or commands",
                );
            }
            if scopes.keys().any(|scope| !is_scope_token(scope)) {
                return Err("scopes must contain valid OAuth scope tokens");
            }
            let mut names = HashSet::new();
            for command in scopes.values().flatten() {
                validate_command(&command.name, &command.executable, &command.allowed_args)?;
                if !names.insert(command.name.as_str()) {
                    return Err("commands must have unique names across scopes");
                }
            }
            if names.is_empty() {
                return Err("scopes must configure at least one SSH command");
            }
        }
        AgentSshScopes::Legacy(scopes) => validate_legacy_config(config, scopes)?,
    }
    if !config.state_directory.is_absolute() {
        return Err("state_directory must be an absolute path");
    }
    Ok(())
}

fn validate_legacy_config(config: &AgentSshConfig, scopes: &[String]) -> Result<(), &'static str> {
    match (&config.executable, config.commands.is_empty()) {
        (Some(executable), true) if scopes.is_empty() && valid_executable(executable) => {}
        (Some(_), true) => {
            return Err(
                "executable must be a safe absolute path for legacy configuration without scopes",
            );
        }
        (Some(_), false) => return Err("commands cannot be combined with the legacy executable"),
        (None, true) => return Err("commands must configure at least one SSH command"),
        (None, false) => {}
    }
    let mut seen = HashSet::new();
    if scopes
        .iter()
        .any(|scope| !is_scope_token(scope) || !seen.insert(scope))
    {
        return Err("scopes must contain unique, non-empty OAuth scope tokens");
    }
    for (name, command) in &config.commands {
        if !is_scope_token(&command.scope) {
            return Err("commands require valid scope tokens");
        }
        validate_command(name, &command.executable, &command.allowed_args)?;
    }
    Ok(())
}

fn validate_command(
    name: &str,
    executable: &Path,
    args: &[Vec<String>],
) -> Result<(), &'static str> {
    if !valid_command_name(name) || !valid_executable(executable) {
        return Err("commands require valid names and safe absolute executable paths");
    }
    if args.iter().flatten().any(|arg| arg.contains('\0')) {
        return Err("commands.allowed_args must not contain NUL bytes");
    }
    Ok(())
}

fn valid_executable(path: &Path) -> bool {
    path.is_absolute()
        && path.to_str().is_some_and(|path| {
            path.bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"/._-".contains(&byte))
        })
}

fn valid_command_name(name: &str) -> bool {
    !name.is_empty()
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"_-".contains(&byte))
}

fn requested_scopes<'a>(
    config: &AgentSshConfig,
    fields: &'a [&str],
) -> Result<Vec<&'a str>, OAuthError> {
    let invalid = || {
        OAuthError::invalid_request(
            "exactly one SSH-Scope header with valid, unique scope tokens is required",
        )
    };
    let value = match fields {
        [] if config.executable.is_some() => "resource",
        [value] => value.trim_matches([' ', '\t']),
        _ => return Err(invalid()),
    };
    let mut seen = HashSet::new();
    let scopes: Vec<_> = value.split(' ').filter(|scope| !scope.is_empty()).collect();
    if scopes.is_empty()
        || scopes
            .iter()
            .any(|&scope| !is_scope_token(scope) || !seen.insert(scope))
    {
        return Err(invalid());
    }
    Ok(scopes)
}

fn authorized_grants(
    config: &AgentSshConfig,
    scope: &str,
    expires_at: u64,
) -> Result<Vec<CommandGrant>, OAuthError> {
    if let Some(executable) = config.executable.as_deref().filter(|_| scope == "resource") {
        return Ok(vec![CommandGrant::new(
            "resource",
            executable,
            &[],
            expires_at,
            false,
        )]);
    }
    let denied = || OAuthError::unauthorized_client("agent is not authorized for this SSH scope");
    let grants: Vec<_> = match &config.scopes {
        AgentSshScopes::Grouped(scopes) => scopes
            .get(scope)
            .ok_or_else(denied)?
            .iter()
            .flat_map(|command| {
                command_grants(
                    &command.name,
                    &command.executable,
                    &command.allowed_args,
                    expires_at,
                    command.allow_stdin,
                )
            })
            .collect(),
        AgentSshScopes::Legacy(scopes) if scopes.iter().any(|granted| granted == scope) => config
            .commands
            .iter()
            .filter(|(_, command)| command.scope == scope)
            .flat_map(|(name, command)| {
                command_grants(
                    name,
                    &command.executable,
                    &command.allowed_args,
                    expires_at,
                    command.allow_stdin,
                )
            })
            .collect(),
        AgentSshScopes::Legacy(_) => return Err(denied()),
    };
    if grants.is_empty() {
        return Err(OAuthError::unauthorized_client(
            "SSH scope has no configured commands",
        ));
    }
    Ok(grants)
}

fn command_grants<'a>(
    name: &'a str,
    executable: &'a Path,
    allowed_args: &'a [Vec<String>],
    expires_at: u64,
    allow_stdin: bool,
) -> impl Iterator<Item = CommandGrant> + 'a {
    let bare = allowed_args.is_empty().then_some(&[][..]);
    bare.into_iter()
        .chain(allowed_args.iter().map(Vec::as_slice))
        .map(move |args| CommandGrant::new(name, executable, args, expires_at, allow_stdin))
}

/// Registers the key that verified the HTTP signature for the configured SSH
/// commands in all requested SSH scopes. Requires authenticated agent state, an
/// issuer-and-subject match, and every requested scope granted to that agent.
/// Publishes the restricted key before adding the SSH action to response state.
/// Returns `unauthorized_client` for disabled or denied registration, an
/// expired grant, or an unencodable key. Returns `invalid_request` for a
/// missing or invalid scope header. Returns `invalid_token_response` if
/// authenticated state is missing or SSH state cannot be read or written.
pub fn register<T: Register>(mut request: T) -> Result<T, OAuthError> {
    let (agent, signature_created) = request
        .authenticated_agent()
        .ok_or_else(|| OAuthError::invalid_token_response("authenticated agent is missing"))?;
    let config = Config::ssh_resource()
        .ok_or_else(|| OAuthError::unauthorized_client("SSH handoff is not configured"))?;
    if agent.issuer != config.issuer || agent.subject != config.subject {
        return Err(OAuthError::unauthorized_client(
            "agent is not authorized for this SSH resource",
        ));
    }
    let now = jsonwebtoken::get_current_timestamp();
    let expires_at = agent
        .expires_at()
        .min(signature_created.saturating_add(GRANT_LIFETIME));
    let scopes = requested_scopes(config, request.ssh_scope_fields())?;
    let mut grants = Vec::new();
    for scope in &scopes {
        grants.extend(authorized_grants(config, scope, expires_at)?);
    }
    if expires_at <= now {
        return Err(OAuthError::unauthorized_client("SSH registration expired"));
    }
    let key = agent.ssh_key().ok_or_else(|| {
        OAuthError::unauthorized_client("agent key cannot be used for SSH registration")
    })?;
    if grants.iter().any(|grant| !grant.executable.is_file()) {
        return Err(OAuthError::invalid_token_response(
            "SSH resource executable is unavailable",
        ));
    }
    let scope = scopes.join(" ");
    let invocations = grants.iter().map(CommandGrant::invocation).collect();
    write_authorized_key(&config.state_directory, &key, grants, now)
        .map_err(|_| OAuthError::invalid_token_response("SSH registration could not be written"))?;
    request.set_ssh_action(SshAction {
        action: "ssh",
        host: config.host.clone(),
        port: config.port,
        user: "kagome",
        scope,
        commands: invocations,
        expires_at,
    });
    Ok(request)
}

fn write_authorized_key(
    directory: &Path,
    key: &str,
    mut new_grants: Vec<CommandGrant>,
    now: u64,
) -> io::Result<()> {
    let _lock = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(false)
        .open(directory.join("authorized_keys.lock"))?;
    _lock.lock()?;
    let target = directory.join("authorized_keys");
    let current = fs::read_to_string(&target)?;
    let mut entries = Vec::new();
    let mut command_grants = Vec::new();
    let mut registrations = 0;
    for line in current.lines() {
        if let Some((registered_key, mut grants)) = managed_key(line) {
            grants.retain(|entry| entry.expires_at > now);
            if registered_key == key {
                grants.retain(|entry| {
                    if let Some(grant) = new_grants.iter_mut().find(|grant| {
                        entry.name == grant.name
                            && entry.args == grant.args
                            && entry.executable == grant.executable
                            && entry.allow_stdin == grant.allow_stdin
                    }) {
                        grant.expires_at = grant.expires_at.max(entry.expires_at);
                        return false;
                    }
                    !new_grants.iter().any(|grant| entry.name == grant.name)
                });
                command_grants.extend(grants);
            } else if !grants.is_empty() {
                entries.push(authorized_key_line(registered_key, &grants)?);
                registrations += 1;
            }
        } else {
            entries.push(line.to_owned());
        }
    }
    if registrations >= MAX_REGISTRATIONS {
        return Err(io::Error::other("SSH registration capacity reached"));
    }
    command_grants.extend(new_grants);
    entries.push(authorized_key_line(key, &command_grants)?);

    let mut nonce = [0; 16];
    SystemRandom::new()
        .fill(&mut nonce)
        .map_err(|_| io::Error::other("SSH registration temporary filename unavailable"))?;
    let pending = directory.join(format!(
        "authorized_keys.{}.tmp",
        URL_SAFE_NO_PAD.encode(nonce)
    ));
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
    let mut file = options.open(&pending)?;
    let result = (|| {
        for entry in entries {
            writeln!(file, "{entry}")?;
        }
        file.sync_all()?;
        fs::rename(&pending, target)
    })();
    if result.is_err() {
        let _ = fs::remove_file(pending);
    }
    result
}

fn managed_key(line: &str) -> Option<(&str, Vec<CommandGrant>)> {
    let (args, key_and_tag) = line.strip_prefix(MANAGED_PREFIX)?.split_once("\" ")?;
    let (key, tag) = key_and_tag.rsplit_once(MANAGED_TAG)?;
    let args: Vec<_> = args.split_ascii_whitespace().collect();
    let grants = match args.as_slice() {
        ["v2", encoded] if tag.is_empty() => decode_grants(encoded)?,
        [expiry, executable] if tag.starts_with(':') => {
            vec![parse_grant("resource", expiry, executable)?]
        }
        _ if tag.is_empty() && args.len().is_multiple_of(3) => args
            .chunks_exact(3)
            .map(|chunk| parse_grant(chunk[0], chunk[1], chunk[2]))
            .collect::<Option<_>>()?,
        _ => return None,
    };
    Some((key, grants))
}

fn parse_grant(name: &str, expiry: &str, executable: &str) -> Option<CommandGrant> {
    Some(CommandGrant::new(
        name,
        Path::new(executable),
        &[],
        expiry.parse().ok()?,
        false,
    ))
}

fn authorized_key_line(key: &str, grants: &[CommandGrant]) -> io::Result<String> {
    let args = if grants
        .iter()
        .any(|grant| !grant.args.is_empty() || grant.allow_stdin)
    {
        format!("v2 {}", encode_grants(grants)?)
    } else {
        grants
            .iter()
            .map(|grant| {
                format!(
                    "{} {} {}",
                    grant.name,
                    grant.expires_at,
                    grant.executable.display()
                )
            })
            .collect::<Vec<_>>()
            .join(" ")
    };
    let line = format!("{MANAGED_PREFIX}{args}\" {key}{MANAGED_TAG}");
    if line.len() >= MAX_AUTHORIZED_KEY_LINE {
        return Err(io::Error::other(
            "SSH authorized key line exceeds Dropbear's limit",
        ));
    }
    Ok(line)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn state() -> AgentSshConfig {
        let mut nonce = [0; 16];
        SystemRandom::new().fill(&mut nonce).unwrap();
        let state_directory = std::env::temp_dir().join(format!(
            "kagome-ssh-state-{}",
            URL_SAFE_NO_PAD.encode(nonce)
        ));
        fs::create_dir(&state_directory).unwrap();
        AgentSshConfig {
            issuer: "https://agents.example".to_owned(),
            subject: "aauth:agent@agents.example".to_owned(),
            host: "resource.example".to_owned(),
            port: 2222,
            executable: Some("/bin/hostname".into()),
            scopes: AgentSshScopes::default(),
            commands: Default::default(),
            state_directory,
        }
    }

    fn grant(name: &str, expires_at: u64) -> CommandGrant {
        CommandGrant::new(name, Path::new("/bin/hostname"), &[], expires_at, false)
    }

    #[test]
    fn preserves_static_entries_and_prunes_expired_registrations() {
        let config = state();
        let target = config.state_directory.join("authorized_keys");
        fs::write(&target, "# static entry\n").unwrap();
        let directory = &config.state_directory;
        write_authorized_key(
            directory,
            "ssh-ed25519 expired",
            vec![grant("resource", 30)],
            20,
        )
        .unwrap();
        write_authorized_key(
            directory,
            "ssh-ed25519 current",
            vec![grant("details", 40), grant("resource", 60)],
            30,
        )
        .unwrap();
        write_authorized_key(
            directory,
            "ssh-ed25519 current",
            vec![grant("resource", 50)],
            40,
        )
        .unwrap();
        let contents = fs::read_to_string(target).unwrap();
        let entries: Vec<_> = contents.lines().collect();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0], "# static entry");
        assert_eq!(
            managed_key(entries[1]),
            Some(("ssh-ed25519 current", vec![grant("resource", 60)]))
        );
        fs::remove_dir_all(config.state_directory).unwrap();
    }

    #[test]
    fn leaves_existing_registrations_intact_when_capacity_is_reached() {
        let config = state();
        let target = config.state_directory.join("authorized_keys");
        let entries: String = (0..MAX_REGISTRATIONS)
            .map(|index| {
                authorized_key_line(&format!("ssh-ed25519 {index}"), &[grant("resource", 60)])
                    .unwrap()
                    + "\n"
            })
            .collect();
        fs::write(&target, &entries).unwrap();
        assert!(
            write_authorized_key(
                &config.state_directory,
                "ssh-ed25519 new",
                vec![grant("resource", 60)],
                20
            )
            .is_err()
        );
        assert_eq!(fs::read_to_string(target).unwrap(), entries);
        fs::remove_dir_all(config.state_directory).unwrap();
    }

    #[test]
    fn accepts_existing_resource_configuration_and_expiry_entries() {
        let config = state();
        assert_eq!(requested_scopes(&config, &[]).unwrap(), ["resource"]);
        assert_eq!(
            authorized_grants(&config, "resource", 60).unwrap(),
            [grant("resource", 60)],
        );
        let old = format!("{MANAGED_PREFIX}60 /bin/hostname\" ssh-ed25519 old{MANAGED_TAG}:60");
        assert_eq!(
            managed_key(&old),
            Some(("ssh-ed25519 old", vec![grant("resource", 60)]))
        );
        fs::remove_dir_all(config.state_directory).unwrap();
    }

    #[test]
    fn replaces_old_argument_variants_when_a_command_is_registered_again() {
        let config = state();
        let directory = &config.state_directory;
        let target = directory.join("authorized_keys");
        fs::write(&target, "").unwrap();
        let with_arg = |arg: &str, expires_at| {
            CommandGrant::new(
                "resource",
                Path::new("/bin/hostname"),
                &[arg.to_owned()],
                expires_at,
                false,
            )
        };
        let key = "ssh-ed25519 current";
        write_authorized_key(
            directory,
            key,
            vec![with_arg("-f", 60), with_arg("-s", 60)],
            20,
        )
        .unwrap();
        write_authorized_key(
            directory,
            key,
            vec![with_arg("-s", 50), grant("details", 55)],
            30,
        )
        .unwrap();
        let entries = fs::read_to_string(target).unwrap();
        assert_eq!(
            managed_key(entries.trim()),
            Some((key, vec![with_arg("-s", 60), grant("details", 55)])),
        );
        fs::remove_dir_all(config.state_directory).unwrap();
    }
}
