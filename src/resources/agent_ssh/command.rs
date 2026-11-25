use std::{
    env, io,
    path::{Path, PathBuf},
    process::{Command, ExitCode, Stdio},
};

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize, PartialEq, Eq, Serialize)]
pub(super) struct CommandGrant {
    pub name: String,
    pub expires_at: u64,
    pub executable: PathBuf,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub args: Vec<String>,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub allow_stdin: bool,
}

impl CommandGrant {
    pub fn new(
        name: &str,
        executable: &Path,
        args: &[String],
        expires_at: u64,
        allow_stdin: bool,
    ) -> Self {
        Self {
            name: name.to_owned(),
            expires_at,
            executable: executable.to_owned(),
            args: args.to_vec(),
            allow_stdin,
        }
    }

    pub fn invocation(&self) -> String {
        let mut invocation = self.name.clone();
        for arg in &self.args {
            invocation.push(' ');
            if !arg.is_empty()
                && arg
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || b"_@%+=:,./-".contains(&byte))
            {
                invocation.push_str(arg);
            } else {
                invocation.push('\'');
                invocation.push_str(&arg.replace('\'', "'\\''"));
                invocation.push('\'');
            }
        }
        invocation
    }
}

pub(super) fn encode_grants(grants: &[CommandGrant]) -> io::Result<String> {
    Ok(URL_SAFE_NO_PAD.encode(serde_json::to_vec(grants)?))
}

pub(super) fn decode_grants(encoded: &str) -> Option<Vec<CommandGrant>> {
    serde_json::from_slice(&URL_SAFE_NO_PAD.decode(encoded).ok()?).ok()
}

/// Enforces an SSH exec request against grants emitted by the registration
/// pipeline. Requires the encoded grants from Dropbear's forced command and
/// its `SSH_ORIGINAL_COMMAND` environment variable. Launches the matching
/// fixed executable and argument vector, forwarding SSH standard input only
/// when the grant allows it. Returns
/// exit 126 for malformed grants, a denied or expired invocation, or a launch
/// error.
pub fn run_registered_command(encoded: &str) -> ExitCode {
    let original = env::var("SSH_ORIGINAL_COMMAND").unwrap_or_default();
    let now = jsonwebtoken::get_current_timestamp();
    let grant = decode_grants(encoded).and_then(|grants| {
        grants
            .into_iter()
            .find(|grant| grant.invocation() == original)
    });
    let Some(grant) = grant else {
        eprintln!("SSH command is not authorized");
        return ExitCode::from(126);
    };
    if now >= grant.expires_at {
        eprintln!("SSH registration expired");
        return ExitCode::from(126);
    }

    let mut command = Command::new(grant.executable);
    command.args(grant.args).stdin(match grant.allow_stdin {
        true => Stdio::inherit(),
        false => Stdio::null(),
    });
    #[cfg(unix)]
    let error = {
        use std::os::unix::process::CommandExt;
        command.exec()
    };
    #[cfg(not(unix))]
    let error = match command.status() {
        Ok(status) => {
            return ExitCode::from(
                status
                    .code()
                    .and_then(|code| u8::try_from(code).ok())
                    .unwrap_or(126),
            );
        }
        Err(error) => error,
    };
    eprintln!("SSH command could not be executed: {error}");
    ExitCode::from(126)
}
