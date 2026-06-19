use std::{
    env,
    io::{self, BufRead, Write},
    process::Command,
};

use crate::resources::client_credentials;

pub const LOGIN_SERVER_ADDRESS_ENV_VAR: &str = "KAGOME_LOGIN_SERVER_ADDRESS";
pub const DEFAULT_LOGIN_SERVER_ADDRESS: &str = "localhost:4000";

pub fn server_address_from_environment() -> String {
    env::var(LOGIN_SERVER_ADDRESS_ENV_VAR)
        .unwrap_or_else(|_| DEFAULT_LOGIN_SERVER_ADDRESS.to_owned())
}

pub fn prompt_and_login() -> io::Result<()> {
    let mut stdin = io::stdin().lock();
    let mut stdout = io::stdout().lock();

    let username = prompt(&mut stdin, &mut stdout, "username: ")?;
    let response = login(&server_address_from_environment(), &username)?;

    stdout.write_all(response.as_bytes())?;
    stdout.write_all(b"\n")?;
    stdout.flush()
}

pub fn login(server_address: &str, username: &str) -> io::Result<String> {
    let url = authorize_url(server_address, username);

    open_browser(&url)?;

    Ok(format!("opened {url}"))
}

pub fn authorize_url(server_address: &str, username: &str) -> String {
    format!(
        "http://{server_address}{}",
        authorize_path(server_address, username)
    )
}

fn authorize_path(server_address: &str, username: &str) -> String {
    let client_id = format!("{username}@{server_address}");
    format!(
        "/authorize?response_type=code&client_id={}&redirect_uri={}",
        query_encode(&client_id),
        query_encode(&client_credentials::loopback_redirect_uri())
    )
}

fn open_browser(url: &str) -> io::Result<()> {
    let mut command = browser_command(url);
    let status = command.status()?;

    if status.success() {
        Ok(())
    } else {
        Err(io::Error::other(format!(
            "failed to open browser with status {status}"
        )))
    }
}

fn browser_command(url: &str) -> Command {
    if let Ok(browser) = env::var("BROWSER")
        && !browser.is_empty()
    {
        let mut command = Command::new(browser);
        command.arg(url);
        return command;
    }

    #[cfg(target_os = "macos")]
    {
        let mut command = Command::new("open");
        command.arg(url);
        command
    }

    #[cfg(target_os = "windows")]
    {
        let mut command = Command::new("rundll32");
        command.args(["url.dll,FileProtocolHandler", url]);
        command
    }

    #[cfg(all(not(target_os = "macos"), not(target_os = "windows")))]
    {
        let mut command = Command::new("xdg-open");
        command.arg(url);
        command
    }
}

fn prompt(reader: &mut impl BufRead, writer: &mut impl Write, prompt: &str) -> io::Result<String> {
    writer.write_all(prompt.as_bytes())?;
    writer.flush()?;

    let mut value = String::new();
    reader.read_line(&mut value)?;

    Ok(value.trim_end_matches(['\r', '\n']).to_owned())
}

fn query_encode(value: &str) -> String {
    value
        .bytes()
        .flat_map(|byte| match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                vec![byte as char]
            }
            b' ' => vec!['+'],
            _ => {
                let hex = b"0123456789ABCDEF";
                vec![
                    '%',
                    hex[(byte >> 4) as usize] as char,
                    hex[(byte & 0x0F) as usize] as char,
                ]
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::authorize_url;

    #[test]
    fn builds_browser_authorize_url_with_userinfo_client_id() {
        let url = authorize_url("example.com:4000", "username");

        assert!(url.starts_with("http://example.com:4000/authorize?"));
        assert!(url.contains("response_type=code"));
        assert!(url.contains("client_id=username%40example.com%3A4000"));
        assert!(url.contains("redirect_uri=http%3A%2F%2F127.0.0.1%3A4001%2Foauth%2Fcallback"));
        assert!(!url.contains("password"));
    }
}
