use std::{
    env,
    io::{self, BufRead, BufReader, Read, Write},
    net::{TcpListener, TcpStream},
    process::Command,
};

use crate::{http_server, resources::client_credentials};

pub const LOGIN_SERVER_ADDRESS_ENV_VAR: &str = "KAGOME_LOGIN_SERVER_ADDRESS";
pub const DEFAULT_LOGIN_SERVER_ADDRESS: &str = "localhost:4000";

pub fn server_address_from_environment() -> String {
    env::var(LOGIN_SERVER_ADDRESS_ENV_VAR)
        .unwrap_or_else(|_| DEFAULT_LOGIN_SERVER_ADDRESS.to_owned())
}

pub fn prompt_and_login() -> io::Result<()> {
    let listener = TcpListener::bind(http_server::loopback_address_from_environment())?;

    prompt_and_login_with_listener(listener)
}

pub fn prompt_and_login_with_listener(listener: TcpListener) -> io::Result<()> {
    let mut stdin = io::stdin().lock();
    let mut stdout = io::stdout().lock();

    let username = prompt(&mut stdin, &mut stdout, "username: ")?;
    let host = prompt(&mut stdin, &mut stdout, "host: ")?;
    let response = login(
        listener,
        &server_address_from_environment(),
        &username,
        &host,
    )?;

    stdout.write_all(response.as_bytes())?;
    stdout.write_all(b"\n")?;
    stdout.flush()
}

pub fn login(
    listener: TcpListener,
    server_address: &str,
    username: &str,
    host: &str,
) -> io::Result<String> {
    let url = authorize_url(server_address, username);

    open_browser(&url)?;

    let callback_response = handle_callback(listener)?;
    let Some(private_key_path) = private_key_path(&callback_response) else {
        return Ok(console_response(&callback_response));
    };
    let ssh_command = ssh_command(&private_key_path, username, host);
    let status = run_ssh(&private_key_path, username, host)?;

    Ok(format!(
        "ssh command: {ssh_command}\nssh exited with status {status}"
    ))
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

fn handle_callback(listener: TcpListener) -> io::Result<String> {
    let (stream, _) = listener.accept()?;
    let request = read_http_request(&stream)?;
    let response = crate::ssh_login::route_raw_request(&request);
    let mut writer = stream;

    writer.write_all(response.as_bytes())?;

    Ok(response)
}

fn read_http_request(stream: &TcpStream) -> io::Result<String> {
    let mut reader = BufReader::new(stream.try_clone()?);
    let mut request = String::new();
    let mut content_length = 0;

    loop {
        let mut line = String::new();
        reader.read_line(&mut line)?;

        if line.is_empty() {
            return Ok(request);
        }
        if let Some((name, value)) = line.split_once(':')
            && name.eq_ignore_ascii_case("content-length")
        {
            content_length = value.trim().parse().unwrap_or_default();
        }

        let end_of_headers = line == "\r\n" || line == "\n";
        request.push_str(&line);

        if end_of_headers {
            break;
        }
    }

    let mut body = vec![0; content_length];
    reader.read_exact(&mut body)?;
    request.push_str(&String::from_utf8_lossy(&body));

    Ok(request)
}

fn response_body(response: &str) -> &str {
    response
        .split_once("\r\n\r\n")
        .map(|(_, body)| body)
        .unwrap_or(response)
}

fn console_response(response: &str) -> String {
    let body = response_body(response);
    let Some(command) = html_element_text(body, "<code id=\"ssh-command\">", "</code>") else {
        return body.to_owned();
    };

    format!(
        "temporary ssh keys have been created\nssh command: {}",
        html_unescape(&command)
    )
}

fn private_key_path(response: &str) -> Option<String> {
    html_element_text(response_body(response), "private key: <code>", "</code>")
        .map(|path| html_unescape(&path))
}

fn ssh_command(private_key_path: &str, username: &str, host: &str) -> String {
    format!("ssh -i {private_key_path} {username}@{host}")
}

fn run_ssh(
    private_key_path: &str,
    username: &str,
    host: &str,
) -> io::Result<std::process::ExitStatus> {
    Command::new("ssh")
        .arg("-i")
        .arg(private_key_path)
        .arg(format!("{username}@{host}"))
        .status()
}

fn html_element_text(body: &str, start: &str, end: &str) -> Option<String> {
    let start_index = body.find(start)? + start.len();
    let end_index = body[start_index..].find(end)?;

    Some(body[start_index..start_index + end_index].to_owned())
}

fn html_unescape(value: &str) -> String {
    value
        .replace("&quot;", "\"")
        .replace("&#39;", "'")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&amp;", "&")
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
    use super::{authorize_url, console_response, private_key_path, response_body, ssh_command};

    #[test]
    fn builds_browser_authorize_url_with_userinfo_client_id() {
        let url = authorize_url("example.com:4000", "username");

        assert!(url.starts_with("http://example.com:4000/authorize?"));
        assert!(url.contains("response_type=code"));
        assert!(url.contains("client_id=username%40example.com%3A4000"));
        assert!(url.contains("redirect_uri=http%3A%2F%2F127.0.0.1%3A4001%2Foauth%2Fcallback"));
        assert!(!url.contains("password"));
    }

    #[test]
    fn extracts_response_body() {
        assert_eq!(response_body("HTTP/1.1 200 OK\r\n\r\nbody"), "body");
    }

    #[test]
    fn converts_callback_html_to_console_message() {
        let response = "HTTP/1.1 200 OK\r\n\r\n<p>ssh command: <code id=\"ssh-command\">ssh -i ./.ssh/key username@example.com</code></p>";

        assert_eq!(
            console_response(response),
            "temporary ssh keys have been created\nssh command: ssh -i ./.ssh/key username@example.com"
        );
    }

    #[test]
    fn extracts_private_key_path_from_callback_html() {
        let response = "HTTP/1.1 200 OK\r\n\r\n<p>private key: <code>./.ssh/id_ed25519</code></p>";

        assert_eq!(
            private_key_path(response),
            Some("./.ssh/id_ed25519".to_owned())
        );
    }

    #[test]
    fn builds_prompted_host_ssh_command() {
        assert_eq!(
            ssh_command("./.ssh/id_ed25519", "username", "192.0.2.10"),
            "ssh -i ./.ssh/id_ed25519 username@192.0.2.10"
        );
    }
}
