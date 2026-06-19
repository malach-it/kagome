use std::{io, net::TcpListener};

fn main() -> io::Result<()> {
    kagome::ca::ensure_ca_key(kagome::ca::ca_key_path_from_environment())?;
    let listener = TcpListener::bind(kagome::http_server::loopback_address_from_environment())?;

    kagome::login::prompt_and_login_with_listener(listener)
}
