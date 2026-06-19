use std::{io, net::TcpListener, thread};

fn main() -> io::Result<()> {
    kagome::ca::ensure_ca_key(kagome::ca::ca_key_path_from_environment())?;

    let address = kagome::http_server::loopback_address_from_environment();
    let workers = kagome::http_server::worker_count_from_environment();
    let listener = TcpListener::bind(address)?;
    let server = thread::spawn(move || {
        kagome::http_server::serve_listener_with_route(
            listener,
            workers,
            kagome::ssh_login::route_raw_request,
        )
    });

    kagome::login::prompt_and_login()?;

    server
        .join()
        .map_err(|_| io::Error::other("loopback server panicked"))?
}
