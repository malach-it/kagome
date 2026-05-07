use std::{
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    sync::OnceLock,
    thread,
};

static SERVER_ADDRESS: OnceLock<String> = OnceLock::new();

pub fn send_request(request: &str) -> String {
    let mut stream =
        TcpStream::connect(server_address()).expect("failed to connect to kagome server");
    stream
        .write_all(request.as_bytes())
        .expect("failed to write request");

    let mut response = String::new();
    stream
        .read_to_string(&mut response)
        .expect("failed to read response");

    response
}

fn server_address() -> &'static str {
    SERVER_ADDRESS.get_or_init(start_server)
}

fn start_server() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").expect("failed to bind kagome server");
    let address = listener
        .local_addr()
        .expect("failed to read kagome server address")
        .to_string();

    thread::spawn(move || {
        kagome::http_server::serve_listener_with_workers(listener, 2)
            .expect("kagome server failed");
    });

    address
}
