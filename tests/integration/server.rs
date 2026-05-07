use std::{
    io::{BufRead, BufReader, Read, Write},
    net::{TcpListener, TcpStream},
    sync::OnceLock,
    thread,
};

static SERVER_ADDRESS: OnceLock<String> = OnceLock::new();

pub fn send_request(request: &str) -> String {
    let mut stream =
        TcpStream::connect(server_address()).expect("failed to connect to kagome server");
    let mut reader = BufReader::new(
        stream
            .try_clone()
            .expect("failed to clone kagome connection"),
    );

    stream
        .write_all(request.as_bytes())
        .expect("failed to write request");

    read_response(&mut reader)
}

pub fn send_persistent_requests(requests: &[&str]) -> Vec<String> {
    let mut stream =
        TcpStream::connect(server_address()).expect("failed to connect to kagome server");
    let mut reader = BufReader::new(
        stream
            .try_clone()
            .expect("failed to clone kagome connection"),
    );

    requests
        .iter()
        .map(|request| {
            stream
                .write_all(request.as_bytes())
                .expect("failed to write request");

            read_response(&mut reader)
        })
        .collect()
}

#[test]
fn keeps_connection_alive_when_requested() {
    let responses = send_persistent_requests(&[
        "GET /echo HTTP/1.1\r\nhost: example.com\r\nconnection: keep-alive\r\n\r\n",
        "POST /echo HTTP/1.1\r\nhost: example.com\r\nconnection: keep-alive\r\ncontent-length: 6\r\n\r\nsecond",
    ]);

    assert_eq!(responses.len(), 2);
    assert!(responses[0].contains("\"method\":\"GET\""));
    assert!(responses[0].contains("connection: keep-alive\r\n"));
    assert!(responses[0].contains("{\"name\":\"connection\",\"value\":\"keep-alive\"}"));
    assert!(responses[0].ends_with("\"body\":\"\"}"));
    assert!(responses[1].contains("\"method\":\"POST\""));
    assert!(responses[1].contains("connection: keep-alive\r\n"));
    assert!(responses[1].contains("{\"name\":\"connection\",\"value\":\"keep-alive\"}"));
    assert!(responses[1].ends_with("\"body\":\"second\"}"));
}

#[test]
fn closes_connection_by_default() {
    let response = send_request("GET /echo HTTP/1.1\r\nhost: example.com\r\n\r\n");

    assert!(response.contains("connection: close\r\n"));
}

#[test]
fn closes_connection_when_requested() {
    let response =
        send_request("GET /echo HTTP/1.1\r\nhost: example.com\r\nconnection: close\r\n\r\n");

    assert!(response.contains("connection: close\r\n"));
    assert!(response.contains("{\"name\":\"connection\",\"value\":\"close\"}"));
}

fn read_response(reader: &mut BufReader<TcpStream>) -> String {
    let mut response = String::new();
    let mut content_length = 0;

    loop {
        let mut line = String::new();
        reader
            .read_line(&mut line)
            .expect("failed to read response header");

        if let Some((name, value)) = line.split_once(':')
            && name.eq_ignore_ascii_case("content-length")
        {
            content_length = value.trim().parse().unwrap_or_default();
        }

        let is_end_of_headers = line == "\r\n" || line == "\n";
        response.push_str(&line);

        if is_end_of_headers {
            break;
        }
    }

    let mut body = vec![0; content_length];
    reader
        .read_exact(&mut body)
        .expect("failed to read response body");
    response.push_str(&String::from_utf8_lossy(&body));

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
