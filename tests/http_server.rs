use std::{io, net::TcpListener, time::Instant};

use kagome::http_server::{DEFAULT_WORKERS, is_client_disconnect, serve_listener_with_workers};

#[test]
fn server_default_workers_is_four() {
    assert_eq!(DEFAULT_WORKERS, 4);
}

#[test]
fn server_workers_stop_when_listener_closes() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("failed to bind listener");
    listener
        .set_nonblocking(true)
        .expect("failed to set listener nonblocking");
    let started_waiting = Instant::now();
    let result = serve_listener_with_workers(listener, 2);

    assert_eq!(
        result
            .expect_err("server should stop on nonblocking accept")
            .kind(),
        io::ErrorKind::WouldBlock
    );
    assert!(started_waiting.elapsed().as_secs() < 1);
}

#[test]
fn server_treats_client_disconnects_as_expected_errors() {
    assert!(is_client_disconnect(&io::Error::from(
        io::ErrorKind::BrokenPipe
    )));
    assert!(is_client_disconnect(&io::Error::from(
        io::ErrorKind::ConnectionReset
    )));
    assert!(is_client_disconnect(&io::Error::from(
        io::ErrorKind::UnexpectedEof
    )));
}

#[test]
fn server_does_not_treat_other_errors_as_client_disconnects() {
    assert!(!is_client_disconnect(&io::Error::from(
        io::ErrorKind::InvalidData
    )));
}
