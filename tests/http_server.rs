use std::io;

use kagome::http_server::{DEFAULT_WORKERS, MAX_REQUEST_BODY_BYTES, is_client_disconnect};

#[test]
fn server_default_workers_is_four() {
    assert_eq!(DEFAULT_WORKERS, 4);
}

#[test]
fn server_limits_request_bodies_to_ten_mebibytes() {
    assert_eq!(MAX_REQUEST_BODY_BYTES, 10 * 1024 * 1024);
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
