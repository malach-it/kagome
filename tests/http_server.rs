use std::io;

use kagome::http_server::{
    DEFAULT_WORKERS, HEADER_READ_TIMEOUT, MAX_CONCURRENT_CONNECTIONS, MAX_CONCURRENT_REQUESTS,
    MAX_ECHO_REQUEST_BODY_BYTES, MAX_HEADER_BYTES, MAX_PROTOCOL_REQUEST_BODY_BYTES,
    MAX_REQUEST_BODY_BYTES, MAX_REQUEST_HEADERS, REQUEST_BODY_TIMEOUT, RESPONSE_TIMEOUT,
    is_client_disconnect,
};

#[test]
fn server_default_workers_is_four() {
    assert_eq!(DEFAULT_WORKERS, 4);
}

#[test]
fn server_has_bounded_http_resources() {
    assert_eq!(MAX_CONCURRENT_CONNECTIONS, 256);
    assert_eq!(MAX_CONCURRENT_REQUESTS, 128);
    assert_eq!(MAX_REQUEST_HEADERS, 64);
    assert_eq!(MAX_HEADER_BYTES, 32 * 1024);
    assert_eq!(MAX_PROTOCOL_REQUEST_BODY_BYTES, 256 * 1024);
    assert_eq!(MAX_ECHO_REQUEST_BODY_BYTES, 1024 * 1024);
    assert_eq!(MAX_REQUEST_BODY_BYTES, 10 * 1024 * 1024);
    assert_eq!(HEADER_READ_TIMEOUT.as_secs(), 5);
    assert_eq!(REQUEST_BODY_TIMEOUT.as_secs(), 30);
    assert_eq!(RESPONSE_TIMEOUT.as_secs(), 30);
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
