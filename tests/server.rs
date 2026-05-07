use std::{io, net::TcpListener, time::Instant};

use kagome::http_server::{
    DEFAULT_ADDRESS, DEFAULT_WORKERS, serve_listener_with_workers, worker_count_from_value,
};

#[test]
fn server_default_address_binds_all_interfaces_on_port_4000() {
    assert_eq!(DEFAULT_ADDRESS, "0.0.0.0:4000");
}

#[test]
fn server_default_workers_is_four() {
    assert_eq!(DEFAULT_WORKERS, 4);
}

#[test]
fn server_parses_configured_worker_count() {
    assert_eq!(worker_count_from_value(Some("4")), 4);
}

#[test]
fn server_defaults_workers_when_value_is_missing_zero_or_invalid() {
    assert_eq!(worker_count_from_value(None), DEFAULT_WORKERS);
    assert_eq!(worker_count_from_value(Some("0")), DEFAULT_WORKERS);
    assert_eq!(worker_count_from_value(Some("invalid")), DEFAULT_WORKERS);
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
