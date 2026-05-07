use kagome::http_server::{DEFAULT_ADDRESS, DEFAULT_WORKERS, worker_count_from_value};

#[test]
fn server_default_address_is_loopback_port_4000() {
    assert_eq!(DEFAULT_ADDRESS, "127.0.0.1:4000");
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
