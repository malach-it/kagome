use std::{
    io::Write,
    process::{Command, Stdio},
};

#[test]
fn echoes_http_request_parts() {
    let mut process = Command::new(env!("CARGO_BIN_EXE_kagome"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("failed to run kagome binary");

    process
        .stdin
        .as_mut()
        .expect("failed to open kagome stdin")
        .write_all(
            b"POST /echo HTTP/1.1\r\nhost: example.com\r\ncontent-type: text/plain\r\n\r\nhello",
        )
        .expect("failed to write http request");

    let output = process
        .wait_with_output()
        .expect("failed to read kagome output");

    assert!(output.status.success());
    assert!(output.stderr.is_empty());

    let response = String::from_utf8_lossy(&output.stdout);
    assert!(response.starts_with("HTTP/1.1 200 OK\r\n"));
    assert!(response.contains("content-type: application/json\r\n"));
    assert!(response.contains("\"protocol\":\"HTTP/1.1\""));
    assert!(response.contains("{\"name\":\"host\",\"value\":\"example.com\"}"));
    assert!(response.contains("{\"name\":\"content-type\",\"value\":\"text/plain\"}"));
    assert!(response.ends_with("\"body\":\"hello\"}"));
}
