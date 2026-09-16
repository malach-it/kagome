use std::{
    env, io,
    net::{TcpListener, ToSocketAddrs},
};

use axum::{
    Router,
    body::{Body, to_bytes},
    http::{
        HeaderName, HeaderValue, Request, Response, StatusCode,
        header::{CONNECTION, CONTENT_LENGTH},
    },
    routing::any,
};
use axum_server::tls_rustls::RustlsConfig;

use crate::unit::{HttpHeader, KagomeRequest};

pub const DEFAULT_WORKERS: usize = 4;
pub const MAX_REQUEST_BODY_BYTES: usize = 10 * 1024 * 1024;
pub const HTTPS_CERT_ENV_VAR: &str = "KAGOME_HTTPS_CERT";
pub const HTTPS_KEY_ENV_VAR: &str = "KAGOME_HTTPS_KEY";

#[derive(Clone, Debug, Eq, PartialEq)]
struct TlsConfiguration {
    certificate: String,
    private_key: String,
}

pub fn serve(address: impl ToSocketAddrs) -> io::Result<()> {
    serve_with_workers(address, DEFAULT_WORKERS)
}

pub fn serve_with_workers(address: impl ToSocketAddrs, worker_count: usize) -> io::Result<()> {
    let listener = TcpListener::bind(address)?;
    let tls_configuration = tls_configuration_from_environment()?;

    serve_listener_with_workers_and_tls(listener, worker_count, tls_configuration)
}

pub fn serve_listener_with_workers(listener: TcpListener, worker_count: usize) -> io::Result<()> {
    serve_listener_with_workers_and_tls(listener, worker_count, None)
}

fn serve_listener_with_workers_and_tls(
    listener: TcpListener,
    worker_count: usize,
    tls_configuration: Option<TlsConfiguration>,
) -> io::Result<()> {
    let worker_count = worker_count.max(1);
    println!("{}", listener.local_addr()?);
    listener.set_nonblocking(true)?;

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(worker_count)
        .enable_all()
        .thread_name("kagome-http")
        .build()?;

    runtime.block_on(async move {
        let application = Router::new().fallback(any(handle_request));

        match tls_configuration {
            Some(configuration) => {
                let tls = rustls_configuration(configuration).await?;

                axum_server::from_tcp_rustls(listener, tls)?
                    .serve(application.into_make_service())
                    .await
            }
            None => {
                let listener = tokio::net::TcpListener::from_std(listener)?;
                axum::serve(listener, application).await
            }
        }
    })
}

async fn rustls_configuration(configuration: TlsConfiguration) -> io::Result<RustlsConfig> {
    RustlsConfig::from_pem(
        configuration.certificate.into_bytes(),
        configuration.private_key.into_bytes(),
    )
    .await
}

fn tls_configuration_from_environment() -> io::Result<Option<TlsConfiguration>> {
    tls_configuration(
        optional_environment_variable(HTTPS_CERT_ENV_VAR)?,
        optional_environment_variable(HTTPS_KEY_ENV_VAR)?,
    )
}

fn optional_environment_variable(name: &str) -> io::Result<Option<String>> {
    match env::var(name) {
        Ok(value) => Ok(Some(value)),
        Err(env::VarError::NotPresent) => Ok(None),
        Err(env::VarError::NotUnicode(_)) => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{name} must contain valid unicode"),
        )),
    }
}

fn tls_configuration(
    certificate: Option<String>,
    private_key: Option<String>,
) -> io::Result<Option<TlsConfiguration>> {
    match (certificate, private_key) {
        (None, None) => Ok(None),
        (Some(certificate), Some(private_key))
            if !certificate.trim().is_empty() && !private_key.trim().is_empty() =>
        {
            Ok(Some(TlsConfiguration {
                certificate,
                private_key,
            }))
        }
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{HTTPS_CERT_ENV_VAR} and {HTTPS_KEY_ENV_VAR} must both contain PEM values"),
        )),
    }
}

async fn handle_request(request: Request<Body>) -> Response<Body> {
    let keep_alive = request
        .headers()
        .get(CONNECTION)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value.eq_ignore_ascii_case("keep-alive"));

    let request = match kagome_request(request).await {
        Ok(request) => request,
        Err(response) => return *response,
    };

    raw_http_response(&crate::router::route_request(&request), keep_alive)
}

async fn kagome_request(request: Request<Body>) -> Result<KagomeRequest, Box<Response<Body>>> {
    let (parts, body) = request.into_parts();
    let body = to_bytes(body, MAX_REQUEST_BODY_BYTES)
        .await
        .map_err(|_| Box::new(payload_too_large_response()))?;
    let headers = parts
        .headers
        .iter()
        .map(|(name, value)| HttpHeader {
            name: name.as_str().to_owned(),
            value: String::from_utf8_lossy(value.as_bytes()).into_owned(),
        })
        .collect();

    Ok(KagomeRequest::from_http_parts(
        parts.method.as_str().to_owned(),
        parts
            .uri
            .path_and_query()
            .map_or_else(|| "/".to_owned(), ToString::to_string),
        format!("{:?}", parts.version),
        headers,
        String::from_utf8_lossy(&body).into_owned(),
    ))
}

fn raw_http_response(raw_response: &str, keep_alive: bool) -> Response<Body> {
    let Some((head, body)) = raw_response.split_once("\r\n\r\n") else {
        return internal_server_error_response();
    };
    let mut lines = head.lines();
    let status = lines
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|status| status.parse::<u16>().ok())
        .and_then(|status| StatusCode::from_u16(status).ok());
    let Some(status) = status else {
        return internal_server_error_response();
    };
    let mut response = Response::builder().status(status);

    for line in lines {
        let Some((name, value)) = line.split_once(':') else {
            return internal_server_error_response();
        };
        let Ok(name) = HeaderName::from_bytes(name.trim().as_bytes()) else {
            return internal_server_error_response();
        };
        if name == CONTENT_LENGTH || name == CONNECTION {
            continue;
        }
        let Ok(value) = HeaderValue::from_str(value.trim()) else {
            return internal_server_error_response();
        };
        response = response.header(name, value);
    }

    response
        .header(CONNECTION, if keep_alive { "keep-alive" } else { "close" })
        .body(Body::from(body.to_owned()))
        .unwrap_or_else(|_| internal_server_error_response())
}

fn payload_too_large_response() -> Response<Body> {
    text_response(
        StatusCode::PAYLOAD_TOO_LARGE,
        "request body exceeds 10485760 bytes",
    )
}

fn internal_server_error_response() -> Response<Body> {
    text_response(StatusCode::INTERNAL_SERVER_ERROR, "internal server error")
}

fn text_response(status: StatusCode, body: &'static str) -> Response<Body> {
    Response::builder()
        .status(status)
        .header("content-type", "text/plain; charset=utf-8")
        .header(CONNECTION, "close")
        .body(Body::from(body))
        .expect("static HTTP response must be valid")
}

pub fn is_client_disconnect(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::BrokenPipe | io::ErrorKind::ConnectionReset | io::ErrorKind::UnexpectedEof
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn translates_raw_handler_response() {
        let response = raw_http_response(
            "HTTP/1.1 200 OK\r\ncontent-type: text/plain\r\ncontent-length: 2\r\nconnection: close\r\n\r\nok",
            false,
        );

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.headers()[CONNECTION], "close");
        assert_eq!(response.headers()["content-type"], "text/plain");
    }

    #[test]
    fn preserves_explicit_keep_alive_policy() {
        let response = raw_http_response(
            "HTTP/1.1 204 No Content\r\ncontent-length: 0\r\nconnection: close\r\n\r\n",
            true,
        );

        assert_eq!(response.status(), StatusCode::NO_CONTENT);
        assert_eq!(response.headers()[CONNECTION], "keep-alive");
    }

    #[test]
    fn leaves_tls_disabled_when_certificate_and_key_are_absent() {
        assert_eq!(tls_configuration(None, None).unwrap(), None);
    }

    #[test]
    fn enables_tls_when_certificate_and_key_are_present() {
        let configuration = tls_configuration(
            Some("certificate PEM".to_owned()),
            Some("private key PEM".to_owned()),
        )
        .unwrap()
        .unwrap();

        assert_eq!(configuration.certificate, "certificate PEM");
        assert_eq!(configuration.private_key, "private key PEM");
    }

    #[test]
    fn rejects_incomplete_or_empty_tls_configuration() {
        for (certificate, private_key) in [
            (Some("certificate PEM".to_owned()), None),
            (None, Some("private key PEM".to_owned())),
            (Some(String::new()), Some("private key PEM".to_owned())),
            (Some("certificate PEM".to_owned()), Some(" ".to_owned())),
        ] {
            let error = tls_configuration(certificate, private_key).unwrap_err();

            assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
            assert!(error.to_string().contains(HTTPS_CERT_ENV_VAR));
            assert!(error.to_string().contains(HTTPS_KEY_ENV_VAR));
        }
    }

    #[test]
    fn rejects_invalid_tls_pem() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let result = runtime.block_on(rustls_configuration(TlsConfiguration {
            certificate: "not a certificate".to_owned(),
            private_key: "not a private key".to_owned(),
        }));

        assert!(result.is_err());
    }
}
