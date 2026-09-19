use std::{
    env,
    future::Future,
    io,
    net::{TcpListener, ToSocketAddrs},
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};

use axum::extract::ConnectInfo;
use axum::{
    Router,
    body::{Body, to_bytes},
    extract::State,
    http::{
        HeaderName, HeaderValue, Request, Response, StatusCode,
        header::{CONNECTION, CONTENT_LENGTH},
    },
    routing::any,
};
use axum_server::{accept::Accept, tls_rustls::RustlsConfig};
use hyper_util::rt::TokioTimer;
use std::net::SocketAddr;
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    sync::{OwnedSemaphorePermit, Semaphore},
    task::JoinError,
    time::timeout,
};

use crate::unit::{HttpHeader, KagomeRequest};

pub const DEFAULT_WORKERS: usize = 4;
pub const MAX_CONCURRENT_CONNECTIONS: usize = 256;
pub const MAX_CONCURRENT_REQUESTS: usize = 128;
pub const MAX_REQUEST_HEADERS: usize = 64;
pub const MAX_HEADER_BYTES: usize = 32 * 1024;
pub const MAX_PROTOCOL_REQUEST_BODY_BYTES: usize = 256 * 1024;
pub const MAX_ECHO_REQUEST_BODY_BYTES: usize = 1024 * 1024;
pub const MAX_REQUEST_BODY_BYTES: usize = 10 * 1024 * 1024;
pub const HEADER_READ_TIMEOUT: Duration = Duration::from_secs(5);
pub const REQUEST_BODY_TIMEOUT: Duration = Duration::from_secs(30);
pub const RESPONSE_TIMEOUT: Duration = Duration::from_secs(30);
pub const HTTPS_CERT_ENV_VAR: &str = "KAGOME_HTTPS_CERT";
pub const HTTPS_KEY_ENV_VAR: &str = "KAGOME_HTTPS_KEY";

#[derive(Clone, Copy, Debug)]
pub struct ServerLimits {
    pub max_concurrent_connections: usize,
    pub max_concurrent_requests: usize,
    pub max_request_headers: usize,
    pub max_header_bytes: usize,
    pub header_read_timeout: Duration,
    pub request_body_timeout: Duration,
    pub response_timeout: Duration,
}

impl Default for ServerLimits {
    fn default() -> Self {
        Self {
            max_concurrent_connections: MAX_CONCURRENT_CONNECTIONS,
            max_concurrent_requests: MAX_CONCURRENT_REQUESTS,
            max_request_headers: MAX_REQUEST_HEADERS,
            max_header_bytes: MAX_HEADER_BYTES,
            header_read_timeout: HEADER_READ_TIMEOUT,
            request_body_timeout: REQUEST_BODY_TIMEOUT,
            response_timeout: RESPONSE_TIMEOUT,
        }
    }
}

#[derive(Clone)]
struct ApplicationState {
    limits: ServerLimits,
    request_permits: Arc<Semaphore>,
    rate_limiter: Option<Arc<crate::rate_limit::RateLimiter>>,
}

#[derive(Clone)]
struct ConnectionLimitAcceptor<A> {
    inner: A,
    permits: Arc<Semaphore>,
    handshake_timeout: Duration,
}

#[derive(Debug)]
struct ConnectionLimitedStream<S> {
    inner: S,
    _permit: OwnedSemaphorePermit,
}

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
    serve_listener_with_workers_tls_and_limits(
        listener,
        worker_count,
        tls_configuration,
        ServerLimits::default(),
        true,
    )
}

pub fn serve_listener_with_workers_and_limits(
    listener: TcpListener,
    worker_count: usize,
    limits: ServerLimits,
) -> io::Result<()> {
    serve_listener_with_workers_tls_and_limits(listener, worker_count, None, limits, false)
}

fn serve_listener_with_workers_tls_and_limits(
    listener: TcpListener,
    worker_count: usize,
    tls_configuration: Option<TlsConfiguration>,
    limits: ServerLimits,
    rate_limit_enabled: bool,
) -> io::Result<()> {
    validate_limits(limits)?;
    let worker_count = worker_count.max(1);
    let address = listener.local_addr()?;
    listener.set_nonblocking(true)?;

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(worker_count)
        .enable_all()
        .thread_name("kagome-http")
        .build()?;

    runtime.block_on(async move {
        let application =
            Router::new()
                .fallback(any(handle_request))
                .with_state(ApplicationState {
                    limits,
                    request_permits: Arc::new(Semaphore::new(limits.max_concurrent_requests)),
                    rate_limiter: rate_limit_enabled.then(|| {
                        Arc::new(crate::rate_limit::RateLimiter::new(
                            crate::config::Config::global().server.rate_limit,
                        ))
                    }),
                });
        let connection_permits = Arc::new(Semaphore::new(limits.max_concurrent_connections));

        match tls_configuration {
            Some(configuration) => {
                let tls = rustls_configuration(configuration).await?;
                let mut server = axum_server::from_tcp_rustls(listener, tls)?
                    .map(|acceptor| ConnectionLimitAcceptor {
                        inner: acceptor,
                        permits: connection_permits,
                        handshake_timeout: limits.header_read_timeout,
                    })
                    .http1_only();
                configure_http(&mut server, limits);
                println!("kagome listening on {address}\n");
                server
                    .serve(application.into_make_service_with_connect_info::<SocketAddr>())
                    .await
            }
            None => {
                let mut server = axum_server::from_tcp(listener)?
                    .map(|acceptor| ConnectionLimitAcceptor {
                        inner: acceptor,
                        permits: connection_permits,
                        handshake_timeout: limits.header_read_timeout,
                    })
                    .http1_only();
                configure_http(&mut server, limits);
                println!("kagome listening on {address}");
                server
                    .serve(application.into_make_service_with_connect_info::<SocketAddr>())
                    .await
            }
        }
    })
}

fn validate_limits(limits: ServerLimits) -> io::Result<()> {
    if limits.max_concurrent_connections == 0
        || limits.max_concurrent_requests == 0
        || limits.max_request_headers == 0
        || limits.max_header_bytes < 8192
        || limits.header_read_timeout.is_zero()
        || limits.request_body_timeout.is_zero()
        || limits.response_timeout.is_zero()
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "HTTP server limits must be non-zero and max_header_bytes must be at least 8192",
        ));
    }

    Ok(())
}

fn configure_http<A, Acceptor>(server: &mut axum_server::Server<A, Acceptor>, limits: ServerLimits)
where
    A: axum_server::Address,
{
    server
        .http_builder()
        .http1()
        .max_headers(limits.max_request_headers)
        .max_buf_size(limits.max_header_bytes)
        .header_read_timeout(limits.header_read_timeout)
        .timer(TokioTimer::new());
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

async fn handle_request(
    State(state): State<ApplicationState>,
    ConnectInfo(connect_info): ConnectInfo<SocketAddr>,
    request: Request<Body>,
) -> Response<Body> {
    let ip = connect_info.ip();
    if let Some(rate_limiter) = state.rate_limiter {
        match rate_limiter.throttle(ip) {
            crate::rate_limit::Decision::AllowAfter(delay) => tokio::time::sleep(delay).await,
            crate::rate_limit::Decision::Reject => {
                return text_response(StatusCode::TOO_MANY_REQUESTS, "");
            }
        }
    }
    if request.headers().len() > state.limits.max_request_headers
        || request_header_bytes(&request) > state.limits.max_header_bytes
    {
        return request_headers_too_large_response();
    }
    let keep_alive = request
        .headers()
        .get(CONNECTION)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value.eq_ignore_ascii_case("keep-alive"));

    let request_permit = match state.request_permits.clone().try_acquire_owned() {
        Ok(permit) => permit,
        Err(_) => return service_unavailable_response("request concurrency limit reached"),
    };
    let body_limit = request_body_limit(request.uri().path());
    let request = match timeout(
        state.limits.request_body_timeout,
        kagome_request(request, body_limit),
    )
    .await
    {
        Ok(Ok(request)) => request,
        Ok(Err(response)) => return *response,
        Err(_) => return request_timeout_response(),
    };

    blocking_response(
        move || raw_http_response(&crate::router::route_request(&request), keep_alive),
        request_permit,
        state.limits.response_timeout,
    )
    .await
}

fn request_header_bytes(request: &Request<Body>) -> usize {
    request.headers().iter().fold(0, |total, (name, value)| {
        total.saturating_add(name.as_str().len() + value.as_bytes().len() + 4)
    })
}

async fn blocking_response<F>(
    response: F,
    request_permit: OwnedSemaphorePermit,
    response_timeout: Duration,
) -> Response<Body>
where
    F: FnOnce() -> Response<Body> + Send + 'static,
{
    let response = tokio::task::spawn_blocking(move || {
        let _request_permit = request_permit;
        response()
    });
    match timeout(response_timeout, response).await {
        Ok(Ok(response)) => response,
        Ok(Err(error)) => blocking_task_error_response(error),
        Err(_) => service_unavailable_response("request processing timed out"),
    }
}

async fn kagome_request(
    request: Request<Body>,
    body_limit: usize,
) -> Result<KagomeRequest, Box<Response<Body>>> {
    let (parts, body) = request.into_parts();
    let body = to_bytes(body, body_limit)
        .await
        .map_err(|_| Box::new(payload_too_large_response(body_limit)))?;
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

fn request_body_limit(path: &str) -> usize {
    match path {
        "/credential" | "/presentation-response" => MAX_REQUEST_BODY_BYTES,
        "/echo" => MAX_ECHO_REQUEST_BODY_BYTES,
        _ => MAX_PROTOCOL_REQUEST_BODY_BYTES,
    }
}

fn payload_too_large_response(limit: usize) -> Response<Body> {
    text_response(
        StatusCode::PAYLOAD_TOO_LARGE,
        format!("request body exceeds {limit} bytes"),
    )
}

fn request_timeout_response() -> Response<Body> {
    text_response(StatusCode::REQUEST_TIMEOUT, "request body timed out")
}

fn request_headers_too_large_response() -> Response<Body> {
    text_response(
        StatusCode::REQUEST_HEADER_FIELDS_TOO_LARGE,
        "request headers are too large",
    )
}

fn service_unavailable_response(message: &'static str) -> Response<Body> {
    text_response(StatusCode::SERVICE_UNAVAILABLE, message)
}

fn blocking_task_error_response(_error: JoinError) -> Response<Body> {
    internal_server_error_response()
}

fn internal_server_error_response() -> Response<Body> {
    text_response(StatusCode::INTERNAL_SERVER_ERROR, "internal server error")
}

fn text_response(status: StatusCode, body: impl Into<Body>) -> Response<Body> {
    Response::builder()
        .status(status)
        .header("content-type", "text/plain; charset=utf-8")
        .header(CONNECTION, "close")
        .body(body.into())
        .expect("static HTTP response must be valid")
}

impl<I, S, A> Accept<I, S> for ConnectionLimitAcceptor<A>
where
    I: Send + 'static,
    S: Send + 'static,
    A: Accept<I, S> + Clone + Send + Sync + 'static,
    A::Stream: Send + 'static,
    A::Service: Send + 'static,
    A::Future: Send + 'static,
{
    type Stream = ConnectionLimitedStream<A::Stream>;
    type Service = A::Service;
    type Future = Pin<Box<dyn Future<Output = io::Result<(Self::Stream, Self::Service)>> + Send>>;

    fn accept(&self, stream: I, service: S) -> Self::Future {
        let acceptor = self.inner.clone();
        let permits = self.permits.clone();
        let handshake_timeout = self.handshake_timeout;

        Box::pin(async move {
            let permit = permits.try_acquire_owned().map_err(|_| {
                io::Error::new(io::ErrorKind::ConnectionAborted, "connection limit reached")
            })?;
            let (stream, service) = timeout(handshake_timeout, acceptor.accept(stream, service))
                .await
                .map_err(|_| {
                    io::Error::new(io::ErrorKind::TimedOut, "connection handshake timed out")
                })??;

            Ok((
                ConnectionLimitedStream {
                    inner: stream,
                    _permit: permit,
                },
                service,
            ))
        })
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for ConnectionLimitedStream<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(context, buffer)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for ConnectionLimitedStream<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<Result<usize, io::Error>> {
        Pin::new(&mut self.inner).poll_write(context, buffer)
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<Result<(), io::Error>> {
        Pin::new(&mut self.inner).poll_flush(context)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<Result<(), io::Error>> {
        Pin::new(&mut self.inner).poll_shutdown(context)
    }

    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }

    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffers: &[io::IoSlice<'_>],
    ) -> Poll<Result<usize, io::Error>> {
        Pin::new(&mut self.inner).poll_write_vectored(context, buffers)
    }
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

    #[test]
    fn assigns_smaller_body_limits_to_protocol_endpoints() {
        assert_eq!(
            request_body_limit("/token"),
            MAX_PROTOCOL_REQUEST_BODY_BYTES
        );
        assert_eq!(request_body_limit("/credential"), MAX_REQUEST_BODY_BYTES);
        assert_eq!(
            request_body_limit("/presentation-response"),
            MAX_REQUEST_BODY_BYTES
        );
        assert_eq!(request_body_limit("/echo"), MAX_ECHO_REQUEST_BODY_BYTES);
    }

    #[test]
    fn rejects_invalid_server_limits() {
        let defaults = ServerLimits::default();
        assert!(validate_limits(defaults).is_ok());

        for limits in [
            ServerLimits {
                max_concurrent_connections: 0,
                ..defaults
            },
            ServerLimits {
                max_concurrent_requests: 0,
                ..defaults
            },
            ServerLimits {
                max_request_headers: 0,
                ..defaults
            },
            ServerLimits {
                max_header_bytes: 8191,
                ..defaults
            },
            ServerLimits {
                header_read_timeout: Duration::ZERO,
                ..defaults
            },
            ServerLimits {
                request_body_timeout: Duration::ZERO,
                ..defaults
            },
            ServerLimits {
                response_timeout: Duration::ZERO,
                ..defaults
            },
        ] {
            assert_eq!(
                validate_limits(limits).unwrap_err().kind(),
                io::ErrorKind::InvalidInput
            );
        }
    }

    #[test]
    fn connection_acceptor_fails_closed_at_capacity() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async {
            let acceptor = ConnectionLimitAcceptor {
                inner: axum_server::accept::DefaultAcceptor,
                permits: Arc::new(Semaphore::new(1)),
                handshake_timeout: Duration::from_secs(1),
            };
            let (first, ()) = acceptor.accept("first", ()).await.unwrap();

            let error = acceptor.accept("second", ()).await.unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::ConnectionAborted);

            drop(first);
            assert!(acceptor.accept("third", ()).await.is_ok());
        });
    }

    #[test]
    fn rejects_requests_when_request_capacity_is_exhausted() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let response = runtime.block_on(handle_request(
            State(ApplicationState {
                limits: ServerLimits::default(),
                request_permits: Arc::new(Semaphore::new(0)),
                rate_limiter: None,
            }),
            ConnectInfo("127.0.0.1:4000".parse().unwrap()),
            Request::builder().uri("/echo").body(Body::empty()).unwrap(),
        ));

        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    #[test]
    fn times_out_response_generation() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let semaphore = Arc::new(Semaphore::new(1));
        let permit = runtime.block_on(semaphore.acquire_owned()).unwrap();
        let response = runtime.block_on(blocking_response(
            || {
                std::thread::sleep(Duration::from_millis(25));
                text_response(StatusCode::OK, "too late")
            },
            permit,
            Duration::from_millis(1),
        ));

        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    }
}
