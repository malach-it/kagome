use std::{
    io,
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

use crate::unit::{HttpHeader, KagomeRequest};

pub const DEFAULT_WORKERS: usize = 4;
pub const MAX_REQUEST_BODY_BYTES: usize = 10 * 1024 * 1024;

pub fn serve(address: impl ToSocketAddrs) -> io::Result<()> {
    serve_with_workers(address, DEFAULT_WORKERS)
}

pub fn serve_with_workers(address: impl ToSocketAddrs, worker_count: usize) -> io::Result<()> {
    let listener = TcpListener::bind(address)?;

    serve_listener_with_workers(listener, worker_count)
}

pub fn serve_listener_with_workers(listener: TcpListener, worker_count: usize) -> io::Result<()> {
    let worker_count = worker_count.max(1);
    println!("{}", listener.local_addr()?);
    listener.set_nonblocking(true)?;

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(worker_count)
        .enable_all()
        .thread_name("kagome-http")
        .build()?;

    runtime.block_on(async move {
        let listener = tokio::net::TcpListener::from_std(listener)?;
        let application = Router::new().fallback(any(handle_request));

        axum::serve(listener, application).await
    })
}

async fn handle_request(request: Request<Body>) -> Response<Body> {
    let keep_alive = request
        .headers()
        .get(CONNECTION)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value.eq_ignore_ascii_case("keep-alive"));

    let request = match kagome_request(request).await {
        Ok(request) => request,
        Err(response) => return response,
    };

    raw_http_response(&crate::router::route_request(&request), keep_alive)
}

async fn kagome_request(request: Request<Body>) -> Result<KagomeRequest, Response<Body>> {
    let (parts, body) = request.into_parts();
    let body = to_bytes(body, MAX_REQUEST_BODY_BYTES)
        .await
        .map_err(|_| payload_too_large_response())?;
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
}
