//! Preparatory gateway container. No forwarding, credentials, peer identity,
//! metadata discovery, OAuth, enrollment, admin endpoint or file access exists.
use bytes::Bytes;
use http_body_util::Full;
use hyper::{
    body::Incoming,
    header::{CACHE_CONTROL, CONNECTION, CONTENT_TYPE, HOST},
    server::conn::http1,
    service::service_fn,
    Method, Request, Response, StatusCode,
};
use hyper_util::rt::{TokioIo, TokioTimer};
use std::{convert::Infallible, io, sync::Arc, time::Duration};
use tokio::{net::TcpListener, sync::Semaphore, task::JoinSet, time::timeout};
use tokio_util::sync::CancellationToken;

pub const MAX_CONNECTIONS: usize = 16;
pub const CONNECTION_DEADLINE: Duration = Duration::from_secs(5);

fn reply(status: StatusCode, body: &'static str, head: bool) -> Response<Full<Bytes>> {
    let bytes = if head {
        Bytes::new()
    } else {
        Bytes::from_static(body.as_bytes())
    };
    Response::builder()
        .status(status)
        .header(CONTENT_TYPE, "application/json")
        .header(CACHE_CONTROL, "no-store")
        .header(CONNECTION, "close")
        .header("x-content-type-options", "nosniff")
        .body(Full::new(bytes))
        .expect("constant response headers")
}

async fn handle(req: Request<Incoming>) -> Result<Response<Full<Bytes>>, Infallible> {
    let head = req.method() == Method::HEAD;
    // The inert server never interprets Host as a destination, even on errors.
    if req.uri().scheme().is_some()
        || req.uri().authority().is_some()
        || req.method() == Method::CONNECT
        || req.headers().get_all(HOST).iter().count() != 1
        || req
            .headers()
            .get(HOST)
            .is_none_or(|h| h.to_str().is_err() || h.as_bytes().len() > 253)
    {
        return Ok(reply(
            StatusCode::BAD_REQUEST,
            "{\"error\":\"invalid_request\"}",
            head,
        ));
    }
    let path = req.uri().path();
    if req.uri().query().is_some() {
        return Ok(reply(
            StatusCode::NOT_FOUND,
            "{\"error\":\"not_found\"}",
            head,
        ));
    }
    let (status, body) = match (req.method(), path) {
        (&Method::GET | &Method::HEAD, "/healthz") => (
            StatusCode::OK,
            "{\"status\":\"alive\",\"mode\":\"deny-all\"}",
        ),
        (_, "/readyz" | "/mcp") => (
            StatusCode::SERVICE_UNAVAILABLE,
            "{\"error\":\"forwarding_disabled\"}",
        ),
        _ => (StatusCode::NOT_FOUND, "{\"error\":\"not_found\"}"),
    };
    // Never read, reflect or log request bodies, Authorization, cookies or queries.
    // Closing the connection also prevents unconsumed-body request pipelining.
    Ok(reply(status, body, head))
}

/// Callers own the listener; local tests supply an OS-assigned loopback socket.
/// Every connection is capped in lifetime and has a bounded header parser.
pub async fn serve(listener: TcpListener, stopping: CancellationToken) -> io::Result<()> {
    let slots = Arc::new(Semaphore::new(MAX_CONNECTIONS));
    let mut tasks = JoinSet::new();
    loop {
        tokio::select! {
            biased;
            _ = stopping.cancelled() => break,
            _ = tasks.join_next(), if !tasks.is_empty() => {},
            accepted = listener.accept() => {
                let (socket, _) = accepted?;
                let Ok(permit) = slots.clone().try_acquire_owned() else {
                    drop(socket);
                    continue;
                };
                tasks.spawn(async move {
                    let _permit = permit;
                    let mut builder = http1::Builder::new();
                    builder
                        .timer(TokioTimer::new())
                        .header_read_timeout(CONNECTION_DEADLINE)
                        .max_headers(16)
                        .max_buf_size(16 * 1024)
                        .keep_alive(false);
                    let _ = timeout(
                        CONNECTION_DEADLINE,
                        builder.serve_connection(TokioIo::new(socket), service_fn(handle)),
                    ).await;
                    // Errors may contain client-controlled text; do not log them.
                });
            }
        }
    }
    tasks.abort_all();
    while tasks.join_next().await.is_some() {}
    Ok(())
}

pub fn validate_mode(mode: Option<&str>) -> io::Result<()> {
    match mode {
        None | Some("deny-all") => Ok(()),
        _ => Err(io::Error::other("unsupported gateway mode")),
    }
}
