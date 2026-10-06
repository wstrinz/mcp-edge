//! Bounded HTTP/1.1 accept loop for the edge router.

use axum::{extract::ConnectInfo, Router};
use hyper::{body::Incoming, server::conn::http1, Request};
use hyper_util::{
    rt::{TokioIo, TokioTimer},
    service::TowerToHyperService,
};
use std::{io, net::SocketAddr, sync::Arc, time::Duration};
use tokio::{net::TcpListener, sync::Semaphore, task::JoinSet, time::timeout};
use tokio_util::sync::CancellationToken;
use tower::ServiceExt;

/// Simultaneous connections; further connections are closed immediately.
pub const MAX_CONNECTIONS: usize = 128;
/// Time allowed to send request headers.
pub const HEADER_DEADLINE: Duration = Duration::from_secs(10);
/// Hard cap on one connection's lifetime (keep-alive included).
pub const CONNECTION_LIFETIME: Duration = Duration::from_secs(300);

/// Serve `router` on `listener` until `stopping` is cancelled. Callers own the
/// listener; tests pass an OS-assigned loopback socket.
pub async fn serve(
    listener: TcpListener,
    router: Router,
    stopping: CancellationToken,
) -> io::Result<()> {
    let slots = Arc::new(Semaphore::new(MAX_CONNECTIONS));
    let mut tasks = JoinSet::new();
    loop {
        tokio::select! {
            biased;
            _ = stopping.cancelled() => break,
            _ = tasks.join_next(), if !tasks.is_empty() => {},
            accepted = listener.accept() => {
                let (socket, peer) = match accepted {
                    Ok(pair) => pair,
                    Err(_) => {
                        // Transient (e.g. descriptor exhaustion); back off briefly.
                        tokio::time::sleep(Duration::from_millis(50)).await;
                        continue;
                    }
                };
                let Ok(permit) = slots.clone().try_acquire_owned() else {
                    drop(socket);
                    continue;
                };
                let svc = router.clone().map_request(move |mut req: Request<Incoming>| {
                    req.extensions_mut().insert(ConnectInfo::<SocketAddr>(peer));
                    req
                });
                tasks.spawn(async move {
                    let _permit = permit;
                    let mut builder = http1::Builder::new();
                    builder
                        .timer(TokioTimer::new())
                        .header_read_timeout(HEADER_DEADLINE)
                        .max_headers(64)
                        .max_buf_size(64 * 1024)
                        .keep_alive(true);
                    let conn = builder.serve_connection(
                        TokioIo::new(socket),
                        TowerToHyperService::new(svc),
                    );
                    // Errors may contain client-controlled text; do not log them.
                    let _ = timeout(CONNECTION_LIFETIME, conn).await;
                });
            }
        }
    }
    tasks.abort_all();
    while tasks.join_next().await.is_some() {}
    Ok(())
}
