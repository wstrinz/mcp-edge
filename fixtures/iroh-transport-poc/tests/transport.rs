//! Run serially: one test temporarily changes this test process's proxy env.
use anyhow::Result;
use futures_util::StreamExt;
use iroh::Endpoint;
use std::{
    sync::{atomic::Ordering, Arc},
    time::{Duration, Instant},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    time::timeout,
};
use wiskit_edge_poc::*;

async fn post(poc: &Poc, name: &str) -> Result<reqwest::Response> {
    Ok(Poc::client()?
        .post(poc.url())
        .header("host", HOSTNAME)
        .json(&synthetic_request(name))
        .send()
        .await?)
}
async fn wait_until(mut condition: impl FnMut() -> bool) {
    timeout(Duration::from_secs(3), async {
        while !condition() {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("bounded wait for state transition");
}
async fn raw_http(poc: &Poc, bytes: &[u8]) -> Result<String> {
    let mut socket = TcpStream::connect(poc.edge_addr).await?;
    socket.write_all(bytes).await?;
    let mut data = vec![0; 4096];
    let size = timeout(Duration::from_secs(3), socket.read(&mut data)).await??;
    Ok(String::from_utf8_lossy(&data[..size]).into_owned())
}
async fn wire_call(
    poc: &Poc,
    endpoint: &Endpoint,
    metadata: &[u8],
    body: &[u8],
    tail: &[u8],
) -> Result<ResponseMeta> {
    let connection = endpoint.connect(poc.origin_addr.clone(), ALPN).await?;
    let (mut send, mut recv) = connection.open_bi().await?;
    write_field(&mut send, metadata, MAX_META).await?;
    write_field(&mut send, body, MAX_REQUEST).await?;
    send.write_all(tail).await?;
    send.finish()?;
    Ok(serde_json::from_slice(
        &timeout(Duration::from_secs(3), read_field(&mut recv, MAX_META)).await??,
    )?)
}

#[tokio::test]
async fn synthetic_json_round_trip() -> Result<()> {
    let poc = Poc::start().await?;
    assert!(
        poc.edge_addr.ip().is_loopback()
            && poc.mock_addr.ip().is_loopback()
            && poc.trap_addr.ip().is_loopback()
    );
    checked_addr(&poc.gateway)?;
    assert!(poc
        .origin_addr
        .addrs
        .iter()
        .all(|a| matches!(a, iroh::TransportAddr::Ip(a) if a.ip().is_loopback())));
    let response = post(&poc, "synthetic_echo").await?;
    assert_eq!(response.status(), 200);
    let json: serde_json::Value = response.json().await?;
    assert_eq!(json["result"]["synthetic"], true);
    assert_eq!(json["result"]["echo"], synthetic_request("synthetic_echo"));
    assert_eq!(Metrics::get(&poc.metrics.dials), 1);
    assert_eq!(Metrics::get(&poc.metrics.mock_requests), 1);
    poc.shutdown().await;
    Ok(())
}

#[tokio::test]
async fn edge_admission_precedes_every_dial() -> Result<()> {
    let poc = Poc::start().await?;
    let response = Poc::client()?
        .post(poc.url())
        .header("host", "unknown.invalid")
        .json(&synthetic_request("synthetic_echo"))
        .send()
        .await?;
    assert_eq!(response.status(), 403);
    for method in [
        reqwest::Method::GET,
        reqwest::Method::DELETE,
        reqwest::Method::PUT,
    ] {
        assert_eq!(
            Poc::client()?
                .request(method, poc.url())
                .header("host", HOSTNAME)
                .send()
                .await?
                .status(),
            405
        );
    }
    for name in [
        "x-iroh-endpoint",
        "x-target-host",
        "x-target-port",
        "forwarded",
        "x-forwarded-host",
        "authorization",
        "upgrade",
    ] {
        let response = Poc::client()?
            .post(poc.url())
            .header("host", HOSTNAME)
            .header(name, "synthetic")
            .json(&synthetic_request("synthetic_echo"))
            .send()
            .await?;
        assert_eq!(response.status(), 400, "{name}");
    }
    let response = Poc::client()?
        .post(format!("{}?target=127.0.0.1", poc.url()))
        .header("host", HOSTNAME)
        .json(&synthetic_request("synthetic_echo"))
        .send()
        .await?;
    assert_eq!(response.status(), 404);
    assert!(raw_http(
        &poc,
        b"CONNECT 127.0.0.1:1 HTTP/1.1\r\nHost: poc.invalid\r\n\r\n"
    )
    .await?
    .starts_with("HTTP/1.1 400"));
    assert!(raw_http(&poc, b"POST http://127.0.0.1:1/mcp HTTP/1.1\r\nHost: poc.invalid\r\nContent-Length: 2\r\nContent-Type: application/json\r\n\r\n{}").await?.starts_with("HTTP/1.1 400"));
    let duplicate = raw_http(&poc, b"POST /mcp HTTP/1.1\r\nHost: poc.invalid\r\nHost: unknown.invalid\r\nContent-Length: 2\r\nContent-Type: application/json\r\n\r\n{}").await?;
    assert!(duplicate.starts_with("HTTP/1.1 400") || duplicate.starts_with("HTTP/1.1 403"));
    assert_eq!(Metrics::get(&poc.metrics.dials), 0);
    assert_eq!(Metrics::get(&poc.metrics.mock_requests), 0);
    poc.shutdown().await;
    Ok(())
}

#[tokio::test]
async fn incomplete_request_and_idle_response_have_deadlines() -> Result<()> {
    let poc = Poc::start().await?;
    let start = Instant::now();
    let incomplete = raw_http(&poc, b"POST /mcp HTTP/1.1\r\nHost: poc.invalid\r\nContent-Type: application/json\r\nContent-Length: 100\r\n\r\n{").await?;
    assert!(incomplete.starts_with("HTTP/1.1 408"));
    assert!(start.elapsed() < Duration::from_secs(3));
    assert_eq!(Metrics::get(&poc.metrics.dials), 0);
    let response = post(&poc, "synthetic_quiet").await?;
    assert_eq!(response.status(), 200);
    let start = Instant::now();
    assert!(response.bytes().await.is_err());
    assert!(start.elapsed() < Duration::from_secs(3));
    wait_until(|| Metrics::get(&poc.metrics.active_origin) == 0).await;
    poc.shutdown().await;
    Ok(())
}

#[tokio::test]
async fn origin_rejects_unadmitted_peer() -> Result<()> {
    let poc = Poc::start().await?;
    let rogue = loopback_endpoint().await?;
    assert!(wire_call(
        &poc,
        &rogue,
        &serde_json::to_vec(&Envelope::mcp())?,
        b"{}",
        b""
    )
    .await
    .is_err());
    wait_until(|| Metrics::get(&poc.metrics.rejected_peers) == 1).await;
    assert_eq!(Metrics::get(&poc.metrics.mock_requests), 0);
    rogue.close().await;
    poc.shutdown().await;
    Ok(())
}

#[tokio::test]
async fn origin_refuses_destination_fields_paths_and_smuggling() -> Result<()> {
    let poc = Poc::start().await?;
    for metadata in [
        serde_json::json!({"version":1,"path":"/mcp","content_type":"application/json","target_url":"http://127.0.0.1:1"}),
        serde_json::json!({"version":1,"path":"http://127.0.0.1:1/mcp","content_type":"application/json"}),
        serde_json::json!({"version":1,"path":"/other","content_type":"application/json"}),
        serde_json::json!({"version":2,"path":"/mcp","content_type":"application/json"}),
    ] {
        assert_eq!(
            wire_call(
                &poc,
                &poc.gateway,
                &serde_json::to_vec(&metadata)?,
                b"{}",
                b""
            )
            .await?
            .status,
            400
        );
    }
    assert_eq!(
        wire_call(
            &poc,
            &poc.gateway,
            &serde_json::to_vec(&Envelope::mcp())?,
            b"{}",
            b"another request"
        )
        .await?
        .status,
        400
    );
    assert_eq!(Metrics::get(&poc.metrics.mock_requests), 0);
    poc.shutdown().await;
    Ok(())
}

struct ProxyEnv(Vec<(&'static str, Option<std::ffi::OsString>)>);
impl ProxyEnv {
    fn poison(addr: std::net::SocketAddr) -> Self {
        let keys = [
            "HTTP_PROXY",
            "http_proxy",
            "HTTPS_PROXY",
            "https_proxy",
            "ALL_PROXY",
            "all_proxy",
            "NO_PROXY",
            "no_proxy",
        ];
        let previous = keys
            .iter()
            .map(|key| (*key, std::env::var_os(key)))
            .collect();
        for key in keys {
            std::env::set_var(
                key,
                if key.eq_ignore_ascii_case("no_proxy") {
                    String::new()
                } else {
                    format!("http://{addr}")
                },
            );
        }
        Self(previous)
    }
}
impl Drop for ProxyEnv {
    fn drop(&mut self) {
        for (key, value) in &self.0 {
            if let Some(value) = value {
                std::env::set_var(key, value);
            } else {
                std::env::remove_var(key);
            }
        }
    }
}

#[tokio::test]
async fn no_redirects_or_environment_proxy_escape() -> Result<()> {
    let metrics = Arc::new(Metrics::default());
    let trap = proxy_trap(metrics.clone()).await?;
    let control = reqwest::Client::builder()
        .proxy(reqwest::Proxy::all(format!("http://{}", trap.addr))?)
        .timeout(Duration::from_secs(2))
        .build()?;
    assert_eq!(
        control
            .get("http://127.0.0.1:1/control")
            .send()
            .await?
            .status(),
        200
    );
    assert_eq!(Metrics::get(&metrics.trap_requests), 1);
    metrics.trap_requests.store(0, Ordering::SeqCst);
    let guard = ProxyEnv::poison(trap.addr);
    let poc = Poc::start().await?;
    assert_eq!(post(&poc, "synthetic_echo").await?.status(), 200);
    let redirect = post(&poc, "synthetic_redirect").await?;
    assert_eq!(redirect.status(), 302);
    assert!(redirect.headers().get("location").is_none());
    assert_eq!(Metrics::get(&metrics.trap_requests), 0);
    assert_eq!(Metrics::get(&poc.metrics.trap_requests), 0);
    assert_eq!(Metrics::get(&poc.metrics.mock_requests), 2);
    drop(guard);
    poc.shutdown().await;
    trap.stop().await;
    Ok(())
}

#[tokio::test]
async fn request_size_and_wire_length_bounds() -> Result<()> {
    let poc = Poc::start().await?;
    let response = Poc::client()?
        .post(poc.url())
        .header("host", HOSTNAME)
        .header("content-type", "application/json")
        .body(vec![b'x'; MAX_REQUEST + 1])
        .send()
        .await?;
    assert_eq!(response.status(), 413);
    assert_eq!(Metrics::get(&poc.metrics.dials), 0);
    for body_length in [false, true] {
        let connection = poc.gateway.connect(poc.origin_addr.clone(), ALPN).await?;
        let (mut send, mut recv) = connection.open_bi().await?;
        if body_length {
            write_field(&mut send, &serde_json::to_vec(&Envelope::mcp())?, MAX_META).await?;
        }
        send.write_all(
            &((if body_length { MAX_REQUEST } else { MAX_META }) as u32 + 1).to_be_bytes(),
        )
        .await?;
        send.finish()?;
        let meta: ResponseMeta = serde_json::from_slice(
            &timeout(Duration::from_secs(3), read_field(&mut recv, MAX_META)).await??,
        )?;
        assert_eq!(meta.status, 400);
    }
    assert_eq!(Metrics::get(&poc.metrics.mock_requests), 0);
    poc.shutdown().await;
    Ok(())
}

#[tokio::test]
async fn streaming_is_incremental() -> Result<()> {
    let poc = Poc::start().await?;
    let response = post(&poc, "synthetic_stream").await?;
    assert_eq!(response.headers()["content-type"], "text/event-stream");
    let mut stream = response.bytes_stream();
    let first = stream.next().await.unwrap()?;
    assert!(String::from_utf8_lossy(&first).contains("synthetic_chunk\":0"));
    let start = Instant::now();
    let mut rest = Vec::new();
    while let Some(chunk) = stream.next().await {
        rest.extend_from_slice(&chunk?);
    }
    assert!(start.elapsed() >= Duration::from_millis(250));
    assert!(String::from_utf8_lossy(&rest).contains("synthetic_chunk\":3"));
    poc.shutdown().await;
    Ok(())
}

#[tokio::test]
async fn concurrency_lease_and_disconnect_cancellation() -> Result<()> {
    let poc = Poc::start().await?;
    let first = post(&poc, "synthetic_quiet").await?;
    let second = post(&poc, "synthetic_quiet").await?;
    assert_eq!(first.status(), 200);
    assert_eq!(second.status(), 200);
    assert_eq!(Metrics::get(&poc.metrics.active_origin), MAX_ACTIVE);
    assert_eq!(post(&poc, "synthetic_echo").await?.status(), 429);
    drop(first);
    drop(second);
    let dropped_at = Instant::now();
    wait_until(|| Metrics::get(&poc.metrics.active_origin) == 0).await;
    eprintln!(
        "response drop: released in {:?}, cancelled={}",
        dropped_at.elapsed(),
        Metrics::get(&poc.metrics.cancelled)
    );
    assert!(
        dropped_at.elapsed() < Duration::from_secs(1),
        "disconnect must release before the idle deadline"
    );
    assert!(Metrics::get(&poc.metrics.cancelled) >= 2);
    wait_until(|| Metrics::get(&poc.metrics.active_mock) == 0).await;
    assert!(
        dropped_at.elapsed() < Duration::from_secs(1),
        "disconnect must reach the mock before the idle deadline"
    );
    assert_eq!(Metrics::get(&poc.metrics.cancelled_mock), 2);
    assert_eq!(post(&poc, "synthetic_echo").await?.status(), 200);
    poc.shutdown().await;
    Ok(())
}

#[tokio::test]
async fn origin_concurrency_is_global_across_connections() -> Result<()> {
    let poc = Poc::start().await?;
    let meta = serde_json::to_vec(&Envelope::mcp())?;
    let body = serde_json::to_vec(&synthetic_request("synthetic_quiet"))?;
    let mut held = Vec::new();
    for _ in 0..MAX_ACTIVE {
        let connection = poc.gateway.connect(poc.origin_addr.clone(), ALPN).await?;
        let (mut send, mut recv) = connection.open_bi().await?;
        write_field(&mut send, &meta, MAX_META).await?;
        write_field(&mut send, &body, MAX_REQUEST).await?;
        send.finish()?;
        let response: ResponseMeta = serde_json::from_slice(
            &timeout(Duration::from_secs(3), read_field(&mut recv, MAX_META)).await??,
        )?;
        assert_eq!(response.status, 200);
        held.push((connection, recv));
    }
    assert_eq!(
        wire_call(&poc, &poc.gateway, &meta, b"{}", b"")
            .await?
            .status,
        429
    );
    for (_, recv) in &mut held {
        recv.stop(iroh::endpoint::VarInt::from_u32(7))?;
    }
    drop(held);
    wait_until(|| Metrics::get(&poc.metrics.active_origin) == 0).await;
    poc.shutdown().await;
    Ok(())
}

#[tokio::test]
async fn stalled_http_reader_applies_backpressure_and_cancels() -> Result<()> {
    let poc = Poc::start().await?;
    let mut socket = TcpStream::connect(poc.edge_addr).await?;
    socket2::SockRef::from(&socket).set_recv_buffer_size(8192)?;
    let body = serde_json::to_string(&synthetic_request("synthetic_flood"))?;
    socket.write_all(format!("POST /mcp HTTP/1.1\r\nHost: {HOSTNAME}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}", body.len()).as_bytes()).await?;
    wait_until(|| Metrics::get(&poc.metrics.wire_chunks) > 0).await;
    tokio::time::sleep(Duration::from_millis(250)).await;
    let before = Metrics::get(&poc.metrics.wire_chunks);
    tokio::time::sleep(Duration::from_millis(250)).await;
    let after = Metrics::get(&poc.metrics.wire_chunks);
    eprintln!("stalled-reader wire chunks: before={before}, after={after}");
    assert!(
        after <= before + 2,
        "stalled reader: before={before}, after={after}"
    );
    assert!(
        after < MAX_RESPONSE / MAX_CHUNK,
        "backpressure must precede the response cap"
    );
    assert_eq!(Metrics::get(&poc.metrics.active_origin), 1);
    drop(socket);
    wait_until(|| Metrics::get(&poc.metrics.active_origin) == 0).await;
    assert!(Metrics::get(&poc.metrics.cancelled) >= 1);
    poc.shutdown().await;
    Ok(())
}

#[tokio::test]
async fn response_cap_and_origin_offline() -> Result<()> {
    let mut poc = Poc::start().await?;
    let mut stream = post(&poc, "synthetic_flood").await?.bytes_stream();
    let mut count = 0;
    let mut interrupted = false;
    while let Some(chunk) = stream.next().await {
        match chunk {
            Ok(bytes) => count += bytes.len(),
            Err(_) => {
                interrupted = true;
                break;
            }
        }
    }
    assert!(
        interrupted,
        "oversize stream cannot look successfully complete"
    );
    assert!(count <= MAX_RESPONSE);
    drop(stream);
    wait_until(|| Metrics::get(&poc.metrics.active_origin) == 0).await;
    poc.stop_origin().await;
    let start = Instant::now();
    assert!(matches!(
        post(&poc, "synthetic_echo").await?.status().as_u16(),
        502 | 504
    ));
    assert!(start.elapsed() < Duration::from_secs(4));
    poc.shutdown().await;
    Ok(())
}
