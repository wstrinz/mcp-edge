use edge_auth::{
    config::Limits,
    owner::WebauthnOwnerProof,
    support::{StderrLog, SystemClock},
};
use mcp_edge::{
    app::{self, AppConfig, AppDeps, EdgeLimits},
    config::{EdgeConfig, RouteKind, DEFAULT_BIND},
    tunnel::{self, IrohDeps},
    Mode,
};
use std::{
    io::{Read, Write},
    net::{SocketAddr, TcpStream},
    sync::Arc,
    time::Duration,
};
use tokio::net::TcpListener;
use tokio_util::sync::CancellationToken;

// Health check talks only to this container's own loopback listener.
fn healthcheck() -> std::io::Result<()> {
    let bind: SocketAddr = std::env::var("EDGE_BIND")
        .unwrap_or_else(|_| DEFAULT_BIND.into())
        .parse()
        .map_err(|_| std::io::Error::other("bad EDGE_BIND"))?;
    let socket = SocketAddr::from(([127, 0, 0, 1], bind.port()));
    let limit = Duration::from_secs(2);
    let mut stream = TcpStream::connect_timeout(&socket, limit)?;
    stream.set_read_timeout(Some(limit))?;
    stream.set_write_timeout(Some(limit))?;
    stream.write_all(b"GET /healthz HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")?;
    let mut data = [0u8; 512];
    let mut count = 0;
    while count < data.len() {
        let received = stream.read(&mut data[count..])?;
        if received == 0 {
            break;
        }
        count += received;
        if data[..count].windows(2).any(|pair| pair == b"\r\n") {
            break;
        }
    }
    if data[..count].starts_with(b"HTTP/1.1 200 ") {
        Ok(())
    } else {
        Err(std::io::Error::other("health check failed"))
    }
}

async fn stopped() {
    #[cfg(unix)]
    {
        if let Ok(mut term) =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        {
            tokio::select! { _ = tokio::signal::ctrl_c() => {}, _ = term.recv() => {} }
            return;
        }
    }
    let _ = tokio::signal::ctrl_c().await;
}

fn fail(message: &str) -> ! {
    eprintln!("mcp-edge: {message}");
    std::process::exit(1);
}

async fn run_deny_all() {
    // The isolated container listener; tests use serve() on loopback instead.
    let listener = match TcpListener::bind(DEFAULT_BIND).await {
        Ok(listener) => listener,
        Err(_) => fail("listener unavailable"),
    };
    eprintln!("mcp-edge: deny-all; forwarding disabled");
    let stopping = CancellationToken::new();
    let signal = stopping.clone();
    tokio::spawn(async move {
        stopped().await;
        signal.cancel();
    });
    if mcp_edge::deny_all::serve(listener, stopping).await.is_err() {
        fail("listener stopped with error");
    }
}

async fn run_edge() {
    let cfg = match EdgeConfig::from_env(|k| std::env::var(k).ok(), |p| std::fs::read_to_string(p))
    {
        Ok(cfg) => cfg,
        Err(e) => fail(&e.to_string()),
    };
    let seed = match mcp_edge::keyfile::load_or_create_seed(&cfg.data_dir, "assertion-key.bin") {
        Ok(seed) => seed,
        // io::Error text is an OS message or our fixed wrong-size message; no key material.
        Err(e) => fail(&format!("assertion key unavailable: {e}")),
    };
    let origin = match url::Url::parse(&cfg.public_url) {
        Ok(u) => u,
        Err(_) => fail("EDGE_PUBLIC_URL"),
    };
    let proof = match WebauthnOwnerProof::new(&cfg.rp_id, &origin, &cfg.rp_name) {
        Ok(p) => p,
        Err(_) => fail("WebAuthn relying-party configuration rejected"),
    };
    let backend_ids: Vec<String> = cfg.routes.iter().map(|r| r.id.clone()).collect();
    // The iroh identity exists only when an iroh backend is configured. Its
    // file is created like the assertion key and never silently replaced (a
    // new id means re-enrolling every origin). A failed bind is not fatal:
    // health stays green and iroh routes answer `origin_offline`.
    let iroh = if cfg.routes.iter().any(|r| r.kind == RouteKind::Iroh) {
        let seed =
            match mcp_edge::keyfile::load_or_create_seed(&cfg.data_dir, tunnel::IROH_KEY_FILE) {
                Ok(seed) => seed,
                Err(e) => fail(&format!("iroh key unavailable: {e}")),
            };
        let secret_key = edge_tunnel::iroh::SecretKey::from_bytes(&seed);
        let endpoint = match tunnel::bind_edge_endpoint(secret_key.clone()).await {
            Ok(endpoint) => Some(endpoint),
            Err(why) => {
                eprintln!("mcp-edge: event=iroh_unavailable reason={why}");
                None
            }
        };
        eprintln!(
            "mcp-edge: iroh edge_id={}",
            edge_tunnel::ids::endpoint_id_hex(&secret_key.public())
        );
        Some(IrohDeps {
            secret_key,
            endpoint,
            client: edge_tunnel::client::ClientConfig::default(),
            addresses: Default::default(),
        })
    } else {
        None
    };
    let built = app::build(
        AppConfig {
            issuer: cfg.public_url.clone(),
            routes: cfg.routes,
            redirect_allowlist: cfg.redirect_allowlist,
            enroll_code: cfg.enroll_code,
            trusted_proxies: cfg.trusted_proxies,
            auth_limits: Limits::default(),
            edge_limits: EdgeLimits::default(),
        },
        AppDeps {
            db_path: Some(cfg.data_dir.join("edge.db")),
            proof: Arc::new(proof),
            clock: Arc::new(SystemClock),
            log: Arc::new(StderrLog),
            signing_seed: seed,
            iroh,
        },
    );
    let built = match built {
        Ok(b) => b,
        Err(e) => fail(&e.to_string()),
    };
    let listener = match TcpListener::bind(cfg.bind).await {
        Ok(listener) => listener,
        Err(_) => fail("listener unavailable"),
    };
    eprintln!(
        "mcp-edge: edge mode issuer={} backends={} assertion_key={}",
        cfg.public_url,
        backend_ids.join(","),
        built.assertion_public_key
    );
    let stopping = CancellationToken::new();
    let signal = stopping.clone();
    tokio::spawn(async move {
        stopped().await;
        signal.cancel();
    });
    let auth = built.auth.clone();
    let janitor = stopping.clone();
    tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = janitor.cancelled() => break,
                _ = tokio::time::sleep(Duration::from_secs(60)) => auth.cleanup(),
            }
        }
    });
    if mcp_edge::server::serve(listener, built.router, stopping)
        .await
        .is_err()
    {
        fail("listener stopped with error");
    }
}

#[tokio::main(flavor = "multi_thread", worker_threads = 2)]
async fn main() {
    let args: Vec<_> = std::env::args().skip(1).collect();
    if args == ["--healthcheck"] {
        if healthcheck().is_err() {
            std::process::exit(1);
        }
        return;
    }
    if !args.is_empty() {
        fail("refused unsupported arguments");
    }
    match Mode::parse(std::env::var("EDGE_MODE").ok().as_deref()) {
        Ok(Mode::DenyAll) => run_deny_all().await,
        Ok(Mode::Edge) => run_edge().await,
        Err(_) => fail("refused unsupported configuration"),
    }
}
