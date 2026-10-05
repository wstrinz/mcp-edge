use std::{
    io::{Read, Write},
    net::{SocketAddr, TcpStream},
    time::Duration,
};
use tokio::net::TcpListener;
use tokio_util::sync::CancellationToken;

// Health check talks only to this container's fixed loopback socket.
fn healthcheck() -> std::io::Result<()> {
    let socket: SocketAddr = "127.0.0.1:8080".parse().expect("constant socket");
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

#[tokio::main(flavor = "multi_thread", worker_threads = 2)]
async fn main() {
    let args: Vec<_> = std::env::args().skip(1).collect();
    if args == ["--healthcheck"] {
        if healthcheck().is_err() {
            std::process::exit(1);
        }
        return;
    }
    if !args.is_empty()
        || wiskit_gateway_inert::validate_mode(std::env::var("WISKIT_GATEWAY_MODE").ok().as_deref())
            .is_err()
    {
        eprintln!("gateway: refused unsupported configuration");
        std::process::exit(1);
    }
    // This bind is for the isolated container network. Native tests use serve()
    // with an OS-assigned 127.0.0.1 listener and never launch this main process.
    let listener = match TcpListener::bind("0.0.0.0:8080").await {
        Ok(listener) => listener,
        Err(_) => {
            eprintln!("gateway: listener unavailable");
            std::process::exit(1);
        }
    };
    eprintln!("gateway: deny-all; forwarding disabled");
    let stopping = CancellationToken::new();
    let signal = stopping.clone();
    tokio::spawn(async move {
        stopped().await;
        signal.cancel();
    });
    if wiskit_gateway_inert::serve(listener, stopping)
        .await
        .is_err()
    {
        eprintln!("gateway: listener stopped with error");
        std::process::exit(1);
    }
}
