use anyhow::Result;
use wiskit_edge_poc::{synthetic_request, Poc, HOSTNAME};

#[tokio::main]
async fn main() -> Result<()> {
    let poc = Poc::start().await?;
    let response = Poc::client()?
        .post(poc.url())
        .header("host", HOSTNAME)
        .json(&synthetic_request("synthetic_echo"))
        .send()
        .await?;
    println!("loopback synthetic transport: {}", response.status());
    println!("{}", response.text().await?);
    poc.shutdown().await;
    Ok(())
}
