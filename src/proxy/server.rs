use crate::config::Config;
use crate::engine::rules::RuleEngine;
use crate::proxy::handler::LatchHandler;
use crate::proxy::tls::load_ca;
use crate::vault::VaultBackend;

use hudsucker::rustls::crypto::aws_lc_rs;
use hudsucker::Proxy;
use std::net::SocketAddr;
use std::path::Path;
use thiserror::Error;
use tokio::sync::oneshot;
use tracing::info;

#[derive(Debug, Error)]
pub enum ServerError {
    #[error("failed to load CA: {0}")]
    Tls(#[from] crate::proxy::tls::TlsError),
    #[error("failed to compile rules: {0}")]
    Rules(#[from] globset::Error),
    #[error("failed to parse listen address: {0}")]
    AddrParse(#[from] std::net::AddrParseError),
    #[error("proxy error: {0}")]
    Proxy(#[from] hudsucker::Error),
}

pub async fn run_proxy(
    config: &Config,
    vault: Box<dyn VaultBackend>,
    config_dir: &Path,
    shutdown_rx: oneshot::Receiver<()>,
) -> Result<(), ServerError> {
    let ca = load_ca(config_dir)?;
    let engine = RuleEngine::new(config.rules.clone())?;
    let handler =
        LatchHandler::new(engine, vault, config.signature.clone(), &config.mitm.domains)?;

    let addr: SocketAddr = config.proxy.listen.parse()?;

    info!(addr = %addr, "starting network-latch proxy");

    let proxy = Proxy::builder()
        .with_addr(addr)
        .with_ca(ca)
        .with_rustls_connector(aws_lc_rs::default_provider())
        .with_http_handler(handler)
        .with_graceful_shutdown(async move {
            let _ = shutdown_rx.await;
        })
        .build()?;

    proxy.start().await?;

    info!("proxy shut down");
    Ok(())
}
