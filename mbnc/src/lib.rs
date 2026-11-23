//! mbnc — a bouncer for MUDs, MOOs and other M*s.

pub mod backlog;
pub mod client;
pub mod config;
pub mod net;
pub mod registry;
pub mod session;
pub mod telnet;

use anyhow::{Context, Result};
use config::Config;
use registry::Registry;
use std::future::Future;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpListener;
use tracing::{info, warn};

const TLS_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(15);

/// Bind the configured address and serve until SIGINT/SIGTERM.
pub async fn run(cfg: Config) -> Result<()> {
    let listener = TcpListener::bind(&cfg.listen)
        .await
        .with_context(|| format!("binding {}", cfg.listen))?;
    serve(listener, cfg, shutdown_signal()).await
}

/// Serve on an already-bound listener until `shutdown` resolves.
pub async fn serve(listener: TcpListener, cfg: Config, shutdown: impl Future<Output = ()>) -> Result<()> {
    let cfg = Arc::new(cfg);
    let acceptor = match &cfg.tls {
        Some(t) => Some(net::tls_acceptor(&t.cert, &t.key)?),
        None => {
            warn!("TLS disabled: client connections are unencrypted");
            None
        }
    };
    let reg = Registry::load(cfg.clone())?;
    info!(addr = %listener.local_addr()?, tls = acceptor.is_some(), "listening");

    tokio::pin!(shutdown);
    loop {
        tokio::select! {
            r = listener.accept() => {
                let (tcp, peer) = match r {
                    Ok(x) => x,
                    Err(e) => {
                        warn!("accept failed: {e}");
                        tokio::time::sleep(Duration::from_millis(100)).await;
                        continue;
                    }
                };
                net::tune_socket(&tcp);
                let (reg, cfg, acceptor) = (reg.clone(), cfg.clone(), acceptor.clone());
                tokio::spawn(async move {
                    match acceptor {
                        None => client::handle(tcp, peer, reg, cfg).await,
                        Some(acc) => match tokio::time::timeout(TLS_HANDSHAKE_TIMEOUT, acc.accept(tcp)).await {
                            Ok(Ok(tls)) => client::handle(tls, peer, reg, cfg).await,
                            Ok(Err(e)) => info!(%peer, "TLS handshake failed: {e}"),
                            Err(_) => info!(%peer, "TLS handshake timed out"),
                        },
                    }
                });
            }
            _ = &mut shutdown => break,
        }
    }

    info!("shutting down; flushing backlogs");
    let mut flushes = tokio::task::JoinSet::new();
    for h in reg.all() {
        flushes.spawn(async move { h.shutdown().await });
    }
    if tokio::time::timeout(Duration::from_secs(10), flushes.join_all()).await.is_err() {
        warn!("some sessions did not flush in time");
    }
    Ok(())
}

async fn shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        let mut term = signal(SignalKind::terminate()).expect("install SIGTERM handler");
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {}
            _ = term.recv() => {}
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}
