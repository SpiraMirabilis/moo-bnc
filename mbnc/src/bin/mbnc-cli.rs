//! Bare-bones line-mode client for poking at an mbnc server.
//!
//! Not a MUD client: it strips telnet, prints text, and sends each stdin line.
//! Password is taken from $MBNC_PASSWORD.

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use mbnc::net::{self, BoxStream};
use mbnc::telnet;
use mbnc_proto::*;
use std::io::Write;
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::net::TcpStream;

#[derive(Parser)]
#[command(name = "mbnc-cli", about = "Minimal test client for mbnc")]
struct Cli {
    /// Bouncer address, host:port.
    #[arg(short, long, default_value = "127.0.0.1:7777")]
    server: String,
    /// Connect to the bouncer over TLS.
    #[arg(long)]
    tls: bool,
    /// With --tls: don't verify the bouncer's certificate.
    #[arg(long)]
    insecure: bool,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// List sessions.
    List,
    /// Open (create or resume) a session and interact with it.
    Open {
        host: String,
        port: u16,
        character: String,
        /// Connect to the M* with TLS.
        #[arg(long)]
        world_tls: bool,
        /// JSON file with login steps: [{"expect":"Name:","send":"bob"}, ...]
        #[arg(long)]
        login: Option<std::path::PathBuf>,
    },
    /// Attach to an existing session by id and interact with it.
    Attach { session: SessionId },
    /// Close (forget) a session.
    Close { session: SessionId },
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    let password = std::env::var("MBNC_PASSWORD").context("set MBNC_PASSWORD")?;
    let tcp = TcpStream::connect(&cli.server).await.with_context(|| format!("connecting to {}", cli.server))?;
    let stream: BoxStream = if cli.tls {
        let host = cli.server.rsplit_once(':').map(|(h, _)| h).unwrap_or(&cli.server);
        let name = rustls_pki_types::ServerName::try_from(host.trim_matches(['[', ']']).to_string())?;
        let cfg = net::client_tls_config(!cli.insecure)?;
        Box::new(tokio_rustls::TlsConnector::from(Arc::new(cfg)).connect(name, tcp).await?)
    } else {
        Box::new(tcp)
    };
    let (mut rd, mut wr) = tokio::io::split(stream);

    let _hello = next(&mut rd).await?;
    write_frame(&mut wr, &Frame::client(&ClientMsg::Auth { password, client: Some("mbnc-cli".into()) })).await?;
    match next(&mut rd).await?.parse_server()? {
        ServerMsg::AuthOk => {}
        m => bail!("auth failed: {m:?}"),
    }

    let req = match cli.cmd {
        Cmd::List => ClientMsg::List { req: None },
        Cmd::Close { session } => ClientMsg::Close { req: None, session },
        Cmd::Attach { session } => ClientMsg::Attach { req: None, session },
        Cmd::Open { host, port, character, world_tls, login } => {
            let login = match login {
                Some(p) => Some(serde_json::from_slice(&std::fs::read(&p)?)?),
                None => None,
            };
            ClientMsg::Open {
                req: None,
                world: World { host, port, tls: world_tls, verify_cert: false },
                character,
                login,
                telnet: None,
            }
        }
    };
    let interactive = matches!(req, ClientMsg::Open { .. } | ClientMsg::Attach { .. });
    write_frame(&mut wr, &Frame::client(&req)).await?;

    if !interactive {
        loop {
            let f = next(&mut rd).await?;
            if let Ok(m) = f.parse_server() {
                println!("{}", serde_json::to_string_pretty(&m)?);
                if matches!(m, ServerMsg::Sessions { .. } | ServerMsg::Ok { .. } | ServerMsg::Error { .. }) {
                    return Ok(());
                }
            }
        }
    }

    let session = loop {
        match next(&mut rd).await?.parse_server() {
            Ok(ServerMsg::Attached { info, created, .. }) => {
                eprintln!("*** attached to session {} ({})", info.session, if created { "new" } else { "resumed" });
                break info.session;
            }
            Ok(ServerMsg::Error { message, .. }) => bail!("{message}"),
            _ => {}
        }
    };

    // stdin -> server
    let writer = tokio::spawn(async move {
        let mut lines = BufReader::new(tokio::io::stdin()).lines();
        while let Ok(Some(line)) = lines.next_line().await {
            let mut bytes = Vec::new();
            telnet::escape_into(line.as_bytes(), &mut bytes);
            bytes.extend_from_slice(b"\r\n");
            if write_frame(&mut wr, &Frame::Data { session, bytes }).await.is_err() {
                break;
            }
        }
    });

    // server -> stdout
    let mut parser = telnet::Parser::new();
    let mut out = std::io::stdout();
    while let Some(f) = read_frame(&mut rd).await? {
        match f {
            Frame::Data { bytes, .. } | Frame::Backlog { bytes, .. } => {
                out.write_all(&telnet::strip(&mut parser, &bytes))?;
                out.flush()?;
            }
            Frame::Control(_) => match f.parse_server()? {
                ServerMsg::Notice { message, ts_ms, .. } => eprintln!("*** [{ts_ms}] {message}"),
                ServerMsg::Status { state, message, .. } => {
                    eprintln!("*** {state:?}: {}", message.unwrap_or_default())
                }
                ServerMsg::BacklogEnd { bytes, truncated, .. } => {
                    eprintln!("*** end of backlog ({bytes} bytes{})", if truncated { ", truncated" } else { "" })
                }
                m => eprintln!("*** {m:?}"),
            },
        }
    }
    writer.abort();
    Ok(())
}

async fn next<R: tokio::io::AsyncRead + Unpin>(rd: &mut R) -> Result<Frame> {
    read_frame(rd).await?.context("server closed the connection")
}
