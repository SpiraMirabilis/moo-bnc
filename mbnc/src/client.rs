//! One client connection: authentication, then multiplexed control + data.

use crate::config::Config;
use crate::registry::{Opened, Registry};
use crate::session::{ClientTx, SessionHandle};
use crate::telnet;
use anyhow::Result;
use mbnc_proto::{read_frame, ClientMsg, Frame, ServerMsg, SessionId, PROTOCOL_VERSION};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, BufWriter, ReadHalf, WriteHalf};
use tokio::sync::{mpsc, Notify};
use tracing::{info, warn};

const AUTH_TIMEOUT: Duration = Duration::from_secs(30);
const AUTH_FAIL_DELAY: Duration = Duration::from_secs(2);
/// Frames queued per client before it is considered too slow and dropped.
const CLIENT_QUEUE: usize = 4096;

static NEXT_CLIENT: AtomicU64 = AtomicU64::new(1);

pub async fn handle<S>(stream: S, peer: SocketAddr, reg: Arc<Registry>, cfg: Arc<Config>)
where
    S: AsyncRead + AsyncWrite + Send + 'static,
{
    let id = NEXT_CLIENT.fetch_add(1, Ordering::Relaxed);
    let (mut rd, wr) = tokio::io::split(stream);
    let (tx, rx) = mpsc::channel(CLIENT_QUEUE);
    let writer = tokio::spawn(write_loop(wr, rx));
    let mut conn = Conn {
        id,
        peer,
        tx,
        kill: Arc::new(Notify::new()),
        reg,
        cfg,
        attached: HashMap::new(),
    };
    info!(client = id, %peer, "client connected");
    match conn.run(&mut rd).await {
        Ok(()) => info!(client = id, %peer, "client disconnected"),
        Err(e) => info!(client = id, %peer, "client disconnected: {e:#}"),
    }
    for (_, a) in conn.attached.drain() {
        a.handle.detach(id).await;
    }
    drop(conn);
    // Let queued frames (e.g. an auth error) flush, but don't hang on a dead peer.
    let mut writer = writer;
    if tokio::time::timeout(Duration::from_secs(5), &mut writer).await.is_err() {
        writer.abort();
    }
}

async fn write_loop<S: AsyncWrite>(wr: WriteHalf<S>, mut rx: mpsc::Receiver<Frame>) {
    let mut w = BufWriter::with_capacity(64 * 1024, wr);
    let mut buf = Vec::new();
    while let Some(f) = rx.recv().await {
        buf.clear();
        f.encode(&mut buf);
        // Batch whatever else is already queued before flushing.
        while buf.len() < 256 * 1024 {
            match rx.try_recv() {
                Ok(f) => f.encode(&mut buf),
                Err(_) => break,
            }
        }
        if w.write_all(&buf).await.is_err() || w.flush().await.is_err() {
            return;
        }
    }
    let _ = w.shutdown().await;
}

struct Attachment {
    handle: SessionHandle,
    /// Client input may split telnet sequences across DATA frames.
    parser: telnet::Parser,
}

struct Conn {
    id: u64,
    peer: SocketAddr,
    tx: mpsc::Sender<Frame>,
    kill: Arc<Notify>,
    reg: Arc<Registry>,
    cfg: Arc<Config>,
    attached: HashMap<SessionId, Attachment>,
}

impl Conn {
    async fn send(&self, msg: ServerMsg) {
        let _ = self.tx.send(Frame::server(&msg)).await;
    }

    async fn error(&self, req: Option<u64>, session: Option<SessionId>, message: impl Into<String>) {
        self.send(ServerMsg::Error { req, session, message: message.into() }).await;
    }

    async fn run<S: AsyncRead>(&mut self, rd: &mut ReadHalf<S>) -> Result<()> {
        self.send(ServerMsg::Hello {
            server: format!("mbnc/{}", env!("CARGO_PKG_VERSION")),
            protocol: PROTOCOL_VERSION,
        })
        .await;

        // --- authentication ---
        let first = match tokio::time::timeout(AUTH_TIMEOUT, read_frame(rd)).await {
            Ok(r) => r?,
            Err(_) => {
                self.error(None, None, "authentication timed out").await;
                anyhow::bail!("authentication timed out");
            }
        };
        let Some(first) = first else { return Ok(()) };
        let password = match first.parse_client() {
            Ok(ClientMsg::Auth { password, client }) => {
                if let Some(c) = client {
                    info!(client = self.id, "client software: {c}");
                }
                password
            }
            _ => {
                self.error(None, None, "first message must be auth").await;
                anyhow::bail!("protocol error before auth");
            }
        };
        if !verify_password(&self.cfg.password_hash, password).await {
            warn!(client = self.id, peer = %self.peer, "authentication failed");
            tokio::time::sleep(AUTH_FAIL_DELAY).await;
            self.error(None, None, "authentication failed").await;
            anyhow::bail!("authentication failed");
        }
        self.send(ServerMsg::AuthOk).await;

        // --- main loop ---
        let kill = self.kill.clone();
        loop {
            let frame = tokio::select! {
                f = read_frame(rd) => f?,
                _ = kill.notified() => {
                    anyhow::bail!("dropped: client could not keep up with output");
                }
            };
            let Some(frame) = frame else { return Ok(()) };
            match frame {
                Frame::Control(_) => match frame.parse_client() {
                    Ok(msg) => self.handle_msg(msg).await,
                    Err(e) => self.error(None, None, e.to_string()).await,
                },
                Frame::Data { session, bytes } => self.handle_data(session, bytes).await,
                Frame::Backlog { session, .. } => {
                    self.error(None, Some(session), "clients may not send BACKLOG frames").await
                }
            }
        }
    }

    async fn handle_msg(&mut self, msg: ClientMsg) {
        match msg {
            ClientMsg::Auth { .. } => self.error(None, None, "already authenticated").await,
            ClientMsg::Ping { req } => self.send(ServerMsg::Pong { req }).await,
            ClientMsg::List { req } => {
                let mut sessions = Vec::new();
                for h in self.reg.all() {
                    if let Some(info) = h.info().await {
                        sessions.push(info);
                    }
                }
                sessions.sort_by_key(|s| s.session);
                self.send(ServerMsg::Sessions { req, sessions }).await;
            }
            ClientMsg::Open { req, world, character, login, telnet } => {
                match self.reg.open(world, character, login, telnet) {
                    Ok(Opened::Created(h)) => self.attach(h, req, true).await,
                    Ok(Opened::Existing(h, spec)) => {
                        h.update(spec).await;
                        h.connect().await;
                        self.attach(h, req, false).await;
                    }
                    Err(e) => self.error(req, None, format!("{e:#}")).await,
                }
            }
            ClientMsg::Attach { req, session } => match self.reg.get(session) {
                Some(h) => self.attach(h, req, false).await,
                None => self.error(req, Some(session), "no such session").await,
            },
            ClientMsg::Detach { req, session } => match self.attached.remove(&session) {
                Some(a) => {
                    a.handle.detach(self.id).await;
                    self.send(ServerMsg::Ok { req }).await;
                }
                None => self.error(req, Some(session), "not attached to that session").await,
            },
            ClientMsg::Reconnect { req, session } => match self.reg.get(session) {
                Some(h) if h.reconnect().await => self.send(ServerMsg::Ok { req }).await,
                _ => self.error(req, Some(session), "no such session").await,
            },
            ClientMsg::Close { req, session } => {
                self.attached.remove(&session);
                match self.reg.remove(session) {
                    Ok(Some(h)) => {
                        h.close("closed by client request".into()).await;
                        self.send(ServerMsg::Ok { req }).await;
                    }
                    Ok(None) => self.error(req, Some(session), "no such session").await,
                    Err(e) => self.error(req, Some(session), format!("{e:#}")).await,
                }
            }
        }
    }

    async fn attach(&mut self, handle: SessionHandle, req: Option<u64>, created: bool) {
        let sid = handle.id;
        if let Some(old) = self.attached.remove(&sid) {
            old.handle.detach(self.id).await;
        }
        let client = ClientTx { id: self.id, tx: self.tx.clone(), kill: self.kill.clone() };
        if handle.attach(client, req, created).await {
            self.attached.insert(sid, Attachment { handle, parser: telnet::Parser::new() });
        } else {
            self.error(req, Some(sid), "session no longer exists").await;
        }
    }

    async fn handle_data(&mut self, session: SessionId, bytes: Vec<u8>) {
        let Some(a) = self.attached.get_mut(&session) else {
            self.error(None, Some(session), "not attached to that session").await;
            return;
        };
        let mut events = Vec::new();
        a.parser.feed(&bytes, &mut events);
        if events.is_empty() {
            return;
        }
        if !a.handle.input(self.id, events).await {
            self.attached.remove(&session);
            self.error(None, Some(session), "session no longer exists").await;
        }
    }
}

async fn verify_password(hash: &str, password: String) -> bool {
    let hash = hash.to_string();
    tokio::task::spawn_blocking(move || {
        use argon2::password_hash::{PasswordHash, PasswordVerifier};
        match PasswordHash::new(&hash) {
            Ok(h) => argon2::Argon2::default().verify_password(password.as_bytes(), &h).is_ok(),
            Err(_) => false,
        }
    })
    .await
    .unwrap_or(false)
}
