//! One persistent connection to an M* for one character.
//!
//! Each session is an actor task owning the upstream socket. Clients attach
//! by handing it a [`ClientTx`]; output goes to all attached clients, or into
//! the [`Backlog`] when none are attached.
//!
//! Telnet negotiation with the M* is owned by the proxy (it must keep
//! answering while nobody is attached). Clients see *state changes* as
//! synthetic WILL/WONT/DO/DONT, plus a snapshot of the current state on
//! attach; their own negotiation replies are swallowed. See PROTOCOL.md.

use crate::backlog::{Backlog, Entry};
use crate::config::Config;
use crate::net::{self, BoxStream};
use crate::telnet::{self, opt, Event, DO, DONT, IAC, NOP, TTYPE_IS, TTYPE_SEND, WILL, WONT};
use mbnc_proto::{ConnState, Frame, LoginStep, ServerMsg, SessionId, SessionInfo, TelnetPrefs, World};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncReadExt, AsyncWriteExt, ReadHalf, WriteHalf};
use tokio::sync::{mpsc, oneshot, Notify};
use tokio::task::JoinHandle;
use tokio::time::Instant;
use tracing::{info, warn};

/// How long a single frame send to a client may block during backlog replay.
const REPLAY_SEND_TIMEOUT: Duration = Duration::from_secs(30);
const UPSTREAM_WRITE_TIMEOUT: Duration = Duration::from_secs(30);
/// A connection that lasted this long resets the reconnect backoff.
const STABLE_CONNECTION_MS: i64 = 60_000;
const LOGIN_BUF_MAX: usize = 16 * 1024;

pub fn now_ms() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_millis() as i64).unwrap_or(0)
}

/// Everything needed to (re)create a session; persisted in sessions.json.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SessionSpec {
    pub id: SessionId,
    pub world: World,
    pub character: String,
    #[serde(default)]
    pub login: Vec<LoginStep>,
    #[serde(default)]
    pub telnet: TelnetPrefs,
}

/// Identity of a session: (host, port, character), case-insensitive.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SessionKey {
    host: String,
    port: u16,
    character: String,
}

impl SessionKey {
    pub fn new(world: &World, character: &str) -> SessionKey {
        SessionKey {
            host: world.host.trim().to_ascii_lowercase(),
            port: world.port,
            character: character.trim().to_lowercase(),
        }
    }
}

impl SessionSpec {
    pub fn key(&self) -> SessionKey {
        SessionKey::new(&self.world, &self.character)
    }
}

/// A client connection's outbound queue, as seen by a session.
#[derive(Clone)]
pub struct ClientTx {
    pub id: u64,
    pub tx: mpsc::Sender<Frame>,
    /// Signalled when the session gives up on this client (queue full).
    pub kill: Arc<Notify>,
}

pub enum SessionCmd {
    Attach { client: ClientTx, req: Option<u64>, created: bool },
    Detach { client_id: u64 },
    Input { client_id: u64, events: Vec<Event> },
    Update(SessionSpec),
    /// Connect if currently disconnected.
    Connect,
    /// Drop any current connection and connect again.
    Reconnect,
    Info(oneshot::Sender<SessionInfo>),
    Close { reason: String, done: oneshot::Sender<()> },
    Shutdown(oneshot::Sender<()>),
    // internal
    Connected { gen: u64, result: Result<BoxStream, String> },
    Upstream { gen: u64, data: Vec<u8> },
    UpstreamClosed { gen: u64, reason: String },
}

#[derive(Clone)]
pub struct SessionHandle {
    pub id: SessionId,
    tx: mpsc::Sender<SessionCmd>,
}

impl SessionHandle {
    async fn send(&self, cmd: SessionCmd) -> bool {
        self.tx.send(cmd).await.is_ok()
    }
    pub async fn attach(&self, client: ClientTx, req: Option<u64>, created: bool) -> bool {
        self.send(SessionCmd::Attach { client, req, created }).await
    }
    pub async fn detach(&self, client_id: u64) {
        self.send(SessionCmd::Detach { client_id }).await;
    }
    pub async fn input(&self, client_id: u64, events: Vec<Event>) -> bool {
        self.send(SessionCmd::Input { client_id, events }).await
    }
    pub async fn update(&self, spec: SessionSpec) {
        self.send(SessionCmd::Update(spec)).await;
    }
    pub async fn connect(&self) {
        self.send(SessionCmd::Connect).await;
    }
    pub async fn reconnect(&self) -> bool {
        self.send(SessionCmd::Reconnect).await
    }
    pub async fn info(&self) -> Option<SessionInfo> {
        let (tx, rx) = oneshot::channel();
        if !self.send(SessionCmd::Info(tx)).await {
            return None;
        }
        rx.await.ok()
    }
    pub async fn close(&self, reason: String) {
        let (done, rx) = oneshot::channel();
        if self.send(SessionCmd::Close { reason, done }).await {
            let _ = rx.await;
        }
    }
    pub async fn shutdown(&self) {
        let (tx, rx) = oneshot::channel();
        if self.send(SessionCmd::Shutdown(tx)).await {
            let _ = rx.await;
        }
    }
}

pub fn spawn(spec: SessionSpec, cfg: Arc<Config>) -> std::io::Result<SessionHandle> {
    let dir = cfg.data_dir.join("sessions").join(spec.id.to_string());
    let backlog = Backlog::open(&dir, cfg.backlog.memory_bytes, cfg.backlog.disk_bytes)?;
    let (tx, rx) = mpsc::channel(256);
    let id = spec.id;
    let session = Session {
        id,
        backoff: cfg.reconnect.initial_delay(),
        spec,
        cfg,
        rx,
        self_tx: tx.clone(),
        state: ConnState::Disconnected,
        gen: 0,
        writer: None,
        reader_task: None,
        connect_task: None,
        parser: telnet::Parser::new(),
        remote: [false; 256],
        local: [false; 256],
        refused: [false; 256],
        ttype_idx: 0,
        naws: None,
        clients: HashMap::new(),
        backlog,
        want_connected: true,
        reconnect_at: None,
        login_queue: VecDeque::new(),
        login_buf: String::new(),
        login_deadline: None,
        login_delay: None,
        login_armed: false,
        held_input: Vec::new(),
        connected_since: None,
        last_activity: None,
    };
    tokio::spawn(session.run());
    Ok(SessionHandle { id, tx })
}

struct Session {
    id: SessionId,
    spec: SessionSpec,
    cfg: Arc<Config>,
    rx: mpsc::Receiver<SessionCmd>,
    self_tx: mpsc::Sender<SessionCmd>,

    state: ConnState,
    /// Bumped on every connect/teardown so stale internal messages are ignored.
    gen: u64,
    writer: Option<WriteHalf<BoxStream>>,
    reader_task: Option<JoinHandle<()>>,
    connect_task: Option<JoinHandle<()>>,

    parser: telnet::Parser,
    /// Options enabled on the server side (server WILL, we DO).
    remote: [bool; 256],
    /// Options enabled on our side (server DO, we WILL).
    local: [bool; 256],
    /// Options we've already refused this connection (avoid negotiation loops).
    refused: [bool; 256],
    ttype_idx: usize,
    /// Last window size reported by a client.
    naws: Option<(u16, u16)>,

    clients: HashMap<u64, ClientTx>,
    backlog: Backlog,

    want_connected: bool,
    backoff: Duration,
    reconnect_at: Option<Instant>,

    login_queue: VecDeque<LoginStep>,
    login_buf: String,
    login_deadline: Option<Instant>,
    /// When the front login step (already matched) should be sent.
    login_delay: Option<Instant>,
    /// The front login step's `expect` has matched and it is waiting on `delay_ms`.
    login_armed: bool,
    /// Client input received while the login script runs; sent once it finishes.
    held_input: Vec<u8>,

    connected_since: Option<i64>,
    last_activity: Option<i64>,
}

async fn sleep_until_opt(at: Option<Instant>) {
    match at {
        Some(t) => tokio::time::sleep_until(t).await,
        None => std::future::pending().await,
    }
}

impl Session {
    async fn run(mut self) {
        info!(session = self.id, host = %self.spec.world.host, port = self.spec.world.port,
              character = %self.spec.character, "session started");
        self.start_connect().await;
        loop {
            tokio::select! {
                cmd = self.rx.recv() => {
                    let Some(cmd) = cmd else { break };
                    if !self.handle(cmd).await {
                        break;
                    }
                }
                _ = sleep_until_opt(self.reconnect_at) => {
                    self.reconnect_at = None;
                    if self.state == ConnState::Disconnected && self.want_connected {
                        self.start_connect().await;
                    }
                }
                _ = sleep_until_opt(self.login_delay) => {
                    self.login_delay = None;
                    let mut to_server = Vec::new();
                    self.advance_login(&mut to_server).await;
                    self.write_upstream(&to_server).await;
                }
                _ = sleep_until_opt(self.login_deadline) => {
                    self.login_deadline = None;
                    self.login_delay = None;
                    self.login_armed = false;
                    self.login_queue.clear();
                    self.login_buf.clear();
                    self.notice("login script timed out waiting for expected text".into()).await;
                    let held = std::mem::take(&mut self.held_input);
                    self.write_upstream(&held).await;
                }
            }
        }
        self.teardown();
        info!(session = self.id, "session ended");
    }

    /// Returns false when the actor should exit.
    async fn handle(&mut self, cmd: SessionCmd) -> bool {
        match cmd {
            SessionCmd::Attach { client, req, created } => self.attach(client, req, created).await,
            SessionCmd::Detach { client_id } => {
                self.clients.remove(&client_id);
            }
            SessionCmd::Input { client_id, events } => self.client_input(client_id, events).await,
            SessionCmd::Update(spec) => self.spec = spec,
            SessionCmd::Connect => {
                self.want_connected = true;
                if self.state == ConnState::Disconnected {
                    self.backoff = self.cfg.reconnect.initial_delay();
                    self.start_connect().await;
                }
            }
            SessionCmd::Reconnect => {
                self.want_connected = true;
                self.backoff = self.cfg.reconnect.initial_delay();
                self.start_connect().await;
            }
            SessionCmd::Info(tx) => {
                let _ = tx.send(self.info());
            }
            SessionCmd::Close { reason, done } => {
                info!(session = self.id, "closing: {reason}");
                self.teardown();
                self.broadcast(Frame::server(&ServerMsg::Closed { session: self.id, reason }));
                self.clients.clear();
                self.backlog.destroy().await;
                let _ = done.send(());
                return false;
            }
            SessionCmd::Shutdown(done) => {
                if let Err(e) = self.backlog.spill().await {
                    warn!(session = self.id, "flushing backlog on shutdown: {e}");
                }
                let _ = done.send(());
                return false;
            }
            SessionCmd::Connected { gen, result } => self.on_connected(gen, result).await,
            SessionCmd::Upstream { gen, data } => {
                if gen == self.gen {
                    self.on_upstream(&data).await;
                }
            }
            SessionCmd::UpstreamClosed { gen, reason } => {
                if gen == self.gen && self.state == ConnState::Connected {
                    self.upstream_lost(reason).await;
                }
            }
        }
        true
    }

    fn info(&self) -> SessionInfo {
        SessionInfo {
            session: self.id,
            host: self.spec.world.host.clone(),
            port: self.spec.world.port,
            tls: self.spec.world.tls,
            character: self.spec.character.clone(),
            state: self.state,
            attached: self.clients.len() as u32,
            backlog_bytes: self.backlog.total_bytes(),
            connected_since: self.connected_since,
            last_activity: self.last_activity,
        }
    }

    // ----- client fan-out -------------------------------------------------

    /// Non-blocking send to every attached client; clients whose queue is
    /// full are dropped (and their connection killed).
    fn broadcast(&mut self, frame: Frame) {
        let mut dead = Vec::new();
        for (id, c) in &self.clients {
            match c.tx.try_send(frame.clone()) {
                Ok(()) => {}
                Err(mpsc::error::TrySendError::Full(_)) => {
                    warn!(session = self.id, client = id, "client too slow; disconnecting it");
                    c.kill.notify_one();
                    dead.push(*id);
                }
                Err(mpsc::error::TrySendError::Closed(_)) => dead.push(*id),
            }
        }
        for id in dead {
            self.clients.remove(&id);
        }
    }

    /// Deliver telnet stream bytes live, or buffer them.
    async fn deliver(&mut self, bytes: Vec<u8>) {
        if bytes.is_empty() {
            return;
        }
        if self.clients.is_empty() {
            self.backlog.push_data(now_ms(), &bytes).await;
        } else {
            self.broadcast(Frame::Data { session: self.id, bytes });
        }
    }

    async fn notice(&mut self, message: String) {
        info!(session = self.id, "{message}");
        let ts_ms = now_ms();
        if self.clients.is_empty() {
            self.backlog.push_notice(ts_ms, message).await;
        } else {
            self.broadcast(Frame::server(&ServerMsg::Notice { session: self.id, ts_ms, message }));
        }
    }

    async fn set_state(&mut self, state: ConnState, message: String) {
        self.state = state;
        info!(session = self.id, ?state, "{message}");
        if self.clients.is_empty() {
            self.backlog.push_notice(now_ms(), message).await;
        } else {
            self.broadcast(Frame::server(&ServerMsg::Status {
                session: self.id,
                state,
                message: Some(message),
            }));
        }
    }

    async fn attach(&mut self, client: ClientTx, req: Option<u64>, created: bool) {
        async fn send(c: &ClientTx, f: Frame) -> bool {
            matches!(tokio::time::timeout(REPLAY_SEND_TIMEOUT, c.tx.send(f)).await, Ok(Ok(())))
        }

        let mut info = self.info();
        info.attached += 1;
        if !send(&client, Frame::server(&ServerMsg::Attached { req, created, info })).await {
            return;
        }

        // Current option state, so the client's telnet layer matches the server's.
        let mut snap = Vec::new();
        for o in 0..=255u8 {
            if self.remote[o as usize] {
                snap.extend_from_slice(&[IAC, WILL, o]);
            }
            if self.local[o as usize] && o != opt::TTYPE {
                snap.extend_from_slice(&[IAC, DO, o]);
            }
        }
        if !snap.is_empty() && !send(&client, Frame::Data { session: self.id, bytes: snap }).await {
            return;
        }

        // Replay backlog. If the client goes away mid-replay, put the
        // unsent remainder back so nothing is lost.
        let mut drain = self.backlog.take();
        let mut bytes = 0u64;
        let mut failed = false;
        let mut unsent = Vec::new();
        loop {
            let e = match drain.next().await {
                Ok(Some(e)) => e,
                Ok(None) => break,
                Err(err) => {
                    warn!(session = self.id, "reading backlog: {err}");
                    break;
                }
            };
            if failed {
                unsent.push(e);
                continue;
            }
            let frame = match &e {
                Entry::Data { ts_ms, bytes: b } => {
                    bytes += b.len() as u64;
                    Frame::Backlog { session: self.id, ts_ms: *ts_ms, bytes: b.clone() }
                }
                Entry::Notice { ts_ms, text } => Frame::server(&ServerMsg::Notice {
                    session: self.id,
                    ts_ms: *ts_ms,
                    message: text.clone(),
                }),
            };
            if !send(&client, frame).await {
                failed = true;
                unsent.push(e);
            }
        }
        let truncated = drain.truncated;
        drain.finish().await;
        if failed {
            for e in unsent {
                match e {
                    Entry::Data { ts_ms, bytes } => self.backlog.push_data(ts_ms, &bytes).await,
                    Entry::Notice { ts_ms, text } => self.backlog.push_notice(ts_ms, text).await,
                }
            }
            return;
        }
        let end = ServerMsg::BacklogEnd { session: self.id, bytes, truncated };
        if send(&client, Frame::server(&end)).await {
            info!(session = self.id, client = client.id, replayed = bytes, "client attached");
            self.clients.insert(client.id, client);
        }
    }

    // ----- upstream connection -------------------------------------------

    async fn start_connect(&mut self) {
        self.teardown();
        self.reconnect_at = None;
        let gen = self.gen;
        let World { host, port, tls, verify_cert } = self.spec.world.clone();
        let tx = self.self_tx.clone();
        let limit = self.cfg.reconnect.connect_timeout();
        let msg = format!("connecting to {host}:{port}{}", if tls { " (TLS)" } else { "" });
        self.connect_task = Some(tokio::spawn(async move {
            let result = match tokio::time::timeout(limit, net::connect_upstream(&host, port, tls, verify_cert)).await {
                Ok(Ok(s)) => Ok(s),
                Ok(Err(e)) => Err(format!("{e:#}")),
                Err(_) => Err("connection attempt timed out".to_string()),
            };
            let _ = tx.send(SessionCmd::Connected { gen, result }).await;
        }));
        self.set_state(ConnState::Connecting, msg).await;
    }

    /// Drop any connection / attempt and reset per-connection state.
    fn teardown(&mut self) {
        self.gen += 1;
        if let Some(t) = self.connect_task.take() {
            t.abort();
        }
        if let Some(t) = self.reader_task.take() {
            t.abort();
        }
        self.writer = None;
        self.login_queue.clear();
        self.login_buf.clear();
        self.login_deadline = None;
        self.login_delay = None;
        self.login_armed = false;
        self.held_input.clear();
        self.connected_since = None;
        self.reset_options();
    }

    /// Turn off all negotiated options, telling attached clients.
    fn reset_options(&mut self) {
        let mut b = Vec::new();
        for o in 0..=255u8 {
            if self.remote[o as usize] {
                b.extend_from_slice(&[IAC, WONT, o]);
            }
            if self.local[o as usize] && o != opt::TTYPE {
                b.extend_from_slice(&[IAC, DONT, o]);
            }
        }
        self.remote = [false; 256];
        self.local = [false; 256];
        self.refused = [false; 256];
        self.ttype_idx = 0;
        self.parser = telnet::Parser::new();
        if !b.is_empty() && !self.clients.is_empty() {
            self.broadcast(Frame::Data { session: self.id, bytes: b });
        }
    }

    async fn on_connected(&mut self, gen: u64, result: Result<BoxStream, String>) {
        if gen != self.gen {
            return; // superseded; dropping the stream closes it
        }
        self.connect_task = None;
        match result {
            Ok(stream) => {
                let (r, w) = tokio::io::split(stream);
                self.writer = Some(w);
                self.reader_task = Some(tokio::spawn(read_loop(r, gen, self.self_tx.clone())));
                self.connected_since = Some(now_ms());
                let (host, port) = (self.spec.world.host.clone(), self.spec.world.port);
                self.set_state(ConnState::Connected, format!("connected to {host}:{port}")).await;

                self.login_queue = self.spec.login.iter().cloned().collect();
                if !self.login_queue.is_empty() {
                    self.login_deadline = Some(Instant::now() + self.cfg.reconnect.login_timeout());
                    let mut to_server = Vec::new();
                    self.advance_login(&mut to_server).await;
                    self.write_upstream(&to_server).await;
                }
            }
            Err(msg) => {
                self.set_state(ConnState::Disconnected, format!("connection failed: {msg}")).await;
                if self.want_connected {
                    self.schedule_reconnect().await;
                }
            }
        }
    }

    async fn upstream_lost(&mut self, reason: String) {
        let lived = self.connected_since.map(|t| now_ms() - t).unwrap_or(0);
        self.teardown();
        if lived >= STABLE_CONNECTION_MS {
            self.backoff = self.cfg.reconnect.initial_delay();
        }
        self.set_state(ConnState::Disconnected, reason).await;
        if !self.clients.is_empty() {
            // Someone is watching: maybe they typed QUIT. Let them decide.
            self.want_connected = false;
        } else if self.want_connected && self.cfg.reconnect.enabled {
            self.schedule_reconnect().await;
        }
    }

    async fn schedule_reconnect(&mut self) {
        let d = self.backoff;
        self.reconnect_at = Some(Instant::now() + d);
        self.backoff = (d * 2).min(self.cfg.reconnect.max_delay());
        self.notice(format!("reconnecting in {}s", d.as_secs())).await;
    }

    async fn write_upstream(&mut self, bytes: &[u8]) {
        if bytes.is_empty() {
            return;
        }
        let Some(w) = self.writer.as_mut() else { return };
        let r = tokio::time::timeout(UPSTREAM_WRITE_TIMEOUT, async {
            w.write_all(bytes).await?;
            w.flush().await
        })
        .await;
        match r {
            Ok(Ok(())) => {}
            Ok(Err(e)) => self.upstream_lost(format!("write error: {e}")).await,
            Err(_) => self.upstream_lost("write to server timed out".into()).await,
        }
    }

    // ----- server -> clients ---------------------------------------------

    async fn on_upstream(&mut self, data: &[u8]) {
        self.last_activity = Some(now_ms());
        let mut events = Vec::new();
        self.parser.feed(data, &mut events);
        let live = !self.clients.is_empty();
        let mut out = Vec::with_capacity(data.len());
        let mut to_server = Vec::new();
        let mut saw_text = false;
        for ev in events {
            match ev {
                Event::Data(d) => {
                    if !self.login_queue.is_empty() {
                        self.login_buf.push_str(&String::from_utf8_lossy(&d));
                        saw_text = true;
                    }
                    telnet::escape_into(&d, &mut out);
                }
                Event::Command(NOP) => {}
                Event::Command(c) => out.extend_from_slice(&[IAC, c]),
                Event::Negotiate(verb, o) => self.server_negotiate(verb, o, live, &mut out, &mut to_server),
                Event::Sub(opt::TTYPE, p) => {
                    if p.first() == Some(&TTYPE_SEND) && self.local[opt::TTYPE as usize] {
                        self.send_ttype(&mut to_server);
                    }
                }
                Event::Sub(o, p) => telnet::encode_sub(o, &p, &mut out),
            }
        }
        if saw_text {
            if self.login_buf.len() > LOGIN_BUF_MAX {
                let mut cut = self.login_buf.len() - LOGIN_BUF_MAX / 2;
                while !self.login_buf.is_char_boundary(cut) {
                    cut += 1;
                }
                self.login_buf.drain(..cut);
            }
            self.advance_login(&mut to_server).await;
        }
        self.deliver(out).await;
        self.write_upstream(&to_server).await;
    }

    fn accept_remote(&self, o: u8) -> bool {
        !matches!(o, opt::COMPRESS2 | opt::COMPRESS3 | opt::TTYPE | opt::NAWS)
            && self.spec.telnet.server_options.contains(&o)
    }

    fn accept_local(&self, o: u8) -> bool {
        !matches!(o, opt::COMPRESS2 | opt::COMPRESS3 | opt::ECHO)
            && self.spec.telnet.client_options.contains(&o)
    }

    fn server_negotiate(&mut self, verb: u8, o: u8, live: bool, out: &mut Vec<u8>, to_server: &mut Vec<u8>) {
        let i = o as usize;
        match verb {
            WILL => {
                if self.accept_remote(o) {
                    if !self.remote[i] {
                        self.remote[i] = true;
                        to_server.extend_from_slice(&[IAC, DO, o]);
                        if live {
                            out.extend_from_slice(&[IAC, WILL, o]);
                        }
                    }
                } else if !self.refused[i] {
                    self.refused[i] = true;
                    to_server.extend_from_slice(&[IAC, DONT, o]);
                }
            }
            WONT if self.remote[i] => {
                self.remote[i] = false;
                to_server.extend_from_slice(&[IAC, DONT, o]);
                if live {
                    out.extend_from_slice(&[IAC, WONT, o]);
                }
            }
            DO => {
                if self.accept_local(o) {
                    if !self.local[i] {
                        self.local[i] = true;
                        to_server.extend_from_slice(&[IAC, WILL, o]);
                        if o == opt::NAWS {
                            self.send_naws(to_server);
                        }
                        if live && o != opt::TTYPE {
                            out.extend_from_slice(&[IAC, DO, o]);
                        }
                    }
                } else if !self.refused[i] {
                    self.refused[i] = true;
                    to_server.extend_from_slice(&[IAC, WONT, o]);
                }
            }
            DONT if self.local[i] => {
                self.local[i] = false;
                to_server.extend_from_slice(&[IAC, WONT, o]);
                if live && o != opt::TTYPE {
                    out.extend_from_slice(&[IAC, DONT, o]);
                }
            }
            _ => {}
        }
    }

    fn send_naws(&self, to_server: &mut Vec<u8>) {
        let (w, h) = self.naws.unwrap_or(self.spec.telnet.naws);
        let p = [(w >> 8) as u8, w as u8, (h >> 8) as u8, h as u8];
        telnet::encode_sub(opt::NAWS, &p, to_server);
    }

    /// MTTS: send each name in turn, repeat the last once, then start over.
    fn send_ttype(&mut self, to_server: &mut Vec<u8>) {
        let list = &self.spec.telnet.ttype;
        let name = if list.is_empty() {
            "MBNC".to_string()
        } else {
            list[self.ttype_idx.min(list.len() - 1)].clone()
        };
        self.ttype_idx = if self.ttype_idx >= list.len() { 0 } else { self.ttype_idx + 1 };
        let mut p = vec![TTYPE_IS];
        p.extend_from_slice(name.as_bytes());
        telnet::encode_sub(opt::TTYPE, &p, to_server);
    }

    /// Send every login step whose `expect` has been satisfied.
    async fn advance_login(&mut self, to_server: &mut Vec<u8>) {
        let mut progressed = false;
        while let Some(step) = self.login_queue.front() {
            if self.login_armed {
                if self.login_delay.is_some() {
                    break; // still waiting out delay_ms
                }
            } else {
                if let Some(pat) = step.expect.as_deref().filter(|p| !p.is_empty()) {
                    match self.login_buf.find(pat) {
                        Some(pos) => {
                            self.login_buf.drain(..pos + pat.len());
                        }
                        None => break,
                    }
                }
                if let Some(ms) = step.delay_ms.filter(|&ms| ms > 0) {
                    let d = Duration::from_millis(ms);
                    self.login_armed = true;
                    self.login_delay = Some(Instant::now() + d);
                    // Deliberate waits don't count against the login timeout.
                    self.login_deadline = self.login_deadline.map(|t| t + d);
                    break;
                }
            }
            telnet::escape_into(step.send.as_bytes(), to_server);
            to_server.extend_from_slice(b"\r\n");
            self.login_queue.pop_front();
            self.login_armed = false;
            progressed = true;
        }
        if progressed && self.login_queue.is_empty() {
            self.login_deadline = None;
            self.login_buf.clear();
            to_server.append(&mut self.held_input);
            self.notice("login script completed".into()).await;
        }
    }

    // ----- client -> server ----------------------------------------------

    async fn client_input(&mut self, client_id: u64, events: Vec<Event>) {
        if self.state != ConnState::Connected {
            if events.iter().any(|e| matches!(e, Event::Data(_))) {
                if let Some(c) = self.clients.get(&client_id) {
                    let _ = c.tx.try_send(Frame::server(&ServerMsg::Error {
                        req: None,
                        session: Some(self.id),
                        message: "not connected to the server; input discarded".into(),
                    }));
                }
            }
            return;
        }
        let mut buf = Vec::new();
        for ev in events {
            match ev {
                Event::Data(d) => telnet::escape_into(&d, &mut buf),
                Event::Command(c) => buf.extend_from_slice(&[IAC, c]),
                // The proxy owns option negotiation with the server.
                Event::Negotiate(..) => {}
                Event::Sub(opt::TTYPE, _) => {}
                Event::Sub(opt::NAWS, p) => {
                    if p.len() == 4 {
                        self.naws = Some((u16::from_be_bytes([p[0], p[1]]), u16::from_be_bytes([p[2], p[3]])));
                    }
                    if self.local[opt::NAWS as usize] {
                        telnet::encode_sub(opt::NAWS, &p, &mut buf);
                    }
                }
                Event::Sub(o, p) => {
                    if self.remote[o as usize] || self.local[o as usize] {
                        telnet::encode_sub(o, &p, &mut buf);
                    }
                }
            }
        }
        if !self.login_queue.is_empty() {
            // Don't let the user's typing interleave with the login script.
            self.held_input.extend_from_slice(&buf);
            return;
        }
        self.write_upstream(&buf).await;
    }
}

async fn read_loop(mut r: ReadHalf<BoxStream>, gen: u64, tx: mpsc::Sender<SessionCmd>) {
    let mut buf = vec![0u8; 16 * 1024];
    let reason = loop {
        match r.read(&mut buf).await {
            Ok(0) => break "connection closed by server".to_string(),
            Ok(n) => {
                if tx.send(SessionCmd::Upstream { gen, data: buf[..n].to_vec() }).await.is_err() {
                    return;
                }
            }
            Err(e) => break format!("read error: {e}"),
        }
    };
    let _ = tx.send(SessionCmd::UpstreamClosed { gen, reason }).await;
}
