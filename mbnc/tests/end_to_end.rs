//! Drives a real mbnc server against a fake MUD over loopback.

use mbnc::config::{BacklogConfig, Config, ReconnectConfig};
use mbnc::telnet::{self, opt, DO, DONT, IAC, WILL, WONT};
use mbnc_proto::*;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt, ReadHalf, WriteHalf};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, oneshot};

const T: Duration = Duration::from_secs(10);

// ---------------------------------------------------------------- fake MUD

enum MudCmd {
    Say(String),
    Kick,
}

#[derive(Clone)]
struct FakeMud {
    port: u16,
    connections: Arc<AtomicUsize>,
    logins: Arc<AtomicUsize>,
    /// Raw bytes received on the most recent connection.
    received: Arc<Mutex<Vec<u8>>>,
    current: Arc<Mutex<Option<mpsc::UnboundedSender<MudCmd>>>>,
}

impl FakeMud {
    async fn start() -> FakeMud {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mud = FakeMud {
            port: l.local_addr().unwrap().port(),
            connections: Default::default(),
            logins: Default::default(),
            received: Default::default(),
            current: Default::default(),
        };
        let m = mud.clone();
        tokio::spawn(async move {
            loop {
                let (s, _) = l.accept().await.unwrap();
                m.connections.fetch_add(1, Ordering::SeqCst);
                let (tx, rx) = mpsc::unbounded_channel();
                *m.current.lock().unwrap() = Some(tx);
                m.received.lock().unwrap().clear();
                tokio::spawn(m.clone().serve(s, rx));
            }
        });
        mud
    }

    fn cmd(&self, c: MudCmd) {
        self.current.lock().unwrap().as_ref().unwrap().send(c).ok();
    }

    async fn serve(self, mut s: TcpStream, mut rx: mpsc::UnboundedReceiver<MudCmd>) {
        let mut hello = vec![IAC, WILL, opt::GMCP, IAC, WILL, opt::COMPRESS2, IAC, DO, opt::NAWS, IAC, DO, opt::TTYPE];
        hello.extend_from_slice(b"Welcome to FakeMUD\r\nName? ");
        s.write_all(&hello).await.unwrap();
        let mut parser = telnet::Parser::new();
        let mut line = Vec::new();
        let mut stage = 0;
        let mut buf = [0u8; 4096];
        loop {
            tokio::select! {
                n = s.read(&mut buf) => {
                    let n = n.unwrap_or(0);
                    if n == 0 { return; }
                    self.received.lock().unwrap().extend_from_slice(&buf[..n]);
                    // Ask for terminal type whenever the client agrees to send it.
                    if buf[..n].windows(3).any(|w| w == [IAC, WILL, opt::TTYPE]) {
                        s.write_all(&[IAC, telnet::SB, opt::TTYPE, 1, IAC, telnet::SE]).await.unwrap();
                    }
                    for b in telnet::strip(&mut parser, &buf[..n]) {
                        if b == b'\n' {
                            let l = String::from_utf8_lossy(&line).trim().to_string();
                            line.clear();
                            let reply: Vec<u8> = match stage {
                                0 => { stage = 1; let mut v = b"Password? ".to_vec(); v.extend_from_slice(&[IAC, WILL, opt::ECHO]); assert_eq!(l, "bob"); v }
                                1 => {
                                    stage = 2;
                                    assert_eq!(l, "secret");
                                    self.logins.fetch_add(1, Ordering::SeqCst);
                                    let mut v = vec![IAC, WONT, opt::ECHO];
                                    v.extend_from_slice(b"\r\nWelcome bob!\r\n");
                                    v
                                }
                                _ => format!("You said: {l}\r\n").into_bytes(),
                            };
                            s.write_all(&reply).await.unwrap();
                        } else if b != b'\r' {
                            line.push(b);
                        }
                    }
                }
                c = rx.recv() => match c {
                    Some(MudCmd::Say(t)) => s.write_all(t.as_bytes()).await.unwrap(),
                    Some(MudCmd::Kick) | None => return,
                }
            }
        }
    }
}

// ---------------------------------------------------------------- client

struct Client {
    rd: ReadHalf<TcpStream>,
    wr: WriteHalf<TcpStream>,
}

impl Client {
    async fn connect(port: u16, password: &str) -> Result<Client, String> {
        let s = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        let (rd, wr) = tokio::io::split(s);
        let mut c = Client { rd, wr };
        match c.msg().await {
            ServerMsg::Hello { protocol, .. } => assert_eq!(protocol, PROTOCOL_VERSION),
            m => panic!("expected hello, got {m:?}"),
        }
        c.ctl(ClientMsg::Auth { password: password.into(), client: Some("test".into()) }).await;
        match c.msg().await {
            ServerMsg::AuthOk => Ok(c),
            ServerMsg::Error { message, .. } => Err(message),
            m => panic!("unexpected {m:?}"),
        }
    }

    async fn ctl(&mut self, m: ClientMsg) {
        write_frame(&mut self.wr, &Frame::client(&m)).await.unwrap();
    }

    async fn send_line(&mut self, session: SessionId, line: &str) {
        let f = Frame::Data { session, bytes: format!("{line}\r\n").into_bytes() };
        write_frame(&mut self.wr, &f).await.unwrap();
    }

    async fn frame(&mut self) -> Frame {
        tokio::time::timeout(T, read_frame(&mut self.rd))
            .await
            .expect("timed out waiting for frame")
            .unwrap()
            .expect("connection closed")
    }

    async fn msg(&mut self) -> ServerMsg {
        self.frame().await.parse_server().unwrap()
    }

    /// Read frames until the session's text output contains `needle`.
    async fn until_text(&mut self, needle: &str) -> Vec<Frame> {
        let mut parser = telnet::Parser::new();
        let mut text = String::new();
        let mut seen = Vec::new();
        while !text.contains(needle) {
            let f = self.frame().await;
            if let Frame::Data { bytes, .. } | Frame::Backlog { bytes, .. } = &f {
                text.push_str(&String::from_utf8_lossy(&telnet::strip(&mut parser, bytes)));
            }
            seen.push(f);
        }
        seen
    }
}

fn world(port: u16) -> World {
    World { host: "127.0.0.1".into(), port, tls: false, verify_cert: true }
}

fn contains(hay: &[u8], needle: &[u8]) -> bool {
    hay.windows(needle.len()).any(|w| w == needle)
}

async fn wait_for(what: &str, mut f: impl FnMut() -> bool) {
    let deadline = tokio::time::Instant::now() + T;
    while !f() {
        assert!(tokio::time::Instant::now() < deadline, "timed out waiting for {what}");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

struct Server {
    port: u16,
    stop: Option<oneshot::Sender<()>>,
    task: tokio::task::JoinHandle<()>,
}

impl Server {
    async fn start(cfg: Config) -> Server {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = l.local_addr().unwrap().port();
        let (stop, rx) = oneshot::channel::<()>();
        let task = tokio::spawn(async move {
            mbnc::serve(l, cfg, async {
                let _ = rx.await;
            })
            .await
            .unwrap();
        });
        Server { port, stop: Some(stop), task }
    }

    async fn stop(mut self) {
        self.stop.take().unwrap().send(()).unwrap();
        self.task.await.unwrap();
    }
}

fn config(data_dir: &std::path::Path, password: &str) -> Config {
    use argon2::password_hash::{PasswordHasher, SaltString};
    let salt = SaltString::encode_b64(b"test-salt-123456").unwrap();
    // Cheap params: this is a test.
    let a = argon2::Argon2::new(
        argon2::Algorithm::Argon2id,
        argon2::Version::V0x13,
        argon2::Params::new(1024, 1, 1, None).unwrap(),
    );
    Config {
        listen: "unused".into(),
        data_dir: data_dir.to_path_buf(),
        password_hash: a.hash_password(password.as_bytes(), &salt).unwrap().to_string(),
        tls: None,
        allow_plaintext: true,
        backlog: BacklogConfig { memory_bytes: 64, disk_bytes: 1 << 20 }, // force spill to disk
        reconnect: ReconnectConfig { initial_delay_secs: 1, ..Default::default() },
    }
}

// ---------------------------------------------------------------- the test

#[tokio::test]
async fn bouncer_end_to_end() {
    let mud = FakeMud::start().await;
    let dir = tempfile::tempdir().unwrap();
    let server = Server::start(config(dir.path(), "hunter2")).await;

    // Wrong password is rejected.
    assert_eq!(Client::connect(server.port, "nope").await.err().as_deref(), Some("authentication failed"));

    // --- First client: creates the session; the proxy logs in. ---
    let mut a = Client::connect(server.port, "hunter2").await.unwrap();
    a.ctl(ClientMsg::Open {
        req: Some(1),
        world: world(mud.port),
        character: "bob".into(),
        login: Some(vec![
            LoginStep { expect: Some("Name?".into()), send: "bob".into(), delay_ms: None },
            // delay after a match also works
            LoginStep { expect: Some("Password?".into()), send: "secret".into(), delay_ms: Some(50) },
        ]),
        telnet: None,
    })
    .await;
    let sid = match a.msg().await {
        ServerMsg::Attached { req: Some(1), created: true, info } => info.session,
        m => panic!("unexpected {m:?}"),
    };
    let frames = a.until_text("Welcome bob!").await;
    let live: Vec<u8> = frames
        .iter()
        .filter_map(|f| match f {
            Frame::Data { bytes, .. } | Frame::Backlog { bytes, .. } => Some(bytes.clone()),
            _ => None,
        })
        .flatten()
        .collect();
    // Password-mode echo toggling reaches the client.
    assert!(contains(&live, &[IAC, WILL, opt::ECHO]));
    assert!(contains(&live, &[IAC, WONT, opt::ECHO]));
    // MCCP must never reach the client.
    assert!(!contains(&live, &[IAC, WILL, opt::COMPRESS2]));

    a.send_line(sid, "hello there").await;
    a.until_text("You said: hello there").await;

    {
        let got = mud.received.lock().unwrap().clone();
        assert!(contains(&got, &[IAC, DONT, opt::COMPRESS2]), "proxy refuses MCCP");
        assert!(contains(&got, &[IAC, DO, opt::GMCP]));
        assert!(contains(&got, &[IAC, WILL, opt::NAWS]));
        assert!(contains(&got, &[IAC, telnet::SB, opt::NAWS, 0, 80, 0, 24, IAC, telnet::SE]));
        assert!(contains(&got, b"\xff\xfa\x18\x00MBNC\xff\xf0"), "proxy answers TTYPE");
    }
    assert_eq!(mud.logins.load(Ordering::SeqCst), 1);

    // --- Client goes away; output accumulates in the backlog. ---
    drop(a);
    tokio::time::sleep(Duration::from_millis(200)).await;
    mud.cmd(MudCmd::Say("A dragon arrives.\r\n".into()));
    mud.cmd(MudCmd::Say("The dragon breathes fire!\r\n".into()));
    tokio::time::sleep(Duration::from_millis(200)).await;

    // --- Second client: lists, then resumes the same tuple. ---
    let mut b = Client::connect(server.port, "hunter2").await.unwrap();
    b.ctl(ClientMsg::List { req: Some(2) }).await;
    match b.msg().await {
        ServerMsg::Sessions { req: Some(2), sessions } => {
            assert_eq!(sessions.len(), 1);
            assert_eq!(sessions[0].state, ConnState::Connected);
            assert_eq!(sessions[0].attached, 0);
            assert!(sessions[0].backlog_bytes > 0);
        }
        m => panic!("unexpected {m:?}"),
    }
    // Same tuple, different case, no login script: must resume, not reconnect.
    b.ctl(ClientMsg::Open { req: Some(3), world: world(mud.port), character: "BOB".into(), login: None, telnet: None })
        .await;
    match b.msg().await {
        ServerMsg::Attached { req: Some(3), created: false, info } => assert_eq!(info.session, sid),
        m => panic!("unexpected {m:?}"),
    }
    // Option snapshot comes first.
    match b.frame().await {
        Frame::Data { session, bytes } => {
            assert_eq!(session, sid);
            assert!(contains(&bytes, &[IAC, WILL, opt::GMCP]));
            assert!(contains(&bytes, &[IAC, DO, opt::NAWS]));
            assert!(!contains(&bytes, &[IAC, WILL, opt::ECHO]), "echo was turned back off");
        }
        f => panic!("expected snapshot, got {f:?}"),
    }
    let mut backlog = Vec::new();
    loop {
        match b.frame().await {
            Frame::Backlog { session, ts_ms, bytes } => {
                assert_eq!(session, sid);
                assert!(ts_ms > 0);
                backlog.extend_from_slice(&bytes);
            }
            f => match f.parse_server().unwrap() {
                ServerMsg::BacklogEnd { session, bytes, truncated } => {
                    assert_eq!(session, sid);
                    assert_eq!(bytes as usize, backlog.len());
                    assert!(!truncated);
                    break;
                }
                ServerMsg::Notice { .. } => {}
                m => panic!("unexpected {m:?}"),
            },
        }
    }
    let text = String::from_utf8_lossy(&backlog);
    assert_eq!(text, "A dragon arrives.\r\nThe dragon breathes fire!\r\n");
    assert_eq!(mud.connections.load(Ordering::SeqCst), 1, "resume must not reconnect");

    // Live data flows again; GMCP from the client is forwarded (GMCP is enabled).
    let mut gmcp = Vec::new();
    telnet::encode_sub(opt::GMCP, b"Core.Hello {}", &mut gmcp);
    write_frame(&mut b.wr, &Frame::Data { session: sid, bytes: gmcp.clone() }).await.unwrap();
    b.send_line(sid, "still here").await;
    b.until_text("You said: still here").await;
    assert!(contains(&mud.received.lock().unwrap(), &gmcp));

    // --- Auto-reconnect while detached. ---
    b.ctl(ClientMsg::Detach { req: Some(4), session: sid }).await;
    assert!(matches!(b.msg().await, ServerMsg::Ok { req: Some(4) }));
    mud.cmd(MudCmd::Kick);
    wait_for("re-login", || mud.logins.load(Ordering::SeqCst) == 2).await;
    assert_eq!(mud.connections.load(Ordering::SeqCst), 2);

    b.ctl(ClientMsg::Attach { req: Some(5), session: sid }).await;
    assert!(matches!(b.msg().await, ServerMsg::Attached { req: Some(5), created: false, .. }));
    let mut notices = Vec::new();
    let mut text = Vec::new();
    loop {
        match b.frame().await {
            Frame::Backlog { bytes, .. } => text.extend_from_slice(&bytes),
            Frame::Data { .. } => {} // snapshot
            f => match f.parse_server().unwrap() {
                ServerMsg::Notice { message, .. } => notices.push(message),
                ServerMsg::BacklogEnd { .. } => break,
                m => panic!("unexpected {m:?}"),
            },
        }
    }
    let joined = notices.join(" | ");
    assert!(joined.contains("connection closed by server"), "{joined}");
    assert!(joined.contains("reconnecting in"), "{joined}");
    assert!(joined.contains("login script completed"), "{joined}");
    assert!(String::from_utf8_lossy(&text).contains("Welcome bob!"));

    // --- Restart the proxy: the session is restored and re-established. ---
    drop(b);
    server.stop().await;
    assert!(dir.path().join("sessions.json").exists());
    let server = Server::start(config(dir.path(), "hunter2")).await;
    wait_for("login after restart", || mud.logins.load(Ordering::SeqCst) == 3).await;

    let mut c = Client::connect(server.port, "hunter2").await.unwrap();
    c.ctl(ClientMsg::Attach { req: None, session: sid }).await;
    assert!(matches!(c.msg().await, ServerMsg::Attached { created: false, .. }));
    c.until_text("Welcome bob!").await;

    // --- Close forgets the session. ---
    c.ctl(ClientMsg::Close { req: Some(6), session: sid }).await;
    loop {
        match c.frame().await.parse_server() {
            Ok(ServerMsg::Ok { req: Some(6) }) => break,
            Ok(ServerMsg::Closed { session, .. }) => assert_eq!(session, sid),
            _ => {}
        }
    }
    c.ctl(ClientMsg::List { req: Some(7) }).await;
    loop {
        if let Ok(ServerMsg::Sessions { sessions, .. }) = c.frame().await.parse_server() {
            assert!(sessions.is_empty());
            break;
        }
    }
    assert!(!dir.path().join("sessions").join(sid.to_string()).exists());
    server.stop().await;
}

/// Steps without `expect` go out on connect, honouring `delay_ms`.
#[tokio::test]
async fn login_immediate_and_delayed() {
    let mud = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let mud_port = mud.local_addr().unwrap().port();
    let dir = tempfile::tempdir().unwrap();
    let server = Server::start(config(dir.path(), "pw")).await;
    let mut c = Client::connect(server.port, "pw").await.unwrap();

    for (character, delay) in [("quick", None), ("slow", Some(400u64))] {
        c.ctl(ClientMsg::Open {
            req: None,
            world: world(mud_port),
            character: character.into(),
            login: Some(vec![LoginStep { expect: None, send: format!("connect {character} pw"), delay_ms: delay }]),
            telnet: None,
        })
        .await;
        let (mut s, _) = tokio::time::timeout(T, mud.accept()).await.unwrap().unwrap();
        let accepted = tokio::time::Instant::now();
        let mut got = Vec::new();
        while !got.ends_with(b"\r\n") {
            let mut b = [0u8; 256];
            let n = tokio::time::timeout(T, s.read(&mut b)).await.unwrap().unwrap();
            assert!(n > 0);
            got.extend_from_slice(&b[..n]);
        }
        let elapsed = accepted.elapsed();
        assert_eq!(got, format!("connect {character} pw\r\n").into_bytes());
        match delay {
            None => assert!(elapsed < Duration::from_millis(200), "immediate step took {elapsed:?}"),
            Some(ms) => {
                assert!(elapsed >= Duration::from_millis(ms - 50), "delayed step took only {elapsed:?}");
                assert!(elapsed < Duration::from_millis(ms + 1000), "delayed step took {elapsed:?}");
            }
        }
    }
    server.stop().await;
}

