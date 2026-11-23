//! Wire protocol for `mbnc`, a bouncer for MUDs / MOOs / other M*s.
//!
//! See `docs/PROTOCOL.md` in the repository for the prose specification.
//!
//! Every message on the wire is a frame:
//!
//! ```text
//! +----------------+--------+---------------------+
//! | length: u32 BE | type:u8| payload (length-1)  |
//! +----------------+--------+---------------------+
//! ```
//!
//! `length` counts the type byte plus the payload. Frame types:
//!
//! * `0x01` CONTROL — payload is a UTF-8 JSON object ([`ClientMsg`] / [`ServerMsg`]).
//! * `0x02` DATA    — `session: u32 BE` followed by raw telnet bytes.
//! * `0x03` BACKLOG — `session: u32 BE`, `timestamp_ms: i64 BE` (unix epoch), raw telnet bytes.
//!   Only sent proxy -> client.

use serde::{Deserialize, Serialize};
use std::fmt;

/// Protocol version announced in [`ServerMsg::Hello`].
pub const PROTOCOL_VERSION: u32 = 1;

/// Largest frame (type byte + payload) either side will accept.
pub const MAX_FRAME_LEN: usize = 16 * 1024 * 1024;

pub const FRAME_CONTROL: u8 = 0x01;
pub const FRAME_DATA: u8 = 0x02;
pub const FRAME_BACKLOG: u8 = 0x03;

/// Proxy-assigned session identifier. Stable across proxy restarts.
pub type SessionId = u32;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Frame {
    /// JSON control message (already serialized).
    Control(Vec<u8>),
    /// Live telnet stream bytes for a session (either direction).
    Data { session: SessionId, bytes: Vec<u8> },
    /// Telnet stream bytes that were buffered while no client was attached.
    Backlog { session: SessionId, ts_ms: i64, bytes: Vec<u8> },
}

#[derive(Debug)]
pub enum ProtoError {
    FrameTooLarge(usize),
    EmptyFrame,
    UnknownFrameType(u8),
    Truncated,
    Json(serde_json::Error),
    NotControl,
}

impl fmt::Display for ProtoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ProtoError::FrameTooLarge(n) => write!(f, "frame too large ({n} bytes)"),
            ProtoError::EmptyFrame => write!(f, "zero-length frame"),
            ProtoError::UnknownFrameType(t) => write!(f, "unknown frame type 0x{t:02x}"),
            ProtoError::Truncated => write!(f, "frame payload too short for its type"),
            ProtoError::Json(e) => write!(f, "bad control message: {e}"),
            ProtoError::NotControl => write!(f, "frame is not a control frame"),
        }
    }
}

impl std::error::Error for ProtoError {}

impl From<serde_json::Error> for ProtoError {
    fn from(e: serde_json::Error) -> Self {
        ProtoError::Json(e)
    }
}

impl From<ProtoError> for std::io::Error {
    fn from(e: ProtoError) -> Self {
        std::io::Error::new(std::io::ErrorKind::InvalidData, e)
    }
}

impl Frame {
    pub fn client(msg: &ClientMsg) -> Frame {
        Frame::Control(serde_json::to_vec(msg).expect("ClientMsg serializes"))
    }

    pub fn server(msg: &ServerMsg) -> Frame {
        Frame::Control(serde_json::to_vec(msg).expect("ServerMsg serializes"))
    }

    /// Parse a CONTROL frame as a client -> proxy message.
    pub fn parse_client(&self) -> Result<ClientMsg, ProtoError> {
        match self {
            Frame::Control(json) => Ok(serde_json::from_slice(json)?),
            _ => Err(ProtoError::NotControl),
        }
    }

    /// Parse a CONTROL frame as a proxy -> client message.
    pub fn parse_server(&self) -> Result<ServerMsg, ProtoError> {
        match self {
            Frame::Control(json) => Ok(serde_json::from_slice(json)?),
            _ => Err(ProtoError::NotControl),
        }
    }

    fn body_len(&self) -> usize {
        1 + match self {
            Frame::Control(j) => j.len(),
            Frame::Data { bytes, .. } => 4 + bytes.len(),
            Frame::Backlog { bytes, .. } => 12 + bytes.len(),
        }
    }

    /// Append the encoded frame to `out`.
    pub fn encode(&self, out: &mut Vec<u8>) {
        let len = self.body_len();
        out.reserve(4 + len);
        out.extend_from_slice(&(len as u32).to_be_bytes());
        match self {
            Frame::Control(j) => {
                out.push(FRAME_CONTROL);
                out.extend_from_slice(j);
            }
            Frame::Data { session, bytes } => {
                out.push(FRAME_DATA);
                out.extend_from_slice(&session.to_be_bytes());
                out.extend_from_slice(bytes);
            }
            Frame::Backlog { session, ts_ms, bytes } => {
                out.push(FRAME_BACKLOG);
                out.extend_from_slice(&session.to_be_bytes());
                out.extend_from_slice(&ts_ms.to_be_bytes());
                out.extend_from_slice(bytes);
            }
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut v = Vec::new();
        self.encode(&mut v);
        v
    }

    /// Try to decode one frame from the front of `buf`.
    ///
    /// Returns `Ok(None)` if more bytes are needed, or `Ok(Some((frame, consumed)))`.
    pub fn decode(buf: &[u8]) -> Result<Option<(Frame, usize)>, ProtoError> {
        if buf.len() < 4 {
            return Ok(None);
        }
        let len = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;
        if len == 0 {
            return Err(ProtoError::EmptyFrame);
        }
        if len > MAX_FRAME_LEN {
            return Err(ProtoError::FrameTooLarge(len));
        }
        if buf.len() < 4 + len {
            return Ok(None);
        }
        let frame = Self::from_body(&buf[4..4 + len])?;
        Ok(Some((frame, 4 + len)))
    }

    /// Decode a frame body (type byte + payload, without the length prefix).
    pub fn from_body(body: &[u8]) -> Result<Frame, ProtoError> {
        let (&ty, p) = body.split_first().ok_or(ProtoError::EmptyFrame)?;
        match ty {
            FRAME_CONTROL => Ok(Frame::Control(p.to_vec())),
            FRAME_DATA => {
                if p.len() < 4 {
                    return Err(ProtoError::Truncated);
                }
                Ok(Frame::Data {
                    session: u32::from_be_bytes(p[0..4].try_into().unwrap()),
                    bytes: p[4..].to_vec(),
                })
            }
            FRAME_BACKLOG => {
                if p.len() < 12 {
                    return Err(ProtoError::Truncated);
                }
                Ok(Frame::Backlog {
                    session: u32::from_be_bytes(p[0..4].try_into().unwrap()),
                    ts_ms: i64::from_be_bytes(p[4..12].try_into().unwrap()),
                    bytes: p[12..].to_vec(),
                })
            }
            t => Err(ProtoError::UnknownFrameType(t)),
        }
    }
}

#[cfg(feature = "tokio")]
mod io {
    use super::*;
    use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

    /// Read one frame. Returns `Ok(None)` on clean EOF at a frame boundary.
    pub async fn read_frame<R: AsyncRead + Unpin>(r: &mut R) -> std::io::Result<Option<Frame>> {
        let mut len = [0u8; 4];
        match r.read_exact(&mut len).await {
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
            Err(e) => return Err(e),
        }
        let len = u32::from_be_bytes(len) as usize;
        if len == 0 {
            return Err(ProtoError::EmptyFrame.into());
        }
        if len > MAX_FRAME_LEN {
            return Err(ProtoError::FrameTooLarge(len).into());
        }
        let mut body = vec![0u8; len];
        r.read_exact(&mut body).await?;
        Ok(Some(Frame::from_body(&body)?))
    }

    /// Write one frame (does not flush).
    pub async fn write_frame<W: AsyncWrite + Unpin>(w: &mut W, f: &Frame) -> std::io::Result<()> {
        w.write_all(&f.to_bytes()).await
    }
}

#[cfg(feature = "tokio")]
pub use io::{read_frame, write_frame};

// ---------------------------------------------------------------------------
// Control messages
// ---------------------------------------------------------------------------

/// Where the M* lives.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct World {
    pub host: String,
    pub port: u16,
    /// Connect to the M* over TLS.
    #[serde(default)]
    pub tls: bool,
    /// Verify the M*'s TLS certificate against the webpki root store.
    #[serde(default = "default_true")]
    pub verify_cert: bool,
}

fn default_true() -> bool {
    true
}

/// One step of an automatic login script.
///
/// When the upstream connection is established the proxy walks the steps in
/// order. A step with `expect` waits until that substring has appeared in the
/// server's text output (telnet commands stripped) since the previous step;
/// a step without `expect` is ready as soon as the previous step was sent (or
/// on connect, for the first step). Once ready, the proxy waits `delay_ms`
/// (if set), then transmits `send` followed by CR LF.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LoginStep {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expect: Option<String>,
    pub send: String,
    /// Milliseconds to wait after the step becomes ready before sending.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delay_ms: Option<u64>,
}

/// Telnet behaviour the proxy uses on the client's behalf while it holds the
/// upstream connection. See PROTOCOL.md, "Telnet handling".
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TelnetPrefs {
    /// Options the server may enable on its side (server `WILL x` -> proxy `DO x`).
    #[serde(default = "default_server_options")]
    pub server_options: Vec<u8>,
    /// Options the proxy will enable on the client side (server `DO x` -> proxy `WILL x`).
    #[serde(default = "default_client_options")]
    pub client_options: Vec<u8>,
    /// Terminal types answered to `TTYPE SEND`, cycled per MTTS.
    #[serde(default = "default_ttype")]
    pub ttype: Vec<String>,
    /// Window size reported via NAWS until a client sends its own.
    #[serde(default = "default_naws")]
    pub naws: (u16, u16),
}

pub fn default_server_options() -> Vec<u8> {
    // ECHO, SGA, EOR, GMCP
    vec![1, 3, 25, 201]
}

pub fn default_client_options() -> Vec<u8> {
    // TTYPE, NAWS
    vec![24, 31]
}

pub fn default_ttype() -> Vec<String> {
    vec!["MBNC".into(), "XTERM-256COLOR".into(), "MTTS 13".into()]
}

pub fn default_naws() -> (u16, u16) {
    (80, 24)
}

impl Default for TelnetPrefs {
    fn default() -> Self {
        TelnetPrefs {
            server_options: default_server_options(),
            client_options: default_client_options(),
            ttype: default_ttype(),
            naws: default_naws(),
        }
    }
}

/// Client -> proxy control messages.
///
/// `req` is an optional client-chosen request id echoed back in the matching
/// response (`ok`, `error`, `sessions`, `attached`, `pong`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ClientMsg {
    /// Must be the first message on a connection.
    Auth {
        password: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        client: Option<String>,
    },
    Ping {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        req: Option<u64>,
    },
    /// List all sessions the proxy holds.
    List {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        req: Option<u64>,
    },
    /// Attach to the session for (world.host, world.port, character), creating
    /// it (and connecting + logging in) if it does not exist. If it exists but
    /// is disconnected, it is reconnected.
    ///
    /// `login` / `telnet`, when present, replace the stored values for the
    /// session; when absent the stored values are kept (defaults for new sessions).
    Open {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        req: Option<u64>,
        world: World,
        character: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        login: Option<Vec<LoginStep>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        telnet: Option<TelnetPrefs>,
    },
    /// Attach to an existing session by id.
    Attach {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        req: Option<u64>,
        session: SessionId,
    },
    /// Stop receiving a session on this connection. The session keeps running
    /// and buffers output if no other client is attached.
    Detach {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        req: Option<u64>,
        session: SessionId,
    },
    /// Drop and re-establish the upstream connection (re-running the login script).
    Reconnect {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        req: Option<u64>,
        session: SessionId,
    },
    /// Disconnect from the M* and forget the session entirely (incl. backlog).
    Close {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        req: Option<u64>,
        session: SessionId,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConnState {
    Disconnected,
    Connecting,
    Connected,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionInfo {
    pub session: SessionId,
    pub host: String,
    pub port: u16,
    pub tls: bool,
    pub character: String,
    pub state: ConnState,
    /// Number of client connections currently attached.
    pub attached: u32,
    /// Bytes of buffered output waiting for a client.
    pub backlog_bytes: u64,
    /// Unix ms when the current upstream connection was established.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub connected_since: Option<i64>,
    /// Unix ms of the last byte received from the M*.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_activity: Option<i64>,
}

/// Proxy -> client control messages.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ServerMsg {
    /// Sent immediately after the connection (and TLS handshake) is established.
    Hello { server: String, protocol: u32 },
    AuthOk,
    Pong {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        req: Option<u64>,
    },
    /// Generic success for `detach`, `reconnect`, `close`.
    Ok {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        req: Option<u64>,
    },
    Error {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        req: Option<u64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        session: Option<SessionId>,
        message: String,
    },
    Sessions {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        req: Option<u64>,
        sessions: Vec<SessionInfo>,
    },
    /// Response to `open` / `attach`. Followed by: a DATA frame with the
    /// current telnet option state, zero or more BACKLOG frames and `notice`
    /// messages, then `backlog_end`; after that, live DATA.
    Attached {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        req: Option<u64>,
        /// True if this request created the session.
        created: bool,
        info: SessionInfo,
    },
    BacklogEnd {
        session: SessionId,
        /// Total backlog payload bytes replayed.
        bytes: u64,
        /// True if older backlog was discarded because the disk limit was hit.
        truncated: bool,
    },
    /// Upstream connection state changed.
    Status {
        session: SessionId,
        state: ConnState,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        message: Option<String>,
    },
    /// Informational message from the proxy about a session (also replayed
    /// from backlog with its original timestamp).
    Notice {
        session: SessionId,
        ts_ms: i64,
        message: String,
    },
    /// The session was closed (by a `close` from any client) and no longer exists.
    Closed { session: SessionId, reason: String },
    /// This client was detached from the session by the proxy (e.g. too slow).
    Detached { session: SessionId, reason: String },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_frames() {
        let frames = vec![
            Frame::client(&ClientMsg::List { req: Some(7) }),
            Frame::Data { session: 3, bytes: b"look\r\n".to_vec() },
            Frame::Backlog { session: 9, ts_ms: -5, bytes: vec![255, 249] },
        ];
        let mut buf = Vec::new();
        for f in &frames {
            f.encode(&mut buf);
        }
        let mut off = 0;
        for f in &frames {
            let (g, n) = Frame::decode(&buf[off..]).unwrap().unwrap();
            assert_eq!(&g, f);
            off += n;
        }
        assert_eq!(off, buf.len());
        assert!(Frame::decode(&buf[..3]).unwrap().is_none());
    }

    #[test]
    fn open_json_defaults() {
        let m: ClientMsg = serde_json::from_str(
            r#"{"type":"open","world":{"host":"moo.example","port":7777},"character":"bob"}"#,
        )
        .unwrap();
        match m {
            ClientMsg::Open { world, login, telnet, .. } => {
                assert!(!world.tls);
                assert!(world.verify_cert);
                assert!(login.is_none() && telnet.is_none());
            }
            _ => panic!(),
        }
        let t: TelnetPrefs = serde_json::from_str("{}").unwrap();
        assert_eq!(t, TelnetPrefs::default());
    }
}
