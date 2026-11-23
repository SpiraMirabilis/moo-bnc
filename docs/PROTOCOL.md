# mbnc client protocol (version 1)

This is the protocol a client (e.g. your MUD client) speaks to the bouncer.
The Rust types live in the `mbnc-proto` crate, so a Rust client can depend on
it directly:

```toml
mbnc-proto = { path = "../bnc/mbnc-proto" }   # or a git dependency
```

## Transport

One TCP connection, wrapped in TLS when the server has a `[tls]` section
(plain TCP when it runs with `allow_plaintext = true`). Several sessions
(characters) are multiplexed over that single connection, so you never need
more than one connection per client.

## Framing

Everything on the wire, in both directions, is a frame:

```
+-----------------+----------+---------------------------+
| length: u32 BE  | type: u8 | payload (length - 1 bytes)|
+-----------------+----------+---------------------------+
```

`length` counts the type byte plus the payload. The maximum is 16 MiB. A
peer that receives a zero-length, oversized or unknown frame should drop the
connection.

| type | name    | payload                                                   | direction |
|------|---------|-----------------------------------------------------------|-----------|
| 0x01 | CONTROL | UTF-8 JSON object                                         | both      |
| 0x02 | DATA    | `session: u32 BE` + raw telnet bytes                      | both      |
| 0x03 | BACKLOG | `session: u32 BE` + `ts_ms: i64 BE` + raw telnet bytes    | proxy → client |

`ts_ms` is milliseconds since the Unix epoch (UTC), recording when the proxy
received those bytes from the M*.

In the `mbnc-proto` crate, `Frame::encode` / `Frame::decode` handle the
framing, `read_frame` / `write_frame` are the tokio helpers, and
`Frame::client(&ClientMsg)` / `frame.parse_server()` handle the JSON.

## Connection lifecycle

```
proxy  → {"type":"hello","server":"mbnc/0.1.0","protocol":1}
client → {"type":"auth","password":"...","client":"mymudclient/1.2"}
proxy  → {"type":"auth_ok"}
         or {"type":"error","message":"authentication failed"} and the connection closes
```

The client must send `auth` within 30 seconds, and it must be the first
message. After a failed attempt the proxy waits 2 seconds before replying.

## Control messages

Every client request can carry an optional `"req": <u64>`. The proxy echoes
it in that request's response: `ok`, `error`, `sessions`, `attached` or
`pong`. Unsolicited events (`status`, `notice`, `closed`, `detached`,
`backlog_end`) carry no `req`.

### Client → proxy

| type        | fields                                              | response            |
|-------------|-----------------------------------------------------|---------------------|
| `auth`      | `password`, `client?`                               | `auth_ok` / `error` |
| `ping`      | `req?`                                              | `pong`              |
| `list`      | `req?`                                              | `sessions`          |
| `open`      | `req?`, `world`, `character`, `login?`, `telnet?`   | `attached` (+ replay) |
| `attach`    | `req?`, `session`                                   | `attached` (+ replay) |
| `detach`    | `req?`, `session`                                   | `ok`                |
| `reconnect` | `req?`, `session`                                   | `ok`                |
| `close`     | `req?`, `session`                                   | `ok` (attached clients get `closed`) |

#### `open`: the main entry point

```json
{
  "type": "open", "req": 1,
  "world": { "host": "moo.example.org", "port": 7777, "tls": false, "verify_cert": true },
  "character": "Bob",
  "login": [
    { "send": "connect Bob hunter2" }
  ],
  "telnet": {
    "server_options": [1, 3, 25, 201],
    "client_options": [24, 31],
    "ttype": ["MYCLIENT", "XTERM-256COLOR", "MTTS 13"],
    "naws": [120, 40]
  }
}
```

* A session is identified by **(world.host, world.port, character)**,
  compared case-insensitively. `tls` and `verify_cert` are not part of the key.
* If no session has that key, the proxy creates one, connects, runs the
  login script, and attaches you (`"created": true`).
* If the key already exists, you are attached to it (`"created": false`).
  If it is currently disconnected, the proxy also reconnects it, which re-runs
  the login script.
* When `login` or `telnet` is present, it **replaces** the stored value for
  the session. When absent, the stored value is kept; new sessions get an empty
  login script and the default telnet prefs. So a client can send its
  full config on every `open`, which also keeps a changed password up to
  date. A changed `world.host` or `world.port` creates a different key and
  so a different session. A changed `tls` or `verify_cert` takes effect on
  the next (re)connect.
* `world.tls` defaults to `false`; `world.verify_cert` defaults to `true`.
  Set `verify_cert: false` for M*s with self-signed certificates.

**Login script.** The script runs on every (re)connection. Each step has a
`send`, an optional `expect` and an optional `delay_ms`:

| field      | meaning |
|------------|---------|
| `send`     | Line to send; the proxy appends CR LF. |
| `expect`   | Substring (telnet stripped, case-sensitive) to wait for in the server's text since the previous step. If omitted, the step is ready right away: on connect for the first step, otherwise as soon as the previous step was sent. |
| `delay_ms` | Milliseconds to wait once the step is ready, before sending. If omitted or 0, it's sent immediately. |

If the script hasn't finished after `login_timeout_secs` (default 60), it is
abandoned. Time spent in `delay_ms` doesn't count toward that timeout.
**Client input that arrives while the script runs is held back, then sent
after it completes or times out**, so your typing can't interleave with the
password.

Examples:

```json
[{ "send": "connect Bob hunter2" }]                                    // immediately on connect (LambdaMOO-style)
[{ "send": "connect Bob hunter2", "delay_ms": 1500 }]                  // 1.5s after connect, e.g. to let a banner finish
[{ "expect": "By what name", "send": "Bob" },
 { "expect": "Password", "send": "hunter2" }]                          // Diku-style prompts
[{ "expect": "Name:", "send": "Bob" }, { "expect": "Password:", "send": "hunter2" },
 { "expect": "PRESS RETURN", "send": "" }, { "expect": "Make your choice", "send": "1" }]
```

The proxy persists login scripts, passwords included, in
`data_dir/sessions.json` (mode 0600) so it can log back in after reconnects
and restarts.

#### `attach`, `detach`, `reconnect`, `close`

* `attach {session}` attaches to an existing session by id (from `list`).
  Unlike `open`, it does **not** reconnect a disconnected session; send
  `reconnect` for that.
* `detach {session}` stops this connection receiving the session. Closing
  the TCP connection detaches from everything.
* `reconnect {session}` drops the upstream connection (if any) and
  connects again, running the login script.
* `close {session}` disconnects from the M* and **forgets** the session,
  including its backlog and stored login. If you want a clean in-game logout,
  send the game's `QUIT` first.

### Proxy → client

| type          | fields                                                    |
|---------------|-----------------------------------------------------------|
| `hello`       | `server`, `protocol`                                      |
| `auth_ok`     |                                                           |
| `pong`        | `req?`                                                    |
| `ok`          | `req?`                                                    |
| `error`       | `req?`, `session?`, `message`                             |
| `sessions`    | `req?`, `sessions: [SessionInfo]`                         |
| `attached`    | `req?`, `created`, `info: SessionInfo`                    |
| `backlog_end` | `session`, `bytes`, `truncated`                           |
| `status`      | `session`, `state`, `message?`                            |
| `notice`      | `session`, `ts_ms`, `message`                             |
| `closed`      | `session`, `reason`                                       |
| `detached`    | `session`, `reason` (reserved)                            |

`SessionInfo`:

```json
{ "session": 1, "host": "moo.example.org", "port": 7777, "tls": false,
  "character": "Bob", "state": "connected", "attached": 1,
  "backlog_bytes": 5123, "connected_since": 1795457225666, "last_activity": 1795457290001 }
```

`state` is one of `disconnected`, `connecting` or `connected`.

## Attaching: exact frame order

After `open` / `attach`, the proxy sends, in order:

1. `attached` (CONTROL).
2. **Option snapshot** (DATA, only if any options are active):
   `IAC WILL x` for each option the server has enabled and `IAC DO x` for
   each client-side option enabled (except TTYPE). This brings your telnet
   state machine in line with a connection that was negotiated before you
   arrived.
3. **Backlog**: zero or more BACKLOG frames, interleaved with `notice`
   messages (timestamped proxy events such as "connection closed by server",
   "reconnecting in 10s" or "login script completed"), in the order they
   happened.
4. `backlog_end` with the total replayed byte count, and `truncated: true` if
   the disk limit forced the proxy to drop the oldest output.
5. Live DATA frames and `status` / `notice` events from here on.

No output is lost or reordered between steps 3 and 5: while the proxy replays,
it pauses reading from the M*. Once replayed, the backlog is gone; it is not
replayed again to the next client.

The proxy only buffers output while **no** client is attached to the
session. If several clients are attached, each receives all live output.
Input from any of them goes to the M*.

## DATA: the telnet stream

DATA and BACKLOG payloads are the M*'s telnet byte stream (text, ANSI and
`IAC` sequences), so **feed them to the same telnet parser you'd use for a
direct connection**. The proxy re-encodes the stream so that every frame
holds whole telnet commands, but your parser may keep state across frames
anyway.

Client → proxy DATA is what you'd write to the socket directly: escape
`IAC` as `IAC IAC` and end lines with CR LF. Telnet sequences may span
frames.

### Telnet handling

The proxy is the M*'s telnet peer. It has to be, because it keeps answering
negotiation while nobody is attached. Concretely:

* **The proxy negotiates options.** It answers the server's
  `WILL x` with `DO x` when `x` is in `telnet.server_options`, and its
  `DO x` with `WILL x` when `x` is in `telnet.client_options`. Everything
  else is refused. Defaults: `server_options = [ECHO 1, SGA 3, EOR 25, GMCP 201]`,
  `client_options = [TTYPE 24, NAWS 31]`. Only list options your client
  actually understands. For example, accepting MXP (91) makes the server
  embed MXP tags in the text.
* **Clients see state changes, not negotiation.** When an option turns on or
  off while you're attached, you receive a synthetic `IAC WILL/WONT/DO/DONT x`.
  This is how `ECHO` reaches you for password prompts. When the upstream
  connection drops, you receive `WONT`/`DONT` for everything that was on.
* **Your negotiation is swallowed.** `WILL/WONT/DO/DONT` you send are
  dropped (answering the snapshot with `DO GMCP` and so on is fine and
  harmless).
* **Subnegotiation from you is forwarded** when its option is enabled in
  either direction, so GMCP `Core.Hello` / `Core.Supports.Set` work. Send them
  again after every attach, because the server may have restarted the
  connection.
* **MCCP (86, 87) is always refused**, so the stream is never compressed.
* **TTYPE is answered by the proxy** from `telnet.ttype` (cycled per
  MTTS), and TTYPE subnegotiation is neither forwarded to you nor accepted
  from you.
* **NAWS**: the proxy remembers the last `IAC SB NAWS` you sent and
  replays it whenever the server enables NAWS. It uses `telnet.naws`
  until then. Send NAWS on attach and when your window resizes.
* `IAC NOP` from the server is dropped. GA/EOR and other commands pass through.

## Reconnect behaviour

* If the M* drops the connection **while no client is attached**, the proxy
  reconnects with exponential backoff (`initial_delay_secs`, doubling, capped at
  `max_delay_secs`) and re-runs the login script. A connection that stays up
  for 60s resets the backoff.
* If it drops **while a client is attached**, the proxy does *not*
  reconnect, because you may have typed `QUIT`. You get
  `status: disconnected`; send `reconnect` (or `open`) to come back.
* When the proxy restarts, it re-establishes every session that hasn't been
  `close`d. It writes in-memory backlog to disk on SIGTERM/SIGINT, so a clean
  restart loses no buffered output.

## Minimal client sketch (Rust)

```rust
use mbnc_proto::*;
let (mut rd, mut wr) = tokio::io::split(tls_stream);
read_frame(&mut rd).await?;                                    // hello
write_frame(&mut wr, &Frame::client(&ClientMsg::Auth { password, client: None })).await?;
// expect auth_ok
write_frame(&mut wr, &Frame::client(&ClientMsg::Open { req: Some(1), world, character,
                                                        login: Some(steps), telnet: None })).await?;
while let Some(f) = read_frame(&mut rd).await? {
    match f {
        Frame::Data { session, bytes } => my_telnet_parser(session).feed(&bytes),
        Frame::Backlog { session, ts_ms, bytes } => my_telnet_parser(session).feed_backlog(ts_ms, &bytes),
        Frame::Control(_) => match f.parse_server()? { /* attached, status, notice, ... */ _ => {} },
    }
}
// to send input:  write_frame(&mut wr, &Frame::Data { session, bytes: b"look\r\n".to_vec() })
```
