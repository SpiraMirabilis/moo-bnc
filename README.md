# mbnc: a bouncer for MUDs, MOOs and other M*s

Like an IRC BNC, but for M*s. mbnc keeps your characters connected. When you
reconnect, it replays everything the game sent while you were away, with
timestamps, and then carries on live.

* One persistent upstream connection per **(host, port, character)**. If you
  open an existing tuple, mbnc resumes it; if you open a new one, it connects
  and runs your login script.
* Output is buffered while no client is attached. It stays in RAM up to a
  limit, then spills to disk with rotation.
* Clients use a framed, multiplexed protocol over a single TCP+TLS
  connection, so one client connection can carry many characters. The spec
  is in [docs/PROTOCOL.md](docs/PROTOCOL.md), and the `mbnc-proto` crate holds
  the types.
* mbnc handles telnet negotiation itself: it refuses MCCP, answers TTYPE and
  NAWS, and replays option state (ECHO, GMCP, ...) to clients on attach.
* If the M* drops you while you're away, mbnc reconnects and logs back in.
  Sessions also survive a restart of the bouncer.

## Layout

```
mbnc-proto/   wire format: frames + JSON control messages (depend on this from your client)
mbnc/         the server (lib + `mbnc` binary) and `mbnc-cli`, a bare-bones test client
docs/         PROTOCOL.md
contrib/      systemd unit
```

## Build & set up

```sh
cargo build --release
cp mbnc.example.toml mbnc.toml
./target/release/mbnc hash-password          # paste the output into password_hash
./target/release/mbnc check-config
./target/release/mbnc                         # reads ./mbnc.toml; RUST_LOG=debug for more
```

### TLS on a tailnet

You have two good options:

1. **Tailscale-issued certificate** (recommended). Enable HTTPS certificates
   for the tailnet in the admin console, then run
   `sudo tailscale cert <machine>.<tailnet>.ts.net`, point `[tls]` at the
   resulting `.crt` / `.key`, and connect to that hostname. Clients can then
   verify the certificate with the ordinary webpki roots, with no pinning.
   The cert is valid for 90 days; re-run `tailscale cert` (e.g. from a timer)
   and restart mbnc.
2. **Plaintext**. WireGuard already encrypts tailnet traffic, so if the
   listener is *only* reachable over the tailnet, `allow_plaintext = true`
   (and no `[tls]`) is reasonable.

For a quick self-signed cert (clients must then pin it or skip verification):

```sh
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
  -keyout key.pem -out cert.pem -days 3650 -subj /CN=mbnc -addext subjectAltName=DNS:mbnc
```

### Binding to the Tailscale IP

`listen = "100.x.y.z:7777"` fails if mbnc starts before `tailscaled` has the
interface up. The provided [contrib/mbnc.service](contrib/mbnc.service) uses
`Restart=on-failure` to retry. The alternative is to listen on `0.0.0.0` and
rely on a firewall, or on Tailscale ACLs plus a host firewall that blocks the
port elsewhere.

## Trying it with mbnc-cli

```sh
export MBNC_PASSWORD=...
mbnc-cli -s host:7777 --tls open moo.example.org 7777 Bob --login login.json
mbnc-cli -s host:7777 --tls list
mbnc-cli -s host:7777 --tls attach 1
mbnc-cli -s host:7777 --tls close 1
```

where `login.json` is for example `[{"send": "connect Bob hunter2"}]`. Add
`--insecure` for a self-signed bouncer cert. `mbnc-cli` strips telnet and
works line by line; it's meant for testing, not for playing.

## Behaviour notes

* While no client is attached, a dropped M* connection triggers
  auto-reconnect with backoff. While you *are* attached, mbnc does not
  reconnect, because you may have typed `QUIT`. Use `reconnect`.
* `close` forgets a session completely, including its backlog and its stored
  password.
* `data_dir/sessions.json` (mode 0600, in a 0700 dir) stores login scripts,
  **including passwords**, in plain text. That's what makes unattended
  re-login after reconnects and restarts possible.
* Logs go to stderr; filter them with `RUST_LOG`.

## Tests

```sh
cargo test
```

`mbnc/tests/end_to_end.rs` runs the real server against a fake MUD. It
covers the login script, MCCP refusal, TTYPE/NAWS, the ECHO passthrough, the
backlog spilled to disk while detached, resuming without a second login,
GMCP forwarding, auto-reconnect while detached, restart persistence, login
delays, and `close`.
