# mbnc

**A bouncer for MUDs, MOOs, MUSHes and other M\*s.**

Close your laptop and your character stays logged in. When you come back,
mbnc shows you everything you missed, with timestamps, and then carries on
live.

If you've used an IRC bouncer (a "BNC"), it's the same idea for M\*s.

```
 your client  ──TLS──▶  mbnc (always on)  ──telnet──▶  the M*
 (laptop, phone…)       keeps the connection,
                        records what you miss
```

## What it does

- **Keeps you connected.** mbnc holds the connection to the game, so
  closing your client doesn't log your character out.
- **Records what you miss.** While no client is attached, everything the
  game sends is saved, first in memory and then on disk. When you attach
  again, you get it all back with timestamps.
- **Logs you back in.** If the game drops the connection while you're away,
  mbnc reconnects and runs your login script again. Sessions also survive a
  restart of mbnc itself.
- **One connection, many characters.** A client can attach to several
  characters at once over a single TLS connection.
- **Handles telnet for you.** mbnc answers the game's telnet negotiation
  (terminal type, window size, GMCP and so on) while you're away. It also
  brings your client up to date when you attach, so things like hidden
  password prompts still work.

## Clients

mbnc uses its own protocol, so your MUD client has to support it.

- **[Familiar](https://github.com/SpiraMirabilis/familiar)** supports it.
  Add a `[bouncer]` section to Familiar's config and turn on "Connect through
  the bouncer" for a world.
- **`mbnc-cli`** comes with mbnc. It's a bare-bones client for testing, not
  for playing.
- **Your own client:** the protocol is short and documented in
  [docs/PROTOCOL.md](docs/PROTOCOL.md). Rust clients can use the
  `mbnc-proto` crate for the message types.

## Quick start

You need a machine that stays on, such as a home server, a VPS or a
Raspberry Pi, and a [Rust toolchain](https://rustup.rs).

```sh
git clone https://github.com/SpiraMirabilis/moo-bnc
cd moo-bnc
cargo build --release

cp mbnc.example.toml mbnc.toml
./target/release/mbnc hash-password    # type a password, then paste the output into
                                       # password_hash in mbnc.toml
./target/release/mbnc check-config     # make sure the config is valid
./target/release/mbnc                  # run it (reads ./mbnc.toml)
```

Then point your client at `your-server:7777` with that password.

To keep it running and start it at boot, there's a systemd unit in
[contrib/mbnc.service](contrib/mbnc.service), with install steps at the top.
It expects the code in `~/bnc`, so change its paths if you cloned somewhere
else.

## Securing the connection

Your client sends the mbnc password, and your login script sends your game
passwords, so don't expose mbnc unencrypted to the internet. Pick one of
these:

1. **TLS with a Tailscale certificate (easiest on a tailnet).** Turn on
   HTTPS certificates for your tailnet in the Tailscale admin console, then
   run `sudo tailscale cert <machine>.<tailnet>.ts.net`. Point the `[tls]`
   section of `mbnc.toml` at the `.crt` and `.key` it creates, and connect to
   that hostname. Clients can verify the certificate normally. It lasts 90
   days, so re-run `tailscale cert` from a timer and restart mbnc.
2. **TLS with any other certificate.** Any certificate and key in PEM format
   work. For a self-signed one:
   ```sh
   openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
     -keyout key.pem -out cert.pem -days 3650 -subj /CN=mbnc -addext subjectAltName=DNS:mbnc
   ```
   Clients then have to pin the certificate or skip verification.
3. **Plain TCP inside a private network.** If mbnc can *only* be reached over
   Tailscale, WireGuard or an SSH tunnel, the traffic is already encrypted.
   Leave out `[tls]` and set `allow_plaintext = true`.

**Binding to a Tailscale IP:** `listen = "100.x.y.z:7777"` fails if mbnc
starts before Tailscale has brought its interface up. The systemd unit
retries until it works. You can also listen on `0.0.0.0` and block the port
everywhere else with a firewall.

## Configuration

Everything lives in `mbnc.toml`. [mbnc.example.toml](mbnc.example.toml)
lists every option with comments. The main ones are:

| Setting | What it's for |
| --- | --- |
| `listen` | Address and port for clients (default `0.0.0.0:7777`). |
| `password_hash` | Your password, hashed with `mbnc hash-password`. |
| `[tls]` | Certificate and key for client connections. |
| `allow_plaintext` | Allow running without `[tls]`. |
| `[backlog]` | How much missed output to keep per character, in memory and on disk. |
| `[reconnect]` | Whether and how quickly to reconnect while you're away. |

You don't list games or characters in the config. Clients open a session by
naming the game's host and port, the character, and a login script. mbnc
remembers each session until a client closes it.

## Good to know

- **No reconnect while you're watching.** If the game drops the connection
  while a client is attached, mbnc does *not* reconnect, because you might
  have typed `QUIT`. Reconnect from your client when you're ready.
- **Closing forgets everything.** Closing a session disconnects from the
  game and deletes its saved output and login script. For a clean logout,
  send the game's `QUIT` first.
- **Passwords are stored in plain text.** Login scripts, game passwords
  included, are saved in `data/sessions.json` so mbnc can log back in on its
  own. The file is readable only by its owner (mode 0600).
- **Old output gets dropped.** If you're away long enough to fill the disk
  limit, the oldest output goes, and your client is told so.
- **Logs** go to stderr. Set `RUST_LOG=debug` for more.

## Trying it with mbnc-cli

```sh
export MBNC_PASSWORD=...
mbnc-cli -s host:7777 --tls open moo.example.org 7777 Bob --login login.json
mbnc-cli -s host:7777 --tls list
mbnc-cli -s host:7777 --tls attach 1
mbnc-cli -s host:7777 --tls close 1
```

`login.json` holds the login script, for example
`[{"send": "connect Bob hunter2"}]`. Add `--insecure` for a bouncer with a
self-signed certificate. The [protocol doc](docs/PROTOCOL.md#open-the-main-entry-point)
has more login script examples, such as waiting for a `Name:` prompt.

## Project layout

```
mbnc/          the server (the `mbnc` binary) and mbnc-cli
mbnc-proto/    wire protocol types; clients written in Rust can depend on this
docs/          PROTOCOL.md, the client protocol
contrib/       systemd unit
```

## Development

```sh
cargo test
```

`mbnc/tests/end_to_end.rs` runs the real server against a fake MUD. It
covers login scripts, telnet negotiation, saving output while detached,
resuming without logging in twice, reconnecting, and surviving a restart.

## License

MIT. See [LICENSE](LICENSE).
