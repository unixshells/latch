# latch

Terminal multiplexer with built-in remote access. tmux you can SSH
into, open in a browser, or connect to with mosh. One binary.

## Install

```
go install github.com/unixshells/latch/cmd/latch@latest
```

## Usage

```sh
latch                     # start or attach to default session
latch new work            # named session
latch attach work         # attach to existing
latch ls                  # list sessions
latch kill work           # kill a session
```

## Key bindings

Prefix: **Ctrl-]** (configurable).

| Key | Action |
|-----|--------|
| `c` | New window |
| `n` / `p` | Next / prev window |
| `0`-`9` | Select window |
| `g`N`Enter` | Go to window N |
| `x` | Close window |
| `[` | Scroll mode |
| `d` | Detach |
| `s` | Admin panel |
| `Ctrl-]` | Send literal Ctrl-] |

Scroll mode: `j`/`k` line, `Ctrl-d`/`Ctrl-u` half page, `g`/`G`
top/bottom, `q` exit.

## Remote access

### SSH

```sh
latch new --ssh                        # SSH on :2222
ssh -p 2222 user@host                  # attach default session
ssh -p 2222 user@host work             # attach named session
```

Auth: `~/.latch/authorized_keys`. No file = reject all.

### Mosh

```sh
latch new --ssh
mosh user@host --ssh="ssh -p 2222"
```

Mosh connections get full latch sessions -- same windows, HUD, admin
panel, and access controls as SSH and web clients. Multiple transports
can share the same session simultaneously. latch includes a native
mosh server (no `mosh-server` binary needed).

### Web terminal

```sh
latch new --web                        # HTTPS on :7680
```

Self-signed TLS cert on first run. Ed25519 challenge-response auth
with non-extractable keys in IndexedDB.

### Relay

```sh
latch relay register                   # create account
latch relay enable                     # enable in config
latch new --ssh
ssh macbook.alice.unixshells.com       # from anywhere
```

Persistent QUIC connection to the relay. No public IP, port
forwarding, or VPN needed.

## Admin panel

`Ctrl-]` then `s`. Shows active connections (source, address,
duration). Toggle SSH/web/relay globally or per-session. Kick
connections.

## Config

`~/.latch/config`:

```
prefix = C-]
shell = /bin/zsh
scrollback = 10000
max-sessions = 64
mouse = true
ssh-addr = :2222
web-addr = :7680
```

## Architecture

Server-side rendering. The server runs a VT emulator per window,
composites the screen, sends ANSI frames to clients. Clients are
dumb pipes.

```
local   ──unix──> server ──pty──> shell
ssh     ──tcp───> server
mosh    ──udp───> server
browser ──wss───> server
relay   ──quic──> server
```

Four transport bridges (sshBridge, moshBridge, wsBridge, relayBridge)
all implement `net.Conn` and feed the same `handle()` loop.

## License

Copyright (c) 2026 [Unix Shells](https://unixshells.com). MIT license. See [LICENSE](LICENSE).
