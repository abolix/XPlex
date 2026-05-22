# XPlex

Multipath proxy that bonds multiple xray tunnels into one reliable, low-latency SOCKS5 endpoint.

Every byte you send is duplicated across N parallel xray paths. The fastest copy wins; the rest are dropped. If a path dies mid-stream, the others keep delivering — zero packet loss, zero reconnects visible to your application.

## How it works

```
                        ┌─── xray 1 ───┐
 App ──► SOCKS5:2080 ──┼─── xray 2 ───┼──► VPS (xplex server) ──► destination
                        └─── xray 3 ───┘
```

- **Client** (`xplex client`): spawns one xray per share link in `xrays.txt`, opens a long-lived encrypted tunnel pool to your VPS, and exposes a local SOCKS5 port. Any app that connects gets multipath reliability transparently.
- **Server** (`xplex server`): accepts tunnel connections, demuxes by session, dials whatever destination the client requested (full forwarding — works for browsing, mining, anything).
- **Adaptive duplication**: a controller watches per-tunnel win rates and demotes slow tunnels to "shadow" (receive-only) to save bandwidth. Shadows get promoted back if conditions change.
- **PSK encryption**: all traffic between client and server is encrypted with ChaCha20-Poly1305 using a pre-shared key. Xray operators cannot read or tamper with your data.

## Quick start

```bash
# Generate a shared secret (run once, paste into both configs)
xplex gen-key

# Server (on your VPS)
xplex server --config config.json

# Client (on your local machine)
xplex client --config config.json
```

Then point any SOCKS5-capable app at `127.0.0.1:2080`.

## Configuration

### Client (`xplex.config.client.example.json`)

```json
{
  "client": {
    "listen": "2080",
    "server": "your-vps.example.com:7000",
    "xrayLinks": "xrays.txt",
    "xrayBasePort": 1080,
    "psk": "your-64-char-hex-key-here"
  }
}
```

### Server (`xplex.config.server.example.json`)

```json
{
  "server": {
    "listen": "7000",
    "psk": "same-64-char-hex-key-here"
  }
}
```

### xrays.txt

One vless/trojan share link per line:

```
trojan://password@server1:443?security=tls&type=ws&host=cdn.example.com&path=/ws#name1
vless://uuid@server2:443?encryption=none&security=tls&type=ws&host=cdn2.example.com&path=/#name2
```

## Building

```bash
# Requires Go 1.22+
CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o xplex ./cmd/xplex
```

Or just grab a pre-built binary from [Releases](../../releases).

### Supported platforms

| OS | Architectures |
|----|---------------|
| Linux | amd64, arm64, armv7, armv6, 386, mips, mipsle, mips64, mips64le, riscv64 |
| Windows | amd64, arm64, 386 |
| macOS | amd64 (Intel), arm64 (Apple Silicon) |
| FreeBSD | amd64, arm64 |
| OpenBSD | amd64 |

Releases are automated via GitHub Actions — push a tag like `v1.0.0` and binaries for all platforms are built and published automatically.

## Architecture

```
cmd/xplex/          CLI entrypoint (client, server, gen-key subcommands)
internal/
  mppool/           Long-lived tunnel pool with auto-reconnect + Active/Shadow states
  mphub/            Session demux + per-tunnel win tracking
  mpfront/          Local SOCKS5 frontend (client side)
  mpserver/         Tunnel acceptor + destination dialer (server side)
  mpadapt/          Adaptive duplication controller
  mpcrypto/         ChaCha20-Poly1305 AEAD frame encryption
  mpframe/          Wire format (type + session ID + seq + payload)
  mpdedup/          Per-session reorder + dedup buffer
  mpconfig/         JSON config loading + flag merging
  config/           Xray share-link parser + JSON config generator
  links/            xrays.txt reader
  socks5/           SOCKS5 client dialer
  probe/            TLS-handshake latency probe
  stats/            Rolling P50/P90/success-rate tracker
  monitor/          Periodic health-check loop
  runner/           Xray process spawner
  testutil/         Shared test fakes
```

## Key properties

- **Zero visible packet loss**: if any one tunnel is alive, bytes flow.
- **Latency = fastest path**: you always get the best of N tunnels per byte.
- **Encrypted end-to-end**: xray operators see only random bytes.
- **Tamper-proof**: Poly1305 MAC rejects any modification.
- **Self-healing**: dead tunnels reconnect with exponential backoff; sessions are killed cleanly if all tunnels die so apps can retry.
- **Bandwidth-aware**: adaptive controller reduces duplication when paths are stable.

## License

MIT
