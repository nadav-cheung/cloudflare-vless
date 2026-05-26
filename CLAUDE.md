# CLAUDE.md

Single-file VLESS over WebSocket proxy for Cloudflare Workers. Proxies TCP traffic via `cloudflare:sockets`, resolves DNS via DoH. Based on the VLESS protocol spec: https://xtls.github.io/en/development/protocols/vless.html

## Commands

```bash
npx wrangler dev      # Local dev server
npx wrangler deploy   # Deploy to Cloudflare
```

Requires `wrangler.toml` in project root:
```toml
name = "cloudflare-vless"
main = "worker.js"
compatibility_date = "2024-09-23"
```

Set secrets via dashboard or CLI:
```bash
wrangler secret put UUID
wrangler secret put PROXYIP
```

## Architecture

Everything is in `worker.js`, structured top-to-bottom as:

1. **Config constants** — `DEFAULT_UUID`, `PROXY_IPS`, `DEFAULT_DOH`, `HTTPS_PORTS`, `TCP_TIMEOUT`
2. **Router** (`export default fetch`) — WebSocket upgrade → VLESS handler, `GET /sub/{uuid}` → subscription, else 404
3. **`vlessOverWS()`** — WebSocket upgrade + WS readable stream that dispatches first chunk to TCP or DNS path
4. **`parseVlessHeader()`** — Binary parser for VLESS request header (version, UUID, addons, command, port, address). UUID compared as raw bytes against pre-computed `uuidToBytes` result.
5. **`relayTCP()`** — Connects to target via `cloudflare:sockets`, writes initial payload, fires `pipeRemoteToWS()` in background. If remote returns no data, retries once via proxyIP.
6. **`pipeRemoteToWS()`** — Pipes `socket.readable → ws.send()` with VLESS response header (`0x00 0x00`) prepended on first chunk.
7. **`handleDNS()`** — UDP-over-VLESS to DoH bridge. Accumulates data in a buffer, extracts length-prefixed DNS packets, resolves via `fetch(dohURL)`.
8. **`generateSub()`** — Generates base64-encoded list of `vless://` URIs for HTTPS ports (direct + proxyIP).
9. **Utilities** — `makeWSReadable`, `decodeEarlyData` (sec-websocket-protocol 0-RTT), `uuidToBytes`, `isValidUUID`, `safeCloseWS`

## Data Flow

```
Client → WebSocket → [parse VLESS header] → TCP: connect → socket ↔ WS bidirectional relay
                                              → UDP/53: DoH fetch → WS response
```

Key pattern: `remoteRef` object wrapper allows `relayTCP`/`pipeRemoteToWS` to update the socket reference that the WS write handler uses for subsequent chunks.

## Deployment

Environment variables (override defaults):

- `UUID` — override default UUID (validated on each request)
- `PROXYIP` — override random proxyIP selection
- `DNS_RESOLVER_URL` — override DoH endpoint

## Protocol Notes

- VLESS response header is always `[version, 0x00]` (2 bytes, no addons)
- Early data (0-RTT) is base64-encoded in `sec-websocket-protocol` header using URL-safe variant (RFC 4648)
- UDP is only supported for DNS (port 53); all other UDP is rejected
- TCP connection timeout is 10 seconds via `Promise.race` with `clearTimeout` cleanup

## Testing

```bash
# Check subscription endpoint (returns base64-encoded vless:// list)
curl https://<worker>.workers.dev/sub/<uuid>

# Verify 404 on unknown paths
curl https://<worker>.workers.dev/
```

For proxy testing, import the subscription URL into v2rayN, Clash, or sing-box.
