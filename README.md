# cloudflare-vless

[![Deploy to Cloudflare](https://deploy.workers.cloudflare.com/button)](https://deploy.workers.cloudflare.com/?url=https://github.com/nadav-cheung/cloudflare-vless)

[中文](README_CN.md)

VLESS over WebSocket proxy running on Cloudflare Workers.

Single-file implementation based on the [VLESS protocol spec](https://xtls.github.io/en/development/protocols/vless.html). Proxies TCP traffic via `cloudflare:sockets` and resolves DNS via DNS-over-HTTPS.

## Deploy

Click the **Deploy to Cloudflare** button above, or deploy manually:

```bash
npm install -g wrangler
wrangler login
wrangler deploy
```

Set a custom UUID (recommended):

```bash
wrangler secret put UUID
```

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `UUID` | Hardcoded | Authentication UUID |
| `PROXYIP` | Random | Proxy IP for edge fallback |
| `DNS_RESOLVER_URL` | `cloudflare-dns.com` | DoH endpoint |

## Endpoints

| Path | Description |
|------|-------------|
| `WebSocket /` | VLESS proxy |
| `GET /sub/{uuid}` | Base64 subscription |
| `GET /*` | 404 |

## Client Setup

Import subscription URL into your client:

```
https://<worker>.workers.dev/sub/<uuid>
```

Compatible: v2rayN, Clash, sing-box, Shadowrocket, nekobox.

## Protocol Support

- TCP proxy (command `0x01`)
- DNS over HTTPS / UDP port 53 (command `0x02`)
- Early data (0-RTT) via `sec-websocket-protocol`
- Address types: IPv4, Domain, IPv6
