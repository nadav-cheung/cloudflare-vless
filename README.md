# cloudflare-vless

[![Deploy to Cloudflare](https://deploy.workers.cloudflare.com/button)](https://deploy.workers.cloudflare.com/?url=https://github.com/nadav-cheung/cloudflare-vless)

<table>
<tr>
<td width="50%" valign="top">

## English

VLESS over WebSocket proxy running on Cloudflare Workers.

Single-file implementation based on the [VLESS protocol spec](https://xtls.github.io/en/development/protocols/vless.html). Proxies TCP traffic via `cloudflare:sockets` and resolves DNS via DNS-over-HTTPS.

### Quick Deploy

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

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `UUID` | Hardcoded | Authentication UUID |
| `PROXYIP` | Random | Proxy IP for edge fallback |
| `DNS_RESOLVER_URL` | `cloudflare-dns.com` | DoH endpoint |

### Endpoints

| Path | Description |
|------|-------------|
| `WebSocket /` | VLESS proxy |
| `GET /sub/{uuid}` | Base64 subscription |
| `GET /*` | 404 |

### Client Setup

Import subscription URL into your client:

```
https://<worker>.workers.dev/sub/<uuid>
```

Compatible: v2rayN, Clash, sing-box, Shadowrocket, nekobox.

### Protocol Support

- TCP proxy (command `0x01`)
- DNS over HTTPS / UDP port 53 (command `0x02`)
- Early data (0-RTT) via `sec-websocket-protocol`
- Address types: IPv4, Domain, IPv6

</td>
<td width="50%" valign="top">

## 中文

基于 Cloudflare Workers 的 VLESS over WebSocket 代理。

单文件实现，遵循 [VLESS 协议规范](https://xtls.github.io/en/development/protocols/vless.html)。通过 `cloudflare:sockets` 代理 TCP 流量，通过 DNS-over-HTTPS 解析 DNS。

### 一键部署

点击上方的 **Deploy to Cloudflare** 按钮，或手动部署：

```bash
npm install -g wrangler
wrangler login
wrangler deploy
```

设置自定义 UUID（推荐）：

```bash
wrangler secret put UUID
```

### 环境变量

| 变量 | 默认值 | 说明 |
|------|--------|------|
| `UUID` | 硬编码 | 认证 UUID |
| `PROXYIP` | 随机 | 边缘回退代理 IP |
| `DNS_RESOLVER_URL` | `cloudflare-dns.com` | DoH 端点 |

### 端点

| 路径 | 说明 |
|------|------|
| `WebSocket /` | VLESS 代理 |
| `GET /sub/{uuid}` | Base64 订阅 |
| `GET /*` | 404 |

### 客户端配置

将订阅 URL 导入客户端：

```
https://<worker>.workers.dev/sub/<uuid>
```

兼容：v2rayN、Clash、sing-box、Shadowrocket、nekobox。

### 协议支持

- TCP 代理（命令 `0x01`）
- DNS over HTTPS / UDP 53 端口（命令 `0x02`）
- Early Data（0-RTT）通过 `sec-websocket-protocol`
- 地址类型：IPv4、域名、IPv6

</td>
</tr>
</table>
