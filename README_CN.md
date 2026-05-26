# cloudflare-vless

[![Deploy to Cloudflare](https://deploy.workers.cloudflare.com/button)](https://deploy.workers.cloudflare.com/?url=https://github.com/nadav-cheung/cloudflare-vless)

[English](README.md)

基于 Cloudflare Workers 的 VLESS over WebSocket 代理。

单文件实现，遵循 [VLESS 协议规范](https://xtls.github.io/en/development/protocols/vless.html)。通过 `cloudflare:sockets` 代理 TCP 流量，通过 DNS-over-HTTPS 解析 DNS。

## 部署

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

## 环境变量

| 变量 | 默认值 | 说明 |
|------|--------|------|
| `UUID` | 硬编码 | 认证 UUID |
| `PROXYIP` | 随机 | 边缘回退代理 IP |
| `DNS_RESOLVER_URL` | `cloudflare-dns.com` | DoH 端点 |

## 端点

| 路径 | 说明 |
|------|------|
| `WebSocket /` | VLESS 代理 |
| `GET /sub/{uuid}` | Base64 订阅 |
| `GET /*` | 404 |

## 客户端配置

将订阅 URL 导入客户端：

```
https://<worker>.workers.dev/sub/<uuid>
```

兼容：v2rayN、Clash、sing-box、Shadowrocket、nekobox。

## 协议支持

- TCP 代理（命令 `0x01`）
- DNS over HTTPS / UDP 53 端口（命令 `0x02`）
- Early Data（0-RTT）通过 `sec-websocket-protocol`
- 地址类型：IPv4、域名、IPv6
