import { connect } from 'cloudflare:sockets';

// ── Configuration ──────────────────────────────────────────────────────

const DEFAULT_UUID = '80e753d7-3195-4302-a881-50d71d0030e2';
const FALLBACK_PROXY_IPS = [
    '8.212.12.98',
    '47.242.218.87',
    '8.219.245.214',
];
const PROXY_CACHE_TTL = 30 * 60 * 1000; // 30 min
const proxyCache = { ips: [], ts: 0 };
const DEFAULT_DOH = 'https://cloudflare-dns.com/dns-query';
const HTTPS_PORTS = [443, 8443, 2053, 2096, 2087, 2083];
const TCP_TIMEOUT = 10_000;
const WS_OPEN = 1;

if (!isValidUUID(DEFAULT_UUID)) throw new Error('Invalid default UUID');

async function getProxyIP(env) {
    if (env.PROXYIP) return env.PROXYIP;

    const now = Date.now();
    if (proxyCache.ips.length && (now - proxyCache.ts) < PROXY_CACHE_TTL) {
        return proxyCache.ips[Math.floor(Math.random() * proxyCache.ips.length)];
    }

    try {
        const resp = await fetch('https://ipdb.api.030101.xyz/?type=bestproxy');
        if (!resp.ok) throw new Error(`IPDB returned ${resp.status}`);
        const text = await resp.text();
        proxyCache.ips = text.trim().split('\n').filter(Boolean);
        proxyCache.ts = now;
    } catch {}

    if (proxyCache.ips.length) {
        return proxyCache.ips[Math.floor(Math.random() * proxyCache.ips.length)];
    }
    return FALLBACK_PROXY_IPS[Math.floor(Math.random() * FALLBACK_PROXY_IPS.length)];
}

// ── Router ─────────────────────────────────────────────────────────────

export default {
    async fetch(request, env) {
        const uuid = env.UUID || DEFAULT_UUID;
        if (!isValidUUID(uuid)) return new Response('Invalid UUID', { status: 500 });
        const uuidBytes = uuidToBytes(uuid);
        const dohURL = env.DNS_RESOLVER_URL || DEFAULT_DOH;
        const proxyIP = await getProxyIP(env);
        const proxyPort = env.PROXYPORT || null;
        const url = new URL(request.url);

        if (request.headers.get('Upgrade') === 'websocket') {
            return vlessOverWS(request, uuidBytes, proxyIP, proxyPort, dohURL);
        }

        if (url.pathname === `/sub/${uuid}`) {
            return new Response(btoa(generateSub(uuid, url.hostname, proxyIP)), {
                headers: { 'Content-Type': 'text/plain; charset=utf-8' },
            });
        }

        return new Response('Not Found', { status: 404 });
    },
};

// ── VLESS over WebSocket ───────────────────────────────────────────────

async function vlessOverWS(request, uuidBytes, proxyIP, proxyPort, dohURL) {
    const [client, ws] = Object.values(new WebSocketPair());
    ws.accept();

    const earlyData = decodeEarlyData(request.headers.get('sec-websocket-protocol') || '');
    const remoteRef = { value: null };
    let dnsWriter = null;

    makeWSReadable(ws, earlyData).pipeTo(new WritableStream({
        async write(chunk) {
            if (dnsWriter) {
                dnsWriter.write(chunk);
                return;
            }
            if (remoteRef.value) {
                const writer = remoteRef.value.writable.getWriter();
                await writer.write(chunk);
                writer.releaseLock();
                return;
            }

            const hdr = parseVlessHeader(chunk, uuidBytes);
            if (hdr.error) throw new Error(hdr.error);

            const payload = chunk.slice(hdr.rawDataIndex);
            const respHeader = new Uint8Array([hdr.version, 0]);

            if (hdr.isUDP) {
                if (hdr.port !== 53) throw new Error('UDP only for DNS port 53');
                dnsWriter = await handleDNS(ws, respHeader, payload, dohURL);
                return;
            }

            relayTCP(hdr.address, hdr.port, payload, ws, respHeader, proxyIP, proxyPort, remoteRef);
        },
    })).catch(err => console.error('ws pipe error', err));

    return new Response(null, { status: 101, webSocket: client });
}

// ── VLESS Header Parser ───────────────────────────────────────────────
// Spec: https://xtls.github.io/en/development/protocols/vless.html
//
// [0]      Version (0x00)
// [1:17]   UUID (16 bytes)
// [17]     Addons length M
// [18+M]   Command (0x01=TCP, 0x02=UDP)
// [19+M:21+M]  Port (big-endian uint16)
// [21+M]   Address type (1=IPv4, 2=Domain, 3=IPv6)
// [22+M+]  Address value
// After address: raw payload data

function parseVlessHeader(buf, expectedBytes) {
    const v = new Uint8Array(buf);
    if (v.length < 26) return { error: 'Header too short' };

    const version = v[0];
    if (version !== 0x00) return { error: `Unsupported version: ${version}` };
    for (let i = 0; i < 16; i++) {
        if (v[1 + i] !== expectedBytes[i]) return { error: 'Invalid user' };
    }

    const addonsLen = v[17];
    const cmdIdx = 18 + addonsLen;
    if (cmdIdx >= v.length) return { error: 'Truncated at command' };

    const cmd = v[cmdIdx];
    const isUDP = cmd === 0x02;
    if (cmd !== 0x01 && !isUDP) return { error: `Unsupported command: ${cmd}` };

    const portIdx = cmdIdx + 1;
    if (portIdx + 2 > v.length) return { error: 'Truncated at port' };
    const port = (v[portIdx] << 8) | v[portIdx + 1];

    const addrIdx = portIdx + 2;
    if (addrIdx >= v.length) return { error: 'Truncated at address type' };
    const addrType = v[addrIdx];

    let address, rawDataIndex;
    const base = addrIdx + 1;

    switch (addrType) {
        case 0x01:
            if (base + 4 > v.length) return { error: 'Truncated IPv4' };
            address = v.slice(base, base + 4).join('.');
            rawDataIndex = base + 4;
            break;
        case 0x02: {
            if (base >= v.length) return { error: 'Truncated domain length' };
            const dLen = v[base];
            if (base + 1 + dLen > v.length) return { error: 'Truncated domain' };
            address = new TextDecoder().decode(buf.slice(base + 1, base + 1 + dLen));
            rawDataIndex = base + 1 + dLen;
            break;
        }
        case 0x03: {
            if (base + 16 > v.length) return { error: 'Truncated IPv6' };
            const parts = [];
            for (let i = 0; i < 8; i++) {
                parts.push(((v[base + i * 2] << 8) | v[base + i * 2 + 1]).toString(16));
            }
            address = parts.join(':');
            rawDataIndex = base + 16;
            break;
        }
        default:
            return { error: `Unknown address type: ${addrType}` };
    }

    if (!address) return { error: 'Empty address' };
    return { version, isUDP, address, port, rawDataIndex };
}

// ── TCP Relay ──────────────────────────────────────────────────────────

async function relayTCP(address, port, initialData, ws, respHeader, proxyIP, proxyPort, remoteRef) {
    async function connectAndWrite(addr, connectPort) {
        const socket = connect({ hostname: addr, port: connectPort || port });
        remoteRef.value = socket;

        let timer;
        const timeout = new Promise((_, rej) => {
            timer = setTimeout(() => rej(new Error('TCP timeout')), TCP_TIMEOUT);
        });
        try {
            await Promise.race([socket.opened, timeout]);
        } catch (err) {
            socket.close();
            throw err;
        } finally {
            clearTimeout(timer);
        }

        const writer = socket.writable.getWriter();
        await writer.write(initialData);
        writer.releaseLock();
        return socket;
    }

    async function retry() {
        if (ws.readyState !== WS_OPEN) return;
        // Close old socket before retrying
        const old = remoteRef.value;
        remoteRef.value = null;
        if (old) try { old.close(); } catch {}
        try {
            const socket = await connectAndWrite(proxyIP, proxyPort || port);
            pipeRemoteToWS(socket, ws, respHeader, null);
        } catch {
            safeCloseWS(ws);
        }
    }

    try {
        const socket = await connectAndWrite(address);
        pipeRemoteToWS(socket, ws, respHeader, retry);
    } catch {
        if (proxyIP) {
            retry();
        } else {
            safeCloseWS(ws);
        }
    }
}

async function pipeRemoteToWS(socket, ws, respHeader, retryFn) {
    let headerSent = false;
    let hasData = false;

    try {
        await socket.readable.pipeTo(new WritableStream({
            async write(chunk) {
                hasData = true;
                if (ws.readyState !== WS_OPEN) throw new Error('ws closed');
                if (!headerSent) {
                    ws.send(await new Blob([respHeader, chunk]).arrayBuffer());
                    headerSent = true;
                } else {
                    ws.send(chunk);
                }
            },
        }));
    } catch {
        safeCloseWS(ws);
    }

    if (!hasData && retryFn && ws.readyState === WS_OPEN) retryFn();
}

// ── DNS over HTTPS ─────────────────────────────────────────────────────
// UDP data is framed as: [2-byte big-endian length][payload][2-byte length][payload]...
// A single WebSocket message may contain partial framing — buffer handles cross-frame reassembly.

async function handleDNS(ws, respHeader, initialChunk, dohURL) {
    let headerSent = false;
    let buffer = new Uint8Array(0);

    function append(data) {
        const merged = new Uint8Array(buffer.length + data.length);
        merged.set(buffer, 0);
        merged.set(data, buffer.length);
        buffer = merged;
    }

    function extractPackets() {
        const packets = [];
        let off = 0;
        while (off + 2 <= buffer.length) {
            const len = (buffer[off] << 8) | buffer[off + 1];
            if (off + 2 + len > buffer.length) break;
            packets.push(buffer.slice(off + 2, off + 2 + len));
            off += 2 + len;
        }
        if (off > 0) buffer = buffer.slice(off);
        return packets;
    }

    async function resolve(data) {
        try {
            const resp = await fetch(dohURL, {
                method: 'POST',
                headers: { 'content-type': 'application/dns-message' },
                body: data,
            });
            const result = new Uint8Array(await resp.arrayBuffer());
            const sizeHdr = new Uint8Array([(result.length >> 8) & 0xff, result.length & 0xff]);

            if (ws.readyState !== WS_OPEN) return;
            if (!headerSent) {
                ws.send(await new Blob([respHeader, sizeHdr, result]).arrayBuffer());
                headerSent = true;
            } else {
                ws.send(await new Blob([sizeHdr, result]).arrayBuffer());
            }
        } catch (err) {
            console.error('DNS resolve error', err);
        }
    }

    append(new Uint8Array(initialChunk));
    for (const pkt of extractPackets()) resolve(pkt);

    return {
        write(chunk) {
            append(new Uint8Array(chunk));
            for (const pkt of extractPackets()) resolve(pkt);
        },
    };
}

// ── Subscription Generator ─────────────────────────────────────────────

function generateSub(uuid, host, proxyIP) {
    const base = `?encryption=none&security=tls&sni=${host}&fp=random&type=ws&host=${host}&path=%2F%3Fed%3D2048`;
    const lines = [];
    for (const port of HTTPS_PORTS) {
        lines.push(`vless://${uuid}@${host}:${port}${base}#${host}-${port}`);
        lines.push(`vless://${uuid}@${proxyIP}:${port}${base}#${host}-${proxyIP}-${port}`);
    }
    return lines.join('\n');
}

// ── Utilities ──────────────────────────────────────────────────────────

function makeWSReadable(ws, earlyData) {
    return new ReadableStream({
        start(controller) {
            ws.addEventListener('message', e => controller.enqueue(e.data));
            ws.addEventListener('close', () => controller.close());
            ws.addEventListener('error', e => controller.error(e));
            if (earlyData) controller.enqueue(earlyData);
        },
        cancel() {
            safeCloseWS(ws);
        },
    });
}

function decodeEarlyData(header) {
    if (!header) return null;
    try {
        const b64 = header.replace(/-/g, '+').replace(/_/g, '/');
        const decoded = atob(b64);
        return Uint8Array.from(decoded, c => c.charCodeAt(0)).buffer;
    } catch {
        return null;
    }
}

function uuidToBytes(uuid) {
    const hex = uuid.replace(/-/g, '');
    const bytes = new Uint8Array(16);
    for (let i = 0; i < 16; i++) bytes[i] = parseInt(hex.substring(i * 2, i * 2 + 2), 16);
    return bytes;
}

function isValidUUID(uuid) {
    return /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(uuid);
}

function safeCloseWS(ws) {
    try {
        if (ws.readyState === WS_OPEN || ws.readyState === 2) ws.close();
    } catch { /* ignore */ }
}
