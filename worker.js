import { connect } from 'cloudflare:sockets';

// ── Configuration ──────────────────────────────────────────────────────

const DEFAULT_UUID = '80e753d7-3195-4302-a881-50d71d0030e2';
const FALLBACK_PROXY_IPS = [
    '166.1.160.140',
    '107.172.16.110',
    '64.188.27.145',
    '43.169.18.179',
];
const SOURCE_TIERS = [
    { name: 'doh', type: 'doh' },
    { name: 'gh-bestproxy', url: 'https://raw.githubusercontent.com/ymyuuu/IPDB/master/BestProxy/bestproxy.txt' },
    { name: 'gh-proxy', url: 'https://raw.githubusercontent.com/ymyuuu/IPDB/master/BestProxy/proxy.txt' },
    { name: 'gh-proxy-root', url: 'https://raw.githubusercontent.com/ymyuuu/IPDB/master/proxy.txt' },
    { name: 'api-bestproxy', url: 'https://ipdb.api.030101.xyz/?type=bestproxy' },
    { name: 'api-proxy', url: 'https://ipdb.api.030101.xyz/?type=proxy' },
];
const PROXYIP_DOH_DOMAINS = [
    'proxyip.cmliussss.net',
];
const POOL_MIN = 10;
const POOL_MAX = 50;
const PROBE_CONCURRENCY = 6;
const PROBE_TIMEOUT_MS = 100;
const DEFAULT_DOH = 'https://cloudflare-dns.com/dns-query';
const HTTPS_PORTS = [443, 8443, 2053, 2096, 2087, 2083];
const TCP_TIMEOUT = 10_000;
const WS_OPEN = 1;

let _pool = [];
let _refilling = null;
let _refillingStart = 0;
let _refillGen = 0;
let _quickRefilling = false;
let _lastRefillFail = 0;
const REFILL_RETRY_INTERVAL_MS = 60_000;

if (!isValidUUID(DEFAULT_UUID)) throw new Error('Invalid default UUID');

// ── Proxy IP Pool ──────────────────────────────────────────────────────

function getPool() {
    return _pool.length > 0 ? _pool : FALLBACK_PROXY_IPS;
}

async function healthCheck() {
    if (_refilling) await _refilling;
    if (_pool.length === 0) return;
    const before = [..._pool];
    const start = Date.now();
    const alive = await probeBatch(_pool);
    const dead = before.filter(ip => !alive.includes(ip));
    _pool = alive;
    console.log(`[health] ${alive.length}/${before.length} alive, ${dead.length} dead (${Date.now() - start}ms)`);
    if (dead.length > 0) console.log(`[health] removed: ${dead.join(', ')}`);
}

async function quickRefill() {
    if (_quickRefilling) return;
    _quickRefilling = true;
    try {
        const existing = new Set(_pool);
        const candidates = [];
        const [dohResult, ghResult] = await Promise.allSettled([
            resolveDoH(),
            fetchSourceURL(SOURCE_TIERS[1].url),
        ]);
        for (const r of [dohResult, ghResult]) {
            if (r.status === 'fulfilled') {
                for (const ip of r.value) {
                    if (!existing.has(ip) && isPublicIP(ip)) {
                        candidates.push(ip);
                        existing.add(ip);
                    }
                }
            }
        }
        if (candidates.length === 0) return;
        const needed = Math.max(0, POOL_MAX - _pool.length);
        console.log(`[quick-refill] probing ${candidates.length} (need ${needed})`);
        const alive = await probeBatch(candidates, needed);
        const toAdd = alive.slice(0, needed);
        _pool.push(...toAdd);
        console.log(`[quick-refill] +${toAdd.length} added, pool=${_pool.length}`);
    } finally {
        _quickRefilling = false;
    }
}

async function refill() {
    if (_refilling) {
        if (_refillingStart && Date.now() - _refillingStart > 90_000) {
            console.error('[refill] stuck lock detected, clearing');
            _refilling = null;
        } else {
            return _refilling;
        }
    }
    _refillingStart = Date.now();
    const gen = ++_refillGen;
    _refilling = _doRefill().finally(() => {
        if (_refillGen === gen) { _refilling = null; _refillingStart = 0; }
    });
    return _refilling;
}

async function _doRefill() {
    const start = Date.now();
    for (const tier of SOURCE_TIERS) {
        if (_pool.length >= POOL_MAX) break;

        let ips;
        try {
            ips = tier.type === 'doh' ? await resolveDoH() : await fetchSourceURL(tier.url);
        } catch (e) {
            console.log(`[refill] ${tier.name}: fetch failed - ${e.message}`);
            continue;
        }

        const existing = new Set(_pool);
        const candidates = [...new Set(ips.filter(ip => !existing.has(ip) && isPublicIP(ip)))];
        if (candidates.length === 0) {
            console.log(`[refill] ${tier.name}: 0 new IPs, skip`);
            continue;
        }

        const needed = POOL_MAX - _pool.length;
        const tierStart = Date.now();
        console.log(`[refill] ${tier.name}: probing ${candidates.length} (need ${needed})`);
        const alive = await probeBatch(candidates, needed);
        const room = Math.max(0, POOL_MAX - _pool.length);
        const toAdd = alive.slice(0, room);
        _pool.push(...toAdd);
        if (_pool.length > POOL_MAX) _pool.length = POOL_MAX;
        console.log(`[refill] ${tier.name}: ${candidates.length} probed, ${alive.length} alive, +${toAdd.length} added, pool=${_pool.length} (${Date.now() - tierStart}ms)`);
    }
    console.log(`[refill] done: pool=${_pool.length} total=${Date.now() - start}ms`);
}

function isPublicIP(ip) {
    const parts = ip.includes(':') ? null : ip.split('.').map(Number);
    if (!parts || parts.length !== 4 || parts.some(p => isNaN(p) || p < 0 || p > 255)) return false;
    const [a, b, c, d] = parts;
    if (a === 0 || a === 127) return false;
    if (a === 10) return false;
    if (a === 172 && b >= 16 && b <= 31) return false;
    if (a === 192 && b === 168) return false;
    if (a === 169 && b === 254) return false;
    if (a === 100 && b >= 64 && b <= 127) return false;
    if (a === 192 && b === 0 && c === 0) return false;
    if (a === 198 && b === 51 && c === 100) return false;
    if (a === 203 && b === 0 && c === 113) return false;
    if (a === 224) return false;
    if (a >= 240) return false;
    return true;
}

async function fetchSourceURL(url) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 5000);
    try {
        const resp = await fetch(url, { signal: controller.signal });
        if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
        const text = await resp.text();
        const ips = text.trim().split('\n')
            .map(s => s.trim())
            .filter(s => s && !s.startsWith('#') && isPublicIP(s));
        if (ips.length === 0) throw new Error('empty');
        const parsed = new URL(url);
        const tag = parsed.search || parsed.pathname.split('/').pop() || parsed.hostname;
        console.log(`[ipdb] ${tag}: ${ips.length} IPs`);
        return ips;
    } finally {
        clearTimeout(timer);
    }
}

async function resolveDoH() {
    const all = [];
    const results = await Promise.allSettled(PROXYIP_DOH_DOMAINS.map(async (domain) => {
        const resp = await fetch(`https://cloudflare-dns.com/dns-query?name=${domain}&type=A`, {
            headers: { accept: 'application/dns-json' },
        });
        if (!resp.ok) throw new Error(`DoH ${domain}: HTTP ${resp.status}`);
        const data = await resp.json();
        const ips = (data.Answer || []).filter(a => a.type === 1).map(a => a.data);
        if (ips.length === 0) throw new Error(`DoH ${domain}: no IPs`);
        console.log(`[doh] ${domain}: ${ips.length} IPs`);
        return ips;
    }));
    for (const r of results) {
        if (r.status === 'fulfilled' && r.value) all.push(...r.value);
    }
    if (all.length === 0) throw new Error('DoH: all domains failed');
    return [...new Set(all)];
}

async function probeOne(addr) {
    const [host, portStr] = addr.includes(':') ? addr.split(':') : [addr, '443'];
    const port = parseInt(portStr);
    if (!Number.isFinite(port) || port < 1 || port > 65535) {
        throw new Error(`invalid port: ${addr}`);
    }
    const sock = connect({ hostname: host, port });
    try {
        await Promise.race([
            sock.opened,
            new Promise((_, r) => setTimeout(() => r(new Error('timeout')), PROBE_TIMEOUT_MS)),
        ]);
    } catch (e) {
        console.log(`[probe] ${addr} FAIL ${e.message}`);
        throw e;
    } finally {
        sock.close();
    }
    return addr;
}

async function probeBatch(candidates, maxAlive = Infinity) {
    const alive = [];
    for (let i = 0; i < candidates.length && alive.length < maxAlive; i += PROBE_CONCURRENCY) {
        const chunk = candidates.slice(i, i + PROBE_CONCURRENCY);
        const results = await Promise.allSettled(chunk.map(addr => probeOne(addr)));
        for (const r of results) {
            if (r.status === 'fulfilled') {
                alive.push(r.value);
                if (alive.length >= maxAlive) break;
            }
        }
    }
    return alive;
}

// ── Router ─────────────────────────────────────────────────────────────

export default {
    async fetch(request, env, ctx) {
        const uuid = env.UUID || DEFAULT_UUID;
        if (!isValidUUID(uuid)) return new Response('Invalid UUID', { status: 500 });
        const uuidBytes = uuidToBytes(uuid);
        const dohURL = env.DNS_RESOLVER_URL || DEFAULT_DOH;
        const upgradeHeader = request.headers.get('Upgrade');
        if (!upgradeHeader || upgradeHeader.toLowerCase() !== 'websocket') {
            const url = new URL(request.url);
            if (url.pathname === `/sub/${uuid}`) {
                return new Response(btoa(generateSub(uuid, url.hostname)), {
                    headers: { 'Content-Type': 'text/plain; charset=utf-8' },
                });
            }
            return new Response('Not Found', { status: 404 });
        }

        const configProxyIP = env.PROXYIP || null;
        if (!configProxyIP && _pool.length === 0 && !_refilling && (Date.now() - _lastRefillFail) > REFILL_RETRY_INTERVAL_MS) {
            try {
                await Promise.race([
                    quickRefill(),
                    new Promise((_, r) => setTimeout(() => r(new Error('timeout')), 15_000)),
                ]);
            } catch (e) {
                console.error('[pool] quick-refill:', e.message);
            }
            if (_pool.length === 0) _lastRefillFail = Date.now();
        }
        const pool = configProxyIP ? [] : getPool();
        const proxyIP = configProxyIP || pool[Math.floor(Math.random() * pool.length)];
        const proxyPort = env.PROXYPORT || null;
        return vlessOverWS(request, uuidBytes, proxyIP, proxyPort, dohURL);
    },

    async scheduled(controller, env, ctx) {
        await healthCheck();
        if (_pool.length < POOL_MIN) {
            await refill();
        }
    },
};

// ── VLESS over WebSocket ───────────────────────────────────────────────

async function vlessOverWS(request, uuidBytes, proxyIP, proxyPort, dohURL) {
    const [client, ws] = Object.values(new WebSocketPair());
    ws.binaryType = 'arraybuffer';
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
                try {
                    await writer.write(chunk);
                } finally {
                    writer.releaseLock();
                }
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

            relayTCP(hdr.address, hdr.port, payload, ws, respHeader, proxyIP, proxyPort, remoteRef)
                .catch(err => { console.error('relayTCP failed', err); safeCloseWS(ws); });
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
    let diff = 0;
    for (let i = 0; i < 16; i++) diff |= v[1 + i] ^ expectedBytes[i];
    if (diff !== 0) return { error: 'Invalid user' };

    const addonsLen = v[17];
    if (addonsLen > 32) return { error: 'Addons too long' };
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
        try {
            await writer.write(initialData);
        } finally {
            writer.releaseLock();
        }
        return socket;
    }

    async function retry() {
        if (ws.readyState !== WS_OPEN) return;
        const old = remoteRef.value;
        remoteRef.value = null;
        if (old) try { old.close(); } catch {}

        const pool = getPool();
        if (pool.length === 0) { safeCloseWS(ws); return; }
        const maxRetries = 4;
        const tried = new Set();
        const candidates = proxyIP && proxyIP !== address ? [proxyIP] : [];
        for (let i = 0; i < maxRetries && tried.size < pool.length; i++) {
            let idx;
            do { idx = Math.floor(Math.random() * pool.length); } while (tried.has(idx));
            tried.add(idx);
            candidates.push(pool[idx]);
        }

        for (const addr of candidates) {
            const [host, portStr] = addr.includes(':') ? addr.split(':') : [addr, null];
            const p = portStr ? parseInt(portStr) : (proxyPort || port);
            try {
                const socket = await connectAndWrite(host, p);
                pipeRemoteToWS(socket, ws, respHeader, null);
                return;
            } catch { /* try next */ }
        }
        safeCloseWS(ws);
    }

    try {
        const socket = await connectAndWrite(address);
        pipeRemoteToWS(socket, ws, respHeader, retry);
    } catch {
        if (remoteRef.value) {
            try { remoteRef.value.close(); } catch {}
            remoteRef.value = null;
        }
        retry().catch(err => console.error('retry failed', err));
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
    } catch (err) {
        console.error('pipeRemoteToWS error', err);
        safeCloseWS(ws);
    }

    if (!hasData && retryFn && ws.readyState === WS_OPEN) {
        retryFn().catch(err => console.error('retryFn failed', err));
    }
}

// ── DNS over HTTPS ─────────────────────────────────────────────────────
// UDP data is framed as: [2-byte big-endian length][payload][2-byte length][payload]...
// A single WebSocket message may contain partial framing — buffer handles cross-frame reassembly.

const MAX_DNS_PACKET = 4096;
const MAX_DNS_BUFFER = 65536;
const MAX_PENDING_DNS = 16;

async function handleDNS(ws, respHeader, initialChunk, dohURL) {
    let headerSent = false;
    let buffer = new Uint8Array(0);
    let pending = 0;

    function append(data) {
        if (buffer.length + data.length > MAX_DNS_BUFFER) {
            safeCloseWS(ws);
            throw new Error('DNS buffer overflow');
        }
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
            if (len === 0 || len > MAX_DNS_PACKET) {
                off += 2;
                continue;
            }
            if (off + 2 + len > buffer.length) break;
            packets.push(buffer.slice(off + 2, off + 2 + len));
            off += 2 + len;
        }
        if (off > 0) buffer = buffer.slice(off);
        return packets;
    }

    async function resolve(data) {
        if (pending >= MAX_PENDING_DNS) {
            console.warn(`DNS query dropped: ${pending} pending (limit ${MAX_PENDING_DNS})`);
            return;
        }
        pending++;
        try {
            const resp = await fetch(dohURL, {
                method: 'POST',
                headers: { 'content-type': 'application/dns-message' },
                body: data,
            });
            if (!resp.ok) throw new Error(`DoH returned ${resp.status}`);
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
        } finally {
            pending--;
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

function generateSub(uuid, host) {
    const base = `?encryption=none&security=tls&sni=${host}&fp=random&type=ws&host=${host}&path=%2F%3Fed%3D2048`;
    const lines = [];
    for (const port of HTTPS_PORTS) {
        lines.push(`vless://${uuid}@${host}:${port}${base}#${host}-${port}`);
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
