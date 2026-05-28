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
const POOL_MIN = 4;
const POOL_MAX = 16;
const PROBE_CONCURRENCY = 6;
const PROBE_TIMEOUT_MS = 60;
const DEFAULT_DOH = 'https://cloudflare-dns.com/dns-query';
const HTTPS_PORTS = [443, 8443, 2053, 2096, 2087, 2083];
const TCP_TIMEOUT = 10_000;
const RETRY_TIMEOUT = 5_000;
const WS_OPEN = 1;
const WS_CLOSING = 2;

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

function addToPool(ips) {
    const seen = new Set(_pool);
    const room = POOL_MAX - _pool.length;
    let added = 0;
    for (const ip of ips) {
        if (added >= room || seen.has(ip)) continue;
        seen.add(ip);
        _pool.push(ip);
        added++;
    }
    return added;
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
        const added = addToPool(alive);
        console.log(`[quick-refill] +${added} added, pool=${_pool.length}`);
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
        const added = addToPool(alive);
        console.log(`[refill] ${tier.name}: ${candidates.length} probed, ${alive.length} alive, +${added} added, pool=${_pool.length} (${Date.now() - tierStart}ms)`);
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
    const resp = await fetchWithTimeout(url, {}, 5000);
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
}

async function resolveDoH() {
    const all = [];
    const results = await Promise.allSettled(PROXYIP_DOH_DOMAINS.map(async (domain) => {
        const resp = await fetchWithTimeout(
            `https://cloudflare-dns.com/dns-query?name=${domain}&type=A`,
            { headers: { accept: 'application/dns-json' } },
            5000,
        );
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
    const [host, port] = parseHostPort(addr, 443);
    if (!Number.isFinite(port) || port < 1 || port > 65535) {
        throw new Error(`invalid port: ${addr}`);
    }
    const sock = connect({ hostname: host, port });
    let timer;
    try {
        await Promise.race([
            sock.opened,
            new Promise((_, r) => { timer = setTimeout(() => r(new Error('timeout')), PROBE_TIMEOUT_MS); }),
        ]);
    } catch (e) {
        console.log(`[probe] ${addr} FAIL ${e.message}`);
        throw e;
    } finally {
        clearTimeout(timer);
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
                    new Promise(resolve => setTimeout(resolve, 5_000)),
                ]);
            } catch (e) {
                console.error('[pool] quick-refill:', e.message);
            }
            if (_pool.length === 0) _lastRefillFail = Date.now();
        }
        const pool = configProxyIP ? [] : getPool();
        const proxyIP = configProxyIP || pool[Math.floor(Math.random() * pool.length)];
        const proxyPort = parseInt(env.PROXYPORT) || null;
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
    const remoteRef = { value: null, writer: null };
    let dnsWriter = null;
    let relayStarted = false;
    const pending = [];

    makeWSReadable(ws, earlyData).pipeTo(new WritableStream({
        async write(chunk) {
            if (dnsWriter) {
                dnsWriter.write(chunk);
                return;
            }
            // Reuse a single writer for all WS→socket writes, acquired once per connection
            if (remoteRef.writer) {
                await remoteRef.writer.write(chunk);
                return;
            }
            // Buffer chunks arriving during TCP handshake, drained once connected
            if (relayStarted) {
                pending.push(chunk);
                return;
            }
            relayStarted = true;

            const hdr = parseVlessHeader(chunk, uuidBytes);
            if (hdr.error) throw new Error(hdr.error);

            const payload = chunk.slice(hdr.rawDataIndex);
            const respHeader = new Uint8Array([hdr.version, 0]);

            if (hdr.isUDP) {
                if (hdr.port !== 53) throw new Error('UDP only for DNS port 53');
                dnsWriter = await handleDNS(ws, respHeader, payload, dohURL);
                return;
            }

            relayTCP(hdr.address, hdr.port, payload, ws, respHeader, proxyIP, proxyPort, remoteRef, pending);
        },
    })).catch(err => { console.error('ws pipe error', err); safeCloseWS(ws); });

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
    // Floor: version(1)+uuid(16)+addonsLen(1)+command(1)+port(2)+addrType(1)=22;
    // per-field truncation checks below validate the address payload bounds
    if (v.length < 22) return { error: 'Header too short' };

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
            address = _td.decode(v.subarray(base + 1, base + 1 + dLen));
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

async function relayTCP(address, port, initialData, ws, respHeader, proxyIP, proxyPort, remoteRef, pending) {
    async function connectAndWrite(addr, connectPort) {
        const socket = connect({ hostname: addr, port: connectPort || port });

        let timer;
        const timeout = new Promise((_, rej) => {
            timer = setTimeout(() => rej(new Error('TCP timeout')), TCP_TIMEOUT);
        });
        try {
            await Promise.race([socket.opened, timeout]);
        } catch (err) {
            // Don't let socket.close() throw mask the connection error
            try { socket.close(); } catch {}
            throw err;
        } finally {
            clearTimeout(timer);
        }
        // Return writer to caller — caller drains pending before exposing to WS handler
        remoteRef.value = socket;
        const writer = socket.writable.getWriter();
        await writer.write(initialData);
        return { socket, writer };
    }

    async function retry() {
        if (ws.readyState !== WS_OPEN) return;
        if (remoteRef.writer) {
            try { remoteRef.writer.releaseLock(); } catch {}
            remoteRef.writer = null;
        }
        const old = remoteRef.value;
        remoteRef.value = null;
        if (old) try { old.close(); } catch {}

        const pool = getPool();
        if (pool.length === 0) { safeCloseWS(ws); return; }
        const maxRetries = 3;
        const tried = new Set();
        const candidatesSet = new Set(proxyIP && proxyIP !== address ? [proxyIP] : []);
        for (let i = 0; i < maxRetries && tried.size < pool.length; i++) {
            let idx;
            do { idx = Math.floor(Math.random() * pool.length); } while (tried.has(idx));
            tried.add(idx);
            candidatesSet.add(pool[idx]);
        }
        const candidates = [...candidatesSet];

        let won = false;
        const allSockets = [];

        const attempts = candidates.map(async (addr) => {
            const [host, p] = parseHostPort(addr, proxyPort || port);
            if (!Number.isFinite(p) || p < 1 || p > 65535) throw new Error(`invalid port: ${addr}`);
            const socket = connect({ hostname: host, port: p });
            allSockets.push(socket);

            let timer;
            try {
                await Promise.race([
                    socket.opened,
                    new Promise((_, r) => { timer = setTimeout(() => r(new Error('timeout')), RETRY_TIMEOUT); }),
                ]);
            } catch (e) {
                try { socket.close(); } catch {}
                throw e;
            } finally {
                clearTimeout(timer);
            }

            if (won) {
                try { socket.close(); } catch {}
                throw new Error('lost');
            }
            won = true;
            const writer = socket.writable.getWriter();
            try {
                await writer.write(initialData);
                const toDrain = pending.splice(0);
                for (const chunk of toDrain) await writer.write(chunk);
            } finally {
                writer.releaseLock();
            }

            remoteRef.value = socket;
            remoteRef.writer = socket.writable.getWriter();
            // Drain chunks that arrived during the transition
            const late = pending.splice(0);
            for (const chunk of late) await remoteRef.writer.write(chunk);
            for (const s of allSockets) {
                if (s && s !== socket) try { s.close(); } catch {}
            }
            return socket;
        });

        try {
            const socket = await Promise.any(attempts);
            pipeRemoteToWS(socket, ws, respHeader, remoteRef, null);
        } catch {
            for (const s of allSockets) try { s.close(); } catch {}
            safeCloseWS(ws);
        }
    }

    try {
        const { socket, writer } = await connectAndWrite(address);
        const toDrain = pending.splice(0);
        for (const chunk of toDrain) await writer.write(chunk);
        remoteRef.writer = writer;
        // Drain chunks that arrived during the transition
        const late = pending.splice(0);
        for (const chunk of late) await remoteRef.writer.write(chunk);
        pipeRemoteToWS(socket, ws, respHeader, remoteRef, retry);
    } catch {
        if (remoteRef.writer) {
            try { remoteRef.writer.releaseLock(); } catch {}
            remoteRef.writer = null;
        }
        if (remoteRef.value) {
            try { remoteRef.value.close(); } catch {}
            remoteRef.value = null;
        }
        retry().catch(() => {});
    }
}

async function pipeRemoteToWS(socket, ws, respHeader, remoteRef, retryFn) {
    let headerSent = false;
    let hasData = false;

    try {
        await socket.readable.pipeTo(new WritableStream({
            write(chunk) {
                hasData = true;
                if (ws.readyState !== WS_OPEN) throw new Error('ws closed');
                ws.send(headerSent ? chunk : concatBytes(respHeader, chunk));
                headerSent = true;
            },
        }));
    } catch (err) {
        if (hasData || ws.readyState !== WS_OPEN) console.error('pipeRemoteToWS error', err);
    } finally {
        try { socket.close(); } catch {}
    }

    if (!hasData && ws.readyState === WS_OPEN && retryFn) {
        if (remoteRef.writer) {
            try { remoteRef.writer.releaseLock(); } catch {}
            remoteRef.writer = null;
        }
        retryFn().catch(() => {});
    } else {
        safeCloseWS(ws);
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
    const buf = new Uint8Array(MAX_DNS_BUFFER);
    let bufLen = 0;
    let pending = 0;

    function append(data) {
        const d = data instanceof Uint8Array ? data : new Uint8Array(data);
        if (bufLen + d.length > MAX_DNS_BUFFER) {
            safeCloseWS(ws);
            throw new Error('DNS buffer overflow');
        }
        buf.set(d, bufLen);
        bufLen += d.length;
    }

    function extractPackets() {
        const packets = [];
        let off = 0;
        while (off + 2 <= bufLen) {
            const len = (buf[off] << 8) | buf[off + 1];
            if (len === 0 || len > MAX_DNS_PACKET) {
                off += 2;
                continue;
            }
            if (off + 2 + len > bufLen) break;
            packets.push(buf.slice(off + 2, off + 2 + len));
            off += 2 + len;
        }
        if (off > 0) {
            buf.copyWithin(0, off, bufLen);
            bufLen -= off;
        }
        return packets;
    }

    async function resolve(data) {
        if (pending >= MAX_PENDING_DNS) {
            console.warn(`DNS query dropped: ${pending} pending (limit ${MAX_PENDING_DNS})`);
            return;
        }
        pending++;
        try {
            const resp = await fetchWithTimeout(dohURL, {
                method: 'POST',
                headers: { 'content-type': 'application/dns-message' },
                body: data,
            }, 10_000);
            if (!resp.ok) throw new Error(`DoH returned ${resp.status}`);
            const result = new Uint8Array(await resp.arrayBuffer());
            const sizeHdr = new Uint8Array([(result.length >> 8) & 0xff, result.length & 0xff]);

            if (ws.readyState !== WS_OPEN) return;
            if (!headerSent) {
                ws.send(concatBytes(respHeader, sizeHdr, result));
                headerSent = true;
            } else {
                ws.send(concatBytes(sizeHdr, result));
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

const _td = new TextDecoder();

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
        if (ws.readyState === WS_OPEN || ws.readyState === WS_CLOSING) ws.close();
    } catch { /* ignore */ }
}

function concatBytes(...parts) {
    let total = 0;
    for (const p of parts) total += p.byteLength;
    const out = new Uint8Array(total);
    let off = 0;
    for (const p of parts) {
        out.set(p instanceof Uint8Array ? p : new Uint8Array(p), off);
        off += p.byteLength;
    }
    return out;
}

async function fetchWithTimeout(url, opts = {}, ms = 5000) {
    const ac = new AbortController();
    const t = setTimeout(() => ac.abort(), ms);
    try {
        return await fetch(url, { ...opts, signal: ac.signal });
    } finally {
        clearTimeout(t);
    }
}

function parseHostPort(addr, defaultPort) {
    if (addr.startsWith('[')) {
        const close = addr.indexOf(']');
        if (close === -1) return [addr, defaultPort];
        const host = addr.substring(1, close);
        const rest = addr.substring(close + 1);
        return rest.startsWith(':') ? [host, parseInt(rest.substring(1)) || defaultPort] : [host, defaultPort];
    }
    const lastColon = addr.lastIndexOf(':');
    if (lastColon === -1) return [addr, defaultPort];
    if (addr.indexOf(':') === lastColon) {
        const port = parseInt(addr.substring(lastColon + 1));
        return Number.isFinite(port) && port > 0 && port <= 65535
            ? [addr.substring(0, lastColon), port]
            : [addr, defaultPort];
    }
    return [addr, defaultPort];
}
