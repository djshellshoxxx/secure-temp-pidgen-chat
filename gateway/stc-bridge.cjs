#!/usr/bin/env node
'use strict';
/*
 * Secure Temp Chat - local bridge (zero dependencies, Node 18+)
 *
 * Why it exists: a web page cannot open raw TCP sockets, cannot use SOCKS proxies (Tor / I2P),
 * and cannot read the TLS cipher it negotiated. This tiny program, run on YOUR computer,
 * does those three things for the page over a WebSocket on 127.0.0.1.
 *
 *   mode=tcp : plain IRC-style line protocol (IRC servers on 6697/TLS, BitlBee, ...)
 *   mode=ws  : relays a WebSocket to a remote WebSocket (XMPP over wss) through Tor/I2P
 *
 * Safety: binds to 127.0.0.1, ONLY accepts browser pages whose Origin you list with --origin,
 * and only talks to Tor/I2P SOCKS ports that YOU configured. Never expose it to a network.
 *
 * Usage:
 *   node stc-bridge.cjs --origin https://YOURNAME.github.io [--listen 127.0.0.1:8765]
 *        [--tor 127.0.0.1:9050] [--i2p 127.0.0.1:4447] [--allow-insecure-tls]
 *        [--allow-host irc.example.org] (repeatable; default = any host)
 */
const net = require('net');
const tls = require('tls');
const http = require('http');
const crypto = require('crypto');

// ---------------------------------------------------------------- WebSocket framing
const GUID = '258EAFA5-E914-47DA-95CA-C5AB0DC85B11';
const acceptKey = (k) => crypto.createHash('sha1').update(k + GUID).digest('base64');

function encodeFrame(opcode, payload, mask) {
  const len = payload.length;
  let head;
  if (len < 126) head = Buffer.from([0x80 | opcode, (mask ? 0x80 : 0) | len]);
  else if (len < 65536) { head = Buffer.alloc(4); head[0] = 0x80 | opcode; head[1] = (mask ? 0x80 : 0) | 126; head.writeUInt16BE(len, 2); }
  else { head = Buffer.alloc(10); head[0] = 0x80 | opcode; head[1] = (mask ? 0x80 : 0) | 127; head.writeBigUInt64BE(BigInt(len), 2); }
  if (!mask) return Buffer.concat([head, payload]);
  const key = crypto.randomBytes(4);
  const body = Buffer.from(payload);
  for (let i = 0; i < body.length; i++) body[i] ^= key[i & 3];
  return Buffer.concat([head, key, body]);
}

class FrameReader {
  constructor(onFrame, maxSize = 1 << 20) { this.buf = Buffer.alloc(0); this.onFrame = onFrame; this.frag = []; this.fragOp = 0; this.max = maxSize; }
  push(chunk) {
    this.buf = Buffer.concat([this.buf, chunk]);
    for (;;) {
      const b = this.buf;
      if (b.length < 2) return;
      const fin = !!(b[0] & 0x80); const op = b[0] & 0x0f; const masked = !!(b[1] & 0x80);
      let len = b[1] & 0x7f; let off = 2;
      if (len === 126) { if (b.length < 4) return; len = b.readUInt16BE(2); off = 4; }
      else if (len === 127) { if (b.length < 10) return; len = Number(b.readBigUInt64BE(2)); off = 10; }
      if (len > this.max) throw new Error('frame too large');
      const need = off + (masked ? 4 : 0) + len;
      if (b.length < need) return;
      let payload = b.subarray(off + (masked ? 4 : 0), need);
      if (masked) { const k = b.subarray(off, off + 4); payload = Buffer.from(payload); for (let i = 0; i < payload.length; i++) payload[i] ^= k[i & 3]; }
      this.buf = b.subarray(need);
      if (op >= 8) { this.onFrame(op, Buffer.from(payload)); continue; }
      if (op !== 0) { this.fragOp = op; this.frag = []; }
      this.frag.push(Buffer.from(payload));
      if (fin) { const all = Buffer.concat(this.frag); this.frag = []; this.onFrame(this.fragOp, all); }
    }
  }
}

// ---------------------------------------------------------------- SOCKS5 (remote DNS: no leaks, .onion/.i2p work)
function socks5Connect(proxy, host, port, timeout = 30000) {
  return new Promise((resolve, reject) => {
    const [ph, pp] = proxy.split(':');
    const s = net.connect({ host: ph, port: +pp });
    let stage = 0; let acc = Buffer.alloc(0);
    const timer = setTimeout(() => { s.destroy(); reject(new Error('SOCKS5 proxy timed out')); }, timeout);
    const fail = (m) => { clearTimeout(timer); s.destroy(); reject(new Error(m)); };
    s.on('error', (e) => fail('SOCKS5 proxy error: ' + e.message));
    s.on('connect', () => s.write(Buffer.from([5, 1, 0])));
    s.on('data', function onData(d) {
      acc = Buffer.concat([acc, d]);
      if (stage === 0) {
        if (acc.length < 2) return;
        if (acc[0] !== 5 || acc[1] !== 0) return fail('SOCKS5 proxy refused no-auth login');
        acc = acc.subarray(2); stage = 1;
        const h = Buffer.from(host);
        s.write(Buffer.concat([Buffer.from([5, 1, 0, 3, h.length]), h, Buffer.from([port >> 8, port & 255])]));
      }
      if (stage === 1) {
        if (acc.length < 5) return;
        const atyp = acc[3];
        const total = 4 + (atyp === 1 ? 4 : atyp === 4 ? 16 : 1 + acc[4]) + 2;
        if (acc.length < total) return;
        if (acc[1] !== 0) return fail('SOCKS5 connect failed (code ' + acc[1] + ')');
        const rest = acc.subarray(total);
        clearTimeout(timer); s.removeListener('data', onData); s.removeAllListeners('error');
        if (rest.length) s.unshift(rest);
        resolve(s);
      }
    });
  });
}

// ---------------------------------------------------------------- upstream connections
async function rawSocket(route, host, port, cfg) {
  if (route === 'tor') return socks5Connect(cfg.tor, host, port);
  if (route === 'i2p') return socks5Connect(cfg.i2p, host, port);
  return new Promise((resolve, reject) => {
    const s = net.connect({ host, port }, () => { s.removeAllListeners('error'); resolve(s); });
    s.setTimeout(30000, () => { s.destroy(); reject(new Error('connect timeout')); });
    s.on('error', reject);
  });
}

function certSummary(sock) {
  const c = sock.getPeerCertificate && sock.getPeerCertificate();
  if (!c || !c.subject) return '';
  return `${c.subject.CN || ''} (issuer ${c.issuer && (c.issuer.O || c.issuer.CN) || '?'}, expires ${c.valid_to || '?'}, sha256 ${c.fingerprint256 || ''})`;
}

async function connectUpstream(p, cfg) {
  const raw = await rawSocket(p.route, p.host, p.port, cfg);
  if (!p.tls) return { sock: raw, hello: { tls: false } };
  const sock = await new Promise((resolve, reject) => {
    const t = tls.connect({ socket: raw, servername: net.isIP(p.host) ? undefined : p.host, minVersion: 'TLSv1.2', rejectUnauthorized: !p.insecure }, () => resolve(t));
    t.on('error', reject);
  });
  const ci = sock.getCipher();
  return {
    sock,
    hello: { tls: true, protocol: sock.getProtocol(), cipher: ci && ci.name, authorized: sock.authorized, authError: sock.authorized ? '' : String(sock.authorizationError || ''), cert: certSummary(sock) },
  };
}

function wsClientHandshake(sock, host, port, path, subproto, tlsOn) {
  return new Promise((resolve, reject) => {
    const key = crypto.randomBytes(16).toString('base64');
    sock.write(`GET ${path} HTTP/1.1\r\nHost: ${host}${(tlsOn && port === 443) || (!tlsOn && port === 80) ? '' : ':' + port}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: ${key}\r\nSec-WebSocket-Version: 13\r\n${subproto ? 'Sec-WebSocket-Protocol: ' + subproto + '\r\n' : ''}\r\n`);
    let acc = Buffer.alloc(0);
    const onData = (d) => {
      acc = Buffer.concat([acc, d]);
      const i = acc.indexOf('\r\n\r\n');
      if (i < 0) { if (acc.length > 16384) reject(new Error('bad handshake')); return; }
      sock.removeListener('data', onData);
      const head = acc.subarray(0, i).toString();
      if (!/^HTTP\/1\.1 101/.test(head) || !head.includes(acceptKey(key))) { reject(new Error('Remote WebSocket refused: ' + head.split('\r\n')[0])); return; }
      const rest = acc.subarray(i + 4);
      if (rest.length) sock.unshift(rest);
      resolve();
    };
    sock.on('data', onData);
  });
}

// ---------------------------------------------------------------- server
function startBridge(opts) {
  const cfg = {
    origins: opts.origins || [], tor: opts.tor || '127.0.0.1:9050', i2p: opts.i2p || '127.0.0.1:4447',
    allowInsecure: !!opts.allowInsecure, allowHosts: opts.allowHosts || [], log: opts.log || (() => {}),
  };
  const server = http.createServer((req, res) => { res.writeHead(426, { 'Content-Type': 'text/plain' }); res.end('Secure Temp Chat bridge: WebSocket only\n'); });
  server.on('upgrade', (req, sock) => {
    const reject = (code, msg) => { sock.end(`HTTP/1.1 ${code} ${msg}\r\nConnection: close\r\n\r\n`); };
    const origin = req.headers.origin || '';
    if (!cfg.origins.includes(origin)) { cfg.log(`rejected origin "${origin}" (allowed: ${cfg.origins.join(', ') || 'none'})`); return reject(403, 'Forbidden'); }
    const u = new URL(req.url, 'http://x');
    const p = {
      mode: u.searchParams.get('mode') === 'ws' ? 'ws' : 'tcp', host: u.searchParams.get('host') || '', port: parseInt(u.searchParams.get('port') || '0', 10),
      tls: u.searchParams.get('tls') !== '0', route: ['tor', 'i2p'].includes(u.searchParams.get('route')) ? u.searchParams.get('route') : 'direct',
      insecure: u.searchParams.get('insecure') === '1', path: u.searchParams.get('path') || '/', subproto: u.searchParams.get('subproto') || '',
    };
    if (!p.host || !(p.port > 0 && p.port < 65536) || !/^[A-Za-z0-9.\-_]+$/.test(p.host)) return reject(400, 'Bad target');
    if (cfg.allowHosts.length && !cfg.allowHosts.some((h) => p.host === h || p.host.endsWith('.' + h))) return reject(403, 'Host not allowed');
    if (p.insecure && !cfg.allowInsecure) return reject(403, 'Insecure TLS not enabled on this bridge (start it with --allow-insecure-tls)');
    const want = (req.headers['sec-websocket-protocol'] || '').split(',')[0].trim();
    sock.write(`HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: ${acceptKey(req.headers['sec-websocket-key'])}\r\n${want ? 'Sec-WebSocket-Protocol: ' + want + '\r\n' : ''}\r\n`);
    cfg.log(`session: ${p.mode} ${p.host}:${p.port} tls=${p.tls} route=${p.route}`);

    const sendText = (s) => { if (!sock.destroyed) sock.write(encodeFrame(1, Buffer.from(s), false)); };
    let up = null; let closed = false;
    const end = (why) => {
      if (closed) return; closed = true;
      if (why) { try { sock.write(encodeFrame(8, Buffer.from([0x03, 0xe8]), false)); } catch (e) { /* ignore */ } cfg.log('closed: ' + why); }
      try { sock.end(); } catch (e) { /* ignore */ }
      if (up) up.destroy();
    };
    let ready = false; const pending = [];
    const onClientText = (txt) => {
      if (!ready) { pending.push(txt); return; }
      if (p.mode === 'tcp') up.write(txt.replace(/[\r\n]+$/, '').replace(/[\r\n]+/g, ' ') + '\r\n');
      else up.write(encodeFrame(1, Buffer.from(txt), true));
    };
    const reader = new FrameReader((op, data) => {
      if (op === 8) end(); else if (op === 9) sock.write(encodeFrame(10, data, false)); else if (op === 1) onClientText(data.toString('utf8'));
    });
    sock.on('data', (d) => { try { reader.push(d); } catch (e) { end(e.message); } });
    sock.on('close', () => end()); sock.on('error', () => end());

    (async () => {
      try {
        const { sock: u2, hello } = await connectUpstream(p, cfg);
        up = u2; up.on('error', (e) => end('upstream error: ' + e.message)); up.on('close', () => end('upstream closed'));
        if (p.mode === 'ws') await wsClientHandshake(up, p.host, p.port, p.path, p.subproto, p.tls);
        sendText(JSON.stringify({ stc: 'hello', mode: p.mode, route: p.route, proxy: p.route === 'direct' ? '' : (p.route === 'tor' ? cfg.tor : cfg.i2p), ...hello }));
        if (p.mode === 'tcp') {
          let acc = '';
          up.on('data', (d) => { acc += d.toString('utf8'); let i; while ((i = acc.search(/\r?\n/)) >= 0) { const line = acc.slice(0, i); acc = acc.slice(acc.indexOf('\n', i) + 1); if (line) sendText(line); } if (acc.length > 65536) end('line too long'); });
        } else {
          const r = new FrameReader((op, data) => { if (op === 1) sendText(data.toString('utf8')); else if (op === 9) up.write(encodeFrame(10, data, true)); else if (op === 8) end(); });
          up.on('data', (d) => { try { r.push(d); } catch (e) { end(e.message); } });
        }
        ready = true; pending.splice(0).forEach(onClientText);
      } catch (e) { sendText(JSON.stringify({ stc: 'error', message: e.message })); end('connect failed: ' + e.message); }
    })();
  });
  return server;
}

function parseArgs(argv) {
  const o = { origins: [], allowHosts: [], listen: '127.0.0.1:8765' };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i]; const v = () => argv[++i];
    if (a === '--origin') o.origins.push(v().replace(/\/$/, ''));
    else if (a === '--listen') o.listen = v();
    else if (a === '--tor') o.tor = v();
    else if (a === '--i2p') o.i2p = v();
    else if (a === '--allow-host') o.allowHosts.push(v());
    else if (a === '--allow-insecure-tls') o.allowInsecure = true;
    else if (a === '-h' || a === '--help') o.help = true;
    else throw new Error('Unknown option ' + a);
  }
  return o;
}

module.exports = { startBridge, FrameReader, encodeFrame, acceptKey, socks5Connect, parseArgs };

if (require.main === module) {
  let o;
  try { o = parseArgs(process.argv.slice(2)); } catch (e) { console.error(e.message); process.exit(2); }
  if (o.help || !o.origins.length) {
    console.error('Secure Temp Chat bridge\nRequired: --origin https://YOURNAME.github.io   (the exact address of the chat page; repeatable)\nOptional: --listen 127.0.0.1:8765  --tor 127.0.0.1:9050  --i2p 127.0.0.1:4447  --allow-host H  --allow-insecure-tls');
    process.exit(o.help ? 0 : 2);
  }
  const [h, p] = o.listen.split(':');
  if (!['127.0.0.1', 'localhost', '::1'].includes(h)) console.error('WARNING: listening on a non-loopback address exposes a powerful proxy. Do this only if you know why.');
  startBridge({ ...o, log: (m) => console.log(new Date().toISOString(), m) }).listen(+p, h, () => console.log(`Bridge listening on ws://${h}:${p}  (allowed origins: ${o.origins.join(', ')})`));
}
