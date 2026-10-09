import test from 'node:test';
import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
import { execSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import * as C from '../js/crypto.js';
import { ChatCore } from '../js/chat.js';
import { IRCTransport, XMPPTransport } from '../js/transports.js';
const require = createRequire(import.meta.url);
const { mockIrc, mockXmpp, wsServer } = require('./helpers.cjs');
const { startBridge, FrameReader, encodeFrame } = require('../gateway/stc-bridge.cjs');
const http = require('node:http');
const net = require('node:net');
const tls = require('node:tls');
const crypto = require('node:crypto');

const wait = (f, ms = 8000) => new Promise((res, rej) => { const t0 = Date.now(); const i = setInterval(() => { const v = f(); if (v) { clearInterval(i); res(v); } else if (Date.now() - t0 > ms) { clearInterval(i); rej(new Error('timeout')); } }, 20); });

async function chatPair(mkT, o) {
  const log = { a: [], b: [] };
  const mk = (name, k) => {
    const t = mkT(name);
    t.maxChunk = 70; // force fragmentation
    const core = new ChatCore({ transport: t, e2e: o.mode, makeSession: () => new C.Session(o.sessionOpts), onEvent: (e) => log[k].push(e) });
    return { t, core };
  };
  const A = mk('alice', 'a'); const B = mk('bob', 'b');
  await A.t.connect(); await B.t.connect();
  return { A, B, log };
}

test('IRC transport: login, fragmented ratchet chat, SASL', async () => {
  const seen = [];
  const m = await mockIrc({ password: 'pw', seen });
  const url = `ws://127.0.0.1:${m.port}`;
  const so = { mode: 'ratchet', curve: 'P-256', auth: 'sign', identity: await C.makeIdentity() };
  const so2 = { ...so, identity: await C.makeIdentity() };
  const log = { a: [], b: [] };
  const ta = new IRCTransport({ url, nick: 'alice', user: 'alice', password: 'pw', subprotocol: 'text.ircv3.net' }, {});
  const tb = new IRCTransport({ url, nick: 'bob' }, {});
  ta.maxChunk = tb.maxChunk = 70;
  const A = new ChatCore({ transport: ta, e2e: 'ratchet', makeSession: () => new C.Session(so), onEvent: (e) => log.a.push(e) });
  const B = new ChatCore({ transport: tb, e2e: 'ratchet', makeSession: () => new C.Session(so2), onEvent: (e) => log.b.push(e) });
  await ta.connect(); await tb.connect();
  await A.start('bob');
  await wait(() => log.a.some((e) => e.type === 'ready') && log.b.some((e) => e.type === 'ready'));
  await A.sendText('bob', 'hello over irc, a message long enough to be fragmented into many pieces for the wire');
  await wait(() => log.b.some((e) => e.type === 'message'));
  assert.match(log.b.find((e) => e.type === 'message').text, /fragmented into many pieces/);
  await B.sendText('alice', 'reply');
  await wait(() => log.a.some((e) => e.type === 'message' && e.text === 'reply'));
  assert.ok(seen.length > 3 && seen.every((s) => !/hello over irc/.test(s)), 'server only ever saw ciphertext');
  A.close(); B.close(); m.close();
});

test('IRC SASL failure is reported', async () => {
  const m = await mockIrc({ password: 'right' });
  const t = new IRCTransport({ url: `ws://127.0.0.1:${m.port}`, nick: 'x', user: 'x', password: 'wrong' }, {});
  await assert.rejects(t.connect(), /SASL/);
  m.close();
});

test('XMPP transport: PLAIN + ANONYMOUS login, chat over passphrase mode, hints present', async () => {
  const seen = [];
  const m = await mockXmpp('chat.test', { password: 'pw', seen });
  const url = `ws://127.0.0.1:${m.port}`;
  const so = { mode: 'psk', passphrase: 'shared secret words here' };
  const log = { a: [], b: [] };
  const ta = new XMPPTransport({ url, jid: 'alice@chat.test', password: 'pw' }, {});
  const tb = new XMPPTransport({ url, jid: 'chat.test' }, {}); // anonymous
  const A = new ChatCore({ transport: ta, e2e: 'psk', makeSession: () => new C.Session(so), onEvent: (e) => log.a.push(e) });
  const B = new ChatCore({ transport: tb, e2e: 'psk', makeSession: () => new C.Session(so), onEvent: (e) => log.b.push(e) });
  await ta.connect(); await tb.connect();
  assert.match(ta.nick, /^alice@chat\.test\/res$/);
  assert.match(tb.nick, /^anon[0-9a-f]+@chat\.test\/res$/);
  await A.start(tb.nick);
  await A.sendText(tb.nick, 'xmpp <hello> & "friends"');
  await wait(() => log.b.some((e) => e.type === 'message'));
  assert.equal(log.b.find((e) => e.type === 'message').text, 'xmpp <hello> & "friends"');
  assert.ok(seen.every((s) => !/friends/.test(s)));
  A.close(); B.close(); m.close();
});

test('XMPP wrong password fails cleanly', async () => {
  const m = await mockXmpp('chat.test', { password: 'pw', mechs: ['PLAIN'] });
  const t = new XMPPTransport({ url: `ws://127.0.0.1:${m.port}`, jid: 'a@chat.test', password: 'bad' }, {});
  await assert.rejects(t.connect(), /Login failed/);
  m.close();
});

// ---------------- bridge ----------------
function rawWs(port, query, origin) {
  return new Promise((resolve, reject) => {
    const key = crypto.randomBytes(16).toString('base64');
    const req = http.request({ host: '127.0.0.1', port, path: '/?' + query, headers: { Connection: 'Upgrade', Upgrade: 'websocket', 'Sec-WebSocket-Key': key, 'Sec-WebSocket-Version': '13', Origin: origin } });
    req.on('upgrade', (res, sock, head) => {
      const msgs = []; const r = new FrameReader((op, d) => { if (op === 1) msgs.push(d.toString()); });
      if (head.length) r.push(head);
      sock.on('data', (d) => r.push(d));
      resolve({ msgs, send: (s) => sock.write(encodeFrame(1, Buffer.from(s), true)), close: () => sock.destroy() });
    });
    req.on('response', (res) => reject(new Error('HTTP ' + res.statusCode)));
    req.on('error', reject);
    req.end();
  });
}

test('bridge: rejects wrong origin and bad targets', async () => {
  const b = startBridge({ origins: ['https://good.example'], allowHosts: ['ok.example'] });
  await new Promise((r) => b.listen(0, '127.0.0.1', r));
  const port = b.address().port;
  await assert.rejects(rawWs(port, 'host=ok.example&port=6697', 'https://evil.example'), /403/);
  await assert.rejects(rawWs(port, 'host=other.example&port=6697', 'https://good.example'), /403/);
  await assert.rejects(rawWs(port, 'host=ok.example&port=6697&insecure=1', 'https://good.example'), /403/);
  await assert.rejects(rawWs(port, 'host=a%20b&port=1', 'https://good.example'), /400/);
  b.close();
});

test('bridge: TLS to IRC server reports real cipher; relays lines; Tor route uses SOCKS with remote DNS', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'stc-'));
  execSync(`openssl req -x509 -newkey rsa:2048 -nodes -keyout ${dir}/k.pem -out ${dir}/c.pem -days 2 -subj /CN=localhost 2>/dev/null`);
  const lines = [];
  const irc = tls.createServer({ key: fs.readFileSync(dir + '/k.pem'), cert: fs.readFileSync(dir + '/c.pem') }, (s) => {
    s.on('data', (d) => { d.toString().split('\r\n').filter(Boolean).forEach((l) => { lines.push(l); if (l.startsWith('NICK')) s.write(':srv 001 me :hi\r\n'); }); });
  });
  await new Promise((r) => irc.listen(0, '127.0.0.1', r));
  const ircPort = irc.address().port;

  const requested = [];
  const socks = net.createServer((c) => {
    c.once('data', () => {
      c.write(Buffer.from([5, 0]));
      c.once('data', (d) => {
        const n = d[4]; requested.push(d.subarray(5, 5 + n).toString() + ':' + d.readUInt16BE(5 + n));
        const up = net.connect(ircPort, '127.0.0.1', () => { c.write(Buffer.from([5, 0, 0, 1, 0, 0, 0, 0, 0, 0])); up.pipe(c); c.pipe(up); });
      });
    });
  });
  await new Promise((r) => socks.listen(0, '127.0.0.1', r));

  const b = startBridge({ origins: ['https://good.example'], allowInsecure: true, tor: `127.0.0.1:${socks.address().port}` });
  await new Promise((r) => b.listen(0, '127.0.0.1', r));
  const bp = b.address().port;

  // direct, self-signed cert, insecure allowed => authorized=false must be reported
  let w = await rawWs(bp, `host=127.0.0.1&port=${ircPort}&tls=1&insecure=1`, 'https://good.example');
  await wait(() => w.msgs.length);
  let hello = JSON.parse(w.msgs[0]);
  assert.equal(hello.stc, 'hello'); assert.equal(hello.tls, true); assert.equal(hello.authorized, false);
  assert.match(hello.protocol, /TLSv1\.[23]/); assert.match(hello.cipher, /AES|CHACHA/);
  w.send('NICK me'); w.send('USER a 0 * :b');
  await wait(() => w.msgs.includes(':srv 001 me :hi'));
  assert.ok(lines.includes('NICK me'));
  w.close();

  // strict TLS against self-signed must fail
  w = await rawWs(bp, `host=127.0.0.1&port=${ircPort}&tls=1`, 'https://good.example');
  await wait(() => w.msgs.length);
  assert.match(w.msgs[0], /"error"/); w.close();

  // via "tor": hostname is passed to the proxy unresolved (.onion works), and reported
  w = await rawWs(bp, `host=abcdefghijklmnop.onion&port=6697&tls=1&insecure=1&route=tor`, 'https://good.example');
  await wait(() => w.msgs.length);
  hello = JSON.parse(w.msgs[0]);
  assert.equal(hello.route, 'tor'); assert.deepEqual(requested, ['abcdefghijklmnop.onion:6697']); assert.equal(hello.tls, true);
  w.close(); b.close(); irc.close(); socks.close();
});

test('bridge: IRC transport through the bridge in tcp mode (plain) and ws mode (XMPP relay)', async () => {
  // plain TCP IRC
  const got = [];
  const tcp = net.createServer((s) => { s.on('data', (d) => d.toString().split('\r\n').filter(Boolean).forEach((l) => { got.push(l); if (l.startsWith('USER')) s.write(':srv 001 zed :welcome\r\n'); })); });
  await new Promise((r) => tcp.listen(0, '127.0.0.1', r));
  // XMPP ws server
  const x = await mockXmpp('chat.test', {});
  const b = startBridge({ origins: [''] }); // global WebSocket (undici) sends no Origin header
  await new Promise((r) => b.listen(0, '127.0.0.1', r));
  const bp = b.address().port;
  const hellos = [];
  const t = new IRCTransport({ url: `ws://127.0.0.1:${bp}/?mode=tcp&host=127.0.0.1&port=${tcp.address().port}&tls=0`, nick: 'zed', subprotocol: 'none' }, { onHello: (h) => hellos.push(h) });
  await t.connect();
  assert.equal(hellos[0].tls, false);
  assert.equal(t.nick, 'zed');
  const xt = new XMPPTransport({ url: `ws://127.0.0.1:${bp}/?mode=ws&host=127.0.0.1&port=${x.port}&tls=0&subproto=xmpp`, jid: 'chat.test' }, { onHello: (h) => hellos.push(h) });
  await xt.connect();
  assert.match(xt.nick, /@chat\.test\/res$/);
  t.close(); xt.close(); b.close(); tcp.close(); x.close();
});
