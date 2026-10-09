'use strict';
const http = require('http');
const net = require('net');
const crypto = require('crypto');
const { FrameReader, encodeFrame, acceptKey } = require('../gateway/stc-bridge.cjs');

// Generic WebSocket server; onConn(send, onText, close) per client.
function wsServer(onConn) {
  const srv = http.createServer();
  srv.on('upgrade', (req, sock) => {
    const want = (req.headers['sec-websocket-protocol'] || '').split(',')[0].trim();
    sock.write(`HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: ${acceptKey(req.headers['sec-websocket-key'])}\r\n${want ? 'Sec-WebSocket-Protocol: ' + want + '\r\n' : ''}\r\n`);
    const handlers = { text: () => {}, close: () => {} };
    const send = (s) => { if (!sock.destroyed) sock.write(encodeFrame(1, Buffer.from(s), false)); };
    const r = new FrameReader((op, data) => { if (op === 1) handlers.text(data.toString()); else if (op === 8) sock.end(); });
    sock.on('data', (d) => r.push(d));
    sock.on('close', () => handlers.close());
    sock.on('error', () => {});
    onConn({ send, on: (t, f) => { handlers[t] = f; }, protocol: want });
  });
  return new Promise((res) => srv.listen(0, '127.0.0.1', () => res({ srv, port: srv.address().port, close: () => srv.close() })));
}

// Mock IRC: registers nicks, routes PRIVMSG, optional SASL PLAIN check.
function mockIrc(opts = {}) {
  const clients = new Map();
  return wsServer((c) => {
    let nick = ''; let sasl = false; let capEnded = false; let userSeen = false;
    const register = () => { clients.set(nick, c); c.send(`:srv 001 ${nick} :Welcome ${nick}`); c.send('PING :hi'); };
    c.on('text', (line) => {
      const [cmd, ...rest] = line.split(' ');
      const arg = rest.join(' ');
      if (cmd === 'CAP' && rest[0] === 'REQ') { sasl = true; c.send(':srv CAP * ACK :sasl'); }
      else if (cmd === 'CAP' && rest[0] === 'END') { capEnded = true; if (userSeen) register(); }
      else if (cmd === 'AUTHENTICATE') {
        if (arg === 'PLAIN') c.send('AUTHENTICATE +');
        else {
          const [, user, pass] = Buffer.from(arg, 'base64').toString().split('\0');
          if (pass === opts.password) c.send(`:srv 903 ${nick || '*'} :SASL ok`); else c.send(':srv 904 * :SASL fail');
        }
      } else if (cmd === 'NICK') { nick = arg; }
      else if (cmd === 'USER') { userSeen = true; if (!sasl || capEnded) register(); }
      else if (cmd === 'PRIVMSG') {
        const i = arg.indexOf(' :');
        const target = arg.slice(0, i); const text = arg.slice(i + 2);
        const t = clients.get(target);
        if (t) t.send(`:${nick}!u@h PRIVMSG ${target} :${text}`);
        (opts.seen || []).push(text);
      }
    });
    c.on('close', () => clients.delete(nick));
    void sasl;
  });
}

// Mock XMPP (RFC 7395 framing), supports PLAIN with fixed password and ANONYMOUS.
function mockXmpp(domain, opts = {}) {
  const byJid = new Map();
  return wsServer((c) => {
    let authed = false; let jid = null; let user = null;
    const features = () => (authed
      ? '<stream:features xmlns:stream="http://etherx.jabber.org/streams"><bind xmlns="urn:ietf:params:xml:ns:xmpp-bind"/></stream:features>'
      : `<stream:features xmlns:stream="http://etherx.jabber.org/streams"><mechanisms xmlns="urn:ietf:params:xml:ns:xmpp-sasl">${(opts.mechs || ['PLAIN', 'ANONYMOUS']).map((m) => `<mechanism>${m}</mechanism>`).join('')}</mechanisms></stream:features>`);
    c.on('text', (x) => {
      if (x.startsWith('<open')) { c.send(`<open xmlns="urn:ietf:params:xml:ns:xmpp-framing" from="${domain}" id="s1" version="1.0"/>`); c.send(features()); }
      else if (x.startsWith('<auth')) {
        const mech = /mechanism="([^"]+)"/.exec(x)[1];
        if (mech === 'ANONYMOUS') { authed = true; user = 'anon' + crypto.randomBytes(3).toString('hex'); c.send('<success xmlns="urn:ietf:params:xml:ns:xmpp-sasl"/>'); }
        else if (mech === 'PLAIN') {
          const b = /<auth[^>]*>([^<]*)</.exec(x)[1];
          const [, u, p] = Buffer.from(b, 'base64').toString().split('\0');
          if (p === opts.password) { authed = true; user = u; c.send('<success xmlns="urn:ietf:params:xml:ns:xmpp-sasl"/>'); } else c.send('<failure xmlns="urn:ietf:params:xml:ns:xmpp-sasl"><not-authorized/></failure>');
        }
      } else if (x.startsWith('<iq') && x.includes('bind')) {
        jid = `${user}@${domain}/res`; byJid.set(`${user}@${domain}`, c);
        c.send(`<iq type="result" id="bind1"><bind xmlns="urn:ietf:params:xml:ns:xmpp-bind"><jid>${jid}</jid></bind></iq>`);
      } else if (x.startsWith('<message')) {
        const to = /to="([^"]+)"/.exec(x)[1];
        const body = /<body>([^<]*)<\/body>/.exec(x)[1];
        (opts.seen || []).push(body);
        if (!x.includes('urn:xmpp:hints')) throw new Error('hints missing');
        const t = byJid.get(to.replace(/\/.*/, ''));
        if (t) t.send(`<message from="${jid}" to="${to}" type="chat"><body>${body}</body></message>`);
      }
    });
    c.on('close', () => { if (user) byJid.delete(`${user}@${domain}`); });
  });
}

module.exports = { wsServer, mockIrc, mockXmpp, net, FrameReader, encodeFrame };
