// Network transports. Each exposes:
//   connect() -> Promise (resolves when logged in / ready)
//   send(to, text), close(), maxChunk, nick (own address)
// handlers: { onMessage(from, text, target), onStatus(text), onClose(reason), onHello(info) }

import { parseXml, child, esc } from './xml.js';

const te = new TextEncoder();
const S = () => globalThis.crypto.subtle;
const b64 = (u8) => { let s = ''; u8.forEach((c) => { s += String.fromCharCode(c); }); return btoa(s); };
const unb64 = (s) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));

function openSocket(url, protocols) {
  return new Promise((resolve, reject) => {
    let ws;
    try { ws = protocols && protocols.length ? new WebSocket(url, protocols) : new WebSocket(url); } catch (e) { reject(e); return; }
    ws.onopen = () => { ws.onerror = null; resolve(ws); };
    ws.onerror = () => reject(new Error('Could not open the WebSocket (server down, wrong address, blocked by mixed-content/CSP, or certificate problem)'));
  });
}

// ---------------------------------------------------------------- IRC
export class IRCTransport {
  constructor(o, h) {
    this.o = o; this.h = h; this.maxChunk = 330; this.nick = o.nick; this.closed = false;
  }
  async connect() {
    const o = this.o;
    const subp = o.subprotocol === 'none' ? [] : [o.subprotocol || 'text.ircv3.net'];
    const ws = await openSocket(o.url, subp);
    this.ws = ws;
    return new Promise((resolve, reject) => {
      let done = false;
      const fail = (m) => { if (!done) { done = true; reject(new Error(m)); } };
      const useSasl = !!(o.user && o.password);
      ws.onclose = (e) => { this.closed = true; fail('Connection closed before login' + (this.bridgeError ? ': bridge says "' + this.bridgeError + '"' : e.reason ? ': ' + e.reason : '')); this.h.onClose && this.h.onClose(e.reason || 'closed'); };
      ws.onerror = () => fail('WebSocket error');
      ws.onmessage = (ev) => {
        String(ev.data).split(/\r?\n/).forEach((line) => {
          if (!line) return;
          if (line[0] === '{' && line.includes('"stc"')) { try { const j = JSON.parse(line); if (j.stc === 'hello') this.h.onHello && this.h.onHello(j); else if (j.stc === 'error') this.bridgeError = j.message; } catch { /* ignore */ } return; }
          this._line(line, { useSasl, ok: () => { if (!done) { done = true; resolve(); } }, fail });
        });
      };
      if (useSasl) this._raw('CAP REQ :sasl');
      if (o.serverPass) this._raw('PASS ' + o.serverPass);
      this._raw('NICK ' + this.nick);
      this._raw(`USER ${o.ident || 'stc'} 0 * :${o.realname || 'Secure Temp Chat'}`);
      this.h.onStatus && this.h.onStatus('Connected to server, logging in...');
    });
  }
  _raw(l) { if (/[\r\n]/.test(l)) l = l.replace(/[\r\n]+/g, ' '); this.ws.send(l); }
  _line(line, ctx) {
    line = line.replace(/^@\S+ /, '');
    let prefix = '';
    if (line[0] === ':') { const i = line.indexOf(' '); prefix = line.slice(1, i); line = line.slice(i + 1); }
    const ti = line.indexOf(' :');
    let trailing = null;
    if (ti >= 0) { trailing = line.slice(ti + 2); line = line.slice(0, ti); }
    const p = line.split(' ');
    const cmd = p[0].toUpperCase();
    const params = p.slice(1);
    if (trailing !== null) params.push(trailing);
    switch (cmd) {
      case 'PING': this._raw('PONG :' + (params[0] || '')); break;
      case 'CAP':
        if (params[1] === 'ACK' && /sasl/.test(params[2] || '')) this._raw('AUTHENTICATE PLAIN');
        else if (params[1] === 'NAK') { this._raw('CAP END'); }
        break;
      case 'AUTHENTICATE':
        if (params[0] === '+') {
          const blob = b64(te.encode(`${this.o.user}\0${this.o.user}\0${this.o.password}`));
          for (let i = 0; i < blob.length; i += 400) this._raw('AUTHENTICATE ' + blob.slice(i, i + 400));
          if (blob.length % 400 === 0) this._raw('AUTHENTICATE +');
        }
        break;
      case '903': this.h.onStatus && this.h.onStatus('Logged in with SASL'); this._raw('CAP END'); break;
      case '902': case '904': case '905': case '906': ctx.fail('SASL login failed (' + cmd + ')'); this._raw('CAP END'); break;
      case '433': this.nick += '_'; this._raw('NICK ' + this.nick); break;
      case '001': this.nick = params[0] || this.nick; this.h.onStatus && this.h.onStatus('Welcome ' + this.nick); ctx.ok(); break;
      case 'PRIVMSG': {
        const from = prefix.split('!')[0];
        this.h.onMessage && this.h.onMessage(from, params[1] || '', params[0]);
        break;
      }
      case 'ERROR': ctx.fail('Server error: ' + (params[0] || '')); break;
      default:
    }
  }
  send(to, text) { this._raw(`PRIVMSG ${to} :${text}`); }
  close() { this.closed = true; try { this._raw('QUIT :bye'); this.ws.close(); } catch { /* ignore */ } }
}

// ---------------------------------------------------------------- XMPP
export async function scramClient(hashName, user, pass, cnonce) {
  const H = hashName;
  const hmac = async (k, d) => new Uint8Array(await S().sign('HMAC', await S().importKey('raw', k, { name: 'HMAC', hash: H }, false, ['sign']), d));
  const hash = async (d) => new Uint8Array(await S().digest(H, d));
  const bare = `n=${user.replace(/=/g, '=3D').replace(/,/g, '=2C')},r=${cnonce}`;
  let authMessage; let serverKeySig;
  return {
    first: () => 'n,,' + bare,
    async final(serverFirst) {
      const f = Object.fromEntries(serverFirst.split(',').map((x) => [x[0], x.slice(2)]));
      if (!f.r || !f.r.startsWith(cnonce)) throw new Error('SCRAM: bad server nonce');
      const iters = parseInt(f.i, 10);
      if (!(iters > 0 && iters <= 1000000)) throw new Error('SCRAM: bad iteration count');
      const base = await S().importKey('raw', te.encode(pass), 'PBKDF2', false, ['deriveBits']);
      const bits = H === 'SHA-1' ? 160 : 256;
      const salted = new Uint8Array(await S().deriveBits({ name: 'PBKDF2', hash: H, salt: unb64(f.s), iterations: iters }, base, bits));
      const clientKey = await hmac(salted, te.encode('Client Key'));
      const stored = await hash(clientKey);
      const noProof = `c=biws,r=${f.r}`;
      authMessage = te.encode(`${bare},${serverFirst},${noProof}`);
      const sig = await hmac(stored, authMessage);
      const proof = clientKey.map((b, i) => b ^ sig[i]);
      serverKeySig = await hmac(await hmac(salted, te.encode('Server Key')), authMessage);
      return `${noProof},p=${b64(proof)}`;
    },
    verify(serverFinal) {
      const v = serverFinal.startsWith('v=') ? unb64(serverFinal.slice(2)) : null;
      return !!v && v.length === serverKeySig.length && v.every((b, i) => b === serverKeySig[i]);
    },
  };
}

export class XMPPTransport {
  constructor(o, h) { this.o = o; this.h = h; this.maxChunk = 3000; this.closed = false; this.nick = o.jid; }
  async connect() {
    const o = this.o;
    const at = o.jid.indexOf('@');
    this.user = at >= 0 ? o.jid.slice(0, at) : null;
    this.domain = at >= 0 ? o.jid.slice(at + 1) : o.jid;
    const ws = await openSocket(o.url, ['xmpp']);
    this.ws = ws;
    return new Promise((resolve, reject) => {
      let done = false;
      const fail = (m) => { if (!done) { done = true; reject(new Error(m)); } };
      this._ok = () => { if (!done) { done = true; resolve(); } };
      this._fail = fail;
      ws.onclose = (e) => { this.closed = true; fail('Connection closed before login' + (this.bridgeError ? ': bridge says "' + this.bridgeError + '"' : '')); this.h.onClose && this.h.onClose(e.reason || 'closed'); };
      ws.onerror = () => fail('WebSocket error');
      ws.onmessage = (ev) => this._frame(String(ev.data)).catch((e) => fail(e.message));
      this._open();
      this.h.onStatus && this.h.onStatus('Connected, negotiating XMPP stream...');
    });
  }
  _open() { this.ws.send(`<open xmlns="urn:ietf:params:xml:ns:xmpp-framing" to="${esc(this.domain)}" version="1.0"/>`); }
  async _frame(data) {
    if (data[0] === '{' && data.includes('"stc"')) { try { const j = JSON.parse(data); if (j.stc === 'hello') this.h.onHello && this.h.onHello(j); else if (j.stc === 'error') this.bridgeError = j.message; } catch { /* ignore */ } return; }
    const el = parseXml(data);
    if (!el) return;
    switch (el.name) {
      case 'open': break;
      case 'close': this.ws.close(); break;
      case 'features': await this._features(el); break;
      case 'challenge': await this._challenge(el); break;
      case 'success': {
        if (this.scram && el.text.trim() && !this.scram.verify(atob(el.text.trim()))) { this._fail('Server failed SCRAM verification'); return; }
        this.authed = true; this._open(); break;
      }
      case 'failure': this._fail('Login failed: ' + (el.children[0] ? el.children[0].name : 'not-authorized')); break;
      case 'iq': this._iq(el); break;
      case 'message': {
        const body = child(el, 'body');
        if (body && el.attrs.type !== 'error') this.h.onMessage && this.h.onMessage(el.attrs.from || '', body.text, el.attrs.to);
        break;
      }
      default:
    }
  }
  async _features(f) {
    if (!this.authed) {
      const mechs = (child(f, 'mechanisms') || { children: [] }).children.map((m) => m.text.trim());
      const pass = this.o.password;
      let mech;
      if (this.user === null || !pass) mech = mechs.includes('ANONYMOUS') ? 'ANONYMOUS' : null;
      else mech = ['SCRAM-SHA-256', 'SCRAM-SHA-1', 'PLAIN'].find((m) => mechs.includes(m)) || null;
      if (!mech) { this._fail('No usable login method. Server offers: ' + (mechs.join(', ') || 'none') + (pass ? '' : ' (enter a password, or use a server that allows ANONYMOUS)')); return; }
      this.h.onStatus && this.h.onStatus('Logging in with SASL ' + mech);
      const ns = 'urn:ietf:params:xml:ns:xmpp-sasl';
      if (mech === 'ANONYMOUS') this.ws.send(`<auth xmlns="${ns}" mechanism="ANONYMOUS"/>`);
      else if (mech === 'PLAIN') this.ws.send(`<auth xmlns="${ns}" mechanism="PLAIN">${b64(te.encode(`\0${this.user}\0${pass}`))}</auth>`);
      else {
        const nonce = b64(globalThis.crypto.getRandomValues(new Uint8Array(18)));
        this.scram = await scramClient(mech === 'SCRAM-SHA-256' ? 'SHA-256' : 'SHA-1', this.user, pass, nonce);
        this.ws.send(`<auth xmlns="${ns}" mechanism="${mech}">${b64(te.encode(this.scram.first()))}</auth>`);
      }
    } else if (child(f, 'bind')) {
      const res = 'stc-' + b64(globalThis.crypto.getRandomValues(new Uint8Array(4))).replace(/[^a-z0-9]/gi, 'x');
      this.ws.send(`<iq type="set" id="bind1"><bind xmlns="urn:ietf:params:xml:ns:xmpp-bind"><resource>${res}</resource></bind></iq>`);
    }
  }
  async _challenge(el) {
    const serverFirst = atob(el.text.trim());
    const resp = await this.scram.final(serverFirst);
    this.ws.send(`<response xmlns="urn:ietf:params:xml:ns:xmpp-sasl">${b64(te.encode(resp))}</response>`);
  }
  _iq(el) {
    if (el.attrs.id === 'bind1') {
      if (el.attrs.type === 'result') {
        const jid = child(child(el, 'bind'), 'jid');
        this.nick = jid ? jid.text.trim() : this.o.jid;
        this.ws.send('<presence/>');
        this.h.onStatus && this.h.onStatus('Online as ' + this.nick);
        this._ok();
      } else this._fail('Resource binding failed');
    } else if (el.attrs.type === 'get' || el.attrs.type === 'set') {
      this.ws.send(`<iq type="${child(el, 'ping') ? 'result' : 'error'}" id="${esc(el.attrs.id || '')}" to="${esc(el.attrs.from || '')}">${child(el, 'ping') ? '' : '<error type="cancel"><service-unavailable xmlns="urn:ietf:params:xml:ns:xmpp-stanzas"/></error>'}</iq>`);
    }
  }
  send(to, text) {
    // hints keep this out of server archives (MAM) and out of carbon copies
    this.ws.send(`<message to="${esc(to)}" type="chat"><body>${esc(text)}</body><no-store xmlns="urn:xmpp:hints"/><no-permanent-store xmlns="urn:xmpp:hints"/><private xmlns="urn:xmpp:carbons:2"/></message>`);
  }
  close() { this.closed = true; try { this.ws.send('<close xmlns="urn:ietf:params:xml:ns:xmpp-framing"/>'); this.ws.close(); } catch { /* ignore */ } }
}

// ---------------------------------------------------------------- Loopback (two tabs)
export class LoopbackTransport {
  constructor(o, h) { this.o = o; this.h = h; this.maxChunk = 100000; this.nick = o.nick; this.closed = false; }
  async connect() {
    this.bc = new BroadcastChannel('stc-loopback-v1');
    this.bc.onmessage = (e) => {
      const m = e.data;
      if (m && m.to === this.nick && m.from !== this.nick) this.h.onMessage && this.h.onMessage(m.from, m.text, m.to);
    };
    this.h.onStatus && this.h.onStatus(`Loopback ready as "${this.nick}". Open a second tab, pick another nickname, and chat.`);
  }
  send(to, text) { this.bc.postMessage({ from: this.nick, to, text }); }
  close() { this.closed = true; try { this.bc.close(); } catch { /* ignore */ } }
}

export function makeTransport(kind, o, h) {
  if (kind === 'xmpp') return new XMPPTransport(o, h);
  if (kind === 'loopback') return new LoopbackTransport(o, h);
  return new IRCTransport(o, h);
}
