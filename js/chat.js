// ChatCore: glues a transport to per-peer E2EE sessions. No DOM here (testable in Node).
import { Session, WIRE_PREFIX, b64u, rand } from './crypto.js';

const FRAG = 'STCF:';
const MAX_FRAGS = 64;

export class ChatCore {
  /**
   * opts: { transport, makeSession: () => Session, e2e: 'none'|..., onEvent(ev) }
   * ev: {type:'status'|'message'|'plain'|'ready'|'sas'|'peerKey'|'error'|'info', peer, ...}
   */
  constructor(opts) {
    this.t = opts.transport; this.makeSession = opts.makeSession; this.e2e = opts.e2e; this.emit = opts.onEvent;
    this.sessions = new Map();
    this.frags = new Map();
    this.t.h.onMessage = (from, text, target) => this._incoming(from, text, target).catch((e) => this.emit({ type: 'error', peer: from, reason: e.message }));
  }

  _bare(p) { return p.replace(/\/.*$/, ''); }
  _key(p) { return this.t.constructor.name === 'XMPPTransport' ? this._bare(p).toLowerCase() : p.toLowerCase(); }

  _session(peer, create = true) {
    const k = this._key(peer);
    let s = this.sessions.get(k);
    if (!s && create) { s = { session: this.makeSession(), peer }; this.sessions.set(k, s); }
    return s;
  }

  async _sendWires(peer, wires) {
    for (const w of wires) {
      if (w.length <= this.t.maxChunk) { this.t.send(peer, w); continue; }
      const id = b64u(rand(4));
      const n = Math.ceil(w.length / this.t.maxChunk);
      if (n > MAX_FRAGS) throw new Error('Message too long');
      for (let i = 0; i < n; i++) {
        this.t.send(peer, `${FRAG}${id}:${i}:${n}:${w.slice(i * this.t.maxChunk, (i + 1) * this.t.maxChunk)}`);
        if (n > 4) await new Promise((r) => setTimeout(r, 120)); // be polite to server flood limits
      }
    }
  }

  _apply(peer, r, s) {
    for (const ev of r.ev) this.emit({ ...ev, peer, mode: s.session.mode });
  }

  /** Start a secure session with a peer (initiator). */
  async start(peer) {
    if (this.e2e === 'none') { this.emit({ type: 'ready', peer }); return; }
    const old = this._session(peer, false);
    if (old) old.session.wipe();
    this.sessions.delete(this._key(peer));
    const s = this._session(peer);
    const r = await s.session.begin();
    await this._sendWires(peer, r.out);
    this._apply(peer, r, s);
    if (s.session.needsHandshake) this.emit({ type: 'info', peer, text: 'Secure handshake sent to ' + peer + '...' });
  }

  async sendText(peer, text) {
    if (this.e2e === 'none') { this.t.send(peer, text); return; }
    const s = this._session(peer, false);
    if (!s) throw new Error('No secure session with ' + peer + ' yet - press "Start secure session"');
    const w = await s.session.send(text);
    await this._sendWires(peer, [w]);
  }

  async _incoming(from, text, target) {
    // channel traffic is only meaningful for passphrase mode
    if (text.startsWith(FRAG)) {
      const m = /^STCF:([^:]+):(\d+):(\d+):(.*)$/s.exec(text);
      if (!m) return;
      const [, id, i, n, part] = m;
      const nn = +n; const ii = +i;
      if (nn > MAX_FRAGS || ii >= nn) return;
      const key = from + '|' + id;
      let f = this.frags.get(key);
      if (!f) { f = { parts: new Array(nn).fill(null), got: 0, t: Date.now() }; this.frags.set(key, f); }
      if (f.parts[ii] === null) { f.parts[ii] = part; f.got++; }
      if (f.got === nn) { this.frags.delete(key); await this._incoming(from, f.parts.join(''), target); }
      for (const [k, v] of this.frags) if (Date.now() - v.t > 120000) this.frags.delete(k);
      return;
    }
    if (!text.startsWith(WIRE_PREFIX)) {
      this.emit({ type: this.e2e === 'none' ? 'message' : 'plain', peer: from, text });
      return;
    }
    if (this.e2e === 'none') { this.emit({ type: 'error', peer: from, reason: 'Received an encrypted message but end-to-end encryption is switched off here.' }); return; }
    const s = this._session(from);
    const r = await s.session.handle(text);
    if (r.out.length) await this._sendWires(from, r.out);
    this._apply(from, r, s);
  }

  session(peer) { const s = this._session(peer, false); return s ? s.session : null; }
  wipe() { for (const s of this.sessions.values()) s.session.wipe(); this.sessions.clear(); this.frags.clear(); }
  close() { this.wipe(); this.t.close(); }
}
