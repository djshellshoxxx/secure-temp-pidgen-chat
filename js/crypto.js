// Secure Temp Chat - end-to-end encryption engine (WebCrypto only, zero dependencies).
// Works in browsers and in Node 20+ (globalThis.crypto).
//
// Modes:
//   ratchet : ephemeral handshake + Double Ratchet (Signal-style, NOT Signal-compatible)
//   ecdh    : ephemeral handshake + one-way symmetric chains (per-session PFS)
//   static  : long-term static ECDH keys, no ephemeral (NO forward secrecy)
//   psk     : passphrase -> PBKDF2 -> AES-256-GCM (NO forward secrecy)
//   otp     : one-time pad (XOR) + HMAC-SHA256 tag keyed from fresh pad bytes
//
// Handshake auth (ratchet/ecdh only): 'none' (compare SAS), 'sign' (ECDSA P-256), 'psk' (secret mixed in)

const te = new TextEncoder();
const td = new TextDecoder();
const S = () => globalThis.crypto.subtle;
const EMPTY = new Uint8Array(0);

export const WIRE_PREFIX = 'STC1:';
export const PBKDF2_ITERS = 600000;
export const CURVES = ['P-256', 'P-384', 'X25519'];
const MAX_SKIP = 200;
const MAX_SKIPPED_STORED = 1000;

export const rand = (n) => globalThis.crypto.getRandomValues(new Uint8Array(n));

export function b64u(buf) {
  const b = new Uint8Array(buf);
  let s = '';
  for (let i = 0; i < b.length; i += 0x8000) s += String.fromCharCode.apply(null, b.subarray(i, i + 0x8000));
  return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
export function unb64u(s) {
  s = String(s).replace(/-/g, '+').replace(/_/g, '/').replace(/\s+/g, '');
  while (s.length % 4) s += '=';
  const bin = atob(s);
  const o = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) o[i] = bin.charCodeAt(i);
  return o;
}
export const hex = (b) => Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('');

function cat(...parts) {
  let n = 0;
  for (const p of parts) n += p.length;
  const o = new Uint8Array(n);
  let i = 0;
  for (const p of parts) { o.set(p, i); i += p.length; }
  return o;
}
const u32 = (n) => new Uint8Array([(n >>> 24) & 255, (n >>> 16) & 255, (n >>> 8) & 255, n & 255]);
// length-prefixed concatenation: unambiguous transcript encoding
const lv = (...parts) => cat(...parts.flatMap((p) => [u32(p.length), p]));
const str = (s) => te.encode(s);
function ctEq(a, b) {
  if (a.length !== b.length) return false;
  let d = 0;
  for (let i = 0; i < a.length; i++) d |= a[i] ^ b[i];
  return d === 0;
}

const sha256 = async (d) => new Uint8Array(await S().digest('SHA-256', d));
async function hkdf(ikm, salt, info, len) {
  const k = await S().importKey('raw', ikm, 'HKDF', false, ['deriveBits']);
  return new Uint8Array(await S().deriveBits({ name: 'HKDF', hash: 'SHA-256', salt, info }, k, len * 8));
}
async function hmac(key, data) {
  const k = await S().importKey('raw', key, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  return new Uint8Array(await S().sign('HMAC', k, data));
}
async function aeadSeal(key, iv, pt, ad) {
  const k = await S().importKey('raw', key, 'AES-GCM', false, ['encrypt']);
  return new Uint8Array(await S().encrypt({ name: 'AES-GCM', iv, additionalData: ad, tagLength: 128 }, k, pt));
}
async function aeadOpen(key, iv, ct, ad) {
  const k = await S().importKey('raw', key, 'AES-GCM', false, ['decrypt']);
  return new Uint8Array(await S().decrypt({ name: 'AES-GCM', iv, additionalData: ad, tagLength: 128 }, k, ct));
}

// ---------- Diffie-Hellman ----------
const dhAlg = (c) => (c === 'X25519' ? { name: 'X25519' } : { name: 'ECDH', namedCurve: c });
const dhBits = (c) => ({ 'P-256': 256, 'P-384': 384, X25519: 256 })[c];

export async function genDH(curve) {
  const kp = await S().generateKey(dhAlg(curve), true, ['deriveBits']);
  return { priv: kp.privateKey, pub: new Uint8Array(await S().exportKey('raw', kp.publicKey)) };
}
async function dh(curve, priv, pubRaw) {
  const pub = await S().importKey('raw', pubRaw, dhAlg(curve), false, []);
  return new Uint8Array(await S().deriveBits({ ...dhAlg(curve), public: pub }, priv, dhBits(curve)));
}
export async function curveSupported(curve) {
  try { await genDH(curve); return true; } catch { return false; }
}

// ---------- identities ----------
export async function fingerprint(pub) {
  const h = await sha256(pub);
  return hex(h.slice(0, 20)).toUpperCase().match(/.{4}/g).join(' ');
}
export async function makeIdentity() {
  const kp = await S().generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
  const pub = new Uint8Array(await S().exportKey('raw', kp.publicKey));
  return { priv: kp.privateKey, pub, fp: await fingerprint(pub) };
}
export async function makeStatic(curve) {
  const k = await genDH(curve);
  return { ...k, fp: await fingerprint(k.pub) };
}
const ecSign = async (id, data) => new Uint8Array(await S().sign({ name: 'ECDSA', hash: 'SHA-256' }, id.priv, data));
async function ecVerify(pubRaw, sig, data) {
  const k = await S().importKey('raw', pubRaw, { name: 'ECDSA', namedCurve: 'P-256' }, false, ['verify']);
  return S().verify({ name: 'ECDSA', hash: 'SHA-256' }, k, sig, data);
}

// ---------- one-time pad helpers ----------
export function generatePad(bytes) {
  const pad = new Uint8Array(bytes);
  for (let i = 0; i < bytes; i += 65536) globalThis.crypto.getRandomValues(pad.subarray(i, Math.min(i + 65536, bytes)));
  return pad;
}
export const padToText = (pad) => b64u(pad).match(/.{1,76}/g).join('\n');
export const padFromText = (t) => unb64u(t);

// ---------- framing: [flag][u16 len][text][zero pad to 64] ----------
function frame(text, flag = 0) {
  const t = te.encode(text);
  if (t.length > 65535) throw new Error('message too long');
  const raw = cat(new Uint8Array([flag]), new Uint8Array([t.length >> 8, t.length & 255]), t);
  const padded = new Uint8Array(Math.ceil(raw.length / 64) * 64);
  padded.set(raw);
  return padded;
}
function unframe(buf) {
  const len = (buf[1] << 8) | buf[2];
  if (3 + len > buf.length) throw new Error('bad frame');
  return { flag: buf[0], text: td.decode(buf.subarray(3, 3 + len)) };
}

const wire = (obj) => WIRE_PREFIX + b64u(te.encode(JSON.stringify(obj)));
export function parseWire(s) {
  if (typeof s !== 'string' || !s.startsWith(WIRE_PREFIX)) return null;
  try { return JSON.parse(td.decode(unb64u(s.slice(WIRE_PREFIX.length)))); } catch { return null; }
}

const ONE = new Uint8Array([1]);
const TWO = new Uint8Array([2]);
async function step(st, name) {
  const mk = await hmac(st[name], ONE);
  st[name] = await hmac(st[name], TWO);
  return mk;
}
async function mkSeal(mk, pt, ad) {
  const km = await hkdf(mk, EMPTY, str('STC1 msg'), 44);
  return aeadSeal(km.slice(0, 32), km.slice(32), pt, ad);
}
async function mkOpen(mk, ct, ad) {
  const km = await hkdf(mk, EMPTY, str('STC1 msg'), 44);
  return aeadOpen(km.slice(0, 32), km.slice(32), ct, ad);
}
async function kdfRK(rk, dhOut) {
  const o = await hkdf(dhOut, rk, str('STC1 ratchet'), 64);
  return [o.slice(0, 32), o.slice(32)];
}

const R = (out = [], ev = []) => ({ out, ev });
const bad = (reason) => R([], [{ type: 'error', reason }]);

export class Session {
  /**
   * o: { mode, curve, auth, identity, staticKey, passphrase, pad, side }
   */
  constructor(o) {
    this.o = o;
    this.state = 'idle'; // idle | hs1 | await3 | ready
    this.sas = null;
    this.peerFp = null;
    this.pskCache = new Map();
  }

  get mode() { return this.o.mode; }
  get needsHandshake() { return ['ratchet', 'ecdh', 'static'].includes(this.o.mode); }
  canSend() {
    if (this.o.mode === 'psk' || this.o.mode === 'otp') return true;
    if (this.state !== 'ready') return false;
    if (this.o.mode === 'ratchet') return !!this.dr && !!this.dr.CKs;
    return true;
  }
  padRemaining() {
    if (this.o.mode !== 'otp') return null;
    return Math.max(0, this._txEnd() - this.txOff);
  }

  // ----- initiator -----
  async begin() {
    const o = this.o;
    if (!this.needsHandshake) { this.state = 'ready'; return R([], [{ type: 'ready' }]); }
    this.role = 'A';
    this.nA = rand(16);
    const m = { t: 1, m: o.mode, c: o.curve, a: o.auth };
    if (o.mode === 'static') {
      this.stat = o.staticKey;
      m.s = b64u(this.stat.pub);
      m.n = b64u(this.nA);
    } else {
      this.eph = await genDH(o.curve);
      this.cm = await sha256(lv(str('STC1 commit'), this.eph.pub, this.nA));
      m.cm = b64u(this.cm);
      if (o.auth === 'sign') { this.kA = o.identity.pub; m.k = b64u(this.kA); }
    }
    this.state = 'hs1';
    return R([wire(m)]);
  }

  // ----- input from peer -----
  async handle(w) {
    const m = typeof w === 'string' ? parseWire(w) : w;
    if (!m) return bad('Unreadable secure-chat message');
    try {
      switch (m.t) {
        case 1: return await this._onHs1(m);
        case 2: return await this._onHs2(m);
        case 3: return await this._onHs3(m);
        case 4: return await this._onData(m);
        case 5: return await this._onPsk(m);
        case 6: return await this._onOtp(m);
        default: return bad('Unknown message type');
      }
    } catch (e) {
      return bad('Failed to process message: ' + (e && e.message ? e.message : e));
    }
  }

  _checkParams(m) {
    const o = this.o;
    if (m.m !== o.mode || m.a !== o.auth || (o.mode !== 'static' && m.c !== o.curve) || (o.mode === 'static' && m.c !== o.curve)) {
      return `Peer is using different settings (mode ${m.m}, curve ${m.c}, auth ${m.a}); yours are (${o.mode}, ${o.curve}, ${o.auth}). Both sides must match.`;
    }
    return null;
  }

  _hash(eA, nA, eB, nB, kA, kB) {
    const o = this.o;
    return sha256(lv(str(`STC1 H|${o.mode}|${o.curve}|${o.auth}`), eA, nA, eB, nB, kA || EMPTY, kB || EMPTY));
  }

  async _pskKey() {
    if (!this.o.passphrase) throw new Error('A shared passphrase is required for this mode');
    if (!this._pk) {
      const base = await S().importKey('raw', str(this.o.passphrase), 'PBKDF2', false, ['deriveBits']);
      this._pk = new Uint8Array(await S().deriveBits({ name: 'PBKDF2', hash: 'SHA-256', salt: str('STC1 pskmix'), iterations: PBKDF2_ITERS }, base, 256));
    }
    return this._pk;
  }

  async _derive(secret, nA, nB, H) {
    let ikm = secret;
    if (this.o.auth === 'psk' && this.o.mode !== 'static') ikm = cat(secret, await this._pskKey());
    const root = await hkdf(ikm, cat(nA, nB), cat(str('STC1 root'), H), 32);
    const sb = await hkdf(ikm, EMPTY, cat(str('STC1 sas'), H), 4);
    const n = ((sb[0] << 24) | (sb[1] << 16) | (sb[2] << 8) | sb[3]) >>> 0;
    const s = String(n % 100000000).padStart(8, '0');
    this.sas = s.slice(0, 4) + ' ' + s.slice(4);
    this.H = H;
    return root;
  }

  async _initKeys(root, role) {
    const ab = await hkdf(root, EMPTY, str('STC1 chain A>B'), 32);
    const ba = await hkdf(root, EMPTY, str('STC1 chain B>A'), 32);
    if (this.o.mode === 'ratchet') {
      if (role === 'A') {
        const DHs = await genDH(this.o.curve);
        const [RK, CKs] = await kdfRK(root, await dh(this.o.curve, DHs.priv, this.eB));
        this.dr = { RK, DHs, DHr: this.eB, CKs, CKr: null, Ns: 0, Nr: 0, PN: 0, skipped: new Map() };
      } else {
        this.dr = { RK: root, DHs: this.eph, DHr: null, CKs: null, CKr: null, Ns: 0, Nr: 0, PN: 0, skipped: new Map() };
      }
    } else {
      this.send_ = { ck: role === 'A' ? ab : ba, n: 0 };
      this.recv_ = { ck: role === 'A' ? ba : ab, n: 0, skipped: new Map() };
    }
  }

  async _onHs1(m) {
    const o = this.o;
    const mismatch = this._checkParams(m);
    if (mismatch) return bad(mismatch);
    this.role = 'B';
    if (o.mode === 'static') {
      this.stat = o.staticKey;
      const sA = unb64u(m.s);
      const nA = unb64u(m.n);
      const nB = rand(16);
      const H = await this._hash(sA, nA, this.stat.pub, nB);
      const secret = await dh(o.curve, this.stat.priv, sA);
      const root = await this._derive(secret, nA, nB, H);
      await this._initKeys(root, 'B');
      this.peerFp = await fingerprint(sA);
      this.state = 'ready';
      return R([wire({ t: 2, s: b64u(this.stat.pub), n: b64u(nB) })], [
        { type: 'peerKey', fp: this.peerFp, kind: 'static key' },
        { type: 'sas', code: this.sas },
        { type: 'ready' },
      ]);
    }
    this.cm = unb64u(m.cm);
    this.eph = await genDH(o.curve);
    this.nB = rand(16);
    this.kA = m.k ? unb64u(m.k) : null;
    if (o.auth === 'sign' && !this.kA) return bad('Peer did not send an identity key');
    const reply = { t: 2, e: b64u(this.eph.pub), n: b64u(this.nB) };
    if (o.auth === 'sign') {
      this.kB = o.identity.pub;
      reply.k = b64u(this.kB);
      const t2 = await sha256(lv(str('STC1 B'), this.cm, this.eph.pub, this.nB, this.kA, this.kB, str(`${o.mode}|${o.curve}|${o.auth}`)));
      reply.g = b64u(await ecSign(o.identity, t2));
    }
    this.state = 'await3';
    return R([wire(reply)]);
  }

  async _onHs2(m) {
    const o = this.o;
    if (this.state !== 'hs1') return bad('Unexpected handshake reply');
    if (o.mode === 'static') {
      const sB = unb64u(m.s);
      const nB = unb64u(m.n);
      const H = await this._hash(this.stat.pub, this.nA, sB, nB);
      const secret = await dh(o.curve, this.stat.priv, sB);
      const root = await this._derive(secret, this.nA, nB, H);
      await this._initKeys(root, 'A');
      this.peerFp = await fingerprint(sB);
      this.state = 'ready';
      return R([], [
        { type: 'peerKey', fp: this.peerFp, kind: 'static key' },
        { type: 'sas', code: this.sas },
        { type: 'ready' },
      ]);
    }
    const eB = unb64u(m.e);
    const nB = unb64u(m.n);
    let kB = null;
    const ev = [];
    const out = {};
    if (o.auth === 'sign') {
      if (!m.k || !m.g) return bad('Peer did not authenticate (missing signature)');
      kB = unb64u(m.k);
      const t2 = await sha256(lv(str('STC1 B'), this.cm, eB, nB, this.kA, kB, str(`${o.mode}|${o.curve}|${o.auth}`)));
      if (!(await ecVerify(kB, unb64u(m.g), t2))) return bad('Peer signature INVALID - possible man-in-the-middle. Session aborted.');
      this.peerFp = await fingerprint(kB);
      ev.push({ type: 'peerKey', fp: this.peerFp, kind: 'identity key (signature verified)' });
    }
    this.eB = eB;
    const H = await this._hash(this.eph.pub, this.nA, eB, nB, this.kA, kB);
    const secret = await dh(o.curve, this.eph.priv, eB);
    const root = await this._derive(secret, this.nA, nB, H);
    const hs3 = { t: 3, e: b64u(this.eph.pub), n: b64u(this.nA) };
    if (o.auth === 'sign') hs3.g = b64u(await ecSign(o.identity, cat(str('STC1 A'), H)));
    void out;
    await this._initKeys(root, 'A');
    this.state = 'ready';
    const outMsgs = [wire(hs3)];
    ev.push({ type: 'sas', code: this.sas });
    if (o.mode === 'ratchet') {
      outMsgs.push(await this._encrypt('', 1)); // kickoff so the responder can send too
    }
    ev.push({ type: 'ready' });
    return R(outMsgs, ev);
  }

  async _onHs3(m) {
    const o = this.o;
    if (this.state !== 'await3') return bad('Unexpected handshake message');
    const eA = unb64u(m.e);
    const nA = unb64u(m.n);
    const cm = await sha256(lv(str('STC1 commit'), eA, nA));
    if (!ctEq(cm, this.cm)) return bad('Handshake commitment mismatch - session aborted (possible attack).');
    this.eB = null;
    const H = await this._hash(eA, nA, this.eph.pub, this.nB, this.kA, this.kB);
    const ev = [];
    if (o.auth === 'sign') {
      if (!m.g || !(await ecVerify(this.kA, unb64u(m.g), cat(str('STC1 A'), H)))) {
        return bad('Peer signature INVALID - possible man-in-the-middle. Session aborted.');
      }
      this.peerFp = await fingerprint(this.kA);
      ev.push({ type: 'peerKey', fp: this.peerFp, kind: 'identity key (signature verified)' });
    }
    const secret = await dh(o.curve, this.eph.priv, eA);
    const root = await this._derive(secret, nA, this.nB, H);
    await this._initKeys(root, 'B');
    this.state = 'ready';
    ev.push({ type: 'sas', code: this.sas });
    if (o.mode !== 'ratchet') ev.push({ type: 'ready' }); // ratchet: ready once the kickoff message arrives
    return R([], ev);
  }

  // ----- AEAD data (chains / ratchet) -----
  async _encrypt(text, flag = 0) {
    const pt = frame(text, flag);
    if (this.o.mode === 'ratchet') {
      const d = this.dr;
      if (!d.CKs) throw new Error('Waiting for peer to finish securing the session');
      const mk = await step(d, 'CKs');
      const n = d.Ns++;
      const hdr = { d: b64u(d.DHs.pub), p: d.PN, n };
      const ct = await mkSeal(mk, pt, cat(this.H, lv(str('c'), unb64u(hdr.d), u32(hdr.p), u32(hdr.n))));
      return wire({ t: 4, d: hdr.d, p: hdr.p, n: hdr.n, c: b64u(ct) });
    }
    const ch = this.send_;
    const mk = await step(ch, 'ck');
    const n = ch.n++;
    const ct = await mkSeal(mk, pt, cat(this.H, lv(str('s'), u32(n))));
    return wire({ t: 4, n, c: b64u(ct) });
  }

  async send(text) {
    if (!this.canSend()) throw new Error('Secure session is not ready yet');
    switch (this.o.mode) {
      case 'psk': return this._pskEncrypt(text);
      case 'otp': return this._otpEncrypt(text);
      default: return this._encrypt(text);
    }
  }

  async _skip(st, until) {
    if (until - st.Nr > MAX_SKIP) throw new Error('too many skipped messages');
    while (st.Nr < until) {
      const mk = await step(st, 'CKr');
      st.skipped.set(b64u(st.DHr) + ':' + st.Nr, mk);
      st.Nr++;
      if (st.skipped.size > MAX_SKIPPED_STORED) st.skipped.delete(st.skipped.keys().next().value);
    }
  }

  async _onData(m) {
    if (this.state !== 'ready') return bad('Data arrived before the secure session was ready');
    const ct = unb64u(m.c);
    let pt;
    try {
      if (this.o.mode === 'ratchet') pt = await this._drDecrypt(m, ct);
      else pt = await this._chainDecrypt(m, ct);
    } catch (e) {
      return bad('Could not decrypt a message (wrong secret, tampering, or replay)');
    }
    const f = unframe(pt);
    const ev = [];
    if (f.flag === 1) {
      ev.push({ type: 'ready' }); // ratchet kickoff received
      return R([], ev);
    }
    ev.push({ type: 'message', text: f.text });
    return R([], ev);
  }

  async _drDecrypt(m, ct) {
    const s = this.dr;
    const st = { ...s, skipped: new Map(s.skipped) };
    const dhr = unb64u(m.d);
    const n = m.n >>> 0;
    const pn = m.p >>> 0;
    const ad = cat(this.H, lv(str('c'), dhr, u32(pn), u32(n)));
    const key = b64u(dhr) + ':' + n;
    if (st.skipped.has(key)) {
      const mk = st.skipped.get(key);
      const pt = await mkOpen(mk, ct, ad);
      st.skipped.delete(key);
      this.dr = st;
      return pt;
    }
    if (!st.DHr || !ctEq(st.DHr, dhr)) {
      if (st.CKr) await this._skip(st, pn);
      st.PN = st.Ns; st.Ns = 0; st.Nr = 0; st.DHr = dhr;
      [st.RK, st.CKr] = await kdfRK(st.RK, await dh(this.o.curve, st.DHs.priv, dhr));
      st.DHs = await genDH(this.o.curve);
      [st.RK, st.CKs] = await kdfRK(st.RK, await dh(this.o.curve, st.DHs.priv, dhr));
    }
    if (n < st.Nr) throw new Error('replay');
    await this._skip(st, n);
    const mk = await step(st, 'CKr');
    st.Nr++;
    const pt = await mkOpen(mk, ct, ad);
    this.dr = st;
    return pt;
  }

  async _chainDecrypt(m, ct) {
    const r = this.recv_;
    const st = { ck: r.ck, n: r.n, skipped: new Map(r.skipped) };
    const n = m.n >>> 0;
    const ad = cat(this.H, lv(str('s'), u32(n)));
    if (n < st.n) {
      const mk = st.skipped.get(n);
      if (!mk) throw new Error('replay');
      const pt = await mkOpen(mk, ct, ad);
      st.skipped.delete(n);
      this.recv_ = st;
      return pt;
    }
    if (n - st.n > MAX_SKIP) throw new Error('too many skipped');
    while (st.n < n) { st.skipped.set(st.n, await step(st, 'ck')); st.n++; }
    const mk = await step(st, 'ck');
    st.n++;
    const pt = await mkOpen(mk, ct, ad);
    this.recv_ = st;
    return pt;
  }

  // ----- passphrase mode -----
  async _pskKeyFor(salt) {
    const id = b64u(salt);
    if (!this.pskCache.has(id)) {
      if (!this.o.passphrase) throw new Error('A shared passphrase is required');
      const base = await S().importKey('raw', str(this.o.passphrase), 'PBKDF2', false, ['deriveBits']);
      this.pskCache.set(id, new Uint8Array(await S().deriveBits({ name: 'PBKDF2', hash: 'SHA-256', salt, iterations: PBKDF2_ITERS }, base, 256)));
    }
    return this.pskCache.get(id);
  }
  async _pskEncrypt(text) {
    if (!this.pskSalt) this.pskSalt = rand(16);
    const key = await this._pskKeyFor(this.pskSalt);
    const iv = rand(12);
    const ct = await aeadSeal(key, iv, frame(text), str('STC1 psk'));
    return wire({ t: 5, s: b64u(this.pskSalt), i: b64u(iv), c: b64u(ct) });
  }
  async _onPsk(m) {
    if (this.o.mode !== 'psk') return bad('Peer is using passphrase mode but you are not');
    try {
      const key = await this._pskKeyFor(unb64u(m.s));
      const pt = await aeadOpen(key, unb64u(m.i), unb64u(m.c), str('STC1 psk'));
      return R([], [{ type: 'message', text: unframe(pt).text }]);
    } catch {
      return bad('Could not decrypt (wrong passphrase or tampering)');
    }
  }

  // ----- one-time pad mode -----
  _half() { return Math.floor(this.o.pad.length / 2); }
  _txStart() { return this.o.side === 'A' ? 0 : this._half(); }
  _txEnd() { return this._txStart() + this._half(); }
  _rxStart() { return this.o.side === 'A' ? this._half() : 0; }
  get txOff() { if (this._tx === undefined) this._tx = this._txStart(); return this._tx; }
  async _otpEncrypt(text) {
    const pad = this.o.pad;
    const pt = frame(text);
    const off = this.txOff;
    if (off + 32 + pt.length > this._txEnd()) throw new Error('One-time pad exhausted for sending - generate and share a new pad');
    const macKey = pad.slice(off, off + 32);
    const ks = pad.subarray(off + 32, off + 32 + pt.length);
    const ct = new Uint8Array(pt.length);
    for (let i = 0; i < pt.length; i++) ct[i] = pt[i] ^ ks[i];
    const tag = (await hmac(macKey, cat(u32(off), ct))).slice(0, 16);
    pad.fill(0, off, off + 32 + pt.length); // destroy used pad bytes
    this._tx = off + 32 + pt.length;
    return wire({ t: 6, o: off, c: b64u(ct), m: b64u(tag) });
  }
  async _onOtp(m) {
    if (this.o.mode !== 'otp') return bad('Peer is using a one-time pad but you are not');
    const pad = this.o.pad;
    const side = this.o.side;
    const rxStart = this._rxStart();
    const rxEnd = rxStart + this._half();
    if (this._rx === undefined) this._rx = rxStart;
    const off = m.o >>> 0;
    const ct = unb64u(m.c);
    if (off < this._rx || off < rxStart || off + 32 + ct.length > rxEnd) return bad('Pad offset invalid or already used (replay)');
    const macKey = pad.slice(off, off + 32);
    const tag = (await hmac(macKey, cat(u32(off), ct))).slice(0, 16);
    if (!ctEq(tag, unb64u(m.m))) return bad('One-time-pad authentication FAILED (wrong pad, side or tampering)');
    const ks = pad.subarray(off + 32, off + 32 + ct.length);
    const pt = new Uint8Array(ct.length);
    for (let i = 0; i < ct.length; i++) pt[i] = ct[i] ^ ks[i];
    pad.fill(0, off, off + 32 + ct.length);
    this._rx = off + 32 + ct.length;
    void side;
    return R([], [{ type: 'message', text: unframe(pt).text }]);
  }

  wipe() {
    this.dr = this.send_ = this.recv_ = this.eph = this.stat = this._pk = null;
    this.pskCache.clear();
    if (this.o.pad) this.o.pad.fill(0);
    this.state = 'idle';
  }
}
