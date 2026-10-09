import { Session, makeIdentity, makeStatic, generatePad, padToText, padFromText, curveSupported } from './crypto.js';
import { evaluate, urlInfo } from './scoring.js';
import { makeTransport } from './transports.js';
import { ChatCore } from './chat.js';

const $ = (id) => document.getElementById(id);
const el = (tag, cls, text) => { const e = document.createElement(tag); if (cls) e.className = cls; if (text != null) e.textContent = text; return e; };
const val = (id) => $(id).value.trim();
const radio = (name) => document.querySelector(`input[name="${name}"]:checked`).value;

const st = { core: null, bridgeInfo: null, identity: null, pad: null, verified: false, connected: false, ready: false, peerFp: null, timers: new Set() };

const PROTO_NOTES = {
  loopback: 'Try everything without a server: open this page in a second tab, pick a different nickname, and chat between the two tabs. Nothing leaves your browser.',
  irc: 'Browsers cannot open raw IRC connections, only WebSockets. So either (a) use an IRC server that offers a WebSocket address (wss://...) - UnrealIRCd, InspIRCd, Ergo and others can - or (b) use your local bridge in step 3, which lets this page reach ANY IRC server on its normal TLS port (6697), over Tor or I2P too.',
  xmpp: 'XMPP servers that enable the WebSocket module (RFC 7395) can be used directly. Type your JID (or just the server name for an anonymous login) and press "Find it" to try auto-discovery, or paste the wss:// address your provider lists. Or use the bridge for Tor/I2P.',
  silc: 'Not natively possible: no web browser can speak SILC. The honest route is a gateway you run yourself that logs in to SILC and presents an IRC interface (for example BitlBee built with libpurple). Point the bridge at it (default 127.0.0.1:6667) and this page talks IRC to your gateway. SILC\'s own encryption on the far side is chosen by the gateway and cannot be verified here. Untested by the author - treat as experimental.',
  groupwise: 'Not natively possible: no web browser can speak GroupWise. The honest route is a gateway you run yourself that logs in to GroupWise and presents an IRC interface (for example BitlBee built with libpurple). Point the bridge at it (default 127.0.0.1:6667). GroupWise\'s own encryption on the far side cannot be verified here. Untested by the author - treat as experimental.',
};
const E2E_NOTES = {
  ratchet: 'Every message gets its own AES-256-GCM key. Keys come from throw-away Diffie-Hellman exchanges that are re-done as you chat, so stealing a key later reveals neither past nor (after a moment) future messages. Both of you need to open this page.',
  ecdh: 'One throw-away Diffie-Hellman exchange per session, then a one-way chain of AES-256-GCM message keys that are deleted after use. Forward secrecy per session.',
  static: 'Uses fixed keys for the whole session (generated when the page loads, never saved). Authentication is built in via key fingerprints, but this is the case where authentication costs you perfect forward secrecy.',
  psk: 'Both people type the same passphrase; the key is PBKDF2-SHA-256 (600,000 rounds) of it, with AES-256-GCM. Works with channels and groups. Only as strong as the passphrase, and no forward secrecy.',
  otp: 'XOR with a random pad you both hold, plus an HMAC-SHA-256 tag. Perfect secrecy if the pad is random, used once, and kept secret. Pad bytes are wiped as they are used.',
  none: 'Only the connection to the server is encrypted. The server operator can read your messages.',
};
const AUTH_NOTES = {
  none: 'Encrypted but unauthenticated: an attacker in the middle could sit between you. Compare the 8-digit code with your peer (by voice) and tick "Mark as verified". Keeps perfect forward secrecy and deniability.',
  sign: 'Each side signs the handshake with a throw-away ECDSA P-256 identity key and shows its fingerprint. Verify fingerprints once, out of band. PFS is KEPT (the signing key never encrypts messages) but you lose deniability: signatures prove you took part.',
  psk: 'A shared secret is mixed into the key exchange. PFS is KEPT (the exchange is still ephemeral), and a man-in-the-middle without the secret is locked out.',
};
const ANON_NOTES = {
  none: 'Your IP address is visible to the chat server.',
  tor: 'The bridge connects to the chat server through your local Tor SOCKS port (default 127.0.0.1:9050). Onion-service chat servers (.onion) work and keep traffic inside Tor.',
  i2p: 'The bridge connects through your local I2P SOCKS port (default 127.0.0.1:4447). Best with servers inside I2P (.i2p).',
  torbrowser: 'If you opened this page in Tor Browser all traffic from the page already goes through Tor. The page cannot verify this, so it is credited slightly less.',
};

function cfg() {
  const proto = $('proto').value;
  const route = proto === 'loopback' ? 'direct' : proto === 'silc' || proto === 'groupwise' ? 'bridge' : radio('route');
  const e2e = $('e2e').value;
  const auth = e2e === 'ratchet' || e2e === 'ecdh' ? $('auth').value : 'none';
  const passLen = $('passphrase').value.length;
  return {
    proto, route, url: val('url'), bridgeUrl: val('bridgeurl'), bridgeInfo: st.bridgeInfo,
    anon: proto === 'loopback' ? 'none' : $('anon').value,
    e2e, curve: $('curve').value, auth, verified: st.verified, passLen,
    loggedIn: !!val('pass'), disappearing: +$('vanish').value > 0,
  };
}

// ------------------------------------------------------------------ render
function setScore(id, r) {
  const box = $(id);
  box.className = 'score ' + (r.score >= 75 ? 'lv-good' : r.score >= 50 ? 'lv-mid' : 'lv-bad');
  const big = box.querySelector('.big');
  big.textContent = r.score + ' ';
  big.append(el('small', '', '/100 ' + r.grade));
  box.querySelector('.bar i').style.width = r.score + '%';
}
function table(parts) {
  const t = el('table');
  parts.forEach((p) => {
    const tr = el('tr');
    tr.append(el('td', '', p.label), el('td', 'pts', `${p.pts}/${p.max}`), el('td', '', p.note));
    t.append(tr);
  });
  return t;
}
function renderReport() {
  const c = cfg();
  const r = evaluate(c);
  setScore('sc-enc', r.encryption);
  setScore('sc-priv', r.privacy);
  const pfs = $('pfs');
  pfs.className = 'pfs ' + r.pfs.level;
  pfs.replaceChildren(el('b', '', r.pfs.title), el('span', '', r.pfs.text));
  $('deni').textContent = r.deniability.text === 'n/a' ? '' : r.deniability.text;
  const L = $('layers');
  L.replaceChildren();
  r.layers.forEach((l) => {
    const d = el('div', 'layer ' + l.kind + (/^NO |PLAIN/.test(l.name) ? ' bad' : ''));
    d.append(el('span', 'tag', l.kind === 'anon' ? 'Outer layer' : l.kind === 'transport' ? 'Transport layer' : 'End-to-end layer'), el('h4', '', l.name), el('p', 'ciph', l.ciphers));
    if (l.detail) { const x = el('details'); x.append(el('summary', '', 'What does this mean?'), el('p', '', l.detail)); d.append(x); }
    L.append(d);
  });
  L.append(el('div', 'inner', 'Your message'));
  $('narr').textContent = 'Reading inside-out: ' + r.narrative + '.';
  const W = $('warns');
  W.replaceChildren();
  r.warnings.forEach((w) => W.append(el('li', /OFF|NO forward|NOT encrypted|NOT verified|INVALID/.test(w) ? 'err' : '', w)));
  if (!r.warnings.length) W.append(el('li', 'ok', 'No warnings for these settings.'));
  const bd = $('breakdown');
  bd.replaceChildren(el('h3', '', 'Encryption score'), table(r.encryption.parts), el('h3', '', 'Privacy score'), table(r.privacy.parts));
}

function renderForm() {
  const proto = $('proto').value;
  const e2e = $('e2e').value;
  const direct = radio('route') === 'direct';
  const bridge = proto === 'silc' || proto === 'groupwise' || (!direct && proto !== 'loopback');
  $('proto-note').textContent = PROTO_NOTES[proto];
  $('f-server').hidden = proto === 'loopback' || bridge;
  $('f-bridge-target').hidden = !bridge;
  $('bpath-wrap').hidden = !(bridge && proto === 'xmpp');
  $('discover').hidden = !(proto === 'xmpp' && !bridge);
  $('card-route').hidden = proto === 'loopback';
  document.querySelectorAll('input[name="route"]').forEach((r) => { r.disabled = proto === 'silc' || proto === 'groupwise'; });
  if (proto === 'silc' || proto === 'groupwise') document.querySelector('input[name="route"][value="bridge"]').checked = true;
  $('f-bridgeurl').hidden = !bridge;
  $('f-anon').hidden = proto === 'loopback';
  [...$('anon').options].forEach((o) => { o.disabled = !bridge && (o.value === 'tor' || o.value === 'i2p'); });
  if (!bridge && ['tor', 'i2p'].includes($('anon').value)) $('anon').value = 'none';
  $('anon-note').textContent = ANON_NOTES[$('anon').value] + (!bridge && $('anon').value === 'none' ? ' To use Tor or I2P choose "Through my local bridge" above.' : '');
  $('nick-label').textContent = proto === 'xmpp' ? 'Your JID (user@server, or just the server name for anonymous login)' : proto === 'loopback' ? 'Nickname (use a different one in each tab)' : 'Nickname';
  $('peer-hint').textContent = proto === 'xmpp' ? '(their JID, e.g. friend@server.tld)' : '(their nickname)';
  $('e2e-note').textContent = E2E_NOTES[e2e];
  const hs = e2e === 'ratchet' || e2e === 'ecdh';
  $('f-curve').hidden = !(hs || e2e === 'static');
  $('f-auth').hidden = !hs;
  $('auth-note').textContent = AUTH_NOTES[$('auth').value];
  $('f-pass').hidden = !(e2e === 'psk' || (hs && $('auth').value === 'psk'));
  $('f-otp').hidden = e2e !== 'otp';
  const m = $('passmeter');
  const n = $('passphrase').value.length;
  m.style.width = Math.min(100, (n / 20) * 100) + '%';
  m.style.background = n < 12 ? 'var(--bad)' : n < 20 ? 'var(--warn)' : 'var(--good)';
  const u = urlInfo(val('url'));
  const flag = $('tlsflag');
  if (!val('url')) { flag.textContent = ''; flag.className = 'tlsflag'; }
  else if (u.scheme === 'wss') { flag.textContent = 'Encrypted with TLS (wss://)'; flag.className = 'tlsflag ok'; }
  else { flag.textContent = 'NOT encrypted (' + (u.scheme || 'unknown address') + ') - choose a wss:// server'; flag.className = 'tlsflag bad'; }
  $('start').textContent = e2e === 'psk' || e2e === 'otp' ? 'Open secure channel' : 'Start secure session';
  renderReport();
}

// ------------------------------------------------------------------ chat log
let logCount = 0;
function addLog(kind, text, from) {
  const li = el('li', kind);
  li.append(document.createTextNode(text));
  const t = new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
  if (kind === 'me' || kind === '') li.append(el('small', '', (from ? from + ' - ' : '') + t));
  $('log').append(li);
  $('log').scrollTop = $('log').scrollHeight;
  const mins = +$('vanish').value;
  if (mins > 0 && (kind === 'me' || kind === '')) {
    const id = setTimeout(() => { li.remove(); st.timers.delete(id); }, mins * 60000);
    st.timers.add(id);
  }
  logCount++;
}
const sys = (t) => addLog('sys', t);
function setStatus(t, cls = '') { const s = $('status'); s.textContent = t; s.className = 'status ' + cls; }

// ------------------------------------------------------------------ session UI
function showSecurity(kind) {
  $('secbox').hidden = false;
  const sc = cfg();
  $('myfprow').hidden = !(st.identity && sc.auth === 'sign' && (sc.e2e === 'ratchet' || sc.e2e === 'ecdh'));
  if (st.identity) $('myfp').textContent = st.identity.fp;
  if (kind) $('secstate').textContent = kind;
}
function onCoreEvent(ev) {
  const peerInput = $('peer');
  switch (ev.type) {
    case 'ready': {
      if (!peerInput.value) peerInput.value = ev.peer;
      st.ready = true;
      $('msg').disabled = false; $('send').disabled = false;
      showSecurity(cfg().e2e === 'none' ? 'No end-to-end encryption' : `Secured with ${ev.peer}`);
      sys(cfg().e2e === 'none' ? 'Ready (transport encryption only).' : 'Secure session established with ' + ev.peer + '.');
      break;
    }
    case 'sas':
      showSecurity();
      $('sasrow').hidden = false; $('sas').textContent = ev.code;
      $('verrow').hidden = false;
      break;
    case 'peerKey':
      showSecurity();
      $('fprow').hidden = false; $('fpkind').textContent = ev.kind; $('peerfp').textContent = ev.fp;
      $('verrow').hidden = false;
      break;
    case 'message': addLog('', ev.text, ev.peer); break;
    case 'plain': addLog('warn', `UNENCRYPTED message from ${ev.peer} (not protected end-to-end!): ${ev.text}`); break;
    case 'info': sys(ev.text); break;
    case 'error': addLog('err', ev.reason + (ev.peer ? ` (${ev.peer})` : '')); break;
    default:
  }
}

async function buildSession() {
  const c = cfg();
  const o = { mode: c.e2e, curve: c.curve, auth: c.auth, passphrase: $('passphrase').value };
  if (c.e2e === 'ratchet' || c.e2e === 'ecdh') {
    if (c.auth === 'sign') { if (!st.identity) st.identity = await makeIdentity(); o.identity = st.identity; }
    if (c.auth === 'psk' && !o.passphrase) throw new Error('Enter the shared passphrase first.');
  }
  if (c.e2e === 'static') { st.statKey = st.statKey && st.statCurve === c.curve ? st.statKey : await makeStatic(c.curve); st.statCurve = c.curve; o.staticKey = st.statKey; st.identity = { fp: st.statKey.fp }; }
  if (c.e2e === 'psk' && !o.passphrase) throw new Error('Enter the shared passphrase first.');
  if (c.e2e === 'otp') {
    if (!st.pad || st.pad.length < 4096) throw new Error('Generate or paste a one-time pad first (at least 4 KB).');
    o.pad = st.pad; o.side = radio('otpside');
  }
  return () => new Session(o);
}

// ------------------------------------------------------------------ connect
function buildTransport(c, handlers) {
  const proto = c.proto;
  const nick = val('nick');
  if (!nick) throw new Error(proto === 'xmpp' ? 'Enter your JID.' : 'Enter a nickname.');
  if (proto === 'loopback') return makeTransport('loopback', { nick }, handlers);
  const base = { password: val('pass'), serverPass: val('spass') };
  let url;
  if (c.route === 'bridge') {
    const host = val('bhost'); const port = val('bport');
    if (!host || !port) throw new Error('Enter the chat server host and port.');
    const q = new URLSearchParams({ host, port, tls: $('btls').checked ? '1' : '0', route: ['tor', 'i2p'].includes(c.anon) ? c.anon : 'direct' });
    if ($('binsecure').checked) q.set('insecure', '1');
    if (proto === 'xmpp') { q.set('mode', 'ws'); q.set('path', val('bpath') || '/'); q.set('subproto', 'xmpp'); } else q.set('mode', 'tcp');
    url = c.bridgeUrl.replace(/\/$/, '') + '/?' + q;
  } else {
    url = c.url;
    if (!/^wss?:\/\//i.test(url)) throw new Error('The server address must start with wss://');
    if (/^ws:\/\//i.test(url) && !urlInfo(url).local) throw new Error('Plain ws:// is blocked: it is not encrypted (and browsers refuse it from this https page). Use a wss:// address.');
  }
  if (proto === 'xmpp') return makeTransport('xmpp', { ...base, url, jid: nick }, handlers);
  return makeTransport('irc', { ...base, url, nick, user: base.password ? nick : '', subprotocol: c.route === 'bridge' ? 'none' : val('subproto') }, handlers);
}

async function connect() {
  const c = cfg();
  $('connect').disabled = true;
  st.bridgeInfo = null;
  setStatus('Preparing keys...');
  try {
    if (c.e2e !== 'none' && !(await curveSupported(c.curve)) && c.e2e !== 'psk' && c.e2e !== 'otp') throw new Error(`This browser does not support ${c.curve}. Pick another curve (P-256 works everywhere).`);
    const makeSession = c.e2e === 'none' ? null : await buildSession();
    const handlers = {
      onStatus: (s) => setStatus(s),
      onHello: (h) => { st.bridgeInfo = h; renderReport(); sys(h.tls ? `Bridge: ${h.protocol} ${h.cipher} - certificate ${h.authorized ? 'valid' : 'NOT verified'}` : 'Bridge: connection to server is NOT encrypted'); },
      onClose: (why) => { if (st.connected) { setStatus('Disconnected: ' + why, 'bad'); st.connected = false; $('start').disabled = true; $('msg').disabled = true; $('send').disabled = true; $('connect').disabled = false; } },
    };
    const t = buildTransport(c, handlers);
    setStatus('Connecting...');
    await t.connect();
    st.core = new ChatCore({ transport: t, e2e: c.e2e, makeSession, onEvent: onCoreEvent });
    st.connected = true;
    setStatus('Connected as ' + t.nick, 'ok');
    $('burn').disabled = false; $('start').disabled = false;
    if (c.e2e === 'none') { $('msg').disabled = false; $('send').disabled = false; st.ready = true; }
    if (c.e2e === 'otp') { $('padtext').value = ''; $('padstatus').textContent = 'Pad is now held in memory and being consumed; it cannot be re-displayed.'; }
    sys(`Connected. ${c.e2e === 'none' ? 'WARNING: no end-to-end encryption.' : 'Enter your peer\'s name and press the secure-session button.'}`);
    renderReport();
  } catch (e) {
    setStatus(e.message, 'bad');
    $('connect').disabled = false;
  }
}

async function startSession() {
  const peer = val('peer');
  if (!peer) { setStatus('Enter who you want to chat with.', 'bad'); return; }
  try {
    await st.core.start(peer);
    const c = cfg();
    if (c.e2e === 'psk' || c.e2e === 'otp') { st.ready = true; $('msg').disabled = false; $('send').disabled = false; showSecurity('Encrypted channel open (no handshake needed)'); sys('Channel open. Messages are encrypted; your peer needs the same ' + (c.e2e === 'psk' ? 'passphrase.' : 'pad (opposite side).')); }
    else showSecurity('Handshake in progress...');
  } catch (e) { addLog('err', e.message); }
}

async function sendMsg(ev) {
  ev.preventDefault();
  const text = $('msg').value;
  const peer = val('peer');
  if (!text || !peer || !st.core) return;
  try {
    await st.core.sendText(peer, text);
    addLog('me', text, 'you');
    $('msg').value = '';
    const s = st.core.session(peer);
    if (s && s.padRemaining() !== null) $('padstatus').textContent = `One-time pad left for sending: ${s.padRemaining()} bytes.`;
  } catch (e) { addLog('err', e.message); }
}

function burn() {
  if (st.core) { try { st.core.close(); } catch { /* ignore */ } st.core = null; }
  if (st.pad) { st.pad.fill(0); st.pad = null; }
  st.identity = st.statKey = null;
  st.timers.forEach(clearTimeout); st.timers.clear();
  $('log').replaceChildren();
  ['passphrase', 'pass', 'spass', 'padtext', 'msg'].forEach((i) => { $(i).value = ''; });
  $('secbox').hidden = true; $('sasrow').hidden = true; $('fprow').hidden = true; $('verrow').hidden = true; $('verified').checked = false;
  st.verified = false; st.connected = false; st.ready = false; st.bridgeInfo = null;
  $('msg').disabled = $('send').disabled = $('start').disabled = $('burn').disabled = true;
  $('connect').disabled = false;
  setStatus('Burned: keys, pad, passwords and messages wiped from memory. Disconnected.');
  renderForm();
}

// ------------------------------------------------------------------ helpers
async function discover() {
  const jid = val('nick');
  const domain = jid.includes('@') ? jid.split('@')[1] : jid;
  if (!domain) { $('tlsflag').textContent = 'Enter your JID or the server name in the box below first.'; return; }
  $('tlsflag').textContent = 'Looking up ' + domain + '...'; $('tlsflag').className = 'tlsflag';
  try {
    const r = await fetch(`https://${domain}/.well-known/host-meta.json`, { credentials: 'omit', referrerPolicy: 'no-referrer' });
    const j = await r.json();
    const l = (j.links || []).find((x) => x.rel === 'urn:xmpp:alt-connections:websocket');
    if (!l) throw new Error('no WebSocket entry');
    $('url').value = l.href; renderForm();
  } catch {
    $('tlsflag').textContent = 'Auto-discovery failed (the server may not publish it, or blocks web pages). Ask your provider for their WebSocket (wss://) address.';
    $('tlsflag').className = 'tlsflag bad';
  }
}
async function buildCmd() {
  const box = $('cmdbox');
  try {
    const r = await fetch('gateway/stc-bridge.cjs', { cache: 'no-store' });
    if (!r.ok) throw new Error('HTTP ' + r.status);
    const src = (await r.text()).replace(/\r\n/g, '\n').replace(/\n$/, '');
    const origin = location.origin === 'null' ? 'https://YOUR-NAME.github.io' : location.origin;
    const flags = ($('binsecure').checked ? ' --allow-insecure-tls' : '');
    box.value = `cat > ~/stc-bridge.cjs <<'STC_BRIDGE_EOF'\n${src}\nSTC_BRIDGE_EOF\nchmod +x ~/stc-bridge.cjs && node ~/stc-bridge.cjs --origin ${origin}${flags}\n`;
    $('cpcmd').disabled = false;
  } catch (e) { box.value = 'Could not load the bridge file from this site (' + e.message + '). Download gateway/stc-bridge.cjs from the project repository instead.'; }
}
async function copyCmd() {
  try { await navigator.clipboard.writeText($('cmdbox').value); $('cpcmd').textContent = 'Copied'; }
  catch { $('cmdbox').select(); $('cpcmd').textContent = 'Select + Ctrl+C'; }
  setTimeout(() => { $('cpcmd').textContent = 'Copy'; }, 2000);
}
function setPad(p) {
  st.pad = p;
  $('padstatus').textContent = p ? `Pad loaded: ${p.length.toLocaleString()} bytes - about ${Math.floor(p.length / 2 / 100).toLocaleString()} short messages each way. Share it ONLY in person or over a channel you already trust.` : '';
}

// ------------------------------------------------------------------ wire up
['proto', 'url', 'nick', 'pass', 'e2e', 'curve', 'auth', 'passphrase', 'vanish', 'anon', 'bridgeurl', 'bhost', 'bport', 'btls', 'binsecure'].forEach((i) => $(i).addEventListener('input', renderForm));
document.querySelectorAll('input[name="route"]').forEach((r) => r.addEventListener('change', renderForm));
$('proto').addEventListener('change', () => {
  const p = $('proto').value;
  if (p === 'silc' || p === 'groupwise') { $('bhost').value = '127.0.0.1'; $('bport').value = 6667; $('btls').checked = false; }
  else if (p === 'xmpp') { $('bport').value = 443; $('btls').checked = true; }
  else if (p === 'irc') { $('bport').value = 6697; $('btls').checked = true; }
  $('url').placeholder = p === 'xmpp' ? 'wss://xmpp.example.org/xmpp-websocket' : 'wss://irc.example.org/ws';
  renderForm();
});
$('verified').addEventListener('change', () => { st.verified = $('verified').checked; renderReport(); });
$('connect').addEventListener('click', connect);
$('start').addEventListener('click', startSession);
$('burn').addEventListener('click', burn);
$('composer').addEventListener('submit', sendMsg);
$('discover').addEventListener('click', discover);
$('mkcmd').addEventListener('click', buildCmd);
$('cpcmd').addEventListener('click', copyCmd);
$('padgen').addEventListener('click', () => { const p = generatePad(+$('padsize').value); $('padtext').value = padToText(p); setPad(p); });
$('padtext').addEventListener('input', () => { try { const t = $('padtext').value.trim(); setPad(t ? padFromText(t) : null); } catch { setPad(null); $('padstatus').textContent = 'That is not valid base64.'; } });
$('padfile').addEventListener('change', async () => { const f = $('padfile').files[0]; if (!f) return; const p = new Uint8Array(await f.arrayBuffer()); $('padtext').value = padToText(p); setPad(p); });
$('nick').value = 'guest' + Math.random().toString(36).slice(2, 6);
document.addEventListener('visibilitychange', () => { /* nothing is persisted; intentionally no storage */ });
renderForm();
