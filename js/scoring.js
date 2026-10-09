// Encryption layers, plain-language explanations, and the two scores.
// Pure functions: no DOM, no network. Everything shown in the UI comes from evaluate().

export const E2E_LABELS = {
  none: 'None (transport encryption only)',
  ratchet: 'Double Ratchet (Signal-style) - AES-256-GCM',
  ecdh: 'Session ECDH + symmetric chain - AES-256-GCM',
  static: 'Static long-term keys (certificate-style) - AES-256-GCM',
  psk: 'Shared passphrase - PBKDF2 + AES-256-GCM',
  otp: 'One-time pad (XOR) + HMAC-SHA256 tag',
};
export const AUTH_LABELS = {
  none: 'No identity proof (compare the 8-digit code with your peer)',
  sign: 'Signed handshake (ECDSA P-256 identity key)',
  psk: 'Shared secret mixed into the key exchange',
};

const LOCAL = /^(127\.\d+\.\d+\.\d+|localhost|\[?::1\]?)$/i;
export function urlInfo(u) {
  try {
    const x = new URL(u);
    return { scheme: x.protocol.replace(':', ''), host: x.hostname, local: LOCAL.test(x.hostname) };
  } catch { return { scheme: '', host: '', local: false }; }
}

const BROWSER_TLS_NOTE =
  'The exact TLS version and cipher are negotiated between your browser and the server and JavaScript is not allowed to read them. ' +
  'Browsers only allow TLS 1.2 or 1.3 for wss://. Modern servers normally end up with TLS 1.3 (TLS_AES_128_GCM_SHA256, TLS_AES_256_GCM_SHA384 or TLS_CHACHA20_POLY1305_SHA256) ' +
  'or TLS 1.2 with ECDHE + AES-GCM / ChaCha20-Poly1305. To see the real one, click the padlock in your browser > connection details, or use the local bridge, which reports it exactly.';

function pskPoints(len) {
  if (len < 8) return 8;
  if (len < 12) return 16;
  if (len < 16) return 22;
  if (len < 24) return 26;
  return 28;
}

export function grade(n) {
  return n >= 90 ? 'A+' : n >= 80 ? 'A' : n >= 70 ? 'B' : n >= 55 ? 'C' : n >= 40 ? 'D' : 'F';
}

/**
 * cfg = {
 *   proto: 'irc'|'xmpp'|'silc'|'groupwise'|'loopback',
 *   url, route: 'direct'|'bridge',
 *   bridgeUrl, bridgeInfo (hello frame) | null,
 *   anon: 'none'|'tor'|'i2p'|'torbrowser',
 *   e2e, curve, auth, verified (SAS/fingerprint compared), passLen, loggedIn, disappearing
 * }
 */
export function evaluate(cfg) {
  const warnings = [];
  const layers = [];
  const enc = [];
  const priv = [];
  const add = (arr, label, pts, max, note) => arr.push({ label, pts, max, note });

  // ---------- layer 1: anonymity network ----------
  const anonViaBridge = cfg.route === 'bridge' && (cfg.anon === 'tor' || cfg.anon === 'i2p');
  let anonPts = 0;
  let anonActive = 'none';
  if (anonViaBridge) {
    anonActive = cfg.anon;
  } else if (cfg.anon === 'torbrowser') {
    anonActive = 'torbrowser';
  } else if (cfg.anon === 'tor' || cfg.anon === 'i2p') {
    warnings.push(`You chose ${cfg.anon === 'tor' ? 'Tor' : 'I2P'} but a web page cannot route itself through it. Switch the route to "Local bridge" (see the bridge section) - until then this layer is NOT active and is not scored.`);
  }
  if (anonActive === 'tor' || anonActive === 'torbrowser') {
    layers.push({
      name: anonActive === 'tor' ? 'Tor (via your local bridge)' : 'Tor Browser (you declared this - cannot be verified by the page)',
      kind: 'anon',
      ciphers: 'Layered onion encryption: one layer per relay (3 hops to a normal server, 6 to an onion service). Link security: TLS between relays; per-hop circuit keys from ntor (Curve25519) with AES-based relay cell encryption.',
      detail: 'Hides your IP address from the chat server and the server\'s address from your ISP. Does not hide message content from the server - that is what the layers below are for.',
    });
    anonPts = anonActive === 'tor' ? 15 : 12;
  } else if (anonActive === 'i2p') {
    layers.push({
      name: 'I2P (via your local bridge)',
      kind: 'anon',
      ciphers: 'Garlic routing with layered tunnel encryption (AES-256 per hop), NTCP2/SSU2 transports (Noise protocol, X25519 + ChaCha20-Poly1305), end-to-end ECIES-X25519 ratchet.',
      detail: 'Hides your IP address using separate inbound/outbound tunnels. Works best with servers that are themselves inside I2P (.i2p addresses).',
    });
    anonPts = 15;
  }
  add(enc, 'Anonymity-network layer', anonPts, 15, anonPts ? 'Extra independent layers of encryption around everything below.' : 'Not used.');
  add(priv, 'Hides your IP address', anonActive === 'none' ? 0 : anonActive === 'torbrowser' ? 20 : 25, 25,
    anonActive === 'none' ? 'The server (and your ISP) can see your IP address.' : 'Your IP is hidden from the chat server.');

  // ---------- layer 2: transport ----------
  let tlsPts = 0;
  const tlsMax = 20;
  const ui = urlInfo(cfg.url);
  const bi = cfg.bridgeInfo || null;
  if (cfg.proto === 'loopback') {
    layers.push({
      name: 'In-browser loopback (demo)',
      kind: 'transport',
      ciphers: 'None needed - messages never leave this browser (BroadcastChannel between tabs of the same site).',
      detail: 'Use two tabs to try the app without any server. This is not a real network.',
    });
    tlsPts = tlsMax;
  } else if (cfg.route === 'bridge') {
    const bridgeLocal = urlInfo(cfg.bridgeUrl).local;
    const hop1 = bridgeLocal || urlInfo(cfg.bridgeUrl).scheme === 'wss';
    if (!hop1) warnings.push('Your bridge is on another machine but reached over ws:// (plain text). Use wss:// or run the bridge on this computer.');
    if (bi && bi.tls) {
      const aead = /GCM|CHACHA/i.test(bi.cipher || '');
      const proto = bi.protocol || 'TLS';
      layers.push({
        name: `TLS to the server (verified by bridge): ${proto}`,
        kind: 'transport',
        ciphers: `${bi.cipher || 'unknown cipher'}${bi.authorized ? ' - server certificate VALID' : ' - server certificate NOT verified (' + (bi.authError || 'untrusted') + ')'}${bi.cert ? '. Cert: ' + bi.cert : ''}`,
        detail: `Real values read by the bridge from the live connection. ${proto === 'TLSv1.3' ? 'TLS 1.3 always uses ephemeral keys, so the TLS layer itself has forward secrecy.' : proto === 'TLSv1.2' && /ECDHE|DHE/.test(bi.cipher || '') ? 'This cipher uses ephemeral key exchange (forward secrecy).' : ''}`,
      });
      tlsPts = !hop1 ? 0 : !bi.authorized ? 8 : aead && proto === 'TLSv1.3' ? 20 : aead ? 17 : 10;
      if (!bi.authorized) warnings.push('The server\'s TLS certificate was NOT verified. Anyone on the network path could impersonate the server. Prefer a server with a valid certificate.');
    } else if (bi && bi.tls === false) {
      layers.push({ name: 'Bridge to server: PLAIN TEXT (no TLS)', kind: 'transport', ciphers: 'none', detail: 'Everything except your end-to-end layer is readable by anyone on the path.' });
      tlsPts = 0;
      warnings.push('The connection from your bridge to the chat server is NOT encrypted. Use a TLS port (usually 6697 for IRC) or a server that supports TLS.');
    } else {
      layers.push({ name: 'TLS to the server (pending - connect to see real values)', kind: 'transport', ciphers: 'The bridge will report the real TLS version and cipher once connected.', detail: '' });
      tlsPts = 10;
    }
    if (cfg.proto === 'silc' || cfg.proto === 'groupwise') {
      layers.push({
        name: `${cfg.proto === 'silc' ? 'SILC' : 'GroupWise'} hop (inside your gateway)`,
        kind: 'transport',
        ciphers: 'Decided by the gateway software (e.g. BitlBee/libpurple) and the remote server. This page cannot see or verify it.',
        detail: 'SILC has its own built-in encryption (AES and RSA/DH based) and GroupWise can use SSL, but the settings live in your gateway.',
      });
      tlsPts = Math.min(tlsPts, 10);
      warnings.push(`${cfg.proto === 'silc' ? 'SILC' : 'GroupWise'} traffic leaves your gateway using whatever that protocol/gateway negotiates - not verified here. Your end-to-end layer below still protects the message.`);
    }
  } else {
    if (ui.scheme === 'wss') {
      layers.push({ name: 'TLS (wss://) - browser enforced, TLS 1.2 or 1.3', kind: 'transport', ciphers: 'Negotiated automatically; exact cipher not readable by web pages.', detail: BROWSER_TLS_NOTE });
      tlsPts = 17;
    } else if (ui.scheme === 'ws') {
      layers.push({ name: 'NO transport encryption (ws://)', kind: 'transport', ciphers: 'none', detail: 'Plain text on the network.' });
      warnings.push('This server address uses ws:// (not encrypted). Pick a server that offers wss://.');
      tlsPts = 0;
    } else {
      layers.push({ name: 'Transport not set', kind: 'transport', ciphers: '-', detail: 'Enter a server address starting with wss://' });
    }
  }
  add(enc, 'Transport encryption (TLS)', tlsPts, tlsMax, cfg.proto === 'loopback' ? 'No network used.' : tlsPts ? 'Protects against your ISP / Wi-Fi owner. The server operator can still read anything not end-to-end encrypted.' : 'No transport encryption.');

  // ---------- layer 3: end-to-end ----------
  let cipherPts = 0;
  let kxPts = 0;
  let authPts = 0;
  let privAuth = 0;
  let pfs = { level: 'none', title: 'No end-to-end encryption', text: 'The server operator and anyone who compromises the server can read your messages.' };
  let deniability = { ok: false, text: 'n/a' };
  let e2eLayer;
  const curveName = cfg.curve === 'X25519' ? 'X25519' : cfg.curve === 'P-384' ? 'ECDH P-384' : 'ECDH P-256';
  const verified = !!cfg.verified;

  switch (cfg.e2e) {
    case 'ratchet':
    case 'ecdh': {
      cipherPts = 30;
      kxPts = cfg.e2e === 'ratchet' ? 20 : 14;
      e2eLayer = {
        name: cfg.e2e === 'ratchet' ? 'End-to-end: Double Ratchet (Signal-style)' : 'End-to-end: session ECDH with symmetric key chain',
        kind: 'e2e',
        ciphers: `AES-256-GCM (message encryption + integrity), ${curveName} (ephemeral key agreement), HKDF-SHA-256 and HMAC-SHA-256 (key derivation / chain ratchet), 8-digit SAS from SHA-256.`,
        detail: cfg.e2e === 'ratchet'
          ? 'A fresh key per message, and fresh Diffie-Hellman keys every time the conversation changes direction. Stealing a key later does not reveal past messages (forward secrecy) and the chat heals itself afterwards (post-compromise security). This is Signal-STYLE but not Signal-compatible: it only talks to another copy of this app.'
          : 'One ephemeral key agreement per session, then a one-way key chain: each message key is deleted after use. Forward secrecy per session, but no self-healing.',
      };
      pfs = cfg.e2e === 'ratchet'
        ? { level: 'full', title: 'Perfect forward secrecy: YES (per message) + post-compromise security', text: 'Every message has its own key and the ephemeral keys are discarded.' }
        : { level: 'session', title: 'Perfect forward secrecy: YES (per session)', text: 'Session keys come from throw-away keys; per-message keys are deleted after use.' };
      deniability = { ok: true, text: 'Deniable: no signatures, only shared-key authentication, so the transcript proves nothing to a third party.' };
      if (cfg.auth === 'sign') {
        authPts = verified ? 15 : 6;
        privAuth = verified ? 25 : 10;
        deniability = { ok: false, text: 'NOT deniable: your handshake is signed with an identity key, which proves to anyone who sees it that you took part. PFS is unaffected because the signing key never derives message keys.' };
        if (!verified) warnings.push('Signed handshake: compare the identity-key fingerprint with your peer over a trusted channel and press "Mark as verified", otherwise a first-contact attacker could substitute their own key.');
      } else if (cfg.auth === 'psk') {
        authPts = cfg.passLen >= 12 ? 13 : 8;
        privAuth = cfg.passLen >= 12 ? 22 : 13;
        if (cfg.passLen < 12) warnings.push('The shared secret is short. Use 12+ characters; it is the only thing that stops an active attacker.');
      } else {
        authPts = verified ? 12 : 0;
        privAuth = verified ? 20 : 0;
        if (!verified) warnings.push('No authentication yet: the connection is encrypted but you could be talking to an impostor or man-in-the-middle. Compare the 8-digit code with your peer by voice/another channel, then press "Mark as verified".');
      }
      break;
    }
    case 'static': {
      cipherPts = 30;
      kxPts = 3;
      authPts = verified ? 12 : 3;
      privAuth = verified ? 20 : 5;
      e2eLayer = {
        name: 'End-to-end: static long-term keys (certificate-style)',
        kind: 'e2e',
        ciphers: `AES-256-GCM, ${curveName} between the two long-term keys, HKDF-SHA-256 and HMAC-SHA-256.`,
        detail: 'Authentication comes from the fixed keys themselves. That is exactly the case where authentication DOES cost you perfect forward secrecy: the session key is derived from long-term secrets, so anyone who steals either key later (and recorded the traffic) can decrypt all of it. Keys here are generated per page load and never saved, which limits - but does not remove - this.',
      };
      pfs = { level: 'none', title: 'Perfect forward secrecy: NO', text: 'Session keys derive from long-term static keys. A later key theft exposes recorded traffic.' };
      deniability = { ok: true, text: 'Deniable-ish: only shared-key MACs, no signatures.' };
      warnings.push('Static-key mode has NO forward secrecy. Use the Double Ratchet unless you specifically need fixed keys.');
      if (!verified) warnings.push('Compare the static-key fingerprint with your peer and press "Mark as verified".');
      break;
    }
    case 'psk': {
      cipherPts = pskPoints(cfg.passLen);
      kxPts = 0;
      authPts = 10;
      privAuth = 17;
      e2eLayer = {
        name: 'End-to-end: shared passphrase',
        kind: 'e2e',
        ciphers: 'PBKDF2-HMAC-SHA-256 (600,000 rounds, random salt) -> AES-256-GCM. 96-bit random nonce per message.',
        detail: 'Only as strong as the passphrase. Anyone who obtains the passphrase later can decrypt everything that was recorded: no forward secrecy. Works in channels/rooms too, since everyone with the passphrase can read.',
      };
      pfs = { level: 'none', title: 'Perfect forward secrecy: NO', text: 'The key comes straight from a passphrase that does not change.' };
      deniability = { ok: true, text: 'Deniable: anyone with the passphrase could have written any message.' };
      if (cfg.passLen < 16) warnings.push('Use a long random passphrase (5+ random words). Short passphrases can be guessed offline by an attacker who recorded the traffic.');
      break;
    }
    case 'otp': {
      cipherPts = 30;
      kxPts = 10;
      authPts = 12;
      privAuth = 20;
      e2eLayer = {
        name: 'End-to-end: one-time pad',
        kind: 'e2e',
        ciphers: 'XOR with a pre-shared random pad (information-theoretic secrecy if the pad is truly random, used once, and kept secret) + HMAC-SHA-256 tag keyed from fresh pad bytes (computational authenticity).',
        detail: 'Every message consumes fresh pad bytes (plus 32 for the tag key) which are wiped immediately after use. Pads made in the browser use the OS cryptographic RNG - excellent, but not a hardware/dice source. Message length is rounded up to 64 bytes. The pad must be exchanged in person or by another secure channel.',
      };
      pfs = { level: 'pad', title: 'Forward secrecy: depends on the pad', text: 'Used pad bytes are erased so old messages cannot be re-derived from what is left - but if anyone copied the whole pad before use, all messages are exposed. Pad exhaustion stops the chat.' };
      deniability = { ok: true, text: 'Deniable: anyone with the pad could have produced any plaintext of that length.' };
      warnings.push('One-time-pad safety: never reuse a pad, never let a copy of it sit on a synced/cloud drive, and share it only face to face or via an already-secure channel.');
      break;
    }
    default: {
      e2eLayer = { name: 'NO end-to-end encryption', kind: 'e2e', ciphers: 'none', detail: 'Messages are plain text inside the transport layer. The server operator can read everything.' };
      warnings.push('End-to-end encryption is OFF. The chat server can read every message.');
    }
  }
  layers.push(e2eLayer);
  add(enc, 'End-to-end cipher strength', cipherPts, 30, cfg.e2e === 'psk' ? `Limited by passphrase length (${cfg.passLen} chars).` : cfg.e2e === 'none' ? 'No end-to-end layer.' : 'AES-256 (or one-time pad).');
  add(enc, 'Key exchange / forward secrecy', kxPts, 20, pfs.title);
  add(enc, 'Peer authentication', authPts, 15, cfg.e2e === 'none' ? 'Nothing to authenticate.' : authPts >= 12 ? 'Strong: an active attacker is stopped.' : 'Weak or unverified: an impostor could get in.');

  // ---------- privacy score ----------
  const pfsPriv = { ratchet: 30, ecdh: 22, otp: 20, static: 0, psk: 0, none: 0 }[cfg.e2e] || 0;
  add(priv, 'Perfect forward secrecy', pfsPriv, 30, pfs.title);
  add(priv, 'Authentication of your peer', privAuth, 25, cfg.e2e === 'none' ? 'None.' : authPts >= 12 ? 'Peer identity is established.' : 'Not (yet) established.');
  const deniPts = cfg.e2e === 'none' ? 0 : deniability.ok ? 10 : 0;
  add(priv, 'Deniability', deniPts, 10, deniability.text);
  const meta = 4 + (cfg.disappearing ? 3 : 0) + (cfg.loggedIn ? 0 : 3);
  add(priv, 'Metadata hygiene', meta, 10, `Keys and history live in memory only (+4)${cfg.disappearing ? ', messages auto-delete (+3)' : ''}${cfg.loggedIn ? '' : ', anonymous/no account (+3)'}. The server still sees who talks to whom, when, and how big.`);

  const sum = (a) => a.reduce((s, x) => s + x.pts, 0);
  const encScore = cfg.e2e === 'none' ? Math.min(sum(enc), 45) : sum(enc);
  const privScore = sum(priv);

  if (cfg.e2e !== 'none') {
    warnings.push('Even with end-to-end encryption the server operator still sees metadata: your nickname/JID, your peer\'s, timestamps and message sizes.');
  }
  if (cfg.proto === 'irc') warnings.push('IRC servers commonly log connections and many show your hostname/IP to other users. Choose a server with a clear privacy policy, TLS and ideally cloaking, or use Tor/I2P.');

  // narrative: innermost -> outermost
  const order = ['e2e', 'transport', 'anon'];
  const inner = order.flatMap((k) => layers.filter((l) => l.kind === k));
  const narrative = inner.map((l) => l.name).join('  → wrapped inside →  ');

  return {
    layers: [...layers.filter((l) => l.kind === 'anon'), ...layers.filter((l) => l.kind === 'transport'), ...layers.filter((l) => l.kind === 'e2e')],
    narrative,
    layerCount: layers.filter((l) => l.ciphers !== 'none' && l.ciphers !== '-').length,
    encryption: { score: Math.max(0, Math.min(100, encScore)), grade: grade(encScore), parts: enc },
    privacy: { score: Math.max(0, Math.min(100, privScore)), grade: grade(privScore), parts: priv },
    pfs,
    deniability,
    warnings: [...new Set(warnings)],
  };
}
